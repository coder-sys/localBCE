from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from tools import batch_package
from tools import encrypted_witness_envelope as encrypted


class EncryptedWitnessEnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        signing_public = self.signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.wrapping_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.wrapping_public_pem = self.wrapping_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        registry = {
            "agency-signing-key": {
                "public_key_pem_b64": base64.b64encode(signing_public).decode("ascii"),
                "agency_id": "agency-a",
                "status": "active",
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2030-01-01T00:00:00+00:00",
            }
        }
        self.environment = mock.patch.dict(
            os.environ,
            {batch_package.P256_KEY_REGISTRY_ENV: json.dumps(registry)},
        )
        self.environment.start()
        unsigned = batch_package.create_unsigned_batch_package(
            package_id="private-package-001",
            batch_id="private-batch-001",
            claim_count=1,
            serialized_arguments_hex_json=["0x424c2d50415449454e542d303031", "0x12500"],
            expected_output=["0x2", "0x1"],
            source_reference="batch-record-sha256:" + "a" * 64,
            created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )
        message = batch_package.batch_package_signing_message(
            unsigned,
            principal="operator@agency.gov",
            key_id="agency-signing-key",
            agency_id="agency-a",
        )
        signature = self.signing_key.sign(message, ec.ECDSA(hashes.SHA256()))
        self.package = batch_package.authorize_batch_package_p256(
            unsigned,
            principal="operator@agency.gov",
            key_id="agency-signing-key",
            agency_id="agency-a",
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def tearDown(self) -> None:
        self.environment.stop()

    def _unwrap(self, wrapped_key: bytes, key_id: str, context_sha256: str) -> bytes:
        self.assertEqual("agency-wrapping-key", key_id)
        return self.wrapping_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=encrypted.oaep_label_for_context(context_sha256),
            ),
        )

    def test_envelope_round_trip_keeps_witness_out_of_the_stored_file(self) -> None:
        envelope = encrypted.encrypt_batch_package(
            self.package,
            wrapping_public_key_pem=self.wrapping_public_pem,
            wrapping_key_id="agency-wrapping-key",
            agency_id="agency-a",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "witness.envelope.json"
            encrypted.write_envelope(path, envelope)
            stored = path.read_text(encoding="utf-8")
            self.assertNotIn("424c2d50415449454e542d303031", stored)
            self.assertNotIn("serialized_arguments_hex_json", stored)
            loaded = encrypted.load_envelope(path)
        self.assertEqual(self.package, encrypted.decrypt_batch_package(loaded, unwrap_key=self._unwrap))

    def test_locked_header_is_cryptographically_bound_to_key_unwrap(self) -> None:
        envelope = encrypted.encrypt_batch_package(
            self.package,
            wrapping_public_key_pem=self.wrapping_public_pem,
            wrapping_key_id="agency-wrapping-key",
            agency_id="agency-a",
        )
        envelope["claim_count"] = 2
        envelope["envelope_sha256"] = encrypted._sha256(
            {key: value for key, value in envelope.items() if key != "envelope_sha256"}
        )
        with self.assertRaisesRegex(RuntimeError, "failed to unwrap"):
            encrypted.decrypt_batch_package(envelope, unwrap_key=self._unwrap)

    def test_old_unbound_envelope_schema_is_rejected(self) -> None:
        envelope = encrypted.encrypt_batch_package(
            self.package,
            wrapping_public_key_pem=self.wrapping_public_pem,
            wrapping_key_id="agency-wrapping-key",
            agency_id="agency-a",
        )
        envelope["schema_version"] = 1
        envelope["key_wrap_algorithm"] = "RSA-OAEP-SHA256"
        envelope["envelope_sha256"] = encrypted._sha256(
            {key: value for key, value in envelope.items() if key != "envelope_sha256"}
        )
        with self.assertRaisesRegex(RuntimeError, "unsupported encrypted witness envelope schema"):
            encrypted.validate_envelope(envelope)

    def test_oversized_ciphertext_and_file_fail_before_unwrap(self) -> None:
        envelope = encrypted.encrypt_batch_package(
            self.package,
            wrapping_public_key_pem=self.wrapping_public_pem,
            wrapping_key_id="agency-wrapping-key",
            agency_id="agency-a",
        )
        envelope["ciphertext_b64"] = base64.b64encode(
            b"x" * (encrypted.PROTOTYPE_MAX_CIPHERTEXT_BYTES + 1)
        ).decode("ascii")
        envelope["envelope_sha256"] = encrypted._sha256(
            {key: value for key, value in envelope.items() if key != "envelope_sha256"}
        )
        unwrap = mock.Mock(side_effect=self._unwrap)
        with self.assertRaisesRegex(RuntimeError, "ciphertext exceeds prototype byte limit"):
            encrypted.decrypt_batch_package(envelope, unwrap_key=unwrap)
        unwrap.assert_not_called()

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.envelope.json"
            path.write_bytes(b" " * (encrypted.PROTOTYPE_MAX_ENVELOPE_FILE_BYTES + 1))
            with self.assertRaisesRegex(RuntimeError, "file exceeds prototype byte limit"):
                encrypted.load_envelope(path)

    def test_oversized_plaintext_is_rejected_before_encryption(self) -> None:
        oversized = dict(self.package)
        with mock.patch.object(
            encrypted,
            "validate_batch_package",
            return_value=oversized,
        ), mock.patch.object(
            encrypted,
            "_canonical_json_bytes",
            return_value=b"p" * (encrypted.PROTOTYPE_MAX_PLAINTEXT_BYTES + 1),
        ):
            with self.assertRaisesRegex(RuntimeError, "plaintext exceeds prototype byte limit"):
                encrypted.encrypt_batch_package(
                    oversized,
                    wrapping_public_key_pem=self.wrapping_public_pem,
                    wrapping_key_id="agency-wrapping-key",
                    agency_id="agency-a",
                )

    def test_ciphertext_metadata_and_wrapped_key_tampering_fail_closed(self) -> None:
        envelope = encrypted.encrypt_batch_package(
            self.package,
            wrapping_public_key_pem=self.wrapping_public_pem,
            wrapping_key_id="agency-wrapping-key",
            agency_id="agency-a",
        )
        envelope["claim_count"] = 2
        with self.assertRaisesRegex(RuntimeError, "integrity check failed"):
            encrypted.validate_envelope(envelope)

        envelope = encrypted.encrypt_batch_package(
            self.package,
            wrapping_public_key_pem=self.wrapping_public_pem,
            wrapping_key_id="agency-wrapping-key",
            agency_id="agency-a",
        )
        envelope["wrapped_key_b64"] = base64.b64encode(b"forged").decode("ascii")
        envelope["envelope_sha256"] = encrypted._sha256(
            {key: value for key, value in envelope.items() if key != "envelope_sha256"}
        )
        with self.assertRaisesRegex(RuntimeError, "wrapped-key length"):
            encrypted.decrypt_batch_package(envelope, unwrap_key=self._unwrap)

    def test_schema_type_and_producer_metadata_are_validated_on_read(self) -> None:
        changes = [
            ("schema_version", True, "schema"),
            ("agency_id", " invalid agency ", "agency_id"),
            ("retain_until", "not-a-timestamp", "ISO-8601"),
            ("wrapping_key_id", "", "wrapping_key_id"),
        ]
        for field, value, message in changes:
            with self.subTest(field=field):
                envelope = encrypted.encrypt_batch_package(
                    self.package,
                    wrapping_public_key_pem=self.wrapping_public_pem,
                    wrapping_key_id="agency-wrapping-key",
                    agency_id="agency-a",
                )
                envelope[field] = value
                envelope["envelope_sha256"] = encrypted._sha256(
                    {
                        key: item
                        for key, item in envelope.items()
                        if key != "envelope_sha256"
                    }
                )
                with self.assertRaisesRegex(RuntimeError, message):
                    encrypted.validate_envelope(envelope)

    def test_wrong_agency_and_weak_wrapping_key_are_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "agency does not match"):
            encrypted.encrypt_batch_package(
                self.package,
                wrapping_public_key_pem=self.wrapping_public_pem,
                wrapping_key_id="agency-wrapping-key",
                agency_id="agency-b",
            )
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        weak_public = weak_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with self.assertRaisesRegex(RuntimeError, "RSA-3072"):
            encrypted.encrypt_batch_package(
                self.package,
                wrapping_public_key_pem=weak_public,
                wrapping_key_id="weak-key",
                agency_id="agency-a",
            )


if __name__ == "__main__":
    unittest.main()
