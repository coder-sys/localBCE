from __future__ import annotations

from datetime import datetime, timezone
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tools import batch_package


class BatchPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.p256_private_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = self.p256_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.p256_registry = {
            "agency-key-1": {
                "public_key_pem_b64": base64.b64encode(public_pem).decode("ascii"),
                "agency_id": "agency-a",
                "status": "active",
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2030-01-01T00:00:00+00:00",
            }
        }
        self.environment = mock.patch.dict(
            os.environ,
            {
                batch_package.SUBMISSION_KEY_ENV: "test-submission-key-material-00000001",
                batch_package.SUBMISSION_KEY_ID_ENV: "test-key-1",
                batch_package.P256_KEY_REGISTRY_ENV: json.dumps(self.p256_registry),
            },
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()

    def _package(self) -> dict:
        return batch_package.create_batch_package(
            package_id="package-001",
            batch_id="batch-001",
            claim_count=1,
            serialized_arguments_hex_json=["0x1", "0x2"],
            expected_output={"root_before": 3, "root_after": 4},
            principal="operator@example.gov",
            source_reference="ingestion-receipt-001",
            created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )

    def test_package_contains_only_redacted_witness_and_ordered_outputs(self) -> None:
        package = self._package()
        self.assertEqual(["0x3", "0x4"], package["witness"]["expected_output_values"])
        serialized = json.dumps(package).lower()
        self.assertNotIn("edi", serialized)
        self.assertNotIn("claims", serialized)
        batch_package.validate_batch_package(package)

    def test_witness_or_authorization_tampering_is_rejected(self) -> None:
        package = self._package()
        package["witness"]["serialized_arguments_hex_json"][0] = "0x9"
        with self.assertRaisesRegex(RuntimeError, "witness integrity"):
            batch_package.validate_batch_package(package)

        package = self._package()
        package["authorization"]["principal"] = "attacker@example.org"
        with self.assertRaisesRegex(RuntimeError, "authorization failed"):
            batch_package.validate_batch_package(package)

    def test_unknown_fields_are_rejected_instead_of_carrying_raw_claims(self) -> None:
        package = self._package()
        package["claims"] = [{"edi": "sensitive"}]
        with self.assertRaisesRegex(RuntimeError, "locked schema"):
            batch_package.validate_batch_package(package)

    def test_package_file_is_create_only_and_revalidated_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "batch-package.json"
            package = self._package()
            batch_package.write_batch_package(path, package)
            self.assertEqual(package, batch_package.load_batch_package(path))
            with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
                batch_package.write_batch_package(path, package)

    def test_missing_or_short_submission_key_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {batch_package.SUBMISSION_KEY_ENV: "short"}):
            with self.assertRaisesRegex(RuntimeError, "at least 32 bytes"):
                self._package()

    def _p256_package(self) -> dict:
        unsigned = batch_package.create_unsigned_batch_package(
            package_id="package-p256-001",
            batch_id="batch-p256-001",
            claim_count=1,
            serialized_arguments_hex_json=["0x1", "0x2"],
            expected_output=["0x3", "0x4"],
            source_reference="batch-record-sha256:" + "a" * 64,
            created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )
        message = batch_package.batch_package_signing_message(
            unsigned,
            principal="operator@agency.gov",
            key_id="agency-key-1",
            agency_id="agency-a",
        )
        signature = self.p256_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return batch_package.authorize_batch_package_p256(
            unsigned,
            principal="operator@agency.gov",
            key_id="agency-key-1",
            agency_id="agency-a",
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def test_external_p256_authorization_validates_without_private_key_custody(self) -> None:
        package = self._p256_package()
        self.assertEqual("ecdsa-p256-sha256", package["authorization"]["scheme"])
        batch_package.validate_batch_package(package)

    def test_external_signature_tampering_and_key_revocation_fail_closed(self) -> None:
        package = self._p256_package()
        package["authorization"]["signature"] = base64.b64encode(b"forged").decode("ascii")
        with self.assertRaisesRegex(RuntimeError, "authorization failed"):
            batch_package.validate_batch_package(package)

        package = self._p256_package()
        revoked = json.loads(json.dumps(self.p256_registry))
        revoked["agency-key-1"]["status"] = "revoked"
        with mock.patch.dict(
            os.environ, {batch_package.P256_KEY_REGISTRY_ENV: json.dumps(revoked)}
        ):
            with self.assertRaisesRegex(RuntimeError, "not active"):
                batch_package.validate_batch_package(package)

    def test_hmac_authorization_is_rejected_in_production(self) -> None:
        package = self._package()
        with mock.patch.dict(os.environ, {"BL_ENV": "production"}):
            with self.assertRaisesRegex(RuntimeError, "disabled in production"):
                batch_package.validate_batch_package(package)

    def test_production_registry_file_requires_an_exact_hash_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "keys.json"
            content = json.dumps(self.p256_registry, sort_keys=True).encode("utf-8")
            path.write_bytes(content)
            correct_hash = batch_package.hashlib.sha256(content).hexdigest()
            production = {
                "BL_ENV": "production",
                batch_package.P256_KEY_REGISTRY_PATH_ENV: str(path),
                batch_package.P256_KEY_REGISTRY_SHA256_ENV: correct_hash,
            }
            with mock.patch.dict(os.environ, production):
                batch_package.validate_batch_package(self._p256_package())
            production[batch_package.P256_KEY_REGISTRY_SHA256_ENV] = "0" * 64
            with mock.patch.dict(os.environ, production):
                with self.assertRaisesRegex(RuntimeError, "hash pin does not match"):
                    batch_package.validate_batch_package(self._p256_package())

    def test_production_refuses_to_write_plaintext_witness_package(self) -> None:
        package = self._p256_package()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ, {"BL_ENV": "production"}
        ):
            with self.assertRaisesRegex(RuntimeError, "plaintext witness package"):
                batch_package.write_batch_package(
                    Path(temporary) / "forbidden.json", package
                )


if __name__ == "__main__":
    unittest.main()
