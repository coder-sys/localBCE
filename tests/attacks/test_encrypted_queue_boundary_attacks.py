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
from cryptography.hazmat.primitives.asymmetric import ec, padding

from tools import batch_package
from tools import encrypted_witness_envelope as encrypted
from tools import isolated_proving_worker
from tools import proving_submission
from tools.local_kms_simulator import LocalKmsSimulator


class EncryptedQueueBoundaryAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = self.signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        registry = {
            "attack-signing-key": {
                "public_key_pem_b64": base64.b64encode(public_pem).decode("ascii"),
                "agency_id": "synthetic-agency",
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
        created_at = datetime(2026, 7, 13, tzinfo=timezone.utc)
        self.record = proving_submission.create_batch_record(
            batch_id="synthetic-batch",
            agency_id="synthetic-agency",
            claim_count=1,
            expected_output_values=["0x2", "0x1"],
            source_system="synthetic-source",
            created_at=created_at,
        )
        unsigned = batch_package.create_unsigned_batch_package(
            package_id="synthetic-package",
            batch_id="synthetic-batch",
            claim_count=1,
            serialized_arguments_hex_json=["0x53594e544845544943", "0x1"],
            expected_output=["0x2", "0x1"],
            source_reference=proving_submission.batch_record_source_reference(self.record),
            created_at=created_at,
        )
        signature = self.signing_key.sign(
            batch_package.batch_package_signing_message(
                unsigned,
                principal="synthetic-operator@example.invalid",
                key_id="attack-signing-key",
                agency_id="synthetic-agency",
            ),
            ec.ECDSA(hashes.SHA256()),
        )
        self.package = batch_package.authorize_batch_package_p256(
            unsigned,
            principal="synthetic-operator@example.invalid",
            key_id="attack-signing-key",
            agency_id="synthetic-agency",
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def tearDown(self) -> None:
        self.environment.stop()

    def test_context_swap_and_legacy_unbound_oaep_cannot_unwrap(self) -> None:
        with LocalKmsSimulator(
            agency_id="synthetic-agency", key_id="synthetic-wrap-key"
        ) as client:
            public_key = serialization.load_pem_public_key(
                base64.b64decode(client.public_key()["public_key_pem_b64"])
            )
            context = "a" * 64
            contextual = public_key.encrypt(
                b"d" * 32,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=encrypted.oaep_label_for_context(context),
                ),
            )
            with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                client.unwrap_key(
                    contextual,
                    "synthetic-wrap-key",
                    agency_id="synthetic-agency",
                    request_id="context-swap",
                    context_sha256="b" * 64,
                )
            legacy = public_key.encrypt(
                b"d" * 32,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                client.unwrap_key(
                    legacy,
                    "synthetic-wrap-key",
                    agency_id="synthetic-agency",
                    request_id="legacy-unbound",
                    context_sha256=context,
                )

    def test_unauthorized_or_invalid_envelope_cannot_consume_replay_slot(self) -> None:
        with tempfile.TemporaryDirectory(prefix=".attack-encrypted-queue-") as temporary:
            root = Path(temporary)
            with LocalKmsSimulator(
                agency_id="synthetic-agency", key_id="synthetic-wrap-key"
            ) as client:
                envelope = encrypted.encrypt_batch_package(
                    self.package,
                    wrapping_public_key_pem=base64.b64decode(
                        client.public_key()["public_key_pem_b64"]
                    ),
                    wrapping_key_id="synthetic-wrap-key",
                    agency_id="synthetic-agency",
                )
                path = root / "synthetic.envelope.json"
                encrypted.write_envelope(path, envelope)

                proving_submission.submit_encrypted_batch_package(
                    root / "queue",
                    job_id="synthetic-job",
                    batch_record=self.record,
                    encrypted_envelope_path=path,
                    authenticated_principal="synthetic-operator@example.invalid",
                )
                claims = (
                    root
                    / "queue"
                    / "agencies"
                    / "synthetic-agency"
                    / "package_claims"
                )
                self.assertEqual([], list(claims.iterdir()))

                with self.assertRaisesRegex(RuntimeError, "encrypted_package_rejected"):
                    isolated_proving_worker.decrypt_authorized_package(
                        path,
                        batch_record=self.record,
                        authenticated_principal="attacker@example.invalid",
                        kms_client=client,
                    )
                self.assertEqual([], client.audit_events())

                forged = dict(envelope)
                forged_signature = self.signing_key.sign(
                    b"forged-envelope-authorization",
                    ec.ECDSA(hashes.SHA256()),
                )
                forged["authorization_signature_b64"] = base64.b64encode(
                    forged_signature
                ).decode("ascii")
                forged["envelope_sha256"] = encrypted._sha256(
                    {key: value for key, value in forged.items() if key != "envelope_sha256"}
                )
                forged_path = root / "forged-authorization.envelope.json"
                encrypted.write_envelope(forged_path, forged)
                with self.assertRaisesRegex(RuntimeError, "encrypted_package_rejected"):
                    isolated_proving_worker.decrypt_authorized_package(
                        forged_path,
                        batch_record=self.record,
                        authenticated_principal="synthetic-operator@example.invalid",
                        kms_client=client,
                    )
                self.assertEqual([], client.audit_events())

                invalid = dict(envelope)
                ciphertext = bytearray(base64.b64decode(invalid["ciphertext_b64"]))
                ciphertext[-1] ^= 1
                invalid["ciphertext_b64"] = base64.b64encode(ciphertext).decode("ascii")
                invalid["envelope_sha256"] = encrypted._sha256(
                    {key: value for key, value in invalid.items() if key != "envelope_sha256"}
                )
                invalid_path = root / "invalid.envelope.json"
                encrypted.write_envelope(invalid_path, invalid)
                invalid_queue = root / "invalid-queue"
                with self.assertRaisesRegex(RuntimeError, "encrypted_package_rejected"):
                    isolated_proving_worker.decrypt_authorize_and_reserve(
                        invalid_path,
                        batch_record=self.record,
                        authenticated_principal="synthetic-operator@example.invalid",
                        kms_client=client,
                        queue_root=invalid_queue,
                        job_id="invalid-job",
                    )
                invalid_claims = invalid_queue / "package_claims"
                self.assertEqual(
                    [], list(invalid_claims.iterdir()) if invalid_claims.exists() else []
                )


if __name__ == "__main__":
    unittest.main()
