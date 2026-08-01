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
from cryptography.hazmat.primitives.asymmetric import ec

from tools import batch_package, encrypted_witness_envelope, proving_submission
from tools.local_kms_simulator import LocalKmsSimulator


class EncryptedProvingSubmissionTests(unittest.TestCase):
    def test_queue_snapshot_contains_ciphertext_and_defers_replay_reservation(self) -> None:
        with tempfile.TemporaryDirectory(prefix=".test-encrypted-submit-") as temporary:
            root = Path(temporary)
            signing_key = ec.generate_private_key(ec.SECP256R1())
            signing_public = signing_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            registry = {
                "signing-a": {
                    "public_key_pem_b64": base64.b64encode(signing_public).decode("ascii"),
                    "agency_id": "agency-a",
                    "status": "active",
                    "not_before": "2026-01-01T00:00:00+00:00",
                    "not_after": "2030-01-01T00:00:00+00:00",
                }
            }
            with mock.patch.dict(
                os.environ, {batch_package.P256_KEY_REGISTRY_ENV: json.dumps(registry)}
            ), LocalKmsSimulator(agency_id="agency-a", key_id="wrap-a") as kms:
                record = proving_submission.create_batch_record(
                    batch_id="batch-a",
                    agency_id="agency-a",
                    claim_count=1,
                    expected_output_values=["0x2", "0x1"],
                    source_system="source",
                    created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
                )
                unsigned = batch_package.create_unsigned_batch_package(
                    package_id="package-a",
                    batch_id="batch-a",
                    claim_count=1,
                    serialized_arguments_hex_json=["0x534543524554", "0x1"],
                    expected_output=["0x2", "0x1"],
                    source_reference=proving_submission.batch_record_source_reference(record),
                    created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
                )
                signature = signing_key.sign(
                    batch_package.batch_package_signing_message(
                        unsigned,
                        principal="operator@agency.gov",
                        key_id="signing-a",
                        agency_id="agency-a",
                    ),
                    ec.ECDSA(hashes.SHA256()),
                )
                package = batch_package.authorize_batch_package_p256(
                    unsigned,
                    principal="operator@agency.gov",
                    key_id="signing-a",
                    agency_id="agency-a",
                    signature_b64=base64.b64encode(signature).decode("ascii"),
                )
                envelope = encrypted_witness_envelope.encrypt_batch_package(
                    package,
                    wrapping_public_key_pem=base64.b64decode(
                        kms.public_key()["public_key_pem_b64"]
                    ),
                    wrapping_key_id="wrap-a",
                    agency_id="agency-a",
                )
                path = root / "incoming.envelope.json"
                encrypted_witness_envelope.write_envelope(path, envelope)
                status = proving_submission.submit_encrypted_batch_package(
                    root / "queue",
                    job_id="job-a",
                    batch_record=record,
                    encrypted_envelope_path=path,
                    authenticated_principal="operator@agency.gov",
                    threads=8,
                    max_attempts=2,
                    timeout_seconds=300,
                )
                self.assertEqual("queued", status["state"])
                queue_text = "\n".join(
                    item.read_text(encoding="utf-8")
                    for item in (root / "queue").rglob("*")
                    if item.is_file()
                )
                self.assertNotIn("534543524554", queue_text)
                self.assertNotIn("serialized_arguments_hex_json", queue_text)
                agency_queue = root / "queue" / "agencies" / "agency-a"
                self.assertEqual([], list((agency_queue / "package_claims").iterdir()))

                duplicate = proving_submission.submit_encrypted_batch_package(
                    root / "queue",
                    job_id="job-b",
                    batch_record=record,
                    encrypted_envelope_path=path,
                    authenticated_principal="operator@agency.gov",
                    threads=8,
                    max_attempts=2,
                    timeout_seconds=300,
                )
                self.assertEqual("queued", duplicate["state"])
                self.assertEqual([], list((agency_queue / "package_claims").iterdir()))

                with self.assertRaisesRegex(RuntimeError, "principal does not match"):
                    proving_submission.submit_encrypted_batch_package(
                        root / "queue",
                        job_id="job-attacker",
                        batch_record=record,
                        encrypted_envelope_path=path,
                        authenticated_principal="attacker@agency.gov",
                        threads=8,
                        max_attempts=2,
                        timeout_seconds=300,
                    )
                self.assertFalse((agency_queue / "jobs" / "job-attacker").exists())


if __name__ == "__main__":
    unittest.main()
