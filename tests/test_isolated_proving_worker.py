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

from tools import batch_package
from tools import encrypted_witness_envelope
from tools import isolated_proving_worker
from tools import proving_submission
from tools.local_kms_simulator import LocalKmsSimulator


class IsolatedProvingWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix=".test-isolated-worker-")
        self.root = Path(self.temp.name)
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = self.signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        registry = {
            "signing-a": {
                "public_key_pem_b64": base64.b64encode(public_pem).decode("ascii"),
                "agency_id": "agency-a",
                "status": "active",
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2030-01-01T00:00:00+00:00",
            }
        }
        self.environment = mock.patch.dict(
            os.environ, {batch_package.P256_KEY_REGISTRY_ENV: json.dumps(registry)}
        )
        self.environment.start()
        self.record = proving_submission.create_batch_record(
            batch_id="private-batch",
            agency_id="agency-a",
            claim_count=1,
            expected_output_values=["0x2", "0x1"],
            source_system="authorized-source",
            created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )
        unsigned = batch_package.create_unsigned_batch_package(
            package_id="private-package",
            batch_id="private-batch",
            claim_count=1,
            serialized_arguments_hex_json=["0x50415449454e542d534543524554", "0x1"],
            expected_output=["0x2", "0x1"],
            source_reference=proving_submission.batch_record_source_reference(self.record),
            created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )
        signature = self.signing_key.sign(
            batch_package.batch_package_signing_message(
                unsigned,
                principal="operator@agency.gov",
                key_id="signing-a",
                agency_id="agency-a",
            ),
            ec.ECDSA(hashes.SHA256()),
        )
        self.package = batch_package.authorize_batch_package_p256(
            unsigned,
            principal="operator@agency.gov",
            key_id="signing-a",
            agency_id="agency-a",
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def test_ciphertext_to_authorized_worker_without_plaintext_artifacts(self) -> None:
        with LocalKmsSimulator(agency_id="agency-a", key_id="wrap-a") as client:
            public_pem = base64.b64decode(client.public_key()["public_key_pem_b64"])
            envelope = encrypted_witness_envelope.encrypt_batch_package(
                self.package,
                wrapping_public_key_pem=public_pem,
                wrapping_key_id="wrap-a",
                agency_id="agency-a",
            )
            envelope_path = self.root / "witness.envelope.json"
            encrypted_witness_envelope.write_envelope(envelope_path, envelope)
            package = isolated_proving_worker.decrypt_authorized_package(
                envelope_path,
                batch_record=self.record,
                authenticated_principal="operator@agency.gov",
                kms_client=client,
            )
            self.assertEqual(self.package["package_sha256"], package["package_sha256"])
            stored = "\n".join(
                path.read_text(encoding="utf-8")
                for path in self.root.rglob("*")
                if path.is_file()
            )
            self.assertNotIn("50415449454e542d534543524554", stored)
            self.assertNotIn("serialized_arguments_hex_json", stored)

    def test_wrong_principal_and_wrong_agency_fail_before_proving(self) -> None:
        with LocalKmsSimulator(agency_id="agency-a", key_id="wrap-a") as client:
            envelope = encrypted_witness_envelope.encrypt_batch_package(
                self.package,
                wrapping_public_key_pem=base64.b64decode(client.public_key()["public_key_pem_b64"]),
                wrapping_key_id="wrap-a",
                agency_id="agency-a",
            )
            path = self.root / "witness.envelope.json"
            encrypted_witness_envelope.write_envelope(path, envelope)
            with self.assertRaisesRegex(RuntimeError, "principal does not match"):
                isolated_proving_worker.decrypt_authorized_package(
                    path,
                    batch_record=self.record,
                    authenticated_principal="attacker@agency.gov",
                    kms_client=client,
                )
            self.assertEqual([], client.audit_events())
            wrong_record = dict(self.record)
            wrong_record["agency_id"] = "agency-b"
            wrong_record["record_sha256"] = proving_submission._sha256(
                {k: v for k, v in wrong_record.items() if k != "record_sha256"}
            )
            with self.assertRaisesRegex(RuntimeError, "agency does not match"):
                isolated_proving_worker.decrypt_authorized_package(
                    path,
                    batch_record=wrong_record,
                    authenticated_principal="operator@agency.gov",
                    kms_client=client,
                )
            self.assertEqual([], client.audit_events())

    def test_authenticated_hash_is_reserved_only_after_decrypt_and_inner_authorization(self) -> None:
        with LocalKmsSimulator(agency_id="agency-a", key_id="wrap-a") as client:
            envelope = encrypted_witness_envelope.encrypt_batch_package(
                self.package,
                wrapping_public_key_pem=base64.b64decode(client.public_key()["public_key_pem_b64"]),
                wrapping_key_id="wrap-a",
                agency_id="agency-a",
            )
            path = self.root / "reservation.envelope.json"
            encrypted_witness_envelope.write_envelope(path, envelope)
            queue_root = self.root / "authenticated-queue"
            first = isolated_proving_worker.decrypt_authorize_and_reserve(
                path,
                batch_record=self.record,
                authenticated_principal="operator@agency.gov",
                kms_client=client,
                queue_root=queue_root,
                job_id="job-a",
            )
            self.assertEqual(self.package["package_sha256"], first["package_sha256"])
            reservation = queue_root / "package_claims" / self.package["package_sha256"]
            self.assertTrue(reservation.is_file())

            isolated_proving_worker.decrypt_authorize_and_reserve(
                path,
                batch_record=self.record,
                authenticated_principal="operator@agency.gov",
                kms_client=client,
                queue_root=queue_root,
                job_id="job-a",
            )
            with self.assertRaisesRegex(RuntimeError, "replay rejected"):
                isolated_proving_worker.decrypt_authorize_and_reserve(
                    path,
                    batch_record=self.record,
                    authenticated_principal="operator@agency.gov",
                    kms_client=client,
                    queue_root=queue_root,
                    job_id="job-b",
                )

            invalid = dict(envelope)
            ciphertext = bytearray(base64.b64decode(invalid["ciphertext_b64"], validate=True))
            ciphertext[-1] ^= 1
            invalid["ciphertext_b64"] = base64.b64encode(ciphertext).decode("ascii")
            invalid["envelope_sha256"] = encrypted_witness_envelope._sha256(
                {key: value for key, value in invalid.items() if key != "envelope_sha256"}
            )
            invalid_path = self.root / "invalid.envelope.json"
            encrypted_witness_envelope.write_envelope(invalid_path, invalid)
            invalid_queue = self.root / "invalid-queue"
            with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                isolated_proving_worker.decrypt_authorize_and_reserve(
                    invalid_path,
                    batch_record=self.record,
                    authenticated_principal="operator@agency.gov",
                    kms_client=client,
                    queue_root=invalid_queue,
                    job_id="invalid-job",
                )
            claims = invalid_queue / "package_claims"
            self.assertEqual([], list(claims.iterdir()) if claims.exists() else [])

    def test_proof_failure_propagates_and_pipe_payload_is_not_a_command_argument(self) -> None:
        process = mock.Mock(returncode=9)
        containment = mock.Mock()
        with mock.patch.object(
            isolated_proving_worker,
            "_start_contained_process",
            return_value=(process, containment),
        ) as start:
            self.assertEqual(
                9,
                isolated_proving_worker.run_proof_with_pipe(
                    self.package,
                    output_dir=self.root / "proof",
                    threads=8,
                    policy_path=self.root / "trusted-policy.json",
                    ram_token="a" * 32,
                ),
            )
        command = start.call_args.args[0]
        self.assertNotIn("serialized_arguments_hex_json", " ".join(command))
        self.assertIn("a" * 32, command)
        self.assertIn(str(self.root / "trusted-policy.json"), command)
        self.assertIsNotNone(process.communicate.call_args.kwargs["input"])
        containment.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
