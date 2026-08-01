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
from tools import proving_submission


class ProvingSubmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.registry = {
            "agency-a-key-1": {
                "public_key_pem_b64": base64.b64encode(public_pem).decode("ascii"),
                "agency_id": "agency-a",
                "status": "active",
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2030-01-01T00:00:00+00:00",
            }
        }
        self.environment = mock.patch.dict(
            os.environ,
            {batch_package.P256_KEY_REGISTRY_ENV: json.dumps(self.registry)},
        )
        self.environment.start()
        self.temporary = tempfile.TemporaryDirectory(prefix=".test-proving-submission-")
        self.root = Path(self.temporary.name)
        self.record = proving_submission.create_batch_record(
            batch_id="batch-real-001",
            agency_id="agency-a",
            claim_count=1,
            expected_output_values=["0x2", "0x1"],
            source_system="authorized-adjudication-service",
            created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.environment.stop()

    def _package_path(
        self,
        *,
        outputs: list[str] | None = None,
        agency_id: str = "agency-a",
    ) -> Path:
        unsigned = batch_package.create_unsigned_batch_package(
            package_id="real-package-001",
            batch_id="batch-real-001",
            claim_count=1,
            serialized_arguments_hex_json=["0xa", "0xb"],
            expected_output=outputs or ["0x2", "0x1"],
            source_reference=proving_submission.batch_record_source_reference(self.record),
            created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )
        message = batch_package.batch_package_signing_message(
            unsigned,
            principal="operator@agency.gov",
            key_id="agency-a-key-1",
            agency_id=agency_id,
        )
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        package = batch_package.authorize_batch_package_p256(
            unsigned,
            principal="operator@agency.gov",
            key_id="agency-a-key-1",
            agency_id=agency_id,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )
        path = self.root / f"package-{agency_id}-{len(outputs or [])}.json"
        batch_package.write_batch_package(path, package)
        return path

    def _submit(self, path: Path, *, actor: str = "operator@agency.gov", job_id: str = "job-1") -> dict:
        return proving_submission.submit_batch_package(
            self.root / "queue",
            job_id=job_id,
            batch_record=self.record,
            batch_package_path=path,
            authenticated_principal=actor,
            threads=8,
            max_attempts=2,
            timeout_seconds=300,
        )

    def test_authorized_batch_is_bound_and_routed_to_its_agency_queue(self) -> None:
        status = self._submit(self._package_path())
        self.assertEqual("queued", status["state"])
        self.assertEqual("agency-a", Path(status["agency_queue_root"]).name)

    def test_wrong_principal_and_changed_public_outputs_are_rejected(self) -> None:
        path = self._package_path()
        with self.assertRaisesRegex(RuntimeError, "principal does not match"):
            self._submit(path, actor="attacker@agency.gov")

        changed = self._package_path(outputs=["0x2", "0x9"])
        with self.assertRaisesRegex(RuntimeError, "public outputs do not match"):
            self._submit(changed)

    def test_cross_agency_key_use_and_package_replay_are_rejected(self) -> None:
        registry = json.loads(json.dumps(self.registry))
        registry["agency-a-key-1"]["agency_id"] = "agency-b"
        with mock.patch.dict(
            os.environ, {batch_package.P256_KEY_REGISTRY_ENV: json.dumps(registry)}
        ):
            with self.assertRaisesRegex(RuntimeError, "does not own the key"):
                self._package_path(agency_id="agency-a")

        path = self._package_path()
        self._submit(path)
        with self.assertRaisesRegex(RuntimeError, "replay rejected"):
            self._submit(path, job_id="job-2")

    def test_tampered_batch_record_is_rejected_before_queueing(self) -> None:
        path = self._package_path()
        tampered = dict(self.record)
        tampered["claim_count"] = 2
        with self.assertRaisesRegex(RuntimeError, "integrity check failed"):
            proving_submission.submit_batch_package(
                self.root / "queue",
                job_id="tampered-record",
                batch_record=tampered,
                batch_package_path=path,
                authenticated_principal="operator@agency.gov",
                threads=8,
                max_attempts=2,
                timeout_seconds=300,
            )

    def test_future_and_expired_packages_are_rejected_before_queueing(self) -> None:
        future_record = proving_submission.create_batch_record(
            batch_id="batch-future-001",
            agency_id="agency-a",
            claim_count=1,
            expected_output_values=["0x2", "0x1"],
            source_system="authorized-adjudication-service",
            created_at=datetime(2029, 1, 1, tzinfo=timezone.utc),
        )
        unsigned = batch_package.create_unsigned_batch_package(
            package_id="future-package-001",
            batch_id="batch-future-001",
            claim_count=1,
            serialized_arguments_hex_json=["0xa", "0xb"],
            expected_output=["0x2", "0x1"],
            source_reference=proving_submission.batch_record_source_reference(future_record),
            created_at=datetime(2029, 1, 1, tzinfo=timezone.utc),
        )
        message = batch_package.batch_package_signing_message(
            unsigned,
            principal="operator@agency.gov",
            key_id="agency-a-key-1",
            agency_id="agency-a",
        )
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        package = batch_package.authorize_batch_package_p256(
            unsigned,
            principal="operator@agency.gov",
            key_id="agency-a-key-1",
            agency_id="agency-a",
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )
        path = self.root / "future-package.json"
        batch_package.write_batch_package(path, package)
        with self.assertRaisesRegex(RuntimeError, "creation time is in the future"):
            proving_submission.submit_batch_package(
                self.root / "queue",
                job_id="future-job",
                batch_record=future_record,
                batch_package_path=path,
                authenticated_principal="operator@agency.gov",
                threads=8,
                max_attempts=2,
                timeout_seconds=300,
            )

        expired_record = proving_submission.create_batch_record(
            batch_id="batch-expired-001",
            agency_id="agency-a",
            claim_count=1,
            expected_output_values=["0x2", "0x1"],
            source_system="authorized-adjudication-service",
            created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        expired_unsigned = batch_package.create_unsigned_batch_package(
            package_id="expired-package-001",
            batch_id="batch-expired-001",
            claim_count=1,
            serialized_arguments_hex_json=["0xa", "0xb"],
            expected_output=["0x2", "0x1"],
            source_reference=proving_submission.batch_record_source_reference(expired_record),
            retention_days=1,
            created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        expired_message = batch_package.batch_package_signing_message(
            expired_unsigned,
            principal="operator@agency.gov",
            key_id="agency-a-key-1",
            agency_id="agency-a",
        )
        expired_signature = self.private_key.sign(
            expired_message, ec.ECDSA(hashes.SHA256())
        )
        expired_package = batch_package.authorize_batch_package_p256(
            expired_unsigned,
            principal="operator@agency.gov",
            key_id="agency-a-key-1",
            agency_id="agency-a",
            signature_b64=base64.b64encode(expired_signature).decode("ascii"),
        )
        expired_path = self.root / "expired-package.json"
        batch_package.write_batch_package(expired_path, expired_package)
        with self.assertRaisesRegex(RuntimeError, "retention window has expired"):
            proving_submission.submit_batch_package(
                self.root / "queue",
                job_id="expired-job",
                batch_record=expired_record,
                batch_package_path=expired_path,
                authenticated_principal="operator@agency.gov",
                threads=8,
                max_attempts=2,
                timeout_seconds=300,
            )

    def test_plaintext_witness_package_is_rejected_in_production(self) -> None:
        path = self._package_path()
        with mock.patch.dict(os.environ, {"BL_ENV": "production"}):
            with self.assertRaisesRegex(RuntimeError, "encrypted witness envelope"):
                self._submit(path)


if __name__ == "__main__":
    unittest.main()
