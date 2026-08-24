from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timezone
import os

from tools import proving_job_runner as runner
from tools import batch_package
from tools import proving_evidence_policy as evidence_policy
from tests.proving_policy_fixtures import trusted_policy


class ProvingJobRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._environment = mock.patch.dict(
            os.environ,
            {
                batch_package.SUBMISSION_KEY_ENV: "test-submission-key-material-00000001",
                batch_package.SUBMISSION_KEY_ID_ENV: "test-key-1",
            },
        )
        self._environment.start()
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".test-proving-queue-",
            dir=runner.ROOT.parent,
        )
        self.queue_root = Path(self._temporary.name) / "queue"

    def tearDown(self) -> None:
        self._temporary.cleanup()
        self._environment.stop()

    def _enqueue(self, *, job_id: str = "job-001") -> dict:
        return runner.enqueue_job(
            self.queue_root,
            job_id=job_id,
            claim_count=1,
        )

    def _package_path(self) -> Path:
        package = batch_package.create_batch_package(
            package_id="package-001",
            batch_id="batch-001",
            claim_count=1,
            serialized_arguments_hex_json=["0x1", "0x2"],
            expected_output=["0x3", "0x4"],
            principal="operator@example.gov",
            source_reference="ingestion-receipt-001",
            created_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        )
        path = self.queue_root.parent / "package.json"
        batch_package.write_batch_package(path, package)
        return path

    def test_enqueue_binds_status_to_immutable_request_hash(self) -> None:
        status = self._enqueue()
        request_path = self.queue_root / "jobs" / "job-001" / "request.json"
        request = json.loads(request_path.read_text(encoding="utf-8"))

        runner._validate_request(request, request_path)
        self.assertEqual("queued", status["state"])
        self.assertEqual(request["request_sha256"], status["request_sha256"])
        self.assertEqual(8, request["resource_policy"]["threads"])

    def test_duplicate_job_id_is_never_overwritten(self) -> None:
        self._enqueue()
        with self.assertRaisesRegex(RuntimeError, "queue_duplicate_job"):
            self._enqueue()

    def test_tampered_request_fails_integrity_check(self) -> None:
        self._enqueue()
        request_path = self.queue_root / "jobs" / "job-001" / "request.json"
        request = json.loads(request_path.read_text(encoding="utf-8"))
        request["resource_policy"]["threads"] = 16

        with self.assertRaisesRegex(RuntimeError, "queue_request_integrity"):
            runner._validate_request(request, request_path)

    def test_queue_root_inside_source_tree_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "queue_root_inside_source"):
            runner._prepare_queue_root(runner.ROOT / ".forbidden-proving-queue")

    def test_exclusive_lock_rejects_a_second_runner(self) -> None:
        root = runner._prepare_queue_root(self.queue_root)
        with runner._QueueLock(root):
            with self.assertRaisesRegex(RuntimeError, "queue_runner_locked"):
                with runner._QueueLock(root):
                    self.fail("a second proof runner acquired the same queue")

    def test_success_manifest_is_bound_to_the_exact_proof_file(self) -> None:
        attempt_dir = self.queue_root / "attempt"
        attempt_dir.mkdir(parents=True)
        proof_path = attempt_dir / "proof.json"
        proof_path.write_bytes(b"verified-proof-bytes")
        policy = trusted_policy(self.queue_root.parent / "trusted-policy.json")
        bindings = evidence_policy.trusted_manifest_bindings(policy)
        manifest = {
            "status": "independently_verified",
            "evidence_scope": evidence_policy.POLICY_PURPOSE,
            "evidence_policy": {
                "storage_key": "trusted-evidence-policy",
                "registry_sha3_512": policy.registry_sha3_512,
                "sha3_512": policy.sha3_512,
            },
            "trusted_provenance": bindings,
            "semantic_output_match": True,
            "independent_verifier": True,
            "verification_interface": evidence_policy.VERIFIER_INTERFACE,
            "verification_success_marker": True,
            "production_verifier_claimed": False,
            "settlement_contract_verification_run": False,
            "protected_source_manifest_sha3_512_before": bindings[
                "source_manifest_sha3_512"
            ],
            "protected_source_manifest_sha3_512_after": bindings[
                "source_manifest_sha3_512"
            ],
            "proof": {
                "path": "proof.json",
                "bytes": proof_path.stat().st_size,
                "sha256": runner._sha256_file(proof_path),
                "sha3_512": evidence_policy.sha3_512_file(proof_path),
            },
        }
        runner._write_json_atomic(attempt_dir / "run_manifest.json", manifest)

        result = runner._validate_success_manifest(attempt_dir, policy)
        self.assertTrue(result["semantic_output_match"])
        self.assertTrue(result["protected_source_unchanged"])
        self.assertTrue(result["independent_verifier"])

        proof_path.write_bytes(b"tampered-proof-bytes")
        with self.assertRaisesRegex(RuntimeError, "queue_manifest_proof_binding"):
            runner._validate_success_manifest(attempt_dir, policy)

    def test_child_authored_equal_provenance_is_not_trusted(self) -> None:
        attempt_dir = self.queue_root / "untrusted-attempt"
        attempt_dir.mkdir(parents=True)
        proof_path = attempt_dir / "proof.json"
        proof_path.write_bytes(b"attacker-controlled-proof-bytes")
        runner._write_json_atomic(
            attempt_dir / "run_manifest.json",
            {
                "status": "generated_and_verified",
                "semantic_output_match": True,
                "verification_success_marker": True,
                "settlement_contract_verification_run": False,
                "protected_source_manifest_before": "f" * 64,
                "protected_source_manifest_after": "f" * 64,
                "proof": {
                    "path": "proof.json",
                    "bytes": proof_path.stat().st_size,
                    "sha256": runner._sha256_file(proof_path),
                },
            },
        )

        with self.assertRaisesRegex(RuntimeError, "queue_evidence_policy_required"):
            runner._validate_success_manifest(attempt_dir)

    def test_transient_failure_retries_but_permanent_failure_does_not(self) -> None:
        self._enqueue(job_id="retry-job")
        verified_result = {
            "proof_sha256": "b" * 64,
            "proof_storage_key": "proof.json",
            "manifest_storage_key": "run_manifest.json",
            "settlement_contract_verification_run": False,
        }
        with mock.patch.object(
            runner,
            "_run_attempt",
            side_effect=[
                (False, True, {"failure_class": "timeout", "error_code": "timeout"}),
                (True, False, verified_result),
            ],
        ) as run_attempt:
            retry_status = runner.run_next_job(self.queue_root)

        self.assertIsNotNone(retry_status)
        self.assertEqual("succeeded", retry_status["state"])
        self.assertEqual(2, len(retry_status["attempts"]))
        self.assertEqual(2, run_attempt.call_count)

        self._enqueue(job_id="permanent-job")
        with mock.patch.object(
            runner,
            "_run_attempt",
            return_value=(
                False,
                False,
                {"failure_class": "verification_manifest", "error_code": "verification_manifest"},
            ),
        ) as run_attempt:
            permanent_status = runner.run_next_job(self.queue_root)

        self.assertIsNotNone(permanent_status)
        self.assertEqual("failed", permanent_status["state"])
        self.assertEqual(1, len(permanent_status["attempts"]))
        self.assertEqual(1, run_attempt.call_count)

    def test_signed_package_is_snapshotted_and_bound_to_the_request(self) -> None:
        status = runner.enqueue_package_job(
            self.queue_root,
            job_id="real-batch-job",
            batch_package_path=self._package_path(),
        )
        request_path = self.queue_root / "jobs" / "real-batch-job" / "request.json"
        request = json.loads(request_path.read_text(encoding="utf-8"))
        runner._validate_request(request, request_path)
        self.assertEqual("batch_package", request["input_kind"])
        self.assertEqual("operator@example.gov", request["authorized_principal"])
        self.assertEqual(request["request_sha256"], status["request_sha256"])

        snapshot = request_path.with_name("batch_package.json")
        package = json.loads(snapshot.read_text(encoding="utf-8"))
        package["witness"]["serialized_arguments_hex_json"][0] = "0x9"
        snapshot.write_text(json.dumps(package), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "queue_package_invalid"):
            runner._validate_request(request, request_path)

    def test_hash_chained_audit_log_detects_tampering(self) -> None:
        self._enqueue()
        events = runner._verified_audit_events(self.queue_root)
        self.assertEqual("job_enqueued", events[0]["event_type"])
        audit_path = self.queue_root / "audit.jsonl"
        tampered = json.loads(audit_path.read_text(encoding="utf-8"))
        tampered["details"]["job_id"] = "forged"
        audit_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "queue_audit_integrity"):
            runner._verified_audit_events(self.queue_root)

    def test_stale_local_audit_lock_is_recovered_but_live_lock_is_not(self) -> None:
        root = runner._prepare_queue_root(self.queue_root)
        lock_path = root / ".audit.lock"
        runner._write_json_atomic(
            lock_path,
            {
                "pid": 999999999,
                "hostname": runner.socket.gethostname(),
                "started_at": runner._utc_now(),
            },
        )
        with mock.patch.object(runner, "_process_is_alive", return_value=False):
            runner._append_audit_event(root, "recovery_test", {"result": "recovered"})
        self.assertFalse(lock_path.exists())
        self.assertEqual("recovery_test", runner._verified_audit_events(root)[0]["event_type"])

        with runner._AuditLock(root):
            with self.assertRaisesRegex(RuntimeError, "queue_audit_locked"):
                with runner._AuditLock(root):
                    self.fail("a second audit writer acquired a live lock")

    def test_process_probe_recognizes_the_current_windows_process_without_signaling_it(self) -> None:
        self.assertTrue(runner._process_is_alive(os.getpid()))

    def test_job_without_matching_enqueue_audit_event_is_never_run(self) -> None:
        self._enqueue()
        (self.queue_root / "audit.jsonl").unlink()
        with mock.patch.object(runner, "_run_attempt") as run_attempt:
            with self.assertRaisesRegex(RuntimeError, "queue_enqueue_audit_binding"):
                runner.run_next_job(self.queue_root)
        run_attempt.assert_not_called()

    def test_interrupted_attempt_is_recovered_without_overwriting_it(self) -> None:
        self._enqueue()
        status_path = self.queue_root / "jobs" / "job-001" / "status.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        runner._update_status(status_path, status, state="running", active_attempt=1)
        with mock.patch.object(
            runner,
            "_run_attempt",
            return_value=(
                True,
                False,
                {
                    "proof_sha256": "b" * 64,
                    "proof_storage_key": "proof.json",
                    "manifest_storage_key": "run_manifest.json",
                    "settlement_contract_verification_run": False,
                },
            ),
        ) as run_attempt:
            recovered = runner.run_next_job(self.queue_root)
        self.assertEqual("succeeded", recovered["state"])
        self.assertEqual([1, 2], [item["attempt"] for item in recovered["attempts"]])
        run_attempt.assert_called_once()

    def test_retention_is_report_only_and_never_deletes_evidence(self) -> None:
        runner.enqueue_package_job(
            self.queue_root,
            job_id="retained-job",
            batch_package_path=self._package_path(),
        )
        report = runner.retention_report(
            self.queue_root, now=datetime(2040, 1, 1, tzinfo=timezone.utc)
        )
        self.assertTrue(report[0]["retention_expired"])
        self.assertFalse(report[0]["deletion_performed"])
        self.assertTrue((self.queue_root / "jobs" / "retained-job").is_dir())

    def test_same_package_cannot_be_enqueued_twice_under_different_job_ids(self) -> None:
        package_path = self._package_path()
        runner.enqueue_package_job(
            self.queue_root,
            job_id="first-package-job",
            batch_package_path=package_path,
        )
        with self.assertRaisesRegex(RuntimeError, "queue_package_replay"):
            runner.enqueue_package_job(
                self.queue_root,
                job_id="replayed-package-job",
                batch_package_path=package_path,
            )

    def test_authenticated_reservation_is_atomic_and_same_job_idempotent(self) -> None:
        root = runner._prepare_queue_root(self.queue_root)
        package_sha256 = "d" * 64
        runner._reserve_package_once(root, package_sha256, "job-a")
        runner._reserve_package_once(root, package_sha256, "job-a")
        reservation = json.loads(
            (root / "package_claims" / package_sha256).read_text(encoding="utf-8")
        )
        self.assertEqual("job-a", reservation["job_id"])
        self.assertEqual(package_sha256, reservation["package_sha256"])
        with self.assertRaisesRegex(RuntimeError, "queue_package_replay"):
            runner._reserve_package_once(root, package_sha256, "job-b")

    def test_production_refuses_direct_plaintext_package_queue_bypass(self) -> None:
        package_path = self._package_path()
        with mock.patch.dict(os.environ, {"BL_ENV": "production"}):
            with self.assertRaisesRegex(RuntimeError, "queue_plaintext_production"):
                runner.enqueue_package_job(
                    self.queue_root,
                    job_id="forbidden-production-job",
                    batch_package_path=package_path,
                )


if __name__ == "__main__":
    unittest.main()
