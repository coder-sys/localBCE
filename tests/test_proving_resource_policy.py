from __future__ import annotations

import inspect
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import isolated_proving_worker, proving_job_runner, proving_submission
from tools import proving_process_boundary
from tools.proving_resource_policy import (
    MAX_ATTEMPTS,
    MAX_AUDIT_BYTES,
    MAX_AUDIT_EVENTS,
    MAX_AUDIT_LINE_BYTES,
    MAX_JOB_BYTES,
    MAX_NONTERMINAL_JOBS,
    MAX_OWNED_FILES,
    MAX_QUEUE_BYTES,
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    MAX_TOTAL_JOBS,
    TIMEOUT_SECONDS,
    WINDOWS_JOB_MEMORY_CAP_BYTES,
    ProvingResourcePolicyError,
    derive_policy,
    policy_file_bytes,
    read_policy_file,
)


class ProvingResourcePolicyTests(unittest.TestCase):
    def test_policy_is_exact_and_environment_only_controls_threads(self) -> None:
        policy = derive_policy({"BL_PROVER_THREADS": "7"})
        self.assertEqual(7, policy.threads)
        self.assertEqual(MAX_ATTEMPTS, policy.max_attempts)
        self.assertEqual(TIMEOUT_SECONDS, policy.timeout_seconds)
        self.assertEqual(WINDOWS_JOB_MEMORY_CAP_BYTES, policy.windows_job_memory_cap_bytes)
        self.assertEqual(MAX_NONTERMINAL_JOBS, policy.max_nonterminal_jobs)
        self.assertEqual(MAX_TOTAL_JOBS, policy.max_total_jobs)
        self.assertEqual(MAX_JOB_BYTES, policy.max_job_bytes)
        self.assertEqual(MAX_QUEUE_BYTES, policy.max_queue_bytes)
        self.assertEqual(MAX_OWNED_FILES, policy.max_owned_files)
        self.assertEqual(MAX_AUDIT_BYTES, policy.max_audit_bytes)
        self.assertEqual(MAX_AUDIT_EVENTS, policy.max_audit_events)
        self.assertEqual(MAX_AUDIT_LINE_BYTES, policy.max_audit_line_bytes)
        self.assertEqual(MAX_STDOUT_BYTES, policy.max_stdout_bytes)
        self.assertEqual(MAX_STDERR_BYTES, policy.max_stderr_bytes)
        for value in ("0", "33", "not-an-integer"):
            with self.assertRaises(ProvingResourcePolicyError):
                derive_policy({"BL_PROVER_THREADS": value})

    def test_policy_file_is_canonical_and_bounded(self) -> None:
        policy = derive_policy({"BL_PROVER_THREADS": "1"})
        with tempfile.TemporaryDirectory(prefix=".test-resource-policy-") as temporary:
            path = Path(temporary) / "resource-policy.json"
            path.write_bytes(policy_file_bytes(policy))
            self.assertEqual(policy, read_policy_file(path))
            path.write_bytes(path.read_bytes() + b"x" * 20_000)
            with self.assertRaisesRegex(ProvingResourcePolicyError, "proving_policy_file_cap"):
                read_policy_file(path)

    def test_public_submission_surfaces_have_no_legacy_resource_knobs(self) -> None:
        for function in (
            proving_job_runner.enqueue_job,
            proving_job_runner.enqueue_package_job,
            proving_job_runner.enqueue_encrypted_package_job,
            proving_submission.submit_batch_package,
            proving_submission.submit_encrypted_batch_package,
            isolated_proving_worker.run_proof_with_pipe,
        ):
            parameters = inspect.signature(function).parameters
            self.assertNotIn("threads", parameters)
            self.assertNotIn("max_attempts", parameters)
            self.assertNotIn("timeout_seconds", parameters)

    def test_admission_is_bounded_and_public_errors_redact_hostile_failures(self) -> None:
        with tempfile.TemporaryDirectory(prefix=".test-proving-admission-") as temporary:
            queue_root = Path(temporary) / "queue"
            for index in range(MAX_NONTERMINAL_JOBS):
                proving_job_runner.enqueue_job(
                    queue_root,
                    job_id=f"bounded-{index:02d}",
                    claim_count=1,
                )
            with self.assertRaisesRegex(RuntimeError, "queue_nonterminal_capacity"):
                proving_job_runner.enqueue_job(
                    queue_root,
                    job_id="bounded-overflow",
                    claim_count=1,
                )
            self.assertEqual(
                MAX_NONTERMINAL_JOBS,
                proving_job_runner._measure_queue(
                    proving_job_runner._prepare_queue_root(queue_root),
                    derive_policy({"BL_PROVER_THREADS": "1"}),
                )[3],
            )

            with mock.patch.object(
                proving_job_runner,
                "_enqueue_request",
                side_effect=RuntimeError("PHI SECRET C:\\private\\credential"),
            ):
                with self.assertRaisesRegex(RuntimeError, "queue_request_rejected") as caught:
                    proving_job_runner.enqueue_job(
                        Path(temporary) / "other-queue",
                        job_id="hostile",
                        claim_count=1,
                    )
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn("PHI", repr(caught.exception))
            self.assertNotIn("credential", repr(caught.exception))

    def test_contained_process_reports_bounded_telemetry_only(self) -> None:
        policy = derive_policy({"BL_PROVER_THREADS": "1"})
        result = proving_process_boundary.run_contained_process(
            [sys.executable, "-c", 'print("bounded-output")'],
            cwd=proving_job_runner.ROOT,
            policy=policy,
        )
        self.assertEqual(0, result.exit_code)
        self.assertGreater(result.stdout_bytes, 0)
        self.assertEqual(0, result.stderr_bytes)
        self.assertTrue(result.tree_confirmed)
        if proving_process_boundary.os.name == "nt":
            self.assertTrue(result.cap_enforced)
            self.assertEqual(WINDOWS_JOB_MEMORY_CAP_BYTES, result.cap_bytes)
        else:
            self.assertFalse(result.cap_enforced)

    def test_contained_process_stops_output_overflow(self) -> None:
        policy = derive_policy({"BL_PROVER_THREADS": "1"})
        result = proving_process_boundary.run_contained_process(
            [sys.executable, "-c", 'print("x" * (2 * 1024 * 1024))'],
            cwd=proving_job_runner.ROOT,
            policy=policy,
        )
        self.assertTrue(result.output_overflow)
        self.assertLessEqual(result.stdout_bytes, MAX_STDOUT_BYTES)
        self.assertTrue(result.tree_confirmed)


if __name__ == "__main__":
    unittest.main()
