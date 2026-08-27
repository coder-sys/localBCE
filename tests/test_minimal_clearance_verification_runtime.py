import io
import tempfile
import time
import unittest
from pathlib import Path

from app.minimal_clearance_verification_queue import BatchVerifierResult, OperationTemplate, QueueConfig, VolatileProofHandoff
from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime, VerificationRuntimeError


class _Verifier:
    def __init__(self, config: QueueConfig) -> None:
        self.config = config
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, batch):
        self.calls += 1
        while stream.read(23):
            pass
        return BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", self.config.qualification_flags)


class RuntimeV8Tests(unittest.TestCase):
    def test_runtime_exposes_explicit_batch_and_operation_counters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v8", 100)
            verifier = _Verifier(config)
            with self.assertRaisesRegex(VerificationRuntimeError, "runtime_backend_unqualified"):
                MinimalClearanceVerificationRuntime(root=root)
            with MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config) as runtime:
                now = int(time.time() * 1000)
                template = OperationTemplate("shared-runtime", 1, "state-profile-v8", now - 100, now + 2_000_000)
                with self.assertRaises(TypeError):
                    runtime.issue_batch(template=template, operation_refs=tuple(bytes([index]) * 32 for index in range(100)))  # type: ignore[call-arg]
                batch = runtime.issue_batch(template=template)
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"runtime-proof"), declared_length=13)
                result = runtime.run(max_batches=1)
                self.assertEqual((result.outcome, result.accepted_operation_count, result.verified_batch_count, result.rejected_batch_count, result.held_batch_count, result.processed, verifier.calls), ("PROCESSED", 100, 1, 0, 0, 1, 1))
                self.assertEqual(result.verified, 100)
                empty = runtime.run(max_batches=1)
                self.assertEqual((empty.outcome, empty.accepted_operation_count, empty.verified_batch_count, empty.rejected_batch_count, empty.held_batch_count, empty.processed), ("EMPTY", 0, 0, 0, 0, 0))
                runtime._verify_integrity()

    def test_runtime_startup_failure_releases_lock_and_immediate_retry_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v8-retry", 100)
            verifier = _Verifier(config)
            runtime = MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config)
            runtime.close()
            (root / "queue.sqlite").write_bytes(b"not-a-database")
            with self.assertRaises(VerificationRuntimeError):
                MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config)
            self.assertFalse((root / "queue.sqlite.runtime-lock").exists())
            (root / "queue.sqlite").unlink()
            with MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config) as retry:
                retry._verify_integrity()


if __name__ == "__main__":
    unittest.main()
