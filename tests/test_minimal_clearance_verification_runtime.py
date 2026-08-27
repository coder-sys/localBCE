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
    def test_runtime_exposes_only_batch_issue_then_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v8", 100)
            verifier = _Verifier(config)
            with self.assertRaisesRegex(VerificationRuntimeError, "runtime_backend_unqualified"):
                MinimalClearanceVerificationRuntime(root=root)
            with MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config) as runtime:
                now = int(time.time() * 1000)
                templates = tuple(OperationTemplate(f"assertion-{index}", 1, "state-profile-v8", now - 100, now + 2_000_000) for index in range(100))
                batch = runtime.issue_batch(templates=templates)
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"runtime-proof"), declared_length=13)
                result = runtime.run(max_batches=1)
                self.assertEqual((result.outcome, result.accepted_count, result.processed, verifier.calls), ("PROCESSED", 100, 100, 1))
                for name in ("issue_operation", "submit_handoff", "submit_batch_handoffs"):
                    self.assertFalse(hasattr(runtime, name), name)
                runtime._verify_integrity()

    def test_runtime_restart_holds_queued_batch_without_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v8-restart", 100)
            verifier = _Verifier(config)
            runtime = MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config)
            now = int(time.time() * 1000)
            templates = tuple(OperationTemplate(f"restart-{index}", 1, "state-profile-v8", now - 100, now + 2_000_000) for index in range(100))
            batch = runtime.issue_batch(templates=templates)
            runtime.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"restart-proof"), declared_length=13)
            runtime.close()
            restarted = MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config)
            try:
                self.assertEqual(restarted.run(max_batches=1).outcome, "EMPTY")
                restarted._verify_integrity()
            finally:
                restarted.close()


if __name__ == "__main__":
    unittest.main()
