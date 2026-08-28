import io
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app.minimal_clearance_source_auth_verifier_adapter import (
    MinimalClearanceSourceAuthVerifierAdapter,
    SourceAuthVerifierConfig,
)
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


class RuntimeV9Tests(unittest.TestCase):
    def _source_auth_config(self, root: Path) -> SourceAuthVerifierConfig:
        return SourceAuthVerifierConfig(
            queue_config=QueueConfig("runtime-v9-source-auth", 100),
            executable_path=root / "blind-source-auth-v4.exe",
            executable_size_bytes=50_688,
            executable_sha256=bytes.fromhex("68373B03EF32E4FCC9A87B99851C84F4A8158AEB32D189F23DDA3393775AABB2"),
            workspace=root,
            ml_dsa_87_public_key=bytes(2_592),
            timeout_seconds=30.0,
        )

    def test_from_source_auth_constructs_one_adapter_and_delegates_exact_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._source_auth_config(root)
            with patch("app.minimal_clearance_verification_runtime.MinimalClearanceSourceAuthVerifierAdapter") as adapter_factory, patch.object(MinimalClearanceVerificationRuntime, "__init__", return_value=None) as generic_constructor:
                runtime = MinimalClearanceVerificationRuntime.from_source_auth(root=root, source_auth_config=config)
            adapter_factory.assert_called_once_with(config)
            generic_constructor.assert_called_once_with(root=root, verifier=adapter_factory.return_value, config=config.queue_config)
            self.assertIsInstance(runtime, MinimalClearanceVerificationRuntime)

    def test_from_source_auth_is_a_real_nonactivating_production_construction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._source_auth_config(root)
            with MinimalClearanceVerificationRuntime.from_source_auth(root=root, source_auth_config=config) as runtime:
                self.assertIs(type(runtime._verifier), MinimalClearanceSourceAuthVerifierAdapter)
                self.assertIs(runtime._store.config, config.queue_config)
                self.assertEqual(runtime._verifier.config.executable_size_bytes, 50_688)
                self.assertEqual(runtime._verifier.config.executable_sha256, bytes.fromhex("68373B03EF32E4FCC9A87B99851C84F4A8158AEB32D189F23DDA3393775AABB2"))

    def test_source_auth_config_cannot_omit_executable_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v9-required-pin", 100)
            with self.assertRaises(TypeError):
                SourceAuthVerifierConfig(
                    queue_config=config,
                    executable_path=root / "blind-source-auth-v4.exe",
                    workspace=root,
                    ml_dsa_87_public_key=bytes(2_592),
                )  # type: ignore[call-arg]

    def test_runtime_exposes_explicit_batch_and_operation_counters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v9", 100)
            verifier = _Verifier(config)
            with self.assertRaisesRegex(VerificationRuntimeError, "runtime_backend_unqualified"):
                MinimalClearanceVerificationRuntime(root=root)
            with MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config) as runtime:
                now = int(time.time() * 1000)
                template = OperationTemplate("shared-runtime", 1, "state-profile-v9", now - 100, now + 2_000_000)
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
            config = QueueConfig("runtime-v9-retry", 100)
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
