import io
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import app.minimal_clearance_composition as composition
from app.minimal_clearance_composition import CompositionConfigV2, StateDispositionControl
from app.minimal_clearance_source_auth_verifier_adapter import MinimalClearanceSourceAuthVerifierAdapter, SOURCE_AUTH_EXECUTABLE_SHA256, SOURCE_AUTH_EXECUTABLE_SIZE_BYTES, SourceAuthVerifierConfig
from app.minimal_clearance_verification_queue import BatchVerifierResult, OperationTemplate, QueueConfig, VolatileProofHandoff
from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime, VerificationRuntimeError


def _controls(operation_refs: tuple[bytes, ...]) -> dict[bytes, StateDispositionControl]:
    profile = bytes([9]) * 64
    state_id = bytes(64)
    state_bytes = bytes(64)
    continuity = bytes(64)
    audit = bytes(64)
    clearance = bytes(64)
    marker = 0
    result: dict[bytes, StateDispositionControl] = {}
    for index, operation_ref in enumerate(operation_refs):
        control = StateDispositionControl(operation_ref, "PASS", False, bytes(64), profile, state_id, state_bytes, 1, index, continuity, audit, clearance, marker, index)
        result[operation_ref] = control
        state_id = control.state_after_id
        state_bytes = control.state_after_bytes
        continuity = control.state_after_continuity_root
        clearance = control.state_after_clearance_root
        audit = composition._sha(composition._STATE, audit, control.decision_id, control.effective_directive.encode("ascii"))
        marker = 1
    return result


class _Verifier:
    def __init__(self, config: QueueConfig, *, accepted: bool = True) -> None:
        self.config = config
        self.accepted = accepted
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, batch):
        self.calls += 1
        while stream.read(23):
            pass
        return BatchVerifierResult(self.accepted, self.accepted, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted" if self.accepted else "rejected", self.config.qualification_flags)


class _DispositionPort:
    def __init__(self) -> None:
        self.calls = 0

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome):
        self.calls += 1
        return _controls(operation_refs)


class _FailingVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, _stream: VolatileProofHandoff, _batch):
        self.calls += 1
        raise RuntimeError("verifier process failure")


class RuntimeV10Tests(unittest.TestCase):
    def _source_auth_config(self, root: Path) -> SourceAuthVerifierConfig:
        return SourceAuthVerifierConfig(
            queue_config=QueueConfig("runtime-v10-source-auth", 100),
            executable_path=root / "blind-source-auth-v10.exe",
            executable_size_bytes=SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
            executable_sha256=SOURCE_AUTH_EXECUTABLE_SHA256,
            workspace=root,
            ml_dsa_87_public_key=bytes(2_592),
            timeout_seconds=30.0,
        )

    def test_from_source_auth_passes_the_state_port_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._source_auth_config(root)
            port = _DispositionPort()
            with patch("app.minimal_clearance_verification_runtime.MinimalClearanceSourceAuthVerifierAdapter") as adapter_factory, patch.object(MinimalClearanceVerificationRuntime, "__init__", return_value=None) as constructor:
                runtime = MinimalClearanceVerificationRuntime.from_source_auth(root=root, source_auth_config=config, state_disposition_port=port)
            adapter_factory.assert_called_once_with(config)
            constructor.assert_called_once_with(root=root, verifier=adapter_factory.return_value, config=config.queue_config, state_disposition_port=port, composition_config=None)
            self.assertIsInstance(runtime, MinimalClearanceVerificationRuntime)

    def test_from_source_auth_remains_nonactivating_and_unified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._source_auth_config(root)
            with MinimalClearanceVerificationRuntime.from_source_auth(root=root, source_auth_config=config) as runtime:
                self.assertIs(type(runtime._verifier), MinimalClearanceSourceAuthVerifierAdapter)
                self.assertIs(runtime._store.config, config.queue_config)
                self.assertEqual(runtime._database_path.name, "state.sqlite")
                self.assertFalse(runtime.support_summary()["production_usable"])
                self.assertFalse(runtime.support_summary()["activation"])

    def test_runtime_uses_state_port_only_after_accepted_verifier_fact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v10", 100)
            verifier = _Verifier(config)
            port = _DispositionPort()
            with MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config, state_disposition_port=port) as runtime:
                now = int(time.time() * 1000)
                batch = runtime.issue_batch(template=OperationTemplate("shared-runtime", 1, config.profile_version, now - 100, now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"runtime-proof"), declared_length=13)
                result = runtime.run()
                self.assertEqual((result.outcome, result.accepted_operation_count, result.verified_batch_count, result.rejected_batch_count, result.held_batch_count, result.processed, verifier.calls, port.calls), ("PROCESSED", 100, 1, 0, 0, 1, 1, 1))
                self.assertEqual(result.verified, 100)
                self.assertEqual(runtime._database_path.name, "state.sqlite")
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 100)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 100)

    def test_legacy_split_database_is_rejected_without_touching_it(self) -> None:
        for legacy_name in ("queue.sqlite", "composition.sqlite"):
            with self.subTest(legacy_name=legacy_name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                legacy = root / legacy_name
                original = b"old split database bytes"
                legacy.write_bytes(original)
                config = QueueConfig("runtime-v10", 100)
                with self.assertRaisesRegex(VerificationRuntimeError, "legacy_database_unsupported"):
                    MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(config), config=config)
                self.assertEqual(legacy.read_bytes(), original)
                self.assertFalse((root / "state.sqlite").exists())
                self.assertFalse((root / "state.sqlite.runtime-lock").exists())

    def test_one_runtime_owner_and_one_terminal_commit_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v10-owner", 100)
            first = MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort())
            try:
                with self.assertRaisesRegex(VerificationRuntimeError, "runtime_already_owned"):
                    MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort())
                self.assertTrue((root / "state.sqlite.runtime-lock").exists())
            finally:
                first.close()
            self.assertFalse((root / "state.sqlite.runtime-lock").exists())

    def test_concurrent_runtime_creation_has_one_owner_and_one_terminal_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v10-concurrent-owner", 100)
            barrier = threading.Barrier(2)
            winners: list[MinimalClearanceVerificationRuntime] = []
            failures: list[str] = []

            def create_runtime() -> None:
                barrier.wait()
                try:
                    runtime = MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort())
                except VerificationRuntimeError as error:
                    failures.append(str(error))
                else:
                    winners.append(runtime)

            threads = [threading.Thread(target=create_runtime) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(winners), 1)
            self.assertEqual(failures, ["runtime_already_owned"])
            runtime = winners[0]
            try:
                now = int(time.time() * 1000)
                batch = runtime.issue_batch(template=OperationTemplate("concurrent-owner", 1, config.profile_version, now - 100, now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"concurrent-proof"), declared_length=16)
                result = runtime.run()
                self.assertEqual((result.outcome, result.accepted_operation_count), ("PROCESSED", 100))
            finally:
                runtime.close()
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_results WHERE terminal_status='VERIFIED'").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 100)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events WHERE event_kind='APPLIED'").fetchone()[0], 100)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE status='READY'").fetchone()[0], 100)

    def test_verifier_failure_is_held_once_and_never_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v10-failure", 100)
            port = _DispositionPort()
            verifier = _FailingVerifier()
            with MinimalClearanceVerificationRuntime(root=root, verifier=verifier, config=config, state_disposition_port=port) as runtime:
                now = int(time.time() * 1000)
                batch = runtime.issue_batch(template=OperationTemplate("failure", 1, config.profile_version, now - 100, now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"failure-proof"), declared_length=13)
                first = runtime.run()
                second = runtime.run()
                self.assertEqual((first.outcome, first.held_batch_count, verifier.calls, port.calls), ("PROCESSED", 1, 1, 0))
                self.assertEqual((second.outcome, second.processed), ("EMPTY", 0))
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_attempts").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)

    def test_process_crash_before_commit_reopens_without_partial_terminal_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = r'''
import io, os, sys
from pathlib import Path
sys.path.insert(0, os.getcwd())
from app.minimal_clearance_verification_queue import BatchVerifierResult, OperationTemplate, QueueConfig, _QueueRuntimeOwnership, _VerificationQueueStore
from app.minimal_clearance_composition import CompositionConfigV2

class Clock:
    def now_ms(self): return 1700000000000

root = Path(sys.argv[1])
config = QueueConfig("runtime-v10-crash", 100)
composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=Clock(), composition_config=composition_config, before_fault=lambda label: os._exit(17) if label == "before_queue_commit" else None)
now = 1700000000000
batch = store.issue_batch(template=OperationTemplate("crash", 1, config.profile_version, now - 100, now + 60000))
store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"crash-proof"), declared_length=11)
work = store._claim_next_batch()
result = BatchVerifierResult(False, False, batch.proof_statement, batch.batch_root, config.source_auth_profile, config.source_key_epoch, "rejected", ())
store._complete_batch(work, status="REJECTED", verifier_result=result, error_code="proof_or_source_not_accepted")
'''
            child_result = subprocess.run([sys.executable, "-c", child, str(root)], cwd=Path.cwd(), capture_output=True, text=True)
            self.assertEqual(child_result.returncode, 17, child_result.stderr)
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "LEASED")
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_results").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)
            config = QueueConfig("runtime-v10-crash", 100)
            with MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort()) as runtime:
                self.assertEqual(runtime._recovered_leases, 1)
                self.assertEqual(runtime.run().outcome, "EMPTY")
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "HELD")


if __name__ == "__main__":
    unittest.main()
