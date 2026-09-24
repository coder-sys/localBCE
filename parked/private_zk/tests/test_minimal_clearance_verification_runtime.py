import json
import os
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

import parked.private_zk.app.minimal_clearance_composition as composition
from parked.private_zk.app.minimal_clearance_source_auth_verifier_adapter import (
    ML_DSA_87_PUBLIC_KEY_BYTES,
    MinimalClearanceSourceAuthVerifierAdapter,
    SOURCE_AUTH_EXECUTABLE_SHA256,
    SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
    SourceAuthVerifierConfig,
)
import parked.private_zk.app.minimal_clearance_verification_queue as queue_module
import parked.private_zk.app.minimal_clearance_verification_runtime as runtime_module
from parked.private_zk.app.minimal_clearance_composition import CompositionConfigV2, StateDispositionControl, build_synthetic_acknowledgment
from parked.private_zk.app.minimal_clearance_verification_queue import BatchVerifierResult, OperationTemplate, QueueConfig, QueueIndeterminateError, VolatileProofHandoff, _RUNTIME_LOCK_RELEASED_MARKER
from parked.private_zk.app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime, RuntimeOutboxResult, VerificationRuntimeError

# Direct constructor fixtures use this visibly separate reference-only route.
SyntheticReferenceRuntime = MinimalClearanceVerificationRuntime.for_synthetic_reference


_STARTUP_CLEANUP_CHILD_SOURCE = r'''
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch
import parked.private_zk.app.minimal_clearance_composition as composition
import parked.private_zk.app.minimal_clearance_verification_queue as queue_module
import parked.private_zk.app.minimal_clearance_verification_runtime as runtime_module
from parked.private_zk.app.minimal_clearance_verification_queue import QueueConfig, _RUNTIME_LOCK_RELEASED_MARKER
from parked.private_zk.app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime
SyntheticReferenceRuntime = MinimalClearanceVerificationRuntime.for_synthetic_reference

root = Path(sys.argv[1])
config = QueueConfig("startup-native-cleanup", 100)
if os.name == "nt":
    cleanup_patch = patch.object(queue_module, "_runtime_win_mark_delete", side_effect=OSError(5, "delete"))
else:
    original_write_marker = queue_module._QueueRuntimeOwnership._write_marker
    calls = 0

    def fail_cleanup_marker(current_owner, marker: bytes) -> None:
        global calls
        if marker == _RUNTIME_LOCK_RELEASED_MARKER and calls >= 1:
            raise OSError("marker")
        calls += 1
        original_write_marker(current_owner, marker)

    cleanup_patch = patch.object(queue_module._QueueRuntimeOwnership, "_write_marker", new=fail_cleanup_marker)
with cleanup_patch, patch.object(runtime_module, "ClearanceCompositionStoreV2", side_effect=composition.CompositionError("composition_schema")):
    try:
        SyntheticReferenceRuntime(root=root, verifier=object(), config=config)
    except BaseException as error:
        print(json.dumps({"type": type(error).__name__, "message": str(error)}), flush=True)
    else:
        print(json.dumps({"type": "returned", "message": ""}), flush=True)
'''


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
        return BatchVerifierResult(self.accepted, self.accepted, batch.proof_context, batch.public_coin, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted" if self.accepted else "rejected", self.config.qualification_flags)


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


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now

    def advance(self, milliseconds: int) -> None:
        self.now += milliseconds


class _Receiver:
    def __init__(self, config: CompositionConfigV2, clock: _Clock, *, modes: tuple[str, ...] = ("valid",), acks: dict[bytes, bytes] | None = None, directives: dict[bytes, str] | None = None, identity_value: object | None = None) -> None:
        self.config = config
        self.clock = clock
        self.modes = modes
        self.acks = {} if acks is None else acks
        self.directives = {} if directives is None else directives
        self.identity_value = config.receiver_identity if identity_value is None else identity_value
        self.dispatch_calls: list[tuple[bytes, bytes]] = []
        self.lookup_calls: list[tuple[bytes, bytes]] = []
        self.side_effects = 0

    def identity_sha256(self):
        return self.identity_value

    def epoch(self):
        return self.config.receiver_epoch

    def acknowledgment_profile(self):
        return self.config.acknowledgment_profile

    def _mode(self, calls: list[tuple[bytes, bytes]]) -> str:
        return self.modes[len(calls) % len(self.modes)]

    def _valid_ack(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        acknowledgment = self.acks.get(idempotency_key)
        if acknowledgment is None:
            acknowledgment = build_synthetic_acknowledgment(envelope_bytes, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.clock.now_ms())
            self.acks[idempotency_key] = acknowledgment
            self.side_effects += 1
        return acknowledgment

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes | None:
        operation_ref = bytes.fromhex(json.loads(envelope_bytes.decode("ascii"))["operation_ref"])
        self.dispatch_calls.append((operation_ref, idempotency_key))
        mode = self._mode(self.dispatch_calls[:-1])
        if mode == "valid":
            return self._valid_ack(envelope_bytes, idempotency_key)
        if mode == "missing":
            return None
        if mode == "crash":
            self._valid_ack(envelope_bytes, idempotency_key)
            raise KeyboardInterrupt
        raise AssertionError(mode)

    def lookup_acknowledgment(self, **query):
        operation_ref = query["operation_id"]
        idempotency_key = query["idempotency_key"]
        self.lookup_calls.append((operation_ref, idempotency_key))
        mode = self._mode(self.lookup_calls[:-1])
        if mode == "missing":
            return None
        if mode != "valid":
            raise AssertionError(mode)
        envelope = composition._envelope(operation_ref, self.directives[operation_ref], self.config)
        return build_synthetic_acknowledgment(envelope, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.clock.now_ms())


class _ReentrantReceiver(_Receiver):
    def __init__(self, config: CompositionConfigV2, clock: _Clock) -> None:
        super().__init__(config, clock)
        self.runtime = None
        self.reentry_errors: dict[str, str] = {}

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes | None:
        if not self.reentry_errors:
            if self.runtime is None:
                raise AssertionError("runtime not attached")
            actions = {
                "run": self.runtime.run,
                "dispatch": self.runtime.dispatch_outbox,
                "reconcile": self.runtime.reconcile_outbox,
                "close": self.runtime.close,
            }
            for name, action in actions.items():
                try:
                    action()
                except VerificationRuntimeError as error:
                    self.reentry_errors[name] = str(error)
                else:
                    self.reentry_errors[name] = "returned"
        return super().dispatch(envelope_bytes, idempotency_key)


class _BlockingReceiver(_Receiver):
    def __init__(self, config: CompositionConfigV2, clock: _Clock) -> None:
        super().__init__(config, clock)
        self.entered = threading.Event()
        self.release = threading.Event()

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes | None:
        if not self.entered.is_set():
            self.entered.set()
            if not self.release.wait(5):
                raise RuntimeError("test callback release timeout")
        return super().dispatch(envelope_bytes, idempotency_key)


_SOURCE_AUTH_VERIFIER_PATH = Path(
    r"C:\Users\neers\Documents\Codex\2026-09-04\pmb-20260908\Release\dm_pipeline_verifier_cli.exe"
)
_PREPROVISIONED_PROFILE12_PUBLIC_KEY = bytes(
    (index * 17 + 3) % 256 for index in range(ML_DSA_87_PUBLIC_KEY_BYTES)
)


def _source_auth_config(root: Path, queue_id: str) -> SourceAuthVerifierConfig:
    workspace = root / "verifier-workspace"
    workspace.mkdir()
    return SourceAuthVerifierConfig(
        queue_config=QueueConfig(queue_id, 100),
        executable_path=_SOURCE_AUTH_VERIFIER_PATH,
        executable_size_bytes=SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
        executable_sha256=SOURCE_AUTH_EXECUTABLE_SHA256,
        workspace=workspace,
        ml_dsa_87_public_key=_PREPROVISIONED_PROFILE12_PUBLIC_KEY,
        timeout_seconds=30.0,
    )


class RuntimeV12Tests(unittest.TestCase):

    def test_operational_constructor_without_admission_kernel_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(VerificationRuntimeError, "runtime_admission_kernel"):
                MinimalClearanceVerificationRuntime(
                    root=root,
                    verifier=object(),
                    config=QueueConfig("runtime-missing-admission", 100),
                )

    def test_from_source_auth_passes_the_state_port_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_config = _source_auth_config(root, "runtime-source-auth-boundary")
            port = _DispositionPort()
            runtime = MinimalClearanceVerificationRuntime.from_source_auth(
                root=root,
                source_auth_config=source_config,
                state_disposition_port=port,
            )
            try:
                self.assertIsInstance(
                    runtime._verifier,
                    MinimalClearanceSourceAuthVerifierAdapter,
                )
                self.assertIs(runtime._state_disposition_port, port)
                self.assertEqual(runtime._store.config, source_config.queue_config)
                self.assertTrue((root / "state.sqlite").is_file())
                self.assertFalse((root / "queue.sqlite").exists())
                self.assertFalse((root / "composition.sqlite").exists())
            finally:
                runtime.close()

    def test_from_source_auth_remains_nonactivating_and_unified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_config = _source_auth_config(root, "runtime-source-auth-nonactivating")
            runtime = MinimalClearanceVerificationRuntime.from_source_auth(
                root=root,
                source_auth_config=source_config,
            )
            try:
                summary = runtime.support_summary()
                self.assertEqual(summary["schema"], queue_module._SCHEMA)
                self.assertIsNone(summary["proof_suite_id"])
                self.assertFalse(summary["production_usable"])
                self.assertFalse(summary["activation"])
                self.assertFalse(summary["proof_bytes_persisted"])
                self.assertFalse(summary["path_custody"])
                self.assertFalse(summary["backend_qualified"])
                self.assertFalse(summary["resource_product_credit"])
            finally:
                runtime.close()

    def test_runtime_issue_request_v1_replays_after_lost_commit_response_and_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("runtime-issue-request-v1", 100)
            request_id = bytes([0x73]) * 32
            template = OperationTemplate(
                "runtime-issue-request-recovery",
                1,
                config.profile_version,
                clock.now - 100,
                clock.now + 60_000,
            )
            runtime = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config)

            def fail_after_commit(label: str) -> None:
                if label == "after_issue_commit":
                    raise RuntimeError("injected-after-issue-commit")

            try:
                runtime._store._after_commit_fault = fail_after_commit
                with self.assertRaisesRegex(QueueIndeterminateError, "issue_result_indeterminate"):
                    runtime.issue_batch_v1(request_id=request_id, template=template)
                first_resolution = runtime.resolve_issue_request_v1(
                    request_id=request_id,
                    template=template,
                )
                self.assertIsNotNone(first_resolution.batch)
                assert first_resolution.batch is not None
                self.assertEqual(first_resolution.batch.request_version, 1)
            finally:
                runtime.close()

            restarted = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config)
            try:
                after_restart_before_retry = restarted.resolve_issue_request_v1(
                    request_id=request_id,
                    template=template,
                )
                self.assertIsNotNone(after_restart_before_retry.batch)
                assert after_restart_before_retry.batch is not None
                self.assertEqual(after_restart_before_retry.batch.status, "HELD")
                recovered = restarted.issue_batch_v1(request_id=request_id, template=template)
                final_resolution = restarted.resolve_issue_request_v1(
                    request_id=request_id,
                    template=template,
                )
            finally:
                restarted.close()

            self.assertIsNotNone(final_resolution.batch)
            assert final_resolution.batch is not None
            self.assertEqual(recovered.batch_id, first_resolution.batch.batch_id)
            self.assertEqual(recovered.batch_root, first_resolution.batch.batch_root)
            self.assertEqual(recovered.session_ref, first_resolution.batch.session_ref)
            self.assertEqual(recovered.operation_refs, first_resolution.batch.operation_refs)
            self.assertEqual(recovered.public_coin, first_resolution.batch.public_coin)
            self.assertEqual(recovered.proof_context, first_resolution.batch.proof_context)
            self.assertEqual(recovered.identity_digest, first_resolution.batch.identity_digest)
            self.assertEqual(final_resolution.batch.status, "HELD")
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_batches").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_members").fetchone()[0], 100)
                self.assertEqual(
                    connection.execute(
                        "SELECT reservation_before,reservation_after,proof_attempts FROM queue_attempts"
                    ).fetchone(),
                    (0, 101, 101),
                )
                self.assertEqual(
                    connection.execute("SELECT proof_attempts_used,source_u_used FROM queue_metadata WHERE id=1").fetchone(),
                    (101, 1),
                )

    def test_runtime_uses_state_port_only_after_accepted_verifier_fact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v10", 100)
            verifier = _Verifier(config)
            port = _DispositionPort()
            with SyntheticReferenceRuntime(root=root, verifier=verifier, config=config, state_disposition_port=port) as runtime:
                now = int(time.time() * 1000)
                batch = runtime.issue_batch(template=OperationTemplate("shared-runtime", 1, config.profile_version, now - 100, now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"runtime-proof")))
                result = runtime.run()
                self.assertEqual((result.outcome, result.accepted_operation_count, result.verified_batch_count, result.rejected_batch_count, result.held_batch_count, result.processed, verifier.calls, port.calls), ("PROCESSED", 100, 1, 0, 0, 1, 1, 1))
                self.assertEqual(result.verified, 100)
                self.assertEqual(runtime._database_path.name, "state.sqlite")
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 100)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 100)

    def test_runtime_run_drives_configured_delivery_without_new_state_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("runtime-delivery", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, receiver_identity=bytes([7]) * 32, lease_seconds=1, reconciliation_lease_seconds=1)
            receiver = _Receiver(composition_config, clock)
            with SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort(), composition_config=composition_config, receiver=receiver, lookup=receiver, clock=clock) as runtime:
                batch = runtime.issue_batch(template=OperationTemplate("runtime-delivery", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"runtime-proof")))
                result = runtime.run(dispatch_batches=1)
                self.assertEqual((result.outcome, result.processed, result.outbox_processed, result.accepted_operation_count), ("PROCESSED", 1, 1, 100))
                self.assertIsNotNone(result.delivery)
                assert result.delivery is not None
                self.assertEqual((result.delivery.operation, result.delivery.batch_count, result.delivery.attempted_operation_count, result.delivery.acknowledged_operation_count, result.delivery.unconfirmed_operation_count, result.delivery.has_more), ("DIRECT_DELIVERY", 1, 100, 100, 0, False))
                self.assertEqual(len(receiver.dispatch_calls), 100)
                self.assertEqual(runtime.support_summary()["outbox_counts"], {"READY": 0, "LEASED": 0, "ACKNOWLEDGED": 100, "DELIVERY_UNCONFIRMED": 0})
                with self.assertRaisesRegex(VerificationRuntimeError, "runtime_dispatch_max_batches"):
                    runtime.dispatch_outbox(max_batches=0)
                with self.assertRaisesRegex(VerificationRuntimeError, "runtime_reconciliation_max_batches"):
                    runtime.reconcile_outbox(max_batches=257)
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("ACKNOWLEDGED", 100)])
                self.assertEqual(connection.execute("SELECT payment_root FROM composition_meta WHERE id=1").fetchone()[0], bytes(64))
            with self.assertRaisesRegex(VerificationRuntimeError, "runtime_closed"):
                runtime.dispatch_outbox()
            runtime.close()

    def test_runtime_serializes_callback_reentry_and_preserves_owner_until_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("runtime-reentry", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, receiver_identity=bytes([7]) * 32, lease_seconds=1, reconciliation_lease_seconds=1)
            receiver = _ReentrantReceiver(composition_config, clock)
            runtime = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort(), composition_config=composition_config, receiver=receiver, lookup=receiver, clock=clock)
            receiver.runtime = runtime
            try:
                batch = runtime.issue_batch(template=OperationTemplate("runtime-reentry", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"runtime-proof")))
                self.assertEqual(runtime.run().accepted_operation_count, 100)
                result = runtime.dispatch_outbox()
                self.assertEqual((result.acknowledged_operation_count, result.unconfirmed_operation_count), (100, 0))
                self.assertEqual(receiver.reentry_errors, {name: "runtime_busy" for name in ("run", "dispatch", "reconcile", "close")})
                self.assertFalse(runtime._closed)
                self.assertTrue((root / "state.sqlite.runtime-lock").exists())
            finally:
                runtime.close()
            self.assertFalse((root / "state.sqlite.runtime-lock").exists())

    def test_runtime_rejects_concurrent_callers_while_callback_owns_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("runtime-concurrent", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, receiver_identity=bytes([7]) * 32, lease_seconds=1, reconciliation_lease_seconds=1)
            receiver = _BlockingReceiver(composition_config, clock)
            runtime = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort(), composition_config=composition_config, receiver=receiver, lookup=receiver, clock=clock)
            primary_result: list[RuntimeOutboxResult] = []
            primary_errors: list[BaseException] = []
            concurrent_results: dict[str, str] = {}
            try:
                batch = runtime.issue_batch(template=OperationTemplate("runtime-concurrent", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"runtime-proof")))
                self.assertEqual(runtime.run().accepted_operation_count, 100)

                def primary() -> None:
                    try:
                        primary_result.append(runtime.dispatch_outbox())
                    except BaseException as error:
                        primary_errors.append(error)

                worker = threading.Thread(target=primary)
                worker.start()
                self.assertTrue(receiver.entered.wait(5))

                actions = {
                    "run": runtime.run,
                    "dispatch": runtime.dispatch_outbox,
                    "reconcile": runtime.reconcile_outbox,
                    "close": runtime.close,
                }

                def competing(name: str, action) -> None:
                    try:
                        action()
                    except VerificationRuntimeError as error:
                        concurrent_results[name] = str(error)
                    except BaseException as error:
                        concurrent_results[name] = f"unexpected:{type(error).__name__}"
                    else:
                        concurrent_results[name] = "returned"

                competitors = [threading.Thread(target=competing, args=(name, action)) for name, action in actions.items()]
                for thread in competitors:
                    thread.start()
                for thread in competitors:
                    thread.join(5)
                self.assertEqual(concurrent_results, {name: "runtime_busy" for name in actions})
                self.assertTrue(worker.is_alive())
                self.assertTrue((root / "state.sqlite.runtime-lock").exists())
                receiver.release.set()
                worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(primary_errors, [])
                self.assertEqual(len(primary_result), 1)
                self.assertEqual(primary_result[0].acknowledged_operation_count, 100)
            finally:
                receiver.release.set()
                if 'worker' in locals():
                    worker.join(5)
                if not runtime._closed:
                    runtime.close()

    def test_constructor_cleans_queue_store_when_composition_creation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-startup-cleanup", 100)
            original_close = runtime_module._VerificationQueueStore._close
            with patch.object(runtime_module._VerificationQueueStore, "_close", autospec=True, side_effect=original_close) as store_close, patch.object(runtime_module, "ClearanceCompositionStoreV2", side_effect=composition.CompositionError("composition_schema")):
                with self.assertRaisesRegex(VerificationRuntimeError, "composition_schema"):
                    SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config)
            self.assertEqual(store_close.call_count, 1)
            self.assertTrue((root / "state.sqlite").exists())
            if os.name == "nt":
                self.assertFalse((root / "state.sqlite.runtime-lock").exists())
            else:
                self.assertEqual((root / "state.sqlite.runtime-lock").read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)

    def test_constructor_reports_runtime_startup_when_owner_cleanup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-startup-owner-cleanup", 100)
            lock = root / "state.sqlite.runtime-lock"
            failures = 0

            if os.name == "nt":
                cleanup_patch = patch.object(queue_module, "_runtime_win_mark_delete", side_effect=OSError(5, "delete"))
            else:
                original_write_marker = queue_module._QueueRuntimeOwnership._write_marker

                def fail_write_marker(current_owner, marker: bytes) -> None:
                    nonlocal failures
                    if marker == _RUNTIME_LOCK_RELEASED_MARKER and failures == 0:
                        failures += 1
                        raise OSError("marker")
                    original_write_marker(current_owner, marker)

                cleanup_patch = patch.object(queue_module._QueueRuntimeOwnership, "_write_marker", new=fail_write_marker)
            with cleanup_patch, patch.object(runtime_module, "ClearanceCompositionStoreV2", side_effect=composition.CompositionError("composition_schema")):
                with self.assertRaisesRegex(VerificationRuntimeError, "runtime_startup"):
                    SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config)
            self.assertTrue(lock.exists())

    def test_startup_cleanup_releases_native_lock_for_next_process_after_marker_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run(
                [sys.executable, "-B", "-c", _STARTUP_CLEANUP_CHILD_SOURCE, str(root)],
                cwd=str(Path(__file__).resolve().parents[3]),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
            self.assertEqual(result.stderr, "")
            lines = [line for line in result.stdout.splitlines() if line]
            self.assertEqual(len(lines), 1, result.stdout)
            child_result = json.loads(lines[0])
            self.assertEqual(child_result, {"type": "VerificationRuntimeError", "message": "runtime_startup"})
            lock = root / "state.sqlite.runtime-lock"
            self.assertTrue(lock.exists())
            owner = queue_module._QueueRuntimeOwnership(lock_path=lock, parent=root)
            owner.close()
            if os.name == "nt":
                self.assertFalse(lock.exists())
            else:
                self.assertEqual(lock.read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)

    def test_runtime_close_propagates_owner_cleanup_failure_and_retries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-owner-close-retry", 100)
            runtime = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config)
            lock = root / "state.sqlite.runtime-lock"
            failures = 0
            try:
                if os.name == "nt":
                    original_mark_delete = queue_module._runtime_win_mark_delete

                    def fail_once(handle: object) -> None:
                        nonlocal failures
                        if failures == 0:
                            failures += 1
                            raise OSError(5, "delete")
                        original_mark_delete(handle)

                    with patch.object(queue_module, "_runtime_win_mark_delete", side_effect=fail_once):
                        with self.assertRaisesRegex(VerificationRuntimeError, "runtime_scope"):
                            runtime.close()
                else:
                    original_write_marker = queue_module._QueueRuntimeOwnership._write_marker

                    def fail_once(current_owner, marker: bytes) -> None:
                        nonlocal failures
                        if marker == _RUNTIME_LOCK_RELEASED_MARKER and failures == 0:
                            failures += 1
                            raise OSError("marker")
                        original_write_marker(current_owner, marker)

                    with patch.object(queue_module._QueueRuntimeOwnership, "_write_marker", new=fail_once):
                        with self.assertRaisesRegex(VerificationRuntimeError, "runtime_scope"):
                            runtime.close()
                self.assertFalse(runtime._closed)
                self.assertTrue(lock.exists())
                runtime.close()
                self.assertTrue(runtime._closed)
                if os.name == "nt":
                    self.assertFalse(lock.exists())
                else:
                    self.assertEqual(lock.read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)
            finally:
                if not runtime._closed:
                    runtime.close()

    def test_runtime_rejects_dispatch_and_reconcile_after_partial_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("runtime-partial-shutdown", 100)
            composition_config = CompositionConfigV2(
                config.queue_id,
                config.digest,
                receiver_identity=bytes([7]) * 32,
                lease_seconds=1,
                reconciliation_lease_seconds=1,
            )
            receiver = _Receiver(composition_config, clock)
            runtime = SyntheticReferenceRuntime(
                root=root,
                verifier=_Verifier(config),
                config=config,
                composition_config=composition_config,
                receiver=receiver,
                lookup=receiver,
                clock=clock,
            )
            lock = root / "state.sqlite.runtime-lock"
            failures = 0
            try:
                if os.name == "nt":
                    original_mark_delete = queue_module._runtime_win_mark_delete

                    def fail_once(handle: object) -> None:
                        nonlocal failures
                        if failures == 0:
                            failures += 1
                            raise OSError(5, "delete")
                        original_mark_delete(handle)

                    cleanup_patch = patch.object(queue_module, "_runtime_win_mark_delete", side_effect=fail_once)
                else:
                    original_write_marker = queue_module._QueueRuntimeOwnership._write_marker

                    def fail_once(current_owner, marker: bytes) -> None:
                        nonlocal failures
                        if marker == _RUNTIME_LOCK_RELEASED_MARKER and failures == 0:
                            failures += 1
                            raise OSError("marker")
                        original_write_marker(current_owner, marker)

                    cleanup_patch = patch.object(queue_module._QueueRuntimeOwnership, "_write_marker", new=fail_once)
                with cleanup_patch:
                    with self.assertRaisesRegex(VerificationRuntimeError, "runtime_scope"):
                        runtime.close()
                self.assertFalse(runtime._closed)
                self.assertTrue(runtime._closing)
                self.assertTrue(runtime._store._closed)
                for name, action in (("dispatch", runtime.dispatch_outbox), ("reconcile", runtime.reconcile_outbox)):
                    with self.subTest(operation=name), self.assertRaisesRegex(VerificationRuntimeError, "runtime_closed"):
                        action()
                runtime.close()
                self.assertTrue(runtime._closed)
            finally:
                if not runtime._closed:
                    runtime.close()

    def test_runtime_rejects_unbound_receiver_before_creating_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-binding", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, receiver_identity=bytes([7]) * 32)
            receiver = _Receiver(composition_config, _Clock(), identity_value=bytes([8]) * 32)
            with self.assertRaisesRegex(VerificationRuntimeError, "runtime_receiver_binding"):
                SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, composition_config=composition_config, receiver=receiver)
            self.assertFalse((root / "state.sqlite").exists())

    def test_runtime_public_delivery_recovery_and_reconciliation_survive_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("runtime-recovery", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, receiver_identity=bytes([7]) * 32, lease_seconds=1, reconciliation_lease_seconds=1)
            external_acks: dict[bytes, bytes] = {}
            crashing = _Receiver(composition_config, clock, modes=("valid",) * 99 + ("crash",), acks=external_acks)
            runtime = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort(), composition_config=composition_config, receiver=crashing, lookup=crashing, clock=clock)
            batch = runtime.issue_batch(template=OperationTemplate("runtime-recovery", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
            runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"runtime-proof")))
            self.assertEqual(runtime.run().accepted_operation_count, 100)
            with self.assertRaises(KeyboardInterrupt):
                runtime.dispatch_outbox()
            original_keys = tuple(key for _operation, key in crashing.dispatch_calls)
            self.assertEqual((len(original_keys), crashing.side_effects), (100, 100))
            self.assertFalse(runtime._closed)
            self.assertTrue((root / "state.sqlite.runtime-lock").exists())
            self.assertEqual(runtime.support_summary()["outbox_counts"]["LEASED"], 100)
            runtime.close()

            before_expiry = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, composition_config=composition_config, receiver=crashing, lookup=crashing, clock=clock)
            before_direct = before_expiry.dispatch_outbox()
            before_reconciliation = before_expiry.reconcile_outbox()
            self.assertEqual((before_direct.outcome, before_direct.batch_count, before_reconciliation.outcome, before_reconciliation.batch_count, len(crashing.dispatch_calls), len(crashing.lookup_calls)), ("EMPTY", 0, "EMPTY", 0, 100, 0))
            before_expiry.close()

            clock.advance(composition_config.lease_seconds * 1000)
            retry_receiver = _Receiver(composition_config, clock, modes=("missing",), acks=external_acks)
            after_expiry = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, composition_config=composition_config, receiver=retry_receiver, lookup=retry_receiver, clock=clock)
            retry = after_expiry.dispatch_outbox()
            self.assertEqual((retry.outcome, retry.batch_count, retry.attempted_operation_count, retry.acknowledged_operation_count, retry.unconfirmed_operation_count, retry_receiver.side_effects, tuple(key for _operation, key in retry_receiver.dispatch_calls)), ("PROCESSED", 1, 100, 0, 100, 0, original_keys))
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                directives = {bytes(row[0]): str(row[1]) for row in connection.execute("SELECT operation_ref,effective_directive FROM composition_outbox")}
            after_expiry.close()

            lookup = _Receiver(composition_config, clock, modes=("valid",), directives=directives)
            reconciler = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, composition_config=composition_config, receiver=retry_receiver, lookup=lookup, clock=clock)
            reconciliation_run = reconciler.run(reconciliation_batches=1)
            self.assertEqual((reconciliation_run.outcome, reconciliation_run.outbox_processed), ("PROCESSED", 1))
            reconciliation = reconciliation_run.reconciliation
            assert reconciliation is not None
            self.assertEqual((reconciliation.outcome, reconciliation.batch_count, reconciliation.attempted_operation_count, reconciliation.acknowledged_operation_count, reconciliation.unconfirmed_operation_count, tuple(key for _operation, key in lookup.lookup_calls)), ("PROCESSED", 1, 100, 100, 0, original_keys))
            self.assertEqual((reconciler.dispatch_outbox().outcome, reconciler.reconcile_outbox().outcome), ("EMPTY", "EMPTY"))
            self.assertEqual(reconciler.support_summary()["outbox_counts"], {"READY": 0, "LEASED": 0, "ACKNOWLEDGED": 100, "DELIVERY_UNCONFIRMED": 0})
            reconciler.close()
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT status,MIN(attempt),MAX(attempt),COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("ACKNOWLEDGED", 3, 3, 100)])
                self.assertEqual(connection.execute("SELECT payment_root FROM composition_meta WHERE id=1").fetchone()[0], bytes(64))

    def test_runtime_close_retries_after_real_handoff_buffer_export_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-close-retry", 100)
            runtime = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config)
            exported = None
            try:
                now = int(time.time() * 1000)
                batch = runtime.issue_batch(template=OperationTemplate("runtime-close-retry", 1, config.profile_version, now - 100, now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"cleanup-proof")))
                handoff = next(iter(runtime._store._handoffs.values()))
                # A live memoryview makes bytearray.clear raise BufferError;
                # this is a real buffer-lifetime failure, not a mocked close.
                exported = memoryview(handoff._buffer)
                with self.assertRaises(BufferError):
                    runtime.close()
                self.assertFalse(runtime._closed)
                self.assertFalse(handoff.closed)
                self.assertTrue((root / "state.sqlite.runtime-lock").exists())
            finally:
                if exported is not None:
                    exported.release()
                if not runtime._closed:
                    runtime.close()
            self.assertTrue(runtime._closed)
            if os.name == "nt":
                self.assertFalse((root / "state.sqlite.runtime-lock").exists())
            else:
                self.assertEqual((root / "state.sqlite.runtime-lock").read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)
            self.assertEqual(len(handoff._buffer), 0)

    def test_legacy_split_database_is_rejected_without_touching_it(self) -> None:
        for legacy_name in ("queue.sqlite", "composition.sqlite"):
            with self.subTest(legacy_name=legacy_name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                legacy = root / legacy_name
                original = b"old split database bytes"
                legacy.write_bytes(original)
                config = QueueConfig("runtime-v10", 100)
                with self.assertRaisesRegex(VerificationRuntimeError, "legacy_database_unsupported"):
                    SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config)
                self.assertEqual(legacy.read_bytes(), original)
                self.assertFalse((root / "state.sqlite").exists())
                self.assertFalse((root / "state.sqlite.runtime-lock").exists())

    def test_one_runtime_owner_and_one_terminal_commit_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v10-owner", 100)
            first = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort())
            try:
                with self.assertRaisesRegex(VerificationRuntimeError, "runtime_already_owned"):
                    SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort())
                self.assertTrue((root / "state.sqlite.runtime-lock").exists())
            finally:
                first.close()
            if os.name == "nt":
                self.assertFalse((root / "state.sqlite.runtime-lock").exists())
            else:
                self.assertEqual((root / "state.sqlite.runtime-lock").read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)

    def test_concurrent_runtime_creation_has_one_owner_and_one_terminal_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("runtime-v10-concurrent-owner", 100)
            barrier = threading.Barrier(2)
            winners: list[MinimalClearanceVerificationRuntime] = []
            failures: list[dict[str, str | None]] = []

            def create_runtime() -> None:
                barrier.wait()
                try:
                    runtime = SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort())
                except BaseException as error:
                    context = error.__context__
                    cause = error.__cause__
                    failures.append({
                        "type": type(error).__name__,
                        "message": str(error),
                        "context_type": None if context is None else type(context).__name__,
                        "context_message": None if context is None else str(context),
                        "cause_type": None if cause is None else type(cause).__name__,
                        "cause_message": None if cause is None else str(cause),
                    })
                else:
                    winners.append(runtime)

            threads = [threading.Thread(target=create_runtime) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(winners), 1)
            self.assertEqual(len(failures), 1, failures)
            self.assertEqual(failures[0]["type"], "VerificationRuntimeError", failures)
            self.assertEqual(failures[0]["message"], "runtime_already_owned", failures)
            runtime = winners[0]
            try:
                now = int(time.time() * 1000)
                batch = runtime.issue_batch(template=OperationTemplate("concurrent-owner", 1, config.profile_version, now - 100, now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"concurrent-proof")))
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
            with SyntheticReferenceRuntime(root=root, verifier=verifier, config=config, state_disposition_port=port) as runtime:
                now = int(time.time() * 1000)
                batch = runtime.issue_batch(template=OperationTemplate("failure", 1, config.profile_version, now - 100, now + 60_000))
                runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"failure-proof")))
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
import os, sys
from pathlib import Path
sys.path.insert(0, os.getcwd())
from parked.private_zk.app.minimal_clearance_verification_queue import BatchVerifierResult, OperationTemplate, QueueConfig, VolatileProofHandoff, _QueueRuntimeOwnership, _VerificationQueueStore
from parked.private_zk.app.minimal_clearance_composition import CompositionConfigV2

class Clock:
    def now_ms(self): return 1700000000000

root = Path(sys.argv[1])
config = QueueConfig("runtime-v10-crash", 100)
composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=Clock(), composition_config=composition_config, before_fault=lambda label: os._exit(17) if label == "before_queue_commit" else None)
now = 1700000000000
batch = store.issue_batch(template=OperationTemplate("crash", 1, config.profile_version, now - 100, now + 60000))
store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"crash-proof")))
work = store._claim_next_batch()
store._reserve_verifier_launch(work)
result = BatchVerifierResult(False, False, batch.proof_context, batch.public_coin, batch.batch_root, config.source_auth_profile, config.source_key_epoch, "rejected", ())
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
            with SyntheticReferenceRuntime(root=root, verifier=_Verifier(config), config=config, state_disposition_port=_DispositionPort()) as runtime:
                self.assertEqual(runtime._recovered_leases, 1)
                self.assertEqual(runtime.run().outcome, "EMPTY")
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "HELD")


if __name__ == "__main__":
    unittest.main()
