import hashlib
import ctypes
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
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import parked.private_zk.app.minimal_clearance_composition as composition
import parked.private_zk.app.minimal_clearance_lifecycle_adapter as lifecycle_adapter
import parked.private_zk.app.minimal_clearance_verification_queue_independent as queue_independent
import parked.private_zk.app.minimal_clearance_verification_queue as queue_module
from parked.private_zk.app.minimal_clearance_verification_queue import _compute_batch_root_from_refs, _profile12_context
from parked.private_zk.app.minimal_clearance_composition import (
    CompositionConfigV2,
    CompositionConflictError,
    StateDispositionControl,
    resolve_effective_directive,
)
from parked.private_zk.app.minimal_clearance_verification_queue import (
    BatchVerifierResult,
    OperationTemplate,
    QueueConfig,
    QueueConflictError,
    QueueHeldError,
    QueueIndeterminateError,
    QueueIntegrityError,
    QueueLeaseError,
    _RUNTIME_LOCK_RELEASED_MARKER,
    _TRIGGER_DEFS,
    VerificationQueueError,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)


_OWNER_CHILD_SOURCE = r'''
import json
import sys
import time
from pathlib import Path
from parked.private_zk.app.minimal_clearance_verification_queue import _QueueRuntimeOwnership

lock = Path(sys.argv[1])
mode = sys.argv[2]
ready = Path(sys.argv[3])
gate = Path(sys.argv[4])
if mode == "gate":
    original = _QueueRuntimeOwnership._check_marker_and_rebind

    def gated(self, *, created):
        ready.write_text("locked", encoding="ascii")
        deadline = time.monotonic() + 10
        while not gate.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        return original(self, created=created)

    _QueueRuntimeOwnership._check_marker_and_rebind = gated

try:
    owner = _QueueRuntimeOwnership(lock_path=lock, parent=lock.parent)
except BaseException as error:
    print(json.dumps({"status": "error", "type": type(error).__name__, "message": str(error)}), flush=True)
else:
    result = {"status": "acquired"}
    try:
        owner.close()
        result["close"] = "ok"
    except BaseException as error:
        result["close"] = f"{type(error).__name__}:{error}"
    print(json.dumps(result), flush=True)
'''


_OWNER_INITIALIZATION_CHILD_SOURCE = r'''
import json
import sys
import time
from pathlib import Path
import parked.private_zk.app.minimal_clearance_verification_queue as queue_module
from parked.private_zk.app.minimal_clearance_verification_queue import _QueueRuntimeOwnership, _RUNTIME_LOCK_RELEASED_MARKER

lock = Path(sys.argv[1])
ready = Path(sys.argv[2])
gate = Path(sys.argv[3])
original = queue_module._runtime_win_write_marker

def gated(handle, marker):
    if marker == _RUNTIME_LOCK_RELEASED_MARKER:
        ready.write_text("before-marker", encoding="ascii")
        deadline = time.monotonic() + 10
        while not gate.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
    return original(handle, marker)

queue_module._runtime_win_write_marker = gated
try:
    owner = _QueueRuntimeOwnership(lock_path=lock, parent=lock.parent)
except BaseException as error:
    print(json.dumps({"status": "error", "type": type(error).__name__, "message": str(error)}), flush=True)
else:
    result = {"status": "acquired"}
    try:
        owner.close()
        result["close"] = "ok"
    except BaseException as error:
        result["close"] = f"{type(error).__name__}:{error}"
    print(json.dumps(result), flush=True)
'''


def _child_result(completed: subprocess.CompletedProcess[str]) -> dict[str, str]:
    if completed.stderr:
        raise AssertionError(completed.stderr)
    lines = [line for line in completed.stdout.splitlines() if line]
    if not lines:
        raise AssertionError((completed.returncode, completed.stdout, completed.stderr))
    return json.loads(lines[-1])
from parked.private_zk.app.minimal_clearance_verification_queue_independent import _profile12_context as independent_profile12_context, read_verified_batch, verify_database


OLD_PROFILE9_TOKEN = "BLIND-ZKBPP-CUNRUH-RANGE100-V9"
OLD_SOURCE_AUTH_PROFILE9 = "BLIND-MLDSA87-SOURCE-AUTH-V1-R100-V9-UNQUALIFIED"
OLD_PROFILE9_FINGERPRINT = bytes.fromhex(
    "609A2A9D66E3D2E3332E86DE5BE4720699C1ADE901C62E6954715ABD1CF64E19"
    "7F315A32EEB972DEADAEDAB4D4E8882E00AE9EA9EE23575CDED3498429A802DF"
)
OLD_PROFILE9_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v9\x00"
OLD_PROFILE10_TOKEN = "BLIND-ZKBPP-RANGE100-CDG-DIRECT-V1"
OLD_PROFILE10_FINGERPRINT = bytes.fromhex(
    "8490652F6C69FEB8AC1FA2A8EDADF79A45632F67A73F0D67441321AFBB7369C6D"
    "2BBE71302626FB4F92EB378B8B35FE24D09F11DF55F4795FFD227D27EC52F9A"
)
OLD_PROFILE10_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v10\x00"


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


class _CallbackTrap:
    def __init__(self) -> None:
        self.read_calls = 0
        self.close_calls = 0

    def read(self, _size: int = -1) -> bytes:
        self.read_calls += 1
        raise AssertionError("callback must not run")

    def close(self) -> None:
        self.close_calls += 1
        raise AssertionError("callback must not run")


class _ByteArraySubclass(bytearray):
    pass


class _HandoffSubclass(VolatileProofHandoff):
    def __init__(self, payload: bytearray) -> None:
        super().__init__(payload)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        raise AssertionError("handoff subclass must not be closed")


def _new_store(root: Path, clock: _Clock, *, capacity: int = 100, before_fault=None):
    config = QueueConfig("state-test-v10", capacity)
    composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=capacity)
    owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
    store = _VerificationQueueStore(
        path=root / "state.sqlite",
        config=config,
        owner=owner,
        clock=clock,
        before_fault=before_fault,
        composition_config=composition_config,
    )
    return config, composition_config, owner, store


def _prepare(store: _VerificationQueueStore, config: QueueConfig, clock: _Clock, *, proof: bytes = b"volatile-proof", duration: int = 60_000):
    template = OperationTemplate(
        "shared-assertion",
        1,
        config.profile_version,
        clock.now - 100,
        clock.now + duration,
    )
    batch = store.issue_batch(template=template)
    store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(proof)))
    return batch


def _controls(operation_refs: tuple[bytes, ...], policies: tuple[str, ...] | None = None) -> dict[bytes, StateDispositionControl]:
    if policies is None:
        policies = ("PASS", "MISSING", "AMBIGUOUS", "FAIL", "FAIL") * 20
    if len(policies) != 100:
        raise AssertionError(len(policies))
    profile = bytes([9]) * 64
    state_id = bytes(64)
    state_bytes = bytes(64)
    continuity = bytes(64)
    audit = bytes(64)
    clearance = bytes(64)
    marker = 0
    count = 0
    result: dict[bytes, StateDispositionControl] = {}
    for index, operation_ref in enumerate(operation_refs):
        policy = policies[index]
        exception = policy == "FAIL" and index % 5 == 4
        control = StateDispositionControl(
            operation_ref,
            policy,
            exception,
            bytes([index + 1]) * 64 if exception else bytes(64),
            profile,
            state_id,
            state_bytes,
            1,
            index,
            continuity,
            audit,
            clearance,
            marker,
            count,
        )
        result[operation_ref] = control
        state_id = control.state_after_id
        state_bytes = control.state_after_bytes
        continuity = control.state_after_continuity_root
        clearance = control.state_after_clearance_root
        audit = composition._sha(composition._STATE, audit, control.decision_id, control.effective_directive.encode("ascii"))
        marker = int(bool(marker or control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"}))
        count += int(control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"})
    return result


class _Verifier:
    def __init__(self, config: QueueConfig, *, accepted: bool = True, source_authenticated: bool = True, result_code: str | None = None) -> None:
        self.config = config
        self.accepted = accepted
        self.source_authenticated = source_authenticated
        self.result_code = result_code or ("accepted" if accepted and source_authenticated else "rejected")
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, batch):
        self.calls += 1
        while stream.read(23):
            pass
        return BatchVerifierResult(
            self.accepted,
            self.source_authenticated,
            batch.proof_context,
            batch.public_coin,
            batch.batch_root,
            self.config.source_auth_profile,
            self.config.source_key_epoch,
            self.result_code,
            self.config.qualification_flags,
        )


def _verifier_result(config: QueueConfig, batch, *, accepted: bool = True, result_code: str | None = None) -> BatchVerifierResult:
    return BatchVerifierResult(accepted, accepted, batch.proof_context, batch.public_coin, batch.batch_root, config.source_auth_profile, config.source_key_epoch, result_code or ("accepted" if accepted else "rejected"), config.qualification_flags)


class _MalformedVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, _batch):
        self.calls += 1
        while stream.read(23):
            pass
        return {}


class _DispositionPort:
    def __init__(self, *, policies: tuple[str, ...] | None = None) -> None:
        self.policies = policies
        self.calls: list[tuple[bytes, tuple[bytes, ...], object]] = []

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome):
        self.calls.append((batch_id, operation_refs, verification_outcome))
        return _controls(operation_refs, self.policies)


def _counts(path: Path) -> dict[str, int]:
    with closing(sqlite3.connect(str(path))) as connection:
        return {
            "queue_batches": int(connection.execute("SELECT COUNT(*) FROM queue_batches").fetchone()[0]),
            "queue_members": int(connection.execute("SELECT COUNT(*) FROM queue_members").fetchone()[0]),
            "queue_leases": int(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0]),
            "queue_attempts": int(connection.execute("SELECT COUNT(*) FROM queue_attempts").fetchone()[0]),
            "queue_results": int(connection.execute("SELECT COUNT(*) FROM queue_results").fetchone()[0]),
            "queue_transitions": int(connection.execute("SELECT COUNT(*) FROM queue_transitions").fetchone()[0]),
            "composition_transactions": int(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0]),
            "composition_events": int(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0]),
            "composition_outbox": int(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0]),
        }


class QueueV12Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config, self.composition_config, self.owner, self.store = _new_store(self.root, self.clock)

    def tearDown(self) -> None:
        self.store._close()
        self.owner.close()
        self.temp.cleanup()

    def _assert_single_issued_batch(self, template: OperationTemplate, *, batch_id: bytes | None = None) -> None:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            batch_rows = connection.execute(
                "SELECT batch_id,batch_root,status FROM queue_batches ORDER BY admission_seq"
            ).fetchall()
            self.assertEqual(len(batch_rows), 1)
            durable_batch_id = bytes(batch_rows[0][0])
            if batch_id is not None:
                self.assertEqual(durable_batch_id, batch_id)
            self.assertEqual(batch_rows[0][2], "AWAITING_HANDOFF")

            members = connection.execute(
                "SELECT batch_position,operation_ref,admission_seq FROM queue_members WHERE batch_id=? ORDER BY batch_position",
                (durable_batch_id,),
            ).fetchall()
            self.assertEqual(len(members), 100)
            self.assertEqual([int(row[0]) for row in members], list(range(100)))
            self.assertEqual([int(row[2]) for row in members], list(range(1, 101)))
            operation_refs = tuple(bytes(row[1]) for row in members)
            self.assertTrue(all(len(operation_ref) == 32 for operation_ref in operation_refs))
            self.assertEqual(len(set(operation_refs)), 100)
            self.assertEqual(
                bytes(batch_rows[0][1]),
                _compute_batch_root_from_refs(template, operation_refs),
            )

            attempt = connection.execute(
                "SELECT reservation_before,reservation_after,proof_attempts,status,verifier_status "
                "FROM queue_attempts WHERE batch_id=?",
                (durable_batch_id,),
            ).fetchone()
            self.assertEqual(tuple(attempt), (0, 101, 101, "RESERVED", "UNRESERVED"))
            self.assertEqual(
                connection.execute(
                    "SELECT proof_attempts_used,source_u_used,next_admission_seq,nonterminal_count,"
                    "live_lease_count,next_transition_seq,next_attempt_seq FROM queue_metadata WHERE id=1"
                ).fetchone(),
                (101, 1, 100, 1, 0, 1, 1),
            )
            events = connection.execute(
                "SELECT transition_kind,event_bytes FROM queue_transitions ORDER BY sequence"
            ).fetchall()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0][0], "BATCH_ISSUED")
            event = json.loads(bytes(events[0][1]).decode("ascii"))
            self.assertEqual(event["status"], "AWAITING_HANDOFF")
            self.assertEqual(event["attempt"], 0)
            self.assertEqual(event["member_count"], 100)

        verified = queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )
        self.assertEqual(verified["status_counts"]["AWAITING_HANDOFF"], 1)
        self.assertEqual(verified["transition_count"], 1)

    def test_issue_precommit_failure_rolls_back_before_fresh_issue(self) -> None:
        request_id = bytes(range(32))
        template = OperationTemplate(
            "issue-precommit-retry",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 60_000,
        )

        def fail_before_commit(label: str) -> None:
            if label == "before_issue_commit":
                raise RuntimeError("injected-before-issue-commit")

        self.store._before_fault = fail_before_commit
        empty_counts = _counts(self.root / "state.sqlite")
        with self.assertRaisesRegex(RuntimeError, "injected-before-issue-commit"):
            self.store.issue_batch_v1(request_id=request_id, template=template)
        self.assertEqual(_counts(self.root / "state.sqlite"), empty_counts)

        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT proof_attempts_used,source_u_used,next_admission_seq,nonterminal_count,"
                    "next_transition_seq,next_attempt_seq FROM queue_metadata WHERE id=1"
                ).fetchone(),
                (0, 0, 0, 0, 0, 0),
            )
        absent = queue_independent.resolve_issue_request(
            self.root / "state.sqlite",
            request_id=request_id,
            expected_template=template.as_json,
            expected_config=self.config.as_json,
        )
        self.assertIsNone(absent.batch)

        self.store._before_fault = None
        batch = self.store.issue_batch_v1(request_id=request_id, template=template)
        replay = self.store.issue_batch_v1(request_id=request_id, template=template)
        self.assertEqual(replay, batch)
        resolved = queue_independent.resolve_issue_request(
            self.root / "state.sqlite",
            request_id=request_id,
            expected_template=template.as_json,
            expected_config=self.config.as_json,
        )
        self.assertEqual(resolved.request_version, 1)
        self.assertIsNotNone(resolved.batch)
        assert resolved.batch is not None
        self.assertEqual(resolved.batch.batch_id, batch.batch_id)
        self.assertEqual(resolved.batch.operation_refs, batch.operation_refs)
        self._assert_single_issued_batch(template, batch_id=batch.batch_id)

    def test_issue_expiry_at_commit_fence_rolls_back_reservation(self) -> None:
        request_id = bytes(range(32, 64))
        template = OperationTemplate(
            "issue-commit-fence-expiry",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 60_000,
        )

        def expire_before_commit(label: str) -> None:
            if label == "before_issue_commit":
                self.clock.now = template.valid_until_ms

        self.store._before_fault = expire_before_commit
        with self.assertRaisesRegex(QueueConflictError, "validity_expired"):
            self.store.issue_batch_v1(request_id=request_id, template=template)
        self.assertEqual(
            _counts(self.root / "state.sqlite"),
            {
                "queue_batches": 0,
                "queue_members": 0,
                "queue_leases": 0,
                "queue_attempts": 0,
                "queue_results": 0,
                "queue_transitions": 0,
                "composition_transactions": 0,
                "composition_events": 0,
                "composition_outbox": 0,
            },
        )
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT proof_attempts_used,source_u_used,next_admission_seq,nonterminal_count,"
                    "next_transition_seq,next_attempt_seq FROM queue_metadata WHERE id=1"
                ).fetchone(),
                (0, 0, 0, 0, 0, 0),
        )

        self.store._before_fault = None
        self.clock.now = template.valid_until_ms - 1_000
        batch = self.store.issue_batch_v1(request_id=request_id, template=template)
        self._assert_single_issued_batch(template, batch_id=batch.batch_id)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT proof_attempts_used,source_u_used FROM queue_metadata WHERE id=1"
                ).fetchone(),
                (101, 1),
            )
        queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )

    def test_issue_commit_fence_uses_monotonic_elapsed_when_wall_clock_stalls(self) -> None:
        request_id = bytes(range(64, 96))
        template = OperationTemplate(
            "issue-monotonic-fence-expiry",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 50_000,
        )
        with patch.object(
            self.store,
            "_monotonic_ns",
            side_effect=(10_000_000_000, 70_000_000_000),
        ):
            with self.assertRaisesRegex(QueueConflictError, "validity_expired"):
                self.store.issue_batch_v1(request_id=request_id, template=template)
        self.assertEqual(
            _counts(self.root / "state.sqlite")["queue_batches"],
            0,
        )
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT proof_attempts_used,source_u_used,next_admission_seq,nonterminal_count FROM queue_metadata WHERE id=1"
                ).fetchone(),
                (0, 0, 0, 0),
            )
        queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )

    def test_exact_issue_retry_reads_durable_batch_after_validity_expires(self) -> None:
        request_id = bytes(reversed(range(32)))
        template = OperationTemplate(
            "issue-exact-retry-after-expiry",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 5_000,
        )
        batch = self.store.issue_batch_v1(request_id=request_id, template=template)
        self.clock.now = template.valid_until_ms
        replay = self.store.issue_batch_v1(request_id=request_id, template=template)
        self.assertEqual(replay, batch)
        self.assertEqual(_counts(self.root / "state.sqlite")["queue_batches"], 1)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT proof_attempts_used,source_u_used,next_admission_seq FROM queue_metadata WHERE id=1"
                ).fetchone(),
                (101, 1, 100),
            )
        queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )

    def test_queue_event_clock_regression_fails_closed(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        with closing(self.store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(QueueIntegrityError, "queue_clock"):
                self.store._append_event(
                    connection,
                    kind="VERIFIER_UNKNOWN",
                    batch_id=batch.batch_id,
                    status="QUEUED",
                    error_code=None,
                    attempt=0,
                    at_ms=batch.template.valid_from_ms,
                    extra={"member_count": 100},
                )
            connection.rollback()
        queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )

    def test_handoff_commit_fence_holds_batch_when_validity_expires(self) -> None:
        batch = self.store.issue_batch(
            template=OperationTemplate(
                "handoff-commit-fence-expiry",
                1,
                self.config.profile_version,
                self.clock.now - 100,
                self.clock.now + 5_000,
            )
        )
        handoff = VolatileProofHandoff(bytearray(b"volatile-proof"))

        def expire_before_handoff_commit(label: str) -> None:
            if label == "before_handoff_commit":
                self.clock.now = batch.template.valid_until_ms

        self.store._before_fault = expire_before_handoff_commit
        with self.assertRaisesRegex(QueueConflictError, "validity_expired"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=handoff)
        self.assertTrue(handoff.closed)
        self.assertNotIn(batch.batch_id, self.store._handoffs)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status,last_error_code FROM queue_batches WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone(),
                ("HELD", "validity_expired"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT terminal_status,result_code FROM queue_results WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone(),
                ("HELD", "validity_expired"),
            )
            kinds = [
                row[0]
                for row in connection.execute(
                    "SELECT transition_kind FROM queue_transitions WHERE batch_id=? ORDER BY sequence",
                    (batch.batch_id,),
                )
            ]
            self.assertEqual(kinds, ["BATCH_ISSUED", "BATCH_HELD"])
            self.assertEqual(
                connection.execute(
                    "SELECT proof_attempts_used,source_u_used FROM queue_metadata WHERE id=1"
                ).fetchone(),
                (101, 1),
            )
        queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )

    def test_issue_postcommit_failure_is_indeterminate_and_burns_one_reservation(self) -> None:
        request_id = bytes(reversed(range(32)))
        template = OperationTemplate(
            "issue-postcommit-ambiguity",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 60_000,
        )

        def fail_after_commit(label: str) -> None:
            if label == "after_issue_commit":
                raise RuntimeError("injected-after-issue-commit")

        self.store._after_commit_fault = fail_after_commit
        with self.assertRaisesRegex(QueueIndeterminateError, "issue_result_indeterminate"):
            self.store.issue_batch_v1(request_id=request_id, template=template)
        self._assert_single_issued_batch(template)
        before_restart = queue_independent.resolve_issue_request(
            self.root / "state.sqlite",
            request_id=request_id,
            expected_template=template.as_json,
            expected_config=self.config.as_json,
        )
        self.assertIsNotNone(before_restart.batch)
        assert before_restart.batch is not None

        self.store._close()
        self.owner.close()
        self.config, self.composition_config, self.owner, self.store = _new_store(self.root, self.clock)
        recovered = self.store.issue_batch_v1(request_id=request_id, template=template)
        after_restart = queue_independent.resolve_issue_request(
            self.root / "state.sqlite",
            request_id=request_id,
            expected_template=template.as_json,
            expected_config=self.config.as_json,
        )
        self.assertIsNotNone(after_restart.batch)
        assert after_restart.batch is not None
        self.assertEqual(recovered.batch_id, before_restart.batch.batch_id)
        self.assertEqual(recovered.batch_root, before_restart.batch.batch_root)
        self.assertEqual(recovered.session_ref, before_restart.batch.session_ref)
        self.assertEqual(recovered.operation_refs, before_restart.batch.operation_refs)
        self.assertEqual(recovered.public_coin, before_restart.batch.public_coin)
        self.assertEqual(recovered.proof_context, before_restart.batch.proof_context)
        self.assertEqual(recovered.identity_digest, before_restart.batch.identity_digest)
        self.assertEqual(after_restart.batch.batch_id, recovered.batch_id)
        self.assertEqual(after_restart.batch.operation_refs, recovered.operation_refs)
        self.assertEqual(after_restart.batch.status, "HELD")
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
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

    def test_issue_request_v1_rejects_changed_template_without_second_reservation(self) -> None:
        request_id = bytes([0xA5]) * 32
        template = OperationTemplate(
            "issue-request-conflict",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 60_000,
        )
        batch = self.store.issue_batch_v1(request_id=request_id, template=template)
        changed = OperationTemplate(
            "issue-request-conflict-changed",
            1,
            self.config.profile_version,
            template.valid_from_ms,
            template.valid_until_ms,
        )
        before = _counts(self.root / "state.sqlite")
        with self.assertRaisesRegex(QueueConflictError, "issue_request_conflict"):
            self.store.issue_batch_v1(request_id=request_id, template=changed)
        self.assertEqual(_counts(self.root / "state.sqlite"), before)
        with patch.object(
            queue_independent,
            "_verify_connection",
            wraps=queue_independent._verify_connection,
        ) as verify_connection:
            retry = self.store.issue_batch_v1(request_id=request_id, template=template)
        self.assertEqual(verify_connection.call_count, 1)
        self.assertEqual(retry, batch)
        self._assert_single_issued_batch(template, batch_id=batch.batch_id)

    def test_issue_request_v1_concurrent_same_id_serializes_to_one_batch(self) -> None:
        request_id = bytes([0x5A]) * 32
        template = OperationTemplate(
            "issue-request-concurrent-retry",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 60_000,
        )
        barrier = threading.Barrier(3)
        result_lock = threading.Lock()
        batches: list[object] = []
        errors: list[BaseException] = []

        def issue() -> None:
            try:
                barrier.wait(timeout=5)
                batch = self.store.issue_batch_v1(request_id=request_id, template=template)
                with result_lock:
                    batches.append(batch)
            except BaseException as error:
                with result_lock:
                    errors.append(error)

        threads = [threading.Thread(target=issue) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0], batches[1])
        self._assert_single_issued_batch(template, batch_id=batches[0].batch_id)

    def test_issue_concurrent_writers_serialize_exact_100_member_reservations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config, _composition_config, owner, store = _new_store(root, clock, capacity=200)
            templates = {
                index: OperationTemplate(
                    f"concurrent-issue-{index}",
                    1,
                    config.profile_version,
                    clock.now - 100,
                    clock.now + 60_000,
                )
                for index in range(2)
            }
            barrier = threading.Barrier(3)
            result_lock = threading.Lock()
            batches: dict[int, object] = {}
            errors: list[BaseException] = []

            def issue(index: int) -> None:
                try:
                    barrier.wait(timeout=5)
                    batch = store.issue_batch_v1(
                        request_id=bytes([index + 1]) * 32,
                        template=templates[index],
                    )
                    with result_lock:
                        batches[index] = batch
                except BaseException as error:
                    with result_lock:
                        errors.append(error)

            threads = [threading.Thread(target=issue, args=(index,)) for index in range(2)]
            try:
                for thread in threads:
                    thread.start()
                barrier.wait(timeout=5)
                for thread in threads:
                    thread.join(timeout=10)
                self.assertFalse(any(thread.is_alive() for thread in threads))
                self.assertEqual(errors, [])
                self.assertEqual(set(batches), {0, 1})

                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    batch_rows = connection.execute(
                        "SELECT batch_id,admission_seq,batch_root FROM queue_batches ORDER BY admission_seq"
                    ).fetchall()
                    self.assertEqual(len(batch_rows), 2)
                    self.assertEqual([int(row[1]) for row in batch_rows], [1, 2])
                    all_refs: list[bytes] = []
                    for batch_id_value, admission_seq_value, root_value in batch_rows:
                        batch_id = bytes(batch_id_value)
                        admission_seq = int(admission_seq_value)
                        batch = next(value for value in batches.values() if value.batch_id == batch_id)
                        members = connection.execute(
                            "SELECT batch_position,operation_ref,admission_seq FROM queue_members "
                            "WHERE batch_id=? ORDER BY batch_position",
                            (batch_id,),
                        ).fetchall()
                        self.assertEqual(len(members), 100)
                        self.assertEqual([int(row[0]) for row in members], list(range(100)))
                        self.assertEqual(
                            [int(row[2]) for row in members],
                            list(range((admission_seq - 1) * 100 + 1, admission_seq * 100 + 1)),
                        )
                        operation_refs = tuple(bytes(row[1]) for row in members)
                        self.assertEqual(operation_refs, batch.operation_refs)
                        self.assertEqual(
                            bytes(root_value),
                            _compute_batch_root_from_refs(templates[admission_seq - 1], operation_refs),
                        )
                        all_refs.extend(operation_refs)

                    self.assertEqual(len(all_refs), 200)
                    self.assertEqual(len(set(all_refs)), 200)
                    self.assertEqual(
                        connection.execute(
                            "SELECT reservation_before,reservation_after,proof_attempts FROM queue_attempts "
                            "ORDER BY attempt_id"
                        ).fetchall(),
                        [(0, 101, 101), (101, 202, 101)],
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT proof_attempts_used,source_u_used,next_admission_seq,"
                            "nonterminal_count,next_transition_seq,next_attempt_seq "
                            "FROM queue_metadata WHERE id=1"
                        ).fetchone(),
                        (202, 2, 200, 2, 2, 2),
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT sequence,transition_kind FROM queue_transitions ORDER BY sequence"
                        ).fetchall(),
                        [(1, "BATCH_ISSUED"), (2, "BATCH_ISSUED")],
                    )

                verified = queue_independent.verify_database(
                    root / "state.sqlite", expected_config=config.as_json
                )
                self.assertEqual(verified["status_counts"]["AWAITING_HANDOFF"], 2)
                self.assertEqual(verified["transition_count"], 2)
            finally:
                store._close()
                owner.close()

    def test_runtime_owner_rejects_empty_and_partial_markers_without_reclaim(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        for marker in (b"", b"1"):
            lock.write_bytes(marker)
            with self.subTest(marker=marker), self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
                _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
            self.assertEqual(lock.read_bytes(), marker)
            lock.unlink()

    def test_runtime_owner_rejected_live_legacy_marker_is_not_rebound_or_erased(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        marker = queue_module._QueueRuntimeOwnership._marker_bytes(os.getpid())
        lock.write_bytes(marker)
        with self.assertRaisesRegex(VerificationQueueError, "runtime_already_owned"):
            _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        self.assertEqual(lock.read_bytes(), marker)
        lock.unlink()

    def test_runtime_owner_serializes_stale_reclaimers_with_os_lock(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        lock.write_bytes(queue_module._QueueRuntimeOwnership._marker_bytes(9_999_999_999))
        barrier = threading.Barrier(2)
        release = threading.Event()
        owners: list[_QueueRuntimeOwnership] = []
        results: list[str] = []

        def create_owner() -> None:
            barrier.wait()
            try:
                owner = _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
            except VerificationQueueError as error:
                results.append(str(error))
            else:
                owners.append(owner)
                results.append("acquired")
                release.wait(5)

        threads = [threading.Thread(target=create_owner) for _ in range(2)]
        try:
            with patch.object(queue_module, "_runtime_owner_process_is_live", return_value=False):
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(1)
                release.set()
                for thread in threads:
                    thread.join(5)
            self.assertEqual(sorted(results), ["acquired", "runtime_already_owned"])
            self.assertEqual(len(owners), 1)
            self.assertTrue(lock.exists())
        finally:
            release.set()
            for thread in threads:
                thread.join(5)
            for owner in owners:
                if not owner._closed:
                    owner.close()
        if os.name == "nt":
            self.assertFalse(lock.exists())
        else:
            self.assertEqual(lock.read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)

    def test_runtime_owner_close_failure_is_retryable_without_releasing_identity(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        owner = _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
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
                    with self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
                        owner.close()
            else:
                original_write_marker = queue_module._QueueRuntimeOwnership._write_marker

                def fail_once(current_owner, marker: bytes) -> None:
                    nonlocal failures
                    if marker == _RUNTIME_LOCK_RELEASED_MARKER and failures == 0:
                        failures += 1
                        raise OSError("marker")
                    original_write_marker(current_owner, marker)

                with patch.object(queue_module._QueueRuntimeOwnership, "_write_marker", new=fail_once):
                    with self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
                        owner.close()
            self.assertFalse(owner._closed)
            self.assertTrue(lock.exists())
            owner.close()
            self.assertTrue(owner._closed)
            if os.name == "nt":
                self.assertFalse(lock.exists())
            else:
                self.assertEqual(lock.read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)
        finally:
            if not owner._closed:
                owner.close()

    def test_runtime_owner_revalidates_path_after_native_lock(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"

        def replace_path() -> None:
            lock.unlink()
            lock.write_bytes(b"replacement")

        if os.name == "nt":
            original_lock = queue_module._runtime_win_lock

            def swap_before_lock(handle: object):
                replace_path()
                return original_lock(handle)

            patcher = patch.object(queue_module, "_runtime_win_lock", side_effect=swap_before_lock)
        else:
            import fcntl

            original_flock = fcntl.flock

            def swap_before_lock(fd: int, operation: int):
                if operation & fcntl.LOCK_EX:
                    replace_path()
                return original_flock(fd, operation)

            patcher = patch.object(fcntl, "flock", side_effect=swap_before_lock)
        with patcher, self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
            _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        self.assertEqual(lock.read_bytes(), b"replacement")
        lock.unlink()

    def test_runtime_owner_constructor_failure_before_lock_preserves_recoverable_path(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        if os.name == "nt":
            patcher = patch.object(queue_module, "_runtime_win_lock", side_effect=OSError(5, "forced-pre-lock"))
        else:
            import fcntl
            patcher = patch.object(fcntl, "flock", side_effect=OSError(11, "forced-pre-lock"))
        with patcher, self.assertRaisesRegex(VerificationQueueError, "runtime_(?:scope|already_owned)"):
            _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        self.assertTrue(lock.exists())
        self.assertEqual(lock.read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)
        recovered = _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        recovered.close()
        if os.name == "nt":
            self.assertFalse(lock.exists())
        else:
            self.assertEqual(lock.read_bytes(), _RUNTIME_LOCK_RELEASED_MARKER)

    def test_runtime_owner_actual_subprocess_stale_reclaimers_have_one_acquirer(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        dead_pid = int(subprocess.run(
            [sys.executable, "-B", "-c", "import os; print(os.getpid())"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip())
        lock.write_bytes(queue_module._QueueRuntimeOwnership._marker_bytes(dead_pid))
        ready = self.root / "stale-owner-ready"
        gate = self.root / "stale-owner-gate"
        cwd = str(Path(__file__).resolve().parents[3])
        first = second = None
        try:
            first = subprocess.Popen(
                [sys.executable, "-B", "-c", _OWNER_CHILD_SOURCE, str(lock), "gate", str(ready), str(gate)],
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 5
            while not ready.exists() and first.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not ready.exists():
                first_output, first_error = first.communicate(timeout=5)
                self.fail((first.returncode, first_output, first_error))
            second = subprocess.Popen(
                [sys.executable, "-B", "-c", _OWNER_CHILD_SOURCE, str(lock), "plain", str(ready), str(gate)],
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            second_output, second_error = second.communicate(timeout=5)
            self.assertEqual(second_error, "")
            second_result = _child_result(subprocess.CompletedProcess(second.args, second.returncode, second_output, second_error))
            self.assertEqual(second_result["status"], "error")
            self.assertEqual(second_result["message"], "runtime_already_owned")
            gate.write_text("go", encoding="ascii")
            first_output, first_error = first.communicate(timeout=5)
            first_result = _child_result(subprocess.CompletedProcess(first.args, first.returncode, first_output, first_error))
            self.assertEqual(first_result["status"], "acquired")
            self.assertEqual(first_result["close"], "ok")
        finally:
            gate.write_text("go", encoding="ascii")
            for process in (first, second):
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            if lock.exists():
                lock.unlink()

    @unittest.skipUnless(os.name == "nt", "Windows initialization-sharing branch is not executed on POSIX")
    def test_runtime_owner_does_not_expose_partial_windows_initialization(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        ready = self.root / "initialization-ready"
        gate = self.root / "initialization-gate"
        cwd = str(Path(__file__).resolve().parents[3])
        first = subprocess.Popen(
            [sys.executable, "-B", "-c", _OWNER_INITIALIZATION_CHILD_SOURCE, str(lock), str(ready), str(gate)],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and first.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists())
            second = subprocess.run(
                [sys.executable, "-B", "-c", _OWNER_CHILD_SOURCE, str(lock), "plain", str(ready), str(gate)],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
            )
            second_result = _child_result(second)
            self.assertEqual(second_result, {"status": "error", "type": "VerificationQueueError", "message": "runtime_already_owned"})
            gate.write_text("go", encoding="ascii")
            first_output, first_error = first.communicate(timeout=5)
            self.assertEqual(first_error, "")
            first_result = _child_result(subprocess.CompletedProcess(first.args, first.returncode, first_output, first_error))
            self.assertEqual(first_result, {"status": "acquired", "close": "ok"})
        finally:
            gate.write_text("go", encoding="ascii")
            if first.poll() is None:
                first.terminate()
                first.wait(timeout=5)
            if lock.exists():
                lock.unlink()

    def test_runtime_owner_close_does_not_expose_replacement_before_native_release(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        owner = _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        ready = self.root / "release-ready"
        gate = self.root / "release-gate"
        original_release = queue_module._QueueRuntimeOwnership._release_os
        close_result: dict[str, str] = {}

        def gated_release(current_owner, errors):
            ready.write_text("release", encoding="ascii")
            deadline = time.monotonic() + 10
            while not gate.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            return original_release(current_owner, errors)

        def close_owner() -> None:
            try:
                owner.close()
                close_result["status"] = "ok"
            except BaseException as error:
                close_result["status"] = f"{type(error).__name__}:{error}"

        thread = threading.Thread(target=close_owner)
        try:
            with patch.object(queue_module._QueueRuntimeOwnership, "_release_os", new=gated_release):
                thread.start()
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                child = subprocess.run(
                    [sys.executable, "-B", "-c", _OWNER_CHILD_SOURCE, str(lock), "plain", str(ready), str(gate)],
                    cwd=str(Path(__file__).resolve().parents[3]),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                result = _child_result(child)
                self.assertEqual(result["status"], "error")
                gate.write_text("go", encoding="ascii")
                thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(close_result, {"status": "ok"})
            self.assertTrue(owner._closed)
        finally:
            gate.write_text("go", encoding="ascii")
            thread.join(5)
            if not owner._closed:
                errors: list[BaseException] = []
                owner._release_os(errors)
            if lock.exists():
                lock.unlink()

    def test_runtime_owner_identity_reuse_is_never_released_by_path(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        owner = _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        lock.unlink()
        lock.write_bytes(b"replacement")
        with self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
            owner.close()
        self.assertEqual(lock.read_bytes(), b"replacement")
        errors: list[BaseException] = []
        owner._release_os(errors)
        self.assertEqual(errors, [])
        lock.unlink()

    @unittest.skipUnless(os.name == "nt", "Windows native fault branch is not executed on POSIX")
    def test_windows_native_release_and_marker_faults_fail_closed_or_retry(self) -> None:
        self.store._close()
        self.owner.close()
        lock = self.root / "state.sqlite.runtime-lock"
        owner = _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        original_unlock = queue_module._runtime_win_unlock
        unlock_failures = 0

        def fail_unlock_once(handle: object, overlapped: object) -> None:
            nonlocal unlock_failures
            if unlock_failures == 0:
                unlock_failures += 1
                raise OSError(5, "forced-unlock-failure")
            original_unlock(handle, overlapped)

        with patch.object(queue_module, "_runtime_win_unlock", side_effect=fail_unlock_once):
            with self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
                owner.close()
        self.assertFalse(owner._closed)
        self.assertIsNotNone(owner._handle)
        self.assertIsNotNone(owner._overlapped)
        owner.close()
        self.assertTrue(owner._closed)
        self.assertFalse(lock.exists())

        owner = _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        original_close = queue_module._runtime_win_close
        close_failures = 0

        def fail_close_once(handle: object) -> None:
            nonlocal close_failures
            if close_failures == 0:
                close_failures += 1
                raise OSError(5, "forced-close-failure")
            original_close(handle)

        with patch.object(queue_module, "_runtime_win_close", side_effect=fail_close_once):
            with self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
                owner.close()
        self.assertFalse(owner._closed)
        self.assertIsNotNone(owner._handle)
        self.assertIsNone(owner._overlapped)
        owner.close()
        self.assertTrue(owner._closed)
        self.assertFalse(lock.exists())

        lock.write_bytes(b"BL/RUNTIME-LOCK/v1/0000000001")
        with patch.object(queue_module, "_runtime_win_read_marker", side_effect=OSError(5, "forced-read-failure")):
            with self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
                _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        self.assertEqual(lock.read_bytes(), b"BL/RUNTIME-LOCK/v1/0000000001")
        lock.unlink()

        calls = 0
        native_write = queue_module._RUNTIME_WIN_WriteFile

        def fail_after_short_write(handle, payload, length, count, overlapped):
            nonlocal calls
            if calls == 0:
                calls += 1
                return native_write(handle, payload, 1, count, overlapped)
            ctypes.set_last_error(5)
            return False

        with patch.object(queue_module, "_RUNTIME_WIN_WriteFile", side_effect=fail_after_short_write):
            with self.assertRaisesRegex(VerificationQueueError, "runtime_scope"):
                _QueueRuntimeOwnership(lock_path=lock, parent=self.root)
        self.assertTrue(lock.exists())
        self.assertEqual(len(lock.read_bytes()), 1)
        lock.unlink()

    def test_handoff_is_memory_owned_bounded_and_fully_wiped(self) -> None:
        caller = bytearray(b"secret-proof")
        handoff = VolatileProofHandoff(caller)
        self.assertEqual(caller, bytearray())
        caller.extend(b"caller-mutation")
        self.assertEqual(handoff.read(6), b"secret")
        self.assertEqual(handoff.read(), b"-proof")
        self.assertFalse(handoff.exhausted)
        self.assertEqual(handoff.read(1), b"")
        self.assertTrue(handoff.exhausted)
        self.assertEqual(handoff.total_read, len(b"secret-proof"))
        self.assertTrue(handoff.consumed)
        handoff.close()
        handoff.close()
        self.assertTrue(handoff.closed)
        self.assertEqual(len(handoff._buffer), 0)
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_closed"):
            handoff.read(1)

        drained = VolatileProofHandoff(bytearray(b"drain-me"))
        drained.drain()
        self.assertTrue(drained.exhausted)
        self.assertEqual(drained.total_read, len(b"drain-me"))
        drained.close()

    def test_handoff_rejects_callbacks_and_nonexact_types_before_sql(self) -> None:
        template = OperationTemplate("handoff-boundary", 1, self.config.profile_version, self.clock.now - 100, self.clock.now + 60_000)
        batch = self.store.issue_batch(template=template)
        trap = _CallbackTrap()
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_stream"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=trap)
        self.assertEqual((trap.read_calls, trap.close_calls), (0, 0))

        raw = b"raw-proof"
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_stream"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=raw)

        used_handoff = VolatileProofHandoff(bytearray(b"already-used"))
        used_handoff.read(1)
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_used"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=used_handoff)
        self.assertTrue(used_handoff.closed)
        self.assertEqual(len(used_handoff._buffer), 0)

        subclass_payload = _ByteArraySubclass(b"subclass-proof")
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_stream"):
            VolatileProofHandoff(subclass_payload)
        self.assertEqual(subclass_payload, _ByteArraySubclass(b"subclass-proof"))

        handoff_subclass = _HandoffSubclass(bytearray(b"handoff-subclass"))
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_stream"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=handoff_subclass)
        self.assertEqual(handoff_subclass.close_calls, 0)
        VolatileProofHandoff.close(handoff_subclass)

        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_empty"):
            VolatileProofHandoff(bytearray())
        with patch("parked.private_zk.app.minimal_clearance_verification_queue.ADMISSION_CAP_BYTES", 3):
            oversized = bytearray(b"1234")
            with self.assertRaisesRegex(QueueHeldError, "proof_handoff_oversize"):
                VolatileProofHandoff(oversized)
            self.assertEqual(oversized, bytearray(b"1234"))

        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "AWAITING_HANDOFF")
            self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 0))
        counts = _counts(self.root / "state.sqlite")
        self.assertEqual((counts["queue_attempts"], counts["queue_leases"], counts["queue_results"]), (1, 0, 0))
        self.assertEqual(self.store._handoffs, {})

    def test_binding_and_expiry_rejections_close_and_wipe_handoffs(self) -> None:
        template = OperationTemplate("binding-handoff", 1, self.config.profile_version, self.clock.now - 100, self.clock.now + 60_000)
        batch = self.store.issue_batch(template=template)
        forged = replace(batch, identity_digest=bytes(64))
        binding_handoff = VolatileProofHandoff(bytearray(b"binding-proof"))
        with patch.object(lifecycle_adapter, "run_contained_verifier_stream") as sidecar:
            with self.assertRaisesRegex(QueueConflictError, "batch_binding"):
                self.store.submit_batch_handoff(issued_batch=forged, proof_stream=binding_handoff)
            sidecar.assert_not_called()
        self.assertTrue(binding_handoff.closed)
        self.assertEqual(len(binding_handoff._buffer), 0)
        self.assertEqual(self.store._handoffs, {})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config, _composition_config, owner, store = _new_store(root, clock)
            try:
                expiring = store.issue_batch(template=OperationTemplate("expired-handoff", 1, config.profile_version, clock.now - 100, clock.now + 100))
                clock.now = expiring.template.valid_until_ms
                expiry_handoff = VolatileProofHandoff(bytearray(b"expiry-proof"))
                with patch.object(lifecycle_adapter, "run_contained_verifier_stream") as sidecar:
                    with self.assertRaisesRegex(QueueConflictError, "validity_expired"):
                        store.submit_batch_handoff(issued_batch=expiring, proof_stream=expiry_handoff)
                    sidecar.assert_not_called()
                self.assertTrue(expiry_handoff.closed)
                self.assertEqual(len(expiry_handoff._buffer), 0)
                self.assertEqual(store._handoffs, {})
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "HELD")
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_attempts").fetchone()[0], 1)
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)
                    self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 0))
            finally:
                store._close()
                owner.close()

    def test_submission_sql_rollback_closes_and_wipes_handoff_without_queue_mutation(self) -> None:
        template = OperationTemplate("rollback-handoff", 1, self.config.profile_version, self.clock.now - 100, self.clock.now + 60_000)
        batch = self.store.issue_batch(template=template)
        handoff = VolatileProofHandoff(bytearray(b"rollback-proof"))
        with patch.object(self.store, "_append_event", side_effect=RuntimeError("submit rollback")):
            with self.assertRaisesRegex(RuntimeError, "submit rollback"):
                self.store.submit_batch_handoff(issued_batch=batch, proof_stream=handoff)
        self.assertTrue(handoff.closed)
        self.assertEqual(len(handoff._buffer), 0)
        self.assertEqual(self.store._handoffs, {})
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "AWAITING_HANDOFF")
            self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 0))
        counts = _counts(self.root / "state.sqlite")
        self.assertEqual((counts["queue_attempts"], counts["queue_leases"], counts["queue_results"]), (1, 0, 0))

        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"retry-proof")))

    def test_state_database_derives_profile12_context_without_durable_copy(self) -> None:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            self.assertEqual(tables, {"queue_metadata", "queue_batches", "queue_members", "queue_leases", "queue_attempts", "queue_source_admissions", "queue_results", "queue_transitions", "composition_meta", "composition_transactions", "composition_events", "composition_outbox"})
            self.assertEqual(connection.execute("SELECT schema_version FROM queue_metadata").fetchone()[0], 13)
            self.assertEqual(connection.execute("SELECT schema_version FROM composition_meta").fetchone()[0], 4)
            self.assertEqual(connection.execute("PRAGMA foreign_key_list(composition_transactions)").fetchone()[2], "queue_members")
            self.assertEqual(tuple(row[1] for row in connection.execute("PRAGMA table_info(queue_batches)"))[-1], "public_coin")
            self.assertNotIn("proof_context", tuple(row[1] for row in connection.execute("PRAGMA table_info(queue_batches)")))
        batch = _prepare(self.store, self.config, self.clock)
        expected = _profile12_context(session_ref=batch.session_ref, ordered_batch_root=batch.batch_root, public_coin=batch.public_coin, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms)
        self.assertEqual(len(batch.proof_context), 64)
        self.assertEqual(batch.proof_context, expected)
        self.assertEqual(independent_profile12_context(session_ref=batch.session_ref, batch_root=batch.batch_root, public_coin=batch.public_coin, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms), batch.proof_context)
        self.assertEqual(self.config.profile_version, "BLIND-DIRECT-MASK-FAEST256F-DEG3-V1")
        self.assertEqual(self.config.profile_epoch, 12)
        self.assertNotIn(batch.proof_context, (self.root / "state.sqlite").read_bytes())

    def test_profile12_context_rejects_old_bindings_zero_identity_and_invalid_window(self) -> None:
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_epoch"):
            QueueConfig("old-profile10-epoch", 100, profile_epoch=10)
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_version"):
            QueueConfig("old-profile10-version", 100, profile_version=OLD_PROFILE10_TOKEN)
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_invalid"):
            QueueConfig("legacycfg10", 100, profile_digest=OLD_PROFILE10_FINGERPRINT)
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_epoch"):
            QueueConfig("old-profile-epoch", 100, profile_epoch=9)
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_version"):
            QueueConfig("old-profile-version", 100, profile_version=OLD_PROFILE9_TOKEN)
        with self.assertRaisesRegex(VerificationQueueError, "source_auth_profile"):
            QueueConfig("old-source-profile", 100, source_auth_profile=OLD_SOURCE_AUTH_PROFILE9)
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_invalid"):
            QueueConfig("legacycfg", 100, profile_digest=OLD_PROFILE9_FINGERPRINT)
        batch = _prepare(self.store, self.config, self.clock)
        with self.assertRaisesRegex(QueueIntegrityError, "profile12_public_coin"):
            replace(batch, public_coin=bytes(96))
        forged_context = bytearray(batch.proof_context)
        forged_context[0] ^= 1
        with self.assertRaisesRegex(QueueIntegrityError, "profile12_context"):
            replace(batch, proof_context=bytes(forged_context))
        with self.assertRaisesRegex(QueueIntegrityError, "profile12_context"):
            replace(batch, session_ref=bytes([batch.session_ref[0] ^ 1]) + batch.session_ref[1:])
        with self.assertRaisesRegex(QueueIntegrityError, "profile12_context"):
            replace(batch, public_coin=bytes([batch.public_coin[0] ^ 1]) + batch.public_coin[1:])
        with self.assertRaisesRegex(QueueIntegrityError, "profile12_context"):
            replace(batch, proof_context=batch.proof_context[:-1])
        for start, end in ((batch.template.valid_from_ms, batch.template.valid_from_ms), (batch.template.valid_until_ms, batch.template.valid_until_ms), (batch.template.valid_from_ms, batch.template.valid_from_ms + 3_600_001)):
            with self.subTest(start=start, end=end), self.assertRaisesRegex(QueueIntegrityError, "statement_window"):
                _profile12_context(session_ref=batch.session_ref, ordered_batch_root=batch.batch_root, public_coin=batch.public_coin, valid_from_ms=start, valid_until_ms=end)

        for offset in (0, 16, 32, 48, 63):
            forged = bytearray(batch.proof_context)
            forged[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(VerificationQueueError, "profile12_context"):
                replace(batch, proof_context=bytes(forged))

    def test_profile9_database_is_rejected_without_rewrite(self) -> None:
        database = self.root / "state.sqlite"
        self.store._close()
        self.owner.close()
        old_config = dict(self.config.as_json)
        old_config.update(
            profile_version=OLD_PROFILE9_TOKEN,
            profile_digest=OLD_PROFILE9_FINGERPRINT.hex().upper(),
            profile_epoch=9,
            source_auth_profile=OLD_SOURCE_AUTH_PROFILE9,
        )
        old_config_bytes = json.dumps(old_config, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        old_config_digest = hashlib.sha3_512(OLD_PROFILE9_MATERIAL + old_config_bytes).digest()
        with closing(sqlite3.connect(str(database))) as connection:
            connection.execute("DROP TRIGGER queue_metadata_config_guard")
            connection.execute("UPDATE queue_metadata SET config_json=?,config_digest=? WHERE id=1", (old_config_bytes, old_config_digest))
            trigger_sql = dict(_TRIGGER_DEFS)["queue_metadata_config_guard"]
            connection.execute(trigger_sql)
            connection.commit()
        before = database.read_bytes()
        with self.assertRaisesRegex(VerificationQueueError, "queue_config_binding"):
            _VerificationQueueStore(
                path=database,
                config=self.config,
                owner=_QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root),
                clock=self.clock,
                composition_config=self.composition_config,
            )
        self.assertEqual(database.read_bytes(), before)

    def test_profile10_database_is_rejected_without_rewrite(self) -> None:
        database = self.root / "state.sqlite"
        self.store._close()
        self.owner.close()
        old_config = dict(self.config.as_json)
        old_config.update(
            profile_version=OLD_PROFILE10_TOKEN,
            profile_digest=OLD_PROFILE10_FINGERPRINT.hex().upper(),
            profile_epoch=10,
        )
        old_config_bytes = json.dumps(old_config, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        old_config_digest = hashlib.sha3_512(OLD_PROFILE10_MATERIAL + old_config_bytes).digest()
        with closing(sqlite3.connect(str(database))) as connection:
            connection.execute("DROP TRIGGER queue_metadata_config_guard")
            connection.execute("UPDATE queue_metadata SET config_json=?,config_digest=? WHERE id=1", (old_config_bytes, old_config_digest))
            trigger_sql = dict(_TRIGGER_DEFS)["queue_metadata_config_guard"]
            connection.execute(trigger_sql)
            connection.commit()
        before = database.read_bytes()
        with self.assertRaisesRegex(VerificationQueueError, "queue_config_binding"):
            _VerificationQueueStore(
                path=database,
                config=self.config,
                owner=_QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root),
                clock=self.clock,
                composition_config=self.composition_config,
            )
        self.assertEqual(database.read_bytes(), before)

    def test_exact_100_members_and_one_101_unit_attempt_record(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        work = self.store._claim_next_batch()
        self.assertIsNotNone(work)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_members WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], 100)
            attempt = connection.execute("SELECT reservation_before,reservation_after,proof_attempts,status FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)).fetchone()
            self.assertEqual(tuple(attempt), (0, 101, 101, "RESERVED"))
            self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 1))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)

    def test_terminal_completion_requires_verifier_reservation_without_state_or_outbox_effects(self) -> None:
        for status, accepted, error_code in (("VERIFIED", True, None), ("REJECTED", False, "proof_or_source_not_accepted")):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                clock = _Clock()
                config, _composition_config, owner, store = _new_store(root, clock)
                try:
                    batch = _prepare(store, config, clock)
                    work = store._claim_next_batch()
                    self.assertIsNotNone(work)
                    verifier_result = _verifier_result(config, batch, accepted=accepted)
                    controls = _controls(batch.operation_refs)
                    before = _counts(root / "state.sqlite")
                    with self.assertRaisesRegex(QueueLeaseError, "completion_not_live"):
                        store._complete_batch(work, status=status, verifier_result=verifier_result, error_code=error_code, state_controls=controls)
                    self.assertEqual(_counts(root / "state.sqlite"), before)
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "LEASED")
                        self.assertEqual(connection.execute("SELECT status,verifier_status FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)).fetchone(), ("RESERVED", "UNRESERVED"))
                        self.assertEqual(connection.execute("SELECT verifier_v_used FROM queue_metadata WHERE id=1").fetchone()[0], 0)
                    verify_database(root / "state.sqlite")
                finally:
                    store._close()
                    owner.close()

    def test_accepted_batch_commits_queue_and_all_state_rows_once(self) -> None:
        batch = _prepare(self.store, self.config, self.clock, proof=b"raw_proof raw_signature frame_payload challenge_bytes opening_bytes response_bytes")
        verifier = _Verifier(self.config)
        port = _DispositionPort()
        result = self.store._process_one_batch(verifier=verifier, state_disposition_port=port)
        self.assertEqual((result.status, result.accepted_count, verifier.calls, len(port.calls)), ("VERIFIED", 100, 1, 1))
        outcome = port.calls[0][2]
        self.assertFalse(hasattr(outcome, "effective_directive"))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "VERIFIED")
            self.assertEqual(connection.execute("SELECT terminal_status,proof_accepted,source_authenticated FROM queue_results WHERE batch_id=?", (batch.batch_id,)).fetchone(), ("VERIFIED", 1, 1))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions WHERE status='APPLIED'").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events WHERE event_kind='APPLIED'").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE status='READY'").fetchone()[0], 100)
            self.assertEqual({row[0] for row in connection.execute("SELECT DISTINCT effective_directive FROM composition_transactions")}, {"CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"})
            self.assertEqual({row[0] for row in connection.execute("SELECT DISTINCT policy_result FROM composition_transactions")}, {"PASS", "MISSING", "AMBIGUOUS", "FAIL"})
        raw = (self.root / "state.sqlite").read_bytes()
        wal = self.root / "state.sqlite-wal"
        if wal.exists():
            raw += wal.read_bytes()
        for marker in (b"raw_proof", b"raw_signature", b"frame_payload", b"challenge_bytes", b"opening_bytes", b"response_bytes"):
            self.assertNotIn(marker, raw)
        self.assertNotIn(batch.proof_context, raw)
        self.assertEqual(verify_database(self.root / "state.sqlite")["accepted_operation_count"], 100)
        reconstructed = read_verified_batch(self.root / "state.sqlite", batch.batch_id)
        self.assertEqual(len(reconstructed.jobs), 100)

    def test_verifier_acceptance_never_supplies_clearance(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        port = _DispositionPort(policies=("MISSING",) * 100)
        result = self.store._process_one_batch(verifier=_Verifier(self.config), state_disposition_port=port)
        self.assertEqual((result.status, result.accepted_count, len(port.calls)), ("VERIFIED", 100, 1))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT DISTINCT effective_directive FROM composition_transactions").fetchone()[0], "HOLD")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions WHERE policy_result='PASS'").fetchone()[0], 0)
        self.assertEqual(resolve_effective_directive("PASS"), "CLEAR")
        self.assertEqual(batch.batch_id, port.calls[0][0])

    def test_rejected_and_malformed_paths_do_not_call_state_port_or_compose(self) -> None:
        port = _DispositionPort()
        first = _prepare(self.store, self.config, self.clock)
        rejected = self.store._process_one_batch(verifier=_Verifier(self.config, accepted=False), state_disposition_port=port)
        second = _prepare(self.store, self.config, self.clock)
        held = self.store._process_one_batch(verifier=_MalformedVerifier(), state_disposition_port=port)
        self.assertEqual((rejected.status, held.status, len(port.calls)), ("REJECTED", "HELD", 0))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (first.batch_id,)).fetchone()[0], "REJECTED")
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (second.batch_id,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)

    def test_lease_expiry_at_verifier_start_fence_prevents_verifier_launch(self) -> None:
        batch = _prepare(self.store, self.config, self.clock, duration=120_000)
        verifier = _Verifier(self.config)

        def expire_before_verifier_commit(label: str) -> None:
            if label == "before_verifier_start_commit":
                self.clock.now += queue_module._LEASE_MS

        self.store._before_fault = expire_before_verifier_commit
        result = self.store._process_one_batch(
            verifier=verifier,
            state_disposition_port=_DispositionPort(),
        )
        self.assertEqual((result.status, result.error_code, result.accepted_count), ("HELD", "lease_expired", 0))
        self.assertEqual(verifier.calls, 0)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status,last_error_code FROM queue_batches WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone(),
                ("HELD", "lease_expired"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status,verifier_status FROM queue_attempts WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone(),
                ("HELD", "UNRESERVED"),
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)
            events = [
                json.loads(bytes(row[0]).decode("ascii"))
                for row in connection.execute(
                    "SELECT event_bytes FROM queue_transitions WHERE batch_id=? ORDER BY sequence",
                    (batch.batch_id,),
                )
            ]
            self.assertNotIn("VERIFIER_STARTED", [event["kind"] for event in events])
            self.assertEqual(events[-1]["kind"], "BATCH_HELD")
        queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )

    def test_completion_expiry_at_commit_fence_rolls_back_composition(self) -> None:
        batch = _prepare(self.store, self.config, self.clock, duration=120_000)

        def expire_before_completion_commit(label: str) -> None:
            if label == "before_queue_commit":
                self.clock.now += queue_module._LEASE_MS

        self.store._before_fault = expire_before_completion_commit
        result = self.store._process_one_batch(
            verifier=_Verifier(self.config),
            state_disposition_port=_DispositionPort(),
        )
        self.assertEqual((result.status, result.error_code, result.accepted_count), ("HELD", "lease_expired", 0))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status,last_error_code FROM queue_batches WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone(),
                ("HELD", "lease_expired"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT terminal_status,proof_accepted,source_authenticated,result_code FROM queue_results WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone(),
                ("HELD", 0, 0, "lease_expired"),
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)
            attempt = connection.execute(
                "SELECT status,verifier_status,closed_ms FROM queue_attempts WHERE batch_id=?",
                (batch.batch_id,),
            ).fetchone()
            self.assertEqual(tuple(attempt[:2]), ("HELD", "UNKNOWN"))
            self.assertEqual(attempt[2], batch.template.valid_from_ms + 100 + queue_module._LEASE_MS)
        queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )

    def test_terminal_transaction_rolls_back_every_cross_table_stage_and_keeps_live_lease(self) -> None:
        labels = ("after_composition_transactions", "after_composition_events", "after_composition_outbox", "after_composition_meta", "before_composition_commit", "before_queue_commit")
        for label in labels:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                clock = _Clock()
                config, _composition_config, owner, store = _new_store(root, clock)
                try:
                    batch = _prepare(store, config, clock)
                    work = store._claim_next_batch()
                    store._reserve_verifier_launch(work)
                    controls = _controls(batch.operation_refs)
                    verifier_result = _verifier_result(config, batch)
                    store._before_fault = lambda actual, expected=label: (_ for _ in ()).throw(RuntimeError("injected")) if actual == expected else None
                    with self.assertRaisesRegex(RuntimeError, "injected"):
                        store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "LEASED")
                        self.assertEqual(connection.execute("SELECT status,verifier_status FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)).fetchone(), ("RESERVED", "STARTED"))
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 1)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_results").fetchone()[0], 0)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0], 0)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)
                finally:
                    store._close()
                    owner.close()

    def test_stale_lease_token_is_fenced_without_any_state_write(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        work = self.store._claim_next_batch()
        self.store._reserve_verifier_launch(work)
        controls = _controls(batch.operation_refs)
        verifier_result = _verifier_result(self.config, batch)
        stale = replace(work, lease_token=bytes(32))
        with self.assertRaises(QueueLeaseError):
            self.store._complete_batch(stale, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        state = _counts(self.root / "state.sqlite")
        self.assertEqual((state["queue_results"], state["composition_transactions"], state["composition_events"], state["composition_outbox"], state["queue_leases"]), (0, 0, 0, 0, 1))

    def test_duplicate_replay_requires_complete_outbox_and_event_chain(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        work = self.store._claim_next_batch()
        self.store._reserve_verifier_launch(work)
        controls = _controls(batch.operation_refs)
        verifier_result = _verifier_result(self.config, batch)
        self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            saved_outbox = tuple(connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (batch.operation_refs[0],)).fetchone())
            connection.execute("DELETE FROM composition_outbox WHERE operation_ref=?", (batch.operation_refs[0],))
            connection.commit()
        with self.assertRaises(CompositionConflictError):
            self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("INSERT INTO composition_outbox VALUES (?,?,?,?,?,?,?,?)", saved_outbox)
            connection.execute("DROP TRIGGER composition_events_no_update")
            connection.execute("UPDATE composition_events SET event_digest=? WHERE operation_ref=?", (bytes(64), batch.operation_refs[0]))
            connection.commit()
        with self.assertRaises(CompositionConflictError):
            self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "VERIFIED")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 100)

    def test_state_outbox_requires_room_for_one_exact_batch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = QueueConfig("state-outbox-min-capacity-test", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=99)
            owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
            try:
                with self.assertRaisesRegex(VerificationQueueError, "queue_configuration"):
                    _VerificationQueueStore(
                        path=root / "state.sqlite",
                        config=config,
                        owner=owner,
                        composition_config=composition_config,
                    )
            finally:
                owner.close()

    def test_state_outbox_capacity_blocks_claim_before_verifier_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("state-outbox-capacity-test", 200)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
            owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
            store = _VerificationQueueStore(
                path=root / "state.sqlite",
                config=config,
                owner=owner,
                clock=clock,
                composition_config=composition_config,
            )
            try:
                first_batch = _prepare(store, config, clock)
                first_verifier = _Verifier(config)
                first = store._process_one_batch(verifier=first_verifier, state_disposition_port=_DispositionPort())
                self.assertEqual((first.status, first.accepted_count), ("VERIFIED", 100))
                self.assertEqual(first_verifier.calls, 1)

                second_batch = _prepare(store, config, clock)
                before = _counts(root / "state.sqlite")
                retained_handoff = store._handoffs[second_batch.batch_id]
                with self.assertRaisesRegex(queue_module.QueueBackpressureError, "state_outbox_capacity"):
                    store._claim_next_batch()
                self.assertEqual(_counts(root / "state.sqlite"), before)
                self.assertIs(store._handoffs[second_batch.batch_id], retained_handoff)
                self.assertFalse(retained_handoff.closed)
                self.assertEqual(store._last_claim_error, "state_outbox_capacity")
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    self.assertEqual(
                        connection.execute("SELECT status,attempt FROM queue_batches WHERE batch_id=?", (second_batch.batch_id,)).fetchone(),
                        ("QUEUED", 0),
                    )
                    self.assertEqual(
                        connection.execute("SELECT status,verifier_status FROM queue_attempts WHERE batch_id=?", (second_batch.batch_id,)).fetchone(),
                        ("RESERVED", "UNRESERVED"),
                    )
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)
                    self.assertEqual(connection.execute("SELECT proof_attempts_used,verifier_v_used FROM queue_metadata").fetchone(), (202, 1))
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE status IN ('READY','LEASED','DELIVERY_UNCONFIRMED')").fetchone()[0], 100)
                self.assertNotEqual(first_batch.batch_id, second_batch.batch_id)
            finally:
                store._close()
                owner.close()

    def test_versioned_admission_state_handoff_binds_identity_and_rejects_replay(self) -> None:
        template = OperationTemplate(
            "shared-assertion",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 60_000,
        )
        batch = self.store.issue_batch(template=template)
        identity_profile = "accepted"
        executable_size, executable_sha256 = queue_module._SOURCE_IDENTITY_PINS[identity_profile]
        retry_limit = queue_module.SOURCE_ADMISSION_RETRY_LIMIT
        admission = self.store.admit_source_launch(
            batch=batch,
            request_digest=queue_module._source_request_digest(
                batch,
                source_key_epoch=self.config.source_key_epoch,
                retry_limit=retry_limit,
            ),
            retry_limit=retry_limit,
            source_configuration_digest=queue_module.source_configuration_digest(
                identity_profile=identity_profile,
                executable_size_bytes=executable_size,
                executable_sha256=executable_sha256,
                retry_limit=retry_limit,
            ),
            source_identity_profile=identity_profile,
            source_executable_size_bytes=executable_size,
            source_executable_sha256=executable_sha256,
        )
        authorization = self.store.start_source_launch(admission=admission)
        ownership = authorization.consume()
        self.store.finish_source_launch(authorization=authorization, ownership=ownership, success=True)
        self.store.submit_batch_handoff(
            issued_batch=batch,
            proof_stream=VolatileProofHandoff(bytearray(b"accepted-source-handoff-proof")),
        )
        work = self.store._claim_next_batch()
        self.assertIsNotNone(work)
        self.store._reserve_verifier_launch(work)
        verifier_result = _verifier_result(self.config, batch)
        controls = _controls(batch.operation_refs)
        captured: list[bytes] = []
        original_decoder = queue_independent.verify_admission_state_handoff

        def capture_handoff(connection, raw: bytes, *, expected_config):
            captured.append(raw)
            return original_decoder(connection, raw, expected_config=expected_config)

        with patch.object(queue_independent, "verify_admission_state_handoff", side_effect=capture_handoff):
            result = self.store._complete_batch(
                work,
                status="VERIFIED",
                verifier_result=verifier_result,
                state_controls=controls,
            )
        self.assertEqual((result.status, result.accepted_count, len(captured)), ("VERIFIED", 100, 1))
        handoff = captured[0]
        decoded = queue_independent.parse_admission_state_handoff(handoff)
        self.assertEqual(decoded["source"]["status"], "COMPLETED")
        self.assertEqual(decoded["retry_policy"]["source_attempt_retry_limit"], retry_limit)
        self.assertEqual(decoded["attestation"]["proof_accepted"], True)
        self.assertEqual(decoded["attestation"]["source_authenticated"], True)
        self.assertEqual(
            [(event["kind"], event["status"], event["attempt"]) for event in decoded["events"]],
            [
                ("HANDOFF_SUBMITTED", "QUEUED", 0),
                ("VERIFICATION_STARTED", "LEASED", 1),
                ("VERIFIER_STARTED", "LEASED", 1),
                ("VERIFIER_COMPLETED", "LEASED", 1),
                ("BATCH_COMPLETED", "VERIFIED", 1),
            ],
        )
        self.assertEqual(len(decoded["operations"]), 100)
        self.assertEqual(
            [item["position"] for item in decoded["operations"]],
            list(range(100)),
        )
        self.assertTrue(all(item["operation_ref"] == item["outbox_correlation_id"] for item in decoded["operations"]))

        def reframe(value: dict[str, object]) -> bytes:
            payload = queue_independent._json_bytes(value)
            return queue_independent._ADMISSION_STATE_HANDOFF_MAGIC + len(payload).to_bytes(4, "big") + payload

        bad_status = json.loads(handoff[12:].decode("ascii"))
        bad_status["events"][0]["status"] = "AWAITING_HANDOFF"
        bad_correlation = json.loads(handoff[12:].decode("ascii"))
        bad_correlation["operations"][0]["outbox_correlation_id"] = "00" * 32
        bad_duplicate = json.loads(handoff[12:].decode("ascii"))
        bad_duplicate["operations"][1]["operation_ref"] = bad_duplicate["operations"][0]["operation_ref"]
        bad_duplicate["operations"][1]["outbox_correlation_id"] = bad_duplicate["operations"][0]["operation_ref"]
        bad_version = json.loads(handoff[12:].decode("ascii"))
        bad_version["schema"] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/ADMISSION-STATE-HANDOFF/v0"
        for malformed, code in (
            (reframe(bad_status), "state_handoff_events"),
            (reframe(bad_correlation), "state_handoff_outbox_ref"),
            (reframe(bad_duplicate), "state_handoff_replay"),
            (reframe(bad_version), "state_handoff_version"),
            (handoff[:-1], "state_handoff_length"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(queue_independent.IndependentQueueError, code):
                queue_independent.parse_admission_state_handoff(malformed)

        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(queue_independent.IndependentQueueError, "state_handoff_replay"):
                queue_independent.verify_admission_state_handoff(
                    connection,
                    handoff,
                    expected_config=self.config.as_json,
                )
            connection.rollback()

        before_retry = _counts(self.root / "state.sqlite")
        duplicate = self.store._complete_batch(
            work,
            status="VERIFIED",
            verifier_result=verifier_result,
            state_controls=controls,
        )
        self.assertEqual((duplicate.status, duplicate.accepted_count), ("VERIFIED", 100))
        self.assertEqual(_counts(self.root / "state.sqlite"), before_retry)

    def test_duplicate_replay_fences_durable_identity_before_composition(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        work = self.store._claim_next_batch()
        self.store._reserve_verifier_launch(work)
        controls = _controls(batch.operation_refs)
        verifier_result = _verifier_result(self.config, batch)
        first = self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        duplicate = self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        self.assertEqual((first.status, duplicate.status, duplicate.accepted_count), ("VERIFIED", "VERIFIED", 100))

        def snapshot() -> tuple[tuple[tuple[str, int], ...], tuple[bytes | None, ...], tuple[bytes, ...]]:
            with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
                table_names = ("queue_batches", "queue_members", "queue_leases", "queue_attempts", "queue_results", "queue_transitions", "composition_transactions", "composition_events", "composition_outbox")
                counts = tuple((name, int(connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0])) for name in table_names)
                queue_root = connection.execute("SELECT head_root FROM queue_metadata WHERE id=1").fetchone()[0]
                composition_roots = connection.execute("SELECT event_head,state_continuity_root,state_audit_head,state_clearance_root,payment_root FROM composition_meta WHERE id=1").fetchone()
                roots = tuple(None if value is None else bytes(value) for value in (queue_root, *composition_roots))
                batch_roots = tuple(bytes(row[0]) for row in connection.execute("SELECT batch_root FROM queue_batches ORDER BY admission_seq"))
                return counts, roots, batch_roots

        before = snapshot()
        forged_attempt_work = replace(work, attempt=999)
        with self.assertRaises(QueueLeaseError) as attempt_error:
            self.store._complete_batch(forged_attempt_work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        self.assertEqual(str(attempt_error.exception), "completion_not_live")
        self.assertEqual(snapshot(), before)

        forged_template = replace(batch.template, assertion_identifier="forged-assertion")
        forged_root = _compute_batch_root_from_refs(forged_template, batch.operation_refs)
        forged_context = _profile12_context(session_ref=work.batch.session_ref, ordered_batch_root=forged_root, public_coin=work.batch.public_coin, valid_from_ms=forged_template.valid_from_ms, valid_until_ms=forged_template.valid_until_ms)
        forged_batch = replace(work.batch, template=forged_template, batch_root=forged_root, proof_context=forged_context)
        forged_work = replace(work, batch=forged_batch)
        forged_result = _verifier_result(self.config, forged_batch)
        with self.assertRaises(QueueLeaseError) as error:
            self.store._complete_batch(forged_work, status="VERIFIED", verifier_result=forged_result, state_controls=controls)
        self.assertEqual(str(error.exception), "completion_not_live")
        self.assertEqual(snapshot(), before)

    def test_startup_burns_a_live_session_and_never_resumes_it(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        self.assertIsNotNone(self.store._claim_next_batch())
        self.store._close()
        self.owner.close()
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.root / "state.sqlite", config=self.config, owner=self.owner, clock=self.clock, composition_config=self.composition_config)
        self.assertEqual(self.store._startup_recovered_count, 1)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT status FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)

    def test_expired_active_lease_is_burned_before_another_batch_is_claimed(self) -> None:
        self.store._close()
        self.owner.close()
        self.temp.cleanup()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config, self.composition_config, self.owner, self.store = _new_store(self.root, self.clock, capacity=200)
        first = _prepare(self.store, self.config, self.clock, duration=300_000)
        second = _prepare(self.store, self.config, self.clock, duration=300_000)
        self.assertIsNotNone(self.store._claim_next_batch())
        self.clock.now += 61_000
        next_work = self.store._claim_next_batch()
        self.assertIsNotNone(next_work)
        self.assertEqual(self.store._last_claim_held_count, 1)
        self.assertEqual(next_work.batch.batch_id, second.batch_id)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (first.batch_id,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (second.batch_id,)).fetchone()[0], "LEASED")

    def test_claim_commit_fence_holds_batch_when_validity_expires(self) -> None:
        batch = _prepare(self.store, self.config, self.clock, duration=5_000)

        def expire_before_claim_commit(label: str) -> None:
            if label == "before_claim_commit":
                self.clock.now = batch.template.valid_until_ms

        self.store._before_fault = expire_before_claim_commit
        work = self.store._claim_next_batch()
        self.assertIsNone(work)
        self.assertEqual(self.store._last_claim_error, "validity_expired")
        self.assertEqual(self.store._last_claim_held_count, 1)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status,last_error_code FROM queue_batches WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone(),
                ("HELD", "validity_expired"),
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)
            self.assertEqual(
                connection.execute(
                    "SELECT proof_attempts_used,live_lease_count,nonterminal_count FROM queue_metadata WHERE id=1"
                ).fetchone(),
                (101, 0, 0),
            )
            events = [
                json.loads(bytes(row[0]).decode("ascii"))
                for row in connection.execute(
                    "SELECT event_bytes FROM queue_transitions WHERE batch_id=? ORDER BY sequence",
                    (batch.batch_id,),
                )
            ]
            self.assertEqual([event["kind"] for event in events], ["BATCH_ISSUED", "HANDOFF_SUBMITTED", "BATCH_HELD"])
            self.assertEqual(events[-1]["at_ms"], batch.template.valid_until_ms)
        queue_independent.verify_database(
            self.root / "state.sqlite", expected_config=self.config.as_json
        )

    def test_claim_clock_waits_for_sqlite_write_transaction(self) -> None:
        for expect_claim in (True, False):
            with self.subTest(expect_claim=expect_claim), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                clock = _Clock()
                capacity = 200 if expect_claim else 100
                config, _composition_config, owner, store = _new_store(root, clock, capacity=capacity)
                competing = sqlite3.connect(str(root / "state.sqlite"), timeout=5.0)
                claim_thread: threading.Thread | None = None
                claim_outcomes: list[object] = []
                claim_errors: list[BaseException] = []
                begin_attempted = threading.Event()
                begin_acquired = threading.Event()
                owner_checked = threading.Event()
                observed_connections = []
                claim_thread_id: list[int | None] = [None]
                clock_samples: list[tuple[int, bool, bool]] = []
                lifecycle_samples: list[tuple[bool, bool, int, int, str]] = []

                try:
                    expiring = _prepare(store, config, clock, duration=5_000)
                    eligible = _prepare(store, config, clock, duration=60_000) if expect_claim else None
                    initial_now = clock.now
                    post_acquisition_now = expiring.template.valid_until_ms + (5_000 if expect_claim else 0)
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        expected_next = connection.execute(
                            "SELECT next_eligible_ms FROM queue_batches WHERE batch_id=?",
                            ((eligible or expiring).batch_id,),
                        ).fetchone()[0]
                    self.assertEqual(expected_next, initial_now)

                    # Simulate a queued row whose eligibility is just ahead of the
                    # stale pre-wait sample. The clock advances only while the
                    # competing SQLite writer prevents BEGIN IMMEDIATE.
                    clock.now = initial_now - 1
                    competing.execute("BEGIN IMMEDIATE")
                    self.assertTrue(competing.in_transaction)

                    original_connect = store._connect
                    original_sqlite_connect = sqlite3.connect
                    original_assert_owner = store._assert_owner
                    original_now_ms = clock.now_ms
                    original_check_lifecycle = store._check_lifecycle_transition_locked

                    class ObservedConnection(sqlite3.Connection):
                        def __init__(self, *args, **kwargs) -> None:
                            super().__init__(*args, **kwargs)
                            self.closed_in_transaction: bool | None = None

                        def execute(self, statement: str, parameters=()):
                            if statement.strip().upper() == "BEGIN IMMEDIATE":
                                begin_attempted.set()
                                cursor = super().execute(statement, parameters)
                                begin_acquired.set()
                                return cursor
                            return super().execute(statement, parameters)

                        def close(self) -> None:
                            self.closed_in_transaction = self.in_transaction
                            super().close()

                    def observed_sqlite_connect(database, *args, **kwargs):
                        if Path(database) == root / "state.sqlite":
                            kwargs["factory"] = ObservedConnection
                        return original_sqlite_connect(database, *args, **kwargs)

                    def observed_connect():
                        with patch.object(sqlite3, "connect", new=observed_sqlite_connect):
                            connection = original_connect()
                        observed_connections.append(connection)
                        return connection

                    def observed_assert_owner() -> None:
                        original_assert_owner()
                        if threading.get_ident() == claim_thread_id[0]:
                            owner_checked.set()

                    def observed_now_ms() -> int:
                        value = original_now_ms()
                        if threading.get_ident() == claim_thread_id[0]:
                            clock_samples.append((value, begin_acquired.is_set(), owner_checked.is_set()))
                        return value

                    def observed_lifecycle(connection, **kwargs) -> None:
                        lifecycle_samples.append(
                            (
                                connection.in_transaction,
                                owner_checked.is_set(),
                                kwargs["now_ms"],
                                clock.now,
                                kwargs["operation"],
                            )
                        )
                        return original_check_lifecycle(connection, **kwargs)

                    def claim() -> None:
                        claim_thread_id[0] = threading.get_ident()
                        try:
                            claim_outcomes.append(store._claim_next_batch())
                        except BaseException as error:
                            claim_errors.append(error)

                    with patch.object(store, "_connect", new=observed_connect), patch.object(
                        store, "_assert_owner", new=observed_assert_owner
                    ), patch.object(clock, "now_ms", new=observed_now_ms), patch.object(
                        store,
                        "_check_lifecycle_transition_locked",
                        new=observed_lifecycle,
                    ):
                        claim_thread = threading.Thread(target=claim, name="queue-claim-clock-test")
                        claim_thread.start()
                        self.assertTrue(begin_attempted.wait(timeout=5))
                        self.assertTrue(owner_checked.is_set())
                        self.assertFalse(begin_acquired.is_set())
                        owner.assert_live()
                        with closing(sqlite3.connect(str(root / "state.sqlite"), timeout=0.0)) as probe:
                            with self.assertRaises(sqlite3.OperationalError):
                                probe.execute("BEGIN IMMEDIATE")
                        self.assertTrue(competing.in_transaction)

                        clock.now = post_acquisition_now
                        competing.commit()
                        claim_thread.join(timeout=10)
                        self.assertFalse(claim_thread.is_alive())

                    self.assertEqual(claim_errors, [])
                    self.assertEqual(len(claim_outcomes), 1)
                    expected_clock_samples = 3 if expect_claim else 2
                    self.assertEqual(
                        clock_samples,
                        [(post_acquisition_now, True, True)] * expected_clock_samples,
                    )
                    self.assertTrue(begin_acquired.is_set())
                    self.assertTrue(observed_connections)
                    self.assertTrue(all(item.closed_in_transaction is False for item in observed_connections))
                    self.assertEqual(
                        lifecycle_samples,
                        (
                            [(True, True, post_acquisition_now, post_acquisition_now, "claimNextBatch")]
                            if expect_claim
                            else []
                        ),
                    )
                    owner.assert_live()

                    work = claim_outcomes[0]
                    self.assertEqual(work is not None, expect_claim)
                    self.assertEqual(store._last_claim_held_count, 1)
                    if expect_claim:
                        self.assertEqual(work.batch.batch_id, eligible.batch_id)
                    else:
                        self.assertIsNone(work)

                    duplicate = store._claim_next_batch()
                    self.assertIsNone(duplicate)
                    owner.assert_live()

                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        batches = connection.execute(
                            "SELECT batch_id,status,next_eligible_ms,created_ms,updated_ms,last_error_code "
                            "FROM queue_batches ORDER BY admission_seq"
                        ).fetchall()
                        attempts = connection.execute(
                            "SELECT batch_id,reservation_before,reservation_after,proof_attempts,status,reserved_ms,closed_ms,result_code "
                            "FROM queue_attempts ORDER BY attempt_id"
                        ).fetchall()
                        results = connection.execute(
                            "SELECT batch_id,terminal_status,completed_ms,attempt,error_code FROM queue_results"
                        ).fetchall()
                        leases = connection.execute(
                            "SELECT batch_id,leased_ms,expires_ms FROM queue_leases"
                        ).fetchall()
                        meta = connection.execute(
                            "SELECT proof_attempts_used,live_lease_count,nonterminal_count FROM queue_metadata WHERE id=1"
                        ).fetchone()
                        events = [
                            (str(kind), json.loads(bytes(raw).decode("ascii")))
                            for kind, raw in connection.execute(
                                "SELECT transition_kind,event_bytes FROM queue_transitions ORDER BY sequence"
                            )
                        ]
                        self.assertEqual(
                            connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0],
                            1 if expect_claim else 0,
                        )
                        self.assertEqual(
                            connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0],
                            0,
                        )
                        self.assertEqual(
                            connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0],
                            0,
                        )
                        self.assertEqual(
                            connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0],
                            0,
                        )

                    expected_batches = [
                        (
                            expiring.batch_id,
                            "HELD",
                            initial_now,
                            initial_now,
                            post_acquisition_now,
                            "validity_expired",
                        )
                    ]
                    expected_attempts = [
                        (expiring.batch_id, 0, 101, 101, "HELD", initial_now, post_acquisition_now, "validity_expired")
                    ]
                    expected_results = [
                        (expiring.batch_id, "HELD", post_acquisition_now, 0, "validity_expired")
                    ]
                    expected_events = {"BATCH_HELD": 1, "VERIFICATION_STARTED": 0}
                    expected_meta = (101, 0, 0)
                    if expect_claim:
                        expected_batches.append(
                            (eligible.batch_id, "LEASED", initial_now, initial_now, post_acquisition_now, None)
                        )
                        expected_attempts.append(
                            (eligible.batch_id, 101, 202, 101, "RESERVED", initial_now, None, None)
                        )
                        expected_results = [(expiring.batch_id, "HELD", post_acquisition_now, 0, "validity_expired")]
                        expected_leases = [(eligible.batch_id, post_acquisition_now, post_acquisition_now + queue_module._LEASE_MS)]
                        expected_events["VERIFICATION_STARTED"] = 1
                        expected_meta = (202, 1, 1)
                    else:
                        expected_leases = []

                    self.assertEqual(batches, expected_batches)
                    self.assertEqual(attempts, expected_attempts)
                    self.assertEqual(results, expected_results)
                    self.assertEqual(leases, expected_leases)
                    self.assertEqual(meta, expected_meta)
                    self.assertEqual(
                        {kind: sum(actual == kind for actual, _event in events) for kind in expected_events},
                        expected_events,
                    )
                    held_event = next(event for kind, event in events if kind == "BATCH_HELD")
                    self.assertEqual(held_event["at_ms"], post_acquisition_now)
                    self.assertEqual(held_event["error_code"], "validity_expired")
                    if expect_claim:
                        started_event = next(event for kind, event in events if kind == "VERIFICATION_STARTED")
                        self.assertEqual(started_event["batch_id"], eligible.batch_id.hex().upper())
                        self.assertEqual(started_event["at_ms"], post_acquisition_now)
                        self.assertEqual(started_event["reservation_before"], 101)
                        self.assertEqual(started_event["reservation_after"], 202)
                    independently_verified = verify_database(
                        root / "state.sqlite", expected_config=config.as_json
                    )
                    self.assertEqual(
                        independently_verified["status_counts"]["LEASED"],
                        1 if expect_claim else 0,
                    )
                    self.assertEqual(independently_verified["transition_count"], len(events))
                finally:
                    if competing.in_transaction:
                        competing.rollback()
                    competing.close()
                    if claim_thread is not None:
                        claim_thread.join(timeout=10)
                    store._close()
                    owner.close()

    def test_lifecycle_sidecar_submit_claim_event_bytes_and_independent_verify(self) -> None:
        batch = self.store.issue_batch(
            template=OperationTemplate(
                "lifecycle-queue-integration",
                1,
                self.config.profile_version,
                self.clock.now - 100,
                self.clock.now + 60_000,
            )
        )
        handoff = VolatileProofHandoff(bytearray(b"lifecycle-integration-proof"))
        with closing(self.store._connect()) as connection:
            before_meta = tuple(connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone())
            attempt = connection.execute(
                "SELECT reservation_before,reservation_after FROM queue_attempts WHERE batch_id=?",
                (batch.batch_id,),
            ).fetchone()
        self.assertIsNotNone(attempt)

        lifecycle_durations: list[float] = []
        lifecycle_results: list[tuple[str, object]] = []
        original_check_lifecycle = self.store._check_lifecycle_transition_locked

        def measured_lifecycle(connection, **kwargs):
            started = time.monotonic()
            try:
                result = original_check_lifecycle(connection, **kwargs)
                lifecycle_results.append((kwargs["operation"], result))
                return result
            finally:
                lifecycle_durations.append(time.monotonic() - started)

        with patch.object(
            self.store,
            "_check_lifecycle_transition_locked",
            new=measured_lifecycle,
        ):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=handoff)
            self.assertFalse(handoff.closed)
            submitted = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
            self.assertEqual(submitted["status_counts"]["QUEUED"], 1)
            self.assertEqual(submitted["transition_count"], 2)
            with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
                submitted_row = connection.execute(
                    "SELECT status,next_eligible_ms,updated_ms FROM queue_batches WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone()
            with patch.object(
                queue_independent,
                "_verify_connection",
                wraps=queue_independent._verify_connection,
            ) as independent_scan:
                work = self.store._claim_next_batch()
            self.assertEqual(independent_scan.call_count, 2)

        self.assertIsNotNone(work)
        self.assertEqual(work.batch.batch_id, batch.batch_id)
        self.assertEqual(len(lifecycle_durations), 2)
        submit_decision = next(result for operation, result in lifecycle_results if operation == "submitHandoff")
        claim_decision = next(result for operation, result in lifecycle_results if operation == "claimNextBatch")
        claim_after = claim_decision.after
        self.assertEqual(submit_decision.after.batch, "queued")
        self.assertEqual(work.attempt, claim_after.attempt)
        self.assertEqual(work.claim_sequence, claim_after.claim_sequence)
        self.assertEqual(work.lease_started_ms, claim_after.updated_ms)
        self.assertEqual(work.lease_expires_ms, claim_after.lease_expires_ms)
        self.assertTrue(all(duration <= 3.0 for duration in lifecycle_durations))

        expected_events = [
            {
                "schema": queue_module._SCHEMA,
                "sequence": 2,
                "kind": "HANDOFF_SUBMITTED",
                "batch_id": batch.batch_id.hex().upper(),
                "status": "QUEUED",
                "error_code": None,
                "attempt": 0,
                "at_ms": self.clock.now,
                "member_count": 100,
            },
            {
                "schema": queue_module._SCHEMA,
                "sequence": 3,
                "kind": "VERIFICATION_STARTED",
                "batch_id": batch.batch_id.hex().upper(),
                "status": "LEASED",
                "error_code": None,
                "attempt": 1,
                "at_ms": self.clock.now,
                "member_count": 100,
                "reservation_before": int(attempt[0]),
                "reservation_after": int(attempt[1]),
            },
        ]
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            event_rows = connection.execute(
                "SELECT event_bytes FROM queue_transitions WHERE sequence IN (2,3) ORDER BY sequence"
            ).fetchall()
            after_meta = tuple(connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone())
            claimed_row = connection.execute(
                "SELECT status,attempt,updated_ms FROM queue_batches WHERE batch_id=?",
                (batch.batch_id,),
            ).fetchone()
            lease = connection.execute(
                "SELECT attempt,claim_sequence,leased_ms,expires_ms FROM queue_leases WHERE batch_id=?",
                (batch.batch_id,),
            ).fetchone()
            self.assertEqual(
                submitted_row,
                (
                    submit_decision.after.batch.upper(),
                    submit_decision.after.next_eligible_ms,
                    submit_decision.after.updated_ms,
                ),
            )
            self.assertEqual(
                claimed_row,
                (claim_after.batch.upper(), claim_after.attempt, claim_after.updated_ms),
            )
            self.assertEqual(
                lease,
                (
                    claim_after.attempt,
                    claim_after.claim_sequence,
                    claim_after.updated_ms,
                    claim_after.lease_expires_ms,
                ),
            )
            self.assertEqual(
                tuple(row[0] for row in event_rows),
                (
                    queue_module._json_bytes(expected_events[0]),
                    lifecycle_adapter.canonical_queue_event_bytes(claim_decision.event),
                ),
            )
            self.assertEqual(
                lifecycle_adapter.canonical_queue_event_bytes(claim_decision.event),
                queue_module._json_bytes(expected_events[1]),
            )
            self.assertEqual(after_meta[16], claim_after.global_live_lease_count)
            self.assertEqual(
                event_rows[0][0],
                lifecycle_adapter.canonical_queue_event_bytes(submit_decision.event),
            )
            self.assertEqual(
                connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0],
                "LEASED",
            )
        for index in (17, 20, 21, 22, 23, 24):
            self.assertEqual(after_meta[index], before_meta[index])

        verified = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(verified["status_counts"]["LEASED"], 1)
        self.assertEqual(verified["transition_count"], 3)
        self.assertNotIn("attempts", verified)
        self.assertNotIn("leases", verified)

    def test_claim_rejects_transaction_mutation_after_verified_image_capture(self) -> None:
        batch = self.store.issue_batch(
            template=OperationTemplate(
                "lifecycle-verified-image-stale",
                1,
                self.config.profile_version,
                self.clock.now - 100,
                self.clock.now + 60_000,
            )
        )
        handoff = VolatileProofHandoff(bytearray(b"verified-image-stale-proof"))
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=handoff)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            before_batch = tuple(
                connection.execute(
                    "SELECT * FROM queue_batches WHERE batch_id=?", (batch.batch_id,)
                ).fetchone()
            )
            before_attempt = tuple(
                connection.execute(
                    "SELECT * FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)
                ).fetchone()
            )
            before_meta = tuple(connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone())
            before_event_count = connection.execute(
                "SELECT COUNT(*) FROM queue_transitions"
            ).fetchone()[0]

        original_check = self.store._check_lifecycle_transition_locked

        def mutate_after_image_capture(connection, **kwargs):
            changed = connection.execute(
                "UPDATE queue_batches SET updated_ms=updated_ms+1 WHERE batch_id=?",
                (batch.batch_id,),
            )
            self.assertEqual(changed.rowcount, 1)
            return original_check(connection, **kwargs)

        with (
            patch.object(
                self.store,
                "_check_lifecycle_transition_locked",
                new=mutate_after_image_capture,
            ),
            patch.object(
                lifecycle_adapter,
                "evaluate_lifecycle_transition",
                side_effect=AssertionError("stale image must fail before Lifecycle evaluation"),
            ) as lifecycle_evaluation,
            self.assertRaises(queue_module.QueueIntegrityError),
        ):
            self.store._claim_next_batch()

        self.assertEqual(lifecycle_evaluation.call_count, 0)
        self.assertFalse(handoff.closed)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                tuple(connection.execute(
                    "SELECT * FROM queue_batches WHERE batch_id=?", (batch.batch_id,)
                ).fetchone()),
                before_batch,
            )
            self.assertEqual(
                tuple(connection.execute(
                    "SELECT * FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)
                ).fetchone()),
                before_attempt,
            )
            self.assertEqual(tuple(connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()), before_meta)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM queue_transitions").fetchone()[0],
                before_event_count,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0],
                0,
            )
        verified = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(verified["status_counts"]["QUEUED"], 1)
        self.assertEqual(verified["transition_count"], before_event_count)
        retry = self.store._claim_next_batch()
        self.assertIsNotNone(retry)
        self.assertEqual(retry.batch.batch_id, batch.batch_id)
        retried = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(retried["status_counts"]["LEASED"], 1)
        self.assertEqual(retried["transition_count"], before_event_count + 1)

    def test_lifecycle_sidecar_failures_rollback_and_allow_fresh_retry(self) -> None:
        batch = self.store.issue_batch(
            template=OperationTemplate(
                "lifecycle-queue-retry",
                1,
                self.config.profile_version,
                self.clock.now - 100,
                self.clock.now + 60_000,
            )
        )

        def assert_single_reservation() -> None:
            with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
                attempts = connection.execute(
                    "SELECT reservation_before,reservation_after,proof_attempts,status "
                    "FROM queue_attempts WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchall()
                self.assertEqual(len(attempts), 1)
                self.assertEqual(tuple(attempts[0]), (0, 101, 101, "RESERVED"))
                self.assertEqual(
                    connection.execute(
                        "SELECT proof_attempts_used FROM queue_metadata WHERE id=1"
                    ).fetchone()[0],
                    101,
                )

        assert_single_reservation()
        first_handoff = VolatileProofHandoff(bytearray(b"first-lifecycle-proof"))
        with patch.object(
            lifecycle_adapter,
            "run_contained_verifier_stream",
            side_effect=lifecycle_adapter.VerifierProcessError("verifier_timeout"),
        ):
            with self.assertRaisesRegex(
                lifecycle_adapter.LifecycleAdapterError,
                "lifecycle_process:verifier_timeout",
            ):
                self.store.submit_batch_handoff(issued_batch=batch, proof_stream=first_handoff)
        self.assertTrue(first_handoff.closed)
        failed_submit = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(failed_submit["status_counts"]["AWAITING_HANDOFF"], 1)
        self.assertEqual(failed_submit["transition_count"], 1)
        assert_single_reservation()

        provenance_handoff = VolatileProofHandoff(bytearray(b"unreviewed-lifecycle-proof"))
        reviewed_manifest = "a" * 64
        reported_manifest = "b" * 64
        provenance = (
            "BL-LIFECYCLE-PROVENANCE/1;"
            f"manifest_sha256={reported_manifest};"
            f"exe_size={lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES};"
            f"exe_sha256={lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256.hex()}\n"
        ).encode("ascii")
        provenance_result = SimpleNamespace(
            exit_code=0,
            timed_out=False,
            cap_enforced=True,
            active_process_limit=1,
            stdout=b"response must not be decoded",
            stderr=provenance,
        )
        with (
            patch.object(lifecycle_adapter, "_LIFECYCLE_RUNTIME_MODE", "source-bound-v1"),
            patch.object(
                lifecycle_adapter,
                "_LIFECYCLE_SOURCE_MANIFEST_SHA256",
                reviewed_manifest,
            ),
            patch.object(
                lifecycle_adapter,
                "run_contained_verifier_stream",
                return_value=provenance_result,
            ) as runner,
        ):
            with self.assertRaisesRegex(
                lifecycle_adapter.LifecycleAdapterError,
                "lifecycle_provenance_manifest",
            ):
                self.store.submit_batch_handoff(
                    issued_batch=batch,
                    proof_stream=provenance_handoff,
                )
        self.assertEqual(runner.call_count, 1)
        self.assertTrue(provenance_handoff.closed)
        rejected_submit = verify_database(
            self.root / "state.sqlite",
            expected_config=self.config.as_json,
        )
        self.assertEqual(rejected_submit["status_counts"]["AWAITING_HANDOFF"], 1)
        self.assertEqual(rejected_submit["transition_count"], 1)
        assert_single_reservation()


        retry_handoff = VolatileProofHandoff(bytearray(b"retry-lifecycle-proof"))
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=retry_handoff)
        self.assertFalse(retry_handoff.closed)
        queued = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(queued["status_counts"]["QUEUED"], 1)
        self.assertEqual(queued["transition_count"], 2)
        assert_single_reservation()

        with patch.object(
            lifecycle_adapter,
            "run_contained_verifier_stream",
            side_effect=lifecycle_adapter.VerifierProcessError("verifier_timeout"),
        ):
            with self.assertRaisesRegex(
                lifecycle_adapter.LifecycleAdapterError,
                "lifecycle_process:verifier_timeout",
            ):
                self.store._claim_next_batch()
        self.assertFalse(retry_handoff.closed)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(
                connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0],
                "QUEUED",
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT live_lease_count FROM queue_metadata WHERE id=1").fetchone()[0], 0)
        queued_after_failure = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(queued_after_failure["transition_count"], 2)
        assert_single_reservation()

        work = self.store._claim_next_batch()
        self.assertIsNotNone(work)
        self.assertEqual(work.batch.batch_id, batch.batch_id)
        claimed = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(claimed["status_counts"]["LEASED"], 1)
        self.assertEqual(claimed["transition_count"], 3)
        assert_single_reservation()

    def test_no_authoritative_promotion_or_cross_store_process_api_remains(self) -> None:
        from parked.private_zk.app.minimal_clearance_composition import ClearanceCompositionStoreV2

        self.assertFalse(hasattr(ClearanceCompositionStoreV2, "process_verified_jobs"))
        self.assertFalse(hasattr(self.store, "_promote_candidates"))


if __name__ == "__main__":
    unittest.main()
