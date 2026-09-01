import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import fields
from pathlib import Path

import app.minimal_clearance_composition as composition
from app.minimal_clearance_composition import (
    ClearanceCompositionStoreV2,
    CompositionBatchDeliveryResultV2,
    CompositionConfigV2,
    CompositionIntegrityError,
    CompositionOutboxBatchWorkV2,
    StateDispositionControl,
    build_synthetic_acknowledgment,
    resolve_effective_directive,
)
from app.minimal_clearance_verification_queue import (
    BatchVerifierResult,
    OperationTemplate,
    QueueConfig,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)
from app.minimal_clearance_verification_queue_independent import read_verified_batch, verify_database
from app.minimal_clearance_composition_independent import verify_database as verify_composition_database, verify_database_connection


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now
        self.reads = 0
        self.expire_on_read: int | None = None

    def now_ms(self) -> int:
        self.reads += 1
        if self.expire_on_read == self.reads:
            self.now += 300_000
        return self.now

    def advance(self, milliseconds: int) -> None:
        self.now += milliseconds


def _controls(
    operation_refs: tuple[bytes, ...],
    *,
    start: tuple[bytes, bytes, bytes, bytes, bytes, int, int, int] | None = None,
) -> tuple[dict[bytes, StateDispositionControl], tuple[bytes, bytes, bytes, bytes, bytes, int, int, int]]:
    if len(operation_refs) != 100:
        raise AssertionError(len(operation_refs))
    policies = ("PASS", "MISSING", "AMBIGUOUS", "FAIL", "FAIL") * 20
    profile = bytes([9]) * 64
    if start is None:
        state_id = bytes(64)
        state_bytes = bytes(64)
        continuity = bytes(64)
        audit = bytes(64)
        clearance = bytes(64)
        marker = 0
        count = 0
        sequence = 0
    else:
        state_id, state_bytes, continuity, audit, clearance, marker, count, sequence = start
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
            sequence,
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
        sequence += 1
    return result, (state_id, state_bytes, continuity, audit, clearance, marker, count, sequence)


class _Verifier:
    def __init__(self, config: QueueConfig) -> None:
        self.config = config
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, batch):
        self.calls += 1
        while stream.read(17):
            pass
        return BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", ())


class _Port:
    def __init__(self) -> None:
        self.calls = 0
        self._state: tuple[bytes, bytes, bytes, bytes, bytes, int, int, int] | None = None

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome):
        del batch_id, verification_outcome
        self.calls += 1
        controls, self._state = _controls(operation_refs, start=self._state)
        return controls


def _operation_ref(envelope_bytes: bytes) -> bytes:
    return bytes.fromhex(json.loads(envelope_bytes.decode("ascii"))["operation_ref"])


class _Receiver:
    def __init__(
        self,
        config: CompositionConfigV2,
        clock: _Clock,
        *,
        modes: tuple[str, ...] = ("valid",),
        acks: dict[bytes, bytes] | None = None,
        database: Path | None = None,
        stale_target: bytes | None = None,
        advance_after_first: bool = False,
    ) -> None:
        self.config = config
        self.clock = clock
        self.modes = modes
        self.acks = {} if acks is None else acks
        self.database = database
        self.stale_target = stale_target
        self.advance_after_first = advance_after_first
        self.calls: list[tuple[bytes, bytes, int]] = []
        self.side_effects = 0
        self.external_transaction_checks = 0

    def _mode(self, index: int) -> str:
        return self.modes[index % len(self.modes)]

    def _valid_ack(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        acknowledgment = self.acks.get(idempotency_key)
        if acknowledgment is None:
            acknowledgment = build_synthetic_acknowledgment(envelope_bytes, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.clock.now_ms())
            self.acks[idempotency_key] = acknowledgment
            self.side_effects += 1
        return acknowledgment

    def _assert_external_transaction_is_free(self) -> None:
        if self.database is None:
            return
        with closing(sqlite3.connect(str(self.database), timeout=1.0, isolation_level=None)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("ROLLBACK")
        self.external_transaction_checks += 1

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes | None:
        operation_ref = _operation_ref(envelope_bytes)
        self.calls.append((operation_ref, idempotency_key, self.clock.now_ms()))
        self._assert_external_transaction_is_free()
        if self.stale_target == operation_ref and self.database is not None:
            with closing(sqlite3.connect(str(self.database))) as connection:
                connection.execute("UPDATE composition_outbox SET worker_id=? WHERE operation_ref=? AND status='LEASED'", ("stale-worker", operation_ref))
                connection.commit()
            self.stale_target = None
        mode = self._mode(len(self.calls) - 1)
        if mode == "valid":
            acknowledgment = self._valid_ack(envelope_bytes, idempotency_key)
        elif mode == "missing":
            acknowledgment = None
        elif mode == "invalid":
            acknowledgment = b"{}"
        elif mode == "exception":
            raise RuntimeError("synthetic receiver failure")
        elif mode == "crash":
            self._valid_ack(envelope_bytes, idempotency_key)
            raise KeyboardInterrupt
        else:
            raise AssertionError(mode)
        if self.advance_after_first and len(self.calls) == 1:
            self.clock.advance(self.config.lease_seconds * 1000)
        return acknowledgment


class _Lookup:
    def __init__(self, config: CompositionConfigV2, clock: _Clock, directives: dict[bytes, str], *, modes: tuple[str, ...], database: Path | None = None) -> None:
        self.config = config
        self.clock = clock
        self.directives = directives
        self.modes = modes
        self.database = database
        self.calls: list[tuple[bytes, bytes, int]] = []
        self.external_transaction_checks = 0

    def acknowledgment_profile(self):
        return self.config.acknowledgment_profile

    def lookup_acknowledgment(self, **query):
        operation_ref = query["operation_id"]
        idempotency_key = query["idempotency_key"]
        self.calls.append((operation_ref, idempotency_key, self.clock.now_ms()))
        if self.database is not None:
            with closing(sqlite3.connect(str(self.database), timeout=1.0, isolation_level=None)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("ROLLBACK")
            self.external_transaction_checks += 1
        mode = self.modes[(len(self.calls) - 1) % len(self.modes)]
        if mode == "missing":
            return None
        if mode == "invalid":
            return b"{}"
        if mode == "exception":
            raise RuntimeError("synthetic lookup failure")
        if mode != "valid":
            raise AssertionError(mode)
        envelope = composition._envelope(operation_ref, self.directives[operation_ref], self.config)
        return build_synthetic_acknowledgment(envelope, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.clock.now_ms())


class _InstrumentedStore(ClearanceCompositionStoreV2):
    def __init__(self, **kwargs) -> None:
        self.trace: list[str] = []
        super().__init__(**kwargs)

    def _connect(self):
        connection = super()._connect()
        connection.set_trace_callback(self.trace.append)
        return connection


class CompositionV11Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.queue_config = QueueConfig("composition-state-v11", 200)
        self.composition_config = CompositionConfigV2(self.queue_config.queue_id, self.queue_config.digest, capacity=200)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root)
        self.queue = _VerificationQueueStore(path=self.root / "state.sqlite", config=self.queue_config, owner=self.owner, clock=self.clock, composition_config=self.composition_config)
        self.port = _Port()
        self.composition_stores: list[ClearanceCompositionStoreV2] = []

    def tearDown(self) -> None:
        for store in self.composition_stores:
            store.close()
        self.queue._close()
        self.owner.close()
        self.temp.cleanup()

    def _accepted(self):
        template = OperationTemplate("composition-assertion", 1, self.queue_config.profile_version, self.clock.now - 100, self.clock.now + 60_000)
        batch = self.queue.issue_batch(template=template)
        self.queue.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"volatile-proof")))
        result = self.queue._process_one_batch(verifier=_Verifier(self.queue_config), state_disposition_port=self.port)
        self.assertEqual((result.status, result.accepted_count), ("VERIFIED", 100))
        return batch

    def _accepted_two(self):
        return self._accepted(), self._accepted()

    def _store(self) -> ClearanceCompositionStoreV2:
        store = ClearanceCompositionStoreV2(path=self.root / "state.sqlite", config=self.composition_config, clock=self.clock)
        self.composition_stores.append(store)
        return store

    def _directives(self) -> dict[bytes, str]:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            return {bytes(row[0]): str(row[1]) for row in connection.execute("SELECT operation_ref,effective_directive FROM composition_outbox")}

    def test_composition_store_accepts_unified_database_and_removes_single_row_surface(self) -> None:
        old = self.root / "composition.sqlite"
        old.write_bytes(b"old composition bytes")
        with self.assertRaises(CompositionIntegrityError):
            ClearanceCompositionStoreV2(path=old, config=self.composition_config, clock=self.clock)
        store = self._store()
        for name in ("claim_next_outbox", "dispatch", "claim_reconciliation_next", "reconcile_next", "process_verified_jobs"):
            self.assertFalse(hasattr(store, name), name)
        self.assertTrue(hasattr(store, "dispatch_outbox_batch"))
        self.assertTrue(hasattr(store, "reconcile_outbox_batch"))
        self.assertEqual(old.read_bytes(), b"old composition bytes")

    def test_queue_terminal_transaction_and_reconstruction_remain_100_rows(self) -> None:
        batch = self._accepted()
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "VERIFIED")
            self.assertEqual(connection.execute("SELECT terminal_status,proof_accepted,source_authenticated FROM queue_results WHERE batch_id=?", (batch.batch_id,)).fetchone(), ("VERIFIED", 1, 1))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 100)
        reconstructed = read_verified_batch(self.root / "state.sqlite", batch.batch_id)
        self.assertEqual(len(reconstructed.jobs), 100)
        self.assertEqual(verify_database(self.root / "state.sqlite")["accepted_operation_count"], 100)

    def test_independent_queue_and_composition_verifiers_accept_one_state_file(self) -> None:
        self._accepted()
        queue_summary = verify_database(self.root / "state.sqlite")
        composition_summary = verify_composition_database(self.root / "state.sqlite", expected_config=self.composition_config.as_json)
        self.assertEqual((queue_summary["accepted_operation_count"], composition_summary["outbox_count"], composition_summary["state_sequence"]), (100, 100, 100))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(verify_database_connection(connection, expected_config=self.composition_config.as_json)["outbox_count"], 100)

    def test_policy_results_and_effective_directives_are_separate_and_exhaustive(self) -> None:
        self._accepted()
        store = self._store()
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            policies = {row[0] for row in connection.execute("SELECT DISTINCT policy_result FROM composition_transactions")}
            directives = {row[0] for row in connection.execute("SELECT DISTINCT effective_directive FROM composition_transactions")}
            proofs = {row[0] for row in connection.execute("SELECT DISTINCT proof_accepted FROM composition_transactions")}
        self.assertEqual(policies, {"PASS", "MISSING", "AMBIGUOUS", "FAIL"})
        self.assertEqual(directives, {"CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"})
        self.assertEqual(proofs, {1})
        self.assertEqual(tuple(resolve_effective_directive(policy, exception) for policy, exception in (("PASS", False), ("MISSING", False), ("AMBIGUOUS", False), ("FAIL", False), ("FAIL", True))), ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"))
        self.assertEqual(store.snapshot()["state_sequence"], 100)

    def test_claim_returns_two_exact_100_row_batches_with_independent_material_and_has_more(self) -> None:
        self._accepted_two()
        store = self._store()
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            expected_first = tuple(bytes(row[0]) for row in connection.execute("SELECT operation_ref FROM composition_outbox WHERE status='READY' ORDER BY updated_ms,operation_ref LIMIT 100"))
        first = store._claim_outbox_batch("worker-a")
        self.assertIsInstance(first, CompositionOutboxBatchWorkV2)
        assert first is not None
        second = store._claim_outbox_batch("worker-b")
        self.assertIsInstance(second, CompositionOutboxBatchWorkV2)
        assert second is not None
        self.assertEqual((len(first.works), len(second.works), first.has_more, second.has_more), (100, 100, True, False))
        self.assertEqual(tuple(work.operation_id for work in first.works), expected_first)
        all_works = first.works + second.works
        self.assertEqual(len({work.operation_id for work in all_works}), 200)
        self.assertEqual(len({work.lease_token for work in all_works}), 200)
        self.assertEqual(len({work.idempotency_key for work in all_works}), 200)
        self.assertEqual(len({work.envelope_bytes for work in all_works}), 200)
        self.assertTrue(all(work.attempt == 1 and work.lease_expires_ms == self.clock.now + 300_000 for work in all_works))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            rows = connection.execute("SELECT operation_ref,lease_token,updated_ms FROM composition_outbox WHERE status='LEASED' ORDER BY updated_ms,operation_ref").fetchall()
            self.assertEqual(len(rows), 200)
            for work in all_works:
                row = next(row for row in rows if bytes(row[0]) == work.operation_id)
                self.assertEqual(bytes(row[1]), composition._sha(composition._LEASE, work.lease_token))
                self.assertEqual(int(row[2]), self.clock.now)
            self.assertEqual(tuple(row[1] for row in connection.execute("PRAGMA table_info(composition_outbox)")), composition._OUTBOX_COLUMNS)
            self.assertNotIn("batch_id", {str(row[1]) for row in connection.execute("PRAGMA table_info(composition_outbox)")})
        self.assertNotIn("batch_id", {field.name for field in fields(first)})

    def test_claim_rolls_back_after_every_nth_row_update(self) -> None:
        self._accepted()
        store = self._store()
        for failure_at in range(1, 101):
            updates = [0]

            def fault(label: str, *, failure_at: int = failure_at) -> None:
                if label == "after_outbox_claim_update":
                    updates[0] += 1
                    if updates[0] == failure_at:
                        raise RuntimeError("claim fault")

            store._before_fault = fault
            with self.assertRaisesRegex(RuntimeError, "claim fault"):
                store._claim_outbox_batch("worker")
            self.assertEqual(updates[0], failure_at)
            with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE status='READY'").fetchone()[0], 100)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE status='LEASED'").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT MIN(attempt),MAX(attempt),COUNT(*) FROM composition_outbox WHERE status='READY'").fetchone(), (0, 0, 100))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE worker_id IS NOT NULL OR lease_token IS NOT NULL OR lease_expires_ms IS NOT NULL").fetchone()[0], 0)
        store._before_fault = None

    def test_direct_batch_calls_sequentially_outside_sqlite_and_settles_mixed_outcomes(self) -> None:
        batch = self._accepted()
        store = self._store()
        receiver = _Receiver(self.composition_config, self.clock, modes=("valid", "missing", "invalid", "exception"), database=self.root / "state.sqlite")
        result = store.dispatch_outbox_batch("receiver", receiver=receiver)
        self.assertIsInstance(result, CompositionBatchDeliveryResultV2)
        assert result is not None
        self.assertEqual((result.operation, len(result.results), result.has_more, len(receiver.calls), receiver.external_transaction_checks), ("DIRECT_DELIVERY", 100, False, 100, 100))
        self.assertEqual(sum(item.status == "ACKNOWLEDGED" for item in result.results), 25)
        self.assertEqual(sum(item.status == "DELIVERY_UNCONFIRMED" for item in result.results), 75)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            counts = {str(status): int(count) for status, count in connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status")}
            self.assertEqual(counts, {"ACKNOWLEDGED": 25, "DELIVERY_UNCONFIRMED": 75})
            active = int(connection.execute("SELECT active_dispatch_count FROM composition_meta WHERE id=1").fetchone()[0])
            self.assertEqual(active, counts["DELIVERY_UNCONFIRMED"])
            self.assertEqual(active, sum(counts.get(status, 0) for status in ("READY", "LEASED", "DELIVERY_UNCONFIRMED")))
        reconstructed = read_verified_batch(self.root / "state.sqlite", batch.batch_id)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            composition_refs = tuple(bytes(row[0]) for row in connection.execute("SELECT operation_ref FROM composition_events WHERE event_kind='APPLIED' ORDER BY sequence"))
        self.assertEqual(tuple(job.operation_ref for job in reconstructed.jobs), composition_refs)
        store.verify_integrity()

    def test_reconciliation_claim_rolls_back_after_every_nth_row_update(self) -> None:
        self._accepted()
        store = self._store()
        lost = _Receiver(self.composition_config, self.clock, modes=("missing",))
        self.assertIsNotNone(store.dispatch_outbox_batch("receiver", receiver=lost))
        for failure_at in range(1, 101):
            updates = [0]

            def fault(label: str, *, failure_at: int = failure_at) -> None:
                if label == "after_reconciliation_claim_update":
                    updates[0] += 1
                    if updates[0] == failure_at:
                        raise RuntimeError("reconciliation claim fault")

            store._before_fault = fault
            with self.assertRaisesRegex(RuntimeError, "reconciliation claim fault"):
                store._claim_reconciliation_batch("reconciler")
            self.assertEqual(updates[0], failure_at)
            with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT status,MIN(attempt),MAX(attempt),COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("DELIVERY_UNCONFIRMED", 1, 1, 100)])
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE worker_id IS NOT NULL OR lease_token IS NOT NULL OR lease_expires_ms IS NOT NULL").fetchone()[0], 0)
        store._before_fault = None

    def test_100_row_lost_ack_batch_has_two_explicit_immediate_transactions(self) -> None:
        self._accepted()
        store = _InstrumentedStore(path=self.root / "state.sqlite", config=self.composition_config, clock=self.clock)
        self.composition_stores.append(store)
        receiver = _Receiver(self.composition_config, self.clock, modes=("missing",))
        result = store.dispatch_outbox_batch("receiver", receiver=receiver)
        self.assertIsNotNone(result)
        assert result is not None
        begin_count = sum(statement.strip().upper() == "BEGIN IMMEDIATE" for statement in store.trace)
        commit_count = sum(statement.strip().upper() == "COMMIT" for statement in store.trace)
        rollback_count = sum(statement.strip().upper() == "ROLLBACK" for statement in store.trace)
        outbox_update_count = sum(statement.lstrip().upper().startswith("UPDATE COMPOSITION_OUTBOX SET") for statement in store.trace)
        self.assertEqual((len(result.results), len(receiver.calls), begin_count, commit_count, rollback_count, outbox_update_count), (100, 100, 2, 2, 0, 200))
        self.assertTrue(all(item.status == "DELIVERY_UNCONFIRMED" for item in result.results))

    def test_crash_after_claim_commit_leaves_a_recoverable_batch(self) -> None:
        self._accepted()

        def crash_after_claim_commit(label: str) -> None:
            if label == "after_outbox_claim_commit":
                raise KeyboardInterrupt

        store = ClearanceCompositionStoreV2(
            path=self.root / "state.sqlite",
            config=self.composition_config,
            clock=self.clock,
            after_commit_fault=crash_after_claim_commit,
        )
        self.composition_stores.append(store)
        receiver = _Receiver(self.composition_config, self.clock)
        with self.assertRaises(KeyboardInterrupt):
            store.dispatch_outbox_batch("crashed-worker", receiver=receiver)
        self.assertEqual(len(receiver.calls), 0)
        store._after_commit_fault = None
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("LEASED", 100)])
            self.assertEqual(connection.execute("SELECT MIN(attempt),MAX(attempt),active_dispatch_count FROM composition_outbox,composition_meta").fetchone(), (1, 1, 100))
        self.clock.advance(self.composition_config.lease_seconds * 1000)
        recovered = store.dispatch_outbox_batch("recovery-worker", receiver=receiver)
        self.assertIsNotNone(recovered)
        assert recovered is not None
        self.assertEqual((len(receiver.calls), sum(item.status == "ACKNOWLEDGED" for item in recovered.results)), (100, 100))
        store.verify_integrity()

    def test_expiry_before_and_during_loop_prevents_known_expired_external_calls(self) -> None:
        self._accepted()
        store = self._store()
        self.clock.expire_on_read = self.clock.reads + 3
        before_receiver = _Receiver(self.composition_config, self.clock)
        before = store.dispatch_outbox_batch("before-worker", receiver=before_receiver)
        self.assertIsNotNone(before)
        assert before is not None
        self.assertEqual((before.has_more, len(before_receiver.calls)), (True, 0))
        self.assertTrue(all(item.status == "DELIVERY_UNCONFIRMED" for item in before.results))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE status='READY'").fetchone()[0], 100)
        self.clock.expire_on_read = None
        mid_receiver = _Receiver(self.composition_config, self.clock, advance_after_first=True)
        mid = store.dispatch_outbox_batch("mid-worker", receiver=mid_receiver)
        self.assertIsNotNone(mid)
        assert mid is not None
        self.assertEqual(len(mid_receiver.calls), 1)
        self.assertEqual(mid_receiver.calls[0][2], self.clock.now - self.composition_config.lease_seconds * 1000)
        self.assertTrue(all(call[2] < self.clock.now for call in mid_receiver.calls))
        self.assertTrue(all(item.status == "DELIVERY_UNCONFIRMED" for item in mid.results))

    def test_one_stale_fence_does_not_block_other_live_ack_settlements(self) -> None:
        self._accepted()
        store = self._store()
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            target = bytes(connection.execute("SELECT operation_ref FROM composition_outbox WHERE status='READY' ORDER BY updated_ms,operation_ref LIMIT 1").fetchone()[0])
        receiver = _Receiver(self.composition_config, self.clock, database=self.root / "state.sqlite", stale_target=target)
        result = store.dispatch_outbox_batch("receiver", receiver=receiver)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual((len(receiver.calls), sum(item.status == "ACKNOWLEDGED" for item in result.results), sum(item.status == "DELIVERY_UNCONFIRMED" for item in result.results)), (100, 99, 1))
        self.assertEqual(next(item for item in result.results if item.operation_id == target).status, "DELIVERY_UNCONFIRMED")
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status,worker_id FROM composition_outbox WHERE operation_ref=?", (target,)).fetchone(), ("LEASED", "stale-worker"))
            self.assertEqual(connection.execute("SELECT active_dispatch_count FROM composition_meta WHERE id=1").fetchone()[0], 1)
        store.verify_integrity()

    def test_settlement_fault_rolls_back_all_mixed_state_changes(self) -> None:
        self._accepted()
        store = self._store()
        receiver = _Receiver(self.composition_config, self.clock, modes=("valid", "missing", "invalid", "exception"), database=self.root / "state.sqlite")
        updates = [0]

        def fault(label: str) -> None:
            if label == "after_outbox_settlement_update":
                updates[0] += 1
                if updates[0] == 50:
                    raise RuntimeError("settlement fault")

        store._before_fault = fault
        with self.assertRaisesRegex(RuntimeError, "settlement fault"):
            store.dispatch_outbox_batch("receiver", receiver=receiver)
        store._before_fault = None
        self.assertEqual((len(receiver.calls), updates[0]), (100, 50))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("LEASED", 100)])
            self.assertEqual(connection.execute("SELECT active_dispatch_count FROM composition_meta WHERE id=1").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT MIN(attempt),MAX(attempt) FROM composition_outbox").fetchone(), (1, 1))
        store.verify_integrity()

    def test_crash_after_external_effect_before_settlement_retries_with_unchanged_keys(self) -> None:
        self._accepted()
        store = self._store()
        crashing = _Receiver(self.composition_config, self.clock, modes=("valid",) * 99 + ("crash",))
        with self.assertRaises(KeyboardInterrupt):
            store.dispatch_outbox_batch("crashing-worker", receiver=crashing)
        self.assertEqual((len(crashing.calls), crashing.side_effects), (100, 100))
        original_keys = tuple(call[1] for call in crashing.calls)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("LEASED", 100)])
            self.assertEqual(connection.execute("SELECT active_dispatch_count FROM composition_meta WHERE id=1").fetchone()[0], 100)
        self.clock.advance(self.composition_config.lease_seconds * 1000)
        retry = _Receiver(self.composition_config, self.clock, acks=crashing.acks)
        result = store.dispatch_outbox_batch("retry-worker", receiver=retry)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual((len(retry.calls), tuple(call[1] for call in retry.calls), sum(item.status == "ACKNOWLEDGED" for item in result.results)), (100, original_keys, 100))
        self.assertEqual(crashing.side_effects + retry.side_effects, 100)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("ACKNOWLEDGED", 100)])
            self.assertEqual(connection.execute("SELECT MIN(attempt),MAX(attempt),active_dispatch_count FROM composition_outbox,composition_meta").fetchone(), (2, 2, 0))
        store.verify_integrity()

    def test_reconciliation_batch_settles_mixed_lookup_outcomes(self) -> None:
        self._accepted()
        store = self._store()
        lost = _Receiver(self.composition_config, self.clock, modes=("missing",))
        first = store.dispatch_outbox_batch("receiver", receiver=lost)
        self.assertIsNotNone(first)
        directives = self._directives()
        lookup = _Lookup(self.composition_config, self.clock, directives, modes=("valid", "missing", "invalid", "exception"), database=self.root / "state.sqlite")
        result = store.reconcile_outbox_batch("reconciler", lookup=lookup)
        self.assertIsInstance(result, CompositionBatchDeliveryResultV2)
        assert result is not None
        self.assertEqual((result.operation, len(result.results), result.has_more, len(lookup.calls), lookup.external_transaction_checks), ("RECONCILIATION", 100, True, 100, 100))
        self.assertEqual(tuple(call[1] for call in lost.calls), tuple(call[1] for call in lookup.calls))
        self.assertEqual(sum(item.status == "ACKNOWLEDGED" for item in result.results), 25)
        self.assertEqual(sum(item.status == "DELIVERY_UNCONFIRMED" for item in result.results), 75)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("ACKNOWLEDGED", 25), ("DELIVERY_UNCONFIRMED", 75)])
            self.assertEqual(connection.execute("SELECT MIN(attempt),MAX(attempt),active_dispatch_count FROM composition_outbox,composition_meta").fetchone(), (2, 2, 75))
        store.verify_integrity()

    def test_reconciliation_claim_returns_two_exact_100_row_batches(self) -> None:
        self._accepted_two()
        store = self._store()
        lost = _Receiver(self.composition_config, self.clock, modes=("missing",))
        first_direct = store.dispatch_outbox_batch("receiver", receiver=lost)
        second_direct = store.dispatch_outbox_batch("receiver", receiver=lost)
        self.assertIsNotNone(first_direct)
        self.assertIsNotNone(second_direct)
        assert first_direct is not None and second_direct is not None
        self.assertEqual((len(first_direct.results), first_direct.has_more, len(second_direct.results), second_direct.has_more), (100, True, 100, False))
        lookup = _Lookup(self.composition_config, self.clock, self._directives(), modes=("valid",))
        first = store.reconcile_outbox_batch("reconciler-a", lookup=lookup)
        second = store.reconcile_outbox_batch("reconciler-b", lookup=lookup)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        assert first is not None and second is not None
        self.assertEqual((len(first.results), first.has_more, len(second.results), second.has_more, len(lookup.calls)), (100, True, 100, False, 200))
        self.assertTrue(all(item.status == "ACKNOWLEDGED" for item in first.results + second.results))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("ACKNOWLEDGED", 200)])
            self.assertEqual(connection.execute("SELECT active_dispatch_count FROM composition_meta WHERE id=1").fetchone()[0], 0)
        store.verify_integrity()

    def test_max_attempts_are_three_and_no_fourth_reconciliation_is_claimable(self) -> None:
        self._accepted()
        store = self._store()
        lost = _Receiver(self.composition_config, self.clock, modes=("missing",))
        self.assertIsNotNone(store.dispatch_outbox_batch("receiver", receiver=lost))
        directives = self._directives()
        lookup = _Lookup(self.composition_config, self.clock, directives, modes=("missing",))
        second = store.reconcile_outbox_batch("reconciler", lookup=lookup)
        third = store.reconcile_outbox_batch("reconciler", lookup=lookup)
        self.assertIsNotNone(second)
        self.assertIsNotNone(third)
        assert second is not None and third is not None
        self.assertTrue(second.has_more)
        self.assertFalse(third.has_more)
        self.assertIsNone(store.reconcile_outbox_batch("reconciler", lookup=lookup))
        self.assertIsNone(store.dispatch_outbox_batch("receiver", receiver=lost))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT MIN(attempt),MAX(attempt),status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [(3, 3, "DELIVERY_UNCONFIRMED", 100)])
        store.verify_integrity()

    def test_two_concurrent_batch_workers_claim_disjoint_rows(self) -> None:
        self._accepted_two()
        store_a = self._store()
        store_b = self._store()
        receiver_a = _Receiver(self.composition_config, self.clock)
        receiver_b = _Receiver(self.composition_config, self.clock)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = (
                executor.submit(store_a.dispatch_outbox_batch, "worker-a", receiver=receiver_a),
                executor.submit(store_b.dispatch_outbox_batch, "worker-b", receiver=receiver_b),
            )
            results = tuple(future.result() for future in futures)
        self.assertTrue(all(result is not None for result in results))
        assert results[0] is not None and results[1] is not None
        self.assertEqual((len(results[0].results), len(results[1].results), len(receiver_a.calls), len(receiver_b.calls)), (100, 100, 100, 100))
        self.assertEqual({results[0].has_more, results[1].has_more}, {False, True})
        self.assertEqual(set(operation for operation, _key, _at in receiver_a.calls).intersection(operation for operation, _key, _at in receiver_b.calls), set())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status,COUNT(*) FROM composition_outbox GROUP BY status").fetchall(), [("ACKNOWLEDGED", 200)])
            self.assertEqual(connection.execute("SELECT active_dispatch_count FROM composition_meta WHERE id=1").fetchone()[0], 0)
        store_a.verify_integrity()

    def test_batch_objects_and_durable_rows_contain_no_phi_or_batch_identity(self) -> None:
        self._accepted()
        store = self._store()
        direct = store._claim_outbox_batch("worker")
        self.assertIsNotNone(direct)
        assert direct is not None
        self.assertEqual(len(direct.works), 100)
        self.assertNotIn("batch_id", {field.name for field in fields(direct)})
        forbidden = (b"volatile-proof", b"raw_proof", b"raw_signature", b"patient", b"provider", b"case")
        for work in direct.works:
            self.assertEqual(work.job_id, work.operation_id.hex().upper())
            self.assertTrue(all(marker not in work.envelope_bytes for marker in forbidden))
            self.assertEqual(work.idempotency_key, composition._sha(composition._MATERIAL, work.operation_id, work.effective_directive.encode("ascii")))
        settled = store._settle_delivery_batch(worker_id="worker", operation="DIRECT_DELIVERY", works=direct.works, acknowledgments=(None,) * 100, has_more=direct.has_more)
        self.assertTrue(all(item.status == "DELIVERY_UNCONFIRMED" for item in settled.results))
        reconciliation = store._claim_reconciliation_batch("reconciler")
        self.assertIsNotNone(reconciliation)
        assert reconciliation is not None
        self.assertEqual(len(reconciliation.works), 100)
        self.assertNotIn("batch_id", {field.name for field in fields(reconciliation)})
        for work in reconciliation.works:
            self.assertTrue(all(marker not in repr(work).encode("ascii") for marker in forbidden))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            self.assertEqual(tables, composition._QUEUE_TABLES | composition._COMPOSITION_TABLES)
            self.assertEqual(tuple(row[1] for row in connection.execute("PRAGMA table_info(composition_outbox)")), composition._OUTBOX_COLUMNS)
        raw = (self.root / "state.sqlite").read_bytes()
        wal = self.root / "state.sqlite-wal"
        if wal.exists():
            raw += wal.read_bytes()
        for marker in forbidden:
            self.assertNotIn(marker, raw)


if __name__ == "__main__":
    unittest.main()
