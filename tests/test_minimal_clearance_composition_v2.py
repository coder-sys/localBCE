from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path
import shutil
import sqlite3
import tempfile
import traceback
import unittest
from concurrent.futures import ThreadPoolExecutor

import tests.test_minimal_clearance_verification_queue as queue_fixtures
from experiments.longfellow_v09_native_v3.evidence.measure_minimal_clearance_software_pipeline import (
    _digest as _synthetic_digest,
    _synthetic_acceptances,
    _u32 as _synthetic_u32,
)
from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes
from app.minimal_clearance_composition import (
    CompositionConfigV2,
    CompositionConflictError,
    CompositionIntegrityError,
    CompositionLeaseError,
    CompositionOutboxWorkV2,
    ClearanceCompositionStoreV2,
    build_synthetic_acknowledgment,
)
from app.minimal_clearance_composition_independent import IndependentCompositionError, verify_database
import app.minimal_clearance_composition as composition_module
import app.minimal_clearance_composition_independent as composition_independent_module


class _Receiver:
    def __init__(self, config: CompositionConfigV2, *, identity: bytes | None = None) -> None:
        self.config, self.identity = config, identity or config.receiver_identity
        self.calls = 0
        self.ack: bytes | None = None

    def identity_sha256(self) -> bytes: return self.identity
    def epoch(self) -> int: return self.config.receiver_epoch
    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.calls += 1
        self.ack = build_synthetic_acknowledgment(envelope_bytes, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.calls)
        return self.ack


class _Lookup:
    def __init__(self, receiver: _Receiver, config: CompositionConfigV2) -> None:
        self.receiver, self.config, self.calls = receiver, config, 0
    def acknowledgment_profile(self): return self.config.acknowledgment_profile
    def lookup_acknowledgment(self, **_query):
        self.calls += 1
        return self.receiver.ack


class _NoneLookup:
    def acknowledgment_profile(self): return self.config.acknowledgment_profile  # type: ignore[attr-defined]
    def __init__(self, config: CompositionConfigV2) -> None: self.config = config
    def lookup_acknowledgment(self, **_query): return None


class _AcceptanceFactory:
    def __init__(self, acceptances) -> None:
        self.acceptances = tuple(acceptances)
        self.index = 0

    def __call__(self):
        acceptance = self.acceptances[self.index]
        self.index += 1
        verifier = object.__new__(queue_fixtures.NativeMinimalClearanceVerifier)
        verifier._test_acceptance = acceptance  # type: ignore[attr-defined]
        return verifier


class CompositionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.queue_tests = queue_fixtures.VerificationQueueTests(methodName="runTest")
        self.queue_tests.setUp()
        self.temp = tempfile.TemporaryDirectory(prefix="bl-composition-v2-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.queue_tests.tearDown()

    def _config(self, *, capacity: int = 16, lease_seconds: int = 300) -> CompositionConfigV2:
        queue_config = self.queue_tests._config()
        return CompositionConfigV2(queue_id=queue_config.queue_id, queue_config_digest=queue_config.digest, verifier_sha256=queue_fixtures._VERIFIER, receiver_identity=bytes(range(32)), capacity=capacity, lease_seconds=lease_seconds)

    def _verified(self, job_id: str = "job-1", *, factory=None):
        queue = self.queue_tests._store()
        self.queue_tests._verify_one(queue, job_id, factory=factory or queue_fixtures._Factory())
        queue._promote_candidates()
        return queue

    def _store(self, config: CompositionConfigV2 | None = None, **kwargs):
        return ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config or self._config(), **kwargs)

    def _synthetic_chain(self, ordinals: tuple[int, ...]):
        template = self._verified("chain-template")
        acceptances = _synthetic_acceptances(template.path, count=max(ordinals))
        queue = self.queue_tests._store(capacity=4, name="chain.sqlite")
        factory = _AcceptanceFactory(tuple(acceptances[ordinal - 1] for ordinal in ordinals))
        for ordinal, acceptance in zip(ordinals, factory.acceptances):
            artifact = b"BL-SYNTHETIC-QUEUE-V6-" + _synthetic_u32(ordinal) + _synthetic_digest("artifact", ordinal)
            ref = f"composition-chain-{ordinal:03d}"
            source = self.queue_tests.source_root / ref
            source.write_bytes(artifact)
            source.chmod(0o400)
            metadata = queue_fixtures.ArtifactMetadata(
                ref,
                len(artifact),
                acceptance.artifact_sha256,
                acceptance.artifact_digest,
                bytes(acceptance.statement.state("proposed_payment_commitment")),
                acceptance.statement.state_before_id,
                bytes(acceptance.statement.get("private_batch_commitment")),
            )
            queue._admit(job_id=f"chain-{ordinal:03d}", metadata=metadata)
            result = queue._process_one(verifier=factory(), custody=self.queue_tests._custody())
            self.assertIsNotNone(result)
            self.assertEqual(result.status, "CANDIDATE")
        self.assertEqual(len(queue._promote_candidates()), 1)
        return queue

    def _prepared_batch(self, store: ClearanceCompositionStoreV2, queue):
        batch = composition_module.read_verified_batch(queue.path)
        composition_batch_id = composition_module._composition_batch_id(store.config, batch)
        prepared = []
        for member_index, verified in enumerate(batch.jobs):
            acceptance = store._validate_queue_result(verified)
            encoded = bytes(verified.acceptance_bytes)
            queue_view = store._queue_view_bytes(verified, batch, member_index, composition_batch_id)
            queue_view_digest = composition_module._sha(composition_module._MATERIAL, b"queue-view", queue_view)
            acceptance_digest = composition_module._sha(composition_module._MATERIAL, b"acceptance", encoded)
            prepared.append((verified, acceptance, encoded, queue_view, queue_view_digest, acceptance_digest, batch, composition_batch_id, member_index))
        return batch, prepared

    def test_three_table_schema_inventory_and_old_schema_rejection(self) -> None:
        store = self._store()
        with closing(sqlite3.connect(store.path)) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")}
            triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        self.assertEqual(tables, {"composition_meta", "composition_transactions", "composition_events"})
        self.assertEqual(indexes, {"composition_ready_idx", "composition_reconcile_idx", "composition_lease_expiry_idx"})
        self.assertEqual(triggers, {"composition_meta_no_delete", "composition_meta_guard", "composition_transactions_no_delete", "composition_transactions_guard", "composition_events_no_update", "composition_events_no_delete"})
        legacy = self.root / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy)) as connection:
            connection.execute("CREATE TABLE composition_metadata (id INTEGER)")
            connection.commit()
        with self.assertRaises(CompositionIntegrityError):
            ClearanceCompositionStoreV2(path=legacy, config=self._config())
        tampered = self.root / "unknown-config.sqlite3"
        shutil.copy2(store.path, tampered)
        with closing(sqlite3.connect(tampered)) as connection:
            connection.execute("DROP TRIGGER composition_meta_guard")
            raw = json.loads(bytes(connection.execute("SELECT config_json FROM composition_meta WHERE id=1").fetchone()[0]).decode("ascii"))
            raw["unexpected_config_field"] = True
            config_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("ascii")
            config_digest = composition_module._sha(composition_module._MATERIAL, config_bytes)
            head = composition_module._sha(composition_module._GENESIS, raw["composition_id"].encode("ascii"), config_digest)
            connection.execute("UPDATE composition_meta SET config_json=?,config_digest=?,event_head=? WHERE id=1", (config_bytes, config_digest, head))
            connection.commit()
        with self.assertRaises(IndependentCompositionError):
            verify_database(tampered, expected_config=store.config.as_json)

    def test_one_queue_verification_and_exact_retry_no_native_second_call(self) -> None:
        factory = queue_fixtures._Factory()
        queue = self._verified("job-1", factory=factory)
        store = self._store()
        first = store.process_verified_job(queue.path, "job-1")
        retry = store.process_verified_job(queue.path, "job-1")
        self.assertEqual(first.status, "APPLIED")
        self.assertTrue(retry.duplicate_convergence)
        self.assertEqual(len(factory.instances), 1)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0], 1)
        verify_database(store.path, expected_config=store.config.as_json)

    def test_process_verified_jobs_reads_once_and_returns_ordered_tuple(self) -> None:
        queue = self._verified("batch-one")
        store = self._store()
        original_reader = composition_module.read_verified_batch
        observed: list[object] = []

        def reader(path, selector=None):
            observed.append(selector)
            return original_reader(path, selector)

        composition_module.read_verified_batch = reader  # type: ignore[assignment]
        try:
            results = store.process_verified_jobs(queue.path, ("batch-one",))
        finally:
            composition_module.read_verified_batch = original_reader  # type: ignore[assignment]
        self.assertEqual(observed, [None])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "APPLIED")
        self.assertFalse(results[0].duplicate_convergence)
        retry = store.process_verified_jobs(queue.path, ["batch-one"])
        self.assertEqual(len(retry), 1)
        self.assertTrue(retry[0].duplicate_convergence)
        self.assertEqual(retry[0].state_receipt_digest, results[0].state_receipt_digest)

    def test_process_verified_jobs_applies_ordered_sequential_chain(self) -> None:
        queue = self._synthetic_chain((1, 2))
        store = self._store()
        results = store.process_verified_jobs(queue.path, ("chain-001", "chain-002"))
        self.assertEqual([result.status for result in results], ["APPLIED", "APPLIED"])
        with closing(sqlite3.connect(store.path)) as connection:
            rows = connection.execute("SELECT queue_job_id,status,applied_sequence FROM composition_transactions ORDER BY applied_sequence").fetchall()
        self.assertEqual(rows, [("chain-001", "APPLIED", 1), ("chain-002", "APPLIED", 2)])
        retry = store.process_verified_jobs(queue.path, ("chain-001", "chain-002"))
        self.assertTrue(all(result.duplicate_convergence for result in retry))
        summary = verify_database(store.path, expected_config=store.config.as_json)
        self.assertEqual(summary["table_counts"]["composition_transactions"], 2)
        self.assertEqual(summary["table_counts"]["composition_events"], 2)

    def test_process_verified_jobs_rejects_invalid_state_chain_without_mutation(self) -> None:
        queue = self._synthetic_chain((1, 3))
        store = self._store()
        before = store.snapshot()
        with self.assertRaises(CompositionIntegrityError) as caught:
            store.process_verified_jobs(queue.path, ("chain-001", "chain-003"))
        self.assertEqual(str(caught.exception), "composition_batch_state_chain")
        self.assertEqual(store.snapshot(), before)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0], 0)
            meta = connection.execute("SELECT state_id,state_profile_identity,state_bytes,state_sequence,active_dispatch_count FROM composition_meta WHERE id=1").fetchone()
        self.assertEqual(meta, (None, None, None, None, 0))
        summary = verify_database(store.path, expected_config=store.config.as_json)
        self.assertEqual(summary["table_counts"], {"composition_meta": 1, "composition_transactions": 0, "composition_events": 0})
        self.assertEqual(summary["delivery_counts"], {status: 0 for status in sorted(composition_module._DELIVERY_STATES)})

    def test_independent_reconstruction_rejects_persisted_mixed_batch(self) -> None:
        queue = self._synthetic_chain((1, 3))
        store = self._store()
        _batch, prepared = self._prepared_batch(store, queue)
        with closing(store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            results = [store._apply_verified_job_in_transaction(connection, item, int(store.clock.now_ms())) for item in prepared]
            connection.execute("COMMIT")
        self.assertEqual([result.status for result, _applied in results], ["APPLIED", "HELD"])
        with self.assertRaises(IndependentCompositionError) as caught:
            verify_database(store.path, expected_config=store.config.as_json)
        self.assertEqual(str(caught.exception), "composition_batch_partial")

    def test_process_verified_jobs_rejects_partially_persisted_batch_without_mutation(self) -> None:
        queue = self._synthetic_chain((1, 2))
        store = self._store()
        _batch, prepared = self._prepared_batch(store, queue)
        with closing(store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            result, applied = store._apply_verified_job_in_transaction(connection, prepared[0], int(store.clock.now_ms()))
            self.assertEqual((result.status, applied), ("APPLIED", True))
            connection.execute("COMMIT")
        before = store.snapshot()
        with self.assertRaises(CompositionConflictError) as caught:
            store.process_verified_jobs(queue.path, ("chain-001", "chain-002"))
        self.assertEqual(str(caught.exception), "composition_conflicting_retry")
        self.assertEqual(store.snapshot(), before)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0], 1)
        with self.assertRaises(IndependentCompositionError) as independent:
            verify_database(store.path, expected_config=store.config.as_json)
        self.assertEqual(str(independent.exception), "composition_batch_completeness")

    def test_process_verified_jobs_preflights_conflict_before_any_new_mutation(self) -> None:
        queue = self.queue_tests._store(capacity=4)
        self.queue_tests._verify_one(queue, "batch-a")
        self.queue_tests._verify_one(queue, "batch-b")
        queue._promote_candidates()
        store = self._store()
        with self.assertRaises(CompositionConflictError):
            store.process_verified_jobs(queue.path, ("batch-a", "batch-b"))
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0], 0)
        verify_database(store.path, expected_config=store.config.as_json)

    def test_process_verified_jobs_fault_rolls_back_the_batch(self) -> None:
        queue = self._verified("batch-fault")

        def fail(_label: str) -> None:
            raise RuntimeError("test fault")

        store = self._store(before_fault=fail)
        with self.assertRaises(CompositionIntegrityError):
            store.process_verified_jobs(queue.path, ("batch-fault",))
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0], 0)
        verify_database(store.path, expected_config=store.config.as_json)

    def test_one_lease_and_positive_only_reconciliation(self) -> None:
        queue = self._verified()
        config = self._config()
        store = self._store(config)
        store.process_verified_job(queue.path, "job-1")
        receiver = _Receiver(config)
        work = store.claim_next_outbox("dispatch-worker")
        self.assertIsNotNone(work)
        assert work is not None
        uncertain = store._mark_delivery_unconfirmed(work, "response_loss")
        self.assertEqual(uncertain.status, "DELIVERY_UNCONFIRMED")
        self.assertIsNone(store.claim_next_outbox("second-dispatch"))
        recon = store.claim_reconciliation_next("reconcile-worker")
        self.assertIsNotNone(recon)
        assert recon is not None
        acknowledged = store.reconcile(recon, lookup=_Lookup(receiver, config))
        self.assertEqual(acknowledged.status, "DELIVERY_UNCONFIRMED")
        self.assertEqual(receiver.calls, 0)
        recon = store.claim_reconciliation_next("reconcile-worker-2")
        self.assertIsNotNone(recon)
        receiver.dispatch = lambda envelope_bytes, idempotency_key: build_synthetic_acknowledgment(envelope_bytes, config=config, idempotency_key=idempotency_key, accepted_ms=1)  # type: ignore[method-assign]
        assert recon is not None
        receiver.ack = receiver.dispatch(work.envelope_bytes, work.idempotency_key)
        self.assertEqual(store.reconcile(recon, lookup=_Lookup(receiver, config)).status, "ACKNOWLEDGED")
        self.assertIsNone(store.claim_reconciliation_next("later"))
        verify_database(store.path, expected_config=config.as_json)

    def test_missing_profile_ack_is_indeterminate(self) -> None:
        queue = self._verified()
        config = self._config()
        store = self._store(config)
        store.process_verified_job(queue.path, "job-1")
        work = store.claim_next_outbox("worker")
        assert work is not None
        store._mark_delivery_unconfirmed(work, "response_loss")
        recon = store.claim_reconciliation_next("reconciler")
        assert recon is not None
        receiver = _Receiver(config)
        raw = build_synthetic_acknowledgment(work.envelope_bytes, config=config, idempotency_key=work.idempotency_key)
        value = json.loads(raw.decode("ascii"))
        for key in ("profile_digest", "verifier_identity", "verifier_epoch"):
            value.pop(key)
        receiver.ack = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        result = store.reconcile(recon, lookup=_Lookup(receiver, config))
        self.assertEqual(result.status, "DELIVERY_UNCONFIRMED")
        self.assertIsNone(store.claim_next_outbox("no-resend"))
        verify_database(store.path, expected_config=config.as_json)

    def test_exception_authority_fields_are_explicit_and_nonexception_sentinels_bind(self) -> None:
        queue = self._verified()
        store = self._store()
        result = store.process_verified_job(queue.path, "job-1")
        self.assertIsNotNone(result.state_receipt_bytes)
        assert result.state_receipt_bytes is not None
        receipt = json.loads(result.state_receipt_bytes.decode("ascii"))
        self.assertEqual(receipt["exception_authorization_id"], "E0" + "00" * 63)
        self.assertEqual(receipt["exception_scope_id"], "E0" + "00" * 63)
        self.assertEqual(receipt["exception_valid_from"], 0)
        self.assertEqual(receipt["exception_valid_until"], 0)
        self.assertNotIn("exception_amount_commitment", receipt)
        self.assertEqual(len(receipt["settlement_id"]), 128)
        self.assertEqual(len(receipt["settlement_domain"]), 128)
        expected_settlement = composition_module._sha(composition_module._SETTLEMENT_REFERENCE, bytes.fromhex(receipt["settlement_domain"]), bytes((receipt["effective_directive"],)), bytes.fromhex(receipt["decision_id"]), bytes.fromhex(receipt["state_after_id"]), bytes(queue_fixtures._accepted().statement.state("proposed_payment_commitment")))
        self.assertEqual(receipt["settlement_id"], expected_settlement.hex().upper())
        with closing(sqlite3.connect(store.path)) as connection:
            envelope = json.loads(bytes(connection.execute("SELECT envelope_bytes FROM composition_transactions WHERE queue_job_id='job-1'").fetchone()[0]).decode("ascii"))
        self.assertEqual(envelope["exception_authorization_id"], receipt["exception_authorization_id"])
        self.assertNotIn("exception_amount_commitment", envelope)
        self.assertEqual(envelope["settlement_id"], receipt["settlement_id"])
        self.assertEqual(envelope["settlement_domain"], receipt["settlement_domain"])
        verify_database(store.path, expected_config=store.config.as_json)

    def test_state_binding_is_receiver_independent_but_handoff_is_receiver_bound(self) -> None:
        queue = self._verified()
        config_a = self._config()
        config_b = CompositionConfigV2(queue_id=config_a.queue_id, queue_config_digest=config_a.queue_config_digest, verifier_sha256=config_a.verifier_sha256, receiver_identity=b"Y" * 32, receiver_epoch=2)
        store_a = ClearanceCompositionStoreV2(path=self.root / "state-a.sqlite3", config=config_a)
        store_b = ClearanceCompositionStoreV2(path=self.root / "state-b.sqlite3", config=config_b)
        result_a = store_a.process_verified_job(queue.path, "job-1")
        result_b = store_b.process_verified_job(queue.path, "job-1")
        self.assertNotEqual(result_a.state_receipt_bytes, result_b.state_receipt_bytes)
        self.assertNotEqual(result_a.state_receipt_digest, result_b.state_receipt_digest)
        assert result_a.state_receipt_bytes is not None
        receipt = json.loads(result_a.state_receipt_bytes.decode("ascii"))
        receipt_b = json.loads(result_b.state_receipt_bytes.decode("ascii"))
        self.assertNotEqual(config_a.profile_digest, composition_independent_module._profile_digest(queue_fixtures._Acceptance().statement, config_a.verifier_sha256))
        with closing(sqlite3.connect(store_a.path)) as connection_a, closing(sqlite3.connect(store_b.path)) as connection_b:
            state_sql = "SELECT state_id,state_epoch,state_sequence,state_continuity_root,state_clearance_root,state_clearance_count,state_replay_root,payment_root,settled_batch_count,state_binding,audit_head,last_operation_digest FROM composition_meta WHERE id=1"
            self.assertEqual(connection_a.execute(state_sql).fetchone(), connection_b.execute(state_sql).fetchone())
            row_a = connection_a.execute("SELECT state_receipt_digest,envelope_bytes,envelope_digest,outbox_operation_id,idempotency_key FROM composition_transactions WHERE queue_job_id='job-1'").fetchone()
            row_b = connection_b.execute("SELECT state_receipt_digest,envelope_bytes,envelope_digest,outbox_operation_id,idempotency_key FROM composition_transactions WHERE queue_job_id='job-1'").fetchone()
        self.assertNotEqual(row_a[0], row_b[0])
        self.assertNotEqual(row_a[1], row_b[1])
        self.assertNotEqual(row_a[2:], row_b[2:])
        self.assertNotEqual(config_a.digest, config_b.digest)
        self.assertEqual(receipt["state_binding_after"], receipt_b["state_binding_after"])
        verify_database(store_a.path, expected_config=config_a.as_json)
        verify_database(store_b.path, expected_config=config_b.as_json)

        tampered = self.root / "ack-profile-state-binding.sqlite3"
        shutil.copy2(store_a.path, tampered)
        with closing(sqlite3.connect(tampered)) as connection:
            transaction_guard = connection.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='composition_transactions_guard'").fetchone()[0]
            event_guard = connection.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='composition_events_no_update'").fetchone()[0]
            connection.execute("DROP TRIGGER composition_transactions_guard")
            connection.execute("DROP TRIGGER composition_events_no_update")
            tx = tuple(connection.execute("SELECT * FROM composition_transactions WHERE queue_job_id='job-1'").fetchone())
            acceptance = parse_acceptance_bytes(bytes(tx[5]))
            initial_state = composition_independent_module._state_expected(acceptance.statement, config_a.verifier_sha256)
            replay_after = composition_module._sha(composition_module._STATE_REPLAY, bytes(initial_state[6]), acceptance.statement.attempt_id, acceptance.statement.request_id, acceptance.statement.receipt_id)
            wrong_binding = composition_module._sha(composition_module._STATE_BINDING, bytes(initial_state[9]), bytes(tx[11]), acceptance.statement.state_after_id, replay_after, bytes.fromhex(receipt["clearance_root_after"]), composition_module._u64(int(receipt["clearance_count_after"])), bytes(initial_state[7]), composition_module._u64(0), composition_module._u64(int(initial_state[1])), composition_module._u64(int(receipt["sequence_after"])), config_a.verifier_sha256, config_a.profile_digest)
            self.assertNotEqual(wrong_binding, bytes.fromhex(receipt["state_binding_after"]))
            receipt["state_binding_after"] = wrong_binding.hex().upper()
            receipt_raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("ascii")
            receipt_digest = composition_module._receipt_digest(receipt_raw)
            envelope = json.loads(bytes(tx[17]).decode("ascii"))
            envelope["state_receipt_digest"] = receipt_digest.hex().upper()
            envelope_raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("ascii")
            envelope_digest = composition_module._sha(composition_module._ENVELOPE, envelope_raw)
            outbox_operation_id = composition_module._operation_identity(config_a, "job-1", envelope_digest)
            idempotency_key = composition_module._idempotency_key(config_a, "job-1", envelope_digest)
            connection.execute("UPDATE composition_transactions SET state_receipt_bytes=?,state_receipt_digest=?,envelope_bytes=?,envelope_digest=?,outbox_operation_id=?,idempotency_key=? WHERE queue_job_id='job-1'", (receipt_raw, receipt_digest, envelope_raw, envelope_digest, outbox_operation_id, idempotency_key))
            event = tuple(connection.execute("SELECT * FROM composition_events WHERE event_kind='APPLIED'").fetchone())
            event_value = json.loads(bytes(event[11]).decode("ascii"))
            event_value["payload"]["state_receipt_digest"] = receipt_digest.hex().upper()
            event_value["payload"]["envelope_digest"] = envelope_digest.hex().upper()
            event_value["payload"]["outbox_operation_id"] = outbox_operation_id.hex().upper()
            event_value["payload"]["idempotency_key"] = idempotency_key.hex().upper()
            event_value["receipt_digest"] = receipt_digest.hex().upper()
            event_raw = json.dumps(event_value, sort_keys=True, separators=(",", ":")).encode("ascii")
            event_digest = composition_module._sha(composition_module._EVENT, composition_module._u64(int(event[0])), composition_module._u64(int(event[2])), str(event[3]).encode("ascii"), composition_module._fixed_ascii(str(event[1]), "job_id"), bytes(event[4]), bytes(event[5]), bytes(event[6]), str(event[7]).encode("ascii"), str(event[8]).encode("ascii"), bytes(event[9]), event_raw, receipt_digest)
            event_root = composition_module._sha(composition_module._HEAD, bytes(event[9]), composition_module._u64(int(event[0])), event_digest)
            connection.execute("UPDATE composition_events SET event_bytes=?,event_digest=?,event_root=?,receipt_digest=? WHERE global_sequence=?", (event_raw, event_digest, event_root, receipt_digest, event[0]))
            connection.execute("UPDATE composition_meta SET event_head=? WHERE id=1", (event_root,))
            connection.execute(transaction_guard)
            connection.execute(event_guard)
            connection.commit()
        with self.assertRaisesRegex(IndependentCompositionError, "receipt_state"):
            verify_database(tampered, expected_config=config_a.as_json)

    def test_different_valid_ack_is_conflict_event_and_ack_fast_path_checks_work_identity(self) -> None:
        queue = self._verified()
        config = self._config()
        store = self._store(config)
        store.process_verified_job(queue.path, "job-1")
        receiver = _Receiver(config)
        work = store.claim_next_outbox("worker")
        assert work is not None
        first = store.dispatch(work, receiver=receiver)
        self.assertEqual(first.status, "ACKNOWLEDGED")
        second = build_synthetic_acknowledgment(work.envelope_bytes, config=config, idempotency_key=work.idempotency_key, accepted_ms=999)
        with self.assertRaises(CompositionConflictError):
            store._commit_ack(work, second, "ACKNOWLEDGED")
        bad_work = CompositionOutboxWorkV2(config.composition_id, work.job_id, b"X" * 64, work.attempt, work.worker_id, work.lease_token, work.lease_expires_ms, work.envelope_bytes, work.idempotency_key)
        with self.assertRaises(CompositionLeaseError):
            store.dispatch(bad_work, receiver=receiver)
        bad_token = CompositionOutboxWorkV2(config.composition_id, work.job_id, work.operation_id, work.attempt, work.worker_id, b"X" * 24, work.lease_expires_ms, work.envelope_bytes, work.idempotency_key)
        with self.assertRaises(CompositionLeaseError):
            store.dispatch(bad_token, receiver=receiver)
        with closing(sqlite3.connect(store.path)) as connection:
            kinds = [row[0] for row in connection.execute("SELECT event_kind FROM composition_events ORDER BY global_sequence")]
        self.assertIn("ACK_CONFLICT", kinds)
        verify_database(store.path, expected_config=config.as_json)

    def test_ack_event_policy_result_is_bound_to_receipt(self) -> None:
        queue = self._verified()
        config = self._config()
        store = self._store(config)
        store.process_verified_job(queue.path, "job-1")
        work = store.claim_next_outbox("worker")
        assert work is not None
        store.dispatch(work, receiver=_Receiver(config))
        target = self.root / "ack-policy-tampered.sqlite3"
        shutil.copy2(store.path, target)
        with closing(sqlite3.connect(target)) as connection:
            connection.execute("DROP TRIGGER composition_events_no_update")
            row = tuple(connection.execute("SELECT * FROM composition_events WHERE event_kind='ACKNOWLEDGED'").fetchone())
            value = json.loads(bytes(row[11]).decode("ascii"))
            value["payload"]["policy_result"] = (int(value["payload"]["policy_result"]) % 5) + 1
            event_bytes = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            event_digest = composition_module._sha(composition_module._EVENT, composition_module._u64(int(row[0])), composition_module._u64(int(row[2])), str(row[3]).encode("ascii"), composition_module._fixed_ascii(str(row[1]), "job_id"), bytes(row[4]), bytes(row[5]), bytes(row[6]), str(row[7]).encode("ascii"), str(row[8]).encode("ascii"), bytes(row[9]), event_bytes, bytes(row[13]))
            event_root = composition_module._sha(composition_module._HEAD, bytes(row[9]), composition_module._u64(int(row[0])), event_digest)
            connection.execute("UPDATE composition_events SET event_bytes=?,event_digest=?,event_root=? WHERE global_sequence=?", (event_bytes, event_digest, event_root, row[0]))
            connection.execute("UPDATE composition_meta SET event_head=? WHERE id=1", (event_root,))
            connection.commit()
        with self.assertRaises(IndependentCompositionError):
            verify_database(target, expected_config=config.as_json)

    def test_queue_view_telemetry_and_local_digest_cannot_bypass_event_binding(self) -> None:
        queue = self._verified()
        store = self._store()
        store.process_verified_job(queue.path, "job-1")
        target = self.root / "queue-view-tampered.sqlite3"
        shutil.copy2(store.path, target)
        with closing(sqlite3.connect(target)) as connection:
            connection.execute("DROP TRIGGER IF EXISTS composition_transactions_guard")
            raw = json.loads(bytes(connection.execute("SELECT queue_view_bytes FROM composition_transactions WHERE queue_job_id='job-1'").fetchone()[0]).decode("ascii"))
            raw["peak_job_commit_bytes"] = 4_999_999_999
            changed = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("ascii")
            local_digest = composition_module._sha(composition_module._MATERIAL, b"queue-view", changed)
            connection.execute("UPDATE composition_transactions SET queue_view_bytes=?,queue_view_digest=? WHERE queue_job_id='job-1'", (changed, local_digest))
            connection.commit()
        with self.assertRaises(IndependentCompositionError):
            verify_database(target, expected_config=store.config.as_json)

    def test_bounded_dispatch_and_reconciliation_exhaustion_is_terminal(self) -> None:
        queue = self._verified()
        config = self._config()
        store = self._store(config)
        store.process_verified_job(queue.path, "job-1")
        wrong = _Receiver(config, identity=b"Z" * 32)
        for attempt in range(3):
            work = store.claim_next_outbox(f"worker-{attempt}")
            self.assertIsNotNone(work)
            assert work is not None
            result = store.dispatch(work, receiver=wrong)
            self.assertEqual(result.status, "DISPATCH_EXHAUSTED" if attempt == 2 else "READY")
        self.assertIsNone(store.claim_next_outbox("after-exhaustion"))
        store2 = ClearanceCompositionStoreV2(path=self.root / "composition2.sqlite3", config=config)
        store2.process_verified_job(queue.path, "job-1")
        work = store2.claim_next_outbox("dispatch-2")
        assert work is not None
        store2._mark_delivery_unconfirmed(work, "response_loss")
        for attempt in range(3):
            recon = store2.claim_reconciliation_next(f"recon-{attempt}")
            self.assertIsNotNone(recon)
            assert recon is not None
            result = store2.reconcile(recon, lookup=_NoneLookup(config))
            self.assertEqual(result.status, "RECONCILIATION_EXHAUSTED" if attempt == 2 else "DELIVERY_UNCONFIRMED")
        self.assertIsNone(store2.claim_reconciliation_next("after-recon-exhaustion"))
        verify_database(store.path, expected_config=config.as_json)
        verify_database(store2.path, expected_config=config.as_json)

    def test_expired_dispatch_becomes_unknown_and_only_reconciliation_claims(self) -> None:
        clock = queue_fixtures._Clock(1_000)
        config = self._config(lease_seconds=1)
        queue = self._verified()
        store = self._store(config, clock=clock)
        store.process_verified_job(queue.path, "job-1")
        work = store.claim_next_outbox("worker")
        assert work is not None
        clock.advance(2_000)
        recon = store.claim_reconciliation_next("reconciler")
        self.assertIsNone(store.claim_next_outbox("dispatch-after-expiry"))
        self.assertIsNotNone(recon)
        verify_database(store.path, expected_config=config.as_json)

    def test_event_tampering_tail_middle_root_payload_and_head_reject(self) -> None:
        queue = self._verified()
        store = self._store()
        store.process_verified_job(queue.path, "job-1")
        store._mark_delivery_unconfirmed(store.claim_next_outbox("worker"), "response_loss")  # type: ignore[arg-type]
        store.claim_reconciliation_next("reconciler")
        verify_database(store.path, expected_config=store.config.as_json)
        mutations = (
            ("tail", "DELETE FROM composition_events WHERE global_sequence=(SELECT MAX(global_sequence) FROM composition_events)"),
            ("root", "UPDATE composition_events SET previous_root=zeroblob(64) WHERE global_sequence=2"),
            ("payload", "UPDATE composition_events SET event_bytes=? WHERE global_sequence=1"),
            ("head", "UPDATE composition_meta SET event_head=zeroblob(64)"),
        )
        for label, statement in mutations:
            target = self.root / f"{label}.sqlite3"
            shutil.copy2(store.path, target)
            connection = sqlite3.connect(target)
            try:
                connection.execute("PRAGMA foreign_keys=OFF")
                connection.execute("DROP TRIGGER IF EXISTS composition_events_no_delete")
                connection.execute("DROP TRIGGER IF EXISTS composition_events_no_update")
                if label == "payload":
                    raw = connection.execute("SELECT event_bytes FROM composition_events WHERE global_sequence=1").fetchone()[0]
                    connection.execute(statement, (bytes(raw) + b" ",))
                else:
                    connection.execute(statement)
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(IndependentCompositionError, msg=label):
                verify_database(target, expected_config=store.config.as_json)
        reheaded = self.root / "reheaded-tail.sqlite3"
        shutil.copy2(store.path, reheaded)
        with closing(sqlite3.connect(reheaded)) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("DROP TRIGGER IF EXISTS composition_events_no_delete")
            connection.execute("DELETE FROM composition_events WHERE global_sequence=(SELECT MAX(global_sequence) FROM composition_events)")
            prior = connection.execute("SELECT event_root,global_sequence FROM composition_events ORDER BY global_sequence DESC LIMIT 1").fetchone()
            connection.execute("UPDATE composition_meta SET event_head=?,next_event_sequence=? WHERE id=1", (prior[0], prior[1]))
            connection.commit()
        with self.assertRaises(IndependentCompositionError, msg="reheaded-tail"):
            verify_database(reheaded, expected_config=store.config.as_json)

    def test_backup_restore_and_import_graph_gate(self) -> None:
        store = self._store()
        backup, restored = self.root / "backup.sqlite3", self.root / "restored.sqlite3"
        store.create_backup(backup)
        recovered = store.recover_from_backup(backup_path=backup, recovered_path=restored)
        self.assertEqual(recovered.snapshot()["schema"], "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v3")
        verify_database(restored, expected_config=store.config.as_json)
        broken = self.root / "broken-backup.sqlite3"
        shutil.copy2(backup, broken)
        with closing(sqlite3.connect(broken)) as connection:
            connection.execute("DROP TRIGGER composition_events_no_delete")
            connection.commit()
        with self.assertRaises(IndependentCompositionError):
            verify_database(broken, expected_config=store.config.as_json)
        source = Path("app/minimal_clearance_composition.py").read_text(encoding="utf-8") + Path("app/minimal_clearance_composition_independent.py").read_text(encoding="utf-8")
        for forbidden in ("transactional_database_boundary", "production_boundary", "governance_authority_v2", "app.batch", "privacy_v2", "experiments.bl_pq512_crypto_foundation", "stdout_sha3_512", "stderr_sha3_512"):
            self.assertNotIn(forbidden, source)

    def test_query_plan_uses_indexes_and_no_history_count_capacity_scan(self) -> None:
        store = self._store()
        with closing(sqlite3.connect(store.path)) as connection:
            ready = connection.execute("EXPLAIN QUERY PLAN SELECT * FROM composition_transactions WHERE delivery_status='READY' AND lease_kind IS NULL AND next_eligible_ms<=0 ORDER BY created_ms,queue_job_id LIMIT 1").fetchall()
            recon = connection.execute("EXPLAIN QUERY PLAN SELECT * FROM composition_transactions WHERE delivery_status='DELIVERY_UNCONFIRMED' AND lease_kind IS NULL AND next_eligible_ms<=0 ORDER BY created_ms,queue_job_id LIMIT 1").fetchall()
        self.assertTrue(any("composition_ready_idx" in str(row) for row in ready))
        self.assertTrue(any("composition_reconcile_idx" in str(row) for row in recon))
        source = Path("app/minimal_clearance_composition.py").read_text(encoding="utf-8")
        self.assertNotIn("SELECT COUNT(*) FROM outbox", source)

    def test_concurrent_duplicate_processing_converges_once(self) -> None:
        queue = self._verified()
        store = self._store()
        def process(): return store.process_verified_job(queue.path, "job-1")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: process(), (0, 1)))
        self.assertEqual([result.status for result in results], ["APPLIED", "APPLIED"])
        self.assertEqual(sum(result.duplicate_convergence for result in results), 1)
        verify_database(store.path, expected_config=store.config.as_json)

    def test_hostile_public_errors_are_fixed_and_support_has_no_canary(self) -> None:
        canaries = ("PHI_CANARY_MEMBER_0001", "credential CANARY_SECRET_ABC123", r"C:\CANARY\private-clearance.sqlite3")
        store = self._store()
        original_reader = composition_module.read_verified_batch
        def hostile(*_args, **_kwargs): raise RuntimeError("; ".join(canaries))
        composition_module.read_verified_batch = hostile  # type: ignore[assignment]
        try:
            with self.assertRaises(CompositionIntegrityError) as caught:
                store.process_verified_job(self.root / "missing.sqlite3", "job-1")
            rendered = "".join(traceback.format_exception(type(caught.exception), caught.exception, caught.exception.__traceback__))
            for canary in canaries:
                self.assertNotIn(canary, str(caught.exception)); self.assertNotIn(canary, repr(caught.exception)); self.assertNotIn(canary, rendered)
        finally:
            composition_module.read_verified_batch = original_reader  # type: ignore[assignment]
        queue = self._verified("receiver-job")
        store = ClearanceCompositionStoreV2(path=self.root / "receiver.sqlite3", config=self._config())
        store.process_verified_job(queue.path, "receiver-job")
        work = store.claim_next_outbox("receiver-worker")
        assert work is not None
        class HostileReceiver:
            def identity_sha256(self): return store.config.receiver_identity
            def epoch(self): return store.config.receiver_epoch
            def dispatch(self, *_args, **_kwargs): raise RuntimeError("; ".join(canaries))
        result = store.dispatch(work, receiver=HostileReceiver())
        self.assertEqual(result.status, "DELIVERY_UNCONFIRMED")
        with open(store.path, "rb") as database:
            persistent = database.read()
        for canary in canaries:
            self.assertNotIn(canary.encode("ascii"), persistent)
        verify_database(store.path, expected_config=store.config.as_json)
        original_connect = store._connect
        store._connect = lambda: (_ for _ in ()).throw(RuntimeError("; ".join(canaries)))  # type: ignore[method-assign]
        try:
            with self.assertRaises(CompositionIntegrityError) as caught_storage:
                store.snapshot()
            rendered = "".join(traceback.format_exception(type(caught_storage.exception), caught_storage.exception, caught_storage.exception.__traceback__))
            for canary in canaries:
                self.assertNotIn(canary, rendered)
        finally:
            store._connect = original_connect  # type: ignore[method-assign]


if __name__ == "__main__":
    unittest.main()
