from __future__ import annotations

from pathlib import Path
import json
import sqlite3
import tempfile
import traceback
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import inspect
from unittest.mock import patch

import tests.test_minimal_clearance_verification_queue as queue_fixtures
from app.minimal_clearance_composition import (
    CompositionBackpressureError,
    CompositionConfigV2,
    ClearanceCompositionStoreV2,
    build_synthetic_acknowledgment,
)
from app.minimal_clearance_composition_independent import (
    IndependentCompositionError,
    restore_export_to_fresh_database,
    verify_database,
)
import app.minimal_clearance_composition as composition_module


class _Receiver:
    def __init__(self, config: CompositionConfigV2) -> None:
        self.config = config
        self.calls = 0
        self.ack: bytes | None = None

    def identity_sha256(self) -> bytes:
        return self.config.receiver_identity

    def epoch(self) -> int:
        return self.config.receiver_epoch

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.calls += 1
        self.ack = build_synthetic_acknowledgment(
            envelope_bytes, config=self.config, idempotency_key=idempotency_key, accepted_ms=1,
        )
        return self.ack


class _Lookup:
    def __init__(self, receiver: _Receiver, config: CompositionConfigV2) -> None:
        self.receiver = receiver
        self.config = config
        self.calls = 0

    def acknowledgment_profile(self):
        return self.config.acknowledgment_profile

    def lookup_acknowledgment(self, **_query):
        self.calls += 1
        return self.receiver.ack


class CompositionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.queue_tests = queue_fixtures.VerificationQueueTests(methodName="runTest")
        self.queue_tests.setUp()
        self.temp = tempfile.TemporaryDirectory(prefix="bl-composition-v2-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.queue_tests.tearDown()

    def _config(self, *, capacity: int = 16) -> CompositionConfigV2:
        queue_config = self.queue_tests._config()
        return CompositionConfigV2(
            queue_id=queue_config.queue_id,
            queue_config_digest=queue_config.digest,
            verifier_sha256=queue_fixtures._VERIFIER,
            receiver_identity=bytes(range(32)),
            capacity=capacity,
        )

    def _verified_queue(self, job_id: str = "job-1", factory=None):
        queue = self.queue_tests._store()
        self.queue_tests._verify_one(queue, job_id, factory=factory or queue_fixtures._Factory())
        return queue

    def test_one_native_queue_verification_and_zero_composition_retry_calls(self) -> None:
        factory = queue_fixtures._Factory()
        queue = self._verified_queue(factory=factory)
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=self._config())
        first = store.process_verified_job(queue.path, "job-1")
        retry = store.process_verified_job(queue.path, "job-1")
        self.assertEqual(first.status, "APPLIED")
        self.assertTrue(retry.duplicate_convergence)
        self.assertEqual(len(factory.instances), 1)
        self.assertEqual(store.snapshot()["outbox_counts"]["DISCOVERED"], 1)

    def test_send_before_record_response_loss_positive_reconciliation(self) -> None:
        queue = self._verified_queue()
        failed = {"done": False}

        def fault(label: str) -> None:
            if label == "after_dispatch_before_ack_commit" and not failed["done"]:
                failed["done"] = True
                raise RuntimeError("response_lost")

        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config, before_fault=fault)
        store.process_verified_job(queue.path, "job-1")
        receiver = _Receiver(config)
        work = store.claim_next_outbox("dispatch-worker")
        self.assertIsNotNone(work)
        uncertain = store.dispatch(work, receiver=receiver)
        self.assertEqual(uncertain.status, "DELIVERY_UNCONFIRMED")
        self.assertEqual(receiver.calls, 1)
        reconciliation = store.claim_reconciliation_next("reconcile-worker")
        self.assertIsNotNone(reconciliation)
        lookup = _Lookup(receiver, config)
        acknowledged = store.reconcile(reconciliation, lookup=lookup)
        self.assertEqual(acknowledged.status, "ACKNOWLEDGED")
        self.assertEqual(lookup.calls, 1)
        self.assertEqual(store.snapshot()["outbox_counts"]["ACKNOWLEDGED"], 1)
        verify_database(store.path, expected_config=config.as_json)
        restored = self.root / "acknowledged-restored.sqlite3"
        restore_export_to_fresh_database(restored, store.export_bytes(), expected_config=config.as_json)
        verify_database(restored, expected_config=config.as_json)

    def test_dispatch_ack_converges_existing_reconciliation_record(self) -> None:
        queue = self._verified_queue()
        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)
        store.process_verified_job(queue.path, "job-1")
        work = store.claim_next_outbox("dispatch-worker")
        self.assertIsNotNone(work)
        store._mark_delivery_unconfirmed(work, "response_loss")
        retry = store.claim_next_outbox("retry-worker")
        self.assertIsNotNone(retry)
        receiver = _Receiver(config)
        acknowledged = store.dispatch(retry, receiver=receiver)
        self.assertEqual(acknowledged.status, "ACKNOWLEDGED")
        self.assertIsNone(store.claim_reconciliation_next("reconcile-worker"))
        verify_database(store.path, expected_config=config.as_json)

    def test_negative_reconciliation_does_not_redispatch_or_change_delivery(self) -> None:
        queue = self._verified_queue()
        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)
        store.process_verified_job(queue.path, "job-1")
        work = store.claim_next_outbox("dispatch-worker")
        receiver = _Receiver(config)
        store._mark_delivery_unconfirmed(work, "response_loss")
        reconciliation = store.claim_reconciliation_next("reconcile-worker")

        class NoneLookup:
            def lookup_acknowledgment(self, **_query):
                return None

        result = store.reconcile(reconciliation, lookup=NoneLookup())
        self.assertEqual(result.status, "DELIVERY_UNCONFIRMED")
        self.assertEqual(receiver.calls, 0)
        self.assertEqual(store.snapshot()["outbox_counts"]["DELIVERY_UNCONFIRMED"], 1)

    def test_hostile_queue_receiver_and_storage_failures_are_redacted(self) -> None:
        canaries = (
            "PHI_CANARY_MEMBER_0001",
            "credential CANARY_SECRET_ABC123",
            r"C:\CANARY\private-clearance.sqlite3",
        )

        def assert_redacted(error: BaseException) -> None:
            rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            for canary in canaries:
                self.assertNotIn(canary, str(error))
                self.assertNotIn(canary, repr(error))
                self.assertNotIn(canary, rendered)

        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)

        def hostile_reader(*_args, **_kwargs):
            raise RuntimeError("; ".join(canaries))

        with patch.object(composition_module, "read_verified_job", hostile_reader):
            with self.assertRaises(Exception) as caught:
                store.process_verified_job(self.root / "missing-queue.sqlite3", "job-1")
        assert_redacted(caught.exception)

        queue = self._verified_queue()
        store.process_verified_job(queue.path, "job-1")
        work = store.claim_next_outbox("dispatch-worker")
        self.assertIsNotNone(work)
        assert work is not None

        class HostileReceiver(_Receiver):
            def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
                raise RuntimeError("; ".join(canaries))

        receiver = HostileReceiver(config)
        with patch.object(store, "_mark_delivery_unconfirmed", side_effect=RuntimeError("; ".join(canaries))):
            with self.assertRaises(Exception) as caught:
                store.dispatch(work, receiver=receiver)
        assert_redacted(caught.exception)

        support = json.dumps(store.support_summary(), sort_keys=True)
        exported = store.export_bytes()
        persisted = store.path.read_bytes()
        self.assertNotIn(b"stdout_sha3_512", exported)
        self.assertNotIn(b"stderr_sha3_512", exported)
        self.assertNotIn(b"stdout_sha3_512", persisted)
        self.assertNotIn(b"stderr_sha3_512", persisted)
        for canary in canaries:
            self.assertNotIn(canary, support)
            self.assertNotIn(canary.encode("ascii"), exported)
            self.assertNotIn(canary.encode("ascii"), persisted)

    def test_export_restore_and_exact_fresh_table_boundary(self) -> None:
        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)
        with closing(sqlite3.connect(store.path)) as connection:
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
        self.assertEqual(
            tables,
            {
                "composition_metadata", "composition_state", "composition_transitions", "proof_requests",
                "proof_audit", "proof_transitions", "application_dispositions", "outbox_jobs", "outbox_leases",
                "outbox_acks", "outbox_transitions", "reconciliation_records",
            },
        )
        self.assertNotIn("metadata", tables)
        self.assertNotIn("settlement_requests", tables)
        self.assertNotIn("migration_requests", tables)
        self.assertIn("composition_metadata", tables)
        self.assertIn("reconciliation_records", tables)
        raw = store.export_bytes()
        verify_database(store.path, expected_config=config.as_json)
        restore_export_to_fresh_database(self.root / "restored.sqlite3", raw, expected_config=config.as_json)
        verify_database(self.root / "restored.sqlite3", expected_config=config.as_json)

    def test_outbox_capacity_rolls_back_empty_composition(self) -> None:
        queue = self._verified_queue()
        config = self._config(capacity=1)
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute(
                "INSERT INTO outbox_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("sentinel", b"S" * 64, b"D" * 64, b"E", b"G" * 64, b"I" * 64, "DISCOVERED", 0, 0, 0, 0, None),
            )
            connection.commit()
        before = store.snapshot()
        with self.assertRaises(CompositionBackpressureError):
            store.process_verified_job(queue.path, "job-1")
        after = store.snapshot()
        self.assertEqual(before["disposition_counts"], after["disposition_counts"])
        self.assertEqual(before["outbox_counts"], after["outbox_counts"])

    def test_independent_rejects_legacy_table_and_config_substitution(self) -> None:
        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)
        raw = store.export_bytes()
        value = json.loads(raw.decode("ascii"))
        value["config"]["queue_id"] = "wrong-queue"
        tampered = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaises(IndependentCompositionError):
            from app.minimal_clearance_composition_independent import verify_export_bytes
            verify_export_bytes(tampered, expected_config=config.as_json)
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("CREATE TABLE legacy_settlement_requests (id INTEGER)")
            connection.commit()
        with self.assertRaises(IndependentCompositionError):
            verify_database(store.path, expected_config=config.as_json)

    def test_composition_runtime_has_no_settlement_owner_dependency(self) -> None:
        paths = (
            "app/minimal_clearance_composition.py",
            "app/minimal_clearance_composition_independent.py",
            "app/minimal_clearance_proof_primitives.py",
            "app/minimal_clearance_verification_queue.py",
            "app/minimal_clearance_verification_queue_independent.py",
        )
        forbidden = (
            "transactional_database_boundary", "production_boundary", "governance_authority_v2",
            "app.batch", "privacy_v2", "experiments.bl_pq512_crypto_foundation",
        )
        for path in paths:
            source = Path(path).read_text(encoding="utf-8")
            for prefix in forbidden:
                self.assertNotIn(prefix, source, f"{path}: forbidden active dependency {prefix}")
        source = inspect.getsource(composition_module)
        self.assertNotIn("SQLiteSettlementStoreV2", source)

    def test_direct_backup_restore_and_v1_database_rejection(self) -> None:
        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)
        backup = self.root / "backup.sqlite3"
        recovered = self.root / "recovered.sqlite3"
        store.create_backup(backup)
        restored = store.recover_from_backup(backup_path=backup, recovered_path=recovered)
        self.assertEqual(restored.snapshot()["schema"], "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v2")
        legacy = self.root / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy)) as connection:
            connection.execute("CREATE TABLE settlement_requests (id INTEGER)")
            connection.commit()
        with self.assertRaises(Exception) as caught:
            ClearanceCompositionStoreV2(path=legacy, config=config)
        self.assertIn("wrong_schema", str(caught.exception))

    def test_composition_commit_faults_have_no_partial_state_and_exact_retry(self) -> None:
        queue = self._verified_queue()
        config = self._config()
        before = {"fired": False}

        def before_fault(label: str) -> None:
            if label == "before_composition_commit" and not before["fired"]:
                before["fired"] = True
                raise RuntimeError("commit_not_started")

        path = self.root / "composition.sqlite3"
        store = ClearanceCompositionStoreV2(path=path, config=config, before_fault=before_fault)
        with self.assertRaises(RuntimeError):
            store.process_verified_job(queue.path, "job-1")
        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_state").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM application_dispositions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM outbox_jobs").fetchone()[0], 0)
        restarted = ClearanceCompositionStoreV2(path=path, config=config)
        committed = restarted.process_verified_job(queue.path, "job-1")
        self.assertEqual(committed.status, "APPLIED")

        after = {"fired": False}

        def after_fault(label: str) -> None:
            if label == "after_composition_commit" and not after["fired"]:
                after["fired"] = True
                raise RuntimeError("commit_response_lost")

        uncertain_store = ClearanceCompositionStoreV2(path=self.root / "after.sqlite3", config=config, after_commit_fault=after_fault)
        with self.assertRaises(Exception):
            uncertain_store.process_verified_job(queue.path, "job-1")
        retry = uncertain_store.process_verified_job(queue.path, "job-1")
        self.assertTrue(retry.duplicate_convergence)
        verify_database(uncertain_store.path, expected_config=config.as_json)

    def test_concurrent_duplicate_composition_converges_once(self) -> None:
        queue = self._verified_queue()
        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)

        def process() -> object:
            return store.process_verified_job(queue.path, "job-1")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _unused: process(), (0, 1)))
        self.assertEqual(sorted(result.status for result in results), ["APPLIED", "APPLIED"])
        self.assertEqual(sum(result.duplicate_convergence for result in results), 1)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM application_dispositions").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM outbox_jobs").fetchone()[0], 1)
        verify_database(store.path, expected_config=config.as_json)

    def test_expired_outbox_lease_rejects_stale_token_and_recovers(self) -> None:
        queue = self._verified_queue()
        clock = queue_fixtures._Clock(1_000)
        config = CompositionConfigV2(
            queue_id=self.queue_tests._config().queue_id,
            queue_config_digest=self.queue_tests._config().digest,
            verifier_sha256=queue_fixtures._VERIFIER,
            receiver_identity=bytes(range(32)),
            lease_seconds=1,
        )
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config, clock=clock)
        store.process_verified_job(queue.path, "job-1")
        work = store.claim_next_outbox("worker-1")
        self.assertIsNotNone(work)
        clock.advance(1_001)
        receiver = _Receiver(config)
        with self.assertRaises(Exception):
            store.dispatch(work, receiver=receiver)
        self.assertEqual(receiver.calls, 0)
        recovered = store.claim_next_outbox("worker-2")
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.attempt, 2)
        verify_database(store.path, expected_config=config.as_json)


if __name__ == "__main__":
    unittest.main()
