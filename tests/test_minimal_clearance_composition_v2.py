from __future__ import annotations

from pathlib import Path
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
import inspect

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

    def test_export_restore_and_exact_fresh_table_boundary(self) -> None:
        config = self._config()
        store = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite3", config=config)
        with closing(sqlite3.connect(store.path)) as connection:
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
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
        source = inspect.getsource(composition_module)
        self.assertNotIn("transactional_database_boundary", source)
        self.assertNotIn("SQLiteSettlementStoreV2", source)


if __name__ == "__main__":
    unittest.main()
