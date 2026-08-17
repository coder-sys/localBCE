"""Focused evidence for the store-owned SQLite busy-recovery contract."""

from __future__ import annotations

import sqlite3
import threading
import time
import unittest
from unittest.mock import patch

from app.mirror import continuity_store as store
from app.mirror import state_value_ledger as state_value
from app.mirror import transition_mirror as transition
from app.mirror import transition_mirror_independent as transition_independent
from app.mirror import continuity_store_independent as store_independent
from app.mirror import money_mirror_independent as money_independent
from tests.test_mirror_money_mirror import _payload


class MirrorBusyRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.test_mirror_money_mirror import MirrorMoneyMirrorTests

        self._upstream = MirrorMoneyMirrorTests()
        self._upstream.setUp()
        self.addCleanup(self._upstream.doCleanups)

    def _setup(self, name: str = "busy.db"):
        instance, registry, trace_raw, trace_id, money_service = self._upstream._setup(name)
        money_receipt = money_service.observe(trace_id)
        money_id = str(money_independent._parse(_payload(instance, money_receipt))["artifact_id"])
        return (
            instance,
            registry,
            trace_raw,
            money_id,
            transition.TransitionMirrorService(instance, graph_profile_registry=registry),
            state_value.StateValueLedgerService(instance, graph_profile_registry=registry),
        )

    @staticmethod
    def _lock_writer(instance: store.ContinuityStore):
        ready = threading.Event()
        release = threading.Event()
        failures: list[BaseException] = []

        def hold() -> None:
            connection = sqlite3.connect(str(instance.path), timeout=0, isolation_level=None)
            try:
                connection.execute("BEGIN IMMEDIATE")
                ready.set()
                if not release.wait(store.BUSY_RECOVERY_BUDGET_MS / 1000 + 2):
                    failures.append(AssertionError("busy-test:lock-release-timeout"))
                connection.rollback()
            except BaseException as exc:  # evidence collection for the holder only
                failures.append(exc)
            finally:
                connection.close()

        thread = threading.Thread(target=hold)
        thread.start()
        if not ready.wait(2):
            release.set()
            thread.join()
            raise AssertionError("busy-test:lock-not-established")
        return thread, release, failures

    @staticmethod
    def _run_two_writers(service: transition.TransitionMirrorService, money_id: str):
        gate = threading.Barrier(3)
        results: list[bytes] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                gate.wait()
                results.append(service.compare(money_id).raw)
            except BaseException as exc:  # evidence collection only
                failures.append(exc)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        gate.wait()
        return threads, results, failures

    def test_transition_converges_after_contention_beyond_old_budget(self) -> None:
        instance, registry, _trace_raw, money_id, transition_service, _value_service = self._setup("beyond-old.db")
        holder, release, holder_failures = self._lock_writer(instance)
        old_budget_ms = 3 * store.BUSY_TIMEOUT_MS + 50 + 100
        release_timer = threading.Timer((old_budget_ms + 350) / 1000, release.set)
        try:
            started = time.monotonic()
            writers, results, failures = self._run_two_writers(transition_service, money_id)
            release_timer.start()
            for thread in writers:
                thread.join(store.BUSY_RECOVERY_BUDGET_MS / 1000 + 2)
                self.assertFalse(thread.is_alive())
            elapsed_ms = (time.monotonic() - started) * 1000
        finally:
            release_timer.cancel()
            release.set()
            holder.join(store.BUSY_RECOVERY_BUDGET_MS / 1000 + 2)
        self.assertFalse(holder.is_alive())
        self.assertFalse(holder_failures)
        self.assertFalse(failures)
        self.assertEqual(2, len(results))
        self.assertEqual(results[0], results[1])
        self.assertGreaterEqual(elapsed_ms, old_budget_ms)
        self.assertLess(elapsed_ms, store.BUSY_RECOVERY_BUDGET_MS)
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_transition_contention_beyond_supported_budget_fails_without_mutation(self) -> None:
        instance, registry, _trace_raw, money_id, transition_service, _value_service = self._setup("beyond-supported.db")
        before = instance._snapshot_rows()
        holder, release, holder_failures = self._lock_writer(instance)
        release_timer = threading.Timer((store.BUSY_RECOVERY_BUDGET_MS + 500) / 1000, release.set)
        try:
            started = time.monotonic()
            writers, results, failures = self._run_two_writers(transition_service, money_id)
            release_timer.start()
            for thread in writers:
                thread.join(store.BUSY_RECOVERY_BUDGET_MS / 1000 + 2)
                self.assertFalse(thread.is_alive())
            elapsed_ms = (time.monotonic() - started) * 1000
        finally:
            release_timer.cancel()
            release.set()
            holder.join(store.BUSY_RECOVERY_BUDGET_MS / 1000 + 2)
        self.assertFalse(holder.is_alive())
        self.assertFalse(holder_failures)
        self.assertEqual([], results)
        self.assertEqual(2, len(failures))
        self.assertTrue(all(isinstance(error, store.StoreBusyError) for error in failures))
        self.assertGreaterEqual(elapsed_ms, store.BUSY_RECOVERY_BUDGET_MS - 1000)
        self.assertLess(elapsed_ms, store.BUSY_RECOVERY_BUDGET_MS + 1000)
        self.assertEqual(before, instance._snapshot_rows())
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_transition_and_state_value_share_the_store_owned_policy(self) -> None:
        instance, _registry, _trace_raw, money_id, transition_service, value_service = self._setup("shared-owner.db")
        calls: list[object] = []
        original = store.run_with_busy_recovery

        def record(operation):
            calls.append(operation)
            return original(operation)

        with patch.object(store, "run_with_busy_recovery", record):
            transition_service.compare(money_id)
            value_service.observe(money_id)
        self.assertEqual(2, len(calls))

    def test_nonbusy_conflict_is_not_converted_to_retry_success(self) -> None:
        instance, registry, _trace_raw, money_id, _transition_service, _value_service = self._setup("conflict.db")
        before = instance._snapshot_rows()
        with self.assertRaises(store.StoreConflictError):
            instance.admit_transition(
                "TRANSITION_INITIAL",
                money_artifact_id=money_id,
                fixture_id=transition_independent.FIXTURE_MATCHED,
                graph_profile_registry={"wrong": object()},
            )
        self.assertEqual(before, instance._snapshot_rows())
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])


if __name__ == "__main__":
    unittest.main()
