"""Focused queue-receipt to deterministic state-application tests."""

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app.minimal_clearance_proof_state import (
    MinimalClearanceProofStateError,
    MinimalClearanceStateStoreV1,
    MinimalProofAcceptanceV1,
    parse_acceptance_bytes,
)
from app.minimal_clearance_queue_application import (
    QueueApplicationConfigV1,
    QueueApplicationIndeterminateError,
    QueueApplicationIntegrityError,
    QueueApplicationLeaseError,
    QueueApplicationStoreV1,
)
from app.minimal_clearance_queue_application_independent import (
    IndependentQueueApplicationError,
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)
from app.minimal_clearance_verification_queue import (
    ArtifactMetadata,
    QueueConfig,
    QueueWorker,
    VerificationQueueStore,
)

from tests.test_minimal_clearance_verification_queue import (
    _Acceptance,
    _Containment,
    _Custody,
    _Factory,
    _RAW,
    _SHA256,
    _SHA3,
    _VERIFIER,
)


class _NoNativeVerifier:
    def __init__(self, acceptance: MinimalProofAcceptanceV1) -> None:
        self.acceptance = acceptance
        self.identity = _VERIFIER
        self.verify_calls = 0

    def identity_sha256(self) -> bytes:
        return self.identity

    def expected_statement(self) -> bytes:
        return self.acceptance.statement.statement_bytes

    def verify(self, artifact_path: Path) -> MinimalProofAcceptanceV1:
        self.verify_calls += 1
        raise AssertionError("application must not invoke a native verifier")


class _StoreClock:
    def __init__(self) -> None:
        self.value = 10_000

    def now_ms(self) -> int:
        return self.value

    def advance(self, value: int) -> None:
        self.value += value


class QueueApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-queue-application-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _queue_config(self) -> QueueConfig:
        return QueueConfig(
            "queue-application-test", 8, 300, _VERIFIER, 512 * 1024 * 1024,
            ("custody_read", "verifier_timeout"),
        )

    def _queue(self, count: int = 4) -> tuple[Path, QueueConfig, MinimalProofAcceptanceV1]:
        config = self._queue_config()
        path = self.root / "queue.sqlite3"
        store = VerificationQueueStore(path=path, config=config)
        metadata = ArtifactMetadata("opaque-retained-proof", len(_RAW), _SHA256, _SHA3)
        for index in range(count):
            store.admit(job_id=f"job-{index}", metadata=metadata)
        custody = _Custody(self.root / "custody")
        factory = _Factory(containment=_Containment())
        workers = tuple(
            QueueWorker(
                store=store, worker_id=f"worker-{index}", custody=custody,
                verifier_factory=factory,
            )
            for index in range(count)
        )
        for worker in workers:
            result = worker.process_one()
            self.assertIsNotNone(result)
            self.assertEqual(result.status, "VERIFIED")
        store.verify_integrity()
        return path, config, _Acceptance()

    def _state(self, acceptance: MinimalProofAcceptanceV1) -> tuple[MinimalClearanceStateStoreV1, _NoNativeVerifier]:
        verifier = _NoNativeVerifier(acceptance)
        store = MinimalClearanceStateStoreV1(path=self.root / "clearance.sqlite3", verifier=verifier)
        return store, verifier

    def _application(self, config: QueueConfig, state: MinimalClearanceStateStoreV1) -> QueueApplicationStoreV1:
        app_config = QueueApplicationConfigV1(
            application_id="queue-application-test",
            queue_id=config.queue_id,
            queue_config_digest=config.digest,
            verifier_sha256=_VERIFIER,
            state_store_identity=state.state_store_identity(),
            capacity=8,
        )
        return QueueApplicationStoreV1(path=self.root / "application.sqlite3", config=app_config, clock=_StoreClock())

    def test_verified_discovery_apply_and_duplicate_convergence(self) -> None:
        queue_path, queue_config, acceptance = self._queue()
        state, verifier = self._state(acceptance)
        app = self._application(queue_config, state)
        try:
            jobs = [app.discover(queue_path, f"job-{index}") for index in range(4)]
            works = [app.claim_next(f"application-worker-{index}") for index in range(4)]
            self.assertTrue(all(work is not None for work in works))
            results = [app.apply(work, queue_database=queue_path, state_store=state) for work in works if work is not None]
            self.assertEqual([result.status for result in results], ["APPLIED"] * 4)
            self.assertEqual(sum(not result.duplicate_convergence for result in results), 1)
            self.assertEqual(sum(result.duplicate_convergence for result in results), 3)
            self.assertEqual(len({result.state_receipt_bytes for result in results}), 1)
            self.assertEqual(state.snapshot().sequence, acceptance.statement.sequence_before + 1)
            self.assertEqual(verifier.verify_calls, 0)
            self.assertEqual(app.snapshot()["status_counts"], {"APPLIED": 4, "DISCOVERED": 0, "HELD": 0, "LEASED": 0})
            app.verify_integrity()
        finally:
            state.close()

    def test_exact_discovery_retry_conflict_and_nonverified_reject(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=1)
        state, _ = self._state(acceptance)
        app = self._application(queue_config, state)
        try:
            first = app.discover(queue_path, "job-0")
            retry = app.discover(queue_path, "job-0")
            self.assertEqual(first.operation_id, retry.operation_id)
            with self.assertRaises(QueueApplicationIntegrityError):
                app.discover(queue_path, "missing-job")
        finally:
            state.close()

    def test_queue_tamper_is_rejected_before_state_mutation(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=1)
        state, verifier = self._state(acceptance)
        app = self._application(queue_config, state)
        try:
            app.discover(queue_path, "job-0")
            work = app.claim_next("worker")
            self.assertIsNotNone(work)
            with closing(sqlite3.connect(queue_path)) as connection:
                connection.execute("DROP TRIGGER queue_transitions_no_update")
                connection.execute("UPDATE queue_results SET receipt_bytes=? WHERE job_id='job-0'", (b"tampered",))
                connection.commit()
            before = state.snapshot()
            result = app.apply(work, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
            self.assertEqual(result.status, "HELD")
            self.assertEqual(state.snapshot(), before)
            self.assertEqual(verifier.verify_calls, 0)
        finally:
            state.close()

    def test_stale_application_lease_rejects_before_state_admission(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=1)
        state, verifier = self._state(acceptance)
        app = self._application(queue_config, state)
        try:
            app.discover(queue_path, "job-0")
            work = app.claim_next("worker")
            self.assertIsNotNone(work)
            before = state.snapshot()
            before_application = app.snapshot()
            stale = replace(work, lease_token=b"X" * len(work.lease_token))  # type: ignore[arg-type]
            with self.assertRaises(QueueApplicationLeaseError):
                app.apply(stale, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
            self.assertEqual(state.snapshot(), before)
            self.assertEqual(app.snapshot(), before_application)
            self.assertEqual(verifier.verify_calls, 0)
        finally:
            state.close()

    def test_reordered_same_acceptance_uses_atomic_state_disposition(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=2)
        state, verifier = self._state(acceptance)
        app = self._application(queue_config, state)
        try:
            app.discover(queue_path, "job-0")
            app.discover(queue_path, "job-1")
            first = app.claim_next("worker-0")
            second = app.claim_next("worker-1")
            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            results = [
                app.apply(second, queue_database=queue_path, state_store=state),  # type: ignore[arg-type]
                app.apply(first, queue_database=queue_path, state_store=state),  # type: ignore[arg-type]
            ]
            self.assertEqual([result.status for result in results], ["APPLIED", "APPLIED"])
            self.assertEqual(sum(not result.duplicate_convergence for result in results), 1)
            self.assertEqual(sum(result.duplicate_convergence for result in results), 1)
            self.assertEqual(len({result.state_receipt_bytes for result in results}), 1)
            self.assertEqual(state.snapshot().sequence, acceptance.statement.sequence_before + 1)
            self.assertEqual(verifier.verify_calls, 0)
            app.verify_integrity()
        finally:
            state.close()

    def test_expired_lease_requeues_and_old_token_cannot_apply(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=1)
        state, verifier = self._state(acceptance)
        clock = _StoreClock()
        app_config = QueueApplicationConfigV1(
            "queue-application-test", queue_config.queue_id, queue_config.digest, _VERIFIER,
            state.state_store_identity(), capacity=8, lease_seconds=1,
        )
        app = QueueApplicationStoreV1(path=self.root / "application.sqlite3", config=app_config, clock=clock)
        try:
            app.discover(queue_path, "job-0")
            old = app.claim_next("worker-0")
            self.assertIsNotNone(old)
            clock.advance(1001)
            fresh = app.claim_next("worker-1")
            self.assertIsNotNone(fresh)
            self.assertEqual(fresh.attempt, 2)  # type: ignore[union-attr]
            with self.assertRaises(QueueApplicationLeaseError):
                app.apply(old, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
            result = app.apply(fresh, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
            self.assertEqual(result.status, "APPLIED")
            self.assertFalse(result.duplicate_convergence)
            app.verify_integrity()
            verify_database(app.path, expected_config=app.config.as_json())
        finally:
            state.close()

    def test_expired_third_attempt_becomes_held_with_reconstruction_parity(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=1)
        state, _ = self._state(acceptance)
        clock = _StoreClock()
        app_config = QueueApplicationConfigV1(
            "queue-application-test", queue_config.queue_id, queue_config.digest, _VERIFIER,
            state.state_store_identity(), capacity=8, lease_seconds=1,
        )
        app = QueueApplicationStoreV1(path=self.root / "application.sqlite3", config=app_config, clock=clock)
        try:
            app.discover(queue_path, "job-0")
            for expected_attempt in (1, 2, 3):
                work = app.claim_next("worker")
                self.assertIsNotNone(work)
                self.assertEqual(work.attempt, expected_attempt)  # type: ignore[union-attr]
                clock.advance(1001)
            self.assertIsNone(app.claim_next("worker"))
            self.assertEqual(app.snapshot()["status_counts"], {"APPLIED": 0, "DISCOVERED": 0, "HELD": 1, "LEASED": 0})
            app.verify_integrity()
            exported = app.export_bytes()
            verify_export_bytes(exported, expected_config=app.config.as_json())
            verify_database(app.path, expected_config=app.config.as_json())
        finally:
            state.close()

    def test_state_commit_then_lease_expiry_recovers_as_duplicate(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=1)
        state, verifier = self._state(acceptance)
        clock = _StoreClock()
        app_config = QueueApplicationConfigV1(
            "queue-application-test", queue_config.queue_id, queue_config.digest, _VERIFIER,
            state.state_store_identity(), capacity=8, lease_seconds=1,
        )
        fired = {"value": False}
        def expire_after_state(name: str) -> None:
            if name == "after_state_commit_before_coordinator" and not fired["value"]:
                fired["value"] = True
                clock.advance(1001)
        app = QueueApplicationStoreV1(
            path=self.root / "application.sqlite3", config=app_config, clock=clock,
            before_fault=expire_after_state,
        )
        try:
            app.discover(queue_path, "job-0")
            first = app.claim_next("worker-0")
            self.assertIsNotNone(first)
            with self.assertRaises(QueueApplicationIndeterminateError):
                app.apply(first, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
            self.assertEqual(state.snapshot().sequence, acceptance.statement.sequence_before + 1)
            second = app.claim_next("worker-1")
            self.assertIsNotNone(second)
            result = app.apply(second, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
            self.assertEqual(result.status, "APPLIED")
            self.assertTrue(result.duplicate_convergence)
            self.assertEqual(state.snapshot().sequence, acceptance.statement.sequence_before + 1)
            self.assertEqual(verifier.verify_calls, 0)
            app.verify_integrity()
        finally:
            state.close()

    def test_coordinator_precommit_loss_recovers_by_exact_state_retry(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=1)
        state, verifier = self._state(acceptance)
        failures = {"count": 0}

        def fault(name: str) -> None:
            if name == "after_state_commit_before_coordinator" and failures["count"] == 0:
                failures["count"] += 1
                raise RuntimeError("synthetic_coordinator_response_loss")

        app_config = QueueApplicationConfigV1(
            "queue-application-test", queue_config.queue_id, queue_config.digest, _VERIFIER,
            state.state_store_identity(), capacity=8,
        )
        app = QueueApplicationStoreV1(path=self.root / "application.sqlite3", config=app_config, before_fault=fault)
        try:
            app.discover(queue_path, "job-0")
            work = app.claim_next("worker")
            self.assertIsNotNone(work)
            with self.assertRaisesRegex(RuntimeError, "response_loss"):
                app.apply(work, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
            self.assertEqual(state.snapshot().sequence, acceptance.statement.sequence_before + 1)
            recovered = app.apply(work, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
            self.assertEqual(recovered.status, "APPLIED")
            self.assertTrue(recovered.duplicate_convergence)
            self.assertEqual(state.snapshot().sequence, acceptance.statement.sequence_before + 1)
            self.assertEqual(verifier.verify_calls, 0)
            app.verify_integrity()
        finally:
            state.close()

    def test_export_restore_independent_parity_and_acceptance_tamper(self) -> None:
        queue_path, queue_config, acceptance = self._queue(count=1)
        state, _ = self._state(acceptance)
        app = self._application(queue_config, state)
        try:
            app.discover(queue_path, "job-0")
            exported = app.export_bytes()
            self.assertEqual(verify_export_bytes(exported, expected_config=app.config.as_json()), verify_database(app.path, expected_config=app.config.as_json()))
            restored = restore_export_to_fresh_database(self.root / "application-restore.sqlite3", exported)
            self.assertEqual(restored, verify_export_bytes(exported, expected_config=app.config.as_json()))
            value = json.loads(exported.decode("ascii"))
            value["jobs"][0]["acceptance_bytes"] = ("00" + value["jobs"][0]["acceptance_bytes"][2:])
            tampered = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            with self.assertRaises(IndependentQueueApplicationError):
                verify_export_bytes(tampered)
            with closing(sqlite3.connect(app.path)) as connection:
                connection.execute("UPDATE app_metadata SET verifier_sha256=? WHERE id=1", (b"Z" * 32,))
                connection.commit()
            with self.assertRaises(IndependentQueueApplicationError):
                verify_database(app.path)
        finally:
            state.close()

    def test_typed_admission_never_calls_verifier_or_mutates_payment(self) -> None:
        _, _, acceptance = self._queue(count=1)
        state, verifier = self._state(acceptance)
        try:
            before = state.snapshot()
            first = state.submit_verified_acceptance_outcome(parse_acceptance_bytes(acceptance.canonical_bytes()))
            second = state.submit_verified_acceptance_outcome(parse_acceptance_bytes(acceptance.canonical_bytes()))
            self.assertTrue(first.transition_applied)
            self.assertFalse(second.transition_applied)
            receipt = second.receipt
            after = state.snapshot()
            self.assertEqual(verifier.verify_calls, 0)
            self.assertEqual(before.payment_root, after.payment_root)
            self.assertEqual(before.settled_batch_count, after.settled_batch_count)
            self.assertFalse(receipt.economic_mutation)
            self.assertTrue(receipt.proof_session_accepted)
            self.assertIsNone(receipt.proof_suite_id)
        finally:
            state.close()


if __name__ == "__main__":
    unittest.main()
