import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import app.minimal_clearance_verification_queue as queue
from app.minimal_clearance_composition import CompositionConfigV2
from app.minimal_clearance_verification_queue import (
    BatchVerifierResult,
    OperationTemplate,
    PROOF_ATTEMPTS_CAP,
    QueueBackpressureError,
    QueueConfig,
    VerificationQueueError,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)
from app.minimal_clearance_verification_queue_independent import verify_database
from app.minimal_clearance_verification_queue_independent import IndependentQueueError, _verify_lifecycle


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


class Profile12StateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config = QueueConfig("profile12-focused", 100)
        self.composition_config = CompositionConfigV2(self.config.queue_id, self.config.digest, capacity=100)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.root / "state.sqlite", config=self.config, owner=self.owner, clock=self.clock, composition_config=self.composition_config)

    def tearDown(self) -> None:
        self.store._close()
        self.owner.close()
        self.temp.cleanup()

    def _template(self) -> OperationTemplate:
        return OperationTemplate("profile12-assertion", 1, self.config.profile_version, self.clock.now - 100, self.clock.now + 60_000)

    def test_independent_context_kat_and_runtime_context_are_exact(self) -> None:
        self.assertEqual(queue.PROFILE12_CONTEXT_KAT.hex(), "931fee1e981d0c844438d08662f6853cc62db7b6ac33a789b82032b33a764997677a505644a5e86085b871ac929c4c36667460883cf3d50b658dc50223c1417d")
        self.assertEqual(queue._profile12_context(session_ref=bytes(range(64)), ordered_batch_root=bytes(range(64, 128)), public_coin=bytes(range(96)), valid_from_ms=6000, valid_until_ms=9000), queue.PROFILE12_CONTEXT_KAT)
        batch = self.store.issue_batch(template=self._template())
        self.assertEqual(batch.proof_context, queue._profile12_context(session_ref=batch.session_ref, ordered_batch_root=batch.batch_root, public_coin=batch.public_coin, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms))
        self.assertNotIn(batch.proof_context, (self.root / "state.sqlite").read_bytes())
        with self.assertRaisesRegex(VerificationQueueError, "session_ref"):
            queue._profile12_context(session_ref=bytes(64), ordered_batch_root=batch.batch_root, public_coin=batch.public_coin, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms)
        with self.assertRaisesRegex(VerificationQueueError, "batch_root"):
            queue._profile12_context(session_ref=batch.session_ref, ordered_batch_root=bytes(64), public_coin=batch.public_coin, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms)

    def test_public_coin_zero_retry_and_malformed_sample_fail_closed(self) -> None:
        nonzero = bytes([7]) * 96
        with patch.object(queue.secrets, "token_bytes", side_effect=[bytes(96), nonzero]) as sampler:
            self.assertEqual(queue._sample_public_coin(), nonzero)
        self.assertEqual(sampler.call_count, 2)
        with patch.object(queue.secrets, "token_bytes", return_value=b"wrong") as sampler:
            with self.assertRaisesRegex(VerificationQueueError, "queue_randomness"):
                queue._sample_public_coin()
        self.assertEqual(sampler.call_count, 1)
        with patch.object(queue.secrets, "token_bytes", return_value=bytes(96)) as sampler:
            with self.assertRaisesRegex(VerificationQueueError, "queue_randomness"):
                queue._sample_public_coin()
        self.assertEqual(sampler.call_count, 4)

    def test_issue_reserves_once_before_return_and_claim_does_not_charge_again(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 0))
            self.assertEqual(connection.execute("SELECT reservation_before,reservation_after,status FROM queue_attempts").fetchone(), (0, 101, "RESERVED"))
            event = connection.execute("SELECT event_bytes FROM queue_transitions WHERE sequence=1").fetchone()[0]
            self.assertIn(b'"reservation_after":101', bytes(event))
        handoff = VolatileProofHandoff(bytearray(b"proof"))
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=handoff)
        work = self.store._claim_next_batch()
        self.assertIsNotNone(work)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 1))
            self.assertEqual(connection.execute("SELECT transition_kind FROM queue_transitions ORDER BY sequence").fetchall(), [("BATCH_ISSUED",), ("HANDOFF_SUBMITTED",), ("VERIFICATION_STARTED",)])
        verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)

    def test_issue_commit_boundaries_preserve_rollback_and_burn_postcommit_reservation(self) -> None:
        def fail_before(label: str) -> None:
            if label == "before_issue_commit":
                raise RuntimeError("issue precommit")

        self.store._before_fault = fail_before
        with self.assertRaisesRegex(RuntimeError, "issue precommit"):
            self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_batches").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_attempts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 0)

        self.store._before_fault = None
        self.store._after_commit_fault = lambda label: (_ for _ in ()).throw(RuntimeError("issue postcommit")) if label == "after_issue_commit" else None
        with self.assertRaisesRegex(RuntimeError, "issue postcommit"):
            self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "AWAITING_HANDOFF")
            self.assertEqual(connection.execute("SELECT status FROM queue_attempts").fetchone()[0], "RESERVED")
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 101)
        verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)

    def test_claim_rejects_public_coin_and_attempt_epoch_tampering_before_lease(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
        triggers = dict(queue._TRIGGER_DEFS)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("DROP TRIGGER queue_batches_identity_guard")
            connection.execute("UPDATE queue_batches SET public_coin=? WHERE batch_id=?", (bytes(96), batch.batch_id))
            connection.execute(triggers["queue_batches_identity_guard"])
            connection.commit()
        self.assertIsNone(self.store._claim_next_batch())
        self.assertEqual(self.store._last_claim_error, "queue_integrity_failed")
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("DROP TRIGGER queue_batches_identity_guard")
            connection.execute("UPDATE queue_batches SET public_coin=? WHERE batch_id=?", (batch.public_coin, batch.batch_id))
            connection.execute(triggers["queue_batches_identity_guard"])
            connection.execute("DROP TRIGGER queue_attempts_transition_guard")
            connection.execute("UPDATE queue_attempts SET source_key_epoch=? WHERE batch_id=?", ((2).to_bytes(8, "big"), batch.batch_id))
            connection.execute(triggers["queue_attempts_transition_guard"])
            connection.commit()
        self.assertIsNone(self.store._claim_next_batch())
        self.assertEqual(self.store._last_claim_error, "queue_integrity_failed")
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "QUEUED")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)

    def test_lifetime_exhaustion_is_checked_before_rng(self) -> None:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_metadata SET proof_attempts_used=? WHERE id=1", (PROOF_ATTEMPTS_CAP - 100,))
            connection.commit()
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("rng must not run")) as sampler:
            with self.assertRaisesRegex(QueueBackpressureError, "computational_budget_exhausted"):
                self.store.issue_batch(template=self._template())
        self.assertEqual(sampler.call_count, 0)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], PROOF_ATTEMPTS_CAP - 100)

    def test_independent_lifecycle_binds_issue_and_start_reservation(self) -> None:
        def event(kind: str, status: str, attempt: int, **extra: object) -> dict[str, object]:
            return {"kind": kind, "status": status, "attempt": attempt, "error_code": None, "member_count": 100, **extra}

        events = [
            event("BATCH_ISSUED", "AWAITING_HANDOFF", 0, identity_digest="00" * 64, reservation_before=0, reservation_after=101),
            event("HANDOFF_SUBMITTED", "QUEUED", 0),
            event("VERIFICATION_STARTED", "LEASED", 1, reservation_before=0, reservation_after=101),
        ]
        _verify_lifecycle(events, "LEASED", 1, reservation_before=0, reservation_after=101)
        events[2]["reservation_after"] = 202
        with self.assertRaisesRegex(IndependentQueueError, "lifecycle_verification_started"):
            _verify_lifecycle(events, "LEASED", 1, reservation_before=0, reservation_after=101)

    def test_capacity_rejection_happens_before_any_rng(self) -> None:
        self.store.issue_batch(template=self._template())
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("rng must not run")) as sampler:
            with self.assertRaisesRegex(QueueBackpressureError, "queue_capacity"):
                self.store.issue_batch(template=self._template())
        self.assertEqual(sampler.call_count, 0)

    def test_hold_at_issue_burns_reservation_without_refund(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.store._hold_batch_locked(connection, batch_id=batch.batch_id, now=self.clock.now_ms(), code="fresh_handoff_required")
            connection.commit()
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT status FROM queue_attempts").fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 101)
        verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)


if __name__ == "__main__":
    unittest.main()
