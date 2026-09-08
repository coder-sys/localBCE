import sqlite3
import tempfile
import unittest
from contextlib import closing
import json
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
from app.minimal_clearance_verification_queue_independent import (
    read_verified_batch,
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)
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

    def test_overstated_lifetime_counter_is_rejected_before_rng(self) -> None:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_metadata SET proof_attempts_used=? WHERE id=1", (PROOF_ATTEMPTS_CAP - 100,))
            connection.commit()
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("rng must not run")) as sampler:
            with self.assertRaisesRegex(VerificationQueueError, "queue_integrity_failed"):
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

    def test_read_only_version_gate_and_restore_preserve_invalid_source_and_destination(self) -> None:
        old_path = self.root / "old.sqlite"
        old_path.write_bytes((self.root / "state.sqlite").read_bytes())
        with closing(sqlite3.connect(str(old_path))) as connection:
            connection.execute("DROP TRIGGER queue_metadata_config_guard")
            connection.execute("UPDATE queue_metadata SET schema_version=11 WHERE id=1")
            connection.commit()
        source_bytes = old_path.read_bytes()
        with self.assertRaisesRegex(Exception, "queue_schema_unsupported"):
            verify_database(old_path)
        self.assertEqual(old_path.read_bytes(), source_bytes)
        destination = self.root / "restored-old.sqlite"
        with self.assertRaisesRegex(Exception, "queue_schema_unsupported"):
            restore_export_to_fresh_database(export_bytes=source_bytes, destination=destination)
        self.assertFalse(destination.exists())

    def test_valid_restore_prevalidates_then_creates_exclusive_destination(self) -> None:
        source_bytes = (self.root / "state.sqlite").read_bytes()
        destination = self.root / "restored.sqlite"
        result = restore_export_to_fresh_database(export_bytes=source_bytes, destination=destination, expected_config=self.config.as_json)
        self.assertFalse(result["production_usable"])
        self.assertEqual(destination.read_bytes(), source_bytes)
        self.assertEqual((self.root / "state.sqlite").read_bytes(), source_bytes)

    def test_exact_counter_tamper_blocks_issue_and_claim_before_rng(self) -> None:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_metadata SET proof_attempts_used=101.5 WHERE id=1")
            connection.commit()
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("issue RNG must not run")) as sampler:
            with self.assertRaisesRegex(VerificationQueueError, "queue_integrity_failed"):
                self.store.issue_batch(template=self._template())
        self.assertEqual(sampler.call_count, 0)

        self.store._close()
        self.owner.close()
        self.temp.cleanup()

        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config = QueueConfig("profile12-focused", 100)
        self.composition_config = CompositionConfigV2(self.config.queue_id, self.config.digest, capacity=100)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.root / "state.sqlite", config=self.config, owner=self.owner, clock=self.clock, composition_config=self.composition_config)
        batch = self.store.issue_batch(template=self._template())
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_metadata SET next_transition_seq=1.5 WHERE id=1")
            connection.commit()
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("lease RNG must not run")) as sampler:
            self.assertIsNone(self.store._claim_next_batch())
        self.assertEqual(sampler.call_count, 0)
        self.assertEqual(self.store._last_claim_error, "queue_integrity_failed")

    def test_receipt_flags_and_orphan_results_are_closed(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.store._hold_batch_locked(connection, batch_id=batch.batch_id, now=self.clock.now_ms(), code="fresh_handoff_required")
            connection.commit()
            raw = connection.execute("SELECT receipt_bytes FROM queue_results WHERE batch_id=?", (batch.batch_id,)).fetchone()[0]
            value = json.loads(bytes(raw).decode("ascii"))
            value["qualification_flags"] = ["unexpected"]
            bad_receipt = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            connection.execute("DROP TRIGGER queue_results_no_update")
            connection.execute("UPDATE queue_results SET receipt_bytes=? WHERE batch_id=?", (bad_receipt, batch.batch_id))
            connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_update"])
            connection.commit()
        for verifier in (
            lambda: verify_database(self.root / "state.sqlite"),
            lambda: read_verified_batch(self.root / "state.sqlite"),
            lambda: verify_export_bytes((self.root / "state.sqlite").read_bytes()),
        ):
            with self.assertRaisesRegex(Exception, "receipt_flags"):
                verifier()
        invalid_destination = self.root / "invalid-receipt-restore.sqlite"
        with self.assertRaisesRegex(Exception, "receipt_flags"):
            restore_export_to_fresh_database(export_bytes=(self.root / "state.sqlite").read_bytes(), destination=invalid_destination)
        self.assertFalse(invalid_destination.exists())

        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("DROP TRIGGER queue_results_no_update")
            connection.execute("UPDATE queue_results SET receipt_bytes=? WHERE batch_id=?", (raw, batch.batch_id))
            connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_update"])
            connection.commit()
        orphan_path = self.root / "orphan.sqlite"
        orphan_path.write_bytes((self.root / "state.sqlite").read_bytes())
        with closing(sqlite3.connect(str(orphan_path))) as connection:
            connection.execute("INSERT INTO queue_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (bytes([9]) * 32, "HELD", bytes([8]) * 32, b"arbitrary", 0, 0, bytes([7]) * 64, self.config.source_auth_profile, (1).to_bytes(8, "big"), "fresh_handoff_required", b'{"qualification_flags":[]}', self.clock.now_ms(), 0, "fresh_handoff_required"))
            connection.commit()
        with self.assertRaisesRegex(Exception, "result_orphan"):
            verify_database(orphan_path)

    def test_missing_attempt_and_config_drift_block_issue_and_claim_before_rng(self) -> None:
        def fresh() -> tuple[tempfile.TemporaryDirectory[str], Path, _Clock, QueueConfig, _QueueRuntimeOwnership, _VerificationQueueStore]:
            temp = tempfile.TemporaryDirectory()
            root = Path(temp.name)
            clock = _Clock()
            config = QueueConfig("profile12-focused", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
            owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
            store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=clock, composition_config=composition_config)
            return temp, root, clock, config, owner, store

        for mutation in ("missing_attempt", "config_drift"):
            temp, root, clock, config, owner, store = fresh()
            try:
                batch = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                if mutation == "missing_attempt":
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        connection.execute("DROP TRIGGER queue_attempts_no_delete")
                        connection.execute("DELETE FROM queue_attempts WHERE batch_id=?", (batch.batch_id,))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_no_delete"])
                        connection.commit()
                else:
                    drifted = QueueConfig("profile12-drifted", 100).canonical_bytes
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        connection.execute("DROP TRIGGER queue_metadata_config_guard")
                        connection.execute("UPDATE queue_metadata SET config_json=? WHERE id=1", (drifted,))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_metadata_config_guard"])
                        connection.commit()
                with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("request RNG must not run")) as sampler:
                    with self.assertRaisesRegex(VerificationQueueError, "queue_integrity_failed"):
                        store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                self.assertEqual(sampler.call_count, 0)
            finally:
                store._close()
                owner.close()
                temp.cleanup()

        temp, root, clock, config, owner, store = fresh()
        try:
            batch = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
            store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                connection.execute("DROP TRIGGER queue_attempts_no_delete")
                connection.execute("DELETE FROM queue_attempts WHERE batch_id=?", (batch.batch_id,))
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_no_delete"])
                connection.commit()
            with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("lease RNG must not run")) as sampler:
                self.assertIsNone(store._claim_next_batch())
            self.assertEqual(sampler.call_count, 0)
            self.assertEqual(store._last_claim_error, "queue_integrity_failed")
        finally:
            store._close()
            owner.close()
            temp.cleanup()

    def test_independent_rejects_lease_timestamp_and_sequence_tamper(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
        self.assertIsNotNone(self.store._claim_next_batch())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_leases SET claim_sequence=claim_sequence+1 WHERE batch_id=?", (batch.batch_id,))
            connection.commit()
        with self.assertRaisesRegex(Exception, "lease_binding"):
            verify_database(self.root / "state.sqlite")


if __name__ == "__main__":
    unittest.main()
