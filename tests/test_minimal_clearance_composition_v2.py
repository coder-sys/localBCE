import io
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

import app.minimal_clearance_composition as composition
from app.minimal_clearance_composition import (
    ClearanceCompositionStoreV2,
    CompositionConfigV2,
    CompositionIntegrityError,
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
from app.minimal_clearance_verification_queue_independent import read_verified_batch


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


class _Verifier:
    def __init__(self, config: QueueConfig) -> None:
        self.config = config
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, batch):
        self.calls += 1
        while stream.read(31):
            pass
        return BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", self.config.qualification_flags)


class _Receiver:
    def __init__(self, config: CompositionConfigV2, clock: _Clock) -> None:
        self.config = config
        self.clock = clock
        self.calls = 0

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.calls += 1
        return build_synthetic_acknowledgment(envelope_bytes, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.clock.now_ms())


class CompositionV8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.clock = _Clock()
        self.queue_path = self.root / "queue.sqlite"
        self.queue_config = QueueConfig("queue-v8", 512)
        self.queue_owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        self.queue = _VerificationQueueStore(path=self.queue_path, config=self.queue_config, owner=self.queue_owner, clock=self.clock)
        self.composition_path = self.root / "composition.sqlite"
        self.composition_config = CompositionConfigV2("queue-v8", self.queue_config.digest, capacity=200)
        self.composition_store = ClearanceCompositionStoreV2(path=self.composition_path, config=self.composition_config, clock=self.clock)

    def tearDown(self) -> None:
        self.composition_store.close()
        self.queue._close()
        self.queue_owner.close()
        self._temp.cleanup()

    def _verified_batch(self, offset: int = 0):
        template = OperationTemplate(f"assertion-{offset}", 1, "state-profile-v8", self.clock.now - 100, self.clock.now + 3_000_000)
        refs = tuple((offset + index + 1).to_bytes(32, "big") for index in range(100))
        batch = self.queue.issue_batch(template=template, operation_refs=refs)
        self.queue.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"volatile-proof"), declared_length=14)
        self.assertEqual(self.queue._process_one_batch(verifier=_Verifier(self.queue_config)).status, "VERIFIED")
        return read_verified_batch(self.queue_path, batch.batch_id)

    def _controls(self, batch, *, sequence_before: int = 0, predecessor: StateDispositionControl | None = None):
        controls = {}
        profile = bytes([9]) * 64
        state_id = bytes(64)
        state_bytes = bytes(64)
        continuity = bytes(64)
        audit = bytes(64)
        clearance = bytes(64)
        marker = 0
        count = 0
        for index, job in enumerate(batch.jobs):
            policy = ("PASS", "MISSING", "AMBIGUOUS", "FAIL", "FAIL")[index % 5]
            exception = policy == "FAIL" and index % 5 == 4
            control = StateDispositionControl(
                job.operation_ref,
                policy,
                exception,
                bytes([index + 1]) * 64 if exception else bytes(64),
                profile,
                state_id,
                state_bytes,
                1,
                sequence_before + index,
                continuity,
                audit,
                clearance,
                marker,
                count,
            )
            controls[job.operation_ref] = control
            state_id = control.state_after_id
            state_bytes = control.state_after_bytes
            continuity = control.state_after_continuity_root
            clearance = control.state_after_clearance_root
            audit = composition._sha(composition._STATE, audit, control.decision_id, control.effective_directive.encode("ascii"))
            marker = int(bool(marker or control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"}))
            count += int(control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"})
        return controls

    def test_state_disposition_has_exact_five_directives_and_proof_is_non_dispositive(self) -> None:
        self.assertEqual(tuple(resolve_effective_directive(policy, exception) for policy, exception in (("PASS", False), ("MISSING", False), ("AMBIGUOUS", False), ("FAIL", False), ("FAIL", True))), ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"))
        batch = self._verified_batch()
        controls = self._controls(batch)
        result = self.composition_store.process_verified_jobs(self.queue_path, batch, state_controls=controls)
        self.assertEqual(len(result), 100)
        self.assertTrue(all(item.status == "APPLIED" and item.operation_id == item.outbox_operation_id for item in result))
        with closing(sqlite3.connect(str(self.composition_path))) as connection:
            directives = {row[0] for row in connection.execute("SELECT DISTINCT effective_directive FROM composition_transactions")}
            proof_values = {row[0] for row in connection.execute("SELECT DISTINCT proof_accepted FROM composition_transactions")}
            outbox_count = connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0]
        self.assertEqual(directives, {"CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"})
        self.assertEqual(proof_values, {1})
        self.assertEqual(outbox_count, 100)
        self.assertEqual(self.composition_store.snapshot()["state_sequence"], 100)
        self.composition_store.verify_integrity()

    def test_outbox_ack_is_idempotent_and_receives_only_state_directive(self) -> None:
        batch = self._verified_batch()
        controls = self._controls(batch)
        self.composition_store.process_verified_jobs(self.queue_path, batch, state_controls=controls)
        receiver = _Receiver(self.composition_config, self.clock)
        acknowledged = 0
        while True:
            work = self.composition_store.claim_next_outbox("receiver")
            if work is None:
                break
            delivery = self.composition_store.dispatch(work, receiver=receiver)
            self.assertEqual(delivery.status, "ACKNOWLEDGED")
            acknowledged += 1
            self.assertNotIn(b"volatile-proof", work.envelope_bytes)
            self.assertNotIn(b"batch_root", work.envelope_bytes)
        self.assertEqual((acknowledged, receiver.calls), (100, 100))
        snapshot = self.composition_store.snapshot()
        self.assertEqual(snapshot["outbox_counts"]["ACKNOWLEDGED"], 100)
        self.composition_store.verify_integrity()

    def test_bad_state_control_rolls_back_all_members_transactions_events_and_outbox(self) -> None:
        first = self._verified_batch()
        self.composition_store.process_verified_jobs(self.queue_path, first, state_controls=self._controls(first))
        second = self._verified_batch(offset=200)
        before = self.composition_store.snapshot()
        bad = self._controls(second, sequence_before=0)
        with self.assertRaises(CompositionIntegrityError):
            self.composition_store.process_verified_jobs(self.queue_path, second, state_controls=bad)
        self.assertEqual(self.composition_store.snapshot(), before)
        with closing(sqlite3.connect(str(self.composition_path))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 100)
        self.composition_store.verify_integrity()

    def test_queue_authority_mismatch_fails_before_composition_transaction(self) -> None:
        batch = self._verified_batch()
        before = self.composition_store.snapshot()
        wrong = CompositionConfigV2("attacker-queue", bytes([8]) * 64, capacity=200)
        wrong_store = ClearanceCompositionStoreV2(path=self.root / "wrong-composition.sqlite", config=wrong, clock=self.clock)
        try:
            with self.assertRaises(CompositionIntegrityError) as raised:
                wrong_store.process_verified_jobs(self.queue_path, batch)
            self.assertEqual(str(raised.exception), "queue_authority_binding")
            self.assertEqual(wrong_store.snapshot()["transaction_counts"], {"APPLIED": 0, "HELD": 0})
        finally:
            wrong_store.close()
        self.assertEqual(self.composition_store.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
