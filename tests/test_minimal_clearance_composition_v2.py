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
from app.minimal_clearance_verification_queue import BatchVerifierResult, OperationTemplate, QueueConfig, VolatileProofHandoff, _QueueRuntimeOwnership, _VerificationQueueStore
from app.minimal_clearance_verification_queue_independent import verify_database
from app.minimal_clearance_composition_independent import verify_database as verify_composition_database, verify_database_connection


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


def _controls(operation_refs: tuple[bytes, ...]) -> dict[bytes, StateDispositionControl]:
    policies = ("PASS", "MISSING", "AMBIGUOUS", "FAIL", "FAIL") * 20
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
        control = StateDispositionControl(operation_ref, policy, exception, bytes([index + 1]) * 64 if exception else bytes(64), profile, state_id, state_bytes, 1, index, continuity, audit, clearance, marker, count)
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
    def __init__(self, config: QueueConfig) -> None:
        self.config = config

    def verify(self, stream: VolatileProofHandoff, batch):
        while stream.read(17):
            pass
        return BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", ())


class _Port:
    def __init__(self) -> None:
        self.calls = 0

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome):
        self.calls += 1
        return _controls(operation_refs)


class _Receiver:
    def __init__(self, config: CompositionConfigV2, clock: _Clock) -> None:
        self.config = config
        self.clock = clock
        self.calls = 0

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.calls += 1
        return build_synthetic_acknowledgment(envelope_bytes, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.clock.now_ms())


class CompositionV10Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.queue_config = QueueConfig("composition-state-v10", 100)
        self.composition_config = CompositionConfigV2(self.queue_config.queue_id, self.queue_config.digest, capacity=100)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root)
        self.queue = _VerificationQueueStore(path=self.root / "state.sqlite", config=self.queue_config, owner=self.owner, clock=self.clock, composition_config=self.composition_config)
        self.composition_store: ClearanceCompositionStoreV2 | None = None

    def tearDown(self) -> None:
        if self.composition_store is not None:
            self.composition_store.close()
        self.queue._close()
        self.owner.close()
        self.temp.cleanup()

    def _accepted(self):
        template = OperationTemplate("composition-assertion", 1, self.queue_config.profile_version, self.clock.now - 100, self.clock.now + 60_000)
        batch = self.queue.issue_batch(template=template)
        self.queue.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"volatile-proof"), declared_length=14)
        result = self.queue._process_one_batch(verifier=_Verifier(self.queue_config), state_disposition_port=_Port())
        self.assertEqual((result.status, result.accepted_count), ("VERIFIED", 100))
        return batch

    def _store(self) -> ClearanceCompositionStoreV2:
        self.composition_store = ClearanceCompositionStoreV2(path=self.root / "state.sqlite", config=self.composition_config, clock=self.clock)
        return self.composition_store

    def test_composition_store_accepts_only_the_unified_state_database(self) -> None:
        old = self.root / "composition.sqlite"
        old.write_bytes(b"old composition bytes")
        with self.assertRaises(CompositionIntegrityError):
            ClearanceCompositionStoreV2(path=old, config=self.composition_config, clock=self.clock)
        self.assertEqual(old.read_bytes(), b"old composition bytes")
        self.assertIsNotNone(self._store())
        self.assertFalse(hasattr(ClearanceCompositionStoreV2, "process_verified_jobs"))

    def test_independent_queue_and_composition_verifiers_accept_one_state_file(self) -> None:
        self._accepted()
        queue_summary = verify_database(self.root / "state.sqlite")
        composition_summary = verify_composition_database(self.root / "state.sqlite", expected_config=self.composition_config.as_json)
        self.assertEqual((queue_summary["accepted_operation_count"], composition_summary["outbox_count"], composition_summary["state_sequence"]), (100, 100, 100))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(verify_database_connection(connection, expected_config=self.composition_config.as_json)["outbox_count"], 100)

    def test_policy_results_and_effective_directives_are_separate_and_exhaustive(self) -> None:
        batch = self._accepted()
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
        self.assertEqual(self.queue._read_projection()["verified_batch_count"], 1)

    def test_delivery_acknowledgment_is_state_owned_and_idempotent(self) -> None:
        self._accepted()
        store = self._store()
        receiver = _Receiver(self.composition_config, self.clock)
        acknowledged = 0
        while True:
            work = store.claim_next_outbox("receiver")
            if work is None:
                break
            self.assertNotIn(b"volatile-proof", work.envelope_bytes)
            self.assertNotIn(b"proof_statement", work.envelope_bytes)
            delivery = store.dispatch(work, receiver=receiver)
            self.assertEqual(delivery.status, "ACKNOWLEDGED")
            acknowledged += 1
        self.assertEqual((acknowledged, receiver.calls), (100, 100))
        snapshot = store.snapshot()
        self.assertEqual(snapshot["outbox_counts"]["ACKNOWLEDGED"], 100)
        store.verify_integrity()

    def test_split_or_partial_schema_is_rejected_by_both_independent_verifiers(self) -> None:
        split = self.root / "queue.sqlite"
        with closing(sqlite3.connect(str(split))) as connection:
            connection.execute("CREATE TABLE queue_only(value TEXT)")
            connection.commit()
        with self.assertRaises(Exception):
            verify_database(split)
        with self.assertRaises(Exception):
            verify_composition_database(split)


if __name__ == "__main__":
    unittest.main()
