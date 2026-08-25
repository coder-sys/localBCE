from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest

import app.minimal_clearance_composition as composition_module
from app.minimal_clearance_composition import (
    ClearanceCompositionStoreV2,
    CompositionConflictError,
    CompositionConfigV2,
    CompositionLeaseError,
    CompositionIntegrityError,
    StateDispositionControl,
    build_synthetic_acknowledgment,
    resolve_effective_directive,
)
from app.minimal_clearance_composition_independent import (
    IndependentCompositionError,
    verify_database,
)
from app.minimal_clearance_verification_queue import (
    OperationStatement,
    QueueConfig,
    VerifierResult,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)
from app.minimal_clearance_verification_queue_independent import read_verified_batch, verify_database as verify_queue


class _Verifier:
    def verify(self, stream, statement, operation_ref):
        stream.read()
        stream.read()
        return VerifierResult(True, operation_ref, statement.assertion_identifier, statement.assertion_version, statement.state_profile_version, statement.valid_from_ms, statement.valid_until_ms, statement.batch_position, statement.batch_root, "synthetic-v7-unqualified", "ok", qualification_flags=statement.qualification_flags)


class _Receiver:
    def __init__(self, config: CompositionConfigV2) -> None:
        self.config = config
        self.calls = 0

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.calls += 1
        return build_synthetic_acknowledgment(envelope_bytes, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.calls)


class _InvalidReceiver:
    def dispatch(self, _envelope_bytes: bytes, _idempotency_key: bytes) -> bytes:
        return b"not-a-validated-ack"


class _Lookup:
    def __init__(self, config: CompositionConfigV2) -> None:
        self.config = config

    def lookup_acknowledgment(self, **query):
        operation_ref = query["operation_ref"]
        envelope = composition_module._envelope(operation_ref, "CLEAR", self.config)
        return build_synthetic_acknowledgment(envelope, config=self.config, idempotency_key=query["idempotency_key"], accepted_ms=99)


class _Clock:
    def __init__(self, value: int = 0) -> None:
        self.value = value

    def now_ms(self) -> int:
        return self.value


class CompositionV7Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-composition-v7-")
        self.root = Path(self.temp.name)
        self.queue_config = QueueConfig("queue-v7-composition", 8)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        self.queue = _VerificationQueueStore(path=self.root / "queue.sqlite", config=self.queue_config, owner=self.owner)
        self.composition_config = CompositionConfigV2(queue_id=self.queue_config.queue_id, queue_config_digest=self.queue_config.digest)

    def tearDown(self) -> None:
        self.queue._close()
        self.owner.close()
        self.temp.cleanup()

    def _admit_verified(self, count: int = 2):
        root = b"r" * 64
        statements = tuple(OperationStatement(f"assertion-{index}", 1, "state-profile-v7", 0, 100_000, index, root, None, ()) for index in range(count))
        jobs = self.queue.admit_batch(statements=statements, proof_streams=tuple(io.BytesIO(f"proof-{index}".encode("ascii")) for index in range(count)))
        verifier = _Verifier()
        for _ in jobs:
            self.assertEqual(self.queue._process_one(verifier=verifier).status, "VERIFIED")
        return jobs, read_verified_batch(self.queue.path)

    def _controls(self, jobs):
        profile = b"p" * 64
        first = StateDispositionControl(jobs[0].operation_ref, "PASS", state_profile_identity=profile, decision_id=b"1" * 64)
        audit_after_first = composition_module._sha(composition_module._STATE, b"\x00" * 64, first.decision_id, b"CLEAR")
        second = StateDispositionControl(jobs[1].operation_ref, "MISSING", state_profile_identity=profile, predecessor_state_id=first.state_after_id, predecessor_state_bytes=first.state_after_bytes, sequence_before=1, predecessor_continuity_root=first.state_after_continuity_root, predecessor_audit_head=audit_after_first, predecessor_clearance_root=first.state_after_clearance_root, clearance_marker_before=1, clearance_count_before=1, decision_id=b"2" * 64)
        return {jobs[0].operation_ref: first, jobs[1].operation_ref: second}

    def _store(self, *, before_fault=None) -> ClearanceCompositionStoreV2:
        return ClearanceCompositionStoreV2(path=self.root / "composition.sqlite", config=self.composition_config, before_fault=before_fault)

    def test_positive_two_member_ordered_chain_applies_and_reconstructs(self) -> None:
        jobs, batch = self._admit_verified(2)
        store = self._store()
        controls = self._controls(jobs)
        results = store.process_verified_jobs(self.queue.path, batch, state_controls=controls)
        self.assertEqual([result.status for result in results], ["APPLIED", "APPLIED"])
        self.assertEqual([result.duplicate_convergence for result in results], [False, False])
        self.assertEqual(store.snapshot()["state_sequence"], 2)
        self.assertEqual(verify_database(store.path, expected_config=self.composition_config.as_json)["transaction_counts"], {"APPLIED": 2, "HELD": 0})
        retry = store.process_verified_jobs(self.queue.path, batch, state_controls=controls)
        self.assertTrue(all(result.duplicate_convergence for result in retry))
        store.verify_integrity()
        store.close()

    def test_three_member_chain_advances_clearance_root_from_prior_root(self) -> None:
        jobs, batch = self._admit_verified(3)
        store = self._store()
        first, second = self._controls(jobs)[jobs[0].operation_ref], self._controls(jobs)[jobs[1].operation_ref]
        audit_after_second = composition_module._sha(composition_module._STATE, composition_module._sha(composition_module._STATE, b"\x00" * 64, first.decision_id, b"CLEAR"), second.decision_id, b"HOLD")
        third = StateDispositionControl(jobs[2].operation_ref, "PASS", state_profile_identity=first.state_profile_identity, predecessor_state_id=second.state_after_id, predecessor_state_bytes=second.state_after_bytes, sequence_before=2, predecessor_continuity_root=second.state_after_continuity_root, predecessor_audit_head=audit_after_second, predecessor_clearance_root=second.state_after_clearance_root, clearance_marker_before=1, clearance_count_before=1, decision_id=b"3" * 64)
        controls = {jobs[0].operation_ref: first, jobs[1].operation_ref: second, jobs[2].operation_ref: third}
        results = store.process_verified_jobs(self.queue.path, batch, state_controls=controls)
        self.assertEqual([result.status for result in results], ["APPLIED", "APPLIED", "APPLIED"])
        self.assertEqual(store.snapshot()["state_sequence"], 3)
        self.assertEqual(verify_database(store.path, expected_config=self.composition_config.as_json)["transaction_counts"], {"APPLIED": 3, "HELD": 0})
        store.close()

    def test_duplicate_retry_with_different_state_control_is_a_conflict(self) -> None:
        jobs, batch = self._admit_verified(1)
        store = self._store()
        control = StateDispositionControl(jobs[0].operation_ref, "PASS", state_profile_identity=b"p" * 64)
        store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: control})
        changed = StateDispositionControl(jobs[0].operation_ref, "MISSING", state_profile_identity=b"p" * 64)
        with self.assertRaises(CompositionConflictError) as raised:
            store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: changed})
        self.assertEqual(str(raised.exception), "composition_conflicting_retry")
        store.verify_integrity()
        store.close()

    def test_outbox_lease_expiry_requeues_without_proof_reuse(self) -> None:
        clock = _Clock()
        config = CompositionConfigV2(queue_id=self.queue_config.queue_id, queue_config_digest=self.queue_config.digest, lease_seconds=1)
        store = ClearanceCompositionStoreV2(path=self.root / "lease-composition.sqlite", config=config, clock=clock)
        jobs, batch = self._admit_verified(1)
        control = StateDispositionControl(jobs[0].operation_ref, "PASS", state_profile_identity=b"p" * 64)
        store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: control})
        first = store.claim_next_outbox("state-dispatcher")
        clock.value = 1_001
        second = store.claim_next_outbox("state-dispatcher-2")
        self.assertEqual(first.attempt, 1)
        self.assertEqual(second.attempt, 2)
        store.close()

    def test_composition_config_identity_and_delivery_settings_are_bound(self) -> None:
        jobs, batch = self._admit_verified(1)
        store = self._store()
        control = StateDispositionControl(jobs[0].operation_ref, "PASS", state_profile_identity=b"p" * 64)
        store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: control})
        alternate = CompositionConfigV2(queue_id=self.queue_config.queue_id, queue_config_digest=self.queue_config.digest, receiver_identity=b"r" * 32)
        with self.assertRaises(CompositionIntegrityError) as raised:
            ClearanceCompositionStoreV2(path=store.path, config=alternate)
        self.assertEqual(str(raised.exception), "composition_schema")
        store.close()

    def test_invalid_second_predecessor_fails_before_any_composition_mutation(self) -> None:
        jobs, batch = self._admit_verified(2)
        store = self._store()
        controls = self._controls(jobs)
        bad = controls[jobs[1].operation_ref]
        controls[jobs[1].operation_ref] = StateDispositionControl(jobs[1].operation_ref, "MISSING", state_profile_identity=bad.state_profile_identity, predecessor_state_id=b"x" * 64, predecessor_state_bytes=bad.predecessor_state_bytes, sequence_before=1, predecessor_audit_head=bad.predecessor_audit_head, clearance_marker_before=1, clearance_count_before=1, decision_id=bad.decision_id)
        before_bytes = store.path.read_bytes()
        before_snapshot = store.snapshot()
        with self.assertRaises(CompositionIntegrityError) as raised:
            store.process_verified_jobs(self.queue.path, batch, state_controls=controls)
        self.assertEqual(str(raised.exception), "composition_batch_state_chain")
        self.assertEqual(store.path.read_bytes(), before_bytes)
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(verify_database(store.path, expected_config=self.composition_config.as_json)["transaction_counts"], {"APPLIED": 0, "HELD": 0})
        store.close()

    def test_state_owner_maps_four_policy_results_and_proof_cannot_supply_clear(self) -> None:
        expected = {"PASS": "CLEAR", "MISSING": "HOLD", "AMBIGUOUS": "HUMAN_REVIEW", "FAIL": "BLOCK"}
        for policy, directive in expected.items():
            self.assertEqual(resolve_effective_directive(policy), directive)
        self.assertEqual(resolve_effective_directive("FAIL", True), "EXCEPTION_APPROVED")
        self.assertEqual(resolve_effective_directive("FAIL", False), "BLOCK")
        jobs, batch = self._admit_verified(1)
        store = self._store()
        control = StateDispositionControl(jobs[0].operation_ref, "MISSING", state_profile_identity=b"p" * 64)
        result = store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: control})[0]
        self.assertEqual(result.status, "APPLIED")
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT policy_result,effective_directive,proof_accepted FROM composition_transactions").fetchone(), ("MISSING", "HOLD", 1))
        store.close()

    def test_state_exception_authorization_is_required_for_exception_approved(self) -> None:
        jobs, batch = self._admit_verified(1)
        store = self._store()
        control = StateDispositionControl(jobs[0].operation_ref, "FAIL", exception_approved=True, exception_authorization_id=b"e" * 64, state_profile_identity=b"p" * 64)
        result = store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: control})[0]
        self.assertEqual(result.status, "APPLIED")
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT policy_result,effective_directive FROM composition_transactions").fetchone(), ("FAIL", "EXCEPTION_APPROVED"))
        store.verify_integrity()
        store.close()

    def test_injected_fault_rolls_back_all_rows_events_state_and_outbox(self) -> None:
        jobs, batch = self._admit_verified(2)
        fired = []
        def fault(label: str) -> None:
            fired.append(label)
            raise RuntimeError("injected")
        store = self._store(before_fault=fault)
        before = store.snapshot()
        with self.assertRaises(CompositionIntegrityError) as raised:
            store.process_verified_jobs(self.queue.path, batch, state_controls=self._controls(jobs))
        self.assertEqual(str(raised.exception), "composition_transaction_rollback")
        self.assertEqual(fired, ["before_composition_commit"])
        self.assertEqual(store.snapshot(), before)
        store.verify_integrity()
        store.close()

    def test_outbox_contains_only_reference_and_state_directive(self) -> None:
        jobs, batch = self._admit_verified(1)
        store = self._store()
        control = StateDispositionControl(jobs[0].operation_ref, "PASS", state_profile_identity=b"p" * 64)
        store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: control})
        work = store.claim_next_outbox("state-dispatcher")
        self.assertEqual(work.effective_directive, "CLEAR")
        self.assertIn(jobs[0].operation_ref.hex().upper().encode("ascii"), work.envelope_bytes)
        self.assertNotIn(b"policy_result", work.envelope_bytes)
        receiver = _Receiver(self.composition_config)
        self.assertEqual(store.dispatch(work, receiver=receiver).status, "ACKNOWLEDGED")
        store.verify_integrity()
        store.close()

    def test_outbox_fences_work_validates_ack_and_reconciles_delivery_uncertainty(self) -> None:
        jobs, batch = self._admit_verified(1)
        store = self._store()
        control = StateDispositionControl(jobs[0].operation_ref, "PASS", state_profile_identity=b"p" * 64)
        store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: control})
        work = store.claim_next_outbox("state-dispatcher")
        with self.assertRaises(CompositionLeaseError) as raised:
            store.dispatch(replace(work, lease_token=b"x" * 32), receiver=_Receiver(self.composition_config))
        self.assertEqual(str(raised.exception), "outbox_lease_fence")
        uncertain = store.dispatch(work, receiver=_InvalidReceiver())
        self.assertEqual(uncertain.status, "DELIVERY_UNCONFIRMED")
        reconciled = store.reconcile_next("reconciler", lookup=_Lookup(self.composition_config))
        self.assertEqual(reconciled.status, "ACKNOWLEDGED")
        store.verify_integrity()
        store.close()

    def test_independent_reconstruction_rejects_outbox_directive_substitution(self) -> None:
        jobs, batch = self._admit_verified(1)
        store = self._store()
        control = StateDispositionControl(jobs[0].operation_ref, "PASS", state_profile_identity=b"p" * 64)
        store.process_verified_jobs(self.queue.path, batch, state_controls={jobs[0].operation_ref: control})
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("UPDATE composition_outbox SET effective_directive='BLOCK' WHERE operation_ref=?", (jobs[0].operation_ref,))
            connection.commit()
        with self.assertRaises(IndependentCompositionError) as raised:
            verify_database(store.path, expected_config=self.composition_config.as_json)
        self.assertEqual(str(raised.exception), "outbox_binding")
        store.close()

    def test_independent_reconstruction_rejects_persisted_mixed_applied_held_batch(self) -> None:
        jobs, batch = self._admit_verified(2)
        store = self._store()
        controls = self._controls(jobs)
        store.process_verified_jobs(self.queue.path, batch, state_controls=controls)
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("INSERT INTO composition_transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (b"h" * 64, b"h" * 32, "HELD", 0, "MISSING", "HOLD", b"d" * 64, b"p" * 64, b"b" * 64, b"a" * 64, 2, 3, None, None, "state_profile_mismatch", 1, 1))
            connection.commit()
        with self.assertRaises(IndependentCompositionError) as raised:
            verify_database(store.path, expected_config=self.composition_config.as_json)
        self.assertEqual(str(raised.exception), "mixed_semantic_batch")
        store.close()


if __name__ == "__main__":
    unittest.main()
