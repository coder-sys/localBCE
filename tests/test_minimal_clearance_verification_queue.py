import io
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path

from app.minimal_clearance_verification_queue import (
    ADMISSION_CAP_BYTES,
    BatchVerifierResult,
    QueueConfig,
    QueueConflictError,
    QueueHeldError,
    OperationTemplate,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
    _build_statement,
    _reserve_units,
)
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    read_verified_batch,
    verify_database,
)


class _Clock:
    def __init__(self, now: int) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


class _Verifier:
    def __init__(self, config: QueueConfig, *, proof_accepted: bool = True, source_authenticated: bool = True, mutate: str | None = None, unknown: bool = False) -> None:
        self.config = config
        self.proof_accepted = proof_accepted
        self.source_authenticated = source_authenticated
        self.mutate = mutate
        self.unknown = unknown
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, issued_batch):
        self.calls += 1
        while stream.read(17):
            pass
        statement = issued_batch.proof_statement
        root = issued_batch.batch_root
        if self.mutate == "statement":
            statement = bytes([statement[0] ^ 1]) + statement[1:]
        if self.mutate == "root":
            root = bytes([root[0] ^ 1]) + root[1:]
        source_profile = self.config.source_auth_profile
        source_epoch = self.config.source_key_epoch
        flags = self.config.qualification_flags
        if self.mutate == "source_profile":
            source_profile = "untrusted-source-auth"
        if self.mutate == "source_epoch":
            source_epoch += 1
        if self.mutate == "flags":
            flags = ("untrusted-flag",)
        if self.unknown:
            return {
                "proof_accepted": self.proof_accepted,
                "source_authenticated": self.source_authenticated,
                "proof_statement": statement,
                "batch_root": root,
                "source_auth_profile": source_profile,
                "source_key_epoch": source_epoch,
                "result_code": "accepted" if self.proof_accepted else "rejected",
                "qualification_flags": list(flags),
                "policyResult": "PASS",
            }
        return BatchVerifierResult(
            self.proof_accepted,
            self.source_authenticated,
            statement,
            root,
            source_profile,
            source_epoch,
            "accepted" if self.proof_accepted else "rejected",
            flags,
        )


class QueueV8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.path = self.root / "queue.sqlite"
        self.clock = _Clock(1_700_000_000_000)
        self.config = QueueConfig("queue-v8", 512)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.path, config=self.config, owner=self.owner, clock=self.clock)

    def tearDown(self) -> None:
        self.store._close()
        self.owner.close()
        self._temp.cleanup()

    def templates(self, *, offset: int = 0, registry: bytes | None = None) -> tuple[OperationTemplate, ...]:
        return tuple(OperationTemplate(f"assertion-{offset + index}", 1, "state-profile-v8", self.clock.now - 100, self.clock.now + 3_000_000, registry, ()) for index in range(100))

    def issue(self, *, offset: int = 0, registry: bytes | None = None):
        return self.store.issue_batch(templates=self.templates(offset=offset, registry=registry))

    def submit(self, batch, proof: bytes = b"synthetic-volatile-proof") -> None:
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(proof), declared_length=len(proof))

    def snapshot(self) -> bytes:
        return self.path.read_bytes()

    def test_exact_100_state_issuance_and_v3_statement(self) -> None:
        batch = self.issue()
        self.assertEqual(len(batch.statements), 100)
        self.assertEqual(len({item.operation_ref for item in batch.statements}), 100)
        self.assertEqual(batch.statements[0].batch_position, 0)
        self.assertEqual(batch.statements[-1].batch_position, 99)
        self.assertEqual(len(batch.batch_root), 64)
        self.assertEqual(batch.ordered_binding, batch.batch_root[:32])
        self.assertEqual(len(batch.proof_statement), 240)
        self.assertEqual(batch.proof_statement[:16], b"BL-R100-STMT-V1\x00")
        self.assertEqual(batch.proof_statement[16:18], b"\x01\x00")
        self.assertEqual(int.from_bytes(batch.proof_statement[18:20], "little"), 240)
        self.assertEqual(batch.proof_statement[52:84], batch.batch_root[:32])
        fixed_root = bytes(range(64))
        fixed_statement = _build_statement(
            batch_root=fixed_root,
            state_challenge=bytes(range(32)),
            valid_from_ms=1,
            valid_until_ms=2,
        )
        self.assertEqual(fixed_statement[52:84], bytes(range(32)))
        self.assertEqual(int.from_bytes(batch.proof_statement[84:88], "little"), 3)
        self.assertEqual(batch.proof_statement[112:176], bytes.fromhex("982cbb064e424c3734b09a4e8579338092fd3b71d7ae81f7a64174d9ba8919f6c1fcc3b7c0837d64dc1cec954194e1648f3375bfe7f08a8a9347aa320137efd4"))
        self.assertEqual(batch.proof_statement[176:240], bytes.fromhex("625af0b814643d81b5848bb3ee1f76935e5f05c8232d31c9f6b969e810e28c885897a5bab2a89ae3f4721208b64f9b99c677a8e8e90b481aec4fc3ddc9b921fe"))
        with self.assertRaises(TypeError):
            OperationTemplate("x", 1, "state", 1, 2, operation_ref=b"x")
        for name in ("issue_operation", "submit_handoff", "submit_batch_handoffs", "_process_one"):
            self.assertFalse(hasattr(self.store, name), name)

    def test_issue_requires_exactly_100_and_caller_cannot_supply_root_or_refs(self) -> None:
        with self.assertRaisesRegex(Exception, "queue_batch_requires_100"):
            self.store.issue_batch(templates=self.templates()[:-1])
        with self.assertRaisesRegex(Exception, "queue_batch_requires_100"):
            self.store.issue_batch(templates=self.templates() + (self.templates()[0],))
        with self.assertRaises(TypeError):
            self.store.issue_batch(templates=self.templates(), batch_root=bytes(64))

    def test_attempt_budget_exact_boundary_is_101_units_and_does_not_roll_by_epoch(self) -> None:
        self.assertEqual(_reserve_units(2**32 - 101), 2**32)
        with self.assertRaisesRegex(Exception, "computational_budget_exhausted"):
            _reserve_units(2**32 - 100)
        with self.assertRaisesRegex(Exception, "computational_ledger"):
            _reserve_units(-1)

    def test_valid_batch_is_one_verifier_call_and_one_atomic_verified_projection(self) -> None:
        batch = self.issue()
        self.submit(batch)
        verifier = _Verifier(self.config)
        result = self.store._process_one_batch(verifier=verifier)
        self.assertEqual((result.status, result.accepted_count, verifier.calls), ("VERIFIED", 100, 1))
        promoted = read_verified_batch(self.path, batch.batch_id)
        self.assertEqual(len(promoted.jobs), 100)
        self.assertEqual(tuple(job.operation_ref for job in promoted.jobs), tuple(item.operation_ref for item in batch.statements))
        self.assertEqual(promoted.batch.batch_id, batch.batch_id)
        self.assertEqual(promoted.batch.accepted_count, 100)
        self.assertEqual(verify_database(self.path)["verified_count"], 100)
        durable = self.snapshot()
        self.assertNotIn(b"synthetic-volatile-proof", durable)
        self.assertNotIn(b"raw_proof", durable)
        self.assertNotIn(b"source_path", durable)

    def test_proof_and_source_acceptance_are_both_required_and_unknown_result_is_held(self) -> None:
        for accepted, authenticated, expected in ((False, True, "REJECTED"), (True, False, "REJECTED")):
            batch = self.issue(offset=10 if accepted else 20)
            self.submit(batch)
            result = self.store._process_one_batch(verifier=_Verifier(self.config, proof_accepted=accepted, source_authenticated=authenticated))
            self.assertEqual(result.status, expected)
            with self.assertRaisesRegex(IndependentQueueError, "batch_incomplete"):
                read_verified_batch(self.path, batch.batch_id)
        unknown = self.issue(offset=30)
        self.submit(unknown)
        result = self.store._process_one_batch(verifier=_Verifier(self.config, unknown=True))
        self.assertEqual((result.status, result.error_code), ("HELD", "verifier_result_unknown_field"))
        with self.assertRaisesRegex(IndependentQueueError, "batch_incomplete"):
            read_verified_batch(self.path, unknown.batch_id)

    def test_result_statement_and_root_mismatch_fail_closed(self) -> None:
        for kind in ("statement", "root"):
            batch = self.issue(offset=40 if kind == "statement" else 50)
            self.submit(batch)
            result = self.store._process_one_batch(verifier=_Verifier(self.config, mutate=kind))
            self.assertEqual(result.status, "REJECTED")
            with self.assertRaisesRegex(IndependentQueueError, "batch_incomplete"):
                read_verified_batch(self.path, batch.batch_id)

    def test_result_source_profile_epoch_and_flags_are_state_bound(self) -> None:
        for index, kind in enumerate(("source_profile", "source_epoch", "flags"), start=60):
            batch = self.issue(offset=index * 100)
            self.submit(batch)
            result = self.store._process_one_batch(verifier=_Verifier(self.config, mutate=kind))
            self.assertEqual((result.status, result.error_code), ("REJECTED", "verifier_result_mismatch"))
            with self.assertRaisesRegex(IndependentQueueError, "batch_incomplete"):
                read_verified_batch(self.path, batch.batch_id)

    def test_handoff_is_single_use_and_declared_oversize_is_rejected_before_queueing(self) -> None:
        batch = self.issue()
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_oversize"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"x"), declared_length=ADMISSION_CAP_BYTES + 1)
        self.assertEqual(verify_database(self.path)["status_counts"]["AWAITING_HANDOFF"], 100)
        self.submit(batch)
        with self.assertRaisesRegex(QueueConflictError, "fresh_handoff_required"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"duplicate"), declared_length=9)

    def test_reservation_precedes_verifier_and_restart_holds_without_reuse(self) -> None:
        batch = self.issue()
        self.submit(batch)
        def crash(label: str) -> None:
            if label == "after_reservation":
                raise RuntimeError("injected")
        self.store._after_commit_fault = crash
        with self.assertRaises(RuntimeError):
            self.store._process_one_batch(verifier=_Verifier(self.config))
        with closing(sqlite3.connect(str(self.path))) as connection:
            self.assertEqual(connection.execute("SELECT status,attempt FROM queue_batches").fetchone(), ("LEASED", 1))
            self.assertEqual(connection.execute("SELECT computational_units_used FROM queue_metadata").fetchone()[0], 101)
        self.store._close()
        self.owner.close()
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.path, config=self.config, owner=self.owner, clock=self.clock)
        self.assertEqual(verify_database(self.path)["status_counts"]["HELD"], 100)
        with self.assertRaisesRegex(IndependentQueueError, "batch_incomplete"):
            read_verified_batch(self.path, batch.batch_id)
        with self.assertRaisesRegex(QueueConflictError, "fresh_handoff_required"):
            self.submit(batch)
        replacement = self.issue(offset=90)
        self.assertNotEqual(replacement.batch_id, batch.batch_id)
        self.assertNotEqual(replacement.state_challenge, batch.state_challenge)

    def test_startup_rejects_mixed_active_image_before_recovery_mutation(self) -> None:
        batch = self.issue()
        self.submit(batch)
        self.store._close()
        self.owner.close()
        with closing(sqlite3.connect(str(self.path))) as connection:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute("UPDATE queue_jobs SET status='HELD' WHERE batch_position=0")
            connection.commit()
        before = self.snapshot()
        replacement_owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        try:
            with self.assertRaisesRegex(IndependentQueueError, "batch_status_binding"):
                _VerificationQueueStore(path=self.path, config=self.config, owner=replacement_owner, clock=self.clock)
            self.assertEqual(self.snapshot(), before)
        finally:
            replacement_owner.close()

    def test_validity_window_is_checked_before_crypto_and_has_no_attempt_charge(self) -> None:
        too_old = self.store.issue_batch(templates=tuple(OperationTemplate(f"expired-{i}", 1, "state-profile-v8", 1, 2) for i in range(100)))
        with self.assertRaisesRegex(QueueConflictError, "validity_expired"):
            self.submit(too_old)
        verifier = _Verifier(self.config)
        self.assertIsNone(self.store._process_one_batch(verifier=verifier))
        self.assertEqual(verifier.calls, 0)
        with closing(sqlite3.connect(str(self.path))) as connection:
            self.assertEqual(connection.execute("SELECT computational_units_used FROM queue_metadata").fetchone()[0], 0)
        self.assertEqual(verify_database(self.path)["status_counts"]["HELD"], 100)

    def test_unselected_reader_skips_incomplete_older_batch_and_selector_cannot_shrink(self) -> None:
        older = self.issue(offset=100)
        later = self.issue(offset=200)
        self.submit(later)
        self.assertEqual(self.store._process_one_batch(verifier=_Verifier(self.config)).status, "VERIFIED")
        selected = read_verified_batch(self.path)
        self.assertEqual(selected.batch.batch_id, later.batch_id)
        self.assertEqual(len(selected.jobs), 100)
        with self.assertRaisesRegex(IndependentQueueError, "batch_incomplete"):
            read_verified_batch(self.path, older.batch_id)

    def test_independent_reconstruction_rejects_root_prefix_refs_positions_templates_and_partial_images(self) -> None:
        batch = self.issue(registry=bytes([7]) * 64)
        self.submit(batch)
        self.assertEqual(self.store._process_one_batch(verifier=_Verifier(self.config)).status, "VERIFIED")
        self.store._close()
        self.owner.close()
        original = self.path.read_bytes()
        mutations = ("ordered_binding", "ref", "position", "template", "registry", "partial")
        for mutation in mutations:
            self.path.write_bytes(original)
            with closing(sqlite3.connect(str(self.path))) as connection:
                if mutation == "ordered_binding":
                    connection.execute("UPDATE queue_batches SET ordered_binding=?", (bytes(32),))
                elif mutation == "ref":
                    connection.execute("UPDATE queue_jobs SET operation_ref=? WHERE batch_position=0", (bytes([8]) * 32,))
                elif mutation == "position":
                    connection.execute("PRAGMA ignore_check_constraints=ON")
                    connection.execute("UPDATE queue_jobs SET batch_position=100 WHERE batch_position=0")
                elif mutation == "template":
                    connection.execute("UPDATE queue_jobs SET assertion_version=2 WHERE batch_position=0")
                elif mutation == "registry":
                    connection.execute("UPDATE queue_jobs SET approved_source_registry_root=? WHERE batch_position=0", (bytes([8]) * 64,))
                else:
                    connection.execute("DROP TRIGGER queue_jobs_no_delete")
                    connection.execute("DELETE FROM queue_jobs WHERE batch_position=99")
                connection.commit()
            with self.assertRaises(IndependentQueueError):
                verify_database(self.path)
        self.path.write_bytes(original)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.path, config=self.config, owner=self.owner, clock=self.clock)


if __name__ == "__main__":
    unittest.main()
