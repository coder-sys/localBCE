import io
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from app.minimal_clearance_verification_queue import (
    ADMISSION_CAP_BYTES,
    DATABASE_MAX_PAGE_COUNT,
    DATABASE_PAGE_SIZE,
    BatchVerifierResult,
    OperationTemplate,
    QueueConfig,
    QueueConflictError,
    QueueHeldError,
    QueueIntegrityError,
    QueueLeaseError,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
    _build_statement,
    _reserve_proof_attempt,
)
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    read_verified_batch,
    verify_database,
)


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


class _Verifier:
    def __init__(self, config: QueueConfig, *, proof_accepted: bool = True, source_authenticated: bool = True, mutate: str | None = None, unknown: bool = False, advance: int | None = None) -> None:
        self.config = config
        self.proof_accepted = proof_accepted
        self.source_authenticated = source_authenticated
        self.mutate = mutate
        self.unknown = unknown
        self.advance = advance
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, issued_batch):
        self.calls += 1
        while stream.read(17):
            pass
        if self.advance is not None:
            self.config.clock.now += self.advance  # type: ignore[attr-defined]
        statement = issued_batch.proof_statement
        root = issued_batch.batch_root
        profile = self.config.source_auth_profile
        epoch = self.config.source_key_epoch
        flags = self.config.qualification_flags
        if self.mutate == "statement":
            statement = bytes([statement[0] ^ 1]) + statement[1:]
        if self.mutate == "root":
            root = bytes([root[0] ^ 1]) + root[1:]
        if self.mutate == "source_profile":
            profile = "untrusted-source-auth"
        if self.mutate == "source_epoch":
            epoch += 1
        if self.mutate == "flags":
            flags = ("untrusted-flag",)
        if self.unknown:
            return {"proof_accepted": self.proof_accepted, "source_authenticated": self.source_authenticated, "proof_statement": statement, "batch_root": root, "source_auth_profile": profile, "source_key_epoch": epoch, "result_code": "accepted", "qualification_flags": list(flags), "policyResult": "PASS"}
        return BatchVerifierResult(self.proof_accepted, self.source_authenticated, statement, root, profile, epoch, "accepted" if self.proof_accepted else "rejected", flags)


class _AdvanceVerifier(_Verifier):
    def __init__(self, config: QueueConfig, clock: _Clock, advance: int) -> None:
        super().__init__(config)
        self._clock = clock
        self._advance = advance

    def verify(self, stream: VolatileProofHandoff, issued_batch):
        self.calls += 1
        while stream.read(17):
            pass
        self._clock.now += self._advance
        return BatchVerifierResult(True, True, issued_batch.proof_statement, issued_batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", self.config.qualification_flags)


class _RollbackVerifier:
    def __init__(self, config: QueueConfig) -> None:
        self.config = config
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, issued_batch):
        self.calls += 1
        while stream.read(11):
            pass
        return BatchVerifierResult(True, True, issued_batch.proof_statement, issued_batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", self.config.qualification_flags)


class _BadCodeVerifier:
    def __init__(self, config: QueueConfig, result: dict[str, object]) -> None:
        self.config = config
        self.result = result

    def verify(self, stream: VolatileProofHandoff, _batch):
        while stream.read(11):
            pass
        return self.result


class _NoReadVerifier:
    def __init__(self, config: QueueConfig) -> None:
        self.config = config
        self.calls = 0

    def verify(self, _stream: VolatileProofHandoff, batch):
        self.calls += 1
        return BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", self.config.qualification_flags)


class QueueV8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.path = self.root / "queue.sqlite"
        self.clock = _Clock()
        self.config = QueueConfig("queue-v8", 512)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.path, config=self.config, owner=self.owner, clock=self.clock)

    def tearDown(self) -> None:
        self.store._close()
        self.owner.close()
        self._temp.cleanup()

    def template(self, *, identifier: str = "shared-assertion", start: int | None = None, end: int | None = None, registry: bytes | None = None) -> OperationTemplate:
        return OperationTemplate(identifier, 1, "state-profile-v8", self.clock.now - 100 if start is None else start, self.clock.now + 3_000_000 if end is None else end, registry, ())

    def refs(self, offset: int = 0) -> tuple[bytes, ...]:
        return tuple((offset + index + 1).to_bytes(32, "big") for index in range(100))

    def issue(self, *, offset: int = 0, template: OperationTemplate | None = None):
        return self.store.issue_batch(template=template or self.template(), operation_refs=self.refs(offset))

    def submit(self, batch, proof: bytes = b"synthetic-volatile-proof") -> None:
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(proof), declared_length=len(proof))

    def test_exact_100_has_one_shared_owner_and_fixed_statement(self) -> None:
        batch = self.issue()
        self.assertEqual(len(batch.operation_refs), 100)
        self.assertEqual(len(batch.statements), 100)
        self.assertEqual(len({item.operation_ref for item in batch.statements}), 100)
        self.assertEqual(len({item.template for item in batch.statements}), 1)
        self.assertEqual(batch.statements[0].batch_position, 0)
        self.assertEqual(batch.statements[-1].batch_position, 99)
        self.assertEqual(batch.ordered_binding, batch.batch_root[:32])
        self.assertEqual(len(batch.proof_statement), 240)
        self.assertEqual(batch.proof_statement[:16], b"BL-R100-STMT-V1\x00")
        self.assertEqual(batch.proof_statement[16:18], b"\x01\x00")
        self.assertEqual(int.from_bytes(batch.proof_statement[18:20], "little"), 240)
        self.assertEqual(batch.proof_statement[52:84], batch.batch_root[:32])
        fixed = _build_statement(batch_root=bytes(range(64)), state_challenge=bytes(range(32)), valid_from_ms=1, valid_until_ms=2)
        self.assertEqual(fixed[52:84], bytes(range(32)))
        with closing(sqlite3.connect(str(self.path))) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            self.assertIn("queue_members", tables)
            self.assertNotIn("queue_jobs", tables)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_members").fetchone()[0], 100)

    def test_issue_requires_exact_100_refs_and_rejects_heterogeneous_template(self) -> None:
        with self.assertRaisesRegex(Exception, "queue_batch_requires_100"):
            self.store.issue_batch(template=self.template(), operation_refs=self.refs()[:-1])
        with self.assertRaisesRegex(Exception, "queue_batch_requires_100"):
            self.store.issue_batch(template=self.template(), operation_refs=self.refs() + (self.refs()[0],))
        with self.assertRaises(TypeError):
            self.store.issue_batch(templates=tuple(self.template(identifier=f"different-{i}") for i in range(100)))  # type: ignore[call-arg]
        with self.assertRaisesRegex(Exception, "template_shape"):
            self.store.issue_batch(template=(self.template(),), operation_refs=self.refs())  # type: ignore[arg-type]

    def test_operation_refs_and_admission_sequences_are_global_and_immutable(self) -> None:
        first = self.issue()
        with self.assertRaises(sqlite3.IntegrityError):
            self.issue()
        with closing(sqlite3.connect(str(self.path))) as connection:
            rows = connection.execute("SELECT batch_position,operation_ref,admission_seq FROM queue_members WHERE batch_id=? ORDER BY batch_position", (first.batch_id,)).fetchall()
            self.assertEqual([int(row[2]) for row in rows], list(range(1, 101)))

    def test_attempt_budget_is_one_proof_attempt(self) -> None:
        self.assertEqual(_reserve_proof_attempt(2**32 - 1), 2**32)
        with self.assertRaisesRegex(Exception, "computational_budget_exhausted"):
            _reserve_proof_attempt(2**32)
        with self.assertRaisesRegex(Exception, "proof_attempt_ledger"):
            _reserve_proof_attempt(-1)

    def test_valid_batch_is_one_verifier_call_one_reservation_and_atomic_projection(self) -> None:
        batch = self.issue()
        self.submit(batch)
        verifier = _Verifier(self.config)
        result = self.store._process_one_batch(verifier=verifier)
        self.assertEqual((result.status, result.accepted_count, verifier.calls), ("VERIFIED", 100, 1))
        with closing(sqlite3.connect(str(self.path))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_attempts").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT proof_attempts FROM queue_attempts").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_results").fetchone()[0], 1)
        promoted = read_verified_batch(self.path, batch.batch_id)
        self.assertEqual(len(promoted.jobs), 100)
        self.assertEqual(tuple(job.operation_ref for job in promoted.jobs), batch.operation_refs)
        self.assertEqual(promoted.batch.accepted_count, 100)
        self.assertEqual(verify_database(self.path)["accepted_operation_count"], 100)
        durable = self.path.read_bytes()
        self.assertNotIn(b"synthetic-volatile-proof", durable)
        self.assertNotIn(b"raw_proof", durable)
        self.assertNotIn(b"source_path", durable)

    def test_invalid_signature_is_typed_reject_and_internal_result_is_held(self) -> None:
        batch = self.issue()
        self.submit(batch)
        result = self.store._process_one_batch(verifier=_Verifier(self.config, proof_accepted=False))
        self.assertEqual((result.status, result.error_code), ("REJECTED", "proof_or_source_not_accepted"))
        with self.assertRaisesRegex(IndependentQueueError, "batch_incomplete"):
            read_verified_batch(self.path, batch.batch_id)
        malformed = self.issue(offset=100)
        self.submit(malformed)
        held = self.store._process_one_batch(verifier=_Verifier(self.config, unknown=True))
        self.assertEqual((held.status, held.error_code), ("HELD", "verifier_result_unknown_field"))

    def test_result_binding_mismatch_rejects_without_verified_exposure(self) -> None:
        for index, kind in enumerate(("statement", "root", "source_profile", "source_epoch", "flags")):
            batch = self.issue(offset=200 + index * 100)
            self.submit(batch)
            result = self.store._process_one_batch(verifier=_Verifier(self.config, mutate=kind))
            self.assertEqual(result.status, "REJECTED")
            with self.assertRaisesRegex(IndependentQueueError, "batch_incomplete"):
                read_verified_batch(self.path, batch.batch_id)

    def test_handoff_is_single_use_and_oversize_is_rejected(self) -> None:
        batch = self.issue()
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_oversize"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"x"), declared_length=ADMISSION_CAP_BYTES + 1)
        self.assertEqual(verify_database(self.path)["status_counts"]["AWAITING_HANDOFF"], 1)
        self.submit(batch)
        with self.assertRaisesRegex(QueueConflictError, "fresh_handoff_required"):
            self.store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"duplicate"), declared_length=9)

    def test_handoff_null_empty_and_declared_length_errors_are_typed(self) -> None:
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_stream"):
            VolatileProofHandoff(None)  # type: ignore[arg-type]
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_empty"):
            VolatileProofHandoff(io.BytesIO(b""), declared_length=0).read()
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_length"):
            handoff = VolatileProofHandoff(io.BytesIO(b"abc"), declared_length=2)
            handoff.read()

    def test_source_epoch_accepts_full_u64_value_in_configuration(self) -> None:
        config = QueueConfig("u64-epoch", 100, source_key_epoch=2**32)
        self.assertEqual(config.source_key_epoch, 2**32)
        epoch_root = self.root / "epoch"
        epoch_root.mkdir()
        epoch_path = epoch_root / "queue.sqlite"
        epoch_owner = _QueueRuntimeOwnership(lock_path=epoch_root / "queue.sqlite.runtime-lock", parent=epoch_root)
        epoch_store = _VerificationQueueStore(path=epoch_path, config=QueueConfig("u64-epoch-max", 100, source_key_epoch=2**64 - 1), owner=epoch_owner, clock=self.clock)
        try:
            batch = epoch_store.issue_batch(template=self.template(), operation_refs=self.refs(10_000))
            epoch_store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(b"epoch-proof"), declared_length=11)
            self.assertEqual(epoch_store._process_one_batch(verifier=_Verifier(epoch_store.config)).status, "VERIFIED")
            verify_database(epoch_path, expected_config=epoch_store.config.as_json)
        finally:
            epoch_store._close()
            epoch_owner.close()

    def test_validity_and_lease_expiry_inside_verifier_return_held(self) -> None:
        batch = self.issue(template=self.template(end=self.clock.now + 10_000))
        self.submit(batch)
        verifier = _AdvanceVerifier(self.config, self.clock, 10_001)
        result = self.store._process_one_batch(verifier=verifier)
        self.assertEqual((result.status, result.error_code), ("HELD", "validity_expired"))
        batch2 = self.issue(offset=500, template=self.template(end=self.clock.now + 100_000))
        self.submit(batch2)
        verifier2 = _AdvanceVerifier(self.config, self.clock, 60_001)
        result2 = self.store._process_one_batch(verifier=verifier2)
        self.assertEqual((result2.status, result2.error_code), ("HELD", "lease_expired"))

    def test_stale_lease_token_fails_without_mutating_current_work(self) -> None:
        batch = self.issue()
        self.submit(batch)
        work = self.store._claim_next_batch()
        self.assertIsNotNone(work)
        stale = replace(work, lease_token=bytes(32))
        before = self.path.read_bytes()
        with self.assertRaises(QueueLeaseError):
            self.store._complete_batch(stale, status="HELD", error_code="fresh_handoff_required")
        self.assertEqual(self.path.read_bytes(), before)
        with closing(sqlite3.connect(str(self.path))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "LEASED")

    def test_identity_rewrite_and_required_trigger_tamper_are_rejected(self) -> None:
        batch = self.issue()
        with closing(sqlite3.connect(str(self.path))) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE queue_batches SET batch_root=? WHERE batch_id=?", (bytes(64), batch.batch_id))
            connection.rollback()
            connection.commit()
        original = self.path.read_bytes()
        with closing(sqlite3.connect(str(self.path))) as connection:
            connection.execute("DROP TRIGGER queue_members_no_update")
            connection.commit()
        with self.assertRaises(IndependentQueueError):
            verify_database(self.path)
        self.path.write_bytes(original)

    def test_required_trigger_tamper_does_not_get_repaired_by_startup(self) -> None:
        batch = self.issue()
        self.store._close()
        self.owner.close()
        with closing(sqlite3.connect(str(self.path))) as connection:
            connection.execute("DROP TRIGGER queue_members_no_delete")
            connection.commit()
        replacement = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        try:
            with self.assertRaises(Exception):
                _VerificationQueueStore(path=self.path, config=self.config, owner=replacement, clock=self.clock)
            self.assertFalse((self.root / "queue.sqlite.runtime-lock").exists())
        finally:
            replacement.close()

    def test_zero_phi_code_allowlist_rejects_before_persistence_and_scans_durable_codes(self) -> None:
        bad_codes = ("provider_id_mismatch", "identity", "digest", "path", "log")
        batches = []
        for index, bad_code in enumerate(bad_codes):
            batch = self.issue(offset=index * 100)
            batches.append(batch)
            self.submit(batch)
            malicious = {"proof_accepted": False, "source_authenticated": False, "proof_statement": batch.proof_statement, "batch_root": batch.batch_root, "source_auth_profile": self.config.source_auth_profile, "source_key_epoch": self.config.source_key_epoch, "result_code": bad_code, "qualification_flags": []}
            held = self.store._process_one_batch(verifier=_BadCodeVerifier(self.config, malicious))
            self.assertEqual((held.status, held.error_code), ("HELD", "verifier_result_code"))
        with closing(sqlite3.connect(str(self.path))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_results").fetchone()[0], len(bad_codes))
            rows = connection.execute("SELECT result_code,error_code FROM queue_results").fetchall()
            self.assertEqual({row[0] for row in rows}, {"fresh_handoff_required"})
            self.assertEqual({row[1] for row in rows}, {"verifier_result_code"})
            connection.execute("UPDATE queue_batches SET last_error_code='provider_id_mismatch' WHERE batch_id=?", (batches[-1].batch_id,))
            connection.commit()
        with self.assertRaises(IndependentQueueError):
            verify_database(self.path)

    def test_database_cap_and_pragmas_are_exact_without_large_materialization(self) -> None:
        self.assertEqual(DATABASE_PAGE_SIZE * DATABASE_MAX_PAGE_COUNT, 134_217_728)
        with closing(self.store._connect()) as connection:
            self.assertEqual(connection.execute("PRAGMA page_size").fetchone()[0], DATABASE_PAGE_SIZE)
            self.assertEqual(connection.execute("PRAGMA max_page_count").fetchone()[0], DATABASE_MAX_PAGE_COUNT)
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "delete")
            self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertLessEqual(self.path.stat().st_size, 134_217_728)

    def test_rollback_after_consumption_closes_as_fresh_handoff_required(self) -> None:
        batch = self.issue()
        self.submit(batch)
        self.store._before_fault = lambda label: (_ for _ in ()).throw(RuntimeError("injected")) if label == "before_queue_commit" else None
        with self.assertRaises(RuntimeError):
            self.store._process_one_batch(verifier=_RollbackVerifier(self.config))
        self.assertEqual(verify_database(self.path)["status_counts"]["HELD"], 1)
        self.assertIsNone(self.store._process_one_batch(verifier=_RollbackVerifier(self.config)))

    def test_rollback_before_consumption_preserves_handoff_for_same_attempt_retry(self) -> None:
        batch = self.issue()
        self.submit(batch)
        self.store._before_fault = lambda label: (_ for _ in ()).throw(RuntimeError("injected")) if label == "before_queue_commit" else None
        with self.assertRaises(RuntimeError):
            self.store._process_one_batch(verifier=_NoReadVerifier(self.config))
        with closing(sqlite3.connect(str(self.path))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "LEASED")
        self.store._before_fault = None
        verifier = _Verifier(self.config)
        result = self.store._process_one_batch(verifier=verifier)
        self.assertEqual((result.status, verifier.calls), ("VERIFIED", 1))

    def test_batch_local_post_root_is_stable_after_later_batch(self) -> None:
        first = self.issue()
        self.submit(first)
        self.assertEqual(self.store._process_one_batch(verifier=_Verifier(self.config)).status, "VERIFIED")
        first_read = read_verified_batch(self.path, first.batch_id)
        second = self.issue(offset=1000)
        self.submit(second)
        self.assertEqual(self.store._process_one_batch(verifier=_Verifier(self.config)).status, "VERIFIED")
        second_read = read_verified_batch(self.path, second.batch_id)
        self.assertNotEqual(first_read.batch.post_head_root, second_read.batch.post_head_root)
        self.assertEqual(read_verified_batch(self.path, first.batch_id).batch.post_head_root, first_read.batch.post_head_root)

    def test_startup_releases_owner_after_failure_and_retry_succeeds(self) -> None:
        batch = self.issue()
        self.store._close()
        self.owner.close()
        with closing(sqlite3.connect(str(self.path))) as connection:
            connection.execute("DROP TRIGGER queue_metadata_config_guard")
            connection.execute("UPDATE queue_metadata SET config_json=? WHERE id=1", (b"bad",))
            connection.commit()
        replacement = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        with self.assertRaises(Exception):
            _VerificationQueueStore(path=self.path, config=self.config, owner=replacement, clock=self.clock)
        self.assertFalse((self.root / "queue.sqlite.runtime-lock").exists())
        replacement.close()


if __name__ == "__main__":
    unittest.main()
