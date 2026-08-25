from __future__ import annotations

from contextlib import closing
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app.minimal_clearance_verification_queue import (
    ADMISSION_CAP_BYTES,
    PROCESS_TREE_PEAK_CAP_BYTES,
    OperationStatement,
    QueueConfig,
    QueueHeldError,
    QueueIntegrityError,
    QueueLeaseError,
    VerifierResult,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    read_verified_batch,
    verify_database,
)
import app.minimal_clearance_verification_queue_independent as queue_independent


class _Verifier:
    def __init__(self, *, unknown: bool = False, accepted: bool = True) -> None:
        self.unknown = unknown
        self.accepted = accepted
        self.seen: list[bytes] = []

    def verify(self, stream: VolatileProofHandoff, statement: OperationStatement, operation_ref: bytes):
        self.seen.append(stream.read())
        stream.read()
        if self.unknown:
            return {
                "proof_accepted": True,
                "operation_ref": operation_ref.hex().upper(),
                "assertion_identifier": statement.assertion_identifier,
                "assertion_version": statement.assertion_version,
                "state_profile_version": statement.state_profile_version,
                "valid_from_ms": statement.valid_from_ms,
                "valid_until_ms": statement.valid_until_ms,
                "batch_position": statement.batch_position,
                "batch_root": None if statement.batch_root is None else statement.batch_root.hex().upper(),
                "verifier_profile_version": "synthetic-v7-unqualified",
                "outcome_code": "ok",
                "error_code": None,
                "resource_code": None,
                "qualification_flags": list(statement.qualification_flags),
                "policy_result": "PASS",
            }
        return VerifierResult(
            self.accepted,
            operation_ref,
            statement.assertion_identifier,
            statement.assertion_version,
            statement.state_profile_version,
            statement.valid_from_ms,
            statement.valid_until_ms,
            statement.batch_position,
            statement.batch_root,
            "synthetic-v7-unqualified",
            "ok" if self.accepted else "rejected",
            qualification_flags=statement.qualification_flags,
        )


class _Clock:
    def __init__(self, value: int = 0) -> None:
        self.value = value

    def now_ms(self) -> int:
        return self.value


class QueueV7Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-queue-v7-")
        self.root = Path(self.temp.name)
        self.config = QueueConfig("queue-v7-test", 8)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.root / "queue.sqlite", config=self.config, owner=self.owner)

    def tearDown(self) -> None:
        self.store._close()
        self.owner.close()
        self.temp.cleanup()

    def _statement(self, position: int = 0, *, batch_root: bytes | None = None) -> OperationStatement:
        return OperationStatement(f"assertion-{position}", 1, "state-profile-v7", 0, 10_000, position, batch_root, None, ())

    def test_v7_schema_has_only_allowlisted_fields_and_flags(self) -> None:
        self.assertEqual(self.config.as_json["schema_version"], 7)
        self.assertEqual(self.config.as_json["admission_cap_bytes"], 4_500_000_000)
        self.assertLess(self.config.as_json["process_tree_peak_cap_bytes"], 5_000_000_000)
        with closing(sqlite3.connect(self.store.path)) as connection:
            columns = {
                table: tuple(row[1] for row in connection.execute(f"PRAGMA table_info({table})"))
                for table in ("queue_metadata", "queue_jobs", "queue_leases", "queue_results", "queue_transitions")
            }
        joined = " ".join(" ".join(value) for value in columns.values()).lower()
        for forbidden in ("artifact", "source_path", "patient", "provider", "case_id", "stdout", "stderr", "acceptance_bytes", "policy_result", "effective_directive"):
            self.assertNotIn(forbidden, joined)
        self.assertEqual(ADMISSION_CAP_BYTES, 4_500_000_000)
        self.assertEqual(PROCESS_TREE_PEAK_CAP_BYTES, 4_999_999_999)

    def test_stream_is_single_use_and_raw_material_never_enters_durable_surfaces(self) -> None:
        sentinel = b"RAW_PROOF_SENTINEL_SOURCE_PATH_PATIENT_PROVIDER_CASE"
        stream = io.BytesIO(sentinel)
        job = self.store.admit(statement=self._statement(), proof_stream=stream, declared_length=len(sentinel))
        verifier = _Verifier()
        result = self.store._process_one(verifier=verifier)
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(verifier.seen, [sentinel])
        self.assertTrue(stream.closed)
        self.assertEqual(len(job.operation_ref), 32)
        receipt = result.receipt_bytes or b""
        exported = self.store._export_bytes()
        database = self.store.path.read_bytes()
        self.assertNotIn(sentinel, receipt)
        self.assertNotIn(sentinel, exported)
        self.assertNotIn(sentinel, database)
        self.assertFalse(any("workspace" in item.name.lower() for item in self.root.iterdir()))
        self.assertEqual(verify_database(self.store.path, expected_config=self.config.as_json)["verified_count"], 1)

    def test_new_admission_generates_different_reference_and_unknown_verifier_fields_hold(self) -> None:
        first = self.store.admit(statement=self._statement(), proof_stream=io.BytesIO(b"first"))
        self.assertEqual(self.store._process_one(verifier=_Verifier()).status, "VERIFIED")
        second = self.store.admit(statement=OperationStatement("assertion-1", 1, "state-profile-v7", 0, 10_000), proof_stream=io.BytesIO(b"second"))
        self.assertNotEqual(first.operation_ref, second.operation_ref)
        held = self.store._process_one(verifier=_Verifier(unknown=True))
        self.assertEqual(held.status, "HELD")
        self.assertEqual(held.error_code, "verifier_result_unknown_field")
        self.assertEqual(verify_database(self.store.path, expected_config=self.config.as_json)["status_counts"]["HELD"], 1)

    def test_declared_oversize_rejected_before_any_queue_mutation(self) -> None:
        stream = io.BytesIO(b"oversize")
        with self.assertRaises(QueueHeldError) as raised:
            self.store.admit(statement=self._statement(), proof_stream=stream, declared_length=ADMISSION_CAP_BYTES + 1)
        self.assertEqual(str(raised.exception), "proof_handoff_oversize")
        self.assertTrue(stream.closed)
        self.assertEqual(self.store._snapshot()["counts"]["QUEUED"], 0)
        self.assertEqual(self.store._snapshot()["admission_count"], 0)

    def test_batch_admission_is_atomic_when_a_later_handoff_is_invalid(self) -> None:
        first = io.BytesIO(b"first")
        second = io.BytesIO(b"second")
        with self.assertRaises(QueueHeldError) as raised:
            self.store.admit_batch(statements=(self._statement(0), self._statement(1)), proof_streams=(first, second), declared_lengths=(5, ADMISSION_CAP_BYTES + 1))
        self.assertEqual(str(raised.exception), "proof_handoff_oversize")
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)
        self.assertEqual(self.store._snapshot()["admission_count"], 0)
        self.assertEqual(self.store._snapshot()["counts"]["QUEUED"], 0)

    def test_expiry_completion_commits_held_and_closes_the_volatile_handoff(self) -> None:
        clock = _Clock()
        path = self.root / "expiry.sqlite"
        owner = _QueueRuntimeOwnership(lock_path=self.root / "expiry.sqlite.runtime-lock", parent=self.root)
        store = _VerificationQueueStore(path=path, config=self.config, owner=owner, clock=clock)
        stream = io.BytesIO(b"expired")
        try:
            job = store.admit(statement=self._statement(), proof_stream=stream)
            work = store._claim_next()
            clock.value = 3_600_001
            with self.assertRaises(QueueLeaseError) as raised:
                store._complete(work, status="HELD", error_code="fresh_handoff_required")
            self.assertEqual(str(raised.exception), "lease_expired")
            self.assertTrue(stream.closed)
            self.assertEqual(store._get_job(job.operation_ref).status, "HELD")
            self.assertEqual(verify_database(path, expected_config=self.config.as_json)["status_counts"]["HELD"], 1)
        finally:
            store._close()
            owner.close()

    def test_restart_and_lease_expiry_are_held_and_require_fresh_handoff(self) -> None:
        job = self.store.admit(statement=self._statement(), proof_stream=io.BytesIO(b"gone"))
        work = self.store._claim_next()
        self.assertEqual(work.operation_ref, job.operation_ref)
        self.store._close()
        self.owner.close()
        owner = _QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root)
        restarted = _VerificationQueueStore(path=self.store.path, config=self.config, owner=owner)
        try:
            recovered = restarted._get_job(job.operation_ref)
            self.assertEqual(recovered.status, "HELD")
            self.assertEqual(recovered.last_error_code, "fresh_handoff_required")
            self.assertIsNone(restarted._claim_next())
            self.assertEqual(verify_database(restarted.path, expected_config=self.config.as_json)["status_counts"]["HELD"], 1)
        finally:
            restarted._close()
            owner.close()
            self.store = _VerificationQueueStore(path=self.root / "queue.sqlite", config=self.config, owner=_QueueRuntimeOwnership(lock_path=self.root / "queue.sqlite.runtime-lock", parent=self.root))
            self.owner = self.store._owner

    def test_old_schema_is_unsupported_without_migration(self) -> None:
        old = self.root / "old.sqlite"
        with closing(sqlite3.connect(old)) as connection:
            connection.execute("CREATE TABLE queue_metadata (id INTEGER PRIMARY KEY, schema_version INTEGER)")
            connection.commit()
        owner = _QueueRuntimeOwnership(lock_path=self.root / "old.sqlite.runtime-lock", parent=self.root)
        try:
            with self.assertRaises(QueueIntegrityError) as raised:
                _VerificationQueueStore(path=old, config=self.config, owner=owner)
            self.assertEqual(str(raised.exception), "queue_schema")
        finally:
            owner.close()

    def test_verified_batch_is_ordered_and_independent(self) -> None:
        root = b"b" * 64
        statements = tuple(self._statement(index, batch_root=root) for index in range(2))
        jobs = self.store.admit_batch(statements=statements, proof_streams=(io.BytesIO(b"one"), io.BytesIO(b"two")))
        verifier = _Verifier()
        self.assertEqual(self.store._process_one(verifier=verifier).status, "VERIFIED")
        self.assertEqual(self.store._process_one(verifier=verifier).status, "VERIFIED")
        batch = read_verified_batch(self.store.path)
        self.assertEqual(tuple(job.operation_ref for job in batch.jobs), tuple(job.operation_ref for job in jobs))
        self.assertEqual(tuple(job.batch_position for job in batch.jobs), (0, 1))
        self.assertEqual(verify_database(self.store.path, expected_config=self.config.as_json)["verified_count"], 2)

    def test_independent_reconstruction_rejects_a_self_consistent_missing_lifecycle(self) -> None:
        job = self.store.admit(statement=self._statement(), proof_stream=io.BytesIO(b"proof"))
        self.assertEqual(self.store._process_one(verifier=_Verifier()).status, "VERIFIED")
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute("DROP TRIGGER queue_transitions_no_delete")
            connection.execute("DELETE FROM queue_transitions WHERE operation_ref=?", (job.operation_ref,))
            genesis = queue_independent._sha(queue_independent._GENESIS, self.config.queue_id.encode("ascii"), self.config.digest)
            connection.execute("UPDATE queue_metadata SET head_root=?,next_transition_seq=0 WHERE id=1", (genesis,))
            connection.commit()
        with self.assertRaises(IndependentQueueError) as raised:
            verify_database(self.store.path, expected_config=self.config.as_json)
        self.assertEqual(str(raised.exception), "lifecycle_admission")


if __name__ == "__main__":
    unittest.main()
