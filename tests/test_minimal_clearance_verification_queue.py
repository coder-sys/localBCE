from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app.minimal_clearance_verification_queue import (
    ADMISSION_CAP_BYTES,
    PROCESS_TREE_PEAK_CAP_BYTES,
    IssuedOperationStatement,
    OperationTemplate,
    QueueConfig,
    QueueConflictError,
    QueueDeterministicRejectError,
    QueueHeldError,
    QueueIntegrityError,
    QueueLeaseError,
    VerifierResult,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
    _compute_batch_root,
)
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    read_verified_batch,
    verify_database,
)
import app.minimal_clearance_verification_queue_independent as queue_independent


class _Verifier:
    def __init__(self, *, unknown: bool = False, accepted: bool = True, profile: str = "synthetic-v7-unqualified") -> None:
        self.unknown = unknown
        self.accepted = accepted
        self.profile = profile
        self.seen: list[bytes] = []

    def verify(self, stream: VolatileProofHandoff, statement: IssuedOperationStatement):
        raw = stream.read()
        stream.read()
        self.seen.append(raw)
        embedded = _decode_proof(raw)
        if self.unknown:
            return {
                "proof_accepted": True,
                "operation_ref": embedded.operation_ref.hex().upper(),
                "assertion_identifier": embedded.assertion_identifier,
                "assertion_version": embedded.assertion_version,
                "state_profile_version": embedded.state_profile_version,
                "valid_from_ms": embedded.valid_from_ms,
                "valid_until_ms": embedded.valid_until_ms,
                "batch_position": embedded.batch_position,
                "batch_root": None if embedded.batch_root is None else embedded.batch_root.hex().upper(),
                "approved_source_registry_root": None if embedded.approved_source_registry_root is None else embedded.approved_source_registry_root.hex().upper(),
                "verifier_profile_version": self.profile,
                "outcome_code": "ok",
                "error_code": None,
                "resource_code": None,
                "qualification_flags": list(embedded.qualification_flags),
                "policy_result": "PASS",
            }
        return VerifierResult(
            self.accepted,
            embedded.operation_ref,
            embedded.assertion_identifier,
            embedded.assertion_version,
            embedded.state_profile_version,
            embedded.valid_from_ms,
            embedded.valid_until_ms,
            embedded.batch_position,
            embedded.batch_root,
            embedded.approved_source_registry_root,
            self.profile,
            "ok" if self.accepted else "rejected",
            qualification_flags=embedded.qualification_flags,
        )


_PROOF_MAGIC = b"BL/SYNTHETIC-QUEUE-PROOF/v7\x00"


def _proof_bytes(statement: IssuedOperationStatement) -> bytes:
    raw = statement.canonical_bytes
    return _PROOF_MAGIC + len(raw).to_bytes(4, "big") + raw


def _decode_proof(raw: bytes) -> IssuedOperationStatement:
    start = raw.find(_PROOF_MAGIC)
    if start < 0 or len(raw) < start + len(_PROOF_MAGIC) + 4:
        raise QueueDeterministicRejectError("synthetic_proof")
    offset = start + len(_PROOF_MAGIC)
    length = int.from_bytes(raw[offset:offset + 4], "big")
    payload = raw[offset + 4:offset + 4 + length]
    if length != len(payload):
        raise QueueDeterministicRejectError("synthetic_proof")
    try:
        value = json.loads(payload.decode("ascii"))
        if set(value) != set(IssuedOperationStatement(b"r" * 32, "a", 1, "p", 0, 1).as_json):
            raise ValueError
        return IssuedOperationStatement(
            bytes.fromhex(value["operation_ref"]), value["assertion_identifier"], int(value["assertion_version"]),
            value["state_profile_version"], int(value["valid_from_ms"]), int(value["valid_until_ms"]),
            int(value["batch_position"]), None if value["batch_root"] is None else bytes.fromhex(value["batch_root"]),
            None if value["approved_source_registry_root"] is None else bytes.fromhex(value["approved_source_registry_root"]),
            tuple(value["qualification_flags"]),
        )
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        raise QueueDeterministicRejectError("synthetic_proof")


class _Clock:
    def __init__(self, value: int = 0) -> None:
        self.value = value

    def now_ms(self) -> int:
        return self.value


class _EchoVerifier:
    def verify(self, _stream: VolatileProofHandoff, statement: IssuedOperationStatement) -> VerifierResult:
        return VerifierResult(True, statement.operation_ref, statement.assertion_identifier, statement.assertion_version, statement.state_profile_version, statement.valid_from_ms, statement.valid_until_ms, statement.batch_position, statement.batch_root, statement.approved_source_registry_root, "synthetic-v7-unqualified", "echo", qualification_flags=statement.qualification_flags)


class _PartialVerifier:
    def verify(self, stream: VolatileProofHandoff, statement: IssuedOperationStatement) -> VerifierResult:
        stream.read(1)
        stream.read(0)
        return VerifierResult(True, statement.operation_ref, statement.assertion_identifier, statement.assertion_version, statement.state_profile_version, statement.valid_from_ms, statement.valid_until_ms, statement.batch_position, statement.batch_root, statement.approved_source_registry_root, "synthetic-v7-unqualified", "partial", qualification_flags=statement.qualification_flags)


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

    def _template(self, position: int = 0) -> OperationTemplate:
        return OperationTemplate(f"assertion-{position}", 1, "state-profile-v7", 0, 10**15, None, ())

    def _issue(self, position: int = 0) -> tuple[IssuedOperationStatement, object]:
        statement = self.store.issue_operation(template=self._template(position))
        job = self.store.submit_handoff(operation_ref=statement.operation_ref, proof_stream=io.BytesIO(_proof_bytes(statement)), declared_length=len(_proof_bytes(statement)))
        return statement, job

    def test_v7_schema_has_only_allowlisted_fields_and_flags(self) -> None:
        self.assertEqual(self.config.as_json["schema_version"], 7)
        self.assertEqual(self.config.as_json["handoff_protocol"], "ISSUE_THEN_HANDOFF_V1")
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
        statement = self.store.issue_operation(template=self._template())
        proof = sentinel + _proof_bytes(statement)
        stream = io.BytesIO(proof)
        job = self.store.submit_handoff(operation_ref=statement.operation_ref, proof_stream=stream, declared_length=len(proof))
        verifier = _Verifier()
        result = self.store._process_one(verifier=verifier)
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(len(verifier.seen), 1)
        self.assertIn(sentinel, verifier.seen[0])
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
        first_statement, first = self._issue()
        self.assertEqual(self.store._process_one(verifier=_Verifier()).status, "VERIFIED")
        second_statement = self.store.issue_operation(template=self._template(1))
        second = self.store.submit_handoff(operation_ref=second_statement.operation_ref, proof_stream=io.BytesIO(_proof_bytes(second_statement)))
        self.assertNotEqual(first.operation_ref, second.operation_ref)
        held = self.store._process_one(verifier=_Verifier(unknown=True))
        self.assertEqual(held.status, "HELD")
        self.assertEqual(held.error_code, "verifier_result_unknown_field")
        self.assertEqual(verify_database(self.store.path, expected_config=self.config.as_json)["status_counts"]["HELD"], 1)

    def test_declared_oversize_rejected_before_any_queue_mutation(self) -> None:
        stream = io.BytesIO(b"oversize")
        with self.assertRaises(QueueHeldError) as raised:
            statement = self.store.issue_operation(template=self._template())
            self.store.submit_handoff(operation_ref=statement.operation_ref, proof_stream=stream, declared_length=ADMISSION_CAP_BYTES + 1)
        self.assertEqual(str(raised.exception), "proof_handoff_oversize")
        self.assertTrue(stream.closed)
        self.assertEqual(self.store._snapshot()["counts"]["AWAITING_HANDOFF"], 1)
        self.assertEqual(self.store._snapshot()["admission_count"], 1)

    def test_batch_admission_is_atomic_when_a_later_handoff_is_invalid(self) -> None:
        first = io.BytesIO(b"first")
        second = io.BytesIO(b"second")
        with self.assertRaises(QueueHeldError) as raised:
            statements = self.store.issue_batch(templates=(self._template(0), self._template(1)))
            before = self.store._snapshot()
            self.store.submit_batch_handoffs(statements=statements, proof_streams=(first, second), declared_lengths=(5, ADMISSION_CAP_BYTES + 1))
        self.assertEqual(str(raised.exception), "proof_handoff_oversize")
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)
        self.assertEqual(self.store._snapshot()["admission_count"], 2)
        self.assertEqual(self.store._snapshot()["counts"]["AWAITING_HANDOFF"], 2)
        self.assertEqual(self.store._snapshot(), before)

    def test_two_phase_api_has_no_one_step_alias_and_echo_only_verifier_fails_closed(self) -> None:
        self.assertFalse(hasattr(self.store, "admit"))
        self.assertFalse(hasattr(self.store, "admit_batch"))
        with self.assertRaises(TypeError):
            self.store.submit_handoff(proof_stream=io.BytesIO(b"proof"))
        statement = self.store.issue_operation(template=self._template())
        self.assertEqual(self.store._snapshot()["counts"]["AWAITING_HANDOFF"], 1)
        self.store.submit_handoff(operation_ref=statement.operation_ref, proof_stream=io.BytesIO(_proof_bytes(statement)))
        result = self.store._process_one(verifier=_EchoVerifier())
        self.assertEqual((result.status, result.error_code), ("HELD", "verifier_stream_not_consumed"))
        self.assertEqual(self.store._get_job(statement.operation_ref).status, "HELD")
        duplicate_stream = io.BytesIO(_proof_bytes(statement))
        with self.assertRaises(QueueConflictError) as raised:
            self.store.submit_handoff(operation_ref=statement.operation_ref, proof_stream=duplicate_stream)
        self.assertEqual(str(raised.exception), "handoff_duplicate")
        self.assertTrue(duplicate_stream.closed)

    def test_precomputed_proof_wrong_reference_and_statement_fields_fail_closed(self) -> None:
        first = self.store.issue_operation(template=self._template(0))
        second = self.store.issue_operation(template=self._template(1))
        self.store.submit_handoff(operation_ref=second.operation_ref, proof_stream=io.BytesIO(_proof_bytes(first)))
        self.assertEqual(self.store._process_one(verifier=_Verifier()).error_code, "verifier_statement_mismatch")
        mutations = (
            {"assertion_identifier": "wrong-assertion"},
            {"state_profile_version": "wrong-profile"},
            {"valid_until_ms": 10**14},
            {"batch_position": 1},
            {"batch_root": b"z" * 64},
        )
        for index, changes in enumerate(mutations, start=2):
            issued = self.store.issue_operation(template=self._template(index))
            wrong = replace(issued, **changes)
            self.store.submit_handoff(operation_ref=issued.operation_ref, proof_stream=io.BytesIO(_proof_bytes(wrong)))
            self.assertEqual(self.store._process_one(verifier=_Verifier()).error_code, "verifier_statement_mismatch")

    def test_complete_statement_and_verifier_profile_are_bound(self) -> None:
        template = OperationTemplate("registry-bound", 1, "state-profile-v7", 0, 10**15, b"a" * 64, ())
        issued = self.store.issue_operation(template=template)
        wrong = replace(issued, approved_source_registry_root=b"b" * 64)
        self.store.submit_handoff(operation_ref=issued.operation_ref, proof_stream=io.BytesIO(_proof_bytes(wrong)))
        self.assertEqual(self.store._process_one(verifier=_Verifier()).error_code, "verifier_statement_mismatch")
        profiled = self.store.issue_operation(template=self._template(1))
        self.store.submit_handoff(operation_ref=profiled.operation_ref, proof_stream=io.BytesIO(_proof_bytes(profiled)))
        self.assertEqual(self.store._process_one(verifier=_Verifier(profile="wrong-profile")).error_code, "verifier_statement_mismatch")

    def test_partial_stream_cannot_mark_eof_with_zero_length_read(self) -> None:
        issued = self.store.issue_operation(template=self._template())
        proof = _proof_bytes(issued)
        self.store.submit_handoff(operation_ref=issued.operation_ref, proof_stream=io.BytesIO(proof))
        result = self.store._process_one(verifier=_PartialVerifier())
        self.assertEqual((result.status, result.error_code), ("HELD", "verifier_stream_not_consumed"))

    def test_state_issued_batch_root_is_recomputed_and_caller_cannot_supply_one(self) -> None:
        with self.assertRaises(TypeError):
            OperationTemplate("caller-root", 1, "state-profile-v7", 0, 10**15, None, (), batch_root=b"x" * 64)
        statements = self.store.issue_batch(templates=(self._template(0), self._template(1)))
        self.assertEqual(statements[0].batch_root, _compute_batch_root(tuple(replace(statement, batch_root=None) for statement in statements)))
        self.assertEqual(verify_database(self.store.path, expected_config=self.config.as_json)["status_counts"]["AWAITING_HANDOFF"], 2)
        with self.assertRaises(QueueConflictError) as raised:
            self.store.submit_batch_handoffs(statements=(statements[1], statements[0]), proof_streams=(io.BytesIO(_proof_bytes(statements[1])), io.BytesIO(_proof_bytes(statements[0]))))
        self.assertEqual(str(raised.exception), "queue_batch_binding")
        self.assertEqual(verify_database(self.store.path, expected_config=self.config.as_json)["status_counts"]["HELD"], 2)

    def test_failed_and_expired_handoffs_consume_reference_and_new_issue_is_distinct(self) -> None:
        failed = self.store.issue_operation(template=self._template())
        self.store.submit_handoff(operation_ref=failed.operation_ref, proof_stream=io.BytesIO(b"not-a-proof"))
        self.assertEqual(self.store._process_one(verifier=_Verifier()).status, "REJECTED")
        with self.assertRaises(QueueConflictError) as raised:
            self.store.submit_handoff(operation_ref=failed.operation_ref, proof_stream=io.BytesIO(b"not-a-proof"))
        self.assertEqual(str(raised.exception), "handoff_duplicate")
        expired_owner = _QueueRuntimeOwnership(lock_path=self.root / "expired.sqlite.runtime-lock", parent=self.root)
        expired_clock = _Clock(2)
        expired_store = _VerificationQueueStore(path=self.root / "expired.sqlite", config=self.config, owner=expired_owner, clock=expired_clock)
        try:
            expired = expired_store.issue_operation(template=OperationTemplate("expired", 1, "state-profile-v7", 0, 1))
            expired_stream = io.BytesIO(b"proof")
            with self.assertRaises(QueueHeldError) as held:
                expired_store.submit_handoff(operation_ref=expired.operation_ref, proof_stream=expired_stream)
            self.assertEqual(str(held.exception), "fresh_handoff_required")
            self.assertTrue(expired_stream.closed)
            fresh = expired_store.issue_operation(template=self._template())
            self.assertNotEqual(expired.operation_ref, fresh.operation_ref)
        finally:
            expired_store._close()
            expired_owner.close()

    def test_expiry_completion_commits_held_and_closes_the_volatile_handoff(self) -> None:
        clock = _Clock()
        path = self.root / "expiry.sqlite"
        owner = _QueueRuntimeOwnership(lock_path=self.root / "expiry.sqlite.runtime-lock", parent=self.root)
        store = _VerificationQueueStore(path=path, config=self.config, owner=owner, clock=clock)
        stream = io.BytesIO(b"expired")
        try:
            statement = store.issue_operation(template=self._template())
            job = store.submit_handoff(operation_ref=statement.operation_ref, proof_stream=stream)
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
        statement, job = self._issue()
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
        statements = self.store.issue_batch(templates=(self._template(0), self._template(1)))
        jobs = self.store.submit_batch_handoffs(statements=statements, proof_streams=tuple(io.BytesIO(_proof_bytes(statement)) for statement in statements))
        verifier = _Verifier()
        self.assertEqual(self.store._process_one(verifier=verifier).status, "VERIFIED")
        self.assertEqual(self.store._process_one(verifier=verifier).status, "VERIFIED")
        batch = read_verified_batch(self.store.path)
        self.assertEqual(tuple(job.operation_ref for job in batch.jobs), tuple(job.operation_ref for job in jobs))
        self.assertEqual(tuple(job.batch_position for job in batch.jobs), (0, 1))
        self.assertEqual(verify_database(self.store.path, expected_config=self.config.as_json)["verified_count"], 2)

    def test_independent_reconstruction_rejects_a_self_consistent_missing_lifecycle(self) -> None:
        statement, job = self._issue()
        self.assertEqual(self.store._process_one(verifier=_Verifier()).status, "VERIFIED")
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute("DROP TRIGGER queue_transitions_no_delete")
            connection.execute("DELETE FROM queue_transitions WHERE operation_ref=?", (job.operation_ref,))
            genesis = queue_independent._sha(queue_independent._GENESIS, self.config.queue_id.encode("ascii"), self.config.digest)
            connection.execute("UPDATE queue_metadata SET head_root=?,next_transition_seq=0 WHERE id=1", (genesis,))
            connection.commit()
        with self.assertRaises(IndependentQueueError) as raised:
            verify_database(self.store.path, expected_config=self.config.as_json)
        self.assertEqual(str(raised.exception), "lifecycle_issue")


if __name__ == "__main__":
    unittest.main()
