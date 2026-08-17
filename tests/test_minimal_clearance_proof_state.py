from __future__ import annotations

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from app.direct_state_owned_clearance_v1 import DIRECT_INITIAL_PAYMENT_ROOT
from app.minimal_clearance_proof_state import (
    MinimalClearanceIndeterminateError,
    MinimalClearanceProofStateError,
    MinimalClearanceStateStoreV1,
    MinimalProofAcceptanceV1,
    StaticMinimalClearanceVerifier,
    _CIRCUIT_ID,
    _PROOF_ROLE,
    _STATE_BYTES,
    _STATE_DIGEST_NAMES,
    _STATE_MAGIC,
    _STATEMENT_DIGEST_NAMES,
    _artifact_public_bytes,
    _parse_statement,
    _sha,
    _u32,
    _u64,
    parse_acceptance_bytes,
)


_ARTIFACT = Path(
    r"C:\Temp\blind-ledger-minimal-clearance-proof-20260817c\minimal_clearance_case0.blmc"
)
_DIRECTIVE_POLICY = {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}
_DIRECTIVE_FLAGS = {
    1: (1, 1, 0, 1, 0, 0),
    2: (1, 0, 1, 0, 0, 0),
    3: (0, 0, 0, 0, 0, 0),
    4: (1, 1, 0, 0, 0, 0),
    5: (1, 1, 0, 0, 1, 1),
}


def _base_acceptance() -> MinimalProofAcceptanceV1:
    if not _ARTIFACT.is_file():
        raise AssertionError(f"retained artifact missing: {_ARTIFACT}")
    raw = _ARTIFACT.read_bytes()
    circuit_id, statement_bytes, _ = _artifact_public_bytes(raw)
    return MinimalProofAcceptanceV1(
        statement=_parse_statement(statement_bytes),
        artifact_sha256=hashlib.sha256(raw).digest(),
        artifact_digest=hashlib.sha3_512(raw).digest(),
        artifact_bytes=len(raw),
        circuit_id=circuit_id,
    )


def _serialize_state(state: dict[str, object]) -> bytes:
    output = bytearray(_STATE_MAGIC)
    output.append(1)
    for name in (
        "policy_result", "effective_directive", "complete", "membership", "absence",
        "active", "exception_present", "exception_authorized", "economic_mutation",
        "clearance_marker_before", "clearance_marker_after",
    ):
        output.extend(bytes((int(state[name]),)))
    for name in (
        "epoch", "sequence_before", "rule_effective_time", "event_time", "observation_time",
        "decision_time", "read_time", "write_time", "exception_valid_from",
        "exception_valid_until", "sequence_after",
    ):
        output.extend(_u64(int(state[name])))
    for name in (
        "decision_index", "decision_count", "read_access_index", "write_access_index",
        "access_count", "read_decision_index", "write_decision_index",
    ):
        output.extend(_u32(int(state[name])))
    output.extend(bytes((int(state["read_mode"]), int(state["write_mode"]))))
    for name in ("clearance_count_before", "clearance_count_after"):
        output.extend(_u64(int(state[name])))
    for name in _STATE_DIGEST_NAMES:
        output.extend(bytes(state[name]))
    if len(output) != _STATE_BYTES:
        raise AssertionError(f"state serialization length {len(output)}")
    return bytes(output)


def _synthetic_acceptance(
    base: MinimalProofAcceptanceV1,
    directive: int,
    *,
    exception_valid_until: int | None = None,
) -> MinimalProofAcceptanceV1:
    values = dict(base.statement.values)
    state = dict(base.statement.state_values)
    policy = _DIRECTIVE_POLICY[directive]
    complete, membership, absence, active, exception_present, exception_authorized = _DIRECTIVE_FLAGS[directive]
    values.update(
        complete=complete,
        authoritative_membership=membership,
        authoritative_absence=absence,
        active=active,
    )
    state.update(
        policy_result=policy,
        effective_directive=directive,
        complete=complete,
        membership=membership,
        absence=absence,
        active=active,
        exception_present=exception_present,
        exception_authorized=exception_authorized,
        clearance_marker_after=int(bool(int(state["clearance_marker_before"]) or directive in (1, 5))),
        clearance_count_after=int(state["clearance_count_before"]) + int(directive in (1, 5)),
    )
    if directive == 5:
        exception_id = _sha(b"BL/TEST/EXCEPTION-ID/v1\x00", base.statement.request_id)
        exception_scope_id = _sha(b"BL/TEST/EXCEPTION-SCOPE/v1\x00", base.statement.request_id)
        values["exception_id"] = exception_id
        values["exception_scope_id"] = exception_scope_id
        state["exception_id"] = exception_id
        state["exception_scope_id"] = exception_scope_id
        state["exception_valid_from"] = int(state["event_time"]) - 1
        state["exception_valid_until"] = (
            int(state["decision_time"]) + 1
            if exception_valid_until is None else exception_valid_until
        )
    else:
        sentinel = b"\xe0" + bytes(63)
        values["exception_id"] = sentinel
        values["exception_scope_id"] = sentinel
        state["exception_id"] = sentinel
        state["exception_scope_id"] = sentinel
        state["exception_valid_from"] = 0
        state["exception_valid_until"] = 0
    decision_id = _sha(
        b"BL/NATIVE-V3/MINIMAL-DECISION/v1\x00",
        bytes(values["request_id"]), bytes(values["source_root_id"]),
        bytes(values["completeness_id"]), bytes((policy, directive)),
        bytes(values["exception_id"]),
    )
    values["decision_id"] = decision_id
    state["decision_id"] = decision_id
    state["read_decision_id"] = decision_id
    state["write_decision_id"] = decision_id
    state["write_key"] = decision_id
    state["after_audit_head"] = _sha(
        b"BL/NATIVE-V3/MINIMAL-AUDIT-HEAD/v1\x00",
        bytes(state["before_audit_head"]), decision_id, bytes((directive,)),
    )
    state["after_continuity_root"] = _sha(
        b"BL/NATIVE-V3/MINIMAL-CONTINUITY-ROOT/v1\x00",
        bytes(state["before_continuity_root"]), bytes(values["source_root_id"]), decision_id,
    )
    state["write_after"] = state["after_audit_head"]
    state_bytes = _serialize_state(state)
    values["state_commitment_bytes"] = state_bytes
    values["state_after_id"] = _sha(
        b"BL/NATIVE-V3/MINIMAL-STATE-ID/v1\x00", b"\x01", state_bytes,
    )
    statement = bytearray()
    statement.extend(bytes((int(values["protocol_version"]),)))
    statement.extend(_PROOF_ROLE)
    for name in _STATEMENT_DIGEST_NAMES:
        statement.extend(bytes(values[name]))
    statement.extend(_u64(int(values["epoch"])))
    statement.extend(_u64(int(values["sequence_before"])))
    for name in ("active", "complete", "authoritative_membership", "authoritative_absence"):
        statement.extend(bytes((int(values[name]),)))
    statement.extend(state_bytes)
    parsed = _parse_statement(bytes(statement))
    return MinimalProofAcceptanceV1(
        statement=parsed,
        artifact_sha256=base.artifact_sha256,
        artifact_digest=base.artifact_digest,
        artifact_bytes=base.artifact_bytes,
        circuit_id=_CIRCUIT_ID,
    )


def _new_store(directory: str, acceptance: MinimalProofAcceptanceV1, **kwargs: object) -> MinimalClearanceStateStoreV1:
    return MinimalClearanceStateStoreV1(
        path=Path(directory) / "clearance.sqlite3",
        verifier=StaticMinimalClearanceVerifier(acceptance),
        **kwargs,
    )


def _corrupt_transition_kind(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("DROP TRIGGER IF EXISTS minimal_proof_transition_no_update")
        connection.execute(
            "ALTER TABLE minimal_proof_clearance_transitions "
            "RENAME TO minimal_proof_clearance_transitions_corrupt_copy"
        )
        connection.execute(
            """
            CREATE TABLE minimal_proof_clearance_transitions (
                sequence_after INTEGER PRIMARY KEY,
                transition_kind TEXT NOT NULL,
                operation_digest BLOB NOT NULL UNIQUE,
                state_binding_before BLOB NOT NULL,
                state_binding_after BLOB NOT NULL,
                payment_root_before BLOB NOT NULL,
                payment_root_after BLOB NOT NULL,
                settled_batch_count_before INTEGER NOT NULL,
                settled_batch_count_after INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO minimal_proof_clearance_transitions "
            "SELECT * FROM minimal_proof_clearance_transitions_corrupt_copy"
        )
        connection.execute("DROP TABLE minimal_proof_clearance_transitions_corrupt_copy")
        connection.execute(
            "UPDATE minimal_proof_clearance_transitions SET transition_kind='SETTLEMENT'"
        )
        connection.commit()


class MinimalClearanceProofStateTests(unittest.TestCase):
    def test_acceptance_roundtrip_and_five_directive_state_ownership(self) -> None:
        base = _base_acceptance()
        self.assertEqual(parse_acceptance_bytes(base.canonical_bytes()), base)
        for directive in range(1, 6):
            acceptance = _synthetic_acceptance(base, directive)
            with tempfile.TemporaryDirectory(prefix="blind-ledger-directive-") as directory:
                store = _new_store(directory, acceptance)
                try:
                    before = store.snapshot()
                    receipt = store.apply_acceptance(acceptance)
                    after = store.snapshot()
                    store.verify_integrity()
                    self.assertEqual(receipt.effective_directive, directive)
                    self.assertEqual(receipt.policy_result, _DIRECTIVE_POLICY[directive])
                    self.assertEqual(after.payment_root, before.payment_root)
                    self.assertEqual(after.settled_batch_count, before.settled_batch_count)
                    if directive in (1, 5):
                        self.assertNotEqual(after.clearance_root, before.clearance_root)
                        self.assertEqual(after.clearance_count, before.clearance_count + 1)
                    else:
                        self.assertEqual(after.clearance_root, before.clearance_root)
                        self.assertEqual(after.clearance_count, before.clearance_count)
                    with closing(sqlite3.connect(store.path)) as connection:
                        row = connection.execute(
                            "SELECT transition_kind, payment_root_before, payment_root_after, "
                            "settled_batch_count_before, settled_batch_count_after "
                            "FROM minimal_proof_clearance_transitions"
                        ).fetchone()
                    self.assertEqual(row[0], "DIRECT_CLEARANCE")
                    self.assertEqual(bytes(row[1]), bytes(row[2]))
                    self.assertEqual(row[3], row[4])
                finally:
                    store.close()

    def test_exact_retry_conflict_and_rejected_verifier_do_not_mutate(self) -> None:
        base = _base_acceptance()
        with tempfile.TemporaryDirectory(prefix="blind-ledger-retry-") as directory:
            store = _new_store(directory, base)
            try:
                before = store.snapshot()
                receipt = store.apply_acceptance(base)
                retry = store.apply_acceptance(base)
                self.assertEqual(retry.canonical_bytes(), receipt.canonical_bytes())
                conflicting = replace(base, artifact_sha256=b"\x99" * 32)
                with self.assertRaises(MinimalClearanceProofStateError) as conflict:
                    store.apply_acceptance(conflicting)
                self.assertIn("conflicting_retry", str(conflict.exception))
                with closing(sqlite3.connect(store.path)) as connection:
                    count = connection.execute("SELECT COUNT(*) FROM minimal_proof_clearance_requests").fetchone()[0]
                self.assertEqual(count, 1)
                self.assertEqual(store.snapshot().sequence, before.sequence + 1)
            finally:
                store.close()

        with self.assertRaisesRegex(MinimalClearanceProofStateError, "proof_exception_interval"):
            _synthetic_acceptance(
                base,
                5,
                exception_valid_until=int(base.statement.state("decision_time")) - 1,
            )

        class RejectingVerifier:
            def expected_statement(self) -> bytes:
                return base.statement.statement_bytes

            def verify(self, artifact_path: Path) -> MinimalProofAcceptanceV1:
                raise MinimalClearanceProofStateError("synthetic_verifier_rejected")

        with tempfile.TemporaryDirectory(prefix="blind-ledger-reject-") as directory:
            store = MinimalClearanceStateStoreV1(
                path=Path(directory) / "clearance.sqlite3",
                verifier=RejectingVerifier(),
            )
            try:
                before = store.snapshot()
                with self.assertRaises(MinimalClearanceProofStateError):
                    store.submit(_ARTIFACT)
                self.assertEqual(store.snapshot(), before)
            finally:
                store.close()

    def test_fault_boundaries_roll_back_without_partial_rows(self) -> None:
        base = _base_acceptance()
        for stage in ("before_transaction", "after_replay_reservation", "after_state_write", "after_audit_write", "before_receipt_commit"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(prefix="blind-ledger-fault-") as directory:
                def fail(observed: str, expected: str = stage) -> None:
                    if observed == expected:
                        raise RuntimeError(observed)

                store = _new_store(directory, base, before_fault=fail)
                try:
                    before = store.snapshot()
                    with self.assertRaises(RuntimeError):
                        store.apply_acceptance(base)
                    self.assertEqual(store.snapshot(), before)
                    store.verify_integrity()
                    with closing(sqlite3.connect(store.path)) as connection:
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM minimal_proof_clearance_requests").fetchone()[0], 0)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM minimal_proof_clearance_audit").fetchone()[0], 0)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM minimal_proof_clearance_transitions").fetchone()[0], 0)
                finally:
                    store.close()

    def test_post_commit_indeterminate_reopens_and_exact_retry_converges(self) -> None:
        base = _base_acceptance()
        with tempfile.TemporaryDirectory(prefix="blind-ledger-indeterminate-") as directory:
            def fail_after_commit(_: str) -> None:
                raise RuntimeError("post_commit_uncertain")

            store = _new_store(directory, base, after_commit_fault=fail_after_commit)
            try:
                with self.assertRaises(MinimalClearanceIndeterminateError):
                    store.apply_acceptance(base)
            finally:
                store.close()
            reopened = _new_store(directory, base)
            try:
                receipt = reopened.apply_acceptance(base)
                reopened.verify_integrity()
                self.assertEqual(receipt.sequence_after, base.statement.sequence_before + 1)
                self.assertEqual(reopened.snapshot().clearance_count, 1)
            finally:
                reopened.close()

    def test_two_exact_writers_converge_to_one_transition(self) -> None:
        base = _base_acceptance()
        with tempfile.TemporaryDirectory(prefix="blind-ledger-concurrency-") as directory:
            store_one = _new_store(directory, base)
            store_two = _new_store(directory, base)
            try:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [
                        executor.submit(store_one.apply_acceptance, base),
                        executor.submit(store_two.apply_acceptance, base),
                    ]
                    receipts = [future.result() for future in futures]
                self.assertEqual(receipts[0].canonical_bytes(), receipts[1].canonical_bytes())
                store_one.verify_integrity()
                with closing(sqlite3.connect(store_one.path)) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM minimal_proof_clearance_requests").fetchone()[0], 1)
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM minimal_proof_clearance_transitions").fetchone()[0], 1)
            finally:
                store_one.close()
                store_two.close()

    def test_backup_restart_and_corruption_reject(self) -> None:
        base = _base_acceptance()
        with tempfile.TemporaryDirectory(prefix="blind-ledger-recovery-") as directory:
            root = Path(directory)
            store = _new_store(directory, base)
            store.apply_acceptance(base)
            backup = root / "backup.sqlite3"
            recovered_path = root / "recovered.sqlite3"
            store.create_backup(backup)
            recovered = store.recover_from_backup(backup_path=backup, recovered_path=recovered_path)
            try:
                retry = recovered.apply_acceptance(base)
                recovered.verify_integrity()
                self.assertEqual(retry.sequence_after, 12)
            finally:
                recovered.close()
            verifier_store = _new_store(directory, base)
            store.close()
            _corrupt_transition_kind(root / "clearance.sqlite3")
            with self.assertRaises(MinimalClearanceProofStateError):
                MinimalClearanceStateStoreV1(
                    path=root / "clearance.sqlite3",
                    verifier=StaticMinimalClearanceVerifier(base),
                )

            bad_backup = root / "bad-backup.sqlite3"
            shutil.copy2(backup, bad_backup)
            try:
                _corrupt_transition_kind(bad_backup)
                with self.assertRaises(MinimalClearanceProofStateError):
                    verifier_store.recover_from_backup(
                        backup_path=bad_backup,
                        recovered_path=root / "bad-recovered.sqlite3",
                    )
            finally:
                verifier_store.close()


if __name__ == "__main__":
    unittest.main()
