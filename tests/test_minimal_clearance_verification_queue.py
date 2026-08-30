import io
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import app.minimal_clearance_composition as composition
from app.minimal_clearance_verification_queue import _build_statement, _compute_batch_root_from_refs
from app.minimal_clearance_composition import (
    CompositionConfigV2,
    CompositionConflictError,
    StateDispositionControl,
    resolve_effective_directive,
)
from app.minimal_clearance_verification_queue import (
    BatchVerifierResult,
    OperationTemplate,
    QueueConfig,
    QueueIntegrityError,
    QueueLeaseError,
    VerificationQueueError,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)
from app.minimal_clearance_verification_queue_independent import read_verified_batch, verify_database


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


def _new_store(root: Path, clock: _Clock, *, capacity: int = 100, before_fault=None):
    config = QueueConfig("state-test-v10", capacity)
    composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=capacity)
    owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
    store = _VerificationQueueStore(
        path=root / "state.sqlite",
        config=config,
        owner=owner,
        clock=clock,
        before_fault=before_fault,
        composition_config=composition_config,
    )
    return config, composition_config, owner, store


def _prepare(store: _VerificationQueueStore, config: QueueConfig, clock: _Clock, *, proof: bytes = b"volatile-proof", duration: int = 60_000):
    template = OperationTemplate(
        "shared-assertion",
        1,
        config.profile_version,
        clock.now - 100,
        clock.now + duration,
    )
    batch = store.issue_batch(template=template)
    store.submit_batch_handoff(issued_batch=batch, proof_stream=io.BytesIO(proof), declared_length=len(proof))
    return batch


def _controls(operation_refs: tuple[bytes, ...], policies: tuple[str, ...] | None = None) -> dict[bytes, StateDispositionControl]:
    if policies is None:
        policies = ("PASS", "MISSING", "AMBIGUOUS", "FAIL", "FAIL") * 20
    if len(policies) != 100:
        raise AssertionError(len(policies))
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
        control = StateDispositionControl(
            operation_ref,
            policy,
            exception,
            bytes([index + 1]) * 64 if exception else bytes(64),
            profile,
            state_id,
            state_bytes,
            1,
            index,
            continuity,
            audit,
            clearance,
            marker,
            count,
        )
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
    def __init__(self, config: QueueConfig, *, accepted: bool = True, source_authenticated: bool = True, result_code: str | None = None) -> None:
        self.config = config
        self.accepted = accepted
        self.source_authenticated = source_authenticated
        self.result_code = result_code or ("accepted" if accepted and source_authenticated else "rejected")
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, batch):
        self.calls += 1
        while stream.read(23):
            pass
        return BatchVerifierResult(
            self.accepted,
            self.source_authenticated,
            batch.proof_statement,
            batch.batch_root,
            self.config.source_auth_profile,
            self.config.source_key_epoch,
            self.result_code,
            self.config.qualification_flags,
        )


class _MalformedVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, _batch):
        self.calls += 1
        while stream.read(23):
            pass
        return {}


class _DispositionPort:
    def __init__(self, *, policies: tuple[str, ...] | None = None) -> None:
        self.policies = policies
        self.calls: list[tuple[bytes, tuple[bytes, ...], object]] = []

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome):
        self.calls.append((batch_id, operation_refs, verification_outcome))
        return _controls(operation_refs, self.policies)


def _counts(path: Path) -> dict[str, int]:
    with closing(sqlite3.connect(str(path))) as connection:
        return {
            "queue_batches": int(connection.execute("SELECT COUNT(*) FROM queue_batches").fetchone()[0]),
            "queue_members": int(connection.execute("SELECT COUNT(*) FROM queue_members").fetchone()[0]),
            "queue_leases": int(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0]),
            "queue_attempts": int(connection.execute("SELECT COUNT(*) FROM queue_attempts").fetchone()[0]),
            "queue_results": int(connection.execute("SELECT COUNT(*) FROM queue_results").fetchone()[0]),
            "queue_transitions": int(connection.execute("SELECT COUNT(*) FROM queue_transitions").fetchone()[0]),
            "composition_transactions": int(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0]),
            "composition_events": int(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0]),
            "composition_outbox": int(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0]),
        }


class QueueV11Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config, self.composition_config, self.owner, self.store = _new_store(self.root, self.clock)

    def tearDown(self) -> None:
        self.store._close()
        self.owner.close()
        self.temp.cleanup()

    def test_state_database_derives_profile9_statement_without_durable_copy(self) -> None:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            self.assertEqual(tables, {"queue_metadata", "queue_batches", "queue_members", "queue_leases", "queue_attempts", "queue_results", "queue_transitions", "composition_meta", "composition_transactions", "composition_events", "composition_outbox"})
            self.assertEqual(connection.execute("SELECT schema_version FROM queue_metadata").fetchone()[0], 11)
            self.assertEqual(connection.execute("SELECT schema_version FROM composition_meta").fetchone()[0], 4)
            self.assertEqual(connection.execute("PRAGMA foreign_key_list(composition_transactions)").fetchone()[2], "queue_members")
            self.assertEqual(tuple(row[1] for row in connection.execute("PRAGMA table_info(queue_batches)")), ("batch_id", "batch_root", "session_ref", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "approved_source_registry_root", "qualification_flags", "identity_digest", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"))
            self.assertNotIn("proof_statement", tuple(row[1] for row in connection.execute("PRAGMA table_info(queue_results)")))
        batch = _prepare(self.store, self.config, self.clock)
        expected = (
            b"BL-R100-STMT-V2\x00"
            + (2).to_bytes(2, "little")
            + (304).to_bytes(2, "little")
            + batch.session_ref
            + batch.batch_root
            + (9).to_bytes(4, "little")
            + bytes((1, 0, 0, 0))
            + (1).to_bytes(4, "little")
            + batch.template.valid_from_ms.to_bytes(8, "little")
            + batch.template.valid_until_ms.to_bytes(8, "little")
            + bytes.fromhex("A85A1A5F4AD3E9B777E5F9043F8B43F5C0018F8A6AAB51359AEDFE1264091C0C0F973C9D4E3BF9064383F0DB9BEB2606BAD62B92677DB0588006475236BD83CF")
            + bytes.fromhex("609A2A9D66E3D2E3332E86DE5BE4720699C1ADE901C62E6954715ABD1CF64E197F315A32EEB972DEADAEDAB4D4E8882E00AE9EA9EE23575CDED3498429A802DF")
        )
        self.assertEqual(len(batch.session_ref), 64)
        self.assertNotEqual(batch.session_ref, bytes(64))
        self.assertEqual(len(batch.proof_statement), 304)
        self.assertEqual(batch.proof_statement, expected)
        self.assertEqual(batch.proof_statement[20:84], batch.session_ref)
        self.assertEqual(batch.proof_statement[84:148], batch.batch_root)
        self.assertEqual(batch.proof_statement[148:152], b"\x09\x00\x00\x00")
        self.assertEqual(batch.proof_statement[152:156], b"\x01\x00\x00\x00")
        self.assertEqual(batch.proof_statement[156:160], b"\x01\x00\x00\x00")
        self.assertEqual(self.config.profile_version, "BLIND-ZKBPP-CUNRUH-RANGE100-V9")
        self.assertEqual(self.config.profile_epoch, 9)
        self.assertNotIn(batch.proof_statement, (self.root / "state.sqlite").read_bytes())

    def test_profile9_statement_rejects_old_profile_zero_identity_and_invalid_window(self) -> None:
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_epoch"):
            QueueConfig("old-profile-epoch", 100, profile_epoch=6)
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_version"):
            QueueConfig("old-profile-version", 100, profile_version="BLIND-ZKBPP-CUNRUH-RANGE100-V6")
        with self.assertRaisesRegex(VerificationQueueError, "source_auth_profile"):
            QueueConfig("old-source-profile", 100, source_auth_profile="BLIND-MLDSA87-SOURCE-AUTH-V1-R100-V6-UNQUALIFIED")
        with self.assertRaisesRegex(VerificationQueueError, "queue_profile_invalid"):
            QueueConfig("legacycfg", 100, profile_digest=bytes.fromhex("D8F4730213839DDF027AF1B122AED5D80F4D8A725E9493C0CED59A59F560B12E97B6BAC28A373FA80CEC1DB4C6E0FBCCFD9ED2E37B3D0086A72D17F32F42EDF2"))
        batch = _prepare(self.store, self.config, self.clock)
        with self.assertRaisesRegex(QueueIntegrityError, "session_ref"):
            _build_statement(batch_root=batch.batch_root, session_ref=bytes(64), valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms)
        with self.assertRaisesRegex(QueueIntegrityError, "batch_root"):
            _build_statement(batch_root=bytes(64), session_ref=batch.session_ref, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms)
        with self.assertRaisesRegex(QueueIntegrityError, "session_ref"):
            _build_statement(batch_root=batch.batch_root, session_ref=batch.session_ref[:-1], valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms)
        with self.assertRaisesRegex(QueueIntegrityError, "proof_statement"):
            replace(batch, proof_statement=batch.proof_statement[:-1])
        for start, end in ((batch.template.valid_from_ms, batch.template.valid_from_ms), (batch.template.valid_until_ms, batch.template.valid_until_ms), (batch.template.valid_from_ms, batch.template.valid_from_ms + 3_600_001)):
            with self.subTest(start=start, end=end), self.assertRaisesRegex(QueueIntegrityError, "statement_window"):
                _build_statement(batch_root=batch.batch_root, session_ref=batch.session_ref, valid_from_ms=start, valid_until_ms=end)

        for offset in (0, 16, 18, 153, 176, 240):
            forged = bytearray(batch.proof_statement)
            forged[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(VerificationQueueError, "statement_binding"):
                replace(batch, proof_statement=bytes(forged))

    def test_exact_100_members_and_one_101_unit_attempt_record(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        work = self.store._claim_next_batch()
        self.assertIsNotNone(work)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_members WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], 100)
            attempt = connection.execute("SELECT reservation_before,reservation_after,proof_attempts,status FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)).fetchone()
            self.assertEqual(tuple(attempt), (0, 101, 101, "RESERVED"))
            self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 1))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)

    def test_accepted_batch_commits_queue_and_all_state_rows_once(self) -> None:
        batch = _prepare(self.store, self.config, self.clock, proof=b"raw_proof raw_signature frame_payload challenge_bytes opening_bytes response_bytes")
        verifier = _Verifier(self.config)
        port = _DispositionPort()
        result = self.store._process_one_batch(verifier=verifier, state_disposition_port=port)
        self.assertEqual((result.status, result.accepted_count, verifier.calls, len(port.calls)), ("VERIFIED", 100, 1, 1))
        outcome = port.calls[0][2]
        self.assertFalse(hasattr(outcome, "effective_directive"))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "VERIFIED")
            self.assertEqual(connection.execute("SELECT terminal_status,proof_accepted,source_authenticated FROM queue_results WHERE batch_id=?", (batch.batch_id,)).fetchone(), ("VERIFIED", 1, 1))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions WHERE status='APPLIED'").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events WHERE event_kind='APPLIED'").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox WHERE status='READY'").fetchone()[0], 100)
            self.assertEqual({row[0] for row in connection.execute("SELECT DISTINCT effective_directive FROM composition_transactions")}, {"CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"})
            self.assertEqual({row[0] for row in connection.execute("SELECT DISTINCT policy_result FROM composition_transactions")}, {"PASS", "MISSING", "AMBIGUOUS", "FAIL"})
        raw = (self.root / "state.sqlite").read_bytes()
        wal = self.root / "state.sqlite-wal"
        if wal.exists():
            raw += wal.read_bytes()
        for marker in (b"raw_proof", b"raw_signature", b"frame_payload", b"challenge_bytes", b"opening_bytes", b"response_bytes"):
            self.assertNotIn(marker, raw)
        self.assertNotIn(batch.proof_statement, raw)
        self.assertEqual(verify_database(self.root / "state.sqlite")["accepted_operation_count"], 100)
        reconstructed = read_verified_batch(self.root / "state.sqlite", batch.batch_id)
        self.assertEqual(len(reconstructed.jobs), 100)

    def test_verifier_acceptance_never_supplies_clearance(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        port = _DispositionPort(policies=("MISSING",) * 100)
        result = self.store._process_one_batch(verifier=_Verifier(self.config), state_disposition_port=port)
        self.assertEqual((result.status, result.accepted_count, len(port.calls)), ("VERIFIED", 100, 1))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT DISTINCT effective_directive FROM composition_transactions").fetchone()[0], "HOLD")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions WHERE policy_result='PASS'").fetchone()[0], 0)
        self.assertEqual(resolve_effective_directive("PASS"), "CLEAR")
        self.assertEqual(batch.batch_id, port.calls[0][0])

    def test_rejected_and_malformed_paths_do_not_call_state_port_or_compose(self) -> None:
        port = _DispositionPort()
        first = _prepare(self.store, self.config, self.clock)
        rejected = self.store._process_one_batch(verifier=_Verifier(self.config, accepted=False), state_disposition_port=port)
        second = _prepare(self.store, self.config, self.clock)
        held = self.store._process_one_batch(verifier=_MalformedVerifier(), state_disposition_port=port)
        self.assertEqual((rejected.status, held.status, len(port.calls)), ("REJECTED", "HELD", 0))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (first.batch_id,)).fetchone()[0], "REJECTED")
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (second.batch_id,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)

    def test_terminal_transaction_rolls_back_every_cross_table_stage_and_keeps_live_lease(self) -> None:
        labels = ("after_composition_transactions", "after_composition_events", "after_composition_outbox", "after_composition_meta", "before_composition_commit", "before_queue_commit")
        for label in labels:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                clock = _Clock()
                config, _composition_config, owner, store = _new_store(root, clock)
                try:
                    batch = _prepare(store, config, clock)
                    work = store._claim_next_batch()
                    controls = _controls(batch.operation_refs)
                    verifier_result = BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, config.source_auth_profile, config.source_key_epoch, "accepted", ())
                    store._before_fault = lambda actual, expected=label: (_ for _ in ()).throw(RuntimeError("injected")) if actual == expected else None
                    with self.assertRaisesRegex(RuntimeError, "injected"):
                        store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "LEASED")
                        self.assertEqual(connection.execute("SELECT status FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "RESERVED")
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 1)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_results").fetchone()[0], 0)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_events").fetchone()[0], 0)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)
                finally:
                    store._close()
                    owner.close()

    def test_stale_lease_token_is_fenced_without_any_state_write(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        work = self.store._claim_next_batch()
        controls = _controls(batch.operation_refs)
        verifier_result = BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", ())
        stale = replace(work, lease_token=bytes(32))
        with self.assertRaises(QueueLeaseError):
            self.store._complete_batch(stale, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        state = _counts(self.root / "state.sqlite")
        self.assertEqual((state["queue_results"], state["composition_transactions"], state["composition_events"], state["composition_outbox"], state["queue_leases"]), (0, 0, 0, 0, 1))

    def test_duplicate_replay_requires_complete_outbox_and_event_chain(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        work = self.store._claim_next_batch()
        controls = _controls(batch.operation_refs)
        verifier_result = BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", ())
        self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            saved_outbox = tuple(connection.execute("SELECT * FROM composition_outbox WHERE operation_ref=?", (batch.operation_refs[0],)).fetchone())
            connection.execute("DELETE FROM composition_outbox WHERE operation_ref=?", (batch.operation_refs[0],))
            connection.commit()
        with self.assertRaises(CompositionConflictError):
            self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("INSERT INTO composition_outbox VALUES (?,?,?,?,?,?,?,?)", saved_outbox)
            connection.execute("DROP TRIGGER composition_events_no_update")
            connection.execute("UPDATE composition_events SET event_digest=? WHERE operation_ref=?", (bytes(64), batch.operation_refs[0]))
            connection.commit()
        with self.assertRaises(CompositionConflictError):
            self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "VERIFIED")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 100)

    def test_duplicate_replay_fences_durable_identity_before_composition(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        work = self.store._claim_next_batch()
        controls = _controls(batch.operation_refs)
        verifier_result = BatchVerifierResult(True, True, batch.proof_statement, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", ())
        first = self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        duplicate = self.store._complete_batch(work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        self.assertEqual((first.status, duplicate.status, duplicate.accepted_count), ("VERIFIED", "VERIFIED", 100))

        def snapshot() -> tuple[tuple[tuple[str, int], ...], tuple[bytes | None, ...], tuple[bytes, ...]]:
            with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
                table_names = ("queue_batches", "queue_members", "queue_leases", "queue_attempts", "queue_results", "queue_transitions", "composition_transactions", "composition_events", "composition_outbox")
                counts = tuple((name, int(connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0])) for name in table_names)
                queue_root = connection.execute("SELECT head_root FROM queue_metadata WHERE id=1").fetchone()[0]
                composition_roots = connection.execute("SELECT event_head,state_continuity_root,state_audit_head,state_clearance_root,payment_root FROM composition_meta WHERE id=1").fetchone()
                roots = tuple(None if value is None else bytes(value) for value in (queue_root, *composition_roots))
                batch_roots = tuple(bytes(row[0]) for row in connection.execute("SELECT batch_root FROM queue_batches ORDER BY admission_seq"))
                return counts, roots, batch_roots

        before = snapshot()
        forged_attempt_work = replace(work, attempt=999)
        with self.assertRaises(QueueLeaseError) as attempt_error:
            self.store._complete_batch(forged_attempt_work, status="VERIFIED", verifier_result=verifier_result, state_controls=controls)
        self.assertEqual(str(attempt_error.exception), "completion_not_live")
        self.assertEqual(snapshot(), before)

        forged_template = replace(batch.template, assertion_identifier="forged-assertion")
        forged_root = _compute_batch_root_from_refs(forged_template, batch.operation_refs)
        forged_batch = replace(work.batch, template=forged_template, batch_root=forged_root, proof_statement=_build_statement(batch_root=forged_root, session_ref=work.batch.session_ref, valid_from_ms=forged_template.valid_from_ms, valid_until_ms=forged_template.valid_until_ms))
        forged_work = replace(work, batch=forged_batch)
        forged_result = BatchVerifierResult(True, True, forged_batch.proof_statement, forged_batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", ())
        with self.assertRaises(QueueLeaseError) as error:
            self.store._complete_batch(forged_work, status="VERIFIED", verifier_result=forged_result, state_controls=controls)
        self.assertEqual(str(error.exception), "completion_not_live")
        self.assertEqual(snapshot(), before)

    def test_startup_burns_a_live_session_and_never_resumes_it(self) -> None:
        batch = _prepare(self.store, self.config, self.clock)
        self.assertIsNotNone(self.store._claim_next_batch())
        self.store._close()
        self.owner.close()
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.root / "state.sqlite", config=self.config, owner=self.owner, clock=self.clock, composition_config=self.composition_config)
        self.assertEqual(self.store._startup_recovered_count, 1)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT status FROM queue_attempts WHERE batch_id=?", (batch.batch_id,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)

    def test_expired_active_lease_is_burned_before_another_batch_is_claimed(self) -> None:
        self.store._close()
        self.owner.close()
        self.temp.cleanup()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config, self.composition_config, self.owner, self.store = _new_store(self.root, self.clock, capacity=200)
        first = _prepare(self.store, self.config, self.clock, duration=300_000)
        second = _prepare(self.store, self.config, self.clock, duration=300_000)
        self.assertIsNotNone(self.store._claim_next_batch())
        self.clock.now += 61_000
        next_work = self.store._claim_next_batch()
        self.assertIsNotNone(next_work)
        self.assertEqual(self.store._last_claim_held_count, 1)
        self.assertEqual(next_work.batch.batch_id, second.batch_id)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (first.batch_id,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (second.batch_id,)).fetchone()[0], "LEASED")

    def test_no_authoritative_promotion_or_cross_store_process_api_remains(self) -> None:
        from app.minimal_clearance_composition import ClearanceCompositionStoreV2

        self.assertFalse(hasattr(ClearanceCompositionStoreV2, "process_verified_jobs"))
        self.assertFalse(hasattr(self.store, "_promote_candidates"))


if __name__ == "__main__":
    unittest.main()
