from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import io
import hashlib
import sqlite3
from pathlib import Path
import tempfile
import unittest

from pqcrypto.sign import ml_dsa_65

import app.minimal_clearance_composition as composition_module
from app.minimal_clearance_authoritative_assertion import (
    AuthoritativeAssertionError,
    AuthoritativeAssertionTemplateV1,
    AuthoritativeAssertionVerifierV1,
    AuthoritativeBatchStatementV1,
    AuthoritativeIssuedOperationV1,
    MEMBER_COUNT,
    RESERVATION_UNITS,
    VolatileSignatureHandoff,
    compute_batch_root,
    parse_result,
    signature_message,
)
from app.minimal_clearance_authoritative_assertion_independent import (
    IndependentAuthoritativeAssertionError,
    read_authoritative_batch,
    verify_authoritative_database,
)
from app.minimal_clearance_composition import (
    ClearanceCompositionStoreV2,
    CompositionConfigV2,
    CompositionIntegrityError,
    StateDispositionControl,
    build_synthetic_acknowledgment,
)
from app.minimal_clearance_composition_independent import verify_database


class _Receiver:
    def __init__(self, config: CompositionConfigV2) -> None:
        self.config = config
        self.calls = 0

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.calls += 1
        return build_synthetic_acknowledgment(envelope_bytes, config=self.config, idempotency_key=idempotency_key, accepted_ms=self.calls)


class _ChunkedStream:
    def __init__(self, value: bytes) -> None:
        self._value = bytearray(value)
        self.reads = 0
        self.closed = False

    def read(self, size: int) -> bytes:
        self.reads += 1
        if not self._value:
            return b""
        take = min(7, size, len(self._value))
        result = bytes(self._value[:take])
        del self._value[:take]
        return result

    def close(self) -> None:
        self.closed = True
        for index in range(len(self._value)):
            self._value[index] = 0
        self._value.clear()


class AuthoritativeAssertionV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_key, cls.secret_key = ml_dsa_65.generate_keypair()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-authoritative-v1-")
        self.root = Path(self.temp.name)
        self.config = CompositionConfigV2("authoritative-v1", b"q" * 64, capacity=128)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _store(self, name: str = "composition.sqlite") -> ClearanceCompositionStoreV2:
        return ClearanceCompositionStoreV2(path=self.root / name, config=self.config)

    def _templates(self, suffix: str = "") -> tuple[AuthoritativeAssertionTemplateV1, ...]:
        return tuple(AuthoritativeAssertionTemplateV1(f"assertion-{suffix}{index}", 1, "state-policy-v1", 0, 31_536_000_000) for index in range(MEMBER_COUNT))

    def _issue(self, store: ClearanceCompositionStoreV2, suffix: str = "") -> AuthoritativeBatchStatementV1:
        return store.issue_authoritative_batch(templates=self._templates(suffix))

    def _controls(self, batch: AuthoritativeBatchStatementV1) -> dict[bytes, StateDispositionControl]:
        profile = b"s" * 64
        zero = bytes(64)
        predecessor_id = predecessor_bytes = continuity = audit = clearance = zero
        controls: dict[bytes, StateDispositionControl] = {}
        for position, statement in enumerate(batch.statements):
            decision_id = bytes([position + 1]) * 64
            control = StateDispositionControl(
                statement.operation_ref,
                "MISSING",
                state_profile_identity=profile,
                predecessor_state_id=predecessor_id,
                predecessor_state_bytes=predecessor_bytes,
                sequence_before=position,
                predecessor_continuity_root=continuity,
                predecessor_audit_head=audit,
                predecessor_clearance_root=clearance,
                clearance_marker_before=0,
                clearance_count_before=0,
                decision_id=decision_id,
            )
            controls[statement.operation_ref] = control
            predecessor_id = control.state_after_id
            predecessor_bytes = control.state_after_bytes
            continuity = control.state_after_continuity_root
            audit = composition_module._sha(composition_module._STATE, audit, control.decision_id, b"HOLD")
            clearance = control.state_after_clearance_root
        return controls

    def _rebuild_batch(self, batch: AuthoritativeBatchStatementV1, statements: list[AuthoritativeIssuedOperationV1]) -> AuthoritativeBatchStatementV1:
        unsigned = tuple(AuthoritativeIssuedOperationV1(statement.operation_ref, statement.template, position, bytes(64)) for position, statement in enumerate(statements))
        batch_root = compute_batch_root(unsigned)
        rebound = tuple(AuthoritativeIssuedOperationV1(statement.operation_ref, statement.template, statement.batch_position, batch_root) for statement in unsigned)
        return AuthoritativeBatchStatementV1(rebound, batch_root, batch.source_key_epoch)

    def _signed_result(self, store: ClearanceCompositionStoreV2, batch: AuthoritativeBatchStatementV1):
        reservation = store.reserve_authoritative_batch(batch)
        signature = ml_dsa_65.sign(self.secret_key, signature_message(batch))
        result = AuthoritativeAssertionVerifierV1(public_key=self.public_key).verify(batch, io.BytesIO(signature), reservation=reservation, declared_length=len(signature))
        return signature, result

    def test_real_ml_dsa65_batch_applies_dispatches_backs_up_and_reconstructs(self) -> None:
        store = self._store()
        batch = self._issue(store)
        signature, result = self._signed_result(store, batch)
        self.assertTrue(result.assertion_accepted)
        results = store.process_authoritative_assertion(batch, result, state_controls=self._controls(batch))
        self.assertEqual(len(results), MEMBER_COUNT)
        self.assertTrue(all(item.status == "APPLIED" for item in results))
        self.assertEqual(store.snapshot()["state_sequence"], MEMBER_COUNT)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], MEMBER_COUNT)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], MEMBER_COUNT)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM authoritative_operations WHERE status='APPLIED'").fetchone()[0], MEMBER_COUNT)
            self.assertEqual(connection.execute("SELECT computational_units_used,statistical_units_used FROM authoritative_profile_ledger").fetchone(), (RESERVATION_UNITS, 0))
            columns = [str(row[1]).lower() for table in ("authoritative_operations", "authoritative_batches", "authoritative_results", "authoritative_profile_ledger") for row in connection.execute(f"PRAGMA table_info({table})")]
            self.assertFalse(any(column in {"signature", "signature_bytes", "public_key", "public_key_bytes", "secret_key", "secret_key_bytes", "message_digest", "source_digest", "artifact_digest"} for column in columns))
        self.assertNotIn(signature, store.path.read_bytes())
        self.assertNotIn(self.public_key, store.path.read_bytes())
        self.assertNotIn(hashlib.sha3_512(signature_message(batch)).digest(), store.path.read_bytes())
        self.assertEqual(verify_database(store.path, expected_config=self.config.as_json)["transaction_counts"], {"APPLIED": MEMBER_COUNT, "HELD": 0})
        self.assertEqual(verify_authoritative_database(store.path)["computational_units_used"], RESERVATION_UNITS)
        self.assertEqual(read_authoritative_batch(store.path, batch.batch_root).status, "APPLIED")
        receiver = _Receiver(self.config)
        dispatched = 0
        while True:
            work = store.claim_next_outbox(f"worker-{dispatched}")
            if work is None:
                break
            delivery = store.dispatch(work, receiver=receiver)
            self.assertEqual(delivery.status, "ACKNOWLEDGED")
            dispatched += 1
        self.assertEqual(dispatched, MEMBER_COUNT)
        backup = self.root / "backup.sqlite"
        recovered = self.root / "recovered.sqlite"
        store.create_backup(backup)
        recovered_store = ClearanceCompositionStoreV2.recover_from_backup(backup_path=backup, recovered_path=recovered, config=self.config)
        self.assertEqual(verify_database(recovered, expected_config=self.config.as_json)["transaction_counts"], {"APPLIED": MEMBER_COUNT, "HELD": 0})
        recovered_store.close()
        store.close()

    def test_bad_signature_holds_and_consumes_reservation_without_state_mutation(self) -> None:
        store = self._store()
        batch = self._issue(store)
        before = store.snapshot()
        reservation = store.reserve_authoritative_batch(batch)
        bad = bytearray(ml_dsa_65.sign(self.secret_key, signature_message(batch)))
        bad[0] ^= 1
        result = AuthoritativeAssertionVerifierV1(public_key=self.public_key).verify(batch, io.BytesIO(bytes(bad)), reservation=reservation, declared_length=len(bad))
        self.assertFalse(result.assertion_accepted)
        store.hold_authoritative_batch(batch, result)
        self.assertEqual(store.snapshot(), before)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT computational_units_used FROM authoritative_profile_ledger").fetchone()[0], RESERVATION_UNITS)
        self.assertEqual(read_authoritative_batch(store.path, batch.batch_root).status, "HELD")
        verify_database(store.path, expected_config=self.config.as_json)
        store.close()

    def test_state_chain_failure_rolls_back_all_100_members_after_acceptance(self) -> None:
        store = self._store()
        batch = self._issue(store)
        signature, result = self._signed_result(store, batch)
        self.assertTrue(signature)
        controls = self._controls(batch)
        target = batch.statements[1].operation_ref
        controls[target] = replace(controls[target], predecessor_state_id=b"x" * 64)
        before = store.snapshot()
        with self.assertRaises(CompositionIntegrityError) as raised:
            store.process_authoritative_assertion(batch, result, state_controls=controls)
        self.assertEqual(str(raised.exception), "composition_batch_state_chain")
        self.assertEqual(store.snapshot(), before)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT computational_units_used FROM authoritative_profile_ledger").fetchone()[0], RESERVATION_UNITS)
        store.close()

    def test_signature_stream_is_single_use_and_output_has_no_disposition(self) -> None:
        store = self._store()
        batch = self._issue(store)
        reservation = store.reserve_authoritative_batch(batch)
        signature = ml_dsa_65.sign(self.secret_key, signature_message(batch))
        stream = _ChunkedStream(signature)
        handoff = VolatileSignatureHandoff(stream, declared_length=len(signature))
        verifier = AuthoritativeAssertionVerifierV1(public_key=self.public_key)
        result = verifier.verify(batch, handoff, reservation=reservation)
        self.assertTrue(result.assertion_accepted)
        self.assertTrue(handoff.closed)
        self.assertTrue(stream.closed)
        self.assertGreater(stream.reads, 2)
        self.assertNotIn("policy_result", result.as_json)
        self.assertNotIn("effective_directive", result.as_json)
        with self.assertRaises(AuthoritativeAssertionError) as raised:
            verifier.verify(batch, handoff, reservation=reservation)
        self.assertEqual(str(raised.exception), "reservation_reuse")
        store.close()

    def test_signed_statement_mutations_are_held_without_partial_state(self) -> None:
        mutations = (
            ("operation_ref", lambda statements: [replace(statement, operation_ref=(b"m" * 32 if index == 0 else statement.operation_ref)) for index, statement in enumerate(statements)]),
            ("assertion_identifier", lambda statements: [replace(statement, template=replace(statement.template, assertion_identifier="mutated-assertion")) if index == 0 else statement for index, statement in enumerate(statements)]),
            ("state_profile_version", lambda statements: [replace(statement, template=replace(statement.template, state_profile_version="mutated-policy-v1")) for statement in statements]),
            ("validity_window", lambda statements: [replace(statement, template=replace(statement.template, valid_until_ms=31_535_999_999)) if index == 0 else statement for index, statement in enumerate(statements)]),
            ("approved_source_registry_root", lambda statements: [replace(statement, template=replace(statement.template, approved_source_registry_root=b"r" * 64)) if index == 0 else statement for index, statement in enumerate(statements)]),
            ("ordered_positions", lambda statements: [statements[1], statements[0], *statements[2:]]),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                store = self._store(f"mutation-{label}.sqlite")
                batch = self._issue(store, f"{label}-")
                mutated = self._rebuild_batch(batch, mutate(list(batch.statements)))
                signature = ml_dsa_65.sign(self.secret_key, signature_message(mutated))
                before = store.snapshot()
                reservation = store.reserve_authoritative_batch(batch)
                result = AuthoritativeAssertionVerifierV1(public_key=self.public_key).verify(batch, io.BytesIO(signature), reservation=reservation, declared_length=len(signature))
                self.assertFalse(result.assertion_accepted)
                store.hold_authoritative_batch(batch, result)
                self.assertEqual(store.snapshot(), before)
                with closing(sqlite3.connect(store.path)) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], 0)
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_outbox").fetchone()[0], 0)
                store.close()

    def test_malformed_or_oversized_signature_is_a_consuming_held_outcome(self) -> None:
        store = self._store()
        batch = self._issue(store)
        reservation = store.reserve_authoritative_batch(batch)
        malformed = AuthoritativeAssertionVerifierV1(public_key=self.public_key).verify(batch, io.BytesIO(b"x" * 3308), reservation=reservation, declared_length=3308)
        self.assertFalse(malformed.assertion_accepted)
        self.assertEqual(malformed.outcome_code, "MALFORMED")
        store.hold_authoritative_batch(batch, malformed)
        second = self._issue(store, "oversized-")
        second_reservation = store.reserve_authoritative_batch(second)
        oversized = AuthoritativeAssertionVerifierV1(public_key=self.public_key).verify(batch=second, signature_stream=io.BytesIO(b"x" * 3310), reservation=second_reservation, declared_length=3310)
        self.assertFalse(oversized.assertion_accepted)
        self.assertEqual(oversized.error_code, "signature_length")
        store.hold_authoritative_batch(second, oversized)
        verify_authoritative_database(store.path)
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("UPDATE authoritative_results SET receipt_digest=? WHERE batch_root=?", (b"z" * 64, second.batch_root))
            connection.commit()
        with self.assertRaises(IndependentAuthoritativeAssertionError):
            verify_authoritative_database(store.path)
        store.close()

    def test_statement_mutations_and_caller_root_or_cardinality_are_rejected(self) -> None:
        store = self._store()
        batch = self._issue(store)
        original = batch.statements[0]
        with self.assertRaises(AuthoritativeAssertionError):
            AuthoritativeBatchStatementV1(batch.statements[:-1], batch.batch_root)
        with self.assertRaises(AuthoritativeAssertionError):
            AuthoritativeBatchStatementV1(batch.statements + (original,), batch.batch_root)
        with self.assertRaises(AuthoritativeAssertionError):
            AuthoritativeBatchStatementV1((replace(original, operation_ref=b"x" * 32),) + batch.statements[1:], batch.batch_root)
        with self.assertRaises(AuthoritativeAssertionError):
            AuthoritativeBatchStatementV1((replace(original, batch_position=1),) + batch.statements[1:], batch.batch_root)
        with self.assertRaises(TypeError):
            store.issue_authoritative_batch(templates=self._templates(), batch_root=b"x" * 64)  # type: ignore[call-arg]
        store.close()

    def test_wrong_key_old_signature_and_profile_result_fields_fail_closed(self) -> None:
        store = self._store()
        batch = self._issue(store)
        reservation = store.reserve_authoritative_batch(batch)
        wrong_public, wrong_secret = ml_dsa_65.generate_keypair()
        signature = ml_dsa_65.sign(self.secret_key, signature_message(batch))
        wrong_key_result = AuthoritativeAssertionVerifierV1(public_key=wrong_public).verify(batch, io.BytesIO(signature), reservation=reservation, declared_length=len(signature))
        self.assertFalse(wrong_key_result.assertion_accepted)
        store.hold_authoritative_batch(batch, wrong_key_result)
        second = self._issue(store, "second-")
        second_reservation = store.reserve_authoritative_batch(second)
        old_result = AuthoritativeAssertionVerifierV1(public_key=self.public_key).verify(second, io.BytesIO(signature), reservation=second_reservation, declared_length=len(signature))
        self.assertFalse(old_result.assertion_accepted)
        store.hold_authoritative_batch(second, old_result)
        with self.assertRaises(AuthoritativeAssertionError):
            parse_result({**old_result.as_json, "effective_directive": "CLEAR"})
        self.assertNotEqual(batch.operation_refs, second.operation_refs)
        store.close()

    def test_reservation_is_nonrefundable_and_restart_requires_a_fresh_batch(self) -> None:
        store = self._store()
        batch = self._issue(store)
        store.reserve_authoritative_batch(batch)
        refs = batch.operation_refs
        store.close()
        recovered = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite", config=self.config)
        self.assertEqual(read_authoritative_batch(recovered.path, batch.batch_root).status, "HELD")
        with closing(sqlite3.connect(recovered.path)) as connection:
            self.assertEqual(connection.execute("SELECT computational_units_used FROM authoritative_profile_ledger").fetchone()[0], RESERVATION_UNITS)
        fresh = self._issue(recovered, "fresh-")
        self.assertNotEqual(refs, fresh.operation_refs)
        with self.assertRaises(AuthoritativeAssertionError) as raised:
            AuthoritativeAssertionVerifierV1(public_key=self.public_key).verify(fresh, io.BytesIO(b"x" * 3309), reservation=None, declared_length=3309)
        self.assertEqual(str(raised.exception), "reservation_required")
        recovered.close()

    def test_key_epoch_rotation_is_nested_and_nonrefundable(self) -> None:
        store = self._store()
        first = self._issue(store, "epoch-zero-")
        reservation = store.reserve_authoritative_batch(first)
        failed = AuthoritativeAssertionVerifierV1(public_key=self.public_key).verify(first, io.BytesIO(b"x" * 3309), reservation=reservation, declared_length=3309)
        store.hold_authoritative_batch(first, failed)
        store.rotate_authoritative_key_epoch(1)
        second = self._issue(store, "epoch-one-")
        self.assertEqual(second.source_key_epoch, 1)
        new_public, new_secret = ml_dsa_65.generate_keypair()
        second_reservation = store.reserve_authoritative_batch(second)
        signature = ml_dsa_65.sign(new_secret, signature_message(second))
        result = AuthoritativeAssertionVerifierV1(public_key=new_public, source_key_epoch=1).verify(second, io.BytesIO(signature), reservation=second_reservation, declared_length=len(signature))
        self.assertTrue(result.assertion_accepted)
        store.process_authoritative_assertion(second, result, state_controls=self._controls(second))
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT computational_units_used,statistical_units_used,last_key_epoch FROM authoritative_profile_ledger").fetchone(), (2 * RESERVATION_UNITS, 0, 1))
        store.close()

    def test_wrong_verifier_epoch_is_held_after_consuming_reservation(self) -> None:
        store = self._store()
        store.rotate_authoritative_key_epoch(1)
        batch = self._issue(store, "wrong-epoch-")
        reservation = store.reserve_authoritative_batch(batch)
        result = AuthoritativeAssertionVerifierV1(public_key=self.public_key, source_key_epoch=0).verify(batch, io.BytesIO(b"x" * 3309), reservation=reservation, declared_length=3309)
        self.assertFalse(result.assertion_accepted)
        self.assertEqual(result.error_code, "source_key_epoch_mismatch")
        self.assertEqual(result.source_key_epoch, batch.source_key_epoch)
        store.hold_authoritative_batch(batch, result)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT status FROM authoritative_batches WHERE batch_root=?", (batch.batch_root,)).fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT computational_units_used FROM authoritative_profile_ledger").fetchone()[0], RESERVATION_UNITS)
        store.close()

    def test_concurrent_submitters_have_one_finalization_and_one_duplicate(self) -> None:
        store = self._store()
        batch = self._issue(store, "concurrent-")
        signature, result = self._signed_result(store, batch)
        controls = self._controls(batch)

        def submit() -> tuple[bool, ...]:
            return tuple(item.duplicate_convergence for item in store.process_authoritative_assertion(batch, result, state_controls=controls))

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = [future.result() for future in (executor.submit(submit), executor.submit(submit))]
        self.assertEqual(sum(not all(outcome) for outcome in outcomes), 1)
        self.assertEqual(sum(all(outcome) for outcome in outcomes), 1)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM composition_transactions").fetchone()[0], MEMBER_COUNT)
            self.assertEqual(connection.execute("SELECT status FROM authoritative_batches WHERE batch_root=?", (batch.batch_root,)).fetchone()[0], "APPLIED")
        store.close()

    def test_lifetime_cap_accepts_exact_boundary_then_fails_closed(self) -> None:
        store = self._store()
        batch = self._issue(store)
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("UPDATE authoritative_profile_ledger SET computational_units_used=?", (2**32 - RESERVATION_UNITS,))
            connection.commit()
        store.reserve_authoritative_batch(batch)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(connection.execute("SELECT computational_units_used FROM authoritative_profile_ledger").fetchone()[0], 2**32)
        store.close()
        recovered = ClearanceCompositionStoreV2(path=self.root / "composition.sqlite", config=self.config)
        next_batch = self._issue(recovered, "cap-")
        with self.assertRaises(CompositionIntegrityError) as raised:
            recovered.reserve_authoritative_batch(next_batch)
        self.assertEqual(str(raised.exception), "authoritative_budget_exhausted")
        recovered.close()


if __name__ == "__main__":
    unittest.main()
