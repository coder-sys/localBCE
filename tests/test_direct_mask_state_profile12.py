import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
import json
from pathlib import Path
from unittest.mock import patch

import app.minimal_clearance_composition as composition
import app.minimal_clearance_verification_queue as queue
import app.minimal_clearance_verification_queue_independent as independent
from app.minimal_clearance_composition import CompositionConfigV2, StateDispositionControl
from app.minimal_clearance_verification_queue import (
    BatchVerifierResult,
    CIRCUIT_FINGERPRINT,
    OperationTemplate,
    PROOF_ATTEMPTS_CAP,
    PROOF_ATTEMPTS_PER_BATCH,
    PROFILE_FINGERPRINT,
    QueueBackpressureError,
    QueueConfig,
    QueueIntegrityError,
    QueueHeldError,
    VerificationQueueError,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
    _reserve_proof_attempt,
)
from app.minimal_clearance_verification_queue_independent import (
    _verify_connection,
    _verify_lifecycle,
    _verify_temporal_bindings,
    read_verified_batch,
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)
from app.minimal_clearance_verification_queue_independent import IndependentQueueError


_IMMUTABLE_V11_PRODUCT = Path(r"C:\Users\neers\Documents\Codex\2026-08-30\cleanup-v2\work\aggressive-obsolete-removal-20260907")
_V11_BUILDER = r'''
from pathlib import Path
import sys
sys.path.insert(0, str(Path.cwd()))
from app.minimal_clearance_composition import CompositionConfigV2
from app.minimal_clearance_verification_queue import QueueConfig, _QueueRuntimeOwnership, _VerificationQueueStore
root = Path(sys.argv[1])
config = QueueConfig("legacy-v11-shape", 100)
owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
store = _VerificationQueueStore(
    path=root / "state.sqlite",
    config=config,
    owner=owner,
    composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=100),
)
store._close()
owner.close()
'''


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


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


class Profile12StateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config = QueueConfig("profile12-focused", 100)
        self.composition_config = CompositionConfigV2(self.config.queue_id, self.config.digest, capacity=100)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.root / "state.sqlite", config=self.config, owner=self.owner, clock=self.clock, composition_config=self.composition_config)

    def tearDown(self) -> None:
        self.store._close()
        self.owner.close()
        self.temp.cleanup()

    def _template(self) -> OperationTemplate:
        return OperationTemplate("profile12-assertion", 1, self.config.profile_version, self.clock.now - 100, self.clock.now + 60_000)

    def _verified_batch(self, *, valid_from_ms: int | None = None, valid_until_ms: int | None = None) -> object:
        start = self.clock.now - 100 if valid_from_ms is None else valid_from_ms
        end = self.clock.now + 120_000 if valid_until_ms is None else valid_until_ms
        batch = self.store.issue_batch(template=OperationTemplate("profile12-assertion", 1, self.config.profile_version, start, end))
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
        work = self.store._claim_next_batch()
        self.assertIsNotNone(work)
        result = BatchVerifierResult(True, True, batch.proof_context, batch.public_coin, batch.batch_root, self.config.source_auth_profile, self.config.source_key_epoch, "accepted", self.config.qualification_flags)
        self.store._complete_batch(work, status="VERIFIED", verifier_result=result, state_controls=_controls(batch.operation_refs))
        return batch

    def _copy_state(self, name: str) -> Path:
        path = self.root / name
        path.write_bytes((self.root / "state.sqlite").read_bytes())
        return path

    def _rehash_transitions(self, path: Path) -> None:
        with closing(sqlite3.connect(str(path))) as connection:
            rows = connection.execute("SELECT sequence,event_bytes FROM queue_transitions ORDER BY sequence").fetchall()
            queue_id, config_digest = connection.execute("SELECT queue_id,config_digest FROM queue_metadata WHERE id=1").fetchone()
            expected = queue._sha3(queue._GENESIS, str(queue_id).encode("ascii"), bytes(config_digest))
            connection.execute("DROP TRIGGER queue_transitions_no_update")
            for sequence, event_bytes in rows:
                digest = queue._sha3(queue._EVENT, queue._u64(int(sequence)), bytes(event_bytes))
                after = queue._sha3(queue._HEAD, expected, queue._u64(int(sequence)), digest)
                connection.execute("UPDATE queue_transitions SET before_root=?,after_root=?,event_digest=? WHERE sequence=?", (expected, after, digest, sequence))
                expected = after
            connection.execute("UPDATE queue_metadata SET head_root=? WHERE id=1", (expected,))
            connection.execute(dict(queue._TRIGGER_DEFS)["queue_transitions_no_update"])
            connection.commit()

    def _set_event_time(self, path: Path, sequence: int, at_ms: object) -> None:
        with closing(sqlite3.connect(str(path))) as connection:
            raw = connection.execute("SELECT event_bytes FROM queue_transitions WHERE sequence=?", (sequence,)).fetchone()[0]
            event = json.loads(bytes(raw).decode("ascii"))
            event["at_ms"] = at_ms
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("ascii")
            connection.execute("DROP TRIGGER queue_transitions_no_update")
            connection.execute("UPDATE queue_transitions SET event_bytes=? WHERE sequence=?", (encoded, sequence))
            connection.execute(dict(queue._TRIGGER_DEFS)["queue_transitions_no_update"])
            connection.commit()
        self._rehash_transitions(path)

    def _assert_all_entrypoints_reject(self, path: Path, code: str, *, destination_name: str) -> None:
        raw = path.read_bytes()
        checks = (
            ("verify_database", lambda: verify_database(path)),
            ("read_verified_batch", lambda: read_verified_batch(path)),
            ("verify_export_bytes", lambda: verify_export_bytes(raw)),
        )
        for name, check in checks:
            with self.subTest(entrypoint=name):
                with self.assertRaisesRegex(Exception, code):
                    check()
                self.assertEqual(path.read_bytes(), raw)
        destination = self.root / destination_name
        with self.assertRaisesRegex(Exception, code):
            restore_export_to_fresh_database(export_bytes=raw, destination=destination)
        self.assertEqual(path.read_bytes(), raw)
        self.assertFalse(destination.exists())

    def test_independent_context_kat_and_runtime_context_are_exact(self) -> None:
        self.assertEqual(queue.PROFILE12_CONTEXT_KAT.hex(), "931fee1e981d0c844438d08662f6853cc62db7b6ac33a789b82032b33a764997677a505644a5e86085b871ac929c4c36667460883cf3d50b658dc50223c1417d")
        self.assertEqual(len(queue._PROFILE12_CIRCUIT_PREIMAGE), 120)
        self.assertEqual(len(queue._PROFILE12_PROFILE_PREIMAGE), 248)
        self.assertEqual(CIRCUIT_FINGERPRINT.hex(), "01ee8be0a1b1bbb9957a9dcbfdc1f15f510226505a735d95f9b15e73de16161bf462522589824a3f0d0193d67aaf43c97736d24e4a00b9da655403cefd38f4a8")
        self.assertEqual(PROFILE_FINGERPRINT.hex(), "306885c3f4dba50a14bd7aa9e51ce90d4b29d750d813980ed801ba2aff0159e5b256385357219c1e848f55bff8c020d08c5c59f3b63bc5a3b32b388ff794023a")
        self.assertEqual(independent._CIRCUIT, CIRCUIT_FINGERPRINT)
        self.assertEqual(independent._PROFILE, PROFILE_FINGERPRINT)
        self.assertEqual(queue._profile12_context(session_ref=bytes(range(64)), ordered_batch_root=bytes(range(64, 128)), public_coin=bytes(range(96)), valid_from_ms=6000, valid_until_ms=9000), queue.PROFILE12_CONTEXT_KAT)
        batch = self.store.issue_batch(template=self._template())
        self.assertEqual(batch.proof_context, queue._profile12_context(session_ref=batch.session_ref, ordered_batch_root=batch.batch_root, public_coin=batch.public_coin, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms))
        self.assertNotIn(batch.proof_context, (self.root / "state.sqlite").read_bytes())
        with self.assertRaisesRegex(VerificationQueueError, "session_ref"):
            queue._profile12_context(session_ref=bytes(64), ordered_batch_root=batch.batch_root, public_coin=batch.public_coin, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms)
        with self.assertRaisesRegex(VerificationQueueError, "batch_root"):
            queue._profile12_context(session_ref=batch.session_ref, ordered_batch_root=bytes(64), public_coin=batch.public_coin, valid_from_ms=batch.template.valid_from_ms, valid_until_ms=batch.template.valid_until_ms)

    def test_profile12_serializer_and_context_binding_matrix(self) -> None:
        template = OperationTemplate(
            "profile12-serializer",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + 60_000,
            bytes([7]) * 64,
            ("alpha", "zeta"),
        )
        batch = self.store.issue_batch(template=template)
        self.assertEqual(json.loads(self.config.canonical_bytes.decode("ascii")), self.config.as_json)
        self.assertEqual(json.loads(template.canonical_bytes.decode("ascii")), template.as_json)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            metadata = tuple(connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone())
            batch_row = tuple(connection.execute("SELECT * FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone())
            members = tuple(tuple(row) for row in connection.execute("SELECT * FROM queue_members WHERE batch_id=? ORDER BY batch_position", (batch.batch_id,)).fetchall())
        parsed_config = independent._parse_config(bytes(metadata[3]), self.config.as_json)
        self.assertEqual(parsed_config, self.config.as_json)
        self.assertEqual(independent._template_bytes(batch_row), template.canonical_bytes)
        self.assertEqual(independent._expected_batch_root(batch_row, members), batch.batch_root)
        self.assertEqual(queue._compute_batch_root_from_refs(template, batch.operation_refs), batch.batch_root)
        self.assertEqual(independent._identity_digest(batch_row, members, parsed_config), batch.identity_digest)

        base_context_args = {
            "session_ref": batch.session_ref,
            "batch_root": batch.batch_root,
            "public_coin": batch.public_coin,
            "valid_from_ms": template.valid_from_ms,
            "valid_until_ms": template.valid_until_ms,
        }
        context_mutations = {
            "session_ref": bytes([batch.session_ref[0] ^ 1]) + batch.session_ref[1:],
            "batch_root": bytes([batch.batch_root[0] ^ 1]) + batch.batch_root[1:],
            "public_coin": bytes([batch.public_coin[0] ^ 1]) + batch.public_coin[1:],
            "valid_from_ms": template.valid_from_ms + 1,
            "valid_until_ms": template.valid_until_ms + 1,
        }
        self.assertEqual(len(context_mutations), 5)
        for binding, mutated in context_mutations.items():
            args = dict(base_context_args)
            args[binding] = mutated
            checker_args = dict(args)
            with self.subTest(context_binding=binding):
                producer = queue._profile12_context(ordered_batch_root=args.pop("batch_root"), **args)
                checker = independent._profile12_context(**checker_args)
                self.assertEqual(producer, checker)
                self.assertNotEqual(producer, batch.proof_context)

        config_mutations = (
            ("handoff_protocol", 1, "config_shape"),
            ("schema_version", 12.0, "config_shape"),
            ("queue_id", 1, "config_queue_id"),
            ("capacity", 100.0, "config_capacity"),
            ("admission_cap_bytes", float(queue.ADMISSION_CAP_BYTES), "config_limits"),
            ("active_process_limit", 1.0, "config_limits"),
            ("database_page_size", float(queue.DATABASE_PAGE_SIZE), "config_database"),
            ("database_synchronous", 2.0, "config_database"),
            ("proof_attempts_cap", float(queue.PROOF_ATTEMPTS_CAP), "config_database"),
            ("proof_context_bytes", 64.0, "config_database"),
            ("profile_digest", "00" * 64, "config_profile"),
            ("profile_epoch", 12.0, "config_profile_epoch"),
            ("source_key_epoch", 1.0, "config_source_epoch"),
            ("qualification_flags", ["zeta", "alpha"], "config_flags"),
            ("directives", list(reversed(queue.DIRECTIVES)), "config_nonactivation"),
        )
        self.assertEqual(len(config_mutations), 15)
        base_path = self.root / "state.sqlite"
        for field, value, expected in config_mutations:
            path = self.root / f"serializer-config-{field}.sqlite"
            path.write_bytes(base_path.read_bytes())
            with closing(sqlite3.connect(str(path))) as connection:
                raw_config = json.loads(bytes(connection.execute("SELECT config_json FROM queue_metadata WHERE id=1").fetchone()[0]).decode("ascii"))
                raw_config[field] = value
                encoded = json.dumps(raw_config, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                connection.execute("DROP TRIGGER queue_metadata_config_guard")
                connection.execute("UPDATE queue_metadata SET config_json=?,config_digest=? WHERE id=1", (encoded, queue._sha3(queue._MATERIAL, encoded)))
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_metadata_config_guard"])
                connection.commit()
            with self.subTest(config_binding=field):
                self._assert_all_entrypoints_reject(path, expected, destination_name=f"restore-serializer-{field}.sqlite")

    def test_public_coin_zero_retry_and_malformed_sample_fail_closed(self) -> None:
        nonzero = bytes([7]) * 96
        with patch.object(queue.secrets, "token_bytes", side_effect=[bytes(96), nonzero]) as sampler:
            self.assertEqual(queue._sample_public_coin(), nonzero)
        self.assertEqual(sampler.call_count, 2)
        with patch.object(queue.secrets, "token_bytes", side_effect=[bytes(96), bytes(96), nonzero]) as sampler:
            self.assertEqual(queue._sample_public_coin(), nonzero)
        self.assertEqual(sampler.call_count, 3)
        for malformed in (b"wrong", bytearray(96), bytes(97)):
            with self.subTest(malformed_type=type(malformed).__name__, malformed_length=len(malformed)):
                with patch.object(queue.secrets, "token_bytes", return_value=malformed) as sampler:
                    with self.assertRaisesRegex(VerificationQueueError, "queue_randomness"):
                        queue._sample_public_coin()
                self.assertEqual(sampler.call_count, 1)
        with patch.object(queue.secrets, "token_bytes", side_effect=OSError("os-csprng")) as sampler:
            with self.assertRaisesRegex(VerificationQueueError, "queue_randomness"):
                queue._sample_public_coin()
        self.assertEqual(sampler.call_count, 1)
        with patch.object(queue.secrets, "token_bytes", return_value=bytes(96)) as sampler:
            with self.assertRaisesRegex(VerificationQueueError, "queue_randomness"):
                queue._sample_public_coin()
        self.assertEqual(sampler.call_count, 4)

        repeated_temp = tempfile.TemporaryDirectory()
        repeated_root = Path(repeated_temp.name)
        repeated_clock = _Clock()
        repeated_config = QueueConfig("profile12-repeated-u", 200)
        repeated_owner = _QueueRuntimeOwnership(lock_path=repeated_root / "state.sqlite.runtime-lock", parent=repeated_root)
        repeated_store = _VerificationQueueStore(path=repeated_root / "state.sqlite", config=repeated_config, owner=repeated_owner, clock=repeated_clock, composition_config=CompositionConfigV2(repeated_config.queue_id, repeated_config.digest, capacity=200))
        try:
            with patch.object(queue, "_sample_public_coin", return_value=nonzero):
                first = repeated_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, repeated_config.profile_version, repeated_clock.now - 100, repeated_clock.now + 60_000))
                second = repeated_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, repeated_config.profile_version, repeated_clock.now - 100, repeated_clock.now + 60_000))
            self.assertEqual(first.public_coin, second.public_coin)
            self.assertNotEqual(first.operation_refs, second.operation_refs)
            self.assertNotEqual(first.batch_id, second.batch_id)
            verify_database(repeated_root / "state.sqlite", expected_config=repeated_config.as_json)
        finally:
            repeated_store._close()
            repeated_owner.close()
            repeated_temp.cleanup()

        with patch.object(queue, "_sample_public_coin", side_effect=VerificationQueueError("queue_randomness")):
            with self.assertRaisesRegex(VerificationQueueError, "queue_randomness"):
                self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_batches").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 0)

    def test_issue_reserves_once_before_return_and_claim_does_not_charge_again(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 0))
            self.assertEqual(connection.execute("SELECT reservation_before,reservation_after,status FROM queue_attempts").fetchone(), (0, 101, "RESERVED"))
            event = connection.execute("SELECT event_bytes FROM queue_transitions WHERE sequence=1").fetchone()[0]
            self.assertIn(b'"reservation_after":101', bytes(event))
        handoff = VolatileProofHandoff(bytearray(b"proof"))
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=handoff)
        work = self.store._claim_next_batch()
        self.assertIsNotNone(work)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone(), (101, 1))
            self.assertEqual(connection.execute("SELECT transition_kind FROM queue_transitions ORDER BY sequence").fetchall(), [("BATCH_ISSUED",), ("HANDOFF_SUBMITTED",), ("VERIFICATION_STARTED",)])
        verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)

    def test_issue_commit_boundaries_preserve_rollback_and_burn_postcommit_reservation(self) -> None:
        def fail_before(label: str) -> None:
            if label == "before_issue_commit":
                raise RuntimeError("issue precommit")

        self.store._before_fault = fail_before
        with self.assertRaisesRegex(RuntimeError, "issue precommit"):
            self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_batches").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_attempts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 0)

        self.store._before_fault = None
        self.store._after_commit_fault = lambda label: (_ for _ in ()).throw(RuntimeError("issue postcommit")) if label == "after_issue_commit" else None
        with self.assertRaisesRegex(RuntimeError, "issue postcommit"):
            self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "AWAITING_HANDOFF")
            self.assertEqual(connection.execute("SELECT status FROM queue_attempts").fetchone()[0], "RESERVED")
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 101)
        verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)

    def test_claim_rejects_public_coin_and_attempt_epoch_tampering_before_lease(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
        triggers = dict(queue._TRIGGER_DEFS)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("DROP TRIGGER queue_batches_identity_guard")
            connection.execute("UPDATE queue_batches SET public_coin=? WHERE batch_id=?", (bytes(96), batch.batch_id))
            connection.execute(triggers["queue_batches_identity_guard"])
            connection.commit()
        self.assertIsNone(self.store._claim_next_batch())
        self.assertEqual(self.store._last_claim_error, "queue_integrity_failed")
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("DROP TRIGGER queue_batches_identity_guard")
            connection.execute("UPDATE queue_batches SET public_coin=? WHERE batch_id=?", (batch.public_coin, batch.batch_id))
            connection.execute(triggers["queue_batches_identity_guard"])
            connection.execute("DROP TRIGGER queue_attempts_transition_guard")
            connection.execute("UPDATE queue_attempts SET source_key_epoch=? WHERE batch_id=?", ((2).to_bytes(8, "big"), batch.batch_id))
            connection.execute(triggers["queue_attempts_transition_guard"])
            connection.commit()
        self.assertIsNone(self.store._claim_next_batch())
        self.assertEqual(self.store._last_claim_error, "queue_integrity_failed")
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "QUEUED")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_leases").fetchone()[0], 0)

    def test_overstated_lifetime_counter_is_rejected_before_rng(self) -> None:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_metadata SET proof_attempts_used=? WHERE id=1", (PROOF_ATTEMPTS_CAP - 100,))
            connection.commit()
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("rng must not run")) as sampler:
            with self.assertRaisesRegex(VerificationQueueError, "queue_integrity_failed"):
                self.store.issue_batch(template=self._template())
        self.assertEqual(sampler.call_count, 0)
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], PROOF_ATTEMPTS_CAP - 100)

    def test_independent_lifecycle_binds_issue_and_start_reservation(self) -> None:
        def event(kind: str, status: str, attempt: int, **extra: object) -> dict[str, object]:
            return {"kind": kind, "status": status, "attempt": attempt, "error_code": None, "member_count": 100, **extra}

        events = [
            event("BATCH_ISSUED", "AWAITING_HANDOFF", 0, identity_digest="00" * 64, reservation_before=0, reservation_after=101),
            event("HANDOFF_SUBMITTED", "QUEUED", 0),
            event("VERIFICATION_STARTED", "LEASED", 1, reservation_before=0, reservation_after=101),
        ]
        _verify_lifecycle(events, "LEASED", 1, reservation_before=0, reservation_after=101)
        events[2]["reservation_after"] = 202
        with self.assertRaisesRegex(IndependentQueueError, "lifecycle_verification_started"):
            _verify_lifecycle(events, "LEASED", 1, reservation_before=0, reservation_after=101)

    def test_capacity_rejection_happens_before_any_rng(self) -> None:
        self.store.issue_batch(template=self._template())
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("rng must not run")) as sampler:
            with self.assertRaisesRegex(QueueBackpressureError, "queue_capacity"):
                self.store.issue_batch(template=self._template())
        self.assertEqual(sampler.call_count, 0)

    def test_reservation_arithmetic_exhaustion_and_overflow_boundaries(self) -> None:
        self.assertEqual(_reserve_proof_attempt(PROOF_ATTEMPTS_CAP - PROOF_ATTEMPTS_PER_BATCH), PROOF_ATTEMPTS_CAP)
        for used in (PROOF_ATTEMPTS_CAP - PROOF_ATTEMPTS_PER_BATCH + 1, PROOF_ATTEMPTS_CAP, 2**64):
            with self.subTest(used=used), self.assertRaisesRegex(QueueBackpressureError, "computational_budget_exhausted"):
                _reserve_proof_attempt(used)
        with self.assertRaisesRegex(VerificationQueueError, "proof_attempt_ledger"):
            _reserve_proof_attempt(-1)

    def test_hold_at_issue_burns_reservation_without_refund(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.store._hold_batch_locked(connection, batch_id=batch.batch_id, now=self.clock.now_ms(), code="fresh_handoff_required")
            connection.commit()
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT status FROM queue_attempts").fetchone()[0], "HELD")
            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 101)
        verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)

    def test_read_only_version_gate_and_restore_preserve_invalid_source_and_destination(self) -> None:
        old_path = self.root / "old.sqlite"
        old_path.write_bytes((self.root / "state.sqlite").read_bytes())
        with closing(sqlite3.connect(str(old_path))) as connection:
            connection.execute("DROP TRIGGER queue_metadata_config_guard")
            connection.execute("UPDATE queue_metadata SET schema_version=11 WHERE id=1")
            connection.commit()
        source_bytes = old_path.read_bytes()
        with self.assertRaisesRegex(Exception, "queue_schema_unsupported"):
            verify_database(old_path)
        self.assertEqual(old_path.read_bytes(), source_bytes)
        with closing(sqlite3.connect(str(old_path))) as connection:
            trace: list[str] = []
            connection.set_trace_callback(trace.append)
            with self.assertRaisesRegex(IndependentQueueError, "queue_schema_unsupported"):
                _verify_connection(connection)
            setting_pragmas = [statement for statement in trace if statement.upper().startswith("PRAGMA") and "=" in statement]
            self.assertEqual(setting_pragmas, [])
        destination = self.root / "restored-old.sqlite"
        with self.assertRaisesRegex(Exception, "queue_schema_unsupported"):
            restore_export_to_fresh_database(export_bytes=source_bytes, destination=destination)
        self.assertFalse(destination.exists())

    def test_genuine_v11_shape_rejects_before_pragmas_and_preserves_wal_sidecars(self) -> None:
        self.assertTrue(_IMMUTABLE_V11_PRODUCT.is_dir())
        legacy_temp = tempfile.TemporaryDirectory()
        legacy_root = Path(legacy_temp.name)
        wal_connection = None
        try:
            built = subprocess.run(
                [sys.executable, "-B", "-c", _V11_BUILDER, str(legacy_root)],
                cwd=_IMMUTABLE_V11_PRODUCT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual((built.returncode, built.stderr), (0, ""), built.stdout)
            path = legacy_root / "state.sqlite"
            # Keep a connection open while exercising every reader.  SQLite checkpoints
            # and removes WAL/SHM sidecars when the final connection closes; closing the
            # setup connection here would make the preservation assertion vacuous.
            wal_connection = sqlite3.connect(str(path))
            connection = wal_connection
            self.assertEqual(connection.execute("SELECT schema_version FROM queue_metadata").fetchone()[0], 11)
            self.assertNotIn("public_coin", tuple(row[1] for row in connection.execute("PRAGMA table_info(queue_batches)")))
            trigger_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='queue_metadata_config_guard'").fetchone()[0]
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower(), "wal")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("DROP TRIGGER queue_metadata_config_guard")
            connection.execute("UPDATE queue_metadata SET next_transition_seq=next_transition_seq+1 WHERE id=1")
            connection.execute(trigger_sql)
            connection.commit()
            sidecars = (path.with_name("state.sqlite-wal"), path.with_name("state.sqlite-shm"))
            self.assertTrue(all(sidecar.exists() for sidecar in sidecars))
            snapshots = {path: path.read_bytes(), **{sidecar: sidecar.read_bytes() for sidecar in sidecars}}

            config = QueueConfig("profile12-v11-reject", 100)
            owner = _QueueRuntimeOwnership(lock_path=legacy_root / "state.sqlite.runtime-lock", parent=legacy_root)
            try:
                with self.assertRaisesRegex(VerificationQueueError, "queue_schema_unsupported"):
                    _VerificationQueueStore(path=path, config=config, owner=owner, composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=100))
            finally:
                owner.close()
            for preserved_path, original in snapshots.items():
                self.assertEqual(preserved_path.read_bytes(), original, preserved_path.name)

            with self.assertRaisesRegex(Exception, "queue_schema_unsupported"):
                verify_database(path)
            for preserved_path, original in snapshots.items():
                self.assertEqual(preserved_path.read_bytes(), original)

            with closing(sqlite3.connect(path.resolve().as_uri() + "?immutable=1", uri=True)) as connection:
                trace: list[str] = []
                connection.set_trace_callback(trace.append)
                with self.assertRaisesRegex(IndependentQueueError, "queue_schema_unsupported"):
                    _verify_connection(connection)
                self.assertEqual([statement for statement in trace if statement.upper().lstrip().startswith("PRAGMA")], [])

            export_bytes = snapshots[path]
            backup = legacy_root / "original-export.sqlite"
            backup.write_bytes(export_bytes)
            destination = legacy_root / "restored-v11.sqlite"
            with self.assertRaisesRegex(Exception, "queue_schema_unsupported"):
                verify_export_bytes(export_bytes)
            with self.assertRaisesRegex(Exception, "queue_schema_unsupported"):
                restore_export_to_fresh_database(export_bytes=backup.read_bytes(), destination=destination)
            self.assertEqual(backup.read_bytes(), export_bytes)
            self.assertFalse(destination.exists())
            for preserved_path, original in snapshots.items():
                self.assertEqual(preserved_path.read_bytes(), original, preserved_path.name)
        finally:
            if wal_connection is not None:
                wal_connection.close()
            legacy_temp.cleanup()

    def test_live_v12_wal_schema_drift_is_not_accepted_from_immutable_main_image(self) -> None:
        self.store._close()
        self.owner.close()
        path = self.root / "v12-wal-drift.sqlite"
        path.write_bytes((self.root / "state.sqlite").read_bytes())
        wal_connection = sqlite3.connect(str(path))
        try:
            self.assertEqual(wal_connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower(), "wal")
            wal_connection.execute("PRAGMA wal_autocheckpoint=0")
            trigger_sql = wal_connection.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='queue_metadata_config_guard'").fetchone()[0]
            wal_connection.execute("DROP TRIGGER queue_metadata_config_guard")
            wal_connection.execute("UPDATE queue_metadata SET schema_version=11 WHERE id=1")
            wal_connection.execute(trigger_sql)
            wal_connection.commit()
            sidecars = (path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm"))
            self.assertTrue(all(sidecar.exists() for sidecar in sidecars))
            snapshots = {path: path.read_bytes(), sidecars[0]: sidecars[0].read_bytes()}
            # The immutable main image still reports v12. The authoritative
            # live read must follow WAL state and reject the v11 drift before
            # any mutable PRAGMA is attempted.
            with self.assertRaisesRegex(IndependentQueueError, "queue_schema_unsupported"):
                verify_database(path)
            for preserved_path, original in snapshots.items():
                self.assertEqual(preserved_path.read_bytes(), original, preserved_path.name)
            self.assertTrue(sidecars[1].exists())
        finally:
            wal_connection.close()

    def test_valid_restore_prevalidates_then_creates_exclusive_destination(self) -> None:
        source_bytes = (self.root / "state.sqlite").read_bytes()
        destination = self.root / "restored.sqlite"
        result = restore_export_to_fresh_database(export_bytes=source_bytes, destination=destination, expected_config=self.config.as_json)
        self.assertFalse(result["production_usable"])
        self.assertEqual(destination.read_bytes(), source_bytes)
        self.assertEqual((self.root / "state.sqlite").read_bytes(), source_bytes)

    def test_exact_counter_tamper_blocks_issue_and_claim_before_rng(self) -> None:
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_metadata SET proof_attempts_used=101.5 WHERE id=1")
            connection.commit()
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("issue RNG must not run")) as sampler:
            with self.assertRaisesRegex(VerificationQueueError, "queue_integrity_failed"):
                self.store.issue_batch(template=self._template())
        self.assertEqual(sampler.call_count, 0)

        self.store._close()
        self.owner.close()
        self.temp.cleanup()

        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config = QueueConfig("profile12-focused", 100)
        self.composition_config = CompositionConfigV2(self.config.queue_id, self.config.digest, capacity=100)
        self.owner = _QueueRuntimeOwnership(lock_path=self.root / "state.sqlite.runtime-lock", parent=self.root)
        self.store = _VerificationQueueStore(path=self.root / "state.sqlite", config=self.config, owner=self.owner, clock=self.clock, composition_config=self.composition_config)
        batch = self.store.issue_batch(template=self._template())
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_metadata SET next_transition_seq=1.5 WHERE id=1")
            connection.commit()
        with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("lease RNG must not run")) as sampler:
            self.assertIsNone(self.store._claim_next_batch())
        self.assertEqual(sampler.call_count, 0)
        self.assertEqual(self.store._last_claim_error, "queue_integrity_failed")

    def test_issue_claim_counter_sequence_matrix_and_actual_sampler_draw_count(self) -> None:
        counter_cases = (
            ("issue-next-transition-rollback", "next_transition_seq", -1, "issue"),
            ("issue-next-transition-overstatement", "next_transition_seq", 1, "issue"),
            ("issue-next-admission-rollback", "next_admission_seq", -1, "issue"),
            ("issue-next-admission-overstatement", "next_admission_seq", 100, "issue"),
            ("issue-next-attempt-rollback", "next_attempt_seq", -1, "issue"),
            ("issue-next-attempt-overstatement", "next_attempt_seq", 1, "issue"),
            ("issue-proof-attempts-rollback", "proof_attempts_used", -1, "issue"),
            ("issue-proof-attempts-overstatement", "proof_attempts_used", 101, "issue"),
            ("claim-next-transition-rollback", "next_transition_seq", 1, "claim"),
            ("claim-next-transition-overstatement", "next_transition_seq", 999, "claim"),
            ("claim-next-admission-rollback", "next_admission_seq", 0, "claim"),
            ("claim-next-admission-overstatement", "next_admission_seq", 200, "claim"),
            ("claim-next-attempt-rollback", "next_attempt_seq", 0, "claim"),
            ("claim-next-attempt-overstatement", "next_attempt_seq", 2, "claim"),
            ("claim-proof-attempts-rollback", "proof_attempts_used", 0, "claim"),
            ("claim-proof-attempts-overstatement", "proof_attempts_used", 202, "claim"),
        )
        self.assertEqual(len(counter_cases), 16)

        def fresh(label: str, capacity: int = 200) -> tuple[tempfile.TemporaryDirectory[str], Path, _Clock, QueueConfig, _QueueRuntimeOwnership, _VerificationQueueStore]:
            temp = tempfile.TemporaryDirectory()
            root = Path(temp.name)
            clock = _Clock()
            config = QueueConfig(f"profile12-counter-{label.replace('claim', 'lease')}", capacity)
            owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
            store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=clock, composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=capacity))
            return temp, root, clock, config, owner, store

        for label, column, value, phase in counter_cases:
            temp, root, clock, config, owner, store = fresh(label)
            try:
                if phase == "claim":
                    issued = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                    store.submit_batch_handoff(issued_batch=issued, proof_stream=VolatileProofHandoff(bytearray(b"counter-proof")))
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    connection.execute(f"UPDATE queue_metadata SET {column}=? WHERE id=1", (value,))
                    connection.commit()
                tampered = (root / "state.sqlite").read_bytes()
                with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("counter gate must precede RNG")) as sampler:
                    if phase == "issue":
                        with self.assertRaisesRegex(VerificationQueueError, "queue_integrity_failed"):
                            store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                    else:
                        self.assertIsNone(store._claim_next_batch())
                self.assertEqual(sampler.call_count, 0)
                if phase == "claim":
                    self.assertEqual(store._last_claim_error, "queue_integrity_failed")
                self.assertEqual((root / "state.sqlite").read_bytes(), tampered)
            finally:
                store._close()
                owner.close()
                temp.cleanup()

        temp, root, clock, config, owner, store = fresh("sampler", 200)
        draw_sizes: list[int] = []
        coin_draws = 0

        def deterministic_token_bytes(size: int) -> bytes:
            nonlocal coin_draws
            draw_sizes.append(size)
            if size == queue.PUBLIC_COIN_BYTES:
                coin_draws += 1
                return bytes(size) if coin_draws == 1 else bytes([0xA5]) * size
            return len(draw_sizes).to_bytes(size, "big")

        try:
            with patch.object(queue.secrets, "token_bytes", side_effect=deterministic_token_bytes):
                issued = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
            self.assertEqual(coin_draws, 2)
            self.assertEqual(draw_sizes.count(queue.PUBLIC_COIN_BYTES), 2)
            self.assertEqual(draw_sizes.count(queue.MAX_OPERATION_REF_BYTES), 101)
            self.assertNotEqual(issued.public_coin, bytes(queue.PUBLIC_COIN_BYTES))
            verify_database(root / "state.sqlite", expected_config=config.as_json)
        finally:
            store._close()
            owner.close()
            temp.cleanup()

    def test_issue_and_handoff_clock_contract_rejects_malformed_backward_and_u64_values(self) -> None:
        clock_values = ("malformed", -1, 2**64, 1.5)
        self.assertEqual(len(clock_values), 4)
        for index, value in enumerate(clock_values):
            temp = tempfile.TemporaryDirectory()
            root = Path(temp.name)
            clock = _Clock()
            config = QueueConfig(f"profile12-clock-{index}", 100)
            owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
            store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=clock, composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=100))
            try:
                before = (root / "state.sqlite").read_bytes()
                clock.now = value
                with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("clock gate must precede RNG")) as sampler:
                    with self.assertRaisesRegex(QueueIntegrityError, "queue_clock"):
                        store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, 0, 10_000))
                self.assertEqual(sampler.call_count, 0)
                self.assertEqual((root / "state.sqlite").read_bytes(), before)
                verify_database(root / "state.sqlite", expected_config=config.as_json)
            finally:
                store._close()
                owner.close()
                temp.cleanup()

        for index, value in enumerate((999, 2**64, "malformed")):
            temp = tempfile.TemporaryDirectory()
            root = Path(temp.name)
            clock = _Clock(1000)
            config = QueueConfig(f"profile12-handoff-clock-{index}", 100)
            owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
            store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=clock, composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=100))
            try:
                issued = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, 900, 2_000))
                before = (root / "state.sqlite").read_bytes()
                clock.now = value
                handoff = VolatileProofHandoff(bytearray(b"clock-handoff"))
                with self.assertRaisesRegex(QueueIntegrityError, "queue_clock"):
                    store.submit_batch_handoff(issued_batch=issued, proof_stream=handoff)
                self.assertTrue(handoff.closed)
                self.assertEqual((root / "state.sqlite").read_bytes(), before)
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    self.assertEqual(connection.execute("SELECT status FROM queue_batches").fetchone()[0], "AWAITING_HANDOFF")
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_transitions").fetchone()[0], 1)
                verify_database(root / "state.sqlite", expected_config=config.as_json)
            finally:
                store._close()
                owner.close()
                temp.cleanup()

    def test_receipt_flags_and_orphan_results_are_closed(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.store._hold_batch_locked(connection, batch_id=batch.batch_id, now=self.clock.now_ms(), code="fresh_handoff_required")
            connection.commit()
            raw = bytes(connection.execute("SELECT receipt_bytes FROM queue_results WHERE batch_id=?", (batch.batch_id,)).fetchone()[0])
        base_value = json.loads(raw.decode("ascii"))

        malformed = {
            "dictionary": {"qualification_flags": {"nested": "not-a-list"}},
            "nested": {"qualification_flags": [["nested"]]},
            "extra": {**base_value, "unexpected": "field"},
        }
        for label, value in malformed.items():
            path = self._copy_state(f"malformed-receipt-{label}.sqlite")
            if label != "extra":
                value = {**base_value, **value}
            bad_receipt = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            with closing(sqlite3.connect(str(path))) as connection:
                connection.execute("DROP TRIGGER queue_results_no_update")
                connection.execute("UPDATE queue_results SET receipt_bytes=? WHERE batch_id=?", (bad_receipt, batch.batch_id))
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_update"])
                connection.commit()
            expected = {"dictionary": "receipt_flags", "nested": "flags_shape", "extra": "receipt_keys"}[label]
            self._assert_all_entrypoints_reject(path, expected, destination_name=f"restore-{label}.sqlite")

        orphan_path = self._copy_state("orphan.sqlite")
        with closing(sqlite3.connect(str(orphan_path))) as connection:
            connection.execute("INSERT INTO queue_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (bytes([9]) * 32, "HELD", bytes([8]) * 32, b"arbitrary", 0, 0, bytes([7]) * 64, self.config.source_auth_profile, (1).to_bytes(8, "big"), "fresh_handoff_required", b'{"qualification_flags":[]}', self.clock.now_ms(), 0, "fresh_handoff_required"))
            connection.commit()
        self._assert_all_entrypoints_reject(orphan_path, "result_orphan", destination_name="restore-orphan.sqlite")

        missing_path = self._copy_state("missing-result.sqlite")
        with closing(sqlite3.connect(str(missing_path))) as connection:
            connection.execute("DROP TRIGGER queue_results_no_delete")
            connection.execute("DELETE FROM queue_results WHERE batch_id=?", (batch.batch_id,))
            connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_delete"])
            connection.commit()
        self._assert_all_entrypoints_reject(missing_path, "result_set", destination_name="restore-missing-result.sqlite")

    def test_association_closure_matrix_rejects_missing_and_orphan_rows_everywhere(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        base = (self.root / "state.sqlite").read_bytes()
        orphan_batch_id = bytes([0xE1]) * 32

        issue_cases = (
            ("member_missing", "batch_cardinality"),
            ("member_orphan", "member_binding"),
            ("attempt_missing", "attempt_missing"),
            ("attempt_orphan", "attempt_orphan"),
            ("transition_missing", "head_binding"),
            ("transition_orphan", "transition_orphan"),
        )
        self.assertEqual(len(issue_cases), 6)
        for label, expected in issue_cases:
            path = self.root / f"association-{label}.sqlite"
            path.write_bytes(base)
            with closing(sqlite3.connect(str(path))) as connection:
                if label == "member_missing":
                    connection.execute("DROP TRIGGER queue_members_no_delete")
                    connection.execute("DELETE FROM queue_members WHERE batch_id=? AND batch_position=99", (batch.batch_id,))
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_members_no_delete"])
                elif label == "member_orphan":
                    connection.execute("DROP TRIGGER queue_members_no_delete")
                    connection.execute("DELETE FROM queue_members WHERE batch_id=? AND batch_position=99", (batch.batch_id,))
                    connection.execute("INSERT INTO queue_members VALUES (?,?,?,?)", (orphan_batch_id, 99, bytes([0xE2]) * 32, 100))
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_members_no_delete"])
                elif label == "attempt_missing":
                    connection.execute("DROP TRIGGER queue_attempts_no_delete")
                    connection.execute("DELETE FROM queue_attempts WHERE batch_id=?", (batch.batch_id,))
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_no_delete"])
                elif label == "attempt_orphan":
                    connection.execute("INSERT INTO queue_attempts VALUES (?,?,?,?,?,?,?,?,?,?)", (2, orphan_batch_id, 101, 202, 101, (1).to_bytes(8, "big"), "RESERVED", self.clock.now_ms(), None, None))
                elif label == "transition_missing":
                    connection.execute("DROP TRIGGER queue_transitions_no_delete")
                    connection.execute("DELETE FROM queue_transitions WHERE sequence=1")
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_transitions_no_delete"])
                else:
                    connection.execute("INSERT INTO queue_transitions VALUES (?,?,?,?,?,?,?)", (2, "BATCH_ISSUED", orphan_batch_id, bytes(64), bytes(64), b"{}", bytes(64)))
                connection.commit()
            with self.subTest(association=label):
                self._assert_all_entrypoints_reject(path, expected, destination_name=f"restore-association-{label}.sqlite")

        lease_temp = tempfile.TemporaryDirectory()
        lease_root = Path(lease_temp.name)
        lease_clock = _Clock()
        lease_config = QueueConfig("profile12-assoc-lease", 200)
        lease_owner = _QueueRuntimeOwnership(lock_path=lease_root / "state.sqlite.runtime-lock", parent=lease_root)
        lease_store = _VerificationQueueStore(path=lease_root / "state.sqlite", config=lease_config, owner=lease_owner, clock=lease_clock, composition_config=CompositionConfigV2(lease_config.queue_id, lease_config.digest, capacity=200))
        try:
            lease_batch = lease_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, lease_config.profile_version, lease_clock.now - 100, lease_clock.now + 60_000))
            lease_store.submit_batch_handoff(issued_batch=lease_batch, proof_stream=VolatileProofHandoff(bytearray(b"lease-proof")))
            self.assertIsNotNone(lease_store._claim_next_batch())
            lease_base = (lease_root / "state.sqlite").read_bytes()
            for label, expected in (("lease_missing", "lease_binding"), ("lease_orphan", "lease_orphan")):
                path = lease_root / f"association-{label}.sqlite"
                path.write_bytes(lease_base)
                with closing(sqlite3.connect(str(path))) as connection:
                    connection.execute("DELETE FROM queue_leases WHERE batch_id=?", (lease_batch.batch_id,))
                    if label == "lease_orphan":
                        connection.execute("INSERT INTO queue_leases VALUES (?,?,?,?,?,?,?)", (orphan_batch_id, "queue-v12-worker", bytes([0xE3]) * 64, 1, 3, lease_clock.now, lease_clock.now + 60_000))
                    connection.commit()
                with self.subTest(association=label):
                    self._assert_all_entrypoints_reject(path, expected, destination_name=f"restore-association-{label}.sqlite")
        finally:
            lease_store._close()
            lease_owner.close()
            lease_temp.cleanup()

    def test_writer_generated_handled_held_failures_preserve_result_error_separation(self) -> None:
        class _TransportVerifier:
            def verify(self, _stream, _batch):
                raise QueueHeldError("verifier_transport")

        class _ShapeVerifier:
            def verify(self, stream, _batch):
                while stream.read(23):
                    pass
                return []

        class _AcceptedVerifier:
            def __init__(self, config: QueueConfig) -> None:
                self.config = config

            def verify(self, stream, batch):
                while stream.read(23):
                    pass
                return BatchVerifierResult(
                    True,
                    True,
                    batch.proof_context,
                    batch.public_coin,
                    batch.batch_root,
                    self.config.source_auth_profile,
                    self.config.source_key_epoch,
                    "accepted",
                    self.config.qualification_flags,
                )

        cases = (
            ("transport", _TransportVerifier, "verifier_transport"),
            ("shape", _ShapeVerifier, "verifier_result_shape"),
            ("state_controls", _AcceptedVerifier, "state_disposition"),
        )
        for label, verifier_type, error_code in cases:
            with self.subTest(handled_failure=label):
                temp = tempfile.TemporaryDirectory()
                root = Path(temp.name)
                clock = _Clock()
                config = QueueConfig(f"profile12-held-{label}", 100)
                owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
                store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=clock, composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=100))
                try:
                    batch = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 120_000))
                    store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"handled-failure-proof")))
                    verifier = verifier_type(config) if label == "state_controls" else verifier_type()
                    result = store._process_one_batch(verifier=verifier, state_disposition_port=None)
                    self.assertIsNotNone(result)
                    assert result is not None
                    self.assertEqual((result.status, result.error_code), ("HELD", error_code))
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        batch_row = connection.execute("SELECT status,last_error_code FROM queue_batches").fetchone()
                        attempt_row = connection.execute("SELECT status,result_code,reservation_before,reservation_after FROM queue_attempts").fetchone()
                        result_row = connection.execute("SELECT terminal_status,result_code,error_code,attempt FROM queue_results").fetchone()
                        receipt = json.loads(bytes(connection.execute("SELECT receipt_bytes FROM queue_results").fetchone()[0]).decode("ascii"))
                        event = json.loads(bytes(connection.execute("SELECT event_bytes FROM queue_transitions ORDER BY sequence DESC LIMIT 1").fetchone()[0]).decode("ascii"))
                        composition_counts = tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("composition_transactions", "composition_events", "composition_outbox"))
                        self.assertEqual(batch_row, ("HELD", error_code))
                        self.assertEqual(attempt_row, ("HELD", "fresh_handoff_required", 0, 101))
                        self.assertEqual(result_row, ("HELD", "fresh_handoff_required", error_code, 1))
                        self.assertEqual((receipt["result_code"], receipt["error_code"]), ("fresh_handoff_required", error_code))
                        self.assertEqual((event["kind"], event["error_code"]), ("BATCH_HELD", error_code))
                        self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 101)
                        self.assertEqual(composition_counts, (0, 0, 0))
                    verify_database(root / "state.sqlite", expected_config=config.as_json)
                    promoted = read_verified_batch(root / "state.sqlite")
                    self.assertEqual((promoted.batch.accepted_count, promoted.jobs), (0, ()))
                    raw = (root / "state.sqlite").read_bytes()
                    verify_export_bytes(raw, expected_config=config.as_json)
                    restored = root / "restored.sqlite"
                    restore_export_to_fresh_database(export_bytes=raw, destination=restored, expected_config=config.as_json)
                    verify_database(restored, expected_config=config.as_json)

                    contradictory_receipt = root / "contradictory-receipt.sqlite"
                    contradictory_receipt.write_bytes(raw)
                    with closing(sqlite3.connect(str(contradictory_receipt))) as connection:
                        receipt_value = json.loads(bytes(connection.execute("SELECT receipt_bytes FROM queue_results").fetchone()[0]).decode("ascii"))
                        receipt_value["error_code"] = "fresh_handoff_required"
                        connection.execute("DROP TRIGGER queue_results_no_update")
                        connection.execute("UPDATE queue_results SET receipt_bytes=?", (json.dumps(receipt_value, sort_keys=True, separators=(",", ":")).encode("ascii"),))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_update"])
                        connection.commit()
                    self._assert_all_entrypoints_reject(contradictory_receipt, "receipt_result_binding", destination_name=f"restore-contradictory-receipt-{label}.sqlite")

                    contradictory_attempt = root / "contradictory-attempt.sqlite"
                    contradictory_attempt.write_bytes(raw)
                    with closing(sqlite3.connect(str(contradictory_attempt))) as connection:
                        connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                        connection.execute("UPDATE queue_attempts SET result_code='verifier_transport'")
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                        connection.commit()
                    self._assert_all_entrypoints_reject(contradictory_attempt, "attempt_result_binding", destination_name=f"restore-contradictory-attempt-{label}.sqlite")

                    store._close()
                    owner.close()
                    reopened_owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
                    reopened = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=reopened_owner, clock=clock, composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=100))
                    try:
                        next_batch = reopened.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 120_000))
                        self.assertNotEqual(next_batch.batch_id, batch.batch_id)
                        with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                            self.assertEqual(connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0], 202)
                    finally:
                        reopened._close()
                        reopened_owner.close()
                finally:
                    if not store._closed:
                        store._close()
                    owner.close()
                    temp.cleanup()

    def test_missing_attempt_and_config_drift_block_issue_and_claim_before_rng(self) -> None:
        def fresh() -> tuple[tempfile.TemporaryDirectory[str], Path, _Clock, QueueConfig, _QueueRuntimeOwnership, _VerificationQueueStore]:
            temp = tempfile.TemporaryDirectory()
            root = Path(temp.name)
            clock = _Clock()
            config = QueueConfig("profile12-focused", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
            owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
            store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=clock, composition_config=composition_config)
            return temp, root, clock, config, owner, store

        for mutation in ("missing_attempt", "config_drift"):
            temp, root, clock, config, owner, store = fresh()
            try:
                batch = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                if mutation == "missing_attempt":
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        connection.execute("DROP TRIGGER queue_attempts_no_delete")
                        connection.execute("DELETE FROM queue_attempts WHERE batch_id=?", (batch.batch_id,))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_no_delete"])
                        connection.commit()
                else:
                    drifted = QueueConfig("profile12-drifted", 100).canonical_bytes
                    with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                        connection.execute("DROP TRIGGER queue_metadata_config_guard")
                        connection.execute("UPDATE queue_metadata SET config_json=? WHERE id=1", (drifted,))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_metadata_config_guard"])
                        connection.commit()
                with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("request RNG must not run")) as sampler:
                    with self.assertRaisesRegex(VerificationQueueError, "queue_integrity_failed"):
                        store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                self.assertEqual(sampler.call_count, 0)
            finally:
                store._close()
                owner.close()
                temp.cleanup()

        temp, root, clock, config, owner, store = fresh()
        try:
            batch = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
            store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                connection.execute("DROP TRIGGER queue_attempts_no_delete")
                connection.execute("DELETE FROM queue_attempts WHERE batch_id=?", (batch.batch_id,))
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_no_delete"])
                connection.commit()
            with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("lease RNG must not run")) as sampler:
                self.assertIsNone(store._claim_next_batch())
            self.assertEqual(sampler.call_count, 0)
            self.assertEqual(store._last_claim_error, "queue_integrity_failed")
        finally:
            store._close()
            owner.close()
            temp.cleanup()

    def test_issue_and_claim_revalidate_counters_reservations_config_and_epoch_before_work(self) -> None:
        def fresh(capacity: int) -> tuple[tempfile.TemporaryDirectory[str], Path, _Clock, QueueConfig, _QueueRuntimeOwnership, _VerificationQueueStore]:
            temp = tempfile.TemporaryDirectory()
            root = Path(temp.name)
            clock = _Clock()
            config = QueueConfig("profile12-revalidation", capacity)
            owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
            store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=clock, composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=capacity))
            return temp, root, clock, config, owner, store

        issue_cases = ("fractional_transition", "rollback", "overstatement", "reservation", "epoch", "config")
        for case in issue_cases:
            temp, root, clock, config, owner, store = fresh(200)
            try:
                first = None
                if case in {"rollback", "overstatement", "reservation", "epoch"}:
                    first = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    if case == "fractional_transition":
                        connection.execute("UPDATE queue_metadata SET next_transition_seq=1.5 WHERE id=1")
                    elif case == "rollback":
                        connection.execute("UPDATE queue_metadata SET proof_attempts_used=0 WHERE id=1")
                    elif case == "overstatement":
                        connection.execute("UPDATE queue_metadata SET proof_attempts_used=202 WHERE id=1")
                    elif case == "reservation":
                        connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                        connection.execute("UPDATE queue_attempts SET reservation_after=202 WHERE batch_id=?", (first.batch_id,))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                    elif case == "epoch":
                        connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                        connection.execute("UPDATE queue_attempts SET source_key_epoch=? WHERE batch_id=?", ((2).to_bytes(8, "big"), first.batch_id))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                    else:
                        drifted = QueueConfig("profile12-revalidation-drift", 200).canonical_bytes
                        connection.execute("DROP TRIGGER queue_metadata_config_guard")
                        connection.execute("UPDATE queue_metadata SET config_json=? WHERE id=1", (drifted,))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_metadata_config_guard"])
                    connection.commit()
                    before = (connection.execute("SELECT COUNT(*) FROM queue_batches").fetchone()[0], connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0])
                with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("issue RNG must not run")) as sampler:
                    with self.assertRaisesRegex(VerificationQueueError, "queue_integrity_failed"):
                        store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                self.assertEqual(sampler.call_count, 0)
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    after = (connection.execute("SELECT COUNT(*) FROM queue_batches").fetchone()[0], connection.execute("SELECT proof_attempts_used FROM queue_metadata").fetchone()[0])
                self.assertEqual(after, before)
            finally:
                store._close()
                owner.close()
                temp.cleanup()

        claim_cases = ("fractional_transition", "fractional_lease_count", "rollback", "reservation", "epoch", "config")
        for case in claim_cases:
            temp, root, clock, config, owner, store = fresh(100)
            try:
                batch = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 60_000))
                store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    if case == "fractional_transition":
                        connection.execute("UPDATE queue_metadata SET next_transition_seq=1.5 WHERE id=1")
                    elif case == "fractional_lease_count":
                        connection.execute("UPDATE queue_metadata SET live_lease_count=0.5 WHERE id=1")
                    elif case == "rollback":
                        connection.execute("UPDATE queue_metadata SET proof_attempts_used=0 WHERE id=1")
                    elif case == "reservation":
                        connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                        connection.execute("UPDATE queue_attempts SET reservation_before=1 WHERE batch_id=?", (batch.batch_id,))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                    elif case == "epoch":
                        connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                        connection.execute("UPDATE queue_attempts SET source_key_epoch=? WHERE batch_id=?", ((2).to_bytes(8, "big"), batch.batch_id))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                    else:
                        drifted = QueueConfig("profile12-altcfg", 100).canonical_bytes
                        connection.execute("DROP TRIGGER queue_metadata_config_guard")
                        connection.execute("UPDATE queue_metadata SET config_json=? WHERE id=1", (drifted,))
                        connection.execute(dict(queue._TRIGGER_DEFS)["queue_metadata_config_guard"])
                    connection.commit()
                    before = (connection.execute("SELECT status FROM queue_batches").fetchone()[0], connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone())
                with patch.object(queue.secrets, "token_bytes", side_effect=AssertionError("lease RNG must not run")) as sampler:
                    self.assertIsNone(store._claim_next_batch())
                self.assertEqual(sampler.call_count, 0)
                self.assertEqual(store._last_claim_error, "queue_integrity_failed")
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    after = (connection.execute("SELECT status FROM queue_batches").fetchone()[0], connection.execute("SELECT proof_attempts_used,live_lease_count FROM queue_metadata").fetchone())
                self.assertEqual(after, before)
            finally:
                store._close()
                owner.close()
                temp.cleanup()

    def test_independent_rejects_lease_timestamp_and_sequence_tamper(self) -> None:
        batch = self.store.issue_batch(template=self._template())
        self.store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
        self.assertIsNotNone(self.store._claim_next_batch())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("UPDATE queue_leases SET claim_sequence=claim_sequence+1 WHERE batch_id=?", (batch.batch_id,))
            connection.commit()
        with self.assertRaisesRegex(Exception, "lease_binding"):
            verify_database(self.root / "state.sqlite")

    def test_temporal_deadlines_and_terminal_contract_are_exact(self) -> None:
        batch = self._verified_batch()
        valid_path = self.root / "state.sqlite"
        verify_database(valid_path, expected_config=self.config.as_json)
        with closing(sqlite3.connect(str(valid_path))) as connection:
            valid_until = int(connection.execute("SELECT valid_until_ms FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0])
            started_raw = bytes(connection.execute("SELECT event_bytes FROM queue_transitions WHERE transition_kind='VERIFICATION_STARTED'").fetchone()[0])
            started = int(json.loads(started_raw.decode("ascii"))["at_ms"])

        def shift_terminal(path: Path, timestamp: int) -> None:
            with closing(sqlite3.connect(str(path))) as connection:
                connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                connection.execute("DROP TRIGGER queue_results_no_update")
                connection.execute("UPDATE queue_attempts SET closed_ms=? WHERE batch_id=?", (timestamp, batch.batch_id))
                connection.execute("UPDATE queue_results SET completed_ms=? WHERE batch_id=?", (timestamp, batch.batch_id))
                connection.execute("UPDATE queue_batches SET updated_ms=? WHERE batch_id=?", (timestamp, batch.batch_id))
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_update"])
                connection.commit()
            self._set_event_time(path, 4, timestamp)

        validity_path = self._copy_state("terminal-at-validity-boundary.sqlite")
        shift_terminal(validity_path, valid_until)
        with self.assertRaisesRegex(Exception, "validity_deadline"):
            verify_database(validity_path)

        lease_path = self._copy_state("terminal-at-lease-boundary.sqlite")
        shift_terminal(lease_path, started + 60_000)
        with self.assertRaisesRegex(Exception, "lease_deadline"):
            verify_database(lease_path)

        boundary_temp = tempfile.TemporaryDirectory()
        boundary_root = Path(boundary_temp.name)
        boundary_clock = _Clock()
        boundary_config = QueueConfig("profile12-boundary", 100)
        boundary_owner = _QueueRuntimeOwnership(lock_path=boundary_root / "state.sqlite.runtime-lock", parent=boundary_root)
        boundary_store = _VerificationQueueStore(path=boundary_root / "state.sqlite", config=boundary_config, owner=boundary_owner, clock=boundary_clock, composition_config=CompositionConfigV2(boundary_config.queue_id, boundary_config.digest, capacity=100))
        try:
            boundary_batch = self._template()
            boundary_batch = OperationTemplate("profile12-assertion", 1, boundary_config.profile_version, boundary_clock.now, boundary_clock.now + 120_000)
            issued = boundary_store.issue_batch(template=boundary_batch)
            boundary_store.submit_batch_handoff(issued_batch=issued, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
            work = boundary_store._claim_next_batch()
            self.assertIsNotNone(work)
            result = BatchVerifierResult(True, True, issued.proof_context, issued.public_coin, issued.batch_root, boundary_config.source_auth_profile, boundary_config.source_key_epoch, "accepted", boundary_config.qualification_flags)
            boundary_store._complete_batch(work, status="VERIFIED", verifier_result=result, state_controls=_controls(issued.operation_refs))
            verify_database(boundary_root / "state.sqlite", expected_config=boundary_config.as_json)
        finally:
            boundary_store._close()
            boundary_owner.close()
            boundary_temp.cleanup()

        held_temp = tempfile.TemporaryDirectory()
        held_root = Path(held_temp.name)
        held_clock = _Clock()
        held_config = QueueConfig("profile12-held-boundary", 100)
        held_owner = _QueueRuntimeOwnership(lock_path=held_root / "state.sqlite.runtime-lock", parent=held_root)
        held_store = _VerificationQueueStore(path=held_root / "state.sqlite", config=held_config, owner=held_owner, clock=held_clock, composition_config=CompositionConfigV2(held_config.queue_id, held_config.digest, capacity=100))
        try:
            held_batch = held_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, held_config.profile_version, held_clock.now - 100, held_clock.now + 120_000))
            held_store.submit_batch_handoff(issued_batch=held_batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
            self.assertIsNotNone(held_store._claim_next_batch())
            held_clock.now += 60_000
            with closing(sqlite3.connect(str(held_root / "state.sqlite"))) as connection:
                connection.execute("BEGIN IMMEDIATE")
                held_store._hold_batch_locked(connection, batch_id=held_batch.batch_id, now=held_clock.now, code="lease_expired")
                connection.commit()
            verify_database(held_root / "state.sqlite", expected_config=held_config.as_json)
        finally:
            held_store._close()
            held_owner.close()
            held_temp.cleanup()

    def test_terminal_errors_and_acceptance_bits_bind_across_all_entrypoints(self) -> None:
        batch = self._verified_batch()
        verified_bytes = (self.root / "state.sqlite").read_bytes()

        last_error_path = self.root / "verified-last-error.sqlite"
        last_error_path.write_bytes(verified_bytes)
        with closing(sqlite3.connect(str(last_error_path))) as connection:
            connection.execute("UPDATE queue_batches SET last_error_code='lease_expired' WHERE batch_id=?", (batch.batch_id,))
            connection.commit()
        self._assert_all_entrypoints_reject(last_error_path, "terminal_error_binding", destination_name="restore-last-error.sqlite")

        bits_path = self.root / "verified-partial-bits.sqlite"
        bits_path.write_bytes(verified_bytes)
        with closing(sqlite3.connect(str(bits_path))) as connection:
            raw = bytes(connection.execute("SELECT receipt_bytes FROM queue_results WHERE batch_id=?", (batch.batch_id,)).fetchone()[0])
            receipt = json.loads(raw.decode("ascii"))
            receipt["proof_accepted"] = True
            receipt["source_authenticated"] = False
            encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("ascii")
            connection.execute("DROP TRIGGER queue_results_no_update")
            connection.execute("UPDATE queue_results SET proof_accepted=1,source_authenticated=0,receipt_bytes=? WHERE batch_id=?", (encoded, batch.batch_id))
            connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_update"])
            connection.commit()
        self._assert_all_entrypoints_reject(bits_path, "verified_acceptance", destination_name="restore-partial-bits.sqlite")

        event_path = self.root / "verified-event-error.sqlite"
        event_path.write_bytes(verified_bytes)
        with closing(sqlite3.connect(str(event_path))) as connection:
            raw = bytes(connection.execute("SELECT event_bytes FROM queue_transitions WHERE sequence=4").fetchone()[0])
            event = json.loads(raw.decode("ascii"))
            event["error_code"] = "lease_expired"
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("ascii")
            connection.execute("DROP TRIGGER queue_transitions_no_update")
            connection.execute("UPDATE queue_transitions SET event_bytes=? WHERE sequence=4", (encoded,))
            connection.execute(dict(queue._TRIGGER_DEFS)["queue_transitions_no_update"])
            connection.commit()
        self._rehash_transitions(event_path)
        self._assert_all_entrypoints_reject(event_path, "terminal_error_binding", destination_name="restore-event-error.sqlite")

        rejected_temp = tempfile.TemporaryDirectory()
        rejected_root = Path(rejected_temp.name)
        rejected_clock = _Clock()
        rejected_config = QueueConfig("profile12-partial-reject", 100)
        rejected_owner = _QueueRuntimeOwnership(lock_path=rejected_root / "state.sqlite.runtime-lock", parent=rejected_root)
        rejected_store = _VerificationQueueStore(path=rejected_root / "state.sqlite", config=rejected_config, owner=rejected_owner, clock=rejected_clock, composition_config=CompositionConfigV2(rejected_config.queue_id, rejected_config.digest, capacity=100))
        try:
            rejected_batch = rejected_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, rejected_config.profile_version, rejected_clock.now - 100, rejected_clock.now + 120_000))
            rejected_store.submit_batch_handoff(issued_batch=rejected_batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
            rejected_work = rejected_store._claim_next_batch()
            self.assertIsNotNone(rejected_work)
            rejected_result = BatchVerifierResult(False, True, rejected_batch.proof_context, rejected_batch.public_coin, rejected_batch.batch_root, rejected_config.source_auth_profile, rejected_config.source_key_epoch, "rejected", rejected_config.qualification_flags)
            rejected_store._complete_batch(rejected_work, status="REJECTED", verifier_result=rejected_result, error_code="proof_or_source_not_accepted")
            verify_database(rejected_root / "state.sqlite", expected_config=rejected_config.as_json)
        finally:
            rejected_store._close()
            rejected_owner.close()
            rejected_temp.cleanup()

    def test_lifecycle_specific_expiry_contract_rejects_coherent_prelease_expiry_recode(self) -> None:
        expired_temp = tempfile.TemporaryDirectory()
        expired_root = Path(expired_temp.name)
        expired_clock = _Clock()
        expired_config = QueueConfig("profile12-prelease-expiry", 100)
        expired_owner = _QueueRuntimeOwnership(lock_path=expired_root / "state.sqlite.runtime-lock", parent=expired_root)
        expired_store = _VerificationQueueStore(path=expired_root / "state.sqlite", config=expired_config, owner=expired_owner, clock=expired_clock, composition_config=CompositionConfigV2(expired_config.queue_id, expired_config.digest, capacity=100))
        try:
            expired_batch = expired_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, expired_config.profile_version, expired_clock.now - 100, expired_clock.now - 1))
            with self.assertRaisesRegex(Exception, "validity_expired"):
                expired_store.submit_batch_handoff(issued_batch=expired_batch, proof_stream=VolatileProofHandoff(bytearray(b"expired-handoff")))
            verify_database(expired_root / "state.sqlite", expected_config=expired_config.as_json)
            with closing(sqlite3.connect(str(expired_root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_transitions").fetchone()[0], 2)
                self.assertEqual(connection.execute("SELECT last_error_code FROM queue_batches").fetchone()[0], "validity_expired")
        finally:
            expired_store._close()
            expired_owner.close()
            expired_temp.cleanup()

        queued_temp = tempfile.TemporaryDirectory()
        queued_root = Path(queued_temp.name)
        queued_clock = _Clock()
        queued_config = QueueConfig("profile12-queued-expiry", 100)
        queued_owner = _QueueRuntimeOwnership(lock_path=queued_root / "state.sqlite.runtime-lock", parent=queued_root)
        queued_store = _VerificationQueueStore(path=queued_root / "state.sqlite", config=queued_config, owner=queued_owner, clock=queued_clock, composition_config=CompositionConfigV2(queued_config.queue_id, queued_config.digest, capacity=100))
        try:
            queued_batch = queued_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, queued_config.profile_version, queued_clock.now - 100, queued_clock.now + 100))
            queued_store.submit_batch_handoff(issued_batch=queued_batch, proof_stream=VolatileProofHandoff(bytearray(b"queued-expiry")))
            queued_clock.now += 101
            self.assertIsNone(queued_store._claim_next_batch())
            verify_database(queued_root / "state.sqlite", expected_config=queued_config.as_json)
            with closing(sqlite3.connect(str(queued_root / "state.sqlite"))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_transitions").fetchone()[0], 3)
                self.assertEqual(connection.execute("SELECT last_error_code FROM queue_batches").fetchone()[0], "validity_expired")
        finally:
            queued_store._close()
            queued_owner.close()
            queued_temp.cleanup()

        recovery_temp = tempfile.TemporaryDirectory()
        recovery_root = Path(recovery_temp.name)
        recovery_clock = _Clock()
        recovery_config = QueueConfig("profile12-recovery-fresh", 100)
        recovery_owner = _QueueRuntimeOwnership(lock_path=recovery_root / "state.sqlite.runtime-lock", parent=recovery_root)
        recovery_store = _VerificationQueueStore(path=recovery_root / "state.sqlite", config=recovery_config, owner=recovery_owner, clock=recovery_clock, composition_config=CompositionConfigV2(recovery_config.queue_id, recovery_config.digest, capacity=100))
        try:
            recovery_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, recovery_config.profile_version, recovery_clock.now - 100, recovery_clock.now + 10))
            recovery_store._close()
            recovery_owner.close()
            recovery_clock.now += 100_000
            reopened_owner = _QueueRuntimeOwnership(lock_path=recovery_root / "state.sqlite.runtime-lock", parent=recovery_root)
            reopened = _VerificationQueueStore(path=recovery_root / "state.sqlite", config=recovery_config, owner=reopened_owner, clock=recovery_clock, composition_config=CompositionConfigV2(recovery_config.queue_id, recovery_config.digest, capacity=100))
            try:
                verify_database(recovery_root / "state.sqlite", expected_config=recovery_config.as_json)
                with closing(sqlite3.connect(str(recovery_root / "state.sqlite"))) as connection:
                    self.assertEqual(connection.execute("SELECT last_error_code FROM queue_batches").fetchone()[0], "fresh_handoff_required")
            finally:
                reopened._close()
                reopened_owner.close()
        finally:
            if not recovery_store._closed:
                recovery_store._close()
            recovery_owner.close()
            recovery_temp.cleanup()

        batch = self.store.issue_batch(template=self._template())
        with closing(sqlite3.connect(str(self.root / "state.sqlite"))) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.store._hold_batch_locked(connection, batch_id=batch.batch_id, now=self.clock.now, code="fresh_handoff_required")
            connection.commit()
        base = (self.root / "state.sqlite").read_bytes()
        for label, code, expected in (("lease", "lease_expired", "terminal_error_binding"), ("validity", "validity_expired", "validity_deadline")):
            path = self.root / f"prelease-recode-{label}.sqlite"
            path.write_bytes(base)
            with closing(sqlite3.connect(str(path))) as connection:
                raw_receipt = bytes(connection.execute("SELECT receipt_bytes FROM queue_results").fetchone()[0])
                receipt = json.loads(raw_receipt.decode("ascii"))
                receipt["result_code"] = code
                receipt["error_code"] = code
                encoded_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("ascii")
                event_raw = bytes(connection.execute("SELECT event_bytes FROM queue_transitions ORDER BY sequence DESC LIMIT 1").fetchone()[0])
                event = json.loads(event_raw.decode("ascii"))
                event["error_code"] = code
                encoded_event = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("ascii")
                connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                connection.execute("DROP TRIGGER queue_results_no_update")
                connection.execute("DROP TRIGGER queue_transitions_no_update")
                connection.execute("UPDATE queue_batches SET last_error_code=? WHERE batch_id=?", (code, batch.batch_id))
                connection.execute("UPDATE queue_attempts SET result_code=? WHERE batch_id=?", (code, batch.batch_id))
                connection.execute("UPDATE queue_results SET result_code=?,error_code=?,receipt_bytes=? WHERE batch_id=?", (code, code, encoded_receipt, batch.batch_id))
                connection.execute("UPDATE queue_transitions SET event_bytes=? WHERE sequence=(SELECT MAX(sequence) FROM queue_transitions)", (encoded_event,))
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_update"])
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_transitions_no_update"])
                connection.commit()
            self._rehash_transitions(path)
            with self.subTest(prelease_expiry_recode=label):
                self._assert_all_entrypoints_reject(path, expected, destination_name=f"restore-prelease-recode-{label}.sqlite")

    def test_reservation_and_issue_event_order_are_cross_bound(self) -> None:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        clock = _Clock()
        config = QueueConfig("profile12-order", 200)
        owner = _QueueRuntimeOwnership(lock_path=root / "state.sqlite.runtime-lock", parent=root)
        store = _VerificationQueueStore(path=root / "state.sqlite", config=config, owner=owner, clock=clock, composition_config=CompositionConfigV2(config.queue_id, config.digest, capacity=200))
        try:
            first = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 120_000))
            second = store.issue_batch(template=OperationTemplate("profile12-assertion", 1, config.profile_version, clock.now - 100, clock.now + 120_000))
            base = (root / "state.sqlite").read_bytes()

            attempt_path = root / "swapped-attempt-order.sqlite"
            attempt_path.write_bytes(base)
            with closing(sqlite3.connect(str(attempt_path))) as connection:
                connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                connection.execute("UPDATE queue_attempts SET attempt_id=-1,reservation_before=101,reservation_after=202 WHERE batch_id=?", (first.batch_id,))
                connection.execute("UPDATE queue_attempts SET attempt_id=1,reservation_before=0,reservation_after=101 WHERE batch_id=?", (second.batch_id,))
                connection.execute("UPDATE queue_attempts SET attempt_id=2,reservation_before=101,reservation_after=202 WHERE batch_id=?", (first.batch_id,))
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                connection.commit()
            self._assert_all_entrypoints_reject(attempt_path, "attempt_binding", destination_name="restore-swapped-attempt-order.sqlite")

            event_path = root / "swapped-issue-event-order.sqlite"
            event_path.write_bytes(base)
            with closing(sqlite3.connect(str(event_path))) as connection:
                first_raw = bytes(connection.execute("SELECT event_bytes FROM queue_transitions WHERE sequence=1").fetchone()[0])
                second_raw = bytes(connection.execute("SELECT event_bytes FROM queue_transitions WHERE sequence=2").fetchone()[0])
                first_event = json.loads(first_raw.decode("ascii"))
                second_event = json.loads(second_raw.decode("ascii"))
                first_event.update(batch_id=second.batch_id.hex().upper(), identity_digest=second.identity_digest.hex().upper(), reservation_before=101, reservation_after=202)
                second_event.update(batch_id=first.batch_id.hex().upper(), identity_digest=first.identity_digest.hex().upper(), reservation_before=0, reservation_after=101)
                connection.execute("DROP TRIGGER queue_transitions_no_update")
                connection.execute("UPDATE queue_transitions SET batch_id=?,event_bytes=? WHERE sequence=1", (second.batch_id, json.dumps(first_event, sort_keys=True, separators=(",", ":")).encode("ascii")))
                connection.execute("UPDATE queue_transitions SET batch_id=?,event_bytes=? WHERE sequence=2", (first.batch_id, json.dumps(second_event, sort_keys=True, separators=(",", ":")).encode("ascii")))
                connection.execute(dict(queue._TRIGGER_DEFS)["queue_transitions_no_update"])
                connection.commit()
            self._rehash_transitions(event_path)
            self._assert_all_entrypoints_reject(event_path, "issue_order", destination_name="restore-swapped-issue-order.sqlite")
        finally:
            store._close()
            owner.close()
            temp.cleanup()

    def test_temporal_field_matrix_rejects_backward_malformed_and_out_of_u64_values(self) -> None:
        batch = self._verified_batch()
        base = (self.root / "state.sqlite").read_bytes()

        def mutate(path: Path, field: str) -> None:
            with closing(sqlite3.connect(str(path))) as connection:
                if field == "created":
                    connection.execute("DROP TRIGGER queue_batches_identity_guard")
                    connection.execute("UPDATE queue_batches SET created_ms=created_ms+1 WHERE batch_id=?", (batch.batch_id,))
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_batches_identity_guard"])
                elif field == "updated":
                    connection.execute("UPDATE queue_batches SET updated_ms=updated_ms+1 WHERE batch_id=?", (batch.batch_id,))
                elif field == "next_eligible":
                    connection.execute("UPDATE queue_batches SET next_eligible_ms=next_eligible_ms+1 WHERE batch_id=?", (batch.batch_id,))
                elif field == "reserved":
                    connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                    connection.execute("UPDATE queue_attempts SET reserved_ms=reserved_ms+1,closed_ms=closed_ms+1 WHERE batch_id=?", (batch.batch_id,))
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                elif field == "closed":
                    connection.execute("DROP TRIGGER queue_attempts_transition_guard")
                    connection.execute("UPDATE queue_attempts SET closed_ms=closed_ms+1 WHERE batch_id=?", (batch.batch_id,))
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_attempts_transition_guard"])
                elif field == "result":
                    connection.execute("DROP TRIGGER queue_results_no_update")
                    connection.execute("UPDATE queue_results SET completed_ms=completed_ms+1 WHERE batch_id=?", (batch.batch_id,))
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_results_no_update"])
                elif field == "backward":
                    connection.execute("DROP TRIGGER queue_batches_identity_guard")
                    connection.execute("UPDATE queue_batches SET created_ms=-1 WHERE batch_id=?", (batch.batch_id,))
                    connection.execute(dict(queue._TRIGGER_DEFS)["queue_batches_identity_guard"])
                else:
                    connection.execute("UPDATE queue_batches SET updated_ms=? WHERE batch_id=?", (str(2**64), batch.batch_id))
                connection.commit()

        for field, expected in (("created", "timestamp_binding"), ("updated", "timestamp_binding"), ("next_eligible", "next_eligible_binding"), ("reserved", "timestamp_binding"), ("closed", "attempt_timestamp_binding"), ("result", "result_timestamp_binding"), ("event", "timestamp_binding"), ("backward", "timestamp_binding"), ("u64", "batch_numeric")):
            path = self.root / f"timestamp-{field}.sqlite"
            path.write_bytes(base)
            if field == "event":
                self._set_event_time(path, 4, self.clock.now + 1)
                expected = "timestamp_binding"
            else:
                mutate(path, field)
            with self.subTest(field=field):
                with self.assertRaisesRegex(Exception, expected):
                    verify_database(path)

        lease_temp = tempfile.TemporaryDirectory()
        lease_root = Path(lease_temp.name)
        lease_clock = _Clock()
        lease_config = QueueConfig("profile12-lease-fields", 100)
        lease_owner = _QueueRuntimeOwnership(lock_path=lease_root / "state.sqlite.runtime-lock", parent=lease_root)
        lease_store = _VerificationQueueStore(path=lease_root / "state.sqlite", config=lease_config, owner=lease_owner, clock=lease_clock, composition_config=CompositionConfigV2(lease_config.queue_id, lease_config.digest, capacity=100))
        try:
            lease_batch = lease_store.issue_batch(template=OperationTemplate("profile12-assertion", 1, lease_config.profile_version, lease_clock.now - 100, lease_clock.now + 120_000))
            lease_store.submit_batch_handoff(issued_batch=lease_batch, proof_stream=VolatileProofHandoff(bytearray(b"proof")))
            self.assertIsNotNone(lease_store._claim_next_batch())
            lease_base = (lease_root / "state.sqlite").read_bytes()
            for field, value, expected in (("leased_ms", -1, "lease_binding"), ("expires_ms", -1, "lease_binding"), ("expires_ms", str(2**64), "lease_numeric"), ("claim_sequence", -1, "lease_binding")):
                path = lease_root / f"lease-{field}-{type(value).__name__}-{value}.sqlite"
                path.write_bytes(lease_base)
                with closing(sqlite3.connect(str(path))) as connection:
                    connection.execute("PRAGMA ignore_check_constraints=ON")
                    connection.execute(f"UPDATE queue_leases SET {field}=? WHERE batch_id=?", (value, lease_batch.batch_id))
                    connection.commit()
                with self.subTest(lease_field=field, value=value):
                    with self.assertRaisesRegex(Exception, expected):
                        verify_database(path)
        finally:
            lease_store._close()
            lease_owner.close()
            lease_temp.cleanup()


if __name__ == "__main__":
    unittest.main()
