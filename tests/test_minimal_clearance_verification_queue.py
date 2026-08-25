"""Focused V3 queue durability, custody, and single-owner tests."""

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest import TestCase
from unittest.mock import patch
import app.minimal_clearance_verification_queue as queue_module
import app.minimal_clearance_verification_queue_independent as independent_queue_module

from app.minimal_clearance_proof_primitives import (
    MinimalClearanceProofStateError,
    MinimalProofAcceptanceV3,
    NativeMinimalClearanceVerifier,
    NativeVerificationCallResult,
    _CIRCUIT_ID,
    _artifact_public_bytes,
    _parse_statement,
)
from app.minimal_clearance_verifier_process import ContainedVerifierResult
from app.minimal_clearance_verification_queue import (
    ArtifactMetadata,
    _FilesystemArtifactCustody,
    QueueBackpressureError,
    QueueConflictError,
    QueueConfig,
    QueueHeldError,
    QueueLeaseError,
    QueueRetryableError,
    VerificationQueueError,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    _parse_config,
    read_verified_jobs,
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)
from app.minimal_clearance_verification_profile import (
    GOVERNANCE_SNAPSHOT,
    SOURCE_PROFILE,
    SOURCE_REGISTRY_SNAPSHOT,
    ExperimentalPrivateZkProfile,
    INSTALLATION_ID,
    statement_matches_static,
)


_RETAINED_ARTIFACT = Path(r"C:\Users\neers\Documents\Codex\2026-08-24-queue-v6-real-run-20260824\source\proof-a.blmc")
_RAW = _RETAINED_ARTIFACT.read_bytes()
_SHA256 = hashlib.sha256(_RAW).digest()
_SHA3 = hashlib.sha3_512(_RAW).digest()
_VERIFIER = bytes.fromhex("AB" * 32)


def _fake_verify(
    verifier: NativeMinimalClearanceVerifier,
    _artifact: Path,
    **_expected_metadata: object,
):
    acceptance = getattr(verifier, "_test_acceptance", None)
    if type(acceptance) is MinimalProofAcceptanceV3:
        return NativeVerificationCallResult(acceptance, _containment())
    failure = getattr(verifier, "_test_failure", None)
    if failure is not None:
        raise failure
    raise MinimalClearanceProofStateError("verifier_timeout")


def _containment() -> ContainedVerifierResult:
    return ContainedVerifierResult(
        exit_code=0, stdout=b"synthetic\n", stderr=b"", peak_job_commit_bytes=1_100_000,
        cap_bytes=5_000_000_000, cap_enforced=True, active_process_limit=1, timed_out=False,
    )


def _accepted() -> MinimalProofAcceptanceV3:
    _, statement_bytes, _ = _artifact_public_bytes(_RAW)
    return MinimalProofAcceptanceV3(
        statement=_parse_statement(statement_bytes), artifact_sha256=_SHA256,
        artifact_digest=_SHA3, artifact_bytes=len(_RAW), circuit_id=_CIRCUIT_ID,
    )


def _Acceptance() -> MinimalProofAcceptanceV3:
    """Compatibility fixture name used by the retained composition tests."""
    return _accepted()


def _mutated_static_acceptance(field: str) -> MinimalProofAcceptanceV3:
    acceptance = _accepted()
    value = bytes(acceptance.statement.get(field))
    raw = bytearray(acceptance.statement.statement_bytes)
    offset = raw.find(value)
    if offset < 0:
        raise AssertionError(field)
    raw[offset] ^= 1
    return replace(acceptance, statement=_parse_statement(bytes(raw)))


class _Factory:
    def __init__(self, *, failure: BaseException | None = None, acceptance: MinimalProofAcceptanceV3 | None = None) -> None:
        self.failure = failure
        self.acceptance = acceptance
        self.instances: list[NativeMinimalClearanceVerifier] = []

    def __call__(self) -> NativeMinimalClearanceVerifier:
        verifier = object.__new__(NativeMinimalClearanceVerifier)
        verifier._test_failure = self.failure  # type: ignore[attr-defined]
        if self.failure is None:
            verifier._test_acceptance = self.acceptance or _accepted()  # type: ignore[attr-defined]
        self.instances.append(verifier)
        return verifier


class _Clock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def now_ms(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


class VerificationQueueTests(TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-queue-v3-")
        self.root = Path(self.temp.name)
        self.source_root = self.root / "source"
        self.workspace_parent = self.root / "workspaces"
        self.source_root.mkdir()
        self.workspace_parent.mkdir()
        self.source = self.source_root / "opaque-ref"
        self.source.write_bytes(_RAW)
        self.source.chmod(0o400)
        self._identity = NativeMinimalClearanceVerifier.identity_sha256
        self._verify = NativeMinimalClearanceVerifier.verify
        self._preflight = NativeMinimalClearanceVerifier.preflight
        NativeMinimalClearanceVerifier.identity_sha256 = lambda _self: _VERIFIER  # type: ignore[assignment]
        NativeMinimalClearanceVerifier.preflight = lambda _self: None  # type: ignore[assignment]
        NativeMinimalClearanceVerifier.verify = _fake_verify  # type: ignore[assignment]
        self._owners: list[_QueueRuntimeOwnership] = []

    def tearDown(self) -> None:
        NativeMinimalClearanceVerifier.identity_sha256 = self._identity
        NativeMinimalClearanceVerifier.verify = self._verify
        NativeMinimalClearanceVerifier.preflight = self._preflight
        for owner in reversed(self._owners):
            owner.close()
        self.temp.cleanup()

    def _config(self, *, capacity: int = 4) -> QueueConfig:
        return QueueConfig("queue-test", capacity, _VERIFIER, 512 * 1024 * 1024, installation_id=INSTALLATION_ID)

    def _store(
        self,
        *,
        capacity: int = 4,
        clock: _Clock | None = None,
        after_commit_fault=None,
        name: str | None = None,
    ) -> _VerificationQueueStore:
        path = self.root / (name or f"queue-{len(list(self.root.glob('queue-*.sqlite')))}.sqlite")
        owner = _QueueRuntimeOwnership(
            lock_path=path.with_name(path.name + ".runtime-lock"),
            parent=path.parent,
        )
        self._owners.append(owner)
        return _VerificationQueueStore(
            path=path,
            config=self._config(capacity=capacity),
            owner=owner,
            clock=clock,
            after_commit_fault=after_commit_fault,
        )

    @staticmethod
    def _metadata(ref: str = "opaque-ref") -> ArtifactMetadata:
        acceptance = _accepted()
        return ArtifactMetadata(ref, len(_RAW), _SHA256, _SHA3, bytes(acceptance.statement.state("proposed_payment_commitment")), acceptance.statement.state_before_id, bytes(acceptance.statement.get("private_batch_commitment")))

    def _admit(self, store: _VerificationQueueStore, job_id: str = "job-1", ref: str = "opaque-ref"):
        return store._admit(job_id=job_id, metadata=self._metadata(ref))

    def _verify_one(self, store: _VerificationQueueStore, job_id: str = "job-1", *, factory: _Factory | None = None):
        self._admit(store, job_id)
        verifier = (factory or _Factory())()
        return store._process_one(verifier=verifier, custody=self._custody())

    def _verifier(self, failure: BaseException | None = None) -> NativeMinimalClearanceVerifier:
        verifier = object.__new__(NativeMinimalClearanceVerifier)
        verifier._test_failure = failure  # type: ignore[attr-defined]
        return verifier

    def _custody(self) -> _FilesystemArtifactCustody:
        return _FilesystemArtifactCustody(source_root=self.source_root, workspace_parent=self.workspace_parent)

    def test_v3_config_and_capacity_are_fixed(self) -> None:
        config = self._config(capacity=512)
        self.assertEqual(config.as_json()["schema_version"], 6)
        self.assertEqual(config.as_json()["max_worker_concurrency"], 1)
        self.assertEqual(config.as_json()["source_registry_snapshot"], SOURCE_REGISTRY_SNAPSHOT.hex().upper())
        self.assertEqual(config.as_json()["source_profile"], SOURCE_PROFILE.hex().upper())
        self.assertEqual(config.as_json()["governance_snapshot"], GOVERNANCE_SNAPSHOT.hex().upper())
        self.assertEqual(config.lease_seconds, 3_600)
        self.assertEqual(config.max_attempts, 3)
        with self.assertRaises(VerificationQueueError):
            QueueConfig("too-wide", 513, _VERIFIER, 1)

        for key, bad in (("schema_version", True), ("max_attempts", 3.0), ("max_worker_concurrency", True), ("profile_epoch", 7.0)):
            candidate = config.as_json()
            candidate[key] = bad
            with self.assertRaises(IndependentQueueError):
                _parse_config(candidate)
        for key in ("source_registry_snapshot", "source_profile", "governance_snapshot"):
            candidate = config.as_json()
            candidate.pop(key)
            with self.assertRaises(IndependentQueueError):
                _parse_config(candidate)

    def test_profile_static_fields_are_bound_before_candidate_and_replayed(self) -> None:
        acceptance = _accepted()
        self.assertTrue(statement_matches_static(acceptance.statement))
        for field in ("source_registry_snapshot", "source_profile", "governance_snapshot"):
            mutated = _mutated_static_acceptance(field)
            self.assertFalse(statement_matches_static(mutated.statement))
            store = self._store(name=f"static-{field}.sqlite")
            result = self._verify_one(store, factory=_Factory(acceptance=mutated))
            self.assertEqual(result.status, "HELD")
            self.assertEqual(store._snapshot()["counts"]["CANDIDATE"], 0)

            replay_store = self._store(name=f"replay-{field}.sqlite")
            self._verify_one(replay_store)
            with closing(sqlite3.connect(replay_store.path)) as connection:
                connection.execute("DROP TRIGGER queue_results_no_update")
                row = connection.execute("SELECT operation_id,receipt_bytes FROM queue_results").fetchone()
                self.assertIsNotNone(row)
                receipt = json.loads(bytes(row[1]).decode("ascii"))
                receipt["evidence"]["acceptance_bytes"] = _mutated_static_acceptance(field).canonical_bytes().hex().upper()
                mutated_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("ascii")
                connection.execute("UPDATE queue_results SET receipt_bytes=? WHERE operation_id=?", (mutated_receipt, bytes(row[0])))
                connection.commit()
                exported = connection.serialize()
            with self.assertRaises(IndependentQueueError):
                verify_database(replay_store.path)
            with self.assertRaises(IndependentQueueError):
                verify_export_bytes(exported)

    def test_candidate_counts_as_nonterminal_projection(self) -> None:
        store = self._store()
        self.assertEqual(store._support_summary()["nonterminal_depth"], 0)
        self._verify_one(store)
        summary = store._support_summary()
        self.assertEqual(summary["nonterminal_depth"], 1)
        self.assertEqual(summary["oldest_admission_seq"], 1)

    def test_admission_exact_retry_conflict_and_bounded_capacity(self) -> None:
        store = self._store(capacity=1)
        first = self._admit(store)
        retry = self._admit(store)
        self.assertEqual(first.operation_id, retry.operation_id)
        with self.assertRaises(QueueConflictError):
            self._admit(store, "job-1", "other-ref")
        with self.assertRaises(QueueBackpressureError):
            self._admit(store, "job-2")
        self.assertEqual(store._snapshot()["counts"]["QUEUED"], 1)

    def test_random_bearer_is_memory_only_and_wrong_token_is_fenced(self) -> None:
        store = self._store(capacity=1)
        self._admit(store)
        work = store._claim_next()
        self.assertIsNotNone(work)
        self.assertEqual(len(work.lease_token), 32)
        exported = store._export_bytes()
        self.assertNotIn(work.lease_token, exported)
        with self.assertRaises(QueueLeaseError):
            store._complete_rejected(replace(work, lease_token=b"x" * 32), "proof_rejected")
        self.assertEqual(exported, store._export_bytes())
        self.assertEqual(store._complete_rejected(work, "proof_rejected").status, "REJECTED")
        self.assertIsNone(store._retry_result(work.operation_id).receipt_bytes)

    def test_claim_after_commit_fault_reconciles_only_while_bearer_is_live(self) -> None:
        faults = {"claim": 0}

        def fault(label: str) -> None:
            if label == "claim" and faults["claim"] == 0:
                faults["claim"] += 1
                raise RuntimeError("response-loss-canary")

        store = self._store(after_commit_fault=fault)
        self._admit(store)
        work = store._claim_next()
        self.assertEqual(work.job_id, "job-1")
        self.assertEqual(store._snapshot()["leases"], 1)
        with self.assertRaises(QueueBackpressureError):
            store._claim_next()

    def test_one_live_lease_and_expiry_requeue_hold_at_attempt_three(self) -> None:
        clock = _Clock()
        store = self._store(clock=clock, capacity=3)
        self._admit(store)
        for attempt in (1, 2):
            work = store._claim_next()
            self.assertEqual(work.attempt, attempt)
            with self.assertRaises(QueueBackpressureError):
                store._claim_next()
            clock.advance(3_600_001)
            self.assertEqual(store._recover_expired(), 1)
            self.assertEqual(store._get_job("job-1").status, "QUEUED")
        work = store._claim_next()
        self.assertEqual(work.attempt, 3)
        clock.advance(3_600_001)
        self.assertEqual(store._recover_expired(), 1)
        self.assertEqual(store._get_job("job-1").status, "HELD")
        self.assertIsNone(store._claim_next())
        verify_database(store.path, expected_config=store.config.as_json())

    def test_startup_recovery_requeues_unexpired_lease_without_bearer(self) -> None:
        store = self._store(capacity=2)
        self._admit(store)
        work = store._claim_next()
        self.assertEqual(store._get_job("job-1").status, "LEASED")
        self.assertEqual(store._recover_startup_leases(), 1)
        self.assertEqual(store._get_job("job-1").status, "QUEUED")
        self.assertEqual(store._get_job("job-1").last_error_code, "runtime_restart")
        exported = store._export_bytes()
        self.assertNotIn(work.lease_token, exported)
        summary = verify_database(store.path, expected_config=store.config.as_json())
        self.assertEqual(summary["lease_count"], 0)

    def test_real_custody_is_direct_child_and_rejects_escape(self) -> None:
        custody = self._custody()
        snapshot = custody.snapshot("opaque-ref", self._metadata())
        self.assertEqual(snapshot.artifact_bytes, len(_RAW))
        self.assertEqual(snapshot.artifact_sha256, _SHA256)
        snapshot.cleanup()
        with self.assertRaises((QueueHeldError, QueueRetryableError)):
            custody.snapshot("..", self._metadata(".."))
        self.assertEqual(tuple(self.workspace_parent.iterdir()), ())

    def test_queue_processor_keeps_external_verifier_failure_nonterminal_without_native_authority(self) -> None:
        store = self._store()
        self._admit(store)
        result = store._process_one(
            verifier=self._verifier(MinimalClearanceProofStateError("verifier_timeout")),
            custody=self._custody(),
        )
        self.assertEqual(result.status, "QUEUED")
        self.assertEqual(result.error_code, "verifier_timeout")
        self.assertEqual(store._snapshot()["counts"]["CANDIDATE"], 0)

    def test_export_restore_and_independent_binary_parity(self) -> None:
        store = self._store()
        self._admit(store)
        exported = store._export_bytes()
        self.assertIsInstance(exported, bytes)
        self.assertLessEqual(len(exported), 64 * 1024 * 1024)
        summary = verify_export_bytes(exported, expected_config=store.config.as_json())
        restored = self.root / "restored.sqlite"
        restored_summary = restore_export_to_fresh_database(restored, exported)
        self.assertEqual(summary, restored_summary)
        with self.assertRaises(IndependentQueueError):
            verify_database(restored, expected_config={**store.config.as_json(), "schema_version": 2})

    def test_create_only_bootstrap_keeps_target_after_post_link_fault(self) -> None:
        path = self.root / "bootstrap-post-link.sqlite"
        owner = _QueueRuntimeOwnership(lock_path=path.with_name(path.name + ".runtime-lock"), parent=path.parent)
        self._owners.append(owner)
        real_verify = independent_queue_module.verify_database
        calls = {"count": 0}

        def fault(target, *, expected_config=None):
            calls["count"] += 1
            if calls["count"] == 2:
                raise IndependentQueueError("post_link_fault")
            return real_verify(target, expected_config=expected_config)

        with patch.object(independent_queue_module, "verify_database", side_effect=fault):
            with self.assertRaises(VerificationQueueError):
                _VerificationQueueStore(path=path, config=self._config(), owner=owner)
        self.assertTrue(path.is_file())
        self.assertEqual(real_verify(path, expected_config=self._config().as_json())["schema"], "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFICATION-QUEUE/v6")
        retry = _VerificationQueueStore(path=path, config=self._config(), owner=owner)
        self.assertEqual(retry._snapshot()["counts"]["QUEUED"], 0)
        self.assertEqual(tuple(self.root.glob(".queue-bootstrap-*")), ())

    def test_create_only_restore_keeps_target_after_post_link_fault(self) -> None:
        store = self._store()
        exported = store._export_bytes()
        target = self.root / "restore-post-link.sqlite"
        real_verify = independent_queue_module.verify_database
        calls = {"count": 0}

        def fault(path, *, expected_config=None):
            calls["count"] += 1
            if calls["count"] == 2:
                raise IndependentQueueError("post_link_fault")
            return real_verify(path, expected_config=expected_config)

        with patch.object(independent_queue_module, "verify_database", side_effect=fault):
            with self.assertRaises(IndependentQueueError):
                restore_export_to_fresh_database(target, exported)
        self.assertTrue(target.is_file())
        self.assertEqual(real_verify(target), verify_export_bytes(exported))
        self.assertEqual(restore_export_to_fresh_database(target, exported), verify_export_bytes(exported))
        self.assertEqual(tuple(self.root.glob(".queue-restore-*")), ())
        conflict = self.root / "restore-conflict.sqlite"
        conflict.write_bytes(b"pre-existing-conflict")
        before = conflict.read_bytes()
        with self.assertRaises(IndependentQueueError):
            restore_export_to_fresh_database(conflict, exported)
        self.assertEqual(conflict.read_bytes(), before)

    def test_batch_reader_replays_once_and_returns_requested_order(self) -> None:
        store = self._store(capacity=2)
        self._verify_one(store, "job-a")
        self._verify_one(store, "job-b", factory=_Factory())
        with self.assertRaises(IndependentQueueError):
            read_verified_jobs(store.path, ("job-a",), expected_config=store.config.as_json())
        store._promote_candidates()
        jobs = read_verified_jobs(store.path, ("job-b", "job-a"), expected_config=store.config.as_json())
        self.assertEqual(tuple(job.job_id for job in jobs), ("job-b", "job-a"))
        with self.assertRaises(IndependentQueueError):
            read_verified_jobs(store.path, ("job-a", "job-a"), expected_config=store.config.as_json())

    def test_candidate_promotion_is_one_batch_and_duplicate_promotion_is_empty(self) -> None:
        store = self._store()
        candidate = self._verify_one(store)
        self.assertEqual(candidate.status, "CANDIDATE")
        self.assertEqual(store._snapshot()["counts"]["VERIFIED"], 0)
        first = store._promote_candidates()
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["accepted_count"], 1)
        self.assertEqual(store._snapshot()["counts"]["VERIFIED"], 1)
        self.assertEqual(store._promote_candidates(), ())
        summary = verify_database(store.path, expected_config=store.config.as_json())
        self.assertEqual(summary["accepted_batch_count"], 1)

    def test_candidate_promotion_requires_complete_oldest_prefix(self) -> None:
        store = self._store(capacity=512)
        for index in range(257):
            self._verify_one(store, f"prefix-job-{index}")
        first = store._promote_candidate_batch()
        second = store._promote_candidate_batch()
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertEqual(first["accepted_count"], 256)
        self.assertEqual(second["accepted_count"], 1)
        self.assertIsNone(store._promote_candidate_batch())
        self.assertEqual(verify_database(store.path, expected_config=store.config.as_json())["accepted_batch_count"], 2)

    def test_promotion_response_loss_is_indeterminate_and_restart_converges(self) -> None:
        fired = {"value": False}

        def fault(label: str) -> None:
            if label == "promote_batch" and not fired["value"]:
                fired["value"] = True
                raise RuntimeError("post-commit-canary")

        store = self._store(after_commit_fault=fault)
        self._verify_one(store)
        with self.assertRaises(queue_module.QueueIndeterminateError):
            store._promote_candidates()
        self.assertEqual(verify_database(store.path, expected_config=store.config.as_json())["status_counts"]["VERIFIED"], 1)
        self.assertEqual(store._promote_candidates(), ())
        path, config, owner = store.path, store.config, store._owner
        owner.close()
        self._owners.remove(owner)
        restarted_owner = _QueueRuntimeOwnership(
            lock_path=path.with_name(path.name + ".runtime-lock"),
            parent=path.parent,
        )
        self._owners.append(restarted_owner)
        restarted = _VerificationQueueStore(path=path, config=config, owner=restarted_owner)
        self.assertEqual(restarted._snapshot()["counts"]["VERIFIED"], 1)
        self.assertEqual(restarted._promote_candidates(), ())

    def test_promotion_rollback_cleanup_failure_is_fixed_indeterminate(self) -> None:
        store = self._store()
        self._verify_one(store)
        original_commit = store._commit
        commit_calls = {"count": 0}

        def close_before_uncertain_commit(connection: sqlite3.Connection) -> None:
            commit_calls["count"] += 1
            if commit_calls["count"] == 2:
                connection.close()
                raise VerificationQueueError("commit_uncertain")
            original_commit(connection)

        store._commit = close_before_uncertain_commit  # type: ignore[method-assign]
        with self.assertRaises(queue_module.QueueIndeterminateError) as caught:
            store._promote_candidates()
        self.assertEqual(str(caught.exception), "queue_promotion_indeterminate")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("commit_uncertain", repr(caught.exception))
        store._commit = original_commit  # type: ignore[method-assign]
        self.assertEqual(verify_database(store.path, expected_config=store.config.as_json())["status_counts"]["CANDIDATE"], 1)
        self.assertEqual(store._promote_candidates()[0]["accepted_count"], 1)

    def test_restart_promotes_durable_candidate_before_new_native_work(self) -> None:
        from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime

        runtime_root = self.root / "candidate-runtime-root"
        runtime_root.mkdir()
        profile = ExperimentalPrivateZkProfile.supplied(Path(sys.executable), _VERIFIER)
        runtime_config = QueueConfig.from_profile(
            profile,
            queue_id="minimal-clearance-queue-v6",
            capacity=512,
            artifact_bytes_cap=512 * 1024 * 1024 + 68 + 5090,
            installation_id=INSTALLATION_ID,
        )
        database = runtime_root / "queue.sqlite"
        owner = _QueueRuntimeOwnership(
            lock_path=database.with_name(database.name + ".runtime-lock"),
            parent=database.parent,
        )
        self._owners.append(owner)
        store = _VerificationQueueStore(path=database, config=runtime_config, owner=owner)
        self._verify_one(store)
        owner.close()
        self._owners.remove(owner)
        runtime = MinimalClearanceVerificationRuntime(
            root=runtime_root,
            profile=profile,
            source_root=self.source_root,
        )
        try:
            result = runtime.run(max_jobs=1)
            self.assertEqual(result.outcome, "ACCEPTED")
            self.assertEqual(result.accepted_count, 1)
            self.assertEqual(result.verified, 1)
        finally:
            runtime.close()

    def test_accept_batch_event_mutation_rejects_independent_replay(self) -> None:
        store = self._store()
        self._verify_one(store)
        store._promote_candidates()
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("DROP TRIGGER queue_transitions_no_update")
            row = connection.execute("SELECT sequence,event_bytes FROM queue_transitions WHERE transition_kind='ACCEPT_BATCH'").fetchone()
            self.assertIsNotNone(row)
            event = json.loads(bytes(row[1]).decode("ascii"))
            event["image_sha3_512"] = "00" * 64
            connection.execute("UPDATE queue_transitions SET event_bytes=? WHERE sequence=?", (json.dumps(event, sort_keys=True, separators=(",", ":")).encode("ascii"), int(row[0])))
            connection.commit()
        with self.assertRaises(IndependentQueueError):
            verify_database(store.path)

    def test_independent_verification_rejects_claim_event_row_drift(self) -> None:
        store = self._store()
        self._admit(store)
        work = store._claim_next()
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("DROP TRIGGER queue_leases_no_update")
            connection.execute("UPDATE queue_leases SET worker_id=? WHERE job_id=?", ("tampered", work.job_id))
            connection.execute("CREATE TRIGGER queue_leases_no_update BEFORE UPDATE ON queue_leases BEGIN SELECT RAISE(ABORT,'queue_leases_insert_delete_only'); END")
            connection.commit()
        with self.assertRaises(IndependentQueueError):
            verify_database(store.path)

    def test_schema_has_five_tables_and_no_operation_projection(self) -> None:
        store = self._store()
        with closing(sqlite3.connect(store.path)) as connection:
            tables = {name for kind, name in connection.execute("SELECT type,name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        self.assertEqual(tables, {"queue_metadata", "queue_jobs", "queue_leases", "queue_results", "queue_transitions"})

    def test_public_queue_objects_redact_bearer_and_paths(self) -> None:
        store = self._store()
        self._admit(store)
        work = store._claim_next()
        rendered = repr(work) + json.dumps(store._support_summary(), sort_keys=True)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn(work.lease_token.hex(), rendered)

    def test_application_surface_has_no_direct_lifecycle_or_evidence_exports(self) -> None:
        exported = set(queue_module.__all__)
        self.assertNotIn("_VerificationQueueStore", exported)
        self.assertNotIn("_QueueWorkItem", exported)
        self.assertNotIn("_VerificationEvidence", exported)
        self.assertNotIn("_build_verification_evidence", exported)
        self.assertFalse(hasattr(queue_module, "VerificationQueueStore"))
        self.assertFalse(hasattr(queue_module, "QueueWorkItem"))
        self.assertFalse(hasattr(queue_module, "VerificationEvidence"))

    def test_store_owner_loss_and_path_substitution_fail_before_database_touch(self) -> None:
        store = self._store()
        store._owner.close()
        with self.assertRaises(VerificationQueueError) as closed:
            store._snapshot()
        self.assertEqual(str(closed.exception), "queue_owner")
        replacement = self._store(name="replacement.sqlite")
        replacement.path = self.root / "not-the-owned-database.sqlite"
        with self.assertRaises(VerificationQueueError) as substituted:
            replacement._snapshot()
        self.assertEqual(str(substituted.exception), "queue_owner")

    def test_database_sidecars_are_rejected_before_read(self) -> None:
        store = self._store()
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(store.path) + suffix)
            sidecar.write_bytes(b"sidecar-canary")
            before = sidecar.read_bytes()
            with self.assertRaises(VerificationQueueError):
                _VerificationQueueStore(path=store.path, config=store.config, owner=store._owner)
            self.assertEqual(sidecar.read_bytes(), before)
            sidecar.unlink()


if __name__ == "__main__":
    import unittest

    unittest.main()
