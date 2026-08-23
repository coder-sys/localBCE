"""Focused durable per-claim verification queue tests.

The fakes model only proof evidence and contained-verifier telemetry.  They
never construct a clearance directive or call the clearance state store.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest import TestCase

from app.minimal_clearance_proof_state import (
    MinimalProofAcceptanceV1,
    NativeMinimalClearanceVerifier,
    _CIRCUIT_ID,
    _artifact_public_bytes,
    _parse_statement,
    parse_acceptance_bytes,
)
from app.minimal_clearance_verifier_process import ContainedVerifierResult

from app.minimal_clearance_verification_queue import (
    ArtifactMetadata,
    CustodySnapshot,
    FilesystemArtifactCustody,
    QueueBackpressureError,
    QueueConflictError,
    QueueDeterministicRejectError,
    QueueHeldError,
    QueueIndeterminateError,
    QueueIntegrityError,
    QueueLeaseError,
    QueueRetryableError,
    QueueConfig,
    QueueWorker,
    VerificationEvidence,
    VerificationQueueStore,
    build_verification_evidence,
    run_bounded_workers,
)
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)


_RAW = b"synthetic opaque proof bytes for queue tests"
_RETAINED_ARTIFACT = Path(
    r"C:\Temp\blind-ledger-minimal-clearance-proof-20260817c\minimal_clearance_case0.blmc"
)
_SHA256 = hashlib.sha256(_RAW).digest()
_SHA3 = hashlib.sha3_512(_RAW).digest()
_VERIFIER = bytes.fromhex("AB" * 32)
_STDOUT = (
    b"MINIMAL_CLEARANCE_VERIFIER_ACCEPT inputs=10993 public_inputs=8145 "
    b"layers=169 terms=21954328 public_bytes=3340 proof_bytes=317784 rate=4 "
    b"queries=189 transcript_version=6 "
    b"circuit_id=1eaaf14f3b23db1ed02f3c378099627767f81142e0114f90448cac7c1cc66be0 "
    b"state_mutations=0 clear_authorizations=0\n"
)
_STDERR = (
    b"MINIMAL_CLEARANCE_BUILD phase=public\n"
    b"MINIMAL_CLEARANCE_BUILD phase=private\n"
    b"MINIMAL_CLEARANCE_BUILD phase=assertions\n"
    b"MINIMAL_CLEARANCE_BUILD phase=mkcircuit\n"
    b"MINIMAL_CLEARANCE_BUILD phase=complete inputs=10993 public_inputs=8145 layers=169 terms=21954328\n"
    b"MINIMAL_CLEARANCE_VERIFIER_STAGE proof.read=accept remaining=0\n"
    b"MINIMAL_CLEARANCE_VERIFIER_STAGE commitment=received\n"
    b"MINIMAL_CLEARANCE_VERIFIER_STAGE verify=accept\n"
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class _Clock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def now_ms(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


def _Acceptance(
    *,
    artifact_bytes: int = len(_RAW),
    artifact_sha256: bytes = _SHA256,
    artifact_digest: bytes = _SHA3,
    proof_accepted: bool = True,
) -> MinimalProofAcceptanceV1:
    retained = _RETAINED_ARTIFACT.read_bytes()
    _, statement_bytes, _ = _artifact_public_bytes(retained)
    return MinimalProofAcceptanceV1(
        statement=_parse_statement(statement_bytes),
        artifact_sha256=artifact_sha256,
        artifact_digest=artifact_digest,
        artifact_bytes=artifact_bytes,
        circuit_id=_CIRCUIT_ID,
        proof_accepted=proof_accepted,
    )


def _Containment(**updates: object) -> ContainedVerifierResult:
    values: dict[str, object] = {
        "exit_code": 0,
        "stdout": _STDOUT,
        "stderr": _STDERR,
        "peak_job_commit_bytes": 1_100_000,
        "cap_bytes": 5_000_000_000,
        "cap_enforced": True,
        "active_process_limit": 1,
        "timed_out": False,
    }
    values.update(updates)
    return ContainedVerifierResult(**values)  # type: ignore[arg-type]


class _Custody:
    def __init__(self, root: Path, raw: bytes = _RAW) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.raw = raw
        self.calls: list[str] = []
        self.snapshot_paths: list[Path] = []

    def snapshot(self, artifact_ref: str, expected: ArtifactMetadata) -> CustodySnapshot:
        self.calls.append(artifact_ref)
        directory = self.root / f"snapshot-{len(self.calls)}"
        directory.mkdir()
        path = directory / "artifact.bin"
        path.write_bytes(self.raw)
        path.chmod(0o400)
        self.snapshot_paths.append(path)

        def cleanup() -> None:
            path.chmod(0o600)
            path.unlink()
            directory.rmdir()

        return CustodySnapshot(path, len(self.raw), hashlib.sha256(self.raw).digest(), hashlib.sha3_512(self.raw).digest(), True, cleanup)


class _Verifier:
    def __init__(self, *, failure: BaseException | None = None, barrier: threading.Barrier | None = None, identity: bytes = _VERIFIER, containment: ContainedVerifierResult | None = None) -> None:
        self.failure = failure
        self.barrier = barrier
        self.identity = identity
        self.workspace_token = object()
        self.last_containment_result = containment or _Containment()

    def identity_sha256(self) -> bytes:
        return self.identity

    def verify(self, artifact_path: Path) -> MinimalProofAcceptanceV1:
        if self.barrier is not None:
            self.barrier.wait(timeout=10)
        if self.failure is not None:
            raise self.failure
        if not artifact_path.is_file() or artifact_path.is_symlink():
            raise QueueHeldError("snapshot_missing")
        return _Acceptance()


class _Factory:
    def __init__(self, *, failure: BaseException | None = None, barrier: threading.Barrier | None = None, identity: bytes = _VERIFIER, containment: ContainedVerifierResult | None = None) -> None:
        self.failure = failure
        self.barrier = barrier
        self.identity = identity
        self.containment = containment
        self.instances: list[_Verifier] = []

    def __call__(self) -> NativeMinimalClearanceVerifier:
        # Test boundary only: the production worker accepts this concrete
        # verifier type, while the contained native call is replaced here by
        # a deterministic fixture.
        verifier = object.__new__(NativeMinimalClearanceVerifier)
        verifier.failure = self.failure
        verifier.barrier = self.barrier
        verifier.identity = self.identity
        verifier.workspace_token = object()
        verifier.last_containment_result = self.containment or _Containment()

        def identity_sha256() -> bytes:
            return verifier.identity

        def verify(artifact_path: Path) -> MinimalProofAcceptanceV1:
            if verifier.barrier is not None:
                verifier.barrier.wait(timeout=10)
            if verifier.failure is not None:
                raise verifier.failure
            if not artifact_path.is_file() or artifact_path.is_symlink():
                raise QueueHeldError("snapshot_missing")
            return _Acceptance()

        verifier.identity_sha256 = identity_sha256
        verifier.verify = verify
        self.instances.append(verifier)
        return verifier


class VerificationQueueTests(TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-queue-tests-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _config(self, *, capacity: int = 4, lease_seconds: int = 30) -> QueueConfig:
        return QueueConfig("queue-test", capacity, lease_seconds, _VERIFIER, 512 * 1024 * 1024, ("custody_read", "verifier_timeout"))

    def _store(self, *, capacity: int = 4, clock: _Clock | None = None, before_fault=None, after_commit_fault=None) -> VerificationQueueStore:
        return VerificationQueueStore(
            path=self.root / f"queue-{len(list(self.root.glob('queue-*.sqlite')))}.sqlite",
            config=self._config(capacity=capacity), clock=clock, before_fault=before_fault, after_commit_fault=after_commit_fault,
        )

    @staticmethod
    def _metadata(ref: str = "opaque-ref") -> ArtifactMetadata:
        return ArtifactMetadata(ref, len(_RAW), _SHA256, _SHA3)

    def _admit(self, store: VerificationQueueStore, job_id: str = "job-1", ref: str = "opaque-ref"):
        return store.admit(job_id=job_id, metadata=self._metadata(ref))

    def _verify_one(self, store: VerificationQueueStore, job_id: str = "job-1", *, factory: _Factory | None = None) -> object:
        self._admit(store, job_id)
        worker = QueueWorker(store=store, worker_id=f"worker-{job_id}", custody=_Custody(self.root / f"custody-{job_id}"), verifier_factory=factory or _Factory())
        return worker.process_one()

    def test_admission_retry_conflict_capacity_and_terminal_backpressure(self) -> None:
        store = self._store(capacity=1)
        first = self._admit(store)
        retry = self._admit(store)
        self.assertEqual(first.operation_id, retry.operation_id)
        with self.assertRaises(QueueConflictError):
            store.admit(job_id="job-1", metadata=self._metadata("different-ref"))
        with self.assertRaises(QueueBackpressureError):
            self._admit(store, "job-2")
        work = store.claim_next(worker_id="worker-1")
        self.assertIsNotNone(work)
        with self.assertRaises(QueueBackpressureError):
            self._admit(store, "job-2")
        store.complete_rejected(work, "proof_rejected")
        self._admit(store, "job-2")
        self.assertEqual(store.snapshot()["counts"]["REJECTED"], 1)

    def test_concurrent_identical_and_distinct_admission_has_no_duplicate(self) -> None:
        store = self._store()
        with ThreadPoolExecutor(max_workers=4) as executor:
            same = list(executor.map(lambda _: self._admit(store, "same"), range(4)))
            distinct = list(executor.map(lambda index: self._admit(store, f"distinct-{index}"), range(3)))
        self.assertEqual(len({item.operation_id for item in same}), 1)
        self.assertEqual(len({item.job_id for item in distinct}), 3)
        self.assertEqual(store.snapshot()["counts"]["QUEUED"], 4)
        store.verify_integrity()

    def test_concurrent_claim_has_one_lease_and_stale_completion_is_zero_mutation(self) -> None:
        store = self._store(capacity=1)
        self._admit(store)
        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(executor.map(lambda worker: store.claim_next(worker_id=worker), ("w1", "w2")))
        work = next(item for item in claims if item is not None)
        self.assertEqual(sum(item is not None for item in claims), 1)
        before = store.export_bytes()
        bad = type(work)(work.queue_id, work.job_id, work.operation_id, work.metadata, work.attempt, "other", work.lease_token, work.lease_expires_ms, work.expected_verifier_sha256)
        with self.assertRaises(QueueLeaseError):
            store.complete_rejected(bad, "proof_rejected")
        self.assertEqual(store.export_bytes(), before)
        store.complete_rejected(work, "proof_rejected")
        with self.assertRaises(QueueLeaseError):
            store.complete_rejected(work, "proof_rejected")
        self.assertEqual(store.retry_result(work.operation_id).status, "REJECTED")

    def test_expiry_requeues_then_holds_at_max_attempt(self) -> None:
        clock = _Clock()
        store = self._store(clock=clock, capacity=1,)
        self._admit(store)
        for attempt in (1, 2):
            work = store.claim_next(worker_id=f"w{attempt}")
            self.assertEqual(work.attempt, attempt)
            clock.advance(31_000)
            self.assertEqual(store.recover_expired(), 1)
            self.assertEqual(store.get_job("job-1").status, "QUEUED")
        work = store.claim_next(worker_id="w3")
        self.assertEqual(work.attempt, 3)
        clock.advance(31_000)
        self.assertEqual(store.recover_expired(), 1)
        self.assertEqual(store.get_job("job-1").status, "HELD")
        store.verify_integrity()

    def test_worker_maps_reject_retry_and_identity_or_custody_failure(self) -> None:
        reject_store = self._store()
        self._admit(reject_store)
        reject_worker = QueueWorker(
            store=reject_store, worker_id="reject-worker", custody=_Custody(self.root / "reject-custody"),
            verifier_factory=_Factory(failure=QueueDeterministicRejectError("proof_rejected")),
        )
        rejected = reject_worker.process_one()
        self.assertEqual(rejected.status, "REJECTED")

        retry_store = self._store()
        self._admit(retry_store)
        retry_custody = _Custody(self.root / "retry-custody")
        first = QueueWorker(
            store=retry_store, worker_id="retry-worker", custody=retry_custody,
            verifier_factory=_Factory(failure=QueueRetryableError("verifier_timeout")),
        ).process_one()
        self.assertEqual(first.status, "QUEUED")
        second = QueueWorker(
            store=retry_store, worker_id="retry-worker-2", custody=retry_custody,
            verifier_factory=_Factory(),
        ).process_one()
        self.assertEqual(second.status, "VERIFIED")

        held_store = self._store()
        self._admit(held_store)
        held = QueueWorker(
            store=held_store, worker_id="held-worker", custody=_Custody(self.root / "held-custody"),
            verifier_factory=_Factory(identity=bytes(32)),
        ).process_one()
        self.assertEqual(held.status, "HELD")

        native_reject_store = self._store()
        self._admit(native_reject_store)
        native_rejected = QueueWorker(
            store=native_reject_store, worker_id="native-reject-worker", custody=_Custody(self.root / "native-reject-custody"),
            verifier_factory=_Factory(failure=RuntimeError("proof_verifier_rejected")),
        ).process_one()
        self.assertEqual(native_rejected.status, "REJECTED")

    def test_snapshot_and_output_failures_are_terminal_or_retryable(self) -> None:
        for name, snapshot in (
            ("missing", CustodySnapshot(self.root / "missing.bin", len(_RAW), _SHA256, _SHA3, True)),
            ("writable", CustodySnapshot(self.root / "missing.bin", len(_RAW), _SHA256, _SHA3, False)),
            ("wrong-size", CustodySnapshot(self.root / "missing.bin", 1, _SHA256, _SHA3, True)),
        ):
            class BadCustody:
                def snapshot(self, artifact_ref, expected):
                    return snapshot

            store = self._store()
            self._admit(store, f"job-{name}")
            result = QueueWorker(
                store=store, worker_id=f"worker-{name}", custody=BadCustody(), verifier_factory=_Factory(),
            ).process_one()
            self.assertEqual(result.status, "HELD")

        for containment in (
            _Containment(cap_enforced=False),
            _Containment(exit_code=1),
            _Containment(timed_out=True),
            _Containment(stdout=b"\xff"),
            _Containment(stderr=b"x" * (262_144 + 1)),
        ):
            store = self._store()
            self._admit(store)
            result = QueueWorker(
                store=store, worker_id="output-worker", custody=_Custody(self.root / "output-custody"), verifier_factory=_Factory(containment=containment),
            ).process_one()
            self.assertEqual(result.status, "HELD")

    def test_evidence_rejects_missing_or_bad_containment_and_preserves_ownership(self) -> None:
        snapshot = CustodySnapshot(Path("opaque-test-path"), len(_RAW), _SHA256, _SHA3, True)
        for containment in (None, _Containment(cap_enforced=False), _Containment(peak_job_commit_bytes=5_000_000_001), _Containment(timed_out=True), _Containment(exit_code=1)):
            with self.subTest(containment=containment):
                with self.assertRaises(QueueRetryableError):
                    build_verification_evidence(_Acceptance(), containment, snapshot, _VERIFIER)
        for containment in (
            _Containment(stdout=_STDOUT.replace(b"rate=4", b"rate=999")),
            _Containment(stderr=_STDERR + b"opaque verifier-owned field\n"),
            _Containment(stdout=b"opaque ASCII verifier output\n", stderr=b"another field\n"),
        ):
            with self.subTest(opaque_output=containment):
                evidence = build_verification_evidence(_Acceptance(), containment, snapshot, _VERIFIER)
                self.assertEqual(evidence.artifact_bytes, len(_RAW))
                self.assertEqual(evidence.verifier_sha256, _VERIFIER)
                self.assertEqual(evidence.stdout_sha3_512, hashlib.sha3_512(containment.stdout).digest())
                self.assertEqual(evidence.stderr_sha3_512, hashlib.sha3_512(containment.stderr).digest())
        with self.assertRaises(QueueHeldError) as caught:
            build_verification_evidence(object(), _Containment(), snapshot, _VERIFIER)
        self.assertEqual(str(caught.exception), "proof_acceptance_type")
        with self.assertRaises(QueueHeldError):
            build_verification_evidence(_Acceptance(artifact_bytes=1), _Containment(), snapshot, _VERIFIER)

    def test_verified_result_persists_canonical_acceptance_and_independent_tamper_rejects(self) -> None:
        store = self._store()
        self._admit(store)
        result = QueueWorker(
            store=store, worker_id="acceptance-worker", custody=_Custody(self.root / "acceptance-custody"), verifier_factory=_Factory(),
        ).process_one()
        self.assertEqual(result.status, "VERIFIED")
        self.assertIsNotNone(result.receipt_bytes)
        receipt = json.loads(result.receipt_bytes.decode("ascii"))
        acceptance_bytes = bytes.fromhex(receipt["evidence"]["acceptance_bytes"])
        self.assertEqual(parse_acceptance_bytes(acceptance_bytes).canonical_bytes(), acceptance_bytes)
        exported = store.export_bytes()
        with closing(sqlite3.connect(store.path)) as connection:
            persisted_receipt = bytes(connection.execute("SELECT receipt_bytes FROM queue_results WHERE job_id='job-1'").fetchone()[0])
        self.assertIn(receipt["evidence"]["acceptance_bytes"].encode("ascii"), persisted_receipt)
        independent = verify_export_bytes(exported, expected_config=store.config.as_json())
        self.assertEqual(independent["status_counts"]["VERIFIED"], 1)
        tampered = json.loads(exported.decode("ascii"))
        receipt_hex = tampered["results"][0]["receipt_bytes"]
        tampered["results"][0]["receipt_bytes"] = ("0" if receipt_hex[0] != "0" else "1") + receipt_hex[1:]
        tampered_bytes = json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaises(IndependentQueueError):
            verify_export_bytes(tampered_bytes)

    def test_faults_roll_back_state_and_export(self) -> None:
        for label in ("after_admission_write", "after_transition"):
            armed = {"value": False}

            def fault(current: str, *, armed=armed, label=label) -> None:
                if armed["value"] and current == label:
                    raise RuntimeError("injected")

            store = self._store(before_fault=fault)
            before = store.export_bytes()
            armed["value"] = True
            with self.assertRaises(RuntimeError):
                self._admit(store)
            self.assertEqual(store.export_bytes(), before)
            store.verify_integrity()

        armed = {"value": False}

        def retry_fault(current: str) -> None:
            if armed["value"] and current == "after_retry_write":
                raise RuntimeError("injected")

        store = self._store(before_fault=retry_fault)
        self._admit(store)
        work = store.claim_next(worker_id="retry-worker")
        before = store.export_bytes()
        armed["value"] = True
        with self.assertRaises(RuntimeError):
            store.complete_retryable(work, "verifier_timeout")
        self.assertEqual(store.export_bytes(), before)
        store.verify_integrity()

        for label in ("after_result_write", "after_transition"):
            armed = {"value": False}

            def fault(current: str, *, armed=armed, label=label) -> None:
                if armed["value"] and current == label:
                    raise RuntimeError("injected")

            store = self._store(before_fault=fault)
            self._admit(store)
            work = store.claim_next(worker_id="worker")
            before = store.export_bytes()
            armed["value"] = True
            with self.assertRaises(RuntimeError):
                store.complete_rejected(work, "proof_rejected")
            self.assertEqual(store.export_bytes(), before)
            store.verify_integrity()

    def test_postcommit_response_loss_has_exact_retry_recovery(self) -> None:
        raised = {"value": False}

        def after_commit(label: str) -> None:
            if label == "admit" and not raised["value"]:
                raised["value"] = True
                raise RuntimeError("response lost")

        store = self._store(after_commit_fault=after_commit)
        with self.assertRaises(QueueIndeterminateError):
            self._admit(store)
        exact = self._admit(store)
        self.assertEqual(exact.status, "QUEUED")

        raised["value"] = False
        work = store.claim_next(worker_id="worker")

        def after_complete(label: str) -> None:
            if label == "complete" and not raised["value"]:
                raised["value"] = True
                raise RuntimeError("response lost")

        store._after_commit_fault = after_complete
        with self.assertRaises(QueueIndeterminateError):
            store.complete_rejected(work, "proof_rejected")
        recovered = store.retry_result(work.operation_id)
        self.assertEqual(recovered.status, "REJECTED")

    def test_export_restore_and_independent_mutations_fail_closed(self) -> None:
        store = self._store()
        self._admit(store, "job-a", "ref-a")
        self._admit(store, "job-b", "ref-b")
        export = store.export_bytes()
        summary = verify_export_bytes(export)
        self.assertEqual(summary["status_counts"]["QUEUED"], 2)
        restored = self.root / "restored.sqlite"
        self.assertEqual(restore_export_to_fresh_database(restored, export), summary)
        self.assertEqual(verify_database(restored), summary)
        value = json.loads(export.decode("ascii"))
        mutations = []
        unknown = json.loads(export.decode("ascii"))
        unknown["unknown"] = 1
        mutations.append(unknown)
        reordered = json.loads(export.decode("ascii"))
        reordered["jobs"].reverse()
        mutations.append(reordered)
        root_drift = json.loads(export.decode("ascii"))
        root_drift["metadata"]["head_root"] = "00" * 64
        mutations.append(root_drift)
        for mutation in mutations:
            with self.subTest(mutation=list(mutation)):
                with self.assertRaises(IndependentQueueError):
                    verify_export_bytes(_canonical(mutation))
        self.assertNotIn(str(self.root), export.decode("ascii"))
        self.assertNotIn(_STDOUT.decode("ascii"), export.decode("ascii"))
        self.assertNotIn(_STDERR.decode("ascii"), export.decode("ascii"))

    def test_four_workers_overlap_and_use_fresh_custody_and_verifiers(self) -> None:
        store = self._store()
        for index in range(4):
            self._admit(store, f"job-{index}", f"opaque-{index}")
        custody = _Custody(self.root / "four-custody")
        barrier = threading.Barrier(4)
        factory = _Factory(barrier=barrier)
        workers = tuple(
            QueueWorker(store=store, worker_id=f"worker-{index}", custody=custody, verifier_factory=factory)
            for index in range(4)
        )
        results = run_bounded_workers(workers)
        self.assertEqual([result.status for result in results], ["VERIFIED"] * 4)
        self.assertEqual(len(factory.instances), 4)
        self.assertEqual(len({id(item) for item in factory.instances}), 4)
        self.assertEqual(len({id(item.workspace_token) for item in factory.instances}), 4)
        self.assertEqual(len(set(custody.calls)), 4)
        self.assertEqual(store.snapshot()["counts"]["VERIFIED"], 4)
        store.verify_integrity()
        self.assertEqual(verify_database(store.path)["status_counts"]["VERIFIED"], 4)
        support = json.dumps(store.support_summary(), sort_keys=True)
        self.assertNotIn("opaque-", support)
        self.assertNotIn("custody", support)

    def test_filesystem_custody_is_fresh_readonly_and_does_not_persist_path(self) -> None:
        source = self.root / "source-proof.bin"
        source.write_bytes(_RAW)
        workspace = self.root / "custody-work"
        workspace.mkdir()
        custody = FilesystemArtifactCustody(resolver=lambda ref: source, workspace_parent=workspace)
        snapshot = custody.snapshot("opaque", self._metadata())
        self.assertTrue(snapshot.path.is_file())
        self.assertTrue(snapshot.readonly)
        self.assertNotEqual(snapshot.path, source)
        self.assertEqual(snapshot.path.read_bytes(), _RAW)
        snapshot.cleanup()
        self.assertEqual(list(workspace.iterdir()), [])

    def test_independent_database_rejects_config_and_identity_drift(self) -> None:
        store = self._store()
        self._admit(store)
        connection = sqlite3.connect(store.path)
        try:
            connection.execute("UPDATE queue_metadata SET verifier_sha256=? WHERE id=1", (bytes(32),))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises((QueueIntegrityError, IndependentQueueError)):
            VerificationQueueStore(path=store.path, config=self._config())
        with self.assertRaises(IndependentQueueError):
            verify_database(store.path)

    def test_sqlite_busy_is_bounded_and_fail_closed(self) -> None:
        store = self._store()
        self._admit(store)
        connection = store._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            with self.assertRaises(Exception) as caught:
                store.claim_next(worker_id="blocked-worker")
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 8.0)
            self.assertIn("queue_busy", str(caught.exception))
        finally:
            connection.execute("ROLLBACK")
            connection.close()

    def test_queue_source_has_no_clearance_state_or_prover_dependency(self) -> None:
        source = Path("app/minimal_clearance_verification_queue.py").read_text(encoding="utf-8")
        independent = Path("app/minimal_clearance_verification_queue_independent.py").read_text(encoding="utf-8")
        for text in (source, independent):
            self.assertNotIn("MinimalClearanceStateStoreV1", text)
            self.assertNotIn("apply_acceptance", text)
            self.assertNotIn("subprocess", text)
            self.assertNotIn("prover", text.lower())
        self.assertIn("MinimalProofAcceptanceV1", source)


if __name__ == "__main__":
    import unittest

    unittest.main()
