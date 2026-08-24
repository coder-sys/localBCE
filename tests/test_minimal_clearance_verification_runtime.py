from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from app.minimal_clearance_proof_primitives import MinimalClearanceProofStateError, NativeMinimalClearanceVerifier
from app.minimal_clearance_verification_queue import ArtifactMetadata, QueueConfig, VerificationQueueError, _QueueRuntimeOwnership, _VerificationQueueStore
from app.minimal_clearance_verification_profile import ExperimentalPrivateZkProfile, derive_installation_id
from app.minimal_clearance_verification_runtime import (
    MinimalClearanceVerificationRuntime,
    RuntimeRunResult,
    VerificationRuntimeError,
)


def _runtime_failure(
    _verifier: NativeMinimalClearanceVerifier,
    _artifact: Path,
    **_expected_metadata: object,
) -> object:
    raise MinimalClearanceProofStateError("verifier_timeout")


class VerificationRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-runtime-v3-")
        self.root = Path(self.temp.name)
        self.source_root = self.root / "source"
        self.source_root.mkdir()
        self.source = self.source_root / "opaque-ref"
        self.raw = b"runtime synthetic artifact"
        self.source.write_bytes(self.raw)
        self.source.chmod(0o400)
        self.executable = Path(sys.executable)
        self.verifier_hash = hashlib.sha256(self.executable.read_bytes()).digest()
        self.profile = ExperimentalPrivateZkProfile.supplied(self.executable, self.verifier_hash)
        self.config = QueueConfig("runtime-queue", 4, self.verifier_hash, 512 * 1024 * 1024)
        self.identity = NativeMinimalClearanceVerifier.identity_sha256
        self.preflight = NativeMinimalClearanceVerifier.preflight
        self.verify = NativeMinimalClearanceVerifier.verify
        NativeMinimalClearanceVerifier.identity_sha256 = lambda _self: self.verifier_hash  # type: ignore[assignment]
        NativeMinimalClearanceVerifier.preflight = lambda _self: None  # type: ignore[assignment]
        NativeMinimalClearanceVerifier.verify = _runtime_failure  # type: ignore[assignment]
        self._owners: list[_QueueRuntimeOwnership] = []

    def tearDown(self) -> None:
        NativeMinimalClearanceVerifier.identity_sha256 = self.identity
        NativeMinimalClearanceVerifier.preflight = self.preflight
        NativeMinimalClearanceVerifier.verify = self.verify
        for owner in reversed(self._owners):
            owner.close()
        self.temp.cleanup()

    def _runtime_root(self, database: Path) -> Path:
        root = self.root / (database.stem + "-runtime-root")
        root.mkdir(exist_ok=True)
        return root

    def _runtime(self, database: Path) -> MinimalClearanceVerificationRuntime:
        return MinimalClearanceVerificationRuntime(root=self._runtime_root(database), profile=self.profile, source_root=self.source_root)

    def _runtime_database(self, database: Path) -> Path:
        return self._runtime_root(database) / "queue.sqlite"

    def _runtime_config(self, database: Path) -> QueueConfig:
        return QueueConfig.from_profile(
            self.profile,
            queue_id="minimal-clearance-queue-v4",
            capacity=512,
            artifact_bytes_cap=512 * 1024 * 1024,
            installation_id=derive_installation_id(self._runtime_root(database)),
        )

    def _direct_store(self, database: Path) -> _VerificationQueueStore:
        owner = _QueueRuntimeOwnership(
            lock_path=database.with_name(database.name + ".runtime-lock"),
            parent=database.parent,
        )
        self._owners.append(owner)
        return _VerificationQueueStore(path=database, config=self.config, owner=owner)

    def test_one_os_released_owner_blocks_second_runtime_before_claim(self) -> None:
        database = self.root / "runtime.sqlite"
        first = self._runtime(database)
        try:
            with self.assertRaises(VerificationRuntimeError) as raised:
                self._runtime(database)
            self.assertEqual(str(raised.exception), "runtime_owner")
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)
        finally:
            first.close()
        second = self._runtime(database)
        self.assertEqual(second.run(max_jobs=1).processed, 0)
        second.close()

    def test_private_store_requires_exact_live_runtime_owner_and_preserves_lease(self) -> None:
        database = self.root / "private-store.sqlite"
        missing_database = self.root / "missing-without-owner.sqlite"
        with self.assertRaises(VerificationQueueError):
            _VerificationQueueStore(path=missing_database, config=self.config)
        self.assertFalse(missing_database.exists())
        runtime = self._runtime(database)
        runtime_database = runtime._database_path
        runtime_config = runtime._store.config  # type: ignore[union-attr]
        metadata = ArtifactMetadata("opaque-ref", len(self.raw), hashlib.sha256(self.raw).digest(), hashlib.sha3_512(self.raw).digest())
        runtime.admit(job_id="owned-job", metadata=metadata)
        work = runtime._store._claim_next()  # type: ignore[union-attr]
        self.assertIsNotNone(work)
        with self.assertRaises(VerificationQueueError) as missing:
            _VerificationQueueStore(path=runtime_database, config=runtime_config)  # type: ignore[call-arg]
        self.assertEqual(str(missing.exception), "queue_owner")

        wrong_database = self.root / "wrong-owner.sqlite"
        wrong_owner = _QueueRuntimeOwnership(
            lock_path=wrong_database.with_name(wrong_database.name + ".runtime-lock"),
            parent=wrong_database.parent,
        )
        self._owners.append(wrong_owner)
        with self.assertRaises(VerificationQueueError) as wrong:
            _VerificationQueueStore(path=runtime_database, config=runtime_config, owner=wrong_owner)
        self.assertEqual(str(wrong.exception), "queue_owner")
        with self.assertRaises(VerificationQueueError) as second_owner:
            _QueueRuntimeOwnership(
                lock_path=runtime_database.with_name(runtime_database.name + ".runtime-lock"),
                parent=runtime_database.parent,
            )
        self.assertEqual(str(second_owner.exception), "queue_owner")

        self.assertEqual(runtime._store._get_job("owned-job").status, "LEASED")  # type: ignore[union-attr]
        result = runtime._store._complete_rejected(work, "proof_rejected")  # type: ignore[union-attr]
        self.assertEqual(result.status, "REJECTED")
        retry = runtime._store._complete_rejected(work, "proof_rejected")  # type: ignore[union-attr]
        self.assertEqual(retry.status, "REJECTED")
        runtime.close()
        restarted = self._runtime(database)
        restarted.close()

    @unittest.skipUnless(os.name == "nt", "Windows CreateFile share-deny contention is not qualified on this platform")
    def test_windows_subprocess_cannot_acquire_or_replace_runtime_owner(self) -> None:
        database = self.root / "windows-contention.sqlite"
        runtime = self._runtime(database)
        runtime_root = self._runtime_root(database)
        lock = runtime._database_path.with_name(runtime._database_path.name + ".runtime-lock")
        try:
            with self.assertRaises(OSError):
                lock.unlink()
            with self.assertRaises(OSError):
                lock.write_bytes(b"replace")
            script = (
                "import sys\n"
                "from pathlib import Path\n"
                "from app.minimal_clearance_verification_profile import ExperimentalPrivateZkProfile\n"
                "from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime, VerificationRuntimeError\n"
                "try:\n"
                " executable=Path(sys.executable)\n"
                " profile=ExperimentalPrivateZkProfile.supplied(executable, bytes.fromhex(sys.argv[3]))\n"
                " MinimalClearanceVerificationRuntime(root=Path(sys.argv[1]), profile=profile, source_root=Path(sys.argv[2]))\n"
                "except VerificationRuntimeError as error:\n"
                " raise SystemExit(0 if str(error) == 'runtime_owner' else 2)\n"
                "raise SystemExit(3)\n"
            )
            completed = subprocess.run(
                [sys.executable, "-c", script, str(runtime_root), str(self.source_root), self.verifier_hash.hex()],
                cwd=str(Path(__file__).parents[1]),
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
        finally:
            runtime.close()

    def test_state_owned_roots_isolate_workspace_owners(self) -> None:
        first = self._runtime(self.root / "first.sqlite")
        try:
            second = self._runtime(self.root / "second.sqlite")
            second.close()
        finally:
            first.close()

    def test_runtime_owner_loss_is_fixed_and_closes_other_owner(self) -> None:
        runtime = self._runtime(self.root / "owner-loss.sqlite")
        runtime._database_owner.close()  # type: ignore[union-attr]
        with self.assertRaises(VerificationRuntimeError) as raised:
            runtime.support_summary()
        self.assertEqual(str(raised.exception), "runtime_owner")
        with self.assertRaises(VerificationRuntimeError):
            runtime.close()
        replacement = _QueueRuntimeOwnership(
            lock_path=runtime._workspace_parent / ".BLV3-WORKSPACE-PARENT-LOCK",
            parent=runtime._workspace_parent,
        )
        replacement.close()

    def test_same_state_owned_root_cannot_have_second_runtime(self) -> None:
        database = self.root / "switched.sqlite"
        first = self._runtime(database)
        try:
            with self.assertRaises(VerificationRuntimeError) as raised:
                MinimalClearanceVerificationRuntime(
                    root=self._runtime_root(database),
                    profile=self.profile,
                    source_root=self.source_root,
                )
            self.assertEqual(str(raised.exception), "runtime_owner")
        finally:
            first.close()

    def test_startup_scavenges_only_marked_v3_workspace_and_reports_count(self) -> None:
        runtime_root = self._runtime_root(self.root / "scavenge.sqlite")
        workspace = runtime_root / "workspaces"
        workspace.mkdir()
        orphan = workspace / "BLV3-WORKSPACE-orphan"
        orphan.mkdir()
        (orphan / ".BLV3-WORKSPACE").write_bytes(b"BL/NATIVE-V3/MINIMAL-CLEARANCE-WORKSPACE/v3\x00")
        (orphan / "canary.bin").write_bytes(b"PHI-CANARY-CREDENTIAL")
        with self.assertRaises(VerificationRuntimeError) as raised:
            self._runtime(self.root / "scavenge.sqlite")
        self.assertEqual(str(raised.exception), "runtime_workspace")
        self.assertTrue(orphan.exists())

    def test_malformed_v3_workspace_fails_closed_and_is_not_deleted(self) -> None:
        runtime_root = self._runtime_root(self.root / "malformed.sqlite")
        workspace = runtime_root / "workspaces"
        workspace.mkdir()
        malformed = workspace / "BLV3-WORKSPACE-malformed"
        malformed.mkdir()
        (malformed / "unexpected").write_bytes(b"canary")
        with self.assertRaises(VerificationRuntimeError) as raised:
            self._runtime(self.root / "malformed.sqlite")
        self.assertEqual(str(raised.exception), "runtime_workspace")
        self.assertTrue(malformed.exists())

    def test_sequential_runtime_processing_has_bounded_aggregate_result(self) -> None:
        database = self.root / "process.sqlite"
        runtime_database = self._runtime_database(database)
        owner = _QueueRuntimeOwnership(
            lock_path=runtime_database.with_name(runtime_database.name + ".runtime-lock"),
            parent=runtime_database.parent,
        )
        self._owners.append(owner)
        store = _VerificationQueueStore(path=runtime_database, config=self._runtime_config(database), owner=owner)
        metadata = ArtifactMetadata("opaque-ref", len(self.raw), hashlib.sha256(self.raw).digest(), hashlib.sha3_512(self.raw).digest())
        store._admit(job_id="job-1", metadata=metadata)
        store._admit(job_id="job-2", metadata=metadata)
        store._owner.close()
        self._owners.remove(store._owner)
        runtime = self._runtime(database)
        try:
            result = runtime.run(max_jobs=2)
            self.assertIsInstance(result, RuntimeRunResult)
            self.assertEqual(result.processed, 2)
            self.assertEqual(result.verified, 0)
            self.assertEqual(result.requeued, 2)
            rendered = repr(result)
            self.assertNotIn(str(self.root), rendered)
            self.assertNotIn("opaque-ref", rendered)
        finally:
            runtime.close()

    def test_runtime_limits_and_close_are_fixed(self) -> None:
        runtime = self._runtime(self.root / "limits.sqlite")
        with self.assertRaises(VerificationRuntimeError):
            runtime.run(max_jobs=0)
        runtime.close()
        with self.assertRaises(VerificationRuntimeError) as raised:
            runtime.run(max_jobs=1)
        self.assertEqual(str(raised.exception), "runtime_closed")

    def test_startup_recovers_unexpired_lease_before_preflight(self) -> None:
        database = self.root / "restart.sqlite"
        runtime_database = self._runtime_database(database)
        owner = _QueueRuntimeOwnership(
            lock_path=runtime_database.with_name(runtime_database.name + ".runtime-lock"),
            parent=runtime_database.parent,
        )
        self._owners.append(owner)
        store = _VerificationQueueStore(path=runtime_database, config=self._runtime_config(database), owner=owner)
        metadata = ArtifactMetadata("opaque-ref", len(self.raw), hashlib.sha256(self.raw).digest(), hashlib.sha3_512(self.raw).digest())
        store._admit(job_id="restart-job", metadata=metadata)
        store._claim_next()
        store._owner.close()
        self._owners.remove(store._owner)
        runtime = self._runtime(database)
        try:
            self.assertEqual(runtime._recovered_leases, 1)
        finally:
            runtime.close()
        reopened_owner = _QueueRuntimeOwnership(
            lock_path=runtime_database.with_name(runtime_database.name + ".runtime-lock"),
            parent=runtime_database.parent,
        )
        self._owners.append(reopened_owner)
        reopened = _VerificationQueueStore(path=runtime_database, config=self._runtime_config(database), owner=reopened_owner)
        self.assertEqual(reopened._get_job("restart-job").status, "QUEUED")
        self.assertEqual(reopened._get_job("restart-job").last_error_code, "runtime_restart")

    def test_runtime_source_has_no_legacy_multiworker_surface(self) -> None:
        source = Path(__import__("app.minimal_clearance_verification_runtime").minimal_clearance_verification_runtime.__file__).read_text(encoding="utf-8")
        self.assertNotIn("ThreadPoolExecutor", source)
        self.assertNotIn("QueueWorker", source)
        self.assertNotIn("lease_token", source)


if __name__ == "__main__":
    unittest.main()
