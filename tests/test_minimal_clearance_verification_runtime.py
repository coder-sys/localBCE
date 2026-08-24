from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from app.minimal_clearance_proof_primitives import MinimalClearanceProofStateError, NativeMinimalClearanceVerifier
from app.minimal_clearance_verification_queue import ArtifactMetadata, QueueConfig, _VerificationQueueStore
from app.minimal_clearance_verification_runtime import (
    MinimalClearanceVerificationRuntime,
    RuntimeRunResult,
    VerificationRuntimeError,
)


def _runtime_failure(_verifier: NativeMinimalClearanceVerifier, _artifact: Path) -> object:
    raise MinimalClearanceProofStateError("verifier_timeout")


class VerificationRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-runtime-v3-")
        self.root = Path(self.temp.name)
        self.source_root = self.root / "source"
        self.workspace = self.root / "workspace"
        self.source_root.mkdir()
        self.workspace.mkdir()
        self.source = self.source_root / "opaque-ref"
        self.raw = b"runtime synthetic artifact"
        self.source.write_bytes(self.raw)
        self.source.chmod(0o400)
        self.executable = Path(sys.executable)
        self.verifier_hash = hashlib.sha256(self.executable.read_bytes()).digest()
        self.config = QueueConfig("runtime-queue", 4, self.verifier_hash, 512 * 1024 * 1024)
        self.identity = NativeMinimalClearanceVerifier.identity_sha256
        self.preflight = NativeMinimalClearanceVerifier.preflight
        self.verify = NativeMinimalClearanceVerifier.verify
        NativeMinimalClearanceVerifier.identity_sha256 = lambda _self: self.verifier_hash  # type: ignore[assignment]
        NativeMinimalClearanceVerifier.preflight = lambda _self: None  # type: ignore[assignment]
        NativeMinimalClearanceVerifier.verify = _runtime_failure  # type: ignore[assignment]

    def tearDown(self) -> None:
        NativeMinimalClearanceVerifier.identity_sha256 = self.identity
        NativeMinimalClearanceVerifier.preflight = self.preflight
        NativeMinimalClearanceVerifier.verify = self.verify
        self.temp.cleanup()

    def _runtime(self, database: Path) -> MinimalClearanceVerificationRuntime:
        return MinimalClearanceVerificationRuntime(
            database=database,
            config=self.config,
            executable=self.executable,
            source_root=self.source_root,
            workspace_parent=self.workspace,
        )

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

    def test_workspace_parent_is_a_process_owner_across_distinct_databases(self) -> None:
        first = self._runtime(self.root / "first.sqlite")
        try:
            with self.assertRaises(VerificationRuntimeError) as raised:
                self._runtime(self.root / "second.sqlite")
            self.assertEqual(str(raised.exception), "runtime_owner")
        finally:
            first.close()

    def test_same_database_cannot_switch_workspace_parent(self) -> None:
        database = self.root / "switched.sqlite"
        first = self._runtime(database)
        alternate = self.root / "alternate-workspace"
        alternate.mkdir()
        try:
            with self.assertRaises(VerificationRuntimeError) as raised:
                MinimalClearanceVerificationRuntime(
                    database=database,
                    config=self.config,
                    executable=self.executable,
                    source_root=self.source_root,
                    workspace_parent=alternate,
                )
            self.assertEqual(str(raised.exception), "runtime_owner")
        finally:
            first.close()

    def test_startup_scavenges_only_marked_v3_workspace_and_reports_count(self) -> None:
        orphan = self.workspace / "BLV3-WORKSPACE-orphan"
        orphan.mkdir()
        (orphan / ".BLV3-WORKSPACE").write_bytes(b"BL/NATIVE-V3/MINIMAL-CLEARANCE-WORKSPACE/v3\x00")
        (orphan / "canary.bin").write_bytes(b"PHI-CANARY-CREDENTIAL")
        runtime = self._runtime(self.root / "scavenge.sqlite")
        try:
            result = runtime.run(max_jobs=1)
            self.assertEqual(result.scavenged_workspaces, 1)
            self.assertFalse(orphan.exists())
            self.assertNotIn(b"PHI-CANARY", json.dumps(result.__dict__ if hasattr(result, "__dict__") else repr(result)).encode())
        finally:
            runtime.close()

    def test_malformed_v3_workspace_fails_closed_and_is_not_deleted(self) -> None:
        malformed = self.workspace / "BLV3-WORKSPACE-malformed"
        malformed.mkdir()
        (malformed / "unexpected").write_bytes(b"canary")
        with self.assertRaises(VerificationRuntimeError) as raised:
            self._runtime(self.root / "malformed.sqlite")
        self.assertEqual(str(raised.exception), "runtime_workspace")
        self.assertTrue(malformed.exists())

    def test_sequential_runtime_processing_has_bounded_aggregate_result(self) -> None:
        database = self.root / "process.sqlite"
        store = _VerificationQueueStore(path=database, config=self.config)
        metadata = ArtifactMetadata("opaque-ref", len(self.raw), hashlib.sha256(self.raw).digest(), hashlib.sha3_512(self.raw).digest())
        store._admit(job_id="job-1", metadata=metadata)
        store._admit(job_id="job-2", metadata=metadata)
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
        store = _VerificationQueueStore(path=database, config=self.config)
        metadata = ArtifactMetadata("opaque-ref", len(self.raw), hashlib.sha256(self.raw).digest(), hashlib.sha3_512(self.raw).digest())
        store._admit(job_id="restart-job", metadata=metadata)
        store._claim_next()
        runtime = self._runtime(database)
        try:
            self.assertEqual(runtime._recovered_leases, 1)
        finally:
            runtime.close()
        reopened = _VerificationQueueStore(path=database, config=self.config)
        self.assertEqual(reopened._get_job("restart-job").status, "QUEUED")
        self.assertEqual(reopened._get_job("restart-job").last_error_code, "runtime_restart")

    def test_runtime_source_has_no_legacy_multiworker_surface(self) -> None:
        source = Path(__import__("app.minimal_clearance_verification_runtime").minimal_clearance_verification_runtime.__file__).read_text(encoding="utf-8")
        self.assertNotIn("ThreadPoolExecutor", source)
        self.assertNotIn("QueueWorker", source)
        self.assertNotIn("lease_token", source)


if __name__ == "__main__":
    unittest.main()
