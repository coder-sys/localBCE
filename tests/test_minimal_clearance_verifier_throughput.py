"""Causal checks for the serial runtime evidence wrapper."""

from __future__ import annotations

from dataclasses import dataclass
import inspect
from pathlib import Path
from types import SimpleNamespace
import tempfile
from unittest import TestCase
from unittest.mock import patch

from experiments.longfellow_v09_native_v3.evidence import (
    measure_minimal_clearance_verifier_throughput as harness,
)


@dataclass
class _FakeRuntimeResult:
    processed: int = 2
    verified: int = 2
    rejected: int = 0
    held: int = 0
    requeued: int = 0
    indeterminate: bool = False
    recovered_leases: int = 0
    scavenged_workspaces: int = 1


class _FakeRuntime:
    instances: list["_FakeRuntime"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.admissions: list[str] = []
        self.runs: list[int] = []
        self.closed = False
        self.__class__.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def admit(self, *, job_id, metadata):
        self.admissions.append(job_id)
        self.metadata = metadata

    def run(self, *, max_jobs):
        self.runs.append(max_jobs)
        return _FakeRuntimeResult()

    def verify_integrity(self):
        self.integrity_checked = True

    def export_bytes(self):
        return b"verified-sqlite-image"


class MinimalClearanceVerifierThroughputTests(TestCase):
    def test_source_has_only_serial_runtime_boundary(self):
        source = inspect.getsource(harness)
        for forbidden in (
            "ThreadPoolExecutor",
            "VerifierFactory",
            "run_ladder",
            "NativeMinimalClearanceVerifier",
            "concurrency",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("MinimalClearanceVerificationRuntime", source)
        self.assertIn("workspace_parent=workspace_parent", source)

    def test_run_serial_uses_runtime_and_aggregate_independent_facts(self):
        _FakeRuntime.instances.clear()
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            workspace = root_path / "workspace"
            workspace.mkdir()
            database = root_path / "queue.sqlite"
            restored = root_path / "restored.sqlite"
            output = root_path / "evidence.json"
            artifact = root_path / "artifact.blmc"
            verifier = root_path / "verifier.exe"
            artifact.touch()
            verifier.touch()
            summary = {
                "schema": "queue",
                "queue_id": "serial",
                "head_root": "00",
                "status_counts": {"VERIFIED": 2},
                "lease_count": 0,
                "transition_count": 6,
                "config_digest": "11",
                "storage_used_bytes": 4096,
                "storage_reserved_bytes": 0,
                "claim_count": 2,
                "completion_count": 2,
                "distinct_worker_count": 1,
            }
            jobs = tuple(
                SimpleNamespace(exit_code=0, timed_out=False, cap_enforced=True)
                for _ in range(2)
            )
            with (
                patch.object(harness, "_bounded_digest", side_effect=((harness.ARTIFACT_BYTES, harness.ARTIFACT_SHA256, True), (1, harness.VERIFIER_SHA256, True), (harness.ARTIFACT_BYTES, harness.ARTIFACT_SHA256, True), (1, harness.VERIFIER_SHA256, True))),
                patch.object(harness, "MinimalClearanceVerificationRuntime", _FakeRuntime),
                patch.object(harness, "verify_database", return_value=summary),
                patch.object(harness, "verify_export_bytes", return_value=summary),
                patch.object(harness, "restore_export_to_fresh_database", return_value=summary),
                patch.object(harness, "read_verified_jobs", return_value=jobs),
            ):
                record = harness.run_serial(
                    artifact=artifact,
                    verifier=verifier,
                    database=database,
                    workspace_parent=workspace,
                    restore_database=restored,
                    evidence_output=output,
                    job_count=2,
                )
            runtime = _FakeRuntime.instances[0]
            self.assertEqual(runtime.admissions, ["serial-job-0", "serial-job-1"])
            self.assertEqual(runtime.runs, [2])
            self.assertEqual(runtime.kwargs["workspace_parent"], workspace)
            self.assertTrue(runtime.closed)
            self.assertEqual(record["verification_count"], 2)
            self.assertEqual(record["distinct_worker_count"], 1)
            self.assertTrue(record["serial_owner_runtime"])
            self.assertFalse(record["throughput_qualification"])
            self.assertNotIn(b"MINIMAL_CLEARANCE_", output.read_bytes())

    def test_bounds_and_privacy_are_fixed(self):
        with self.assertRaises(harness.ThroughputError) as caught:
            harness.run_serial(
                artifact=Path("artifact"),
                verifier=Path("verifier"),
                database=Path("database"),
                workspace_parent=Path("workspace"),
                restore_database=Path("restore"),
                evidence_output=Path("output"),
                job_count=0,
            )
        self.assertEqual(caught.exception.code, "job_count")
        with self.assertRaises(harness.ThroughputError):
            harness._canonical_json({"path": "C:\\private\\artifact"})
        with self.assertRaises(harness.ThroughputError):
            harness._canonical_json({"trace": "MINIMAL_CLEARANCE_BUILD phase=private"})

    def test_main_emits_fixed_error_without_arguments_or_exception_text(self):
        with patch.object(harness, "run_serial", side_effect=harness.ThroughputError("runtime_exercise")):
            result = harness.main(
                [
                    "--artifact", r"C:\private\artifact",
                    "--verifier", r"C:\private\verifier",
                    "--database", r"C:\private\queue",
                    "--workspace-parent", r"C:\private\workspace",
                    "--restore-database", r"C:\private\restore",
                    "--evidence-output", r"C:\private\output",
                ]
            )
        self.assertEqual(result, 1)


if __name__ == "__main__":
    import unittest

    unittest.main()
