"""Focused tests for the fixed per-claim verifier throughput ladder."""

from __future__ import annotations

from contextlib import redirect_stderr
from dataclasses import dataclass
import hashlib
import io
import inspect
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch

from experiments.longfellow_v09_native_v3.evidence import (
    measure_minimal_clearance_verifier_throughput as harness,
)


_DIMENSIONS = {"inputs": 11, "public_inputs": 7, "layers": 5, "terms": 13}
_UNSET = object()


def _stdout() -> bytes:
    return (
        b"MINIMAL_CLEARANCE_VERIFIER_ACCEPT "
        b"inputs=11 public_inputs=7 layers=5 terms=13\n"
    )


def _stderr() -> bytes:
    return (
        b"MINIMAL_CLEARANCE_BUILD phase=public\n"
        b"MINIMAL_CLEARANCE_BUILD phase=private\n"
        b"MINIMAL_CLEARANCE_BUILD phase=assertions\n"
        b"MINIMAL_CLEARANCE_BUILD phase=mkcircuit\n"
        b"MINIMAL_CLEARANCE_BUILD phase=complete inputs=11 public_inputs=7 layers=5 terms=13\n"
        b"MINIMAL_CLEARANCE_VERIFIER_STAGE proof.read=accept remaining=0\n"
        b"MINIMAL_CLEARANCE_VERIFIER_STAGE commitment=received\n"
        b"MINIMAL_CLEARANCE_VERIFIER_STAGE verify=accept\n"
    )


@dataclass
class _FakeContainment:
    exit_code: int = 0
    stdout: bytes = _stdout()
    stderr: bytes = _stderr()
    peak_job_commit_bytes: int = 1_042_202_624
    cap_bytes: int = harness.CAP_BYTES
    cap_enforced: bool = True
    active_process_limit: int = harness.ACTIVE_PROCESS_LIMIT
    timed_out: bool = False


@dataclass
class _FakeAcceptance:
    artifact_sha256: bytes
    artifact_digest: bytes
    artifact_bytes: int
    proof_accepted: bool = True


def _fake_artifact() -> harness.ArtifactSnapshot:
    raw = b"test-only-artifact"
    return harness.ArtifactSnapshot(
        raw=raw,
        bytes=len(raw),
        sha256=harness.ARTIFACT_SHA256,
        sha3_512=harness.ARTIFACT_SHA3_512,
        readonly=True,
        file_token=(1, 1),
    )


def _fake_acceptance(artifact: harness.ArtifactSnapshot) -> _FakeAcceptance:
    return _FakeAcceptance(
        artifact_sha256=bytes.fromhex(artifact.sha256),
        artifact_digest=bytes.fromhex(artifact.sha3_512),
        artifact_bytes=artifact.bytes,
    )


class _FakeFactory:
    def __init__(self, artifact: harness.ArtifactSnapshot, *, result=_UNSET, failure=None, acceptance=None):
        self.artifact = artifact
        self.result = result
        self.failure = failure
        self.acceptance = acceptance or _fake_acceptance(artifact)
        self.instances = []

    def __call__(self, executable, *, executable_sha256, timeout_seconds):
        factory = self

        class FakeVerifier:
            def __init__(self):
                self.workspace_token = object()
                self.last_containment_result = (
                    _FakeContainment() if factory.result is _UNSET else factory.result
                )

            def verify(self, artifact_path):
                if factory.failure is not None:
                    raise factory.failure
                return factory.acceptance

        verifier = FakeVerifier()
        self.instances.append(verifier)
        return verifier


class MinimalClearanceVerifierThroughputTests(TestCase):
    def _run_fake_campaign(self, factory: _FakeFactory):
        artifact = _fake_artifact()
        with (
            patch.object(harness, "_read_artifact_once", return_value=artifact),
            patch.object(harness, "_read_verifier_sha256", return_value=harness.VERIFIER_SHA256),
            patch.object(
                harness,
                "_check_artifact_after",
                return_value={"bytes": artifact.bytes, "sha256": artifact.sha256, "sha3_512": artifact.sha3_512, "readonly": True},
            ),
        ):
            return harness.run_ladder(
                Path("artifact-placeholder"),
                Path("verifier-placeholder"),
                memory_probe=lambda: {"uncommitted_bytes": harness.REQUIRED_UNCOMMITTED_BYTES + 1},
                verifier_factory=factory,
            )

    def test_fixed_ladder_has_21_operations_and_no_shared_verifier(self):
        factory = _FakeFactory(_fake_artifact())
        record = self._run_fake_campaign(factory)
        self.assertEqual(record["campaign"]["verification_count"], 21)
        self.assertEqual(record["proof_verification_count"], 21)
        self.assertEqual(record["prover_invocation_count"], 0)
        self.assertEqual(record["state_mutation_count"], 0)
        self.assertEqual([level["verification_count"] for level in record["campaign"]["levels"]], [3, 6, 12])
        self.assertEqual(len(factory.instances), 21)
        self.assertEqual(len({id(instance) for instance in factory.instances}), 21)
        self.assertEqual(len({id(instance.workspace_token) for instance in factory.instances}), 21)

    def test_canonical_output_is_deterministic_and_bounded(self):
        record = {"schema": "BL/NATIVE-V3/TEST/v1", "count": 21, "activation": False}
        first = harness.canonical_json_bytes(record)
        second = harness.canonical_json_bytes(record)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), harness.MAX_EVIDENCE_BYTES)
        self.assertNotIn(b"MINIMAL_CLEARANCE_", first)

    def test_containment_failures_fail_closed(self):
        artifact = _fake_artifact()
        cases = (
            (None, "containment_missing"),
            (_FakeContainment(exit_code=1), "containment_exit"),
            (_FakeContainment(cap_enforced=False), "containment_cap_not_enforced"),
            (_FakeContainment(peak_job_commit_bytes=harness.CAP_BYTES + 1), "containment_peak"),
            (_FakeContainment(timed_out=True), "containment_timeout"),
        )
        for result, label in cases:
            with self.subTest(label=label):
                factory = _FakeFactory(artifact, result=result)
                with self.assertRaises(harness.ThroughputError) as caught:
                    harness._run_one(
                        0,
                        Path("artifact-placeholder"),
                        Path("verifier-placeholder"),
                        artifact,
                        harness.VERIFIER_SHA256,
                        30.0,
                        verifier_factory=factory,
                        monotonic=iter((0.0, 1.0)).__next__,
                    )
                self.assertEqual(caught.exception.code, label)
                self.assertEqual(caught.exception.operation_index, 0)

    def test_output_and_artifact_failures_fail_closed(self):
        artifact = _fake_artifact()
        bad_stdout = _FakeContainment(stdout=b"unexpected\n")
        bad_stderr = _FakeContainment(stderr=_stderr() + b"extra\n")
        bad_acceptance = _FakeAcceptance(
            artifact_sha256=bytes(32),
            artifact_digest=bytes.fromhex(artifact.sha3_512),
            artifact_bytes=artifact.bytes,
        )
        cases = (
            (_FakeFactory(artifact, result=bad_stdout), "verifier_acceptance_marker"),
            (_FakeFactory(artifact, result=bad_stderr), "verifier_trace_line_count"),
            (_FakeFactory(artifact, acceptance=bad_acceptance), "acceptance_sha256_mismatch"),
        )
        for factory, label in cases:
            with self.subTest(label=label):
                with self.assertRaises(harness.ThroughputError) as caught:
                    harness._run_one(
                        0,
                        Path("artifact-placeholder"),
                        Path("verifier-placeholder"),
                        artifact,
                        harness.VERIFIER_SHA256,
                        30.0,
                        verifier_factory=factory,
                        monotonic=iter((0.0, 1.0)).__next__,
                    )
                self.assertEqual(caught.exception.code, label)
                self.assertEqual(caught.exception.operation_index, 0)

    def test_worker_exception_and_incomplete_wave_fail_closed(self):
        artifact = _fake_artifact()
        factory = _FakeFactory(artifact, failure=RuntimeError("worker failure"))
        with patch.object(harness, "_read_artifact_once", return_value=artifact), patch.object(
            harness, "_read_verifier_sha256", return_value=harness.VERIFIER_SHA256
        ):
            with self.assertRaises(harness.ThroughputError):
                harness.run_ladder(
                    Path("artifact-placeholder"),
                    Path("verifier-placeholder"),
                    memory_probe=lambda: {"uncommitted_bytes": harness.REQUIRED_UNCOMMITTED_BYTES + 1},
                    verifier_factory=factory,
                )

    def test_known_error_token_and_os_error_code_are_preserved_without_messages(self):
        artifact = _fake_artifact()
        cases = (
            (harness.MinimalClearanceProofStateError("proof_verifier_rejected"), "proof_verifier_rejected", None),
            (OSError(5, "C:\\private\\path"), "os_error", 5),
        )
        for failure, code, numeric_code in cases:
            with self.subTest(code=code):
                factory = _FakeFactory(artifact, failure=failure)
                with self.assertRaises(harness.ThroughputError) as caught:
                    harness._run_one(
                        0,
                        Path("artifact-placeholder"),
                        Path("verifier-placeholder"),
                        artifact,
                        harness.VERIFIER_SHA256,
                        30.0,
                        verifier_factory=factory,
                        monotonic=iter((0.0, 1.0)).__next__,
                    )
                error = caught.exception
                self.assertEqual(error.code, code)
                self.assertEqual(error.operation_index, 0)
                self.assertEqual(error.win32_error_code, numeric_code)
                self.assertNotIn("private", error.bounded_text())
                self.assertNotIn("path", error.bounded_text())

    def test_wave_selects_first_operation_index_deterministically(self):
        def fail(operation_index, *args, **kwargs):
            raise harness.ThroughputError(f"failure_{operation_index}")

        with patch.object(harness, "_run_one", side_effect=fail):
            with self.assertRaises(harness.ThroughputError) as caught:
                harness._run_wave(
                    2,
                    3,
                    10,
                    Path("artifact-placeholder"),
                    Path("verifier-placeholder"),
                    _fake_artifact(),
                    harness.VERIFIER_SHA256,
                    30.0,
                    verifier_factory=_FakeFactory(_fake_artifact()),
                    monotonic=iter((0.0, 1.0)).__next__,
                )
        error = caught.exception
        self.assertEqual(error.code, "failure_10")
        self.assertEqual(error.concurrency, 2)
        self.assertEqual(error.wave_index, 3)
        self.assertEqual(error.operation_index, 10)

    def test_main_emits_only_bounded_failure_context(self):
        failure = harness.ThroughputError(
            "proof_verifier_rejected",
            concurrency=2,
            wave_index=1,
            operation_index=4,
            exception_class="MinimalClearanceProofStateError",
            win32_error_code=5,
        )
        output = io.StringIO()
        with patch.object(harness, "_ensure_external_workspace"), patch.object(
            harness, "run_ladder", side_effect=failure
        ), redirect_stderr(output):
            result = harness.main(
                [
                    "--artifact",
                    "C:\\private\\artifact.blmc",
                    "--verifier",
                    "C:\\private\\verifier.exe",
                    "--output",
                    "C:\\private\\evidence.json",
                    "--temp-root",
                    "C:\\private\\temp",
                ]
            )
        rendered = output.getvalue()
        self.assertEqual(result, 1)
        self.assertEqual(
            rendered,
            "THROUGHPUT_FAILURE code=proof_verifier_rejected concurrency=2 "
            "wave_index=1 operation_index=4 "
            "exception_class=MinimalClearanceProofStateError win32_error_code=5\n",
        )
        self.assertNotIn("C:\\", rendered)
        self.assertNotIn("private", rendered)
        self.assertNotIn("ThroughputError", rendered)

    def test_memory_reserve_and_concurrency_ceiling_fail_closed(self):
        with self.assertRaises(harness.ThroughputError):
            harness.preflight_memory(lambda: {"uncommitted_bytes": harness.REQUIRED_UNCOMMITTED_BYTES - 1})
        with self.assertRaises(harness.ThroughputError):
            harness._validate_concurrency_level(8)

    def test_arithmetic_projection_and_efficiency_inputs(self):
        waves = [
            {"wave_wall_ms": 1000.0, "operations": [{"wall_ms": 1000.0}]},
            {"wave_wall_ms": 1000.0, "operations": [{"wall_ms": 1000.0}]},
            {"wave_wall_ms": 1000.0, "operations": [{"wall_ms": 1000.0}]},
        ]
        metrics = harness._level_metrics(1, waves)
        self.assertEqual(metrics["throughput_verifications_per_second"], 1.0)
        self.assertEqual(metrics["claims_per_day_projection"], 86400.0)
        self.assertEqual(metrics["latency_ms"], {"min": 1000.0, "median": 1000.0, "max": 1000.0})

    def test_forbidden_paths_raw_output_and_sensitive_fields_reject(self):
        cases = (
            {"artifact_path": "C:\\secret\\artifact"},
            {"stderr": "MINIMAL_CLEARANCE_VERIFIER_ACCEPT"},
            {"persistent_machine_fingerprint": "abc"},
            {"pid": 1234},
            {"secret": "value"},
            {"phi": "synthetic"},
        )
        for record in cases:
            with self.subTest(record=record):
                with self.assertRaises(harness.ThroughputError):
                    harness.canonical_json_bytes(record)

    def test_source_has_no_receipt_artifact_bytes_dependency(self):
        source = inspect.getsource(harness)
        self.assertNotIn("receipt.artifact_bytes", source)

    def test_exact_trace_rejects_non_ascii_reordered_and_substituted_lines(self):
        valid = _stderr()
        cases = (
            valid.replace(b"phase=private", b"phase=public", 1),
            valid + b"diagnostic\n",
            valid.replace(b"verify=accept", b"verify=reject", 1),
            valid.replace(b"\n", b"\xff\n", 1),
        )
        for stderr in cases:
            with self.subTest(stderr=stderr[:32]):
                with self.assertRaises(Exception):
                    harness._validate_acceptance_output(_stdout(), stderr)


if __name__ == "__main__":
    import unittest

    unittest.main()
