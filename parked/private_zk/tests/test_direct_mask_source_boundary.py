from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from app.minimal_clearance_resource_limits import ACTIVE_PROCESS_LIMIT, ADMISSION_CAP_BYTES
from parked.private_zk.app.minimal_clearance_verification_queue import (
    IssuedVerificationBatch,
    OperationTemplate,
    PROFILE_FINGERPRINT,
    PROFILE_VERSION_TOKEN,
    QueueConfig,
    SOURCE_AUTH_PROFILE_DEFAULT,
    SOURCE_ADMISSION_RETRY_LIMIT,
    SourceAdmission,
    SourceLaunchAuthorization,
    _compute_batch_root_from_refs,
    _profile12_context,
)
from app.minimal_clearance_verifier_process import (
    ContainedVerifierResult,
    VerifierProcessError,
    run_contained_verifier,
    run_contained_verifier_stream,
)
from parked.private_zk.tools.direct_mask_complete_path import source_boundary
from parked.private_zk.tools.direct_mask_complete_path.source_boundary import (
    Profile12SourceBoundaryCaller,
    SourceApplianceConfig,
    SourceBoundaryError,
    SOURCE_APPLIANCE_CAPSULE_BYTES,
    SOURCE_APPLIANCE_CONTEXT_BYTES,
    SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
    SOURCE_APPLIANCE_KEY_EPOCH,
    SOURCE_APPLIANCE_MAX_FINAL_RETRIES,
    SOURCE_APPLIANCE_REQUEST_BYTES,
    SOURCE_APPLIANCE_REQUEST_CONTEXT_OFFSET,
    SOURCE_APPLIANCE_REQUEST_EPOCH_OFFSET,
    SOURCE_APPLIANCE_REQUEST_MAGIC,
    SOURCE_APPLIANCE_REQUEST_RETRIES_OFFSET,
    SOURCE_APPLIANCE_REQUEST_U_OFFSET,
    SOURCE_APPLIANCE_STDERR_CAP_BYTES,
    SOURCE_APPLIANCE_STDOUT_CAP_BYTES,
    SOURCE_APPLIANCE_U_BYTES,
    build_source_request,
    source_request_digest,
)


SOURCE_EXECUTABLE = Path(
    r"C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work"
    r"\pq-direct-mask-fixture-20260908\build-fixture\Release\direct_mask_fixture_source.exe"
)


def _contained(
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_code: int = 0,
    timed_out: bool = False,
    peak_job_commit_bytes: int = 1024,
    cap_bytes: int = ADMISSION_CAP_BYTES,
    cap_enforced: bool = True,
    active_process_limit: int = ACTIVE_PROCESS_LIMIT,
    child_process_count: int = 1,
    process_tree_complete: bool = True,
    measurement_complete: bool = True,
    cleanup_complete: bool = True,
    pagefile_growth_evidence: str = "unavailable",
) -> ContainedVerifierResult:
    return ContainedVerifierResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        peak_job_commit_bytes=peak_job_commit_bytes,
        cap_bytes=cap_bytes,
        cap_enforced=cap_enforced,
        active_process_limit=active_process_limit,
        timed_out=timed_out,
        child_process_count=child_process_count,
        process_tree_complete=process_tree_complete,
        measurement_complete=measurement_complete,
        cleanup_complete=cleanup_complete,
        pagefile_growth_evidence=pagefile_growth_evidence,
    )


class DirectMaskSourceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="direct-mask-source-boundary-")
        cls.root = Path(cls.temp.name)
        cls.workspace = cls.root / "source-workspace"
        cls.workspace.mkdir()
        if not SOURCE_EXECUTABLE.is_file():
            raise AssertionError(f"missing source executable: {SOURCE_EXECUTABLE}")
        if SOURCE_EXECUTABLE.stat().st_size != SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES:
            raise AssertionError("source executable size pin mismatch")
        if hashlib.sha256(SOURCE_EXECUTABLE.read_bytes()).digest() != SOURCE_APPLIANCE_EXECUTABLE_SHA256:
            raise AssertionError("source executable hash pin mismatch")
        cls.queue_config = QueueConfig("queue-profile12-source-boundary", 100, source_key_epoch=1)
        cls.caller = Profile12SourceBoundaryCaller(
            SourceApplianceConfig(
                executable_path=SOURCE_EXECUTABLE,
                workspace=cls.workspace,
                executable_size_bytes=SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
                executable_sha256=SOURCE_APPLIANCE_EXECUTABLE_SHA256,
                timeout_seconds=180.0,
            )
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def _batch(self) -> IssuedVerificationBatch:
        template = OperationTemplate("assertion", 1, self.queue_config.profile_version, 6_000, 9_000)
        refs = tuple(bytes([index + 1]) + bytes(31) for index in range(100))
        batch_root = _compute_batch_root_from_refs(template, refs)
        session_ref = bytes(range(64))
        public_coin = bytes(range(1, 97))
        proof_context = _profile12_context(
            session_ref=session_ref,
            ordered_batch_root=batch_root,
            public_coin=public_coin,
            valid_from_ms=template.valid_from_ms,
            valid_until_ms=template.valid_until_ms,
        )
        return IssuedVerificationBatch(
            b"b" * 32,
            template,
            refs,
            batch_root,
            session_ref,
            public_coin,
            proof_context,
            1,
            b"i" * 64,
        )

    def _config(self) -> SourceApplianceConfig:
        return self.caller.config

    def _authorization(self, batch: IssuedVerificationBatch, *, request_digest: bytes | None = None) -> SourceLaunchAuthorization:
        if request_digest is None:
            try:
                request = build_source_request(batch=batch, source_key_epoch=1)
            except SourceBoundaryError:
                request = bytearray(SOURCE_APPLIANCE_REQUEST_BYTES)
                request[: len(SOURCE_APPLIANCE_REQUEST_MAGIC)] = SOURCE_APPLIANCE_REQUEST_MAGIC
                request[SOURCE_APPLIANCE_REQUEST_EPOCH_OFFSET:16] = (1).to_bytes(8, "little")
                request[SOURCE_APPLIANCE_REQUEST_RETRIES_OFFSET:20] = SOURCE_APPLIANCE_MAX_FINAL_RETRIES.to_bytes(4, "little")
                request[SOURCE_APPLIANCE_REQUEST_CONTEXT_OFFSET:84] = batch.proof_context
                request[SOURCE_APPLIANCE_REQUEST_U_OFFSET:] = batch.public_coin
            try:
                request_digest = source_request_digest(request)
            finally:
                for index in range(len(request)):
                    request[index] = 0
                request.clear()
        admission = SourceAdmission(
            batch=batch,
            profile_version=PROFILE_VERSION_TOKEN,
            profile_digest=PROFILE_FINGERPRINT,
            source_auth_profile=SOURCE_AUTH_PROFILE_DEFAULT,
            source_key_epoch=1,
            proof_context=batch.proof_context,
            public_coin=batch.public_coin,
            request_digest=request_digest,
            retry_limit=SOURCE_ADMISSION_RETRY_LIMIT,
            source_configuration_digest=self.caller.configuration_digest,
            source_identity_profile="accepted",
            source_executable_size_bytes=SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
            source_executable_sha256=SOURCE_APPLIANCE_EXECUTABLE_SHA256,
        )
        return SourceLaunchAuthorization(admission)

    def _run_actual_stream(self, payload: bytes | bytearray, arguments: tuple[str, ...] = ()) -> ContainedVerifierResult:
        return run_contained_verifier_stream(
            SOURCE_EXECUTABLE,
            arguments,
            payload,
            workspace=self.workspace,
            timeout_seconds=180.0,
            expected_executable_size_bytes=SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
            expected_executable_sha256=SOURCE_APPLIANCE_EXECUTABLE_SHA256,
            stdout_cap_bytes=SOURCE_APPLIANCE_STDOUT_CAP_BYTES,
            stderr_cap_bytes=SOURCE_APPLIANCE_STDERR_CAP_BYTES,
            stdout_ascii=False,
            expected_input_bytes=SOURCE_APPLIANCE_REQUEST_BYTES
            if len(payload) == SOURCE_APPLIANCE_REQUEST_BYTES
            else None,
        )

    def test_public_request_is_exact_and_wipes_after_one_caller_invocation(self) -> None:
        batch = self._batch()
        request = build_source_request(batch=batch, source_key_epoch=SOURCE_APPLIANCE_KEY_EPOCH)
        try:
            self.assertEqual(len(request), SOURCE_APPLIANCE_REQUEST_BYTES)
            self.assertEqual(request[:8], SOURCE_APPLIANCE_REQUEST_MAGIC)
            self.assertEqual(
                int.from_bytes(request[SOURCE_APPLIANCE_REQUEST_EPOCH_OFFSET:16], "little"),
                SOURCE_APPLIANCE_KEY_EPOCH,
            )
            self.assertEqual(
                int.from_bytes(request[SOURCE_APPLIANCE_REQUEST_RETRIES_OFFSET:20], "little"),
                SOURCE_APPLIANCE_MAX_FINAL_RETRIES,
            )
            self.assertEqual(
                request[SOURCE_APPLIANCE_REQUEST_CONTEXT_OFFSET:84], batch.proof_context
            )
            self.assertEqual(request[SOURCE_APPLIANCE_REQUEST_U_OFFSET:], batch.public_coin)
        finally:
            for index in range(len(request)):
                request[index] = 0
            request.clear()

        captured: dict[str, object] = {}

        def runner(executable: Path, arguments: tuple[str, ...], payload: bytearray, **kwargs: object) -> ContainedVerifierResult:
            captured.update(executable=executable, arguments=arguments, payload=payload, kwargs=kwargs)
            return _contained(stdout=b"c" * SOURCE_APPLIANCE_CAPSULE_BYTES)

        with patch.object(source_boundary, "run_contained_verifier_stream", side_effect=runner) as mocked:
            capsule = self.caller.prove_one(authorization=self._authorization(batch), source_key_epoch=1)
        self.assertEqual(capsule, bytearray(b"c" * SOURCE_APPLIANCE_CAPSULE_BYTES))
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(captured["executable"], SOURCE_EXECUTABLE)
        self.assertEqual(captured["arguments"], ())
        self.assertIsInstance(captured["payload"], bytearray)
        self.assertEqual(captured["payload"], bytearray())  # type: ignore[index]
        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        self.assertEqual(kwargs["expected_input_bytes"], SOURCE_APPLIANCE_REQUEST_BYTES)
        self.assertEqual(kwargs["stdout_cap_bytes"], SOURCE_APPLIANCE_STDOUT_CAP_BYTES)
        self.assertEqual(kwargs["stderr_cap_bytes"], SOURCE_APPLIANCE_STDERR_CAP_BYTES)
        self.assertFalse(kwargs["stdout_ascii"])

    def test_public_binding_mutations_fail_closed_before_native_call(self) -> None:
        batch = self._batch()
        cases = (
            ("epoch", 0, "source_key_epoch"),
            ("epoch-type", True, "source_key_epoch"),
        )
        for name, epoch, code in cases:
            with self.subTest(name=name):
                with patch.object(source_boundary, "run_contained_verifier_stream") as runner:
                    with self.assertRaisesRegex(SourceBoundaryError, code):
                        self.caller.prove_one(authorization=self._authorization(batch), source_key_epoch=epoch)  # type: ignore[arg-type]
                runner.assert_not_called()
        for name, field_name, value, code in (
            ("context", "proof_context", b"x" * SOURCE_APPLIANCE_CONTEXT_BYTES, "source_batch_binding"),
            ("coin", "public_coin", b"x" * SOURCE_APPLIANCE_U_BYTES, "source_batch_binding"),
            ("zero-coin", "public_coin", bytes(SOURCE_APPLIANCE_U_BYTES), "source_batch_binding"),
            ("batch-root", "batch_root", b"x" * 64, "source_batch_binding"),
        ):
            with self.subTest(name=name):
                mutated = object.__new__(IssuedVerificationBatch)
                for field in (
                    "batch_id", "template", "operation_refs", "batch_root", "session_ref",
                    "public_coin", "proof_context", "admission_seq", "identity_digest",
                ):
                    object.__setattr__(mutated, field, getattr(batch, field))
                object.__setattr__(mutated, field_name, value)
                with patch.object(source_boundary, "run_contained_verifier_stream") as runner:
                    with self.assertRaisesRegex(SourceBoundaryError, code):
                        self.caller.prove_one(authorization=self._authorization(mutated), source_key_epoch=1)
                runner.assert_not_called()

    def test_one_use_authorization_serializes_concurrent_native_entry(self) -> None:
        batch = self._batch()
        authorization = self._authorization(batch)
        entered = threading.Event()
        release = threading.Event()
        call_lock = threading.Lock()
        native_calls = 0

        def runner(executable: Path, arguments: tuple[str, ...], payload: bytearray, **kwargs: object) -> ContainedVerifierResult:
            nonlocal native_calls
            del executable, arguments, payload, kwargs
            with call_lock:
                native_calls += 1
            entered.set()
            if not release.wait(5):
                raise AssertionError("native stub was not released")
            return _contained(stdout=b"c" * SOURCE_APPLIANCE_CAPSULE_BYTES)

        with patch.object(source_boundary, "run_contained_verifier_stream", side_effect=runner):
            with ThreadPoolExecutor(max_workers=2) as pool:
                winner = pool.submit(self.caller.prove_one, authorization=authorization, source_key_epoch=1)
                self.assertTrue(entered.wait(5))
                loser = pool.submit(self.caller.prove_one, authorization=authorization, source_key_epoch=1)
                with self.assertRaisesRegex(SourceBoundaryError, "source_authorization"):
                    loser.result(timeout=5)
                release.set()
                capsule = winner.result(timeout=5)
        self.assertEqual(native_calls, 1)
        self.assertTrue(authorization.consumed)
        self.assertEqual(capsule, bytearray(b"c" * SOURCE_APPLIANCE_CAPSULE_BYTES))
        capsule.clear()

    def test_config_pin_timeout_and_type_fail_closed(self) -> None:
        cases = (
            ("config", object(), "source_config"),
            ("path", Path("relative.exe"), "source_executable_path"),
            ("workspace", self.root / "missing", "source_workspace"),
            ("size", SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES + 1, "source_executable_identity"),
            ("hash", bytes(32), "source_executable_identity"),
            ("hash-type", bytearray(SOURCE_APPLIANCE_EXECUTABLE_SHA256), "source_executable_identity"),
            ("timeout", 181.0, "source_timeout"),
            ("timeout-type", 1, "source_timeout"),
        )
        for name, value, code in cases:
            with self.subTest(name=name):
                kwargs = {
                    "executable_path": SOURCE_EXECUTABLE,
                    "workspace": self.workspace,
                    "executable_size_bytes": SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
                    "executable_sha256": SOURCE_APPLIANCE_EXECUTABLE_SHA256,
                    "timeout_seconds": 180.0,
                }
                if name == "config":
                    with self.assertRaisesRegex(SourceBoundaryError, code):
                        Profile12SourceBoundaryCaller(value)  # type: ignore[arg-type]
                    continue
                key = {
                    "path": "executable_path", "workspace": "workspace", "size": "executable_size_bytes",
                    "hash": "executable_sha256", "hash-type": "executable_sha256",
                    "timeout": "timeout_seconds", "timeout-type": "timeout_seconds",
                }[name]
                kwargs[key] = value
                with self.assertRaisesRegex(SourceBoundaryError, code):
                    SourceApplianceConfig(**kwargs)  # type: ignore[arg-type]

    def test_contained_success_and_each_output_or_accounting_failure_is_sanitized(self) -> None:
        exact = b"c" * SOURCE_APPLIANCE_CAPSULE_BYTES
        cases = (
            (_contained(stdout=exact[:-1]), "source_capsule_shape"),
            (_contained(stdout=exact + b"x"), "source_capsule_shape"),
            (_contained(stderr=b"x"), "source_stderr"),
            (_contained(exit_code=1), "source_process"),
            (_contained(timed_out=True), "source_timeout"),
            (_contained(cap_enforced=False), "source_process"),
            (_contained(cap_bytes=ADMISSION_CAP_BYTES + 1), "source_process"),
            (_contained(active_process_limit=ACTIVE_PROCESS_LIMIT + 1), "source_process"),
            (_contained(child_process_count=0), "source_process"),
            (_contained(process_tree_complete=False), "source_process"),
            (_contained(measurement_complete=False), "source_process"),
            (_contained(cleanup_complete=False), "source_process"),
            (_contained(peak_job_commit_bytes=ADMISSION_CAP_BYTES + 1), "source_process"),
            (_contained(pagefile_growth_evidence="measured"), "source_process"),
        )
        for result, code in cases:
            with self.subTest(code=code, result=result):
                with patch.object(source_boundary, "run_contained_verifier_stream", return_value=result):
                    with self.assertRaisesRegex(SourceBoundaryError, code):
                        self.caller.prove_one(authorization=self._authorization(self._batch()), source_key_epoch=1)

    def test_runner_failures_and_wipe_failures_are_fixed(self) -> None:
        batch = self._batch()
        for failure, code in (
            (VerifierProcessError("verifier_timeout"), "source_timeout"),
            (VerifierProcessError("verifier_workspace_changed"), "source_workspace"),
            (VerifierProcessError("verifier_stdout_overflow"), "source_process"),
            (VerifierProcessError("verifier_stderr_overflow"), "source_process"),
            (VerifierProcessError("verifier_stream_cleanup"), "source_process"),
            (RuntimeError("raw native output"), "source_process"),
        ):
            with self.subTest(code=code):
                with patch.object(source_boundary, "run_contained_verifier_stream", side_effect=failure):
                    with self.assertRaisesRegex(SourceBoundaryError, code) as raised:
                        self.caller.prove_one(authorization=self._authorization(batch), source_key_epoch=1)
                self.assertEqual(str(raised.exception), code)
        with patch.object(
            source_boundary,
            "run_contained_verifier_stream",
            return_value=_contained(stdout=b"c" * SOURCE_APPLIANCE_CAPSULE_BYTES),
        ), patch.object(source_boundary, "_wipe", side_effect=RuntimeError("wipe detail")):
            with self.assertRaisesRegex(SourceBoundaryError, "source_cleanup"):
                self.caller.prove_one(authorization=self._authorization(batch), source_key_epoch=1)

    def test_real_source_rejects_exactly_ten_malformed_cases(self) -> None:
        valid = bytes(build_source_request(batch=self._batch(), source_key_epoch=1))
        cases = (
            ("magic", b"X" + valid[1:], ()),
            ("epoch0", valid[:8] + bytes(8) + valid[16:], ()),
            ("epoch2", valid[:8] + (2).to_bytes(8, "little") + valid[16:], ()),
            ("retry0", valid[:16] + bytes(4) + valid[20:], ()),
            ("retry-other", valid[:16] + (1).to_bytes(4, "little") + valid[20:], ()),
            (
                "zero-u",
                valid[:SOURCE_APPLIANCE_REQUEST_U_OFFSET]
                + bytes(SOURCE_APPLIANCE_U_BYTES),
                (),
            ),
            ("short", valid[:-1], ()),
            ("trailing", valid + b"x", ()),
            ("unexpected-argument", valid, ("unexpected",)),
            ("empty-eof", b"", ()),
        )
        for name, payload, arguments in cases:
            with self.subTest(case=name):
                if name == "empty-eof":
                    descriptor = os.open(os.devnull, os.O_RDONLY)
                    try:
                        result = run_contained_verifier(
                            SOURCE_EXECUTABLE,
                            arguments,
                            workspace=self.workspace,
                            timeout_seconds=180.0,
                            job_memory_cap_bytes=ADMISSION_CAP_BYTES,
                            _stdin_descriptor=descriptor,
                            expected_executable_size_bytes=SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
                            expected_executable_sha256=SOURCE_APPLIANCE_EXECUTABLE_SHA256,
                            stdout_cap_bytes=SOURCE_APPLIANCE_STDOUT_CAP_BYTES,
                            stderr_cap_bytes=SOURCE_APPLIANCE_STDERR_CAP_BYTES,
                            stdout_ascii=False,
                        )
                    finally:
                        os.close(descriptor)
                else:
                    result = self._run_actual_stream(payload, arguments)
                self.assertEqual((result.exit_code, result.stdout, result.stderr), (2, b"", b""))
                self.assertTrue(result.cap_enforced)
                self.assertEqual(result.cap_bytes, ADMISSION_CAP_BYTES)
                self.assertEqual(result.active_process_limit, ACTIVE_PROCESS_LIMIT)
                self.assertTrue(result.process_tree_complete)
                self.assertTrue(result.measurement_complete)
                self.assertTrue(result.cleanup_complete)
                self.assertEqual(list(self.workspace.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
