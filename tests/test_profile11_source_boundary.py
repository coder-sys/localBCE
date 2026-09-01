import hashlib
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from pqcrypto.sign import ml_dsa_87

import app.minimal_clearance_composition as composition
import app.minimal_clearance_source_auth_verifier_adapter as source_auth_adapter
from app.minimal_clearance_composition import StateDispositionControl
from app.minimal_clearance_source_auth_verifier_adapter import (
    MinimalClearanceSourceAuthVerifierAdapter,
    SOURCE_AUTH_EXECUTABLE_SHA256,
    SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
)
from app.minimal_clearance_verification_queue import (
    ACTIVE_PROCESS_LIMIT,
    ADMISSION_CAP_BYTES,
    IssuedVerificationBatch,
    OperationTemplate,
    QueueConfig,
    VolatileProofHandoff,
    _build_statement,
    _compute_batch_root_from_refs,
)
from app.minimal_clearance_verifier_process import (
    ContainedVerifierResult,
    VerifierProcessError,
    run_contained_verifier_stream,
)
from profile11_source_boundary import (
    Profile11SourceBoundaryCaller,
    SourceApplianceConfig,
    SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
    SOURCE_APPLIANCE_PROVISION_MAGIC,
    SOURCE_APPLIANCE_PROTOCOL_VERSION,
    SOURCE_APPLIANCE_REQUEST_MAGIC,
    SOURCE_AUTH_FRAME_BYTES,
    SOURCE_AUTH_INPUT_BYTES,
    SOURCE_AUTH_LOWER,
    SOURCE_AUTH_PROVISION_BYTES,
    SOURCE_AUTH_RANDOMIZER_BYTES,
    SOURCE_AUTH_REQUEST_BYTES,
    SOURCE_AUTH_SECRET_KEY_BYTES,
    SOURCE_AUTH_SEED_BYTES,
    SOURCE_AUTH_STDERR_CAP_BYTES,
    SOURCE_AUTH_STDOUT_CAP_BYTES,
    SOURCE_AUTH_WITNESS_BYTES,
    SOURCE_AUTH_WITNESS_COUNT,
    SourceBoundaryError,
    build_provision_record,
    build_request_record,
)


SOURCE_AUTH_C_BUILD = Path(r"C:\Users\neers\Documents\Codex\2026-08-31\build-profile11-throughput-v1\Release")
SOURCE_AUTH_C_VERIFIER = SOURCE_AUTH_C_BUILD / "blind_source_auth_verify_process_v1.exe"
SOURCE_AUTH_C_LIBRARIES = (
    (SOURCE_AUTH_C_BUILD / "blind_source_auth_v1.lib", 146_952, "DDF3B811A9D558E147C49175D45A3B28ED226A39AC5E87546DBADB38D8DD7EF5"),
    (SOURCE_AUTH_C_BUILD / "blind_range100_cdg_direct_v1.lib", 111_148, "C0F9A0772556FFBABC4FE3D8E66AB5677ECAE67A9E03435D685F69FA378BE183"),
)
SOURCE_AUTH_APPLIANCE = Path(r"C:\Users\neers\Documents\Codex\2026-08-31\blind-zkbpp-range100-profile11-source-appliance-v1\target\release\blind_source_auth_profile11_appliance.exe")


def _assert_pinned_file(test: unittest.TestCase, path: Path, expected_bytes: int, expected_sha256: str) -> None:
    test.assertTrue(path.is_file(), path)
    test.assertEqual(path.stat().st_size, expected_bytes, path)
    test.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest().upper(), expected_sha256, path)


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def _contained(
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_code: int = 0,
    timed_out: bool = False,
    cap_enforced: bool = True,
    process_tree_complete: bool = True,
    measurement_complete: bool = True,
    cleanup_complete: bool = True,
) -> ContainedVerifierResult:
    return ContainedVerifierResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        peak_job_commit_bytes=1024,
        cap_bytes=ADMISSION_CAP_BYTES,
        cap_enforced=cap_enforced,
        active_process_limit=ACTIVE_PROCESS_LIMIT,
        timed_out=timed_out,
        child_process_count=1,
        process_tree_complete=process_tree_complete,
        measurement_complete=measurement_complete,
        cleanup_complete=cleanup_complete,
        pagefile_growth_evidence="unavailable",
    )


class _StateDispositionPort:
    def __init__(self) -> None:
        self.calls = 0

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome: object) -> dict[bytes, StateDispositionControl]:
        del batch_id, verification_outcome
        self.calls += 1
        profile = bytes([9]) * 64
        state_id = bytes(64)
        state_bytes = bytes(64)
        continuity = bytes(64)
        audit = bytes(64)
        clearance = bytes(64)
        controls: dict[bytes, StateDispositionControl] = {}
        for index, operation_ref in enumerate(operation_refs):
            control = StateDispositionControl(
                operation_ref=operation_ref,
                policy_result="MISSING",
                state_profile_identity=profile,
                predecessor_state_id=state_id,
                predecessor_state_bytes=state_bytes,
                sequence_before=index,
                predecessor_continuity_root=continuity,
                predecessor_audit_head=audit,
                predecessor_clearance_root=clearance,
            )
            controls[operation_ref] = control
            state_id = control.state_after_id
            state_bytes = control.state_after_bytes
            continuity = control.state_after_continuity_root
            audit = composition._sha(composition._STATE, audit, control.decision_id, control.effective_directive.encode("ascii"))
        return controls


class Profile11SourceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="blind-profile11-source-boundary-")
        cls.root = Path(cls.temp.name)
        cls.source_workspace = cls.root / "source-workspace"
        cls.verifier_workspace = cls.root / "verifier-workspace"
        cls.state_root = cls.root / "state"
        cls.source_workspace.mkdir()
        cls.verifier_workspace.mkdir()
        cls.state_root.mkdir()
        checker = unittest.TestCase()
        _assert_pinned_file(checker, SOURCE_AUTH_APPLIANCE, SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES, SOURCE_APPLIANCE_EXECUTABLE_SHA256.hex().upper())
        _assert_pinned_file(checker, SOURCE_AUTH_C_VERIFIER, SOURCE_AUTH_EXECUTABLE_SIZE_BYTES, SOURCE_AUTH_EXECUTABLE_SHA256.hex().upper())
        for path, expected_bytes, expected_sha256 in SOURCE_AUTH_C_LIBRARIES:
            _assert_pinned_file(checker, path, expected_bytes, expected_sha256)
        cls.public_key, cls.secret_key = ml_dsa_87.generate_keypair()
        if len(cls.public_key) != 2_592 or len(cls.secret_key) != SOURCE_AUTH_SECRET_KEY_BYTES:
            raise AssertionError("test-only ML-DSA-87 key shape")
        cls.queue_config = QueueConfig("queue-profile11-source-e2e", 100, source_key_epoch=0x0102030405060708)
        cls.caller = Profile11SourceBoundaryCaller(
            SourceApplianceConfig(
                executable_path=SOURCE_AUTH_APPLIANCE,
                workspace=cls.source_workspace,
                executable_size_bytes=SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
                executable_sha256=SOURCE_APPLIANCE_EXECUTABLE_SHA256,
                timeout_seconds=180.0,
            )
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.public_key = b""
        cls.secret_key = b""
        cls.temp.cleanup()

    def _template(self) -> OperationTemplate:
        valid_from_ms = time.time_ns() // 1_000_000 - 60_000
        return OperationTemplate(
            "assertion",
            1,
            "state-profile-v11",
            valid_from_ms,
            valid_from_ms + 3_000_000,
            None,
            self.queue_config.qualification_flags,
        )

    def _batch(self) -> IssuedVerificationBatch:
        template = self._template()
        refs = tuple(index.to_bytes(32, "little") for index in range(SOURCE_AUTH_WITNESS_COUNT))
        root = _compute_batch_root_from_refs(template, refs)
        statement = _build_statement(
            batch_root=root,
            session_ref=bytes(range(64)),
            valid_from_ms=template.valid_from_ms,
            valid_until_ms=template.valid_until_ms,
        )
        return IssuedVerificationBatch(b"b" * 32, template, refs, root, bytes(range(64)), statement, 1, b"i" * 64)

    def _source_values(self) -> tuple[tuple[int, ...], bytes, bytes]:
        witness = (SOURCE_AUTH_LOWER,) * SOURCE_AUTH_WITNESS_COUNT
        seed = bytes((index * 13 + 7) % 256 for index in range(SOURCE_AUTH_SEED_BYTES))
        randomizer = bytes([0x5A] * SOURCE_AUTH_RANDOMIZER_BYTES)
        return witness, seed, randomizer

    def _run_appliance(self, payload: bytearray) -> tuple[int, bytes, bytes]:
        try:
            result = run_contained_verifier_stream(
                SOURCE_AUTH_APPLIANCE,
                (),
                payload,
                workspace=self.source_workspace,
                timeout_seconds=180.0,
                expected_executable_size_bytes=SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
                expected_executable_sha256=SOURCE_APPLIANCE_EXECUTABLE_SHA256,
                stdout_cap_bytes=2 * SOURCE_AUTH_FRAME_BYTES + 1,
                stderr_cap_bytes=SOURCE_AUTH_STDERR_CAP_BYTES,
                stdout_ascii=False,
            )
            self.assertTrue(result.process_tree_complete)
            self.assertTrue(result.measurement_complete)
            self.assertTrue(result.cleanup_complete)
            return result.exit_code, result.stdout, result.stderr
        finally:
            _wipe(payload)

    def _assert_empty_workspace(self) -> None:
        self.assertEqual(list(self.source_workspace.iterdir()), [])
        self.assertEqual(list(self.verifier_workspace.iterdir()), [])

    def test_current_appliance_protocol_is_exact_and_source_owned(self) -> None:
        batch = self._batch()
        witness, seed, randomizer = self._source_values()
        provision = build_provision_record(source_key_epoch=self.queue_config.source_key_epoch, secret_key=self.secret_key)
        request = build_request_record(batch=batch, witness=witness, seed=seed, randomizer=randomizer)
        try:
            self.assertEqual(len(provision), SOURCE_AUTH_PROVISION_BYTES)
            self.assertEqual(len(request), SOURCE_AUTH_REQUEST_BYTES)
            self.assertEqual(provision[:16], SOURCE_APPLIANCE_PROVISION_MAGIC)
            self.assertEqual(int.from_bytes(provision[16:18], "little"), SOURCE_APPLIANCE_PROTOCOL_VERSION)
            self.assertEqual(provision[18:20], b"\0\0")
            self.assertEqual(request[:16], SOURCE_APPLIANCE_REQUEST_MAGIC)
            self.assertEqual(len(request) - 16 - 64 - 3_200 - 304, SOURCE_AUTH_WITNESS_BYTES + SOURCE_AUTH_SEED_BYTES + SOURCE_AUTH_RANDOMIZER_BYTES)
        finally:
            _wipe(provision)
            _wipe(request)

    def test_source_caller_uses_exact_pinned_contained_runner_and_one_frame(self) -> None:
        batch = self._batch()
        witness, seed, randomizer = self._source_values()
        expected_frame = b"f" * SOURCE_AUTH_FRAME_BYTES
        provision = build_provision_record(
            source_key_epoch=self.queue_config.source_key_epoch,
            secret_key=self.secret_key,
        )
        request = build_request_record(
            batch=batch,
            witness=witness,
            seed=seed,
            randomizer=randomizer,
        )
        expected_payload = bytes(provision) + bytes(request)
        _wipe(provision)
        _wipe(request)
        captured: dict[str, object] = {}

        def runner(
            executable: Path,
            arguments: tuple[str, ...],
            payload: bytes | bytearray,
            *,
            workspace: Path,
            timeout_seconds: float,
            expected_executable_size_bytes: int,
            expected_executable_sha256: bytes,
            stdout_cap_bytes: int,
            stderr_cap_bytes: int,
            stdout_ascii: bool,
            expected_input_bytes: int,
        ) -> ContainedVerifierResult:
            captured.update(
                executable=executable,
                arguments=arguments,
                payload=bytes(payload),
                payload_type=type(payload),
                workspace=workspace,
                timeout_seconds=timeout_seconds,
                expected_executable_size_bytes=expected_executable_size_bytes,
                expected_executable_sha256=expected_executable_sha256,
                stdout_cap_bytes=stdout_cap_bytes,
                stderr_cap_bytes=stderr_cap_bytes,
                stdout_ascii=stdout_ascii,
                expected_input_bytes=expected_input_bytes,
            )
            return _contained(stdout=expected_frame)

        with patch("profile11_source_boundary.run_contained_verifier_stream", side_effect=runner):
            frame = self.caller.prove_one(
                batch=batch,
                source_key_epoch=self.queue_config.source_key_epoch,
                secret_key=self.secret_key,
                witness=witness,
                seed=seed,
                randomizer=randomizer,
            )
        self.assertEqual(frame, bytearray(expected_frame))
        self.assertEqual(captured["executable"], SOURCE_AUTH_APPLIANCE)
        self.assertEqual(captured["arguments"], ())
        self.assertEqual(captured["payload"], expected_payload)
        self.assertIs(captured["payload_type"], bytearray)
        self.assertEqual(captured["workspace"], self.source_workspace)
        self.assertEqual(captured["timeout_seconds"], 180.0)
        self.assertEqual(captured["expected_executable_size_bytes"], SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES)
        self.assertEqual(captured["expected_executable_sha256"], SOURCE_APPLIANCE_EXECUTABLE_SHA256)
        self.assertEqual(captured["stdout_cap_bytes"], SOURCE_AUTH_STDOUT_CAP_BYTES)
        self.assertEqual(captured["stderr_cap_bytes"], SOURCE_AUTH_STDERR_CAP_BYTES)
        self.assertIs(captured["stdout_ascii"], False)
        self.assertEqual(captured["expected_input_bytes"], SOURCE_AUTH_INPUT_BYTES)

    def test_source_caller_rejects_timeout_shape_output_and_containment_failures(self) -> None:
        batch = self._batch()
        witness, seed, randomizer = self._source_values()
        complete = b"f" * SOURCE_AUTH_FRAME_BYTES
        cases = (
            ("timeout", _contained(timed_out=True), "source_timeout"),
            ("truncation", _contained(stdout=complete[:-1]), "source_frame_truncated"),
            ("trailing", _contained(stdout=complete + b"x"), "source_frame_trailing"),
            ("stderr", _contained(stdout=complete, stderr=b"x"), "source_stderr"),
            ("exit", _contained(stdout=complete, exit_code=1), "source_process"),
            ("containment", _contained(stdout=complete, process_tree_complete=False), "source_process"),
            ("measurement", _contained(stdout=complete, measurement_complete=False), "source_process"),
            ("cleanup", _contained(stdout=complete, cleanup_complete=False), "source_process"),
            ("cap", _contained(stdout=complete, cap_enforced=False), "source_process"),
        )
        for name, contained, error_code in cases:
            with self.subTest(name=name):
                payload_ref: list[bytearray] = []

                def runner(*args: object, **kwargs: object) -> ContainedVerifierResult:
                    del kwargs
                    payload_ref.append(args[2])  # type: ignore[arg-type]
                    return contained

                with patch("profile11_source_boundary.run_contained_verifier_stream", side_effect=runner):
                    with self.assertRaisesRegex(SourceBoundaryError, error_code):
                        self.caller.prove_one(
                            batch=batch,
                            source_key_epoch=self.queue_config.source_key_epoch,
                            secret_key=self.secret_key,
                            witness=witness,
                            seed=seed,
                            randomizer=randomizer,
                        )
                self.assertEqual(len(payload_ref), 1)
                self.assertEqual(payload_ref[0], bytearray())

    def test_source_caller_fails_before_accepting_on_pinned_runner_failure(self) -> None:
        batch = self._batch()
        witness, seed, randomizer = self._source_values()
        for runner_error, source_code in (
            ("verifier_child_image_identity", "source_process"),
            ("verifier_timeout", "source_timeout"),
            ("verifier_stream_input_incomplete", "source_process"),
        ):
            with self.subTest(runner_error=runner_error):
                payload_ref: list[bytearray] = []

                def runner(*args: object, **kwargs: object) -> ContainedVerifierResult:
                    del kwargs
                    payload_ref.append(args[2])  # type: ignore[arg-type]
                    raise VerifierProcessError(runner_error)

                with patch("profile11_source_boundary.run_contained_verifier_stream", side_effect=runner):
                    with self.assertRaisesRegex(SourceBoundaryError, source_code):
                        self.caller.prove_one(
                            batch=batch,
                            source_key_epoch=self.queue_config.source_key_epoch,
                            secret_key=self.secret_key,
                            witness=witness,
                            seed=seed,
                            randomizer=randomizer,
                        )
                self.assertEqual(len(payload_ref), 1)
                self.assertEqual(payload_ref[0], bytearray())

    def test_one_queue_batch_uses_one_appliance_frame_one_c_call_and_settles_100(self) -> None:
        verifier_config = source_auth_adapter.SourceAuthVerifierConfig(
            queue_config=self.queue_config,
            executable_path=SOURCE_AUTH_C_VERIFIER,
            executable_size_bytes=SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
            executable_sha256=SOURCE_AUTH_EXECUTABLE_SHA256,
            workspace=self.verifier_workspace,
            ml_dsa_87_public_key=self.public_key,
            timeout_seconds=30.0,
        )
        state_port = _StateDispositionPort()
        observed: list[ContainedVerifierResult] = []
        real_runner = source_auth_adapter.run_contained_verifier_stream
        runtime = None
        frame_snapshot = b""
        witness, seed, randomizer = self._source_values()
        try:
            from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime

            runtime = MinimalClearanceVerificationRuntime.from_source_auth(
                root=self.state_root,
                source_auth_config=verifier_config,
                state_disposition_port=state_port,
            )
            batch = runtime.issue_batch(template=self._template())
            batch_statement = batch.proof_statement
            frame = self.caller.prove_one(
                batch=batch,
                source_key_epoch=self.queue_config.source_key_epoch,
                secret_key=self.secret_key,
                witness=witness,
                seed=seed,
                randomizer=randomizer,
            )
            self.assertEqual(len(frame), SOURCE_AUTH_FRAME_BYTES)
            frame_snapshot = bytes(frame)

            def runner(*args: object, **kwargs: object) -> ContainedVerifierResult:
                result = real_runner(*args, **kwargs)
                observed.append(result)
                return result

            with patch.object(source_auth_adapter, "run_contained_verifier_stream", side_effect=runner):
                runtime.submit_batch_handoff(
                    issued_batch=batch,
                    proof_stream=VolatileProofHandoff(frame),
                )
                outcome = runtime.run(max_batches=1)
            self.assertEqual(outcome.outcome, "PROCESSED")
            self.assertEqual(outcome.accepted_operation_count, 100)
            self.assertEqual(outcome.verified_batch_count, 1)
            self.assertEqual(outcome.rejected_batch_count, 0)
            self.assertEqual(outcome.held_batch_count, 0)
            self.assertEqual(state_port.calls, 1)
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0].exit_code, 0)
            self.assertEqual(observed[0].stdout, b"")
            self.assertEqual(observed[0].stderr, b"")
            self.assertTrue(observed[0].process_tree_complete)
            self.assertTrue(observed[0].measurement_complete)
            self.assertTrue(observed[0].cleanup_complete)
            self.assertGreaterEqual(observed[0].child_process_count, 1)
            self.assertEqual(observed[0].active_process_limit, ACTIVE_PROCESS_LIMIT)
            self.assertEqual(observed[0].cap_bytes, ADMISSION_CAP_BYTES)
            self.assertLessEqual(observed[0].peak_job_commit_bytes, ADMISSION_CAP_BYTES)
            runtime._verify_integrity()
        finally:
            if runtime is not None:
                runtime.close()
        durable = (self.state_root / "state.sqlite").read_bytes()
        self.assertNotIn(frame_snapshot, durable)
        self.assertNotIn(self.secret_key, durable)
        self.assertNotIn(self.public_key, durable)
        self.assertNotIn(seed, durable)
        self.assertNotIn(randomizer, durable)
        self.assertNotIn(batch_statement, durable)
        connection = sqlite3.connect(self.state_root / "state.sqlite")
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_members").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM queue_results").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT terminal_status FROM queue_results").fetchone()[0], "VERIFIED")
            directives = [row[0] for row in connection.execute("SELECT effective_directive FROM composition_transactions")]
            self.assertEqual(len(directives), 100)
            self.assertEqual(set(directives), {"HOLD"})
        finally:
            connection.close()
        allowed = {"state.sqlite", "state.sqlite-journal", "state.sqlite-wal", "state.sqlite-shm"}
        self.assertTrue({path.name for path in self.state_root.iterdir()} <= allowed)
        self._assert_empty_workspace()

    def test_appliance_no_frame_two_frames_and_complete_then_truncated_next(self) -> None:
        batch = self._batch()
        witness, seed, randomizer = self._source_values()
        provision = build_provision_record(source_key_epoch=self.queue_config.source_key_epoch, secret_key=self.secret_key)
        first = build_request_record(batch=batch, witness=witness, seed=seed, randomizer=randomizer)
        second = build_request_record(batch=batch, witness=witness, seed=bytes([0x21] * SOURCE_AUTH_SEED_BYTES), randomizer=bytes([0x22] * SOURCE_AUTH_RANDOMIZER_BYTES))
        try:
            code, stdout, stderr = self._run_appliance(bytearray(provision))
            self.assertEqual((code, stdout, stderr), (0, b"", b""))
            self._assert_empty_workspace()

            two = bytearray(provision)
            two.extend(first)
            two.extend(second)
            code, stdout, stderr = self._run_appliance(two)
            self.assertEqual((code, len(stdout), stderr), (0, 2 * SOURCE_AUTH_FRAME_BYTES, b""))
            self.assertEqual(stdout[:16], b"BL-SAUTH-FRM-V1\0")
            self.assertEqual(stdout[SOURCE_AUTH_FRAME_BYTES:SOURCE_AUTH_FRAME_BYTES + 16], b"BL-SAUTH-FRM-V1\0")
            self._assert_empty_workspace()

            partial = bytearray(provision)
            partial.extend(first)
            partial.extend(second[:7])
            code, stdout, stderr = self._run_appliance(partial)
            self.assertEqual((code, len(stdout), stderr), (1, SOURCE_AUTH_FRAME_BYTES, b""))
            self.assertEqual(stdout[:16], b"BL-SAUTH-FRM-V1\0")
            self._assert_empty_workspace()
        finally:
            _wipe(provision)
            _wipe(first)
            _wipe(second)


if __name__ == "__main__":
    unittest.main()
