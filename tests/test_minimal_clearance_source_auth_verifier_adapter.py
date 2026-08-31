import hashlib
import threading
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import app.minimal_clearance_composition as composition
from app.minimal_clearance_composition import StateDispositionControl
from app.minimal_clearance_source_auth_verifier_adapter import (
    ML_DSA_87_PUBLIC_KEY_BYTES,
    MinimalClearanceSourceAuthVerifierAdapter,
    SOURCE_AUTH_PROOF_ENVELOPE_BYTES,
    SOURCE_AUTH_SIGNED_PREFIX_BYTES,
    SOURCE_AUTH_SIGNATURE_BYTES,
    SOURCE_AUTH_FRAME_BYTES,
    SOURCE_AUTH_EXECUTABLE_SHA256,
    SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
    SOURCE_AUTH_IPC_PREFIX_BYTES,
    SOURCE_AUTH_IPC_BYTES,
    SOURCE_AUTH_PROCESS_ARGUMENTS,
    SourceAuthVerifierConfig,
)
from app.minimal_clearance_verification_queue import (
    ADMISSION_CAP_BYTES,
    ACTIVE_PROCESS_LIMIT,
    BatchVerifierResult,
    IssuedVerificationBatch,
    OperationTemplate,
    QueueConfig,
    QueueHeldError,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
    _build_statement,
    _compute_batch_root_from_refs,
)
from app.minimal_clearance_verifier_process import ContainedVerifierResult, VerifierProcessError


class _Fixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.executable = self.root / "blind-source-auth-v10.exe"
        self.executable_bytes = b"synthetic-future-v10-executable"
        self.executable.write_bytes(self.executable_bytes)
        self.workspace = self.root / "verifier-workspace"
        self.workspace.mkdir()
        self.key = bytes(range(256)) * (ML_DSA_87_PUBLIC_KEY_BYTES // 256) + bytes(range(ML_DSA_87_PUBLIC_KEY_BYTES % 256))
        self.queue_config = QueueConfig("queue-v10", 100, source_key_epoch=0x0102030405060708)
        template = OperationTemplate("assertion", 1, "state-profile-v10", 1_700_000_000_000, 1_700_003_600_000, None, self.queue_config.qualification_flags)
        refs = tuple(index.to_bytes(32, "little") for index in range(100))
        root = _compute_batch_root_from_refs(template, refs)
        statement = _build_statement(batch_root=root, session_ref=bytes(range(64)), valid_from_ms=template.valid_from_ms, valid_until_ms=template.valid_until_ms)
        self.batch = IssuedVerificationBatch(b"b" * 32, template, refs, root, bytes(range(64)), statement, 1, b"i" * 64)
        self.config = SourceAuthVerifierConfig(
            queue_config=self.queue_config,
            executable_path=self.executable,
            executable_size_bytes=SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
            executable_sha256=SOURCE_AUTH_EXECUTABLE_SHA256,
            workspace=self.workspace,
            ml_dsa_87_public_key=self.key,
            timeout_seconds=30.0,
        )
        self.adapter = MinimalClearanceSourceAuthVerifierAdapter(self.config)
        self.frame = bytes((index * 17) % 256 for index in range(SOURCE_AUTH_FRAME_BYTES))

    def close(self) -> None:
        self.temp.cleanup()


class _Clock:
    def now_ms(self) -> int:
        return 1_700_000_000_001


def _contained(*, exit_code: int = 0, stdout: bytes = b"", stderr: bytes = b"", peak_job_commit_bytes: int = 1024, timed_out: bool = False, cap_bytes: int = ADMISSION_CAP_BYTES, cap_enforced: bool = True, active_process_limit: int = ACTIVE_PROCESS_LIMIT, child_process_count: int = 1, process_tree_complete: bool = True, measurement_complete: bool = True, cleanup_complete: bool = True) -> ContainedVerifierResult:
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
    )


def _state_controls(operation_refs: tuple[bytes, ...]) -> dict[bytes, StateDispositionControl]:
    profile = bytes([9]) * 64
    state_id = bytes(64)
    state_bytes = bytes(64)
    continuity = bytes(64)
    audit = bytes(64)
    clearance = bytes(64)
    result: dict[bytes, StateDispositionControl] = {}
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
        result[operation_ref] = control
        state_id = control.state_after_id
        state_bytes = control.state_after_bytes
        continuity = control.state_after_continuity_root
        audit = composition._sha(composition._STATE, audit, control.decision_id, control.effective_directive.encode("ascii"))
    return result


class _StateDispositionPort:
    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome: object) -> dict[bytes, StateDispositionControl]:
        del batch_id, verification_outcome
        return _state_controls(operation_refs)


class SourceAuthAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def _run(self, result: ContainedVerifierResult = _contained()):
        captured: dict[str, object] = {}

        def runner(
            executable: Path,
            arguments: tuple[str, ...],
            frame: bytes | bytearray,
            *,
            workspace: Path,
            timeout_seconds: float,
            expected_executable_size_bytes: int,
            expected_executable_sha256: bytes,
        ):
            captured.update(
                executable=executable,
                arguments=arguments,
                frame=bytes(frame),
                input_type=type(frame),
                workspace=workspace,
                timeout_seconds=timeout_seconds,
                expected_executable_size_bytes=expected_executable_size_bytes,
                expected_executable_sha256=expected_executable_sha256,
            )
            return result

        return captured, runner

    def test_builds_exact_ordered_ipc_and_returns_bound_acceptance(self) -> None:
        self.assertEqual(SOURCE_AUTH_PROOF_ENVELOPE_BYTES, 16_294_348)
        self.assertEqual(SOURCE_AUTH_SIGNED_PREFIX_BYTES, 16_297_640)
        self.assertEqual(SOURCE_AUTH_SIGNATURE_BYTES, 4_627)
        self.assertEqual(SOURCE_AUTH_FRAME_BYTES, 16_302_267)
        self.assertEqual(SOURCE_AUTH_IPC_PREFIX_BYTES, 6_168)
        self.assertEqual(SOURCE_AUTH_IPC_BYTES, 16_308_435)
        self.assertEqual(SOURCE_AUTH_IPC_BYTES, SOURCE_AUTH_IPC_PREFIX_BYTES + SOURCE_AUTH_FRAME_BYTES)
        captured, runner = self._run()
        handoff = VolatileProofHandoff(bytearray(self.fixture.frame))
        with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=runner):
            result = self.fixture.adapter.verify(handoff, self.fixture.batch)
        self.assertIsInstance(result, BatchVerifierResult)
        self.assertTrue(result.proof_accepted)
        self.assertTrue(result.source_authenticated)
        self.assertEqual(result.proof_statement, self.fixture.batch.proof_statement)
        self.assertEqual(result.batch_root, self.fixture.batch.batch_root)
        self.assertEqual(result.source_auth_profile, self.fixture.queue_config.source_auth_profile)
        self.assertEqual(result.source_auth_profile, "BLIND-MLDSA87-SOURCE-AUTH-V1-R100-CDG-DIRECT-V1-UNQUALIFIED")
        self.assertEqual(result.source_key_epoch, self.fixture.queue_config.source_key_epoch)
        self.assertEqual(result.qualification_flags, self.fixture.queue_config.qualification_flags)
        self.assertEqual(result.result_code, "accepted")
        self.assertEqual(captured["executable"], self.fixture.executable)
        self.assertEqual(captured["arguments"], SOURCE_AUTH_PROCESS_ARGUMENTS)
        self.assertEqual(captured["workspace"], self.fixture.workspace)
        self.assertTrue(self.fixture.workspace.is_dir())
        self.assertEqual(tuple(self.fixture.workspace.iterdir()), ())
        self.assertEqual(captured["timeout_seconds"], 30.0)
        self.assertEqual(captured["expected_executable_size_bytes"], SOURCE_AUTH_EXECUTABLE_SIZE_BYTES)
        self.assertEqual(captured["expected_executable_sha256"], SOURCE_AUTH_EXECUTABLE_SHA256)
        ipc = captured["frame"]
        self.assertIs(captured["input_type"], bytearray)
        self.assertIs(type(ipc), bytes)
        self.assertEqual(len(ipc), SOURCE_AUTH_IPC_BYTES)
        self.assertEqual(ipc[:8], self.fixture.queue_config.source_key_epoch.to_bytes(8, "little"))
        self.assertEqual(ipc[8:72], self.fixture.batch.batch_root)
        self.assertEqual(ipc[72:3272], b"".join(self.fixture.batch.operation_refs))
        self.assertEqual(ipc[3272:3576], self.fixture.batch.proof_statement)
        self.assertEqual(ipc[3576:SOURCE_AUTH_IPC_PREFIX_BYTES], self.fixture.key)
        self.assertEqual(ipc[SOURCE_AUTH_IPC_PREFIX_BYTES:], self.fixture.frame)
        self.assertTrue(handoff.used)
        self.assertTrue(handoff.exhausted)
        self.assertTrue(handoff.closed)
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_closed"):
            self.fixture.adapter.verify(handoff, self.fixture.batch)

    def test_exit_one_is_fail_closed_combined_rejection(self) -> None:
        captured, runner = self._run(_contained(exit_code=1))
        with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=runner):
            result = self.fixture.adapter.verify(VolatileProofHandoff(bytearray(self.fixture.frame)), self.fixture.batch)
        self.assertEqual((result.proof_accepted, result.source_authenticated, result.result_code), (False, False, "rejected"))
        self.assertEqual(len(captured["frame"]), SOURCE_AUTH_IPC_BYTES)

    def _forged_batch(self, **changes: object) -> IssuedVerificationBatch:
        forged = object.__new__(IssuedVerificationBatch)
        field_names = ("batch_id", "template", "operation_refs", "batch_root", "session_ref", "proof_statement", "admission_seq", "identity_digest")
        for field_name in field_names:
            object.__setattr__(forged, field_name, changes.get(field_name, getattr(self.fixture.batch, field_name)))
        return forged

    def test_changed_epoch_key_and_frame_reach_combined_rejection(self) -> None:
        cases = (
            ("epoch", replace(self.fixture.config, queue_config=replace(self.fixture.queue_config, source_key_epoch=self.fixture.queue_config.source_key_epoch + 1)), self.fixture.batch, self.fixture.frame, slice(0, 8)),
            ("public_key", replace(self.fixture.config, ml_dsa_87_public_key=bytes([self.fixture.key[0] ^ 1]) + self.fixture.key[1:]), self.fixture.batch, self.fixture.frame, slice(3576, SOURCE_AUTH_IPC_PREFIX_BYTES)),
            ("frame", self.fixture.config, self.fixture.batch, bytes([self.fixture.frame[0] ^ 1]) + self.fixture.frame[1:], slice(SOURCE_AUTH_IPC_PREFIX_BYTES, SOURCE_AUTH_IPC_BYTES)),
        )
        for name, config, batch, frame, changed_slice in cases:
            with self.subTest(name=name):
                captured, runner = self._run(_contained(exit_code=1))
                with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=runner):
                    result = MinimalClearanceSourceAuthVerifierAdapter(config).verify(VolatileProofHandoff(bytearray(frame)), batch)
                self.assertEqual((result.proof_accepted, result.source_authenticated, result.result_code), (False, False, "rejected"))
                current = captured["frame"]
                baseline = self.fixture.frame if name == "frame" else self.fixture.config.ml_dsa_87_public_key if name == "public_key" else self.fixture.queue_config.source_key_epoch.to_bytes(8, "little")
                self.assertNotEqual(current[changed_slice], baseline)

    def test_changed_root_ref_session_and_statement_fail_before_runner(self) -> None:
        cases = (
            ("root", self._forged_batch(batch_root=bytes([self.fixture.batch.batch_root[0] ^ 1]) + self.fixture.batch.batch_root[1:])),
            ("ref", self._forged_batch(operation_refs=(bytes([self.fixture.batch.operation_refs[0][0] ^ 1]) + self.fixture.batch.operation_refs[0][1:],) + self.fixture.batch.operation_refs[1:])),
            ("session_ref", self._forged_batch(session_ref=bytes([self.fixture.batch.session_ref[0] ^ 1]) + self.fixture.batch.session_ref[1:])),
            ("statement", self._forged_batch(proof_statement=bytes([self.fixture.batch.proof_statement[0] ^ 1]) + self.fixture.batch.proof_statement[1:])),
        )
        for name, batch in cases:
            with self.subTest(name=name):
                with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream") as runner:
                    with self.assertRaisesRegex(QueueHeldError, "batch_binding"):
                        self.fixture.adapter.verify(VolatileProofHandoff(bytearray(self.fixture.frame)), batch)
                runner.assert_not_called()

    def test_short_and_trailing_handoffs_fail_before_runner(self) -> None:
        for payload in (self.fixture.frame[:-1], self.fixture.frame + b"x"):
            with self.subTest(length=len(payload)):
                with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream") as runner:
                    with self.assertRaisesRegex(QueueHeldError, "proof_handoff_length"):
                        self.fixture.adapter.verify(VolatileProofHandoff(bytearray(payload)), self.fixture.batch)
                runner.assert_not_called()

    def test_output_exit_two_timeout_and_containment_fail_closed(self) -> None:
        cases = (
            (_contained(stdout=b"x"), "verifier_transport"),
            (_contained(stderr=b"x"), "verifier_transport"),
            (_contained(exit_code=2), "verifier_transport"),
            (_contained(exit_code=3), "verifier_transport"),
            (_contained(timed_out=True), "verifier_timeout"),
            (_contained(cap_enforced=False), "verifier_transport"),
            (_contained(cap_bytes=ADMISSION_CAP_BYTES + 1), "verifier_transport"),
            (_contained(peak_job_commit_bytes=ADMISSION_CAP_BYTES + 1), "verifier_transport"),
            (_contained(active_process_limit=ACTIVE_PROCESS_LIMIT + 1), "verifier_transport"),
            (_contained(child_process_count=0), "verifier_transport"),
            (_contained(measurement_complete=False), "verifier_transport"),
            (_contained(peak_job_commit_bytes=-1), "verifier_transport"),
            (_contained(process_tree_complete=False), "verifier_transport"),
            (_contained(cleanup_complete=False), "verifier_transport"),
        )
        for contained, code in cases:
            with self.subTest(code=code, contained=contained):
                captured, runner = self._run(contained)
                with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=runner):
                    with self.assertRaisesRegex(QueueHeldError, code):
                        self.fixture.adapter.verify(VolatileProofHandoff(bytearray(self.fixture.frame)), self.fixture.batch)

    def test_runner_timeout_and_containment_errors_are_held(self) -> None:
        for error, code in ((VerifierProcessError("verifier_timeout"), "verifier_timeout"), (VerifierProcessError("verifier_job_assign"), "verifier_transport"), (RuntimeError("internal"), "verifier_transport")):
            with self.subTest(code=code):
                with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=error):
                    with self.assertRaisesRegex(QueueHeldError, code):
                        self.fixture.adapter.verify(VolatileProofHandoff(bytearray(self.fixture.frame)), self.fixture.batch)

    def test_forwards_artifact_pin_to_contained_runner(self) -> None:
        captured, runner = self._run()
        with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=runner):
            MinimalClearanceSourceAuthVerifierAdapter(self.fixture.config).verify(
                VolatileProofHandoff(bytearray(self.fixture.frame)), self.fixture.batch
            )
        self.assertEqual(captured["expected_executable_size_bytes"], SOURCE_AUTH_EXECUTABLE_SIZE_BYTES)
        self.assertEqual(captured["expected_executable_sha256"], self.fixture.config.executable_sha256)

    def test_concurrent_call_is_nonblocking_and_consumes_its_handoff(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        calls = 0

        def runner(*args: object, **kwargs: object) -> ContainedVerifierResult:
            nonlocal calls
            calls += 1
            entered.set()
            self.assertTrue(release.wait(5))
            del args, kwargs
            return _contained()

        first_result: list[BatchVerifierResult] = []
        first_error: list[BaseException] = []

        def first_call() -> None:
            try:
                first_result.append(
                    self.fixture.adapter.verify(
                        VolatileProofHandoff(bytearray(self.fixture.frame)),
                        self.fixture.batch,
                    )
                )
            except BaseException as error:
                first_error.append(error)

        with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=runner):
            worker = threading.Thread(target=first_call)
            worker.start()
            self.assertTrue(entered.wait(5))
            second_handoff = VolatileProofHandoff(bytearray(self.fixture.frame))
            with self.assertRaisesRegex(QueueHeldError, "verifier_transport"):
                self.fixture.adapter.verify(second_handoff, self.fixture.batch)
            self.assertTrue(second_handoff.closed)
            self.assertEqual(calls, 1)
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(first_error, [])
        self.assertEqual(len(first_result), 1)

    def test_recursive_call_is_nonreentrant_and_consumes_its_handoff(self) -> None:
        recursive_handoff: list[VolatileProofHandoff] = []
        recursive_error: list[QueueHeldError] = []

        def runner(*args: object, **kwargs: object) -> ContainedVerifierResult:
            del args, kwargs
            nested = VolatileProofHandoff(bytearray(self.fixture.frame))
            recursive_handoff.append(nested)
            try:
                self.fixture.adapter.verify(nested, self.fixture.batch)
            except QueueHeldError as error:
                recursive_error.append(error)
            return _contained()

        with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=runner):
            result = self.fixture.adapter.verify(
                VolatileProofHandoff(bytearray(self.fixture.frame)),
                self.fixture.batch,
            )
        self.assertEqual(result.result_code, "accepted")
        self.assertEqual([str(error) for error in recursive_error], ["verifier_transport"])
        self.assertEqual(len(recursive_handoff), 1)
        self.assertTrue(recursive_handoff[0].closed)

    def test_handoff_close_is_local_and_idempotent(self) -> None:
        handoff = VolatileProofHandoff(bytearray(self.fixture.frame))
        handoff.read(1)
        handoff.close()
        handoff.close()
        self.assertTrue(handoff.closed)
        self.assertEqual(handoff.total_read, 1)
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_closed"):
            handoff.read(1)

    def test_rejects_any_noncanonical_executable_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_auth_executable_identity"):
            replace(self.fixture.config, executable_size_bytes=SOURCE_AUTH_EXECUTABLE_SIZE_BYTES - 1)
        with self.assertRaisesRegex(ValueError, "source_auth_executable_identity"):
            replace(self.fixture.config, executable_sha256=bytes(32))

    def test_public_key_is_not_repr_or_queue_durable_material(self) -> None:
        self.assertNotIn(self.fixture.key.hex(), repr(self.fixture.config))
        self.assertNotIn(self.fixture.key.hex(), repr(self.fixture.adapter))
        self.assertNotIn(self.fixture.key.hex(), repr(self.fixture.queue_config))
        result = BatchVerifierResult(True, True, self.fixture.batch.proof_statement, self.fixture.batch.batch_root, self.fixture.queue_config.source_auth_profile, self.fixture.queue_config.source_key_epoch, "accepted", self.fixture.queue_config.qualification_flags)
        self.assertNotIn(self.fixture.key.hex(), repr(result))
        self.assertNotIn(self.fixture.key.hex(), str(result.as_json))

    def test_queue_projection_does_not_persist_key_frame_or_ipc(self) -> None:
        database = self.fixture.root / "state.sqlite"
        owner = _QueueRuntimeOwnership(lock_path=database.with_name(database.name + ".runtime-lock"), parent=self.fixture.root)
        store = _VerificationQueueStore(path=database, config=self.fixture.queue_config, owner=owner, clock=_Clock())
        captured: dict[str, bytes] = {}

        def runner(
            _executable: Path,
            _arguments: tuple[str, ...],
            ipc: bytes | bytearray,
            *,
            workspace: Path,
            timeout_seconds: float,
            expected_executable_size_bytes: int,
            expected_executable_sha256: bytes,
        ):
            del workspace, timeout_seconds, expected_executable_size_bytes, expected_executable_sha256
            captured["ipc"] = bytes(ipc)
            return _contained()

        try:
            batch = store.issue_batch(template=self.fixture.batch.template)
            store.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(bytearray(self.fixture.frame)))
            with patch("app.minimal_clearance_source_auth_verifier_adapter.run_contained_verifier_stream", side_effect=runner):
                self.assertEqual(store._process_one_batch(verifier=self.fixture.adapter, state_disposition_port=_StateDispositionPort()).status, "VERIFIED")
            store._verify_integrity()
            durable = database.read_bytes()
            self.assertNotIn(self.fixture.key, durable)
            self.assertNotIn(self.fixture.frame, durable)
            self.assertNotIn(captured["ipc"], durable)
            self.assertNotIn(self.fixture.batch.proof_statement, durable)
        finally:
            store._close()
            owner.close()


if __name__ == "__main__":
    unittest.main()
