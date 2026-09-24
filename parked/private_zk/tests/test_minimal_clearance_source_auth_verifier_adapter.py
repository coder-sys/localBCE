import threading
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import parked.private_zk.app.minimal_clearance_composition as composition
import parked.private_zk.app.minimal_clearance_source_auth_verifier_adapter as source_auth_adapter
from parked.private_zk.app.minimal_clearance_composition import StateDispositionControl
from parked.private_zk.app.minimal_clearance_source_auth_verifier_adapter import (
    ML_DSA_87_PUBLIC_KEY_BYTES,
    MinimalClearanceSourceAuthVerifierAdapter,
    SOURCE_AUTH_EXECUTABLE_SHA256,
    SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
    SOURCE_AUTH_FRAME_BYTES,
    SOURCE_AUTH_IPC_BYTES,
    SOURCE_AUTH_IPC_PREFIX_BYTES,
    SOURCE_AUTH_PROCESS_ARGUMENTS,
    SOURCE_AUTH_PROOF_ENVELOPE_BYTES,
    SOURCE_AUTH_SIGNED_PREFIX_BYTES,
    SOURCE_AUTH_SIGNATURE_BYTES,
    SourceAuthVerifierConfig,
)
from parked.private_zk.app.minimal_clearance_verification_queue import (
    ADMISSION_CAP_BYTES,
    ACTIVE_PROCESS_LIMIT,
    BatchVerifierResult,
    IssuedVerificationBatch,
    OperationTemplate,
    QueueConfig,
    QueueHeldError,
    QueueIntegrityError,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
    _compute_batch_root_from_refs,
    _profile12_context,
)
from app.minimal_clearance_verifier_process import ContainedVerifierResult, VerifierProcessError


def _contained(
    *,
    exit_code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    peak_job_commit_bytes: int = 1024,
    timed_out: bool = False,
    cap_bytes: int = ADMISSION_CAP_BYTES,
    cap_enforced: bool = True,
    active_process_limit: int = ACTIVE_PROCESS_LIMIT,
    child_process_count: int = 1,
    process_tree_complete: bool = True,
    measurement_complete: bool = True,
    cleanup_complete: bool = True,
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
    )


class _Fixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.executable = self.root / "dm_pipeline_verifier_cli.exe"
        self.executable.write_bytes(b"synthetic-pinned-executable")
        self.workspace = self.root / "verifier-workspace"
        self.workspace.mkdir()
        self.key = bytes((index * 17 + 3) % 256 for index in range(ML_DSA_87_PUBLIC_KEY_BYTES))
        self.queue_config = QueueConfig(
            "queue-profile12",
            100,
            source_key_epoch=0x0102030405060708,
        )
        template = OperationTemplate(
            "assertion",
            1,
            self.queue_config.profile_version,
            1_700_000_000_000,
            1_700_003_600_000,
            None,
            self.queue_config.qualification_flags,
        )
        refs = tuple(index.to_bytes(32, "little") for index in range(100))
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
        self.batch = IssuedVerificationBatch(
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
        self.capsule = bytearray(
            (index * 17 + 11) % 256 for index in range(SOURCE_AUTH_FRAME_BYTES)
        )
        self.capsule[:8] = b"DMSP0001"
        self.capsule[8:16] = self.queue_config.source_key_epoch.to_bytes(8, "little")

    def close(self) -> None:
        self.temp.cleanup()


def _state_controls(
    operation_refs: tuple[bytes, ...],
) -> dict[bytes, StateDispositionControl]:
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
        audit = composition._sha(
            composition._STATE,
            audit,
            control.decision_id,
            control.effective_directive.encode("ascii"),
        )
    return result


class _StateDispositionPort:
    def controls_for(
        self,
        *,
        batch_id: bytes,
        operation_refs: tuple[bytes, ...],
        verification_outcome: object,
    ) -> dict[bytes, StateDispositionControl]:
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
            expected_input_bytes: int,
        ) -> ContainedVerifierResult:
            captured.update(
                executable=executable,
                arguments=arguments,
                frame=bytes(frame),
                input_type=type(frame),
                workspace=workspace,
                timeout_seconds=timeout_seconds,
                expected_executable_size_bytes=expected_executable_size_bytes,
                expected_executable_sha256=expected_executable_sha256,
                expected_input_bytes=expected_input_bytes,
            )
            return result

        return captured, runner

    def test_builds_exact_profile12_ipc_and_returns_typed_acceptance(self) -> None:
        self.assertEqual(SOURCE_AUTH_PROOF_ENVELOPE_BYTES, 534_370)
        self.assertEqual(SOURCE_AUTH_SIGNED_PREFIX_BYTES, 4_643)
        self.assertEqual(SOURCE_AUTH_SIGNATURE_BYTES, 4_627)
        self.assertEqual(SOURCE_AUTH_FRAME_BYTES, 539_013)
        self.assertEqual(SOURCE_AUTH_IPC_PREFIX_BYTES, 2_768)
        self.assertEqual(SOURCE_AUTH_IPC_BYTES, 541_781)
        self.assertEqual(
            SOURCE_AUTH_IPC_BYTES,
            SOURCE_AUTH_IPC_PREFIX_BYTES + SOURCE_AUTH_FRAME_BYTES,
        )
        captured, runner = self._run()
        handoff = VolatileProofHandoff(bytearray(self.fixture.capsule))
        with patch.object(
            source_auth_adapter,
            "run_contained_verifier_stream",
            side_effect=runner,
        ):
            result = self.fixture.adapter.verify(handoff, self.fixture.batch)
        self.assertIsInstance(result, BatchVerifierResult)
        self.assertTrue(result.proof_accepted)
        self.assertTrue(result.source_authenticated)
        self.assertEqual(result.proof_context, self.fixture.batch.proof_context)
        self.assertEqual(result.public_coin, self.fixture.batch.public_coin)
        self.assertEqual(result.batch_root, self.fixture.batch.batch_root)
        self.assertEqual(
            result.source_auth_profile,
            "BLIND-MLDSA87-SOURCE-AUTH-DIRECT-MASK-V1-UNQUALIFIED",
        )
        self.assertEqual(result.source_key_epoch, self.fixture.queue_config.source_key_epoch)
        self.assertEqual(result.qualification_flags, self.fixture.queue_config.qualification_flags)
        self.assertEqual(result.result_code, "accepted")
        self.assertEqual(captured["executable"], self.fixture.executable)
        self.assertEqual(captured["arguments"], SOURCE_AUTH_PROCESS_ARGUMENTS)
        self.assertEqual(captured["workspace"], self.fixture.workspace)
        self.assertEqual(captured["timeout_seconds"], 30.0)
        self.assertEqual(
            captured["expected_executable_size_bytes"],
            SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
        )
        self.assertEqual(captured["expected_executable_sha256"], SOURCE_AUTH_EXECUTABLE_SHA256)
        self.assertEqual(captured["expected_input_bytes"], SOURCE_AUTH_IPC_BYTES)
        ipc = captured["frame"]
        self.assertIs(captured["input_type"], bytearray)
        self.assertIs(type(ipc), bytes)
        self.assertEqual(len(ipc), SOURCE_AUTH_IPC_BYTES)
        self.assertEqual(ipc[:8], b"DMVI0001")
        self.assertEqual(
            ipc[8:16],
            self.fixture.queue_config.source_key_epoch.to_bytes(8, "little"),
        )
        self.assertEqual(ipc[16:80], self.fixture.batch.proof_context)
        self.assertEqual(ipc[80:176], self.fixture.batch.public_coin)
        self.assertEqual(ipc[176:SOURCE_AUTH_IPC_PREFIX_BYTES], self.fixture.key)
        self.assertEqual(ipc[SOURCE_AUTH_IPC_PREFIX_BYTES:], self.fixture.capsule)
        self.assertTrue(handoff.used)
        self.assertTrue(handoff.exhausted)
        self.assertTrue(handoff.closed)
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_closed"):
            self.fixture.adapter.verify(handoff, self.fixture.batch)

    def test_exit_one_is_fail_closed_combined_rejection(self) -> None:
        captured, runner = self._run(_contained(exit_code=1))
        with patch.object(
            source_auth_adapter,
            "run_contained_verifier_stream",
            side_effect=runner,
        ):
            result = self.fixture.adapter.verify(
                VolatileProofHandoff(bytearray(self.fixture.capsule)),
                self.fixture.batch,
            )
        self.assertEqual(
            (result.proof_accepted, result.source_authenticated, result.result_code),
            (False, False, "rejected"),
        )
        self.assertEqual(len(captured["frame"]), SOURCE_AUTH_IPC_BYTES)

    def _forged_batch(self, **changes: object) -> IssuedVerificationBatch:
        forged = object.__new__(IssuedVerificationBatch)
        field_names = (
            "batch_id",
            "template",
            "operation_refs",
            "batch_root",
            "session_ref",
            "public_coin",
            "proof_context",
            "admission_seq",
            "identity_digest",
        )
        for field_name in field_names:
            object.__setattr__(
                forged,
                field_name,
                changes.get(field_name, getattr(self.fixture.batch, field_name)),
            )
        return forged

    def test_changed_batch_bindings_fail_before_runner(self) -> None:
        cases = (
            (
                "root",
                self._forged_batch(
                    batch_root=bytes([self.fixture.batch.batch_root[0] ^ 1])
                    + self.fixture.batch.batch_root[1:]
                ),
                QueueIntegrityError,
                "profile12_context",
            ),
            (
                "ref",
                self._forged_batch(
                    operation_refs=(
                        (
                            bytes([self.fixture.batch.operation_refs[0][0] ^ 1])
                            + self.fixture.batch.operation_refs[0][1:]
                        ),
                    )
                    + self.fixture.batch.operation_refs[1:]
                ),
                QueueHeldError,
                "batch_binding",
            ),
            (
                "session_ref",
                self._forged_batch(
                    session_ref=bytes([self.fixture.batch.session_ref[0] ^ 1])
                    + self.fixture.batch.session_ref[1:]
                ),
                QueueIntegrityError,
                "profile12_context",
            ),
            (
                "public_coin",
                self._forged_batch(
                    public_coin=bytes([self.fixture.batch.public_coin[0] ^ 1])
                    + self.fixture.batch.public_coin[1:]
                ),
                QueueIntegrityError,
                "profile12_context",
            ),
            (
                "proof_context",
                self._forged_batch(
                    proof_context=bytes([self.fixture.batch.proof_context[0] ^ 1])
                    + self.fixture.batch.proof_context[1:]
                ),
                QueueIntegrityError,
                "profile12_context",
            ),
        )
        for name, batch, error_type, error_code in cases:
            with self.subTest(name=name):
                with patch.object(
                    source_auth_adapter,
                    "run_contained_verifier_stream",
                ) as runner:
                    with self.assertRaisesRegex(error_type, error_code):
                        self.fixture.adapter.verify(
                            VolatileProofHandoff(bytearray(self.fixture.capsule)),
                            batch,
                        )
                runner.assert_not_called()

    def test_short_and_trailing_handoffs_fail_before_runner(self) -> None:
        for payload in (
            self.fixture.capsule[:-1],
            self.fixture.capsule + b"x",
            self.fixture.capsule + self.fixture.capsule,
        ):
            with self.subTest(length=len(payload)):
                with patch.object(
                    source_auth_adapter,
                    "run_contained_verifier_stream",
                ) as runner:
                    with self.assertRaisesRegex(QueueHeldError, "proof_handoff_length"):
                        self.fixture.adapter.verify(
                            VolatileProofHandoff(bytearray(payload)),
                            self.fixture.batch,
                        )
                runner.assert_not_called()

    def test_stale_inner_frame_width_is_rejected_before_runner(self) -> None:
        stale = self.fixture.capsule[:SOURCE_AUTH_PROOF_ENVELOPE_BYTES]
        with patch.object(
            source_auth_adapter,
            "run_contained_verifier_stream",
        ) as runner:
            with self.assertRaisesRegex(QueueHeldError, "proof_handoff_length"):
                self.fixture.adapter.verify(
                    VolatileProofHandoff(bytearray(stale)),
                    self.fixture.batch,
                )
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
                _captured, runner = self._run(contained)
                with patch.object(
                    source_auth_adapter,
                    "run_contained_verifier_stream",
                    side_effect=runner,
                ):
                    with self.assertRaisesRegex(QueueHeldError, code):
                        self.fixture.adapter.verify(
                            VolatileProofHandoff(bytearray(self.fixture.capsule)),
                            self.fixture.batch,
                        )

    def test_runner_timeout_and_containment_errors_are_held(self) -> None:
        for error, code in (
            (VerifierProcessError("verifier_timeout"), "verifier_timeout"),
            (VerifierProcessError("verifier_stream_input_incomplete"), "verifier_transport"),
            (VerifierProcessError("verifier_job_assign"), "verifier_transport"),
            (RuntimeError("internal"), "verifier_transport"),
        ):
            with self.subTest(code=code):
                with patch.object(
                    source_auth_adapter,
                    "run_contained_verifier_stream",
                    side_effect=error,
                ):
                    with self.assertRaisesRegex(QueueHeldError, code):
                        self.fixture.adapter.verify(
                            VolatileProofHandoff(bytearray(self.fixture.capsule)),
                            self.fixture.batch,
                        )

    def test_forwards_artifact_pin_and_exact_input_length(self) -> None:
        captured, runner = self._run()
        with patch.object(
            source_auth_adapter,
            "run_contained_verifier_stream",
            side_effect=runner,
        ):
            self.fixture.adapter.verify(
                VolatileProofHandoff(bytearray(self.fixture.capsule)),
                self.fixture.batch,
            )
        self.assertEqual(
            captured["expected_executable_size_bytes"],
            SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
        )
        self.assertEqual(captured["expected_executable_sha256"], SOURCE_AUTH_EXECUTABLE_SHA256)
        self.assertEqual(captured["expected_input_bytes"], SOURCE_AUTH_IPC_BYTES)

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
                        VolatileProofHandoff(bytearray(self.fixture.capsule)),
                        self.fixture.batch,
                    )
                )
            except BaseException as error:
                first_error.append(error)

        with patch.object(
            source_auth_adapter,
            "run_contained_verifier_stream",
            side_effect=runner,
        ):
            worker = threading.Thread(target=first_call)
            worker.start()
            self.assertTrue(entered.wait(5))
            second_handoff = VolatileProofHandoff(bytearray(self.fixture.capsule))
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
            nested = VolatileProofHandoff(bytearray(self.fixture.capsule))
            recursive_handoff.append(nested)
            try:
                self.fixture.adapter.verify(nested, self.fixture.batch)
            except QueueHeldError as error:
                recursive_error.append(error)
            return _contained()

        with patch.object(
            source_auth_adapter,
            "run_contained_verifier_stream",
            side_effect=runner,
        ):
            result = self.fixture.adapter.verify(
                VolatileProofHandoff(bytearray(self.fixture.capsule)),
                self.fixture.batch,
            )
        self.assertEqual(result.result_code, "accepted")
        self.assertEqual([str(error) for error in recursive_error], ["verifier_transport"])
        self.assertEqual(len(recursive_handoff), 1)
        self.assertTrue(recursive_handoff[0].closed)

    def test_handoff_close_is_local_and_idempotent(self) -> None:
        handoff = VolatileProofHandoff(bytearray(self.fixture.capsule))
        handoff.read(1)
        handoff.close()
        handoff.close()
        self.assertTrue(handoff.closed)
        self.assertEqual(handoff.total_read, 1)
        with self.assertRaisesRegex(QueueHeldError, "proof_handoff_closed"):
            handoff.read(1)

    def test_rejects_noncanonical_executable_identity_and_key_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_auth_executable_identity"):
            replace(
                self.fixture.config,
                executable_size_bytes=SOURCE_AUTH_EXECUTABLE_SIZE_BYTES - 1,
            )
        with self.assertRaisesRegex(ValueError, "source_auth_executable_identity"):
            replace(self.fixture.config, executable_sha256=bytes(32))
        with self.assertRaisesRegex(ValueError, "source_auth_public_key"):
            replace(
                self.fixture.config,
                ml_dsa_87_public_key=bytes(ML_DSA_87_PUBLIC_KEY_BYTES - 1),
            )

    def test_public_key_is_not_repr_or_queue_durable_material(self) -> None:
        self.assertNotIn(self.fixture.key.hex(), repr(self.fixture.config))
        self.assertNotIn(self.fixture.key.hex(), repr(self.fixture.adapter))
        self.assertNotIn(self.fixture.key.hex(), repr(self.fixture.queue_config))
        result = BatchVerifierResult(
            True,
            True,
            self.fixture.batch.proof_context,
            self.fixture.batch.public_coin,
            self.fixture.batch.batch_root,
            self.fixture.queue_config.source_auth_profile,
            self.fixture.queue_config.source_key_epoch,
            "accepted",
            self.fixture.queue_config.qualification_flags,
        )
        self.assertNotIn(self.fixture.key.hex(), repr(result))
        self.assertNotIn(self.fixture.key.hex(), str(result.as_json))

    def test_queue_projection_does_not_persist_key_capsule_or_ipc(self) -> None:
        database = self.fixture.root / "state.sqlite"
        owner = _QueueRuntimeOwnership(
            lock_path=database.with_name(database.name + ".runtime-lock"),
            parent=self.fixture.root,
        )
        store = _VerificationQueueStore(
            path=database,
            config=self.fixture.queue_config,
            owner=owner,
            clock=type("_Clock", (), {"now_ms": lambda _self: 1_700_000_000_001})(),
        )
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
            expected_input_bytes: int,
        ) -> ContainedVerifierResult:
            del (
                workspace,
                timeout_seconds,
                expected_executable_size_bytes,
                expected_executable_sha256,
                expected_input_bytes,
            )
            captured["ipc"] = bytes(ipc)
            return _contained()

        try:
            batch = store.issue_batch(template=self.fixture.batch.template)
            store.submit_batch_handoff(
                issued_batch=batch,
                proof_stream=VolatileProofHandoff(bytearray(self.fixture.capsule)),
            )
            with patch.object(
                source_auth_adapter,
                "run_contained_verifier_stream",
                side_effect=runner,
            ):
                self.assertEqual(
                    store._process_one_batch(
                        verifier=self.fixture.adapter,
                        state_disposition_port=_StateDispositionPort(),
                    ).status,
                    "VERIFIED",
                )
            store._verify_integrity()
            durable = database.read_bytes()
            self.assertNotIn(self.fixture.key, durable)
            self.assertNotIn(self.fixture.capsule, durable)
            self.assertNotIn(captured["ipc"], durable)
            self.assertNotIn(self.fixture.batch.proof_context, durable)
        finally:
            store._close()
            owner.close()


if __name__ == "__main__":
    unittest.main()
