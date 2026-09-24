import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import parked.private_zk.app.minimal_clearance_composition as composition
import parked.private_zk.app.minimal_clearance_verification_queue as queue_module
from parked.private_zk.app.minimal_clearance_composition import CompositionConfigV2, StateDispositionControl
from parked.private_zk.app.minimal_clearance_verification_queue import (
    BatchVerifierResult,
    LEAN_ADMISSION_INPUT_BYTES,
    LeanAdmissionError,
    LeanAdmissionKernel,
    OperationTemplate,
    PROOF_ATTEMPTS_CAP,
    QueueConfig,
    QueueHeldError,
    SOURCE_ADMISSION_RETRY_LIMIT,
    SourceLaunchAuthorization,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
    _compute_batch_root_from_refs,
    _profile12_context,
    source_configuration_digest,
)
from parked.private_zk.app.minimal_clearance_verification_queue_independent import verify_database
from parked.private_zk.tools.direct_mask_complete_path.source_boundary import (
    SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
    build_source_request,
    source_request_digest,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000_000

    def now_ms(self) -> int:
        return self.now


def _batch(store: _VerificationQueueStore, config: QueueConfig, clock: _Clock):
    template = OperationTemplate(
        "lean-admission-integration",
        1,
        config.profile_version,
        clock.now - 100,
        clock.now + 60_000,
    )
    return store.issue_batch(template=template)


def _source_args(batch: object) -> dict[str, object]:
    request = build_source_request(batch=batch, source_key_epoch=1)  # type: ignore[arg-type]
    try:
        digest = source_request_digest(request)
    finally:
        for index in range(len(request)):
            request[index] = 0
        request.clear()
    return {
        "request_digest": digest,
        "retry_limit": SOURCE_ADMISSION_RETRY_LIMIT,
        "source_configuration_digest": source_configuration_digest(
            identity_profile="accepted",
            executable_size_bytes=SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
            executable_sha256=SOURCE_APPLIANCE_EXECUTABLE_SHA256,
            retry_limit=SOURCE_ADMISSION_RETRY_LIMIT,
        ),
        "source_identity_profile": "accepted",
        "source_executable_size_bytes": SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
        "source_executable_sha256": SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    }


def _controls(operation_refs: tuple[bytes, ...]) -> dict[bytes, StateDispositionControl]:
    profile = bytes([9]) * 64
    state_id = bytes(64)
    state_bytes = bytes(64)
    continuity = bytes(64)
    audit = bytes(64)
    clearance = bytes(64)
    marker = 0
    count = 0
    result: dict[bytes, StateDispositionControl] = {}
    for index, operation_ref in enumerate(operation_refs):
        policy = ("PASS", "MISSING", "AMBIGUOUS", "FAIL", "FAIL")[index % 5]
        exception = policy == "FAIL" and index % 5 == 4
        control = StateDispositionControl(
            operation_ref,
            policy,
            exception,
            bytes([index + 1]) * 64 if exception else bytes(64),
            profile,
            state_id,
            state_bytes,
            1,
            index,
            continuity,
            audit,
            clearance,
            marker,
            count,
        )
        result[operation_ref] = control
        state_id = control.state_after_id
        state_bytes = control.state_after_bytes
        continuity = control.state_after_continuity_root
        clearance = control.state_after_clearance_root
        audit = composition._sha(composition._STATE, audit, control.decision_id, control.effective_directive.encode("ascii"))
        marker = int(bool(marker or control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"}))
        count += int(control.effective_directive in {"CLEAR", "EXCEPTION_APPROVED"})
    return result


class _FailingKernel:
    def decide(self, *_args: object, **_kwargs: object) -> object:
        raise LeanAdmissionError("lean_admission_unavailable")


class LeanAdmissionIntegrationTests(unittest.TestCase):
    def test_compiled_kernel_drives_issue_source_and_verifier_reservations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lean-admission-integration-") as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("lean-admission-integration", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
            owner = _QueueRuntimeOwnership(
                lock_path=root / "state.sqlite.runtime-lock", parent=root
            )
            kernel = LeanAdmissionKernel()
            store = _VerificationQueueStore(
                path=root / "state.sqlite",
                config=config,
                owner=owner,
                clock=clock,
                composition_config=composition_config,
                admission_kernel=kernel,
            )
            try:
                batch = _batch(store, config, clock)
                admission = store.admit_source_launch(batch=batch, **_source_args(batch))
                authorization = store.start_source_launch(admission=admission)
                self.assertIsInstance(authorization, SourceLaunchAuthorization)
                ownership = authorization.consume()
                store.finish_source_launch(
                    authorization=authorization,
                    ownership=ownership,
                    success=True,
                )
                store.submit_batch_handoff(
                    issued_batch=batch,
                    proof_stream=VolatileProofHandoff(bytearray(b"lean-proof")),
                )
                work = store._claim_next_batch()
                self.assertIsNotNone(work)
                store._reserve_verifier_launch(work)
                self.assertEqual(kernel.calls, 5)
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT source_a_used,source_s_used,source_m_used,source_u_used,verifier_v_used FROM queue_metadata"
                        ).fetchone(),
                        (1, 4_096, 100, 1, 1),
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT source_status FROM queue_source_admissions WHERE batch_id=?",
                            (batch.batch_id,),
                        ).fetchone()[0],
                        "COMPLETED",
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT verifier_status FROM queue_attempts WHERE batch_id=?",
                            (batch.batch_id,),
                        ).fetchone()[0],
                        "STARTED",
                    )
                verified = verify_database(root / "state.sqlite", expected_config=config.as_json)
                self.assertEqual(
                    verified["source_accounting"],
                    {"a_used": 1, "s_used": 4_096, "m_used": 100, "u_used": 1, "v_used": 1},
                )
                self.assertIsNotNone(kernel.last_decision)
                assert kernel.last_decision is not None
                print(
                    "LEAN_ADMISSION_INTEGRATION "
                    + json.dumps(
                        {
                            "kernel_calls": kernel.calls,
                            "input_bytes": LEAN_ADMISSION_INPUT_BYTES,
                            "artifact_sha256": kernel.last_decision.artifact_sha256.hex(),
                            "source_binding_sha256": kernel.last_decision.source_binding_sha256.hex(),
                            "source_accounting": verified["source_accounting"],
                            "source_status": "COMPLETED",
                            "verifier_status": "STARTED",
                        },
                        sort_keys=True,
                    )
                )
            finally:
                store._close()
                owner.close()

    def test_kernel_failure_blocks_source_admission_without_durable_reservation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lean-admission-failure-") as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("lean-admission-failure", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
            owner = _QueueRuntimeOwnership(
                lock_path=root / "state.sqlite.runtime-lock", parent=root
            )
            store = _VerificationQueueStore(
                path=root / "state.sqlite",
                config=config,
                owner=owner,
                clock=clock,
                composition_config=composition_config,
            )
            try:
                batch = _batch(store, config, clock)
                store._admission_kernel = _FailingKernel()
                before = verify_database(root / "state.sqlite", expected_config=config.as_json)
                with self.assertRaisesRegex(QueueHeldError, "lean_admission_unavailable"):
                    store.admit_source_launch(batch=batch, **_source_args(batch))
                after = verify_database(root / "state.sqlite", expected_config=config.as_json)
                self.assertEqual(after["source_accounting"], before["source_accounting"])
                self.assertEqual(after["source_admission_count"], 0)
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM queue_source_admissions"
                        ).fetchone()[0],
                        0,
                    )
            finally:
                store._close()
                owner.close()

    def test_compiled_kernel_drives_terminal_finish_and_pre_verifier_recovery(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lean-admission-terminal-") as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("lean-admission-terminal", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
            owner = _QueueRuntimeOwnership(
                lock_path=root / "state.sqlite.runtime-lock", parent=root
            )
            kernel = LeanAdmissionKernel()
            store = _VerificationQueueStore(
                path=root / "state.sqlite",
                config=config,
                owner=owner,
                clock=clock,
                composition_config=composition_config,
                admission_kernel=kernel,
            )
            try:
                rejected_batch = _batch(store, config, clock)
                store.submit_batch_handoff(
                    issued_batch=rejected_batch,
                    proof_stream=VolatileProofHandoff(bytearray(b"reject-proof")),
                )
                rejected_work = store._claim_next_batch()
                self.assertIsNotNone(rejected_work)
                assert rejected_work is not None
                store._reserve_verifier_launch(rejected_work)
                rejected_verifier_result = BatchVerifierResult(
                    False,
                    False,
                    rejected_batch.proof_context,
                    rejected_batch.public_coin,
                    rejected_batch.batch_root,
                    config.source_auth_profile,
                    config.source_key_epoch,
                    "rejected",
                    config.qualification_flags,
                )
                rejected = store._complete_batch(
                    rejected_work,
                    status="REJECTED",
                    verifier_result=rejected_verifier_result,
                    error_code="proof_or_source_not_accepted",
                )
                self.assertEqual(rejected.status, "REJECTED")

                recovered_batch = _batch(store, config, clock)
                store.submit_batch_handoff(
                    issued_batch=recovered_batch,
                    proof_stream=VolatileProofHandoff(bytearray(b"recover-proof")),
                )
                recovered_work = store._claim_next_batch()
                self.assertIsNotNone(recovered_work)
                assert recovered_work is not None
                held = store._complete_batch(
                    recovered_work,
                    status="HELD",
                    error_code="fresh_handoff_required",
                )
                self.assertEqual(held.status, "HELD")
                self.assertEqual(kernel.calls, 5)
                self.assertIsNotNone(kernel.last_decision)
                assert kernel.last_decision is not None
                self.assertEqual(
                    (
                        kernel.last_decision.operation,
                        kernel.last_decision.batch_status,
                        kernel.last_decision.source_status,
                        kernel.last_decision.verifier_status,
                        kernel.last_decision.terminal_status,
                    ),
                    ("recover", "HELD", "ABSENT", "UNRESERVED", "ABORTED"),
                )
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT status FROM queue_batches ORDER BY admission_seq"
                        ).fetchall(),
                        [("REJECTED",), ("HELD",)],
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT status,verifier_status FROM queue_attempts ORDER BY attempt_id"
                        ).fetchall(),
                        [("REJECTED", "COMPLETED"), ("HELD", "UNRESERVED")],
                    )
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM queue_source_admissions").fetchone()[0],
                        0,
                    )
                verified = verify_database(root / "state.sqlite", expected_config=config.as_json)
                self.assertEqual(
                    verified["source_accounting"],
                    {"a_used": 0, "s_used": 0, "m_used": 0, "u_used": 2, "v_used": 1},
                )
            finally:
                store._close()
                owner.close()

    def test_compiled_kernel_covers_source_and_verifier_finish_boundaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lean-admission-finish-boundaries-") as directory:
            root = Path(directory)
            clock = _Clock()
            config = QueueConfig("lean-admission-finish-boundaries", 100)
            composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=100)
            owner = _QueueRuntimeOwnership(
                lock_path=root / "state.sqlite.runtime-lock", parent=root
            )
            kernel = LeanAdmissionKernel()
            store = _VerificationQueueStore(
                path=root / "state.sqlite",
                config=config,
                owner=owner,
                clock=clock,
                composition_config=composition_config,
                admission_kernel=kernel,
            )
            try:
                source_batch = _batch(store, config, clock)
                admission = store.admit_source_launch(batch=source_batch, **_source_args(source_batch))
                authorization = store.start_source_launch(admission=admission)
                ownership = authorization.consume()
                store.finish_source_launch(authorization=authorization, ownership=ownership, success=False)
                self.assertEqual(kernel.last_decision.operation, "source_finish_unknown")

                accepted_batch = _batch(store, config, clock)
                store.submit_batch_handoff(
                    issued_batch=accepted_batch,
                    proof_stream=VolatileProofHandoff(bytearray(b"accepted-proof")),
                )
                accepted_work = store._claim_next_batch()
                self.assertIsNotNone(accepted_work)
                assert accepted_work is not None
                store._reserve_verifier_launch(accepted_work)
                accepted_result = BatchVerifierResult(
                    True,
                    True,
                    accepted_batch.proof_context,
                    accepted_batch.public_coin,
                    accepted_batch.batch_root,
                    config.source_auth_profile,
                    config.source_key_epoch,
                    "accepted",
                    config.qualification_flags,
                )
                accepted = store._complete_batch(
                    accepted_work,
                    status="VERIFIED",
                    verifier_result=accepted_result,
                    state_controls=_controls(accepted_batch.operation_refs),
                )
                self.assertEqual(accepted.status, "VERIFIED")
                self.assertEqual(kernel.last_decision.operation, "verifier_finish_accepted")

                unknown_batch = _batch(store, config, clock)
                store.submit_batch_handoff(
                    issued_batch=unknown_batch,
                    proof_stream=VolatileProofHandoff(bytearray(b"unknown-proof")),
                )
                unknown_work = store._claim_next_batch()
                self.assertIsNotNone(unknown_work)
                assert unknown_work is not None
                store._reserve_verifier_launch(unknown_work)
                held = store._complete_batch(
                    unknown_work,
                    status="HELD",
                    error_code="fresh_handoff_required",
                )
                self.assertEqual(held.status, "HELD")
                self.assertEqual(kernel.last_decision.operation, "verifier_finish_unknown")
                verified = verify_database(root / "state.sqlite", expected_config=config.as_json)
                self.assertEqual(
                    verified["source_accounting"],
                    {"a_used": 1, "s_used": 4_096, "m_used": 100, "u_used": 3, "v_used": 2},
                )
            finally:
                store._close()
                owner.close()

    def test_native_boundary_null_initializer_cleanup_is_guarded(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "semantic_kernel" / "rust" / "native_boundary.c").read_text(encoding="utf-8")
        failure = source.index("g_runtime_state = -1;")
        guarded_cleanup = source.index("if (initialization != NULL)")
        self.assertLess(guarded_cleanup, failure)
        self.assertIn("lean_dec_ref(initialization);", source[guarded_cleanup:failure])

    def test_kernel_identity_pins_fail_closed_without_mutating_artifacts(self) -> None:
        with patch.dict(os.environ, {"BL_ADMISSION_KERNEL_EXE": "forbidden"}, clear=False):
            with self.assertRaisesRegex(LeanAdmissionError, "lean_admission_kernel_override"):
                LeanAdmissionKernel()
        with patch.object(queue_module, "LEAN_ADMISSION_ARTIFACT_SHA256", bytes(32)):
            with self.assertRaisesRegex(LeanAdmissionError, "lean_admission_artifact_binding"):
                LeanAdmissionKernel()
        with patch.object(queue_module, "LEAN_ADMISSION_SOURCE_BINDING_SHA256", bytes(32)):
            with self.assertRaisesRegex(LeanAdmissionError, "lean_admission_source_binding"):
                LeanAdmissionKernel()


if __name__ == "__main__":
    unittest.main()
