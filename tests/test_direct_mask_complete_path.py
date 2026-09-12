from __future__ import annotations

from contextlib import closing
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.minimal_clearance_composition as composition
import app.minimal_clearance_composition_independent as composition_independent
import app.minimal_clearance_source_auth_verifier_adapter as adapter_module
from app.minimal_clearance_composition import (
    CompositionConfigV2,
    StateDispositionControl,
)
from app.minimal_clearance_source_auth_verifier_adapter import (
    BatchVerifierResult,
)
from app.minimal_clearance_verification_queue import (
    IssuedVerificationBatch,
    OperationTemplate,
    QueueConflictError,
    QueueConfig,
    QueueHeldError,
    VolatileProofHandoff,
    _compute_batch_root_from_refs,
    _profile12_context,
)
from app.minimal_clearance_verification_runtime import (
    MinimalClearanceVerificationRuntime,
)
from tools.direct_mask_complete_path import source_boundary
from tools.direct_mask_complete_path.complete_path import (
    COMPLETE_VALID_FROM_MS,
    COMPLETE_VALID_UNTIL_MS,
    SOURCE_APPLIANCE_EXECUTABLE,
    SyntheticReceiver,
    SyntheticStateDispositionPort,
    build_complete_configs,
    run_one_fresh_native_proof,
)
from tools.direct_mask_complete_path.source_boundary import (
    Profile12SourceBoundaryCaller,
    SourceApplianceConfig,
    SourceBoundaryError,
    SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
)


class _StubVerifier:
    def __init__(self, config: QueueConfig, *, accepted: bool) -> None:
        self.config = config
        self.accepted = accepted
        self.calls = 0

    def verify(self, stream: VolatileProofHandoff, batch: IssuedVerificationBatch):
        self.calls += 1
        stream.drain()
        return BatchVerifierResult(
            self.accepted,
            self.accepted,
            batch.proof_context,
            batch.public_coin,
            batch.batch_root,
            self.config.source_auth_profile,
            self.config.source_key_epoch,
            "accepted" if self.accepted else "rejected",
            self.config.qualification_flags,
        )


def _template(config: QueueConfig, now: int) -> OperationTemplate:
    return OperationTemplate(
        "e2e-negative-assertion",
        1,
        config.profile_version,
        now - 100,
        now + 60_000,
    )


def _copy_batch(
    batch: IssuedVerificationBatch,
    **changes: object,
) -> IssuedVerificationBatch:
    result = object.__new__(IssuedVerificationBatch)
    fields = (
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
    for field in fields:
        object.__setattr__(result, field, changes.get(field, getattr(batch, field)))
    return result


def _public_batch(config: QueueConfig) -> IssuedVerificationBatch:
    template = OperationTemplate(
        "e2e-source-binding",
        1,
        config.profile_version,
        COMPLETE_VALID_FROM_MS,
        COMPLETE_VALID_UNTIL_MS,
    )
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


def _new_runtime(
    root: Path,
    config: QueueConfig,
    composition_config: CompositionConfigV2,
    verifier: object,
    state_port: SyntheticStateDispositionPort | None,
    *,
    receiver: SyntheticReceiver | None = None,
    clock: object | None = None,
) -> MinimalClearanceVerificationRuntime:
    kwargs: dict[str, object] = {
        "root": root,
        "verifier": verifier,
        "config": config,
        "state_disposition_port": state_port,
        "composition_config": composition_config,
    }
    if receiver is not None:
        kwargs["receiver"] = receiver
        kwargs["lookup"] = receiver
    if clock is not None:
        kwargs["clock"] = clock
    return MinimalClearanceVerificationRuntime(**kwargs)  # type: ignore[arg-type]


class DirectMaskCompletePathTests(unittest.TestCase):
    def test_one_fresh_native_proof_runs_source_verifier_state_outbox_ack_and_reopen(
        self,
    ) -> None:
        configured_root = os.environ.get("DIRECT_MASK_COMPLETE_BUILD_ROOT")
        build_root = (
            Path(configured_root)
            if configured_root
            else Path(__file__).resolve().parents[1] / "build-complete-path"
        )
        build_root.mkdir(parents=True, exist_ok=True)
        evidence = run_one_fresh_native_proof(build_root=build_root.resolve())
        self.assertEqual(
            (
                evidence.operation_count,
                evidence.issued_batch_count,
                evidence.acknowledged_operation_count,
                evidence.unconfirmed_operation_count,
                evidence.transaction_count,
                evidence.outbox_acknowledged_count,
                evidence.state_sequence,
                evidence.independent_verified_batch_count,
                evidence.independent_operation_count,
                evidence.independent_transaction_count,
                evidence.independent_outbox_count,
                evidence.unique_idempotency_keys,
                evidence.receiver_side_effects,
                evidence.receiver_duplicate_dispatches,
                evidence.source_workspace_empty,
                evidence.verifier_workspace_empty,
                evidence.reopened_without_work,
                evidence.proof_files_persisted,
                evidence.proof_suite_id,
                evidence.production_usable,
                evidence.activation,
            ),
            (100, 1, 100, 0, 100, 100, 100, 1, 100, 100, 100, 100, 100, 0, True, True, True, False, None, False, False),
        )
        self.assertEqual(evidence.source_measurement.exit_code, 0)
        self.assertEqual(evidence.source_measurement.stdout_bytes, 539_013)
        self.assertEqual(evidence.source_measurement.stderr_bytes, 0)
        self.assertEqual(evidence.verifier_measurement.exit_code, 0)
        self.assertEqual(evidence.verifier_measurement.stdout_bytes, 0)
        self.assertEqual(evidence.verifier_measurement.stderr_bytes, 0)
        print("COMPLETE_PATH_EVIDENCE " + json.dumps(evidence.as_json(), sort_keys=True))

    def test_source_context_coin_order_and_epoch_mutations_fail_before_native(self) -> None:
        config = QueueConfig("e2e-source-negative", 100, source_key_epoch=1)
        batch = _public_batch(config)
        with tempfile.TemporaryDirectory(prefix="complete-path-source-negative-") as directory:
            workspace = Path(directory) / "source-workspace"
            workspace.mkdir()
            caller = Profile12SourceBoundaryCaller(
                SourceApplianceConfig(
                    executable_path=SOURCE_APPLIANCE_EXECUTABLE,
                    workspace=workspace,
                    executable_size_bytes=SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
                    executable_sha256=SOURCE_APPLIANCE_EXECUTABLE_SHA256,
                    timeout_seconds=180.0,
                )
            )
            with patch.object(
                source_boundary,
                "run_contained_verifier_stream",
                side_effect=AssertionError("native source call was not allowed"),
            ) as native:
                for name, mutated in (
                    (
                        "context",
                        _copy_batch(
                            batch,
                            proof_context=b"x" + batch.proof_context[1:],
                        ),
                    ),
                    (
                        "coin",
                        _copy_batch(
                            batch,
                            public_coin=b"\x02" + batch.public_coin[1:],
                        ),
                    ),
                    (
                        "order",
                        _copy_batch(
                            batch,
                            operation_refs=(batch.operation_refs[1], batch.operation_refs[0], *batch.operation_refs[2:]),
                        ),
                    ),
                ):
                    with self.subTest(name=name), self.assertRaisesRegex(
                        SourceBoundaryError,
                        "source_batch_binding",
                    ):
                        caller.prove_one(batch=mutated, source_key_epoch=1)
                with self.assertRaisesRegex(SourceBoundaryError, "source_key_epoch"):
                    caller.prove_one(batch=batch, source_key_epoch=2)
                native.assert_not_called()

    def test_consumed_and_replayed_handoffs_are_rejected(self) -> None:
        config, composition_config = build_complete_configs(
            "e2e-handoff-negative"
        )
        with tempfile.TemporaryDirectory(prefix="complete-path-handoff-consumed-") as directory:
            root = Path(directory)
            clock = type("Clock", (), {"now_ms": lambda self: 7_000})()
            verifier = _StubVerifier(config, accepted=True)
            state_port = SyntheticStateDispositionPort()
            runtime = _new_runtime(
                root,
                config,
                composition_config,
                verifier,
                state_port,
                clock=clock,
            )
            try:
                batch = runtime.issue_batch(template=_template(config, 7_000))
                consumed = VolatileProofHandoff(bytearray(b"consumed"))
                self.assertEqual(consumed.read(1), b"c")
                with self.assertRaisesRegex(QueueHeldError, "proof_handoff_used"):
                    runtime.submit_batch_handoff(
                        issued_batch=batch,
                        proof_stream=consumed,
                    )
                self.assertTrue(consumed.closed)
                self.assertEqual(
                    runtime.support_summary()["counts"]["AWAITING_HANDOFF"],
                    1,
                )
            finally:
                runtime.close()

        with tempfile.TemporaryDirectory(prefix="complete-path-handoff-replay-") as directory:
            root = Path(directory)
            clock = type("Clock", (), {"now_ms": lambda self: 7_000})()
            verifier = _StubVerifier(config, accepted=True)
            state_port = SyntheticStateDispositionPort()
            runtime = _new_runtime(
                root,
                config,
                composition_config,
                verifier,
                state_port,
                clock=clock,
            )
            try:
                batch = runtime.issue_batch(template=_template(config, 7_000))
                runtime.submit_batch_handoff(
                    issued_batch=batch,
                    proof_stream=VolatileProofHandoff(bytearray(b"first")),
                )
                replay = VolatileProofHandoff(bytearray(b"replay"))
                with self.assertRaisesRegex(
                    QueueConflictError,
                    "fresh_handoff_required",
                ):
                    runtime.submit_batch_handoff(
                        issued_batch=batch,
                        proof_stream=replay,
                    )
                self.assertEqual(runtime.support_summary()["counts"]["HELD"], 1)
                self.assertTrue(replay.closed)
            finally:
                runtime.close()

    def test_rejected_verifier_cannot_mutate_state(self) -> None:
        config, composition_config = build_complete_configs(
            "e2e-reject-negative"
        )
        with tempfile.TemporaryDirectory(prefix="complete-path-reject-") as directory:
            root = Path(directory)
            clock = type("Clock", (), {"now_ms": lambda self: 7_000})()
            verifier = _StubVerifier(config, accepted=False)
            state_port = SyntheticStateDispositionPort()
            runtime = _new_runtime(
                root,
                config,
                composition_config,
                verifier,
                state_port,
                clock=clock,
            )
            try:
                batch = runtime.issue_batch(template=_template(config, 7_000))
                runtime.submit_batch_handoff(
                    issued_batch=batch,
                    proof_stream=VolatileProofHandoff(bytearray(b"rejected")),
                )
                result = runtime.run(max_batches=1)
                summary = runtime.support_summary()
                self.assertEqual(
                    (
                        result.outcome,
                        result.accepted_operation_count,
                        result.verified_batch_count,
                        result.rejected_batch_count,
                        result.held_batch_count,
                        verifier.calls,
                        state_port.calls,
                        summary["counts"]["REJECTED"],
                        summary["outbox_counts"],
                    ),
                    (
                        "PROCESSED",
                        0,
                        0,
                        1,
                        0,
                        1,
                        0,
                        1,
                        {"READY": 0, "LEASED": 0, "ACKNOWLEDGED": 0, "DELIVERY_UNCONFIRMED": 0},
                    ),
                )
                with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM composition_transactions"
                        ).fetchone()[0],
                        0,
                    )
            finally:
                runtime.close()

    def test_receiver_failure_restart_and_reconciliation_do_not_duplicate_rows_or_acks(
        self,
    ) -> None:
        config, composition_config = build_complete_configs(
            "e2e-restart-negative"
        )
        with tempfile.TemporaryDirectory(prefix="complete-path-restart-") as directory:
            root = Path(directory)
            clock = type("Clock", (), {"now_ms": lambda self: 7_000})()
            receiver = SyntheticReceiver(
                composition_config,
                clock,  # type: ignore[arg-type]
                fail_after_persist=True,
            )
            first_state_port = SyntheticStateDispositionPort()
            first = _new_runtime(
                root,
                config,
                composition_config,
                _StubVerifier(config, accepted=True),
                first_state_port,
                receiver=receiver,
                clock=clock,
            )
            try:
                batch = first.issue_batch(template=_template(config, 7_000))
                first.submit_batch_handoff(
                    issued_batch=batch,
                    proof_stream=VolatileProofHandoff(bytearray(b"accepted")),
                )
                self.assertEqual(first.run(max_batches=1).accepted_operation_count, 100)
                failed_delivery = first.dispatch_outbox(max_batches=1)
                self.assertEqual(
                    (
                        failed_delivery.attempted_operation_count,
                        failed_delivery.acknowledged_operation_count,
                        failed_delivery.unconfirmed_operation_count,
                        receiver.dispatch_calls,
                        receiver.side_effects,
                        len(receiver.acks),
                    ),
                    (100, 0, 100, 100, 100, 100),
                )
            finally:
                first.close()

            second = _new_runtime(
                root,
                config,
                composition_config,
                _StubVerifier(config, accepted=True),
                SyntheticStateDispositionPort(),
                receiver=receiver,
                clock=clock,
            )
            try:
                reconciled = second.reconcile_outbox(max_batches=1)
                empty_run = second.run(max_batches=1)
                empty_delivery = second.dispatch_outbox(max_batches=1)
                summary = second.support_summary()
                self.assertEqual(
                    (
                        reconciled.attempted_operation_count,
                        reconciled.acknowledged_operation_count,
                        reconciled.unconfirmed_operation_count,
                        receiver.dispatch_calls,
                        receiver.lookup_calls,
                        receiver.side_effects,
                        receiver.duplicate_dispatches,
                        empty_run.outcome,
                        empty_delivery.outcome,
                        summary["outbox_counts"],
                    ),
                    (
                        100,
                        100,
                        0,
                        100,
                        100,
                        100,
                        0,
                        "EMPTY",
                        "EMPTY",
                        {"READY": 0, "LEASED": 0, "ACKNOWLEDGED": 100, "DELIVERY_UNCONFIRMED": 0},
                    ),
                )
            finally:
                second.close()

            with closing(sqlite3.connect(str(root / "state.sqlite"))) as connection:
                transaction_count, transaction_unique = connection.execute(
                    "SELECT COUNT(*),COUNT(DISTINCT operation_ref) FROM composition_transactions"
                ).fetchone()
                outbox_count, outbox_unique = connection.execute(
                    "SELECT COUNT(*),COUNT(DISTINCT operation_ref) FROM composition_outbox"
                ).fetchone()
            self.assertEqual(
                (transaction_count, transaction_unique, outbox_count, outbox_unique),
                (100, 100, 100, 100),
            )
            independent = composition_independent.verify_database(
                root / "state.sqlite",
                expected_config=composition_config.as_json,
            )
            self.assertEqual(sum(independent["transaction_counts"].values()), 100)
            self.assertEqual(independent["outbox_count"], 100)


if __name__ == "__main__":
    unittest.main()
