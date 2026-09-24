from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from parked.private_zk.app.minimal_clearance_composition import CompositionConfigV2
import parked.private_zk.app.minimal_clearance_lifecycle_adapter as lifecycle_adapter
from parked.private_zk.app.minimal_clearance_lifecycle_adapter import (
    LifecycleAdapterError,
    LifecycleEvent,
    _decode_response,
    _encode_request,
    _run_lifecycle_frame,
    canonical_queue_event_bytes,
    evaluate_lifecycle_transition,
    reconstruct_lifecycle_state,
)
import parked.private_zk.app.minimal_clearance_verification_queue as queue_module
from parked.private_zk.app.minimal_clearance_verification_queue import (
    OperationTemplate,
    QueueConfig,
    VolatileProofHandoff,
    _RUNTIME_WORKER,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)
from parked.private_zk.app.minimal_clearance_verification_queue_independent import verify_database


class _Clock:
    def __init__(self, now: int = 1_700_000_000_000) -> None:
        self.now = now

    def now_ms(self) -> int:
        return self.now


class LifecycleAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = _Clock()
        self.config = QueueConfig("lifecycle-adapter-test", 200)
        self.composition_config = CompositionConfigV2(
            self.config.queue_id,
            self.config.digest,
            capacity=self.config.capacity,
        )
        self.owner = _QueueRuntimeOwnership(
            lock_path=self.root / "state.sqlite.runtime-lock",
            parent=self.root,
        )
        self.store = _VerificationQueueStore(
            path=self.root / "state.sqlite",
            config=self.config,
            owner=self.owner,
            clock=self.clock,
            composition_config=self.composition_config,
        )
        self.workspace = self.root / "lifecycle-adapter-workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self.store._close()
        self.owner.close()
        self.temp.cleanup()

    def _executable(self) -> Path:
        executable = lifecycle_adapter._LIFECYCLE_EXECUTABLE_PATH
        self.assertTrue(executable.is_absolute() and executable.is_file())
        return executable

    def _issue(self, *, duration: int = 60_000):
        template = OperationTemplate(
            "lifecycle-assertion",
            1,
            self.config.profile_version,
            self.clock.now - 100,
            self.clock.now + duration,
        )
        return self.store.issue_batch(template=template)

    def _submit_event(self, before, now: int) -> LifecycleEvent:
        return LifecycleEvent(
            schema_version=before.config.schema_version,
            sequence=before.transition_sequence + 1,
            kind="handoffSubmitted",
            batch_id=before.identity.batch_id,
            status="queued",
            error_code=None,
            attempt=0,
            at_ms=now,
            member_count=100,
        )

    def _claim_event(self, before, now: int) -> LifecycleEvent:
        return LifecycleEvent(
            schema_version=before.config.schema_version,
            sequence=before.transition_sequence + 1,
            kind="verificationStarted",
            batch_id=before.identity.batch_id,
            status="leased",
            error_code=None,
            attempt=1,
            at_ms=now,
            member_count=100,
            reservation_before=before.reservation_before,
            reservation_after=before.reservation_after,
        )

    def _submit_after(self, before, now: int):
        return replace(
            before,
            batch="queued",
            next_eligible_ms=now,
            updated_ms=now,
            transition_sequence=before.transition_sequence + 1,
            handoff_attached=True,
        )

    def _claim_after(self, before, now: int):
        next_sequence = before.transition_sequence + 1
        return replace(
            before,
            batch="leased",
            updated_ms=now,
            attempt=1,
            global_live_lease_count=1,
            live_lease_count=1,
            lease_expires_ms=now + before.config.lease_duration_ms,
            claim_sequence=next_sequence,
            transition_sequence=next_sequence,
        )

    def _host_event_bytes(self, event: LifecycleEvent) -> bytes:
        kind = {
            "batchIssued": "BATCH_ISSUED",
            "handoffSubmitted": "HANDOFF_SUBMITTED",
            "verificationStarted": "VERIFICATION_STARTED",
        }[event.kind]
        status = {
            "awaitingHandoff": "AWAITING_HANDOFF",
            "queued": "QUEUED",
            "leased": "LEASED",
            "held": "HELD",
        }[event.status]
        self.assertEqual(event.schema_version, queue_module.SCHEMA_VERSION)
        value = {
            "schema": queue_module._SCHEMA,
            "sequence": event.sequence,
            "kind": kind,
            "batch_id": event.batch_id.hex().upper(),
            "status": status,
            "error_code": event.error_code,
            "attempt": event.attempt,
            "at_ms": event.at_ms,
            "member_count": event.member_count,
        }
        if event.receipt_id is not None:
            value["receipt_id"] = event.receipt_id.hex().upper()
        if event.identity_digest is not None:
            value["identity_digest"] = event.identity_digest.hex().upper()
        if event.reservation_before is not None:
            value["reservation_before"] = event.reservation_before
        if event.reservation_after is not None:
            value["reservation_after"] = event.reservation_after
        raw = queue_module._json_bytes(value)
        self.assertEqual(canonical_queue_event_bytes(event), raw)
        return raw

    def _begin_readonly_probe(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[int, tuple[tuple[int], ...], tuple[object, ...]]:
        connection.execute("CREATE TEMP TABLE lifecycle_pending(value INTEGER NOT NULL)")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO lifecycle_pending VALUES (7)")
        pragmas = self._pragma_state(connection)
        return (
            connection.total_changes,
            tuple(connection.execute("SELECT value FROM lifecycle_pending")),
            pragmas,
        )

    def _pragma_state(self, connection: sqlite3.Connection) -> tuple[object, ...]:
        return (
            connection.execute("PRAGMA foreign_keys").fetchone()[0],
            connection.execute("PRAGMA page_size").fetchone()[0],
            connection.execute("PRAGMA max_page_count").fetchone()[0],
            connection.execute("PRAGMA journal_mode").fetchone()[0],
            connection.execute("PRAGMA synchronous").fetchone()[0],
        )

    def _assert_readonly_probe(
        self,
        connection: sqlite3.Connection,
        baseline: tuple[int, tuple[tuple[int], ...], tuple[object, ...]],
    ) -> None:
        self.assertTrue(connection.in_transaction)
        self.assertEqual(connection.total_changes, baseline[0])
        self.assertEqual(tuple(connection.execute("SELECT value FROM lifecycle_pending")), baseline[1])
        self.assertEqual(self._pragma_state(connection), baseline[2])

    def test_caller_cannot_supply_executable_path_or_pin(self) -> None:
        self.assertEqual(lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES, 6_571_008)
        self.assertEqual(
            lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256.hex().upper(),
            "B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881",
        )
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_event = self._submit_event(before, now)
            with self.assertRaises(TypeError):
                evaluate_lifecycle_transition(
                    connection,
                    batch_id=batch.batch_id,
                    operation="submitHandoff",
                    now_ms=now,
                    handoff_attached=False,
                    executable=self._executable(),
                    expected_executable_size_bytes=6_571_008,
                    expected_executable_sha256=bytes.fromhex(
                        "B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881"
                    ),
                    workspace=self.workspace,
                    expected_config=self.config.as_json,
                )
            self._assert_readonly_probe(connection, baseline)

    def test_lifecycle_provenance_protocol_rejects_unreviewed_or_mismatched_identity(self) -> None:
        manifest_sha256 = "a" * 64
        executable_sha256 = lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256.hex()

        def line(
            *,
            version: str = "1",
            manifest: str = manifest_sha256,
            size: int = lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES,
            executable: str = executable_sha256,
        ) -> bytes:
            return (
                f"BL-LIFECYCLE-PROVENANCE/{version};manifest_sha256={manifest};"
                f"exe_size={size};exe_sha256={executable}\n"
            ).encode("ascii")

        valid = line()
        with patch.object(
            lifecycle_adapter,
            "_LIFECYCLE_SOURCE_MANIFEST_SHA256",
            manifest_sha256,
        ):
            lifecycle_adapter._verify_lifecycle_provenance(valid)
            rejected = (
                (b"", "lifecycle_provenance_protocol"),
                (line(version="2"), "lifecycle_provenance_protocol"),
                (valid[:-1], "lifecycle_provenance_protocol"),
                (valid + b"\n", "lifecycle_provenance_protocol"),
                (valid + valid, "lifecycle_provenance_protocol"),
                (line(manifest="A" * 64), "lifecycle_provenance_protocol"),
                (line(manifest="b" * 64), "lifecycle_provenance_manifest"),
                (line(size=lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES + 1), "lifecycle_provenance_executable"),
                (line(executable="0" * 64), "lifecycle_provenance_executable"),
            )
            for provenance, error in rejected:
                with self.subTest(provenance=provenance[:48], error=error):
                    with self.assertRaisesRegex(LifecycleAdapterError, error):
                        lifecycle_adapter._verify_lifecycle_provenance(provenance)

        with self.assertRaisesRegex(
            LifecycleAdapterError,
            "lifecycle_provenance_unreviewed",
        ):
            lifecycle_adapter._verify_lifecycle_provenance(valid)

    def test_legacy_mode_is_exactly_pinned_and_source_mode_never_falls_back(self) -> None:
        self.assertEqual(lifecycle_adapter._LIFECYCLE_RUNTIME_MODE, "legacy-pinned-v2")
        self.assertEqual(
            lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256,
            lifecycle_adapter._LIFECYCLE_LEGACY_EXECUTABLE_SHA256,
        )
        self.assertEqual(
            lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES,
            lifecycle_adapter._LIFECYCLE_LEGACY_EXECUTABLE_SIZE_BYTES,
        )

        def contained_result(stderr: bytes):
            def run(executable, arguments, frame, **kwargs):
                self.assertEqual(executable, lifecycle_adapter._LIFECYCLE_EXECUTABLE_PATH)
                self.assertEqual(arguments, ())
                self.assertEqual(kwargs["expected_executable_size_bytes"], 6_571_008)
                self.assertEqual(
                    kwargs["expected_executable_sha256"],
                    bytes.fromhex("B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881"),
                )
                return SimpleNamespace(
                    exit_code=0,
                    timed_out=False,
                    cap_enforced=True,
                    active_process_limit=1,
                    stdout=b"legacy response",
                    stderr=stderr,
                )

            return run

        with patch.object(
            lifecycle_adapter,
            "run_contained_verifier_stream",
            side_effect=contained_result(b""),
        ):
            self.assertEqual(
                _run_lifecycle_frame(
                    b"request",
                    workspace=self.workspace,
                    timeout_seconds=3.0,
                ),
                b"legacy response",
            )

        provenance = (
            "BL-LIFECYCLE-PROVENANCE/1;"
            f"manifest_sha256={'a' * 64};"
            "exe_size=6571008;"
            f"exe_sha256={lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256.hex()}\n"
        ).encode("ascii")
        with patch.object(
            lifecycle_adapter,
            "run_contained_verifier_stream",
            side_effect=contained_result(provenance),
        ):
            with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_legacy_stderr"):
                _run_lifecycle_frame(
                    b"request",
                    workspace=self.workspace,
                    timeout_seconds=3.0,
                )

        with (
            patch.object(lifecycle_adapter, "_LIFECYCLE_RUNTIME_MODE", "source-bound-v1"),
            patch.object(
                lifecycle_adapter,
                "run_contained_verifier_stream",
                side_effect=contained_result(b""),
            ),
        ):
            with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_provenance_protocol"):
                _run_lifecycle_frame(
                    b"request",
                    workspace=self.workspace,
                    timeout_seconds=3.0,
                )

    def test_source_bound_mode_returns_response_only_after_reviewed_same_invocation_report(self) -> None:
        manifest_sha256 = "a" * 64
        provenance = (
            "BL-LIFECYCLE-PROVENANCE/1;"
            f"manifest_sha256={manifest_sha256};"
            f"exe_size={lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES};"
            f"exe_sha256={lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256.hex()}\n"
        ).encode("ascii")
        result = SimpleNamespace(
            exit_code=0,
            timed_out=False,
            cap_enforced=True,
            active_process_limit=1,
            stdout=b"source-bound response",
            stderr=provenance,
        )

        with (
            patch.object(lifecycle_adapter, "_LIFECYCLE_RUNTIME_MODE", "source-bound-v1"),
            patch.object(lifecycle_adapter, "_LIFECYCLE_SOURCE_MANIFEST_SHA256", manifest_sha256),
            patch.object(
                lifecycle_adapter,
                "run_contained_verifier_stream",
                return_value=result,
            ) as runner,
        ):
            self.assertEqual(
                _run_lifecycle_frame(
                    b"request",
                    workspace=self.workspace,
                    timeout_seconds=3.0,
                ),
                b"source-bound response",
            )

        self.assertEqual(runner.call_count, 1)
        arguments, keyword_arguments = runner.call_args
        self.assertEqual(
            arguments,
            (lifecycle_adapter._LIFECYCLE_EXECUTABLE_PATH, (), b"request"),
        )
        self.assertEqual(
            keyword_arguments["expected_executable_size_bytes"],
            lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES,
        )
        self.assertEqual(
            keyword_arguments["expected_executable_sha256"],
            lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256,
        )

    def test_unreviewed_lifecycle_provenance_fails_before_response_decode_without_mutation(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            provenance = (
                "BL-LIFECYCLE-PROVENANCE/1;"
                f"manifest_sha256={'a' * 64};"
                f"exe_size={lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES};"
                f"exe_sha256={lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256.hex()}\n"
            ).encode("ascii")

            def contained_success(executable, arguments, frame, **kwargs):
                self.assertEqual(executable, lifecycle_adapter._LIFECYCLE_EXECUTABLE_PATH)
                self.assertEqual(arguments, ())
                self.assertEqual(kwargs["expected_executable_size_bytes"], lifecycle_adapter._LIFECYCLE_EXECUTABLE_SIZE_BYTES)
                self.assertEqual(kwargs["expected_executable_sha256"], lifecycle_adapter._LIFECYCLE_EXECUTABLE_SHA256)
                self.assertEqual(kwargs["expected_input_bytes"], len(frame))
                return SimpleNamespace(
                    exit_code=0,
                    timed_out=False,
                    cap_enforced=True,
                    active_process_limit=1,
                    stdout=b"malformed response is never decoded",
                    stderr=provenance,
                )

            with (
                patch.object(lifecycle_adapter, "_LIFECYCLE_RUNTIME_MODE", "source-bound-v1"),
                patch.object(
                    lifecycle_adapter,
                    "run_contained_verifier_stream",
                    side_effect=contained_success,
                ) as runner,
            ):
                with self.assertRaisesRegex(
                    LifecycleAdapterError,
                    "lifecycle_provenance_unreviewed",
                ):
                    evaluate_lifecycle_transition(
                        connection,
                        batch_id=batch.batch_id,
                        operation="submitHandoff",
                        now_ms=self.clock.now,
                        handoff_attached=False,
                        workspace=self.workspace,
                        expected_config=self.config.as_json,
                    )
            self.assertEqual(runner.call_count, 1)
            self._assert_readonly_probe(connection, baseline)

    def test_missing_executable_is_rejected_without_mutating_connection(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_event = self._submit_event(before, now)
            with patch.object(
                lifecycle_adapter,
                "_LIFECYCLE_EXECUTABLE_PATH",
                self.root / "missing-lifecycle.exe",
            ):
                with self.assertRaisesRegex(
                    LifecycleAdapterError,
                    "lifecycle_process:verifier_executable_open:2",
                ):
                    evaluate_lifecycle_transition(
                        connection,
                        batch_id=batch.batch_id,
                        operation="submitHandoff",
                        now_ms=now,
                        handoff_attached=False,
                        workspace=self.workspace,
                        expected_config=self.config.as_json,
                    )
            self._assert_readonly_probe(connection, baseline)

    def test_tampered_executable_is_rejected_without_mutating_connection(self) -> None:
        batch = self._issue()
        tampered = self.root / "lifecycle-tampered.exe"
        shutil.copyfile(self._executable(), tampered)
        with tampered.open("r+b") as stream:
            stream.seek(-1, 2)
            last_byte = stream.read(1)
            stream.seek(-1, 2)
            stream.write(bytes((last_byte[0] ^ 1,)))
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_event = self._submit_event(before, now)
            with patch.object(lifecycle_adapter, "_LIFECYCLE_EXECUTABLE_PATH", tampered):
                with self.assertRaisesRegex(
                    LifecycleAdapterError,
                    "verifier_executable_identity",
                ):
                    evaluate_lifecycle_transition(
                        connection,
                        batch_id=batch.batch_id,
                        operation="submitHandoff",
                        now_ms=now,
                        handoff_attached=False,
                        workspace=self.workspace,
                        expected_config=self.config.as_json,
                    )
            self._assert_readonly_probe(connection, baseline)

    def test_missing_or_mismatched_expected_config_is_rejected_without_mutation(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            with self.assertRaisesRegex(
                LifecycleAdapterError,
                "lifecycle_expected_config",
            ):
                reconstruct_lifecycle_state(
                    connection,
                    batch_id=batch.batch_id,
                    handoff_attached=False,
                )
            self._assert_readonly_probe(connection, baseline)

            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_event = self._submit_event(before, now)
            with self.assertRaisesRegex(
                LifecycleAdapterError,
                "lifecycle_expected_config",
            ):
                evaluate_lifecycle_transition(
                    connection,
                    batch_id=batch.batch_id,
                    operation="submitHandoff",
                    now_ms=now,
                    handoff_attached=False,
                    workspace=self.workspace,
                    expected_config=None,
                )
            self._assert_readonly_probe(connection, baseline)

            mismatched_config = dict(self.config.as_json)
            mismatched_config["queue_id"] = "different-lifecycle-queue"
            with self.assertRaisesRegex(LifecycleAdapterError, "config_binding"):
                evaluate_lifecycle_transition(
                    connection,
                    batch_id=batch.batch_id,
                    operation="submitHandoff",
                    now_ms=now,
                    handoff_attached=False,
                    workspace=self.workspace,
                    expected_config=mismatched_config,
                )
            self._assert_readonly_probe(connection, baseline)

    def test_timeout_above_queue_authority_is_rejected_without_mutating_connection(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_event = self._submit_event(before, now)
            with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_timeout"):
                evaluate_lifecycle_transition(
                    connection,
                    batch_id=batch.batch_id,
                    operation="submitHandoff",
                    now_ms=now,
                    handoff_attached=False,
                    workspace=self.workspace,
                    expected_config=self.config.as_json,
                    timeout_seconds=3.000001,
                )
            self._assert_readonly_probe(connection, baseline)

    def test_timeout_failure_is_rejected_without_mutating_connection(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_event = self._submit_event(before, now)
            with patch.object(
                lifecycle_adapter,
                "run_contained_verifier_stream",
                side_effect=lifecycle_adapter.VerifierProcessError("verifier_timeout"),
            ):
                with self.assertRaisesRegex(
                    LifecycleAdapterError,
                    "lifecycle_process:verifier_timeout",
                ):
                    evaluate_lifecycle_transition(
                        connection,
                        batch_id=batch.batch_id,
                        operation="submitHandoff",
                        now_ms=now,
                        handoff_attached=False,
                        workspace=self.workspace,
                        expected_config=self.config.as_json,
                    )
            self._assert_readonly_probe(connection, baseline)

    def test_unknown_process_exit_fails_closed_without_mutating_connection(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_event = self._submit_event(before, now)
            unknown = SimpleNamespace(
                exit_code=None,
                timed_out=False,
                cap_enforced=True,
                active_process_limit=1,
                stdout=b"",
            )
            with patch.object(
                lifecycle_adapter,
                "run_contained_verifier_stream",
                return_value=unknown,
            ):
                with self.assertRaisesRegex(
                    LifecycleAdapterError,
                    "lifecycle_process_result",
                ):
                    evaluate_lifecycle_transition(
                        connection,
                        batch_id=batch.batch_id,
                        operation="submitHandoff",
                        now_ms=now,
                        handoff_attached=False,
                        workspace=self.workspace,
                        expected_config=self.config.as_json,
                    )
            self._assert_readonly_probe(connection, baseline)

    def test_missing_transaction_is_rejected_without_mutating_connection(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_event = self._submit_event(before, now)
            connection.rollback()
            self.assertFalse(connection.in_transaction)
            total_changes = connection.total_changes
            pragmas = self._pragma_state(connection)
            pending_rows = tuple(
                connection.execute("SELECT value FROM lifecycle_pending")
            )
            batch_row = connection.execute(
                "SELECT status, next_eligible_ms, updated_ms FROM queue_batches WHERE batch_id=?",
                (batch.batch_id,),
            ).fetchone()
            with self.assertRaisesRegex(
                LifecycleAdapterError,
                "lifecycle_transaction_required",
            ):
                evaluate_lifecycle_transition(
                    connection,
                    batch_id=batch.batch_id,
                    operation="submitHandoff",
                    now_ms=now,
                    handoff_attached=False,
                    workspace=self.workspace,
                    expected_config=self.config.as_json,
                )
            self.assertFalse(connection.in_transaction)
            self.assertEqual(connection.total_changes, total_changes)
            self.assertEqual(self._pragma_state(connection), pragmas)
            self.assertEqual(
                tuple(connection.execute("SELECT value FROM lifecycle_pending")),
                pending_rows,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status, next_eligible_ms, updated_ms FROM queue_batches WHERE batch_id=?",
                    (batch.batch_id,),
                ).fetchone(),
                batch_row,
            )

    def test_submit_round_trip_returns_lean_decision_and_preserves_transaction(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            expected_after = self._submit_after(before, now)
            expected_event = self._submit_event(before, now)
            self.assertFalse(hasattr(lifecycle_adapter, "_host_claim_plan"))
            accepted = evaluate_lifecycle_transition(
                connection,
                batch_id=batch.batch_id,
                operation="submitHandoff",
                now_ms=now,
                handoff_attached=False,
                workspace=self.workspace,
                expected_config=self.config.as_json,
            )
            self.assertEqual(accepted.after, expected_after)
            self.assertEqual(accepted.event, expected_event)
            self._assert_readonly_probe(connection, baseline)

            with patch.object(
                lifecycle_adapter,
                "_decode_response",
                return_value=(replace(expected_after, updated_ms=now + 1), expected_event),
            ):
                with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_submit_state_shape"):
                    evaluate_lifecycle_transition(
                        connection,
                        batch_id=batch.batch_id,
                        operation="submitHandoff",
                        now_ms=now,
                        handoff_attached=False,
                        workspace=self.workspace,
                        expected_config=self.config.as_json,
                    )
            changed_proof_counter = replace(
                expected_after.accounting.proof,
                used=expected_after.accounting.proof.used + 1,
            )
            with patch.object(
                lifecycle_adapter,
                "_decode_response",
                return_value=(
                    replace(
                        expected_after,
                        reservation_after=expected_after.reservation_after + 1,
                        accounting=replace(expected_after.accounting, proof=changed_proof_counter),
                    ),
                    expected_event,
                ),
            ):
                with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_submit_state_shape"):
                    evaluate_lifecycle_transition(
                        connection,
                        batch_id=batch.batch_id,
                        operation="submitHandoff",
                        now_ms=now,
                        handoff_attached=False,
                        workspace=self.workspace,
                        expected_config=self.config.as_json,
                    )
            with patch.object(
                lifecycle_adapter,
                "_decode_response",
                return_value=(expected_after, replace(expected_event, at_ms=now + 1)),
            ):
                with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_submit_event_shape"):
                    evaluate_lifecycle_transition(
                        connection,
                        batch_id=batch.batch_id,
                        operation="submitHandoff",
                        now_ms=now,
                        handoff_attached=False,
                        workspace=self.workspace,
                        expected_config=self.config.as_json,
                    )
            self._assert_readonly_probe(connection, baseline)

            self.store._handoffs[batch.batch_id] = VolatileProofHandoff(bytearray(b"synthetic"))
            connection.execute(
                "UPDATE queue_batches SET status=?,next_eligible_ms=?,updated_ms=? WHERE batch_id=?",
                (
                    accepted.after.batch.upper(),
                    accepted.after.next_eligible_ms,
                    accepted.after.updated_ms,
                    batch.batch_id,
                ),
            )
            self.store._append_lifecycle_event(connection, accepted.event)
            connection.commit()

        verified = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(verified["transition_count"], expected_event.sequence)
        with closing(sqlite3.connect(self.root / "state.sqlite")) as connection:
            status = connection.execute(
                "SELECT status FROM queue_batches WHERE batch_id=?",
                (batch.batch_id,),
            ).fetchone()[0]
            raw_event = connection.execute(
                "SELECT event_bytes FROM queue_transitions WHERE sequence=?",
                (expected_event.sequence,),
            ).fetchone()[0]
        self.assertEqual(status, accepted.after.batch.upper())
        self.assertEqual(raw_event, canonical_queue_event_bytes(accepted.event))

    def test_claim_acceptance_and_mutated_global_lease_precondition(self) -> None:
        batch = self._issue()
        self.store.submit_batch_handoff(
            issued_batch=batch,
            proof_stream=VolatileProofHandoff(bytearray(b"synthetic")),
        )
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=True,
                expected_config=self.config.as_json,
            )
            now = self.clock.now
            mutated = replace(before, global_live_lease_count=1)
            mutated_frame = _encode_request("claimNextBatch", now, mutated)
            mutated_response = _run_lifecycle_frame(
                mutated_frame,
                workspace=self.workspace,
                timeout_seconds=3.0,
            )
            with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_precondition_rejected"):
                _decode_response(mutated_response, request=mutated_frame)
            self._assert_readonly_probe(connection, baseline)

            expected_after = self._claim_after(before, now)
            expected_event = self._claim_event(before, now)
            accepted = evaluate_lifecycle_transition(
                connection,
                batch_id=batch.batch_id,
                operation="claimNextBatch",
                now_ms=now,
                handoff_attached=True,
                workspace=self.workspace,
                expected_config=self.config.as_json,
            )
            self.assertEqual(accepted.after, expected_after)
            self.assertEqual(accepted.event, expected_event)
            self._assert_readonly_probe(connection, baseline)

            frame = _encode_request("claimNextBatch", now, before)
            response = _run_lifecycle_frame(
                frame,
                workspace=self.workspace,
                timeout_seconds=3.0,
            )
            echo_start = len(lifecycle_adapter.OUTPUT_MAGIC) + 1 + 1 + 2
            tampered_response = bytearray(response)
            tampered_response[echo_start] ^= 1
            with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_input_binding"):
                _decode_response(bytes(tampered_response), request=frame)

            invalid_states = (
                replace(expected_after, next_eligible_ms=expected_after.next_eligible_ms + 1),
                replace(expected_after, handoff_attached=False),
                replace(expected_after, lease_expires_ms=expected_after.lease_expires_ms + 1),
                replace(expected_after, claim_sequence=expected_after.claim_sequence + 1),
                replace(expected_after, reservation_after=expected_after.reservation_after + 1),
            )
            for invalid_after in invalid_states:
                with self.subTest(invalid_after=invalid_after):
                    with (
                        patch.object(lifecycle_adapter, "_run_lifecycle_frame", return_value=b"response"),
                        patch.object(
                            lifecycle_adapter,
                            "_decode_response",
                            return_value=(invalid_after, expected_event),
                        ),
                    ):
                        with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_claim_state_shape"):
                            evaluate_lifecycle_transition(
                                connection,
                                batch_id=batch.batch_id,
                                operation="claimNextBatch",
                                now_ms=now,
                                handoff_attached=True,
                                workspace=self.workspace,
                                expected_config=self.config.as_json,
                            )

            invalid_events = (
                replace(expected_event, at_ms=now + 1),
                replace(expected_event, reservation_before=expected_event.reservation_before + 1),
                replace(expected_event, receipt_id=bytes(32)),
            )
            for invalid_event in invalid_events:
                with self.subTest(invalid_event=invalid_event):
                    with (
                        patch.object(lifecycle_adapter, "_run_lifecycle_frame", return_value=b"response"),
                        patch.object(
                            lifecycle_adapter,
                            "_decode_response",
                            return_value=(expected_after, invalid_event),
                        ),
                    ):
                        with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_claim_event_shape"):
                            evaluate_lifecycle_transition(
                                connection,
                                batch_id=batch.batch_id,
                                operation="claimNextBatch",
                                now_ms=now,
                                handoff_attached=True,
                                workspace=self.workspace,
                                expected_config=self.config.as_json,
                            )

            self._assert_readonly_probe(connection, baseline)
            connection.execute("UPDATE queue_metadata SET live_lease_count=1 WHERE id=1")
            connection.execute(
                "UPDATE queue_batches SET status='LEASED',attempt=1,updated_ms=? WHERE batch_id=?",
                (now, batch.batch_id),
            )
            connection.execute(
                "INSERT INTO queue_leases VALUES (?,?,?,?,?,?,?)",
                (
                    batch.batch_id,
                    _RUNTIME_WORKER,
                    hashlib.sha3_512(b"synthetic lease token digest").digest(),
                    1,
                    expected_event.sequence,
                    now,
                    now + 60_000,
                ),
            )
            self.store._append_event(
                connection,
                kind="VERIFICATION_STARTED",
                batch_id=batch.batch_id,
                status="LEASED",
                error_code=None,
                attempt=1,
                at_ms=now,
                extra={
                    "member_count": 100,
                    "reservation_before": before.reservation_before,
                    "reservation_after": before.reservation_after,
                },
            )
            connection.commit()

        verified = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(verified["transition_count"], expected_event.sequence)
        with closing(sqlite3.connect(self.root / "state.sqlite")) as connection:
            self.assertEqual(
                connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (batch.batch_id,)).fetchone()[0],
                "LEASED",
            )

    def test_submit_allows_unrelated_live_lease_and_claim_rejects_it(self) -> None:
        first = self._issue()
        self.store.submit_batch_handoff(
            issued_batch=first,
            proof_stream=VolatileProofHandoff(bytearray(b"first")),
        )
        self.assertIsNotNone(self.store._claim_next_batch())
        second = self._issue()

        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=second.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            self.assertEqual(before.global_live_lease_count, 1)
            now = self.clock.now
            expected_after = self._submit_after(before, now)
            expected_event = self._submit_event(before, now)
            accepted = evaluate_lifecycle_transition(
                connection,
                batch_id=second.batch_id,
                operation="submitHandoff",
                now_ms=now,
                handoff_attached=False,
                workspace=self.workspace,
                expected_config=self.config.as_json,
            )
            self.assertEqual(accepted.after.global_live_lease_count, 1)
            self._assert_readonly_probe(connection, baseline)
            self.store._handoffs[second.batch_id] = VolatileProofHandoff(bytearray(b"second"))
            connection.execute(
                "UPDATE queue_batches SET status='QUEUED',next_eligible_ms=?,updated_ms=? WHERE batch_id=?",
                (now, now, second.batch_id),
            )
            self.store._append_event(
                connection,
                kind="HANDOFF_SUBMITTED",
                batch_id=second.batch_id,
                status="QUEUED",
                error_code=None,
                attempt=0,
                at_ms=now,
                extra={"member_count": 100},
            )
            connection.commit()

        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=second.batch_id,
                handoff_attached=True,
                expected_config=self.config.as_json,
            )
            event = self._claim_event(before, self.clock.now)
            with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_precondition_rejected"):
                evaluate_lifecycle_transition(
                    connection,
                    batch_id=second.batch_id,
                    operation="claimNextBatch",
                    now_ms=self.clock.now,
                    handoff_attached=True,
                    workspace=self.workspace,
                    expected_config=self.config.as_json,
                )
            self._assert_readonly_probe(connection, baseline)
            connection.rollback()

        verified = verify_database(self.root / "state.sqlite", expected_config=self.config.as_json)
        self.assertEqual(verified["transition_count"], expected_event.sequence)
        with closing(sqlite3.connect(self.root / "state.sqlite")) as connection:
            self.assertEqual(
                connection.execute("SELECT status FROM queue_batches WHERE batch_id=?", (second.batch_id,)).fetchone()[0],
                "QUEUED",
            )
            self.assertEqual(connection.execute("SELECT live_lease_count FROM queue_metadata WHERE id=1").fetchone()[0], 1)

    def test_invalid_lifecycle_state_field_fails_closed(self) -> None:
        batch = self._issue()
        with closing(self.store._connect()) as connection:
            baseline = self._begin_readonly_probe(connection)
            before = reconstruct_lifecycle_state(
                connection,
                batch_id=batch.batch_id,
                handoff_attached=False,
                expected_config=self.config.as_json,
            )
            mutated_identity = replace(before.identity, member_count=99)
            mutated = replace(before, identity=mutated_identity)
            frame = _encode_request("submitHandoff", self.clock.now, mutated)
            response = _run_lifecycle_frame(
                frame,
                workspace=self.workspace,
                timeout_seconds=3.0,
            )
            with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_kernel_malformed"):
                _decode_response(response, request=frame)
            self._assert_readonly_probe(connection, baseline)
            connection.rollback()

    def test_invalid_lifecycle_event_schema_fails_closed(self) -> None:
        event = LifecycleEvent(
            schema_version=queue_module.SCHEMA_VERSION - 1,
            sequence=1,
            kind="handoffSubmitted",
            batch_id=bytes(32),
            status="queued",
            error_code=None,
            attempt=0,
            at_ms=0,
            member_count=100,
        )
        with self.assertRaisesRegex(LifecycleAdapterError, "lifecycle_event_schema"):
            canonical_queue_event_bytes(event)


if __name__ == "__main__":
    unittest.main()
