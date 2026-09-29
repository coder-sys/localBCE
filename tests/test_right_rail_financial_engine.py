"""Focused tests for the contained application-level financial Engine port."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_engine as engine
from app import right_rail_financial_semantic_adapter as adapter
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_semantic_adapter as semantic_tests
from tests.test_right_rail_financial_acceptance import _correction_transition_test_release


EXPECTED_H_CASH_CENTS = semantic_tests.EXPECTED_H_CASH_CENTS
EXPECTED_H_OWED_CENTS = semantic_tests.EXPECTED_H_OWED_CENTS
EXPECTED_OFFSET_CENTS = semantic_tests.EXPECTED_OFFSET_CENTS


REPO_ROOT = Path(__file__).resolve().parents[1]
# The digest-pinned snapshot evaluator (blind_financial.exe, not the pinned correction
# program). Repo-relative by default; RIGHTRAIL_ACCEPTED_ENGINE_PATH may point
# elsewhere, but the size and SHA-256 pins below still decide acceptance.
ACCEPTED_ENGINE_PATH = Path(
    os.environ.get(
        "RIGHTRAIL_ACCEPTED_ENGINE_PATH",
        str(REPO_ROOT / "artifacts" / "engine-snapshot-398e" / "blind_financial.exe"),
    )
)
ACCEPTED_ENGINE_SIZE_BYTES = 6_001_664
ACCEPTED_ENGINE_SHA256 = bytes.fromhex(
    "398E6D16922D23F71F52074F151553DCE75467723D4C624A8D7B71076FA24D03"
)
ACCEPTED_INPUT_SHA256 = bytes.fromhex(
    "C94A16DA6F2EA33C153F7E0890F95434ABD6F051C6F69FE7D7B1F39985E72344"
)
ACCEPTED_OUTPUT_SHA256 = bytes.fromhex(
    "278D98485EBE968C88AC0E85BCCD4F69C5B7FF1A38F0B20681DD7E79C82A7598"
)
EXPECTED_CORRECTION_ARTIFACT_SIZE_BYTES = 6_279_168
EXPECTED_CORRECTION_ARTIFACT_SHA256 = bytes.fromhex(
    "1A7A18333726484A0737DA7B005EC699F73E99EA0CFACFB409B000F964BED3AF"
)
EXPECTED_CORRECTION_REQUEST_VECTOR_SHA256 = bytes.fromhex(
    "B658DCEE04138FDCBA6C9D72F3D2D044E5F596AA5794B3562A8312FBB57AD067"
)
EXPECTED_CORRECTION_RESULT_VECTOR_SHA256 = bytes.fromhex(
    "83BB53D184B0B7D9268B565B844ECE9D6943C37DD022E2D361F735A4C835E0D6"
)


class RightRailFinancialEngineTests(unittest.TestCase):
    def test_current_engine_matches_independent_reuse_vector(self) -> None:
        vectors = REPO_ROOT / "artifacts" / "engine-correction" / "vectors"
        request, expected_result = (vectors / "reuse-request.bin").read_bytes(), (vectors / "reuse-result.expected.bin").read_bytes()
        self.assertEqual(hashlib.sha256(request).hexdigest(), "9c203f6bf50da69d9d77cafc4adbf7bd3628724dfabf87e69e141a319f185b99")
        self.assertEqual(expected_result.hex(), "424c4643525630320002002052522f46494e414e4349414c2f434f5252454354494f4e2d52455553452f7631010001000100020000")
        release = _correction_transition_test_release(workspace=Path(self.release_dir.name) / "reuse")
        actual = engine._run_pinned(release, ("--assess-correction-reuse",), request, failure_code="reuse_vector_failed")
        self.assertEqual((actual.exit_code, actual.stdout, actual.stderr), (0, expected_result, b""))

    def setUp(self) -> None:
        self.fixture = semantic_tests.RightRailFinancialSemanticAdapterTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.release_dir = tempfile.TemporaryDirectory(prefix="right-rail-engine-")
        self.addCleanup(self.release_dir.cleanup)

    def _release(self, **overrides: object) -> engine.FinancialEngineRelease:
        root = Path(self.release_dir.name)
        executable = root / "financial-engine.exe"
        payload = b"explicit-test-engine-artifact"
        executable.write_bytes(payload)
        workspace = root / "workspace"
        workspace.mkdir(exist_ok=True)
        values: dict[str, object] = {
            "executable": executable,
            "executable_size_bytes": len(payload),
            "executable_sha256": hashlib.sha256(payload).digest(),
            "timeout_seconds": 3.0,
            "input_max_bytes": engine.MAX_ENGINE_INPUT_BYTES,
            "output_max_bytes": adapter.MAX_RESULT_BYTES,
            "stderr_max_bytes": process.MAX_STDERR_BYTES,
            "workspace": workspace,
            "job_memory_cap_bytes": 123_456_789,
        }
        values.update(overrides)
        return engine.FinancialEngineRelease(**values)

    def _correction_release(self, **overrides: object) -> engine.FinancialCorrectionTransitionRelease:
        root = Path(self.release_dir.name)
        workspace = root / "correction-workspace"
        workspace.mkdir(exist_ok=True)
        values: dict[str, object] = {
            "executable": root / "blind_financial_correction.exe",
            "executable_size_bytes": EXPECTED_CORRECTION_ARTIFACT_SIZE_BYTES,
            "executable_sha256": EXPECTED_CORRECTION_ARTIFACT_SHA256,
            "request_vector_sha256": EXPECTED_CORRECTION_REQUEST_VECTOR_SHA256,
            "result_vector_sha256": EXPECTED_CORRECTION_RESULT_VECTOR_SHA256,
            "timeout_seconds": 30.0,
            "input_max_bytes": engine.MAX_CORRECTION_TRANSITION_BYTES,
            "output_max_bytes": engine.MAX_CORRECTION_TRANSITION_BYTES,
            "stderr_max_bytes": process.MAX_STDERR_BYTES,
            "workspace": workspace,
            "job_memory_cap_bytes": 123_456_789,
        }
        values.update(overrides)
        return engine.FinancialCorrectionTransitionRelease(**values)

    def _owner_with_cash_claim(self):
        store = self.fixture._build_base()
        self.fixture._record_cash(store)
        self.fixture._record_claim(store)
        return store

    def _active_connection(self, store):
        connection = store._connect()
        connection.execute("BEGIN")
        self.addCleanup(connection.close)
        self.addCleanup(connection.rollback)
        return connection

    @staticmethod
    def _snapshot(store, connection):
        return adapter.build_locked_semantic_snapshot(
            connection,
            obligation_id=expected.H_OBLIGATION_ID,
            authority_context=adapter.TrustedAuthorityContext.from_authority(store.trusted_authority),
            evaluation_time_ms=2**63 - 2,
            expected_config=store.config,
            expected_scope=store.config,
            expected_mode=store.mode,
            expected_owner_id=store.owner_id,
        )

    @staticmethod
    def _evaluate_snapshot(store, connection, release):
        return engine.evaluate_financial_snapshot(
            connection,
            release=release,
            obligation_id=expected.H_OBLIGATION_ID,
            authority_context=adapter.TrustedAuthorityContext.from_authority(store.trusted_authority),
            evaluation_time_ms=2**63 - 2,
            expected_config=store.config,
            expected_scope=store.config,
            expected_mode=store.mode,
            expected_owner_id=store.owner_id,
        )

    @staticmethod
    def _result_for_snapshot(snapshot: adapter.LockedSemanticSnapshot) -> adapter.DecodedLeanResult:
        data = snapshot.data
        scope = data["scope"]
        owner_body = data["owner"]
        authority = data["authority"]
        pack = data["control_pack"]
        pre = data["pre_evaluation"]
        receipt = data["current_evaluation"]["receipt"]
        return adapter.DecodedLeanResult(
            owner_id=owner_body["owner_id"],
            mode=owner_body["mode"],
            provenance=owner_body["provenance"],
            state_id=scope["state_id"],
            deployment_id=scope["deployment_id"],
            program_id=scope["program_id"],
            period_id=scope["period_id"],
            population_id=data["population"]["population_id"],
            item_id=pre["item_id"],
            obligation_id=pre["obligation_id"],
            currency=scope["currency"],
            authority_id=authority["authority_id"],
            authority_epoch=authority["epoch"],
            authority_digest=bytes.fromhex(authority["digest"]),
            pack_id=pack["canonical_fields"]["pack_id"],
            pack_digest=bytes.fromhex(pack["digest"]),
            before_revision=pre["revision"],
            after_revision=pre["revision"] + 1,
            evaluated_at_ms=data["evaluation_time_ms"],
            rule_version=pack["canonical_fields"]["version"],
            evidence_ids=tuple(receipt["evidence_ids"]),
            completion_at_ms=None,
            owed_cents=EXPECTED_H_OWED_CENTS,
            claimed_adjustment_cents=EXPECTED_OFFSET_CENTS,
            lawful_adjustment_cents=0,
            received_cash_cents=EXPECTED_H_CASH_CENTS,
            shortfall_cents=EXPECTED_OFFSET_CENTS,
            overage_cents=0,
            cash_satisfied=False,
            amount_satisfied=False,
            timely=False,
            reporting_complete=False,
            verification_status="SUPPORTED",
            case_status="OPEN",
            delivery_status="NONE",
        )

    @staticmethod
    def _contained(stdout: bytes, *, cap: int) -> process.ContainedVerifierResult:
        return process.ContainedVerifierResult(
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            peak_job_commit_bytes=1,
            cap_bytes=cap,
            cap_enforced=True,
            active_process_limit=process.ACTIVE_PROCESS_LIMIT,
            timed_out=False,
            child_process_count=1,
            process_tree_complete=True,
            measurement_complete=True,
            cleanup_complete=True,
        )

    def test_release_is_immutable_and_explicitly_bounded(self) -> None:
        release = self._release()
        with self.assertRaises(FrozenInstanceError):
            release.job_memory_cap_bytes = 1
        self.assertEqual(self._release(timeout_seconds=30.0).timeout_seconds, 30.0)
        self.assertEqual(release.input_max_bytes, adapter.MAX_WIRE_BYTES)
        self.assertEqual(release.output_max_bytes, adapter.MAX_RESULT_BYTES)
        self.assertEqual(release.job_memory_cap_bytes, 123_456_789)
        self.assertEqual(adapter.BLFIN02_MAGIC, b"BLFIN02")
        self.assertEqual(adapter.BLFRES02_MAGIC, b"BLFRES02")

        invalid = (
            ("engine_executable_path", {"executable": Path("relative.exe")}),
            ("engine_timeout", {"timeout_seconds": 3}),
            ("engine_timeout", {"timeout_seconds": 30.000001}),
            ("engine_memory_cap", {"job_memory_cap_bytes": True}),
            ("engine_memory_cap", {"job_memory_cap_bytes": engine.MAX_ENGINE_JOB_MEMORY_CAP_BYTES + 1}),
            ("engine_output_limit", {"output_max_bytes": adapter.MAX_RESULT_BYTES + 1}),
        )
        for code, overrides in invalid:
            with self.subTest(code=code):
                with self.assertRaisesRegex(engine.FinancialEngineConfigError, code):
                    self._release(**overrides)

    def test_correction_transition_release_is_immutable_and_pins_artifact_and_vectors(self) -> None:
        self.assertEqual(engine.CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES, EXPECTED_CORRECTION_ARTIFACT_SIZE_BYTES)
        self.assertEqual(engine.CORRECTION_TRANSITION_ARTIFACT_SHA256, EXPECTED_CORRECTION_ARTIFACT_SHA256)
        self.assertEqual(engine.CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256, EXPECTED_CORRECTION_REQUEST_VECTOR_SHA256)
        self.assertEqual(engine.CORRECTION_TRANSITION_RESULT_VECTOR_SHA256, EXPECTED_CORRECTION_RESULT_VECTOR_SHA256)
        release = self._correction_release()
        self.assertIs(engine.require_correction_transition_v1(release), release)
        with self.assertRaises(FrozenInstanceError):
            release.request_vector_sha256 = b"x" * 32

        invalid_config = (
            ("engine_correction_request_vector_hash", {"request_vector_sha256": b"short"}),
            ("engine_correction_result_vector_hash", {"result_vector_sha256": b"short"}),
        )
        for code, overrides in invalid_config:
            with self.subTest(code=code):
                with self.assertRaisesRegex(engine.FinancialEngineConfigError, code):
                    self._correction_release(**overrides)

        invalid_identity = (
            ("engine_correction_transition_artifact_identity", {"executable_sha256": b"x" * 32}),
            ("engine_correction_transition_artifact_identity", {"executable_size_bytes": EXPECTED_CORRECTION_ARTIFACT_SIZE_BYTES + 1}),
            ("engine_correction_transition_request_vector_identity", {"request_vector_sha256": b"r" * 32}),
            ("engine_correction_transition_result_vector_identity", {"result_vector_sha256": b"s" * 32}),
        )
        for code, overrides in invalid_identity:
            with self.subTest(code=code):
                with self.assertRaisesRegex(engine.FinancialEngineArtifactError, code):
                    engine.require_correction_transition_v1(self._correction_release(**overrides))

    def test_correction_transition_gate_rejects_missing_and_wrong_release_type(self) -> None:
        with self.assertRaisesRegex(
            engine.FinancialEngineTransitionUnavailable,
            "engine_correction_transition_release_required",
        ):
            engine.require_correction_transition_v1(None)
        with self.assertRaisesRegex(
            engine.FinancialEngineConfigError,
            "engine_correction_transition_release_type",
        ):
            engine.require_correction_transition_v1(self._release())

    def test_correction_transition_digest_accepts_owner_bytes_and_checked_hex(self) -> None:
        digest = bytes(range(64))
        self.assertEqual(engine._transition_digest(digest, "digest"), digest)
        self.assertEqual(engine._transition_digest(digest.hex().upper(), "digest"), digest)
        for invalid in (b"short", b"x" * 32, "not-a-digest", None):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaisesRegex(engine.FinancialEngineInputError, "digest"):
                    engine._transition_digest(invalid, "digest")

    def test_artifact_identity_rejects_before_snapshot_or_launch(self) -> None:
        release = self._release(executable_sha256=b"x" * 32)
        runner = patch.object(
            engine.process,
            "run_contained_verifier_stream",
            side_effect=AssertionError("launch reached after identity rejection"),
        )
        with runner:
            with self.assertRaisesRegex(engine.FinancialEngineArtifactError, "engine_artifact_identity"):
                engine.evaluate_financial_snapshot(
                    object(),
                    release=release,
                    obligation_id=expected.H_OBLIGATION_ID,
                    authority_context=object(),
                    evaluation_time_ms=2**63 - 2,
                    expected_config=object(),
                    expected_scope=object(),
                    expected_mode="LIVE",
                    expected_owner_id="owner",
                )

    def test_explicit_release_ignores_environment_and_keeps_owner_transaction_unchanged(self) -> None:
        store = self._owner_with_cash_claim()
        connection = self._active_connection(store)
        snapshot = self._snapshot(store, connection)
        expected_result = self._result_for_snapshot(snapshot)
        output = adapter.encode_blfres02_result(expected_result)
        release = self._release()
        captured: dict[str, object] = {}

        def runner(*args: object, **kwargs: object) -> process.ContainedVerifierResult:
            captured["args"] = args
            captured.update(kwargs)
            return self._contained(output, cap=release.job_memory_cap_bytes)

        before_hash = self.fixture._hash(store.path)
        with patch.dict(
            os.environ,
            {
                "BLIND_FINANCIAL_EXE": str(Path(self.release_dir.name) / "wrong.exe"),
                "BLIND_FINANCIAL_EXE_SHA256": "00" * 32,
            },
        ):
            with patch.object(engine.process, "run_contained_verifier_stream", side_effect=runner):
                execution = self._evaluate_snapshot(store, connection, release)

        self.assertEqual(execution.result, expected_result)
        self.assertEqual(execution.input_sha256, hashlib.sha256(captured["args"][2]).digest())
        self.assertEqual(execution.output_sha256, hashlib.sha256(output).digest())
        self.assertEqual(execution.executable_sha256, release.executable_sha256)
        self.assertEqual(captured["args"][:2], (release.executable, engine.ENGINE_ARGUMENTS))
        self.assertEqual(captured["job_memory_cap_bytes"], release.job_memory_cap_bytes)
        self.assertIs(captured["stdout_ascii"], False)
        self.assertIs(captured["stderr_ascii"], False)
        self.assertEqual(captured["expected_input_bytes"], len(captured["args"][2]))
        self.assertTrue(connection.in_transaction)
        self.assertEqual(self.fixture._hash(store.path), before_hash)

    def test_containment_output_and_result_failures_are_fail_closed_without_leaks(self) -> None:
        store = self._owner_with_cash_claim()
        connection = self._active_connection(store)
        snapshot = self._snapshot(store, connection)
        valid_output = adapter.encode_blfres02_result(self._result_for_snapshot(snapshot))
        release = self._release()

        failures = (
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), exit_code=7), "child-secret"),
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), stderr=b"child-secret"), "child-secret"),
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), timed_out=True), ""),
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), cap_bytes=release.job_memory_cap_bytes - 1), ""),
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), active_process_limit=2), ""),
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), child_process_count=0), ""),
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), process_tree_complete=False), ""),
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), measurement_complete=False), ""),
            ("engine_containment", replace(self._contained(valid_output, cap=release.job_memory_cap_bytes), cleanup_complete=False), ""),
            ("engine_result", replace(self._contained(valid_output + b"\x00", cap=release.job_memory_cap_bytes)), ""),
            ("engine_result", replace(self._contained(b"BLFRES02", cap=release.job_memory_cap_bytes)), ""),
        )
        for code, contained, leaked_text in failures:
            with self.subTest(code=code, output=contained.stdout[:8]):
                with patch.object(engine.process, "run_contained_verifier_stream", return_value=contained):
                    with self.assertRaisesRegex(engine.FinancialEngineError, code) as raised:
                        self._evaluate_snapshot(store, connection, release)
                if leaked_text:
                    self.assertNotIn(leaked_text, str(raised.exception))
                self.assertTrue(connection.in_transaction)

        limited_release = self._release(output_max_bytes=len(valid_output) - 1)
        with patch.object(engine.process, "run_contained_verifier_stream", return_value=self._contained(valid_output, cap=limited_release.job_memory_cap_bytes)):
            with self.assertRaisesRegex(engine.FinancialEngineContainmentError, "engine_containment"):
                self._evaluate_snapshot(store, connection, limited_release)

    def test_owner_savepoints_and_pending_writes_survive_success_and_failure(self) -> None:
        store = self._owner_with_cash_claim()
        connection = self._active_connection(store)
        connection.execute(
            "CREATE TEMP TABLE caller_pending_marker (marker TEXT NOT NULL)"
        )
        snapshot = self._snapshot(store, connection)
        output = adapter.encode_blfres02_result(self._result_for_snapshot(snapshot))
        release = self._release()
        real_build = engine.semantic.build_locked_semantic_snapshot
        seen_connections: list[object] = []

        def capture_build(connection_arg: object, *args: object, **kwargs: object):
            seen_connections.append(connection_arg)
            return real_build(connection_arg, *args, **kwargs)

        def accepted_runner(*args: object, **kwargs: object) -> process.ContainedVerifierResult:
            return self._contained(output, cap=release.job_memory_cap_bytes)

        connection.execute("SAVEPOINT caller_success")
        connection.execute(
            "INSERT INTO caller_pending_marker(marker) VALUES (?)",
            ("success-pending",),
        )
        with patch.object(engine.semantic, "build_locked_semantic_snapshot", side_effect=capture_build):
            with patch.object(engine.process, "run_contained_verifier_stream", side_effect=accepted_runner):
                self._evaluate_snapshot(store, connection, release)
        self.assertIs(seen_connections[-1], connection)
        self.assertEqual(
            connection.execute("SELECT marker FROM caller_pending_marker").fetchone()[0],
            "success-pending",
        )
        self.assertTrue(connection.in_transaction)
        connection.execute("ROLLBACK TO caller_success")
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM caller_pending_marker").fetchone()[0], 0)
        connection.execute("RELEASE caller_success")

        connection.execute("SAVEPOINT caller_failure")
        connection.execute(
            "INSERT INTO caller_pending_marker(marker) VALUES (?)",
            ("failure-pending",),
        )
        failed_result = replace(
            self._contained(output, cap=release.job_memory_cap_bytes),
            cleanup_complete=False,
        )
        with patch.object(engine.semantic, "build_locked_semantic_snapshot", side_effect=capture_build):
            with patch.object(engine.process, "run_contained_verifier_stream", return_value=failed_result):
                with self.assertRaisesRegex(engine.FinancialEngineContainmentError, "engine_containment"):
                    self._evaluate_snapshot(store, connection, release)
        self.assertIs(seen_connections[-1], connection)
        self.assertEqual(
            connection.execute("SELECT marker FROM caller_pending_marker").fetchone()[0],
            "failure-pending",
        )
        self.assertTrue(connection.in_transaction)
        connection.execute("ROLLBACK TO caller_failure")
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM caller_pending_marker").fetchone()[0], 0)
        connection.execute("RELEASE caller_failure")

    @unittest.skipUnless(os.name == "nt", "accepted Engine requires Windows Job Object containment")
    def test_bounded_actual_accepted_engine_execution_preserves_cents_and_database(self) -> None:
        # Environment prerequisite, not a product result: the pinned 398E artifact
        # is not in this checkout, so the execution is reported UNEXECUTED (a skip,
        # never a pass). A present file is still held to the size/SHA-256 pins.
        if not ACCEPTED_ENGINE_PATH.exists():
            self.skipTest(f"accepted_engine_execution_unexecuted: pinned artifact absent at {ACCEPTED_ENGINE_PATH}")
        self.assertTrue(ACCEPTED_ENGINE_PATH.is_file(), ACCEPTED_ENGINE_PATH)
        store = self.fixture._build_base()
        self.fixture._record_cash(store)
        claim_id = self.fixture._record_claim(store)
        self.fixture._record_h_support(store)
        self.fixture._authorize(store, claim_id)
        before_hash = self.fixture._hash(store.path)
        connection = self._active_connection(store)
        release = engine.FinancialEngineRelease(
            executable=ACCEPTED_ENGINE_PATH,
            executable_size_bytes=ACCEPTED_ENGINE_SIZE_BYTES,
            executable_sha256=ACCEPTED_ENGINE_SHA256,
            timeout_seconds=30.0,
            input_max_bytes=engine.MAX_ENGINE_INPUT_BYTES,
            output_max_bytes=adapter.MAX_RESULT_BYTES,
            stderr_max_bytes=process.MAX_STDERR_BYTES,
            workspace=Path(self.release_dir.name) / "accepted-workspace",
            job_memory_cap_bytes=engine.MAX_ENGINE_JOB_MEMORY_CAP_BYTES,
        )
        release.workspace.mkdir()
        execution = self._evaluate_snapshot(store, connection, release)
        self.assertEqual(execution.input_size_bytes, 2526)
        self.assertEqual(execution.input_sha256, ACCEPTED_INPUT_SHA256)
        self.assertEqual(execution.output_size_bytes, 552)
        self.assertEqual(execution.output_sha256, ACCEPTED_OUTPUT_SHA256)
        self.assertEqual(execution.result.owed_cents, EXPECTED_H_OWED_CENTS)
        self.assertEqual(execution.result.claimed_adjustment_cents, EXPECTED_OFFSET_CENTS)
        self.assertEqual(execution.result.lawful_adjustment_cents, EXPECTED_OFFSET_CENTS)
        self.assertEqual(execution.result.received_cash_cents, EXPECTED_H_CASH_CENTS)
        self.assertTrue(execution.result.amount_satisfied)
        self.assertEqual(execution.result.shortfall_cents, 0)
        self.assertEqual(execution.result.overage_cents, 0)
        self.assertTrue(connection.in_transaction)
        self.assertEqual(self.fixture._hash(store.path), before_hash)


if __name__ == "__main__":
    unittest.main()
