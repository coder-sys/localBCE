"""Focused tests for the contained application-level financial Engine port."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import tempfile
import unittest

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_engine as engine
from tests.test_right_rail_financial_acceptance import _correction_transition_test_release


REPO_ROOT = Path(__file__).resolve().parents[1]
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
        self.release_dir = tempfile.TemporaryDirectory(prefix="right-rail-engine-")
        self.addCleanup(self.release_dir.cleanup)

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
            engine.require_correction_transition_v1(object())

    def test_correction_transition_digest_accepts_owner_bytes_and_checked_hex(self) -> None:
        digest = bytes(range(64))
        self.assertEqual(engine._transition_digest(digest, "digest"), digest)
        self.assertEqual(engine._transition_digest(digest.hex().upper(), "digest"), digest)
        for invalid in (b"short", b"x" * 32, "not-a-digest", None):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaisesRegex(engine.FinancialEngineInputError, "digest"):
                    engine._transition_digest(invalid, "digest")


if __name__ == "__main__":
    unittest.main()
