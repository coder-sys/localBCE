"""Focused tests for the contained application-level financial Engine port."""

from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner_independent as independent
from tools.right_rail_financial_service_kit import ENGINE_EXE, _engine_pins


REPO_ROOT = Path(__file__).resolve().parents[1]


class RightRailFinancialEngineTests(unittest.TestCase):
    def tearDown(self) -> None:
        engine._close_evaluator()

    def test_correction_request_vector_is_blfcmd03_and_its_mutants_are_refused(self) -> None:
        # Lean paid sum (docs/CORE_REDESIGN.md): the request carries payment links, never paid totals.
        vectors = REPO_ROOT / "artifacts" / "engine-correction" / "vectors"
        request, expected_result = (vectors / "request.bin").read_bytes(), (vectors / "result.expected.bin").read_bytes()
        self.assertEqual(hashlib.sha256(request).digest(), engine.CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256)
        self.assertEqual(request[:10], b"BLFCMD03\x00\x03")
        links_at = request.index(b"BLFIN02") - 6  # the vector's empty link list sits right before the sized input
        self.assertEqual(request[links_at:links_at + 2], b"\x00\x00")
        self.assertEqual(engine._evaluate_wire(request), expected_result)
        self.assertEqual(engine._evaluate_wire((vectors / "request_unbound.bin").read_bytes()), (vectors / "result_unbound.expected.bin").read_bytes())  # zero roster digest: AUTHORITY_STALE
        mutants = {
            "old-magic": b"BLFCMD02" + request[8:],
            "old-version": request[:8] + b"\x00\x02" + request[10:],
            "trailing-byte": request + b"\x00",
            "phantom-link": request[:links_at] + b"\x00\x01" + request[links_at + 2:],
            "cap-plus-one": request + bytes(engine.MAX_CORRECTION_TRANSITION_BYTES + 1 - len(request)),  # refused before the worker
        }
        for name, mutant in mutants.items():
            with self.subTest(name), self.assertRaises(engine.FinancialEngineError):
                engine.run_correction_transition_v1(request=mutant)

    def test_one_worker_pin_is_shared_by_engine_checker_and_service_kit(self) -> None:
        self.assertEqual(independent.CORRECTION_TRANSITION_ARTIFACT_SHA256, engine.EVALUATOR_ARTIFACT_SHA256.hex().upper())
        source = (REPO_ROOT / "app" / "right_rail_financial_engine.py").read_bytes()
        self.assertEqual(_engine_pins(source), {
            "size": engine.EVALUATOR_ARTIFACT_SIZE_BYTES, ENGINE_EXE: engine.EVALUATOR_ARTIFACT_SHA256.hex().upper(),
            "request": engine.CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256.hex().upper(),
            "result": engine.CORRECTION_TRANSITION_RESULT_VECTOR_SHA256.hex().upper()})
        self.assertEqual(hashlib.sha256((REPO_ROOT / "artifacts" / "engine-correction" / "vectors" / "result.expected.bin").read_bytes()).digest(),
                         engine.CORRECTION_TRANSITION_RESULT_VECTOR_SHA256)
        self.assertFalse(hasattr(engine, "load_correction_transition_release") or hasattr(engine, "_run_pinned"))
        self.assertNotIn("blind_financial_correction", (REPO_ROOT / "lean" / "lakefile.toml").read_text(encoding="utf-8"))

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
