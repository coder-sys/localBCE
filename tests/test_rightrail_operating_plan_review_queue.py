from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "build_rightrail_operating_plan_review_queue.py"
)
SPEC = importlib.util.spec_from_file_location("rightrail_operating_plan_queue", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
queue = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = queue
SPEC.loader.exec_module(queue)


def candidate(identifier: str, *, disposition: str = "review_candidate") -> dict[str, object]:
    return {
        "requirement_id": identifier,
        "source_path": queue.SOURCE_PATH,
        "source_sha256": "a" * 64,
        "page_number": 3,
        "line_number": 7,
        "statement": "The state must retain evidence.",
        "domains": ["source_and_evidence"],
        "crosswalk_disposition": disposition,
        "crosswalk_flags": [],
        "runtime_eligible": False,
    }


class RightRailOperatingPlanReviewQueueTests(unittest.TestCase):
    def test_safety_boundaries_are_first(self) -> None:
        priority, rationale = queue.review_priority(
            candidate("rrreq-safety", disposition="adopt_safety_boundary")
        )
        self.assertEqual(priority, 1)
        self.assertEqual(rationale, "existing safety boundary")

    def test_targets_are_stable_and_deduplicated(self) -> None:
        self.assertEqual(
            queue.target_paths(["proof_and_crypto", "settlement_and_payment"]),
            ["STARK_RUNTIME.md"],
        )

    def test_queue_never_auto_adopts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for target in set(queue.DOMAIN_TARGETS.values()):
                path = root / target
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            queue_bytes, _summary_bytes, summary = queue.build_queue(
                [candidate("rrreq-one")],
                {"checkpoint_sha256": "b" * 64, "requirements_sha256": "c" * 64},
                root,
                expected_count=1,
            )
            self.assertEqual(summary["pending_human_review_count"], 1)
            self.assertEqual(summary["runtime_eligible_count"], 0)
            self.assertIn(b'"human_decision":null', queue_bytes)
            self.assertIn(b'"automatic_adoption":false', queue_bytes)
            self.assertIn(b'"proof_binding":false', queue_bytes)

    def test_wrong_source_count_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(queue.ReviewQueueError):
                queue.build_queue([], {}, Path(directory), expected_count=1)


if __name__ == "__main__":
    unittest.main()
