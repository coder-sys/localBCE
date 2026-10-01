from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_rightrail_safety_review_packet.py"
SPEC = importlib.util.spec_from_file_location("rightrail_safety_review_packet", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
packet_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = packet_module
SPEC.loader.exec_module(packet_module)


class RightRailSafetyReviewPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        reports = ROOT / "right-rail-integration" / "reports"
        cls.queue_records = packet_module.load_jsonl(
            reports / "operating_plan_review_queue_v1.jsonl"
        )
        cls.queue_summary = packet_module.load_json(
            reports / "operating_plan_review_queue_summary_v1.json"
        )

    def build(self) -> tuple[bytes, dict[str, object]]:
        return packet_module.build_packet(self.queue_records, self.queue_summary, ROOT)

    def test_packet_contains_only_four_priority_candidates(self) -> None:
        _content, packet = self.build()
        self.assertEqual(packet["priority_candidate_count"], 4)
        self.assertEqual(packet["proposed_decision_counts"], {"adapt": 2, "adopt": 2})
        self.assertEqual(
            {item["requirement_id"] for item in packet["candidates"]},
            set(packet_module.RECOMMENDATIONS),
        )

    def test_packet_never_records_human_approval_or_activation(self) -> None:
        _content, packet = self.build()
        self.assertEqual(packet["human_reviewed_count"], 0)
        self.assertEqual(packet["final_decision_count"], 0)
        self.assertFalse(packet["automatic_adoption"])
        self.assertFalse(packet["execution_allowed"])
        for item in packet["candidates"]:
            self.assertEqual(item["decision_status"], "pending_human_review")
            self.assertIsNone(item["human_decision"])
            self.assertFalse(item["runtime_eligible"])
            self.assertFalse(item["proof_binding"])
            self.assertFalse(item["execution_allowed"])

    def test_evidence_is_hash_pinned_and_resolves_to_exact_lines(self) -> None:
        _content, packet = self.build()
        for item in packet["candidates"]:
            for evidence in item["evidence"]:
                path = ROOT / evidence["path"]
                self.assertEqual(
                    packet_module.hashlib.sha256(path.read_bytes()).hexdigest(),
                    evidence["file_sha256"],
                )
                self.assertEqual(
                    path.read_text(encoding="utf-8").splitlines()[evidence["line_number"] - 1],
                    evidence["excerpt"],
                )

    def test_output_is_deterministic(self) -> None:
        left, left_packet = self.build()
        right, right_packet = self.build()
        self.assertEqual(left, right)
        self.assertEqual(left_packet["checkpoint_sha256"], right_packet["checkpoint_sha256"])
        self.assertEqual(json.loads(left), left_packet)

    def test_missing_evidence_marker_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "evidence.md").write_text("different line\n", encoding="utf-8")
            with self.assertRaisesRegex(
                packet_module.SafetyReviewPacketError, "expected one evidence marker"
            ):
                packet_module.resolve_evidence(
                    root,
                    {
                        "path": "evidence.md",
                        "marker": "required line",
                        "relation": "test",
                    },
                )

    def test_queue_checkpoint_change_fails_closed(self) -> None:
        changed = dict(self.queue_summary)
        changed["checkpoint_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            packet_module.SafetyReviewPacketError, "queue checkpoint changed"
        ):
            packet_module.build_packet(self.queue_records, changed, ROOT)


if __name__ == "__main__":
    unittest.main()
