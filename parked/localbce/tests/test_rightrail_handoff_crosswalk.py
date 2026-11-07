import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_rightrail_handoff_crosswalk",
    ROOT / "scripts" / "build_rightrail_handoff_crosswalk.py",
)
crosswalk = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(crosswalk)


class RightRailHandoffCrosswalkTests(unittest.TestCase):
    def test_crosswalk_covers_every_catalog_record(self):
        outputs = crosswalk.build()
        summary = json.loads(outputs[crosswalk.SUMMARY_NAME])
        self.assertEqual(summary["queue_record_count"], 1108)
        self.assertEqual(summary["package_file_count"], 323)
        self.assertEqual(summary["trunk_file_count"], 637)
        self.assertEqual(summary["git_ref_count"], 148)
        self.assertTrue(summary["complete_catalog_coverage"])

    def test_queue_is_inactive_and_unapproved(self):
        outputs = crosswalk.build()
        queue = [json.loads(line) for line in outputs[crosswalk.QUEUE_NAME].splitlines()]
        self.assertTrue(queue)
        self.assertTrue(all(item["human_decision"] is None for item in queue))
        self.assertTrue(all(item["execution_allowed"] is False for item in queue))
        self.assertTrue(all(item["runtime_eligible"] is False for item in queue))
        self.assertTrue(all(item["proof_binding"] is False for item in queue))
        self.assertEqual(len({item["queue_id"] for item in queue}), len(queue))

    def test_every_domain_has_review_ownership(self):
        outputs = crosswalk.build()
        queue = [json.loads(line) for line in outputs[crosswalk.QUEUE_NAME].splitlines()]
        self.assertTrue(all(item["required_reviewer_roles"] for item in queue))
        self.assertTrue(all(item["target_subsystem"] for item in queue))
        self.assertTrue(all(item["blockers"] for item in queue))

    def test_pq_lane_does_not_activate_mldsa(self):
        outputs = crosswalk.build()
        pq = json.loads(outputs[crosswalk.PQ_NAME])
        self.assertGreater(pq["candidate_count"], 0)
        self.assertFalse(pq["ml_dsa_runtime_activation"])
        self.assertFalse(pq["production_dependency_added"])
        self.assertEqual(pq["stark_envelope_bytes"], 129)
        self.assertTrue(all(not item["bytes_copied"] for item in pq["candidates"]))

    def test_controls_are_non_runtime(self):
        outputs = crosswalk.build()
        controls = json.loads(outputs[crosswalk.CONTROLS_NAME])
        self.assertEqual(controls["control_count"], 10)
        self.assertFalse(controls["runtime_behavior_changed"])
        self.assertEqual(controls["human_approval_count"], 0)
        self.assertTrue(all(not item["runtime_behavior_changed"] for item in controls["controls"]))
        self.assertTrue(all(item["local_evidence"] for item in controls["controls"]))

    def test_final_checkpoint_preserves_localbce_boundaries(self):
        outputs = crosswalk.build()
        checkpoint = json.loads(outputs[crosswalk.CHECKPOINT_NAME])
        self.assertEqual(checkpoint["complete_catalog_record_count"], 1108)
        self.assertEqual(checkpoint["complete_disposition_count"], 1108)
        self.assertTrue(checkpoint["groth16_default_preserved"])
        self.assertTrue(checkpoint["stark_attested_explicitly_gated"])
        self.assertTrue(checkpoint["hardcoded_g1_g10_default_preserved"])
        self.assertFalse(checkpoint["sqlite_runtime_imported"])
        self.assertFalse(checkpoint["formal_runtime_dependency"])
        self.assertFalse(checkpoint["ml_dsa_runtime_activation"])


if __name__ == "__main__":
    unittest.main()
