import unittest

from app.rule_crosswalk import build_rule_crosswalk, rule_crosswalk_hash


class RuleCrosswalkTests(unittest.TestCase):
    def test_crosswalk_marks_native_stark_lane_canonical(self):
        crosswalk = build_rule_crosswalk()

        self.assertEqual(crosswalk["schema_version"], "rule_crosswalk_v2_native_stark")
        self.assertEqual(crosswalk["production_rule_contract"]["canonical_lane"], "native_stark_binding")
        self.assertFalse(crosswalk["production_rule_contract"]["legacy_claim_circuit_allowed_in_production"])
        self.assertTrue(crosswalk["production_rule_contract"]["v9_crosswalk_required_before_production"])
        self.assertEqual(crosswalk["native_stark_binding"]["gates"]["G2"], "eligibility_active")

    def test_crosswalk_hash_is_stable_sha256(self):
        digest = rule_crosswalk_hash()

        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, rule_crosswalk_hash())


if __name__ == "__main__":
    unittest.main()
