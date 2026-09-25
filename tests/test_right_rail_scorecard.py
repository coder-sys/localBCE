"""Felt-value scorecard ratchet (CONSTITUTION Art. XII, XIII.5).

Reruns the Hospital H journey through the real staff server and staff.js and
fails if any measured unit is worse than docs/scorecard/hospital_h.json in its
direction. An improvement passes but is printed so the file gets rewritten with
`python tools/right_rail_scorecard.py --write`.
"""

import json
import unittest

from tools import right_rail_scorecard as scorecard

class FeltValueScorecardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.measured = scorecard.measure()
        except scorecard.HarnessUnavailable as missing:
            raise unittest.SkipTest(f"scorecard not executed: {missing}")
        cls.committed = json.loads(scorecard.SCORECARD_PATH.read_text(encoding="utf-8"))

    def test_committed_card_is_current_and_honest(self):
        card = scorecard.build_scorecard(self.measured)
        self.assertEqual(self.committed["claims"], card["claims"])
        self.assertEqual([unit["id"] for unit in self.committed["units"]], [unit["id"] for unit in card["units"]])
        for unit in self.committed["units"]:
            self.assertTrue(unit["manual_before"]["evidence"].startswith(("assumption (source:", "unknown")), unit["id"])

    def test_no_measured_unit_got_worse(self):
        worse, better = [], []
        for unit in self.committed["units"]:
            was, now = unit["after"]["value"], self.measured["units"][unit["id"]]
            sign = 1 if unit["direction"] == "lower" else -1
            if sign * (now - was) > 0:
                worse.append(f"{unit['id']}: {was} -> {now} ({unit['role']}, {unit['moment']})")
            elif now != was:
                better.append(f"{unit['id']}: {was} -> {now}")
        if better:
            print("\nScorecard improved; rewrite docs/scorecard/hospital_h.json:\n  " + "\n  ".join(better))
        self.assertEqual(worse, [], "felt-value regression (Art. XII)")

if __name__ == "__main__":
    unittest.main()
