"""Design test, still red: the rules vectors must check the anchor.  It moves
into tests/test_gate_rules_vectors.py with that commit.  Synthetic, non-PHI."""

from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AnchorRunTests(unittest.TestCase):
    def test_rules_vectors_check_the_anchor(self) -> None:  # Run decides only anchored
        text = (ROOT / "tests" / "gate_rules" / "rules_v2.vectors").read_text("utf-8")
        self.assertRegex(text, r"(?m)^anchor [0-9a-f]{128}$")
        self.assertRegex(text, r"(?m)^case \S*unanchored")


if __name__ == "__main__":
    unittest.main()
