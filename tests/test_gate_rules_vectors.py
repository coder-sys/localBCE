"""Gate rules vectors and the state-ZZ demo through the built Lean runner (test-only)."""

import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "lean", ".lake", "build", "bin", "gate_rules.exe" if os.name == "nt" else "gate_rules")
# The runner's own sources; Theorems.lean is checked by the build, not linked.
SOURCES = [os.path.join(ROOT, "lean", "BlindLedger", "Gate", "Rules", f) for f in ("Spec.lean", "Run.lean")]


@unittest.skipUnless(os.path.isfile(EXE),
                     f"GATE RULES VECTORS NOT RUN: {EXE} is missing; run `lake build gate_rules` in lean/")
class GateRulesVectors(unittest.TestCase):
    def test_runner_is_current(self):
        stale = [p for p in SOURCES if os.path.getmtime(p) > os.path.getmtime(EXE)]
        self.assertEqual(stale, [], "gate_rules is older than its sources; run `lake build gate_rules` in lean/")

    def test_vectors_pass(self):
        for name in ("rules_v1.vectors", "demo_zz.vectors"):
            with self.subTest(name):
                run = subprocess.run([EXE, os.path.join(ROOT, "tests", "gate_rules", name)],
                                     capture_output=True, text=True, timeout=600)
                self.assertEqual(run.returncode, 0, run.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
