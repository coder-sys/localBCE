"""Gate rules vectors and the state-ZZ demo through the built Lean runner (test-only)."""

import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "lean", ".lake", "build", "bin", "gate_rules.exe" if os.name == "nt" else "gate_rules")


@unittest.skipUnless(os.path.isfile(EXE), f"gate_rules runner not built: {EXE} (lake build gate_rules)")
class GateRulesVectors(unittest.TestCase):
    def test_vectors_pass(self):
        for name in ("rules_v1.vectors", "demo_zz.vectors"):
            with self.subTest(name):
                run = subprocess.run([EXE, os.path.join(ROOT, "tests", "gate_rules", name)],
                                     capture_output=True, text=True, timeout=600)
                self.assertEqual(run.returncode, 0, run.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
