"""Gate rules vectors and the state-ZZ demo through the built Lean runner (test-only)."""

import hashlib
import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEAN = os.path.join(ROOT, "lean")
EXE = os.path.join(LEAN, ".lake", "build", "bin", "gate_rules.exe" if os.name == "nt" else "gate_rules")
# The files the runner embeds (`Run.source`); Theorems.lean is checked by the build, not linked.
SOURCES = ["BlindLedger/Gate/Rules/Spec.lean", "BlindLedger/Gate/Rules/Fast.lean", "BlindLedger/Gate/Rules/Run.lean",
           "BlindLedger/Gate/Rules/RunCli.lean", "BlindLedger/Sha3.lean", "lakefile.toml", "lean-toolchain"]


@unittest.skipUnless(os.path.isfile(EXE),
                     f"GATE RULES VECTORS NOT RUN: {EXE} is missing; run `lake build gate_rules` in lean/")
class GateRulesVectors(unittest.TestCase):
    def test_runner_is_current(self):
        text = b"".join(open(os.path.join(LEAN, p), "rb").read() for p in SOURCES).replace(b"\r\n", b"\n")
        run = subprocess.run([EXE], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.stdout.split("\n")[0], "RULES_SOURCE " + hashlib.sha3_512(text).hexdigest(),
                         "gate_rules was not built from these sources; run `lake build gate_rules` in lean/")

    def test_vectors_pass(self):
        for name in ("rules_v1.vectors", "demo_zz.vectors"):
            with self.subTest(name):
                run = subprocess.run([EXE, os.path.join(ROOT, "tests", "gate_rules", name)],
                                     capture_output=True, text=True, timeout=600)
                self.assertEqual(run.returncode, 0, run.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
