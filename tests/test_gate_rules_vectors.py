"""Gate rules vectors and the state-ZZ demo through the built Lean runner (test-only)."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEAN = os.path.join(ROOT, "lean")
EXE = os.path.join(LEAN, ".lake", "build", "bin", "gate_rules.exe" if os.name == "nt" else "gate_rules")
# The files the runner embeds (`Run.source`); Theorems.lean is checked by the build, not linked.
SOURCES = ["BlindLedger/Gate/Rules/Spec.lean", "BlindLedger/Gate/Rules/Fast.lean", "BlindLedger/Gate/Rules/Run.lean",
           "BlindLedger/Gate/Anchor.lean", "BlindLedger/Gate/Spec.lean", "BlindLedger/Sha3.lean", "BlindLedger/Sha3Fast.lean", "lakefile.toml", "lean-toolchain"]
# The twin's equality proof and the Spec's theorems; the runner does not import them, so only this test notices a stale proof.
PROOFS = ["BlindLedger.Gate.Rules.FastEq", "BlindLedger.Gate.Rules.Theorems", "BlindLedger.Sha3FastEq"]


@unittest.skipUnless(os.path.isfile(EXE),
                     f"GATE RULES VECTORS NOT RUN: {EXE} is missing; run `lake build gate_rules` in lean/")
class GateRulesVectors(unittest.TestCase):
    def test_runner_is_current(self):
        text = b"".join(open(os.path.join(LEAN, p), "rb").read() for p in SOURCES).replace(b"\r\n", b"\n")
        run = subprocess.run([EXE], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.stdout.split("\n")[0], "RULES_SOURCE " + hashlib.sha3_512(text).hexdigest(),
                         "gate_rules was not built from these sources; run `lake build gate_rules` in lean/")

    def test_proofs_are_current(self):
        lake = shutil.which("lake") or os.path.join(os.path.expanduser("~"), ".elan", "bin", "lake")
        run = subprocess.run([lake, "build", "--no-build", *PROOFS], cwd=LEAN, capture_output=True, text=True, timeout=600)
        self.assertEqual(run.returncode, 0, "the FastEq or Theorems proofs are stale; run `lake build` in lean/\n" + run.stdout[-1500:])

    def test_vectors_pass(self):
        for name in ("rules_v1.vectors", "demo_zz.vectors", "shards_v1.vectors"):
            with self.subTest(name):
                run = subprocess.run([EXE, os.path.join(ROOT, "tests", "gate_rules", name)],
                                     capture_output=True, text=True, timeout=600)
                self.assertEqual(run.returncode, 0, run.stdout[-2000:])

    def test_flipped_adds_byte_is_refused(self):
        """One changed byte of the stored adds no longer hashes to the signed anchor: `load` refuses (STATE_MISMATCH)."""
        path = os.path.join(ROOT, "tests", "gate_rules", "shards_v1.vectors")
        lines = open(path).read().split("\n")
        i = next(n for n, line in enumerate(lines) if line.startswith("load "))
        f = lines[i].split(" ")
        f[2] = f[2][:-1] + ("0" if f[2][-1] != "0" else "1")
        lines[i] = " ".join(f)
        with tempfile.TemporaryDirectory() as d:
            flipped = os.path.join(d, "flipped.vectors")
            open(flipped, "w").write("\n".join(lines))
            run = subprocess.run([EXE, flipped], capture_output=True, text=True, timeout=600)
        self.assertEqual(run.returncode, 1)
        self.assertIn("RULES_STATE_MISMATCH load", run.stdout)

    def test_dash_is_zero_rows_and_still_checked(self):
        """`load ASOF - ANCHOR` is an empty add list: it matches only the empty sets' digest."""
        lines = open(os.path.join(ROOT, "tests", "gate_rules", "shards_v1.vectors")).read().split("\n")
        head = lines[: next(n for n, line in enumerate(lines) if line.startswith("case "))]
        load = next(line for line in lines if line.startswith("load ")).split(" ")

        def run(*body):
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "dash.vectors")
                open(path, "w").write("\n".join([*head, *body, "owners 0", "commit", "end 0"]))
                return subprocess.run([EXE, path], capture_output=True, text=True, timeout=600)

        empty = next(r for r in run("case empty").stdout.split("\n") if r.startswith("RULES_DIGEST ")).split(" ")[1]
        ok = run("case dash", f"load {load[1]} - {empty}")
        self.assertEqual(ok.returncode, 0, ok.stdout[-1000:])
        self.assertIn("RULES_DIGEST " + empty, ok.stdout)
        bad = run("case dash", f"load {load[1]} - {load[3]}")
        self.assertEqual(bad.returncode, 1)
        self.assertIn("RULES_STATE_MISMATCH load", bad.stdout)


if __name__ == "__main__":
    unittest.main()
