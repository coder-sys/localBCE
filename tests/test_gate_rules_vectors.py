"""Gate rules vectors and the state-ZZ demo through the built Lean runner (test-only)."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

from tools import gate_rules_data

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEAN = os.path.join(ROOT, "lean")
EXE = os.path.join(LEAN, ".lake", "build", "bin", "gate_rules.exe" if os.name == "nt" else "gate_rules")
# The files the runner embeds (`Run.source`); Theorems.lean is checked by the build, not linked.
SOURCES = ["BlindLedger/Gate/Rules/Spec.lean", "BlindLedger/Gate/Rules/Fast.lean", "BlindLedger/Gate/Rules/Run.lean",
           "BlindLedger/Gate/Rules/Resident.lean", "BlindLedger/Gate/Engine/OneProc.lean", "BlindLedger/Gate/Anchor.lean", "BlindLedger/Gate/Spec.lean", "BlindLedger/Sha3.lean", "BlindLedger/Sha3Fast.lean", "lakefile.toml", "lean-toolchain"]
# The twin's equality proof and the Spec's theorems; the runner does not import them, so only this test notices a stale proof.
PROOFS = ["BlindLedger.Gate.Rules.FastEq", "BlindLedger.Gate.Rules.Resident", "BlindLedger.Gate.Rules.Theorems", "BlindLedger.Sha3FastEq",
          "BlindLedger.Gate.ReadManifest"]


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

    def reads(self, frame):
        """The frame's (`RULES_DIGEST`s, `RULES_READS`s), with `?` pins filled."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "reads.vectors")
            open(path, "w").write("\n".join(gate_rules_data.pin(frame)))
            run = subprocess.run([EXE, path], capture_output=True, text=True, timeout=600)
        out = run.stdout.split("\n")
        return [[r.split(" ")[1] for r in out if r.startswith(t)] for t in ("RULES_DIGEST ", "RULES_READS ")]

    def test_genesis_reads_bind_the_starting_sets(self):
        """Two genesis batches differing only in the declared `released` rows read different bases."""
        line = "901 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500"
        body = ["snap unresolved 20270315 0 ?", "case g", "line 902 FFS_CLAIM 1002 7002 7002 20270306 99214 1 300",
                "owners 0 902:0:0", "commit", "end 0"]
        a = self.reads(["today 20270315", "snap released 20270315 0 ?", *body])[1]
        b = self.reads(["today 20270315", "snap released 20270315 1 ?", "released " + line, *body])[1]
        self.assertEqual((len(a), len(b)), (1, 1))
        self.assertNotEqual(a, b)

    def test_reads_are_the_read_set_bytes(self):
        """`RULES_READS` is recomputed here: u32 today ‖ pins ‖ u32 |P| ‖ P, P the READ-SET/v2 bytes over the declared
        sets' STATE/v1 digest, then the first commit's (kind absent, a redo in the order read, two commits)."""
        frame = ["today 20270315", "snap released 20270315 0 ?", "snap unresolved 20270315 0 ?",
                 "snap dmf 20270301 2 ?", "dmf 9002 20261120", "dmf 9001 20270110",
                 "snap pdeath 20270301 1 ?", "pdeath 7701 20270120",
                 "snap excl 20270310 2 ?", "excl 7802 20260101 20270131", "excl 504 20260101 99991231",
                 "case reads", "line 901 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500", "owners 0 901:0:0", "commit",
                 "redo 11", "redo 12", "line 902 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500", "owners 0 902:0:0",
                 "commit", "end 0"]
        digests, reads = self.reads(frame)
        self.assertEqual((len(digests), len(reads)), (2, 2))

        def be4(*ns):
            return b"".join(n.to_bytes(4, "big") for n in ns)

        def hashed(domain, kind, asof, rows):
            return hashlib.sha3_512(domain.encode() + b"\0" + be4(kind, asof, len(rows)) + b"".join(sorted(rows))).digest()

        kinds = [("dmf", 1, "DMF", 20270301, [("9002", "20261120"), ("9001", "20270110")]),
                 ("pdeath", 2, "PROVIDER-DEATH", 20270301, [("7701", "20270120")]),
                 ("excl", 3, "EXCLUSION", 20270310, [("7802", "20260101", "20270131"), ("504", "20260101", "99991231")]),
                 ("span", 4, "ENROLLMENT", None, None)]
        pins, slots = b"", b""
        for name, k, tag, asof, rows in kinds:
            if rows is None:
                pins, slots = pins + bytes(64), slots + b"\0"
                continue
            rs = [gate_rules_data.row(name, r) for r in rows]
            pins += hashed("RR/GATE/SNAPSHOT/v1", k, asof, rs)
            slots += b"\x01" + hashed(f"RR/GATE/READ-{tag}/v2", k, asof, rs)
        genesis = hashlib.sha3_512(b"RR/GATE/STATE/v1\0" + hashed("RR/GATE/RELEASED/v1", 5, 20270315, []) +
                                   hashed("RR/GATE/UNRESOLVED/v1", 6, 20270315, [])).digest()
        for i, (redo, base) in enumerate([([], genesis), ([12, 11], bytes.fromhex(digests[0]))]):
            pre = b"RR/GATE/READ-SET/v2\0" + slots + be4(len(redo)) + b"".join(
                r.to_bytes(gate_rules_data.PAY, "big") for r in redo) + base
            self.assertEqual(reads[i], (be4(20270315) + pins + be4(len(pre)) + pre).hex(), f"commit {i}")


if __name__ == "__main__":
    unittest.main()
