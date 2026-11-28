"""The cost floor of one obligations command (one-store design 16.3, step 0): `obligations_cost` prints one COST line.

Nothing passes or fails on the figures. The test runs the Lean build's `obligations_cost` (never pinned) on the hospital
scenario's first obligation and the first accepted ML-DSA-87 vector, and checks only that the line parses. The line and
the repeat counts are printed, so they are in the raw log of the guarded run."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests import test_obligations_shard as shard

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "lean" / ".lake" / "build" / "bin" / ("obligations_cost.exe" if os.name == "nt" else "obligations_cost")
VECTORS = ROOT / "tests" / "gate_vectors" / "mldsa87_acvp.vectors"
FIELDS = ("perm_ns", "sha3_512_1k_ns", "record_dec_ns", "record_enc_ns", "probe_ns", "insert_ns", "evaluate_small_ns", "mldsa_verify_us")
LINE = re.compile(r"COST " + " ".join(rf"{name}=(\d+\.\d+)" for name in FIELDS))


class ObligationsCostTests(unittest.TestCase):
    def test_cost_line_parses(self) -> None:
        self.assertTrue(EXE.exists(), f"the Lean build has no obligations_cost program at {EXE}")
        scratch = os.environ.get("E3_SCRATCH")
        if scratch:
            Path(scratch).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch or None) as work:
            wire = Path(work) / "hospital.blfin02"
            wire.write_bytes(shard.Scenario().wire)
            run = subprocess.run([str(EXE), str(wire), str(VECTORS)], capture_output=True, text=True, timeout=600)
        sys.stderr.write(run.stderr)
        sys.stderr.write(run.stdout)
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = run.stdout.splitlines()
        self.assertEqual(len(lines), 1, run.stdout)
        found = LINE.fullmatch(lines[0])
        self.assertIsNotNone(found, lines[0])
        self.assertEqual(len(found.groups()), len(FIELDS))


if __name__ == "__main__":
    unittest.main()
