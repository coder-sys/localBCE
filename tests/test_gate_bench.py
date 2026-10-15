"""The step 0 bench runs, its stages add up, and E1: the Lean SHA3 twin gives the old SHA3-512, SHAKE128 and SHAKE256 bytes
over the bench's seeded stored outputs plus every rate boundary (the proof is ``Sha3FastEq.lean``; this is the differential
run of the built executables, from ``tools/sha3_bench``, which also prints the speed of both).  RR_GATE_BENCH_N / _BATCH resize
the bench run; RR_GATE_BENCH_OUT=<json> keeps its numbers."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from app import minimal_clearance_verifier_process as process
from app import right_rail_gate_decide as decider
from tests import gate_bench as bench
from tests import test_gate_rules_vectors as rules
from tests import test_gate_rules_worker as w

SHA3 = Path(rules.ROOT) / "tools" / "sha3_bench" / ".lake" / "build" / "bin" / "sha3_bench.exe"
N, BATCH = int(os.environ.get("RR_GATE_BENCH_N", 300)), int(os.environ.get("RR_GATE_BENCH_BATCH", 100))


@unittest.skipUnless(os.name == "nt" and os.path.isfile(rules.EXE) and w.WORKER.is_file(), "GATE BENCH NOT RUN: the Lean rules exes are missing")
class GateBench(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = bench.run_bench(N, BATCH, free=lambda: 1 << 62)  # injected: the result never depends on the machine
        if os.environ.get("RR_GATE_BENCH_OUT"):
            Path(os.environ["RR_GATE_BENCH_OUT"]).write_text(json.dumps({**cls.result, "corpus": None}, indent=1), "utf-8")

    def test_stages_add_up(self):
        r = self.result
        self.assertIsNone(r["wall"])
        self.assertEqual((r["lines_done"], r["batches_done"]), (N, -(-N // BATCH)))
        self.assertEqual((r["probes_ok"], r["probes"]), (r["batches_done"],) * 2)  # every replay probe was a clean PASS
        for row in r["batches"]:
            us = row["us_per_line"]
            self.assertGreater(us["lean_replay"], 0)
            self.assertAlmostEqual(sum(us[k] for k in (*bench.REPORT, "other")), us["total"], delta=0.02 * us["total"] + 1)

    def test_memory_wall_stops_the_run_and_says_why(self):
        r = bench.run_bench(BATCH, BATCH, free=lambda: 0)
        self.assertEqual((r["wall"]["reason"], r["lines_done"]), ("memory", 0))

    def test_a_wall_exits_non_zero(self):
        for wall in ({"reason": "refused:state_mismatch", "history_lines": 41000}, {"reason": "memory", "history_lines": 0}, None):
            with self.subTest(wall=wall), mock.patch.object(sys, "argv", ["gate_bench", "--sizes", "10"]), \
                    mock.patch.object(bench, "run_bench", lambda *a: {"wall": wall, "fallbacks": 0, "batches": [], "corpus": []}), \
                    contextlib.redirect_stdout(io.StringIO()):
                if wall is None:
                    bench.main()
                    continue
                with self.assertRaises(SystemExit) as stop:
                    bench.main()
                self.assertNotIn(stop.exception.code, (0, None))
                self.assertIn(wall["reason"], str(stop.exception.code))

    def test_a_worker_reloaded_every_batch_runs_through_unprobed_loads(self):
        """Every answer recycles the worker, so every batch after genesis loads in parts: no probe takes the parts (only
        genesis is probed), and the run completes."""
        with mock.patch.object(decider.RulesWorker, "RECYCLE_CAP_BYTES", -1):
            r = bench.run_bench(3 * BATCH, BATCH, free=lambda: 1 << 62)
        self.assertIsNone(r["wall"])
        self.assertEqual((r["lines_done"], r["probes_ok"], r["probes"]), (3 * BATCH, 1, 1))
        self.assertEqual([row["probed"] for row in r["batches"]], [True, False, False])
        self.assertEqual((r["fallbacks"], r["reloads"], [row["reloaded"] for row in r["batches"]]), (0, 2, [False, True, True]))

    def test_a_batch_on_the_one_shot_exe_exits_non_zero(self):
        """The worker dies once, on the second batch's resume: that batch is decided on the one-shot exe (served says so, the run
        is not a pass), the third loads the history into a new worker (a reload)."""
        real, calls = process.ContainedWorker.exchange, [0]

        def dies(self, *a, **kw):
            calls[0] += 1
            if calls[0] == 2:
                self._terminate()
            return real(self, *a, **kw)
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            with mock.patch.object(process.ContainedWorker, "exchange", dies), mock.patch.object(bench, "free_bytes", lambda: 1 << 62),                     contextlib.redirect_stdout(io.StringIO()), self.assertLogs(decider.LOG, "WARNING"), self.assertRaises(SystemExit) as stop,                     mock.patch.object(sys, "argv", ["gate_bench", "--sizes", "0,300", "--batch", "100", "--no-probe", "--out", f"{tmp}/b.json"]):
                bench.main()
            r = json.loads(Path(tmp, "b.json").read_text("utf-8"))
        self.assertIn("BENCH_FALLBACK 1", str(stop.exception.code))
        self.assertEqual((r["wall"], r["fallbacks"], r["reloads"], [x["served"] for x in r["batches"]], [x["reloaded"] for x in r["batches"]]),
                         (None, 1, 1, ["resident", "one_shot", "resident"], [False, False, True]))

    @unittest.skipUnless(SHA3.is_file(), "SHA3 TWIN NOT RUN: build tools/sha3_bench (lake build -d tools/sha3_bench)")
    def test_sha3_twin_equals_the_old_path(self):
        rng = random.Random(bench.SEED)
        data = [bytes(x) for x in self.result["corpus"] if x] + [rng.randbytes(n) for n in (0, 1, 71, 72, 73, 135, 136, 137, 143, 144, 167, 168, 169, 199, 200, 201, 271, 272, 273, 1000)]
        data.append(rng.randbytes(1 << 20))
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "in.bin"
            path.write_bytes(b"".join(len(d).to_bytes(4, "big") + d for d in data))
            out = subprocess.run([str(SHA3), str(path)], capture_output=True, text=True, timeout=600, check=True).stdout.splitlines()
            big = path.read_bytes()[: 4 << 20]
        self.assertEqual(len(out), len(data) + 3)
        for line, d in zip(out, data):
            _, old, fast = line.split()
            self.assertEqual(old, hashlib.sha3_512(d).hexdigest() + hashlib.shake_128(d).hexdigest(200) + hashlib.shake_256(d).hexdigest(200))
            self.assertEqual(fast, old)
        self.assertEqual([x.split()[1] for x in out[-3:-1]], [hashlib.sha3_512(big).hexdigest()] * 2)
        _, old_rate, fast_rate, size = out[-1].split()
        print(f"\nSHA3_TWIN inputs={len(data)} bytes={sum(map(len, data))} old={int(old_rate) / 100:.2f}MB/s fast={int(fast_rate) / 100:.2f}MB/s over {size} bytes")


if __name__ == "__main__":
    unittest.main()
