"""The gate bench runs, its stages add up, and E1: the Lean SHA3 twin gives the old SHA3-512, SHAKE128 and SHAKE256 bytes
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
from app import right_rail_gate_decide as decider, right_rail_gate_signer as signer
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
        self.assertEqual((r["relaunches"], {row["served"] for row in r["batches"]}), (0, {"resident"}))  # a worker death would pass the rest
        for row in r["batches"]:
            us = row["us_per_line"]
            self.assertGreater(us["lean"], 0)
            self.assertAlmostEqual(sum(us[k] for k in (*bench.REPORT, "other")), us["total"], delta=0.02 * us["total"] + 1)

    def test_memory_wall_stops_the_run_and_says_why(self):
        r = bench.run_bench(BATCH, BATCH, free=lambda: 0)
        self.assertEqual((r["wall"]["reason"], r["lines_done"]), ("memory", 0))

    def test_a_wall_exits_non_zero(self):
        for wall in ({"reason": "held:hold_answer", "history_lines": 41000}, {"reason": "memory", "history_lines": 0}, None):
            with self.subTest(wall=wall), mock.patch.object(sys, "argv", ["gate_bench", "--sizes", "10"]), \
                    mock.patch.object(bench, "run_bench", lambda *a: {"wall": wall, "relaunches": 0, "batches": [], "corpus": []}), \
                    contextlib.redirect_stdout(io.StringIO()):
                if wall is None:
                    bench.main()
                    continue
                with self.assertRaises(SystemExit) as stop:
                    bench.main()
                self.assertNotIn(stop.exception.code, (0, None))
                self.assertIn(wall["reason"], str(stop.exception.code))

    def test_a_state_mismatch_hold_is_reported_under_its_own_label(self):
        hold = decider.Answer((), (), b"", b"", (0, b""), None, ())
        with mock.patch.object(bench.g, "decide_batch", lambda *a, **kw: (hold, [], {1: "HOLD state_mismatch"})):
            r = bench.run_bench(BATCH, BATCH, free=lambda: 1 << 62)
        self.assertEqual(r["wall"]["reason"], "held:state_mismatch")

    def test_a_batch_on_a_relaunched_worker_exits_non_zero(self):
        """The worker dies once, on the second batch's frame (the second rules frame: one frame per batch, nothing to drop): that batch is sent again to a relaunched worker (served says so, the
        run is not a pass), the third goes to the same new worker on the same index."""
        real, calls = process.ContainedWorker.exchange, iter(range(1, 10**9))

        def dies(self, *a, **kw):  # the rules worker only: the resident signer and verifier share ContainedWorker.exchange
            if self not in (signer._SERVER[0], signer._VSERVER[0]) and next(calls) == 2:
                self._terminate()
            return real(self, *a, **kw)
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            with mock.patch.object(process.ContainedWorker, "exchange", dies), mock.patch.object(bench, "free_bytes", lambda: 1 << 62),                     contextlib.redirect_stdout(io.StringIO()), self.assertLogs(decider.LOG, "WARNING"), self.assertRaises(SystemExit) as stop,                     mock.patch.object(sys, "argv", ["gate_bench", "--sizes", "0,300", "--batch", "100", "--out", f"{tmp}/b.json"]):
                bench.main()
            r = json.loads(Path(tmp, "b.json").read_text("utf-8"))
        self.assertIn("BENCH_RELAUNCH 1", str(stop.exception.code))
        self.assertEqual((r["wall"], r["relaunches"], [x["served"] for x in r["batches"]]), (None, 1, ["resident", "relaunched", "resident"]))

    def test_flat_bench_shape(self):
        """The index bench reports, per history size, the trials, the work and pages per line (with the engine's timers on), wall time and peak memory."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            r = bench.run_flat(sizes=(40, 80), batch=20, trials=2, work_dir=tmp, log=lambda *a: None, prof=True)["flat"]
        self.assertEqual([x["history"] for x in r], [40, 80])
        for x in r:
            self.assertEqual((x["lines"], x["trials"], len(x["peak_rss_series"])), (20, 2, 2))
            self.assertTrue(x["us_per_line_min"] <= x["us_per_line_median"] <= x["us_per_line_max"])
            self.assertGreater(x["disk_bytes"], 0)
            self.assertGreater(x["pages_per_line_mean"], 0)
            self.assertGreaterEqual(x["pages_per_line_p99"], x["pages_per_line_mean"])
            self.assertGreater(x["us_per_line_mean"], 0)
            self.assertGreater(x["peak_rss_max"], 0)

    def test_flat_bench_resumes_from_its_checkpoint(self):
        """A seed that stopped after the first size goes on to the second without rebuilding or re-measuring the first,
        with the same corpus span; a resume asking for another span is refused."""
        quiet = dict(batch=20, trials=1, log=lambda *a: None)
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            first = bench.run_flat(sizes=(40,), work_dir=tmp, span=80, **quiet)["flat"]
            with self.assertRaises(ValueError):  # another span would date the repeats differently
                bench.run_flat(sizes=(40, 80), work_dir=tmp, resume=True, span=160, **quiet)
            again = bench.run_flat(sizes=(40, 80), work_dir=tmp, resume=True, **quiet)["flat"]
        self.assertEqual((again[0], len(again)), (first[0], 2))
        self.assertGreater(again[1]["history_built"], again[0]["history_built"])

    @unittest.skipUnless(SHA3.is_file(), "SHA3 TWIN NOT RUN: build tools/sha3_bench (lake build -d tools/sha3_bench)")
    def test_sha3_twin_equals_the_old_path(self):
        rng = random.Random(bench.SEED)
        data = [bytes(x) for x in self.result["corpus"] if x] + [rng.randbytes(n) for n in (0, 1, 71, 72, 73, 135, 136, 137, 143, 144, 167, 168, 169, 199, 200, 201, 271, 272, 273, 1000)]
        data += [rng.randbytes(n) for n in list(range(2, 70)) + [rng.randrange(274, 10001) for _ in range(40)] + [4095, 4096, 4097, 10000]]
        data.append(rng.randbytes(1 << 20))
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "in.bin"
            path.write_bytes(b"".join(len(d).to_bytes(4, "big") + d for d in data))
            out = subprocess.run([str(SHA3), str(path)], capture_output=True, text=True, timeout=600, check=True).stdout.splitlines()
            big = path.read_bytes()[: 4 << 20]
        self.assertEqual(len(out), len(data) + 3)
        for line, d in zip(out, data):
            _, old, fast, quick = line.split()
            self.assertEqual(old, hashlib.sha3_512(d).hexdigest() + hashlib.shake_128(d).hexdigest(200) + hashlib.shake_256(d).hexdigest(200))
            self.assertEqual(fast, old)
            self.assertEqual(quick, hashlib.sha3_256(d).hexdigest() + hashlib.sha3_512(d).hexdigest() + hashlib.shake_128(d).hexdigest(200) + hashlib.shake_256(d).hexdigest(200) + hashlib.shake_128(d).hexdigest(700))
        self.assertEqual([x.split()[1] for x in out[-3:-1]], [hashlib.sha3_512(big).hexdigest()] * 2)
        _, old_rate, fast_rate, size = out[-1].split()
        print(f"\nSHA3_TWIN inputs={len(data)} bytes={sum(map(len, data))} old={int(old_rate) / 100:.2f}MB/s fast={int(fast_rate) / 100:.2f}MB/s over {size} bytes")


if __name__ == "__main__":
    unittest.main()
