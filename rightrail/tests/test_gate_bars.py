"""tests/_gate_bars.py: the four bars are judged from measured numbers only (a bar not measured is MISS with the reason), and the saved-frame
replay builds, runs two shards and gets the saved answers back, every checker verifying its shard."""

import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests import test_flat_worker as fw

SCRIPT = Path(__file__).resolve().parent / "_gate_bars.py"
SPEC = importlib.util.spec_from_file_location("gate_bars_tool", SCRIPT)
bars = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bars)


def sized(lines: int, cpu_e: float, cpu_c: float, private_mb: float) -> dict:
    row = {"engine": {"cpu_s": cpu_e / 1e6, "read_b": 10}, "verifier": {"cpu_s": cpu_c / 1e6, "read_b": 20}, "engine_us": 5.0}
    mem = {"private": private_mb * 1e6, "peak_private": private_mb * 1e6}
    return {"stored_lines": lines + 6000, "rows": [row, row], "engine_mem": mem, "verifier_mem": mem}


def run(*sizes) -> dict:
    return {"exit": 0, "result": {"sizes": [x["stored_lines"] - 6000 for x in sizes], "sizes_result": list(sizes)}}


def tput(rate: int, ok: bool = True, mismatches: int = 0) -> dict:
    return {"runs": {"all": [{"ok": ok, "errors": [] if ok else ["shard 0: died"], "answer_mismatches": mismatches, "pair_lines_per_s": rate}]}}


class Verdicts(unittest.TestCase):
    def verdict(self, runs, tp):
        return {b["bar"][0]: b["verdict"] for b in bars.verdicts(runs, tp, 300_000, 3_000_000)}

    def test_all_measured_within_limits_pass(self):
        r = run(sized(300_000, 15, 15, 200), sized(3_000_000, 15.5, 15.5, 300))
        self.assertEqual(self.verdict({"mixed": r, "hot": r}, {"mixed": tput(250_000), "hot": tput(210_000)}), {"S": "PASS", "T": "PASS", "H": "PASS", "M": "PASS"})

    def test_each_limit_is_enforced(self):
        r = run(sized(300_000, 25, 15, 200), sized(3_000_000, 26, 15.5, 320))  # sum 41.5 > 40, engine ratio 1.04 ok, 320 MB > 310 MB
        got = self.verdict({"mixed": r}, {"mixed": tput(199_999)})
        self.assertEqual(got, {"S": "MISS", "T": "MISS", "H": "PASS", "M": "MISS"})
        r = run(sized(300_000, 10, 10, 200), sized(3_000_000, 10, 11, 300))  # the checker alone grows 1.10x
        self.assertEqual(self.verdict({"mixed": r}, {"mixed": tput(300_000)})["H"], "MISS")

    def test_a_bar_not_measured_is_miss_with_the_reason(self):
        small = run(sized(300_000, 10, 10, 200))
        got = self.verdict({"mixed": small, "hot": {"exit": 1, "result": None}}, {})
        self.assertTrue(all(v.startswith("MISS (") for v in got.values()), got)
        self.assertIn("not measured at 3000000", self.verdict({"mixed": small}, {})["S"])
        self.assertIn("failed", self.verdict({"mixed": small, "hot": {"exit": 1, "result": None}}, {})["S"])
        self.assertIn("answers differ", self.verdict({"mixed": small}, {"mixed": tput(300_000, mismatches=3)})["T"])

    def test_per_size_numbers(self):
        p = bars.per_size(run(sized(3_000_000, 12, 8, 250))["result"])[3_000_000]
        self.assertEqual((round(p["engine_cpu_us"], 3), round(p["sum_cpu_us"], 3)), (12.0, 20.0))
        self.assertAlmostEqual(p["mem_limit_mb"], 310.108)  # 256 MB + 18 B for each of the 3,006,000 lines the store then holds


@unittest.skipUnless(os.name == "nt", "child memory counters are Windows")
class ChildMemory(unittest.TestCase):
    def test_private_is_at_most_its_peak(self):
        import subprocess
        import sys
        import time
        from tests import gate_bench as bench
        # the real interpreter: a venv's python.exe is a launcher that starts it
        child = subprocess.Popen([sys._base_executable, "-c", "x = bytearray(60_000_000); input()"], stdin=subprocess.PIPE)
        try:
            for _ in range(100):  # the child touches its 60 MB before it reads
                m = bench.child_mem(child)
                if m["private"] > 60_000_000:
                    break
                time.sleep(0.1)
            self.assertGreater(m["private"], 60_000_000, m)
            self.assertLessEqual(m["private"], m["peak_private"], m)
            self.assertGreater(m["peak_ws"], 0)
        finally:
            child.communicate(bytes([10]), timeout=30)


@unittest.skipUnless(os.name == "nt" and all((fw.BIN / n).is_file() for n in ("gate_hist3.exe", "gate_verify3.exe")), "GATE BARS REPLAY NOT RUN: build gate_hist3 and gate_verify3")
class Replay(unittest.TestCase):
    def test_two_shards_replay_their_saved_frames(self):
        os.environ["RR_E3_SPEC"], os.environ["E3_NEW_EXE"] = "64", "gate_hist3.exe"
        root = Path(tempfile.mkdtemp(prefix="gbars_", dir=os.environ.get("E3_SCRATCH")))
        try:
            a = SimpleNamespace(tp_lines=4000, batch=2000, shards=2, tp_trials=1, spec="64", frames_dir=str(root / "frames"))
            t = bars.throughput("mixed", a, root, "test")
            for name in ("one", "all"):
                (r,) = t["runs"][name]
                self.assertTrue(r["ok"], r)
                self.assertEqual((r["answer_mismatches"], r["lines"]), (0, 4000 * r["shards"]))
                self.assertTrue(all(r["verified"]) and r["checker_exit"] == [0] * r["shards"], r)
                self.assertGreater(r["pair_lines_per_s"], 0)
            again = bars.build_frames(root / "frames" / "mixed-0.frames", "mixed", 0, 4000, 2000, "test")  # saved: reused, not rebuilt
            self.assertEqual(again["frames"], 3)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
