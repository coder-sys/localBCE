"""Smoke test of tools/cfi_history_bench.py (CFI-HIST H0) at tiny sizes: every key is present and every ratio is finite.
Synthetic, non-PHI, nonpayment; proofSuiteId=null, production_usable=false, activation=false."""

import math
import unittest

from tools import cfi_history_bench as bench


class CfiHistoryBenchSmokeTests(unittest.TestCase):
    def test_tiny_bench_reports_every_key_and_finite_ratios(self):
        rows = bench.run(earlier=(4, 8), lines=(3, 6), routes=("direct", "plan"), seed_items=2, fresh_items=1, cap=3, samples=3)
        self.assertEqual(len(rows), 8)
        for row in rows:
            with self.subTest(row=(row["earlier"], row["lines"], row["route"])):
                self.assertFalse(row.get("refused"), row)
                for key in ("begin_s", "finish_s", "sql_ops", "begin_ops", "finish_ops", "peak_kib", "files_wall_s", "files", "counts_s", "load_s", *bench.RATIOS.values(), *(f"{step}_{end}" for step in bench.STEPS for end in ("min", "max"))):
                    self.assertTrue(math.isfinite(row[key]), key)
                self.assertGreater(row["sql_ops"], 0)
                self.assertEqual(row["samples"], 3)
                self.assertTrue(all(row[step + "_min"] <= row[step] <= row[step + "_max"] for step in bench.STEPS))
                self.assertGreater(row["load_s"], 0)  # begin's obligations and cases load was timed
                self.assertEqual(len(row["per_sample"]), 3)
                for sample in row["per_sample"]:  # a median of each column can break this by chance, a sample cannot
                    self.assertGreaterEqual(sample["begin_s"], sample["counts_s"] + sample["load_s"])
        self.assertEqual([r["files"] for r in rows if r["lines"] == 6][0], 2)
        self.assertTrue(all(r[name] == 1.0 for r in rows if r["earlier"] == 4 for name in ("begin_x", "ops_x")))


if __name__ == "__main__":
    unittest.main()
