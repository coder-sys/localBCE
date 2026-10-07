"""Smoke test of tools/cfi_history_bench.py (CFI-HIST H0) at tiny sizes: every key is present and every ratio is finite.
Synthetic, non-PHI, nonpayment; proofSuiteId=null, production_usable=false, activation=false."""

import math
import unittest

from tools import cfi_history_bench as bench


class CfiHistoryBenchSmokeTests(unittest.TestCase):
    def test_tiny_bench_reports_every_key_and_finite_ratios(self):
        rows = bench.run(earlier=(4, 8), lines=(3, 6), routes=("direct", "plan"), seed_items=2, fresh_items=1, cap=3)
        self.assertEqual(len(rows), 8)
        for row in rows:
            with self.subTest(row=(row["earlier"], row["lines"], row["route"])):
                self.assertFalse(row.get("refused"), row)
                for key in ("begin_s", "finish_s", "sql_ops", "begin_ops", "finish_ops", "peak_kib", "files_wall_s", "files", *bench.RATIOS.values()):
                    self.assertTrue(math.isfinite(row[key]), key)
                self.assertGreater(row["sql_ops"], 0)
        self.assertEqual([r["files"] for r in rows if r["lines"] == 6][0], 2)
        self.assertTrue(all(r[name] == 1.0 for r in rows if r["earlier"] == 4 for name in ("begin_x", "ops_x")))


if __name__ == "__main__":
    unittest.main()
