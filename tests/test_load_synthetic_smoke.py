"""Fast smoke test for the synthetic load harness (tools/load_synthetic.py).

Runs the harness at a tiny N end-to-end (real FinancialOwner, real temp
SQLite store, no mocks) and asserts the JSON result has the shape the
guarded load run depends on. This is a smoke test only, not the guarded
measurement run itself -- keep it fast.
"""

from __future__ import annotations

import unittest

from tools.load_synthetic import run


class LoadSyntheticSmokeTest(unittest.TestCase):
    def test_tiny_run_produces_expected_shape_and_cleans_up(self) -> None:
        result = run(n=12, seed=7)

        self.assertEqual(result["evidence_class"], "measured, local laptop, synthetic")
        self.assertEqual(result["n_requested"], 12)
        self.assertEqual(result["n_completed"], 12)
        self.assertFalse(result["aborted_early"])

        steady = result["steady_state"]
        self.assertEqual(steady["commands"], 12)
        self.assertGreater(steady["commands_per_sec"], 0)
        for key in ("p50", "p95", "p99"):
            self.assertIn(key, steady["latency_ms"])
            self.assertGreaterEqual(steady["latency_ms"][key], 0)
        self.assertEqual(sum(steady["command_mix_counts"].values()), 12)

        overall = result["overall"]
        self.assertGreater(overall["commands"], steady["commands"])
        self.assertGreater(overall["commands_per_sec"], 0)

        self.assertGreater(result["store_size_bytes"], 0)
        self.assertIn("value", result["peak_rss"])
        self.assertIn("note", result["peak_rss"])
        self.assertEqual(result["lean_engine_launch"]["count"], 0)

    def test_bounds_are_enforced(self) -> None:
        with self.assertRaises(SystemExit):
            run(n=1_000_000, seed=1)
        with self.assertRaises(SystemExit):
            run(n=0, seed=1)


if __name__ == "__main__":
    unittest.main()
