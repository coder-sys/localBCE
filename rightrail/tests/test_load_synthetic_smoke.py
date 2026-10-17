"""Smoke test for tests/instruments/load_synthetic.py: a tiny real run of each path, its history round trip, and its bounds."""

import tempfile
import unittest
from pathlib import Path

from tests.instruments.load_synthetic import run


class LoadSyntheticSmokeTest(unittest.TestCase):
    def test_tiny_runs_complete_single_and_batched(self) -> None:
        for batch in (0, 5):
            with self.subTest(batch=batch), tempfile.TemporaryDirectory() as tmp:
                result = run(n=12, seed=7, batch=batch, history=Path(tmp) / "history")
                self.assertEqual((result["evidence_class"], result["n_completed"], result["stopped_by"]), ("measured, local laptop, synthetic", 12, None))
                self.assertGreater(result["commands_per_sec"], 0)
                self.assertLessEqual(0, result["latency_ms"]["p50"], result["latency_ms"]["p99"])
                self.assertGreater(result["store_size_bytes"], 0)
                self.assertIsNotNone(result["history"]["tamper_refusal"])

    def test_bounds_are_enforced(self) -> None:
        for n, batch in ((1_000_000, 0), (0, 0), (12, 1_001)):
            with self.subTest(n=n, batch=batch), self.assertRaises(SystemExit):
                run(n=n, seed=1, batch=batch)


if __name__ == "__main__":
    unittest.main()
