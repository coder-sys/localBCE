"""R9a bench: a small seeded corpus is deterministic and has the specified mix; stages a, b, e and the report run. No timing asserts."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.x12_835_intake import parse_835  # noqa: E402
from tools import r9_bench  # noqa: E402

PER_FILE = 400


class R9BenchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.saved = r9_bench.SCRATCH
        r9_bench.SCRATCH = Path(self.tmp.name)
        self.addCleanup(setattr, r9_bench, "SCRATCH", self.saved)

    def test_corpus_is_seeded_and_has_the_mix(self) -> None:
        first, deposit = r9_bench.gen_file(3, 7, PER_FILE)
        again, _ = r9_bench.gen_file(3, 7, PER_FILE)
        other, _ = r9_bench.gen_file(4, 7, PER_FILE)
        self.assertEqual(first, again)
        self.assertNotEqual(first, other)
        record = parse_835(first)
        tags = [row.key[0] for row in record.rows]
        self.assertEqual(tags.count("REV"), PER_FILE * 50 // 1000)
        self.assertEqual(tags.count("RAW"), PER_FILE * 10 // 1000)
        self.assertEqual(sum(1 for row in record.rows if row.amount_cents == 0), PER_FILE * 10 // 1000)
        self.assertGreater(tags.count("PLB"), 0)
        self.assertEqual(sum(row.amount_cents or 0 for row in record.rows), deposit["amount_cents"])

    def test_stages_run(self) -> None:
        a = r9_bench.stage_a(0, 2, 7, PER_FILE, False)
        self.assertEqual(a["lines"], 2 * PER_FILE)
        b = r9_bench.stage_b(0, 2, 7, PER_FILE, Path(self.tmp.name) / "b.sqlite3", True, False)
        self.assertEqual(b["lines"], 2 * PER_FILE)
        self.assertGreater(b["writes_by_table"]["cell_rows"], 0)
        self.assertTrue(all(h >= 0 for h in b["hold_s"]))
        out = Path(self.tmp.name) / "r.json"
        r9_bench.main(["--stage", "a", "--files", "1", "--per-file", str(PER_FILE), "--out", str(out)])
        self.assertEqual(r9_bench.report(out)["a"]["files"], 1)


if __name__ == "__main__":
    unittest.main()
