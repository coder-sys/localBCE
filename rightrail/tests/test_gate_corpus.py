"""The synthetic claim history is reproducible, streams without holding the history, has the stated mix, and its repeats are
real repeats of earlier claims (test-only; synthetic, non-PHI)."""

import itertools
import tracemalloc
import unittest
from collections import Counter

from tests import gate_corpus as c
from tests import gate_bench as bench

N, SPAN = 100_000, 100_000


def fields(row):
    p = row.split()
    return (int(p[0].split(":")[0]), *map(int, p[2:]))


class GateCorpus(unittest.TestCase):
    def test_same_seed_same_lines_and_any_stretch_regenerates(self):
        whole = list(c.lines(5, 0, 3000, SPAN))
        self.assertEqual(whole, list(c.lines(5, 0, 3000, SPAN)))
        self.assertEqual(whole[1200:1300], list(c.lines(5, 1200, 100, SPAN)))
        self.assertNotEqual(whole[:50], list(c.lines(6, 0, 50, SPAN)))

    def test_the_mix_is_the_stated_one(self):
        got = Counter(c.kind(1, i) for i in range(N))
        for name, share in (("new", 900), ("retry", 30), ("duplicate", 35), ("near", 20), ("correction", 15)):
            self.assertAlmostEqual(got[name] / N * 1000, share, delta=max(4, share * 0.2), msg=name)

    def test_repeats_are_real_repeats_of_earlier_claims(self):
        seen, exact, near = {}, set(), set()
        for i, row in enumerate(c.lines(2, 0, 20_000, SPAN)):
            ident, m, p, r, d, code, u, a = fields(row)
            ek, nk, what = (m, p, d, code, u, a), (m, r, d, code), c.kind(2, i)
            if what == "new":
                self.assertNotIn(ident, seen)
            elif what == "retry":
                self.assertEqual(seen[ident], row.split(" ", 1)[1])
            elif what == "duplicate":
                self.assertNotIn(ident, seen)
                self.assertIn(ek, exact)
            else:
                self.assertNotIn(ident, seen)
                self.assertNotIn(ek, exact)
                self.assertIn(nk, near)
            seen.setdefault(ident, row.split(" ", 1)[1])
            exact.add(ek)
            near.add(nk)

    def test_five_years_of_dates_in_order(self):
        days = [fields(x)[4] for x in c.lines(3, 0, SPAN, SPAN)]
        self.assertEqual((min(days), max(days) >= 20270313), (20220315, True))

    def test_streaming_holds_no_history(self):
        tracemalloc.start()
        for _ in itertools.islice(c.lines(4, 10_000_000, 60_000, 300_000_000), 60_000):
            pass
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertLess(peak, 100_000)

    def test_sizes_read_as_written(self):
        self.assertEqual([bench.size(x) for x in ("300k", "3M", "30M", "300M", "1234")], [300_000, 3_000_000, 30_000_000, 300_000_000, 1234])


if __name__ == "__main__":
    unittest.main()
