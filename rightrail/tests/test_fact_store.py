"""The `facts` file and the links files (design fact-record §2.1-§2.7, §9): the Python twin in
app/right_rail_fact_store.py against the golden bytes held in lean/BlindLedger/Gate/FactStore.lean (the one place they
are written; the Lean build checks the same bytes), the sample chains the Lean checks name, the rebuild from the log
byte for byte at every batch boundary, and refusal of a changed link, a changed tag or a missing row (synthetic,
non-PHI)."""

import re
import unittest
from pathlib import Path

from app import right_rail_fact_codec as codec
from app import right_rail_fact_store as s
from tests.test_fact_codecs import FACTS, RECEIPTS, ident, pat

LEAN_FILE = Path(__file__).resolve().parents[1] / "lean" / "BlindLedger" / "Gate" / "FactStore.lean"


def le(w, v):
    return v.to_bytes(w, "little")


def lean_golden():
    table = LEAN_FILE.read_text("utf-8").split("def golden :", 1)[1].split("#guard", 1)[0]
    return {n: bytes.fromhex(h) for n, h in re.findall(r'\("([a-z_]+)",\s*"([0-9a-f]+)"\)', table)}


def entry(seq, receipt, fkind, vstart, vstop, until, dec):
    return {"seq": seq, "receipt": receipt, "fkind": fkind, "vstart": vstart, "vstop": vstop, "until": until, "dec": dec}


SUMMARY = {"tag": 0x51, "member": pat(32, 1), "kb": 7, "cut": 20230101, "old": 0, "more": 0,
           "entries": [entry(3, 1, 1, 20260101, 99991231, 99991231, 1), entry(5, 1, 0x81, 20260101, 99991231, 99991231, 0)]}
MARKER = {"src": 3, "fkind": 1, "subject": pat(32, 1), "receipt": 5, "roff": 9, "cause": 2, "sidk": 1, "sid": pat(32, 100)}
_ZERO = dict.fromkeys(["line", "cents", "entitled", "verdict", "wbatch", "windex", "cause", "link", "identified",
                       "discovered", "deadline", "reg", "due", "refunded", "questioned", "allocated", "available",
                       "noticed", "under"], 0)
MONEY = dict(_ZERO, form=1, mkind=1, okey=pat(72, 11), line=4, cents=30000, entitled=25000, verdict=1, wbatch=9,
             windex=3, cause=5, identified=20260301, reg=2, due=5000)
PLB = dict(_ZERO, form=2, mkind=8, okey=ident(21, "1234567890") + ident(31, "PLB-REF-1") + le(4, 202603) + bytes(16),
           cents=12000, cause=7, link=6, available=12000)
FACT = FACTS["elig_basic"]
RECEIPT = RECEIPTS["receipt_full"]

# A receipt, a fact row, a marker and a summary of one member, another fact row of it, two money rows of one payment,
# the source's next receipt of the same file, and a provider-level balance (the Lean `sampleBodies`).
BODIES = [codec.encode_receipt(RECEIPT), codec.encode_fact(FACT), s.encode_marker(MARKER), s.encode_summary(SUMMARY),
          codec.encode_fact(dict(FACT, sid=pat(32, 101))), s.encode_money(MONEY), s.encode_money(dict(MONEY, cents=100)),
          codec.encode_receipt(dict(RECEIPT, fseq=2026010202)), s.encode_money(PLB)]
CHAINS = [[(0, 1), (0, 1)], [(0, 1)], [(2, 2)], [(0, 1)], [(3, 3)], [(0, 1)], [(6, 2)], [(1, 2), (1, 2)], [(0, 1)]]

TAIL = {"batch": 9, "windex": 3, "reasons": 0x11, "rule": 1, "day": 20260301}


def row(m, p, r):
    return bytes(124) + pat(32, m) + pat(21, p) + pat(21, r) + bytes(47)


ROWS = [(row(1, 2, 3), TAIL), (row(4, 2, 5), dict(TAIL, windex=4)), (row(1, 6, 3), dict(TAIL, batch=10, windex=0, rule=5))]


def link_column(f):
    return b"".join(f[i * s.RECORD + s.BODY:(i + 1) * s.RECORD] for i in range(len(f) // s.RECORD))


def batches(xs, cuts):
    """`xs` split before each index of `cuts`."""
    edges = [0, *cuts, len(xs)]
    return [xs[a:b] for a, b in zip(edges, edges[1:])]


class FactStoreTests(unittest.TestCase):
    def test_golden_vectors_are_the_leans(self):
        golden = lean_golden()
        mine = {"summary": s.encode_summary(SUMMARY), "marker": s.encode_marker(MARKER), "money": s.encode_money(MONEY),
                "plb": s.encode_money(PLB), "facts_links": link_column(s.facts_writer(BODIES)[0]),
                "links_file": s.links_writer(ROWS)[0], "lift": s.encode_lift(7, [(1, 7), (300, 2 ** 40 - 1)])}
        self.assertEqual(set(golden), set(mine))
        for name, b in mine.items():
            self.assertEqual(b, golden[name], name)

    def test_round_trip_and_tags(self):
        kinds = ["receipt", "fact", "marker", "summary", "fact", "money", "money", "receipt", "money"]
        self.assertEqual([s.decode_body(b)[0] for b in BODIES], kinds)
        self.assertEqual(s.decode_summary(BODIES[3]), SUMMARY)
        self.assertEqual(s.decode_marker(BODIES[2]), MARKER)
        self.assertEqual((s.decode_money(BODIES[5]), s.decode_money(BODIES[8])), (MONEY, PLB))
        self.assertEqual(s.decode_tail(s.encode_tail(TAIL)), TAIL)
        lift = s.encode_lift(7, [(1, 7), (300, 2 ** 40 - 1)])
        self.assertEqual((s.decode_body(lift), s.chain_keys(lift)), (("lift", {"receipt": 7, "lifts": [(1, 7), (300, 2 ** 40 - 1)]}), []))
        for bad in (lift[:6] + bytes([0]) + lift[7:], lift[:6] + bytes([24]) + lift[7:], lift[:6] + bytes([1]) + lift[7:]):
            with self.assertRaises(ValueError):
                s.decode_lift(bad)
        self.assertTrue(all(len(b) == s.BODY for b in BODIES))

    def test_hand_built_layout(self):
        """Offsets written out by hand from the design tables, as the Lean checks state them."""
        b = s.encode_summary(SUMMARY)
        self.assertEqual(b[0:33], bytes([0x51]) + pat(32, 1))
        self.assertEqual(b[33:42], le(5, 7) + le(4, 20230101))
        self.assertEqual(b[52:64], bytes([2]) + le(5, 3) + le(5, 1) + bytes([1]))
        self.assertEqual((b[87], b[101:]), (0x81, bytes(144)))
        m = s.encode_money(MONEY)
        self.assertEqual((m[0:3], m[3:75]), (bytes([0x60, 1, 1]), pat(72, 11)))
        self.assertEqual(m[75:97], le(5, 4) + le(8, 30000) + le(8, 25000) + bytes([1]))
        self.assertEqual(m[97:113], le(8, 9) + le(3, 3) + le(5, 5))
        self.assertEqual((m[118:122], m[130:139]), (le(4, 20260301), bytes([2]) + le(8, 5000)))
        p = s.encode_money(PLB)
        self.assertEqual((p[3:24], p[108:118]), (ident(21, "1234567890"), le(5, 7) + le(5, 6)))
        self.assertEqual((p[163:171], p[187:]), (le(8, 12000), bytes(58)))

    def test_refusals(self):
        bad_sums = [dict(SUMMARY, tag=0x53), dict(SUMMARY, entries=SUMMARY["entries"] * 5)]
        for x in bad_sums:
            self.assertRaises(ValueError, s.encode_summary, x)
        body = bytearray(s.encode_summary(SUMMARY))
        body[52] = 9  # n above eight
        self.assertRaises(ValueError, s.decode_summary, bytes(body))
        body[52] = 1  # one entry listed, a second one left in the padding
        self.assertRaises(ValueError, s.decode_summary, bytes(body))
        bad_money = [dict(MONEY, mkind=6), dict(MONEY, form=3), dict(MONEY, form=5), dict(MONEY, verdict=3),
                     dict(PLB, mkind=1), dict(PLB, line=1), dict(PLB, okey=pat(72, 1))]
        for x in bad_money:
            self.assertRaises(ValueError, s.encode_money, x)
        self.assertRaises(ValueError, s.encode_marker, dict(MARKER, cause=0))
        self.assertRaises(ValueError, s.encode_tail, dict(TAIL, rule=3))
        for b in (bytes([0x41]) + bytes(244), bytes([0x60]) + bytes(244), BODIES[0][:244]):
            self.assertRaises(ValueError, s.decode_body, b)

    def test_sample_chains(self):
        links, tab = s.run({}, 0, [s.chain_keys(b) for b in BODIES])
        self.assertEqual(links, CHAINS)
        self.assertEqual(tab[b"\x03" + pat(32, 1)], (3, 1))  # the member's summary
        self.assertEqual(tab[b"\x05" + pat(8, 40)], (7, 2))  # the file hash: two receipts
        f = s.facts_writer(BODIES)[0]
        self.assertEqual(len(f), 9 * s.RECORD)
        self.assertEqual(f[4 * s.RECORD + s.BODY:5 * s.RECORD], le(5, 3) + le(2, 3) + bytes(4))

    def test_rebuild_from_the_log_at_every_cut(self):
        """facts_projection and links_projection: load at a batch boundary, append the rest, get the whole log's file."""
        whole = s.facts_writer(BODIES)
        for cuts in ([], [4], [1, 3, 8], list(range(1, 9))):
            log = batches(BODIES, cuts)
            for k in range(len(log) + 1):
                w = s.load_facts(s.facts_writer([b for batch in log[:k] for b in batch])[0])
                for batch in log[k:]:
                    w = s.put_facts(w, batch)
                self.assertEqual(w, whole, (cuts, k))
        lw = s.links_writer(ROWS)
        for k in range(4):
            w = s.load_links([r for r, _ in ROWS[:k]], s.links_writer(ROWS[:k])[0])
            self.assertEqual(s.put_links(w, ROWS[k:]), lw, k)

    def test_load_refuses_a_file_its_records_do_not_derive(self):
        f = s.facts_writer(BODIES)[0]
        self.assertEqual(s.load_facts(f)[1], 9)
        for at, v in ((2 * s.RECORD + s.BODY, 0), (3 * s.RECORD, 0x53), (s.RECORD + s.BODY + 8, 1)):
            g = bytearray(f)
            g[at] = v
            self.assertIsNone(s.load_facts(bytes(g)), at)
        self.assertIsNone(s.load_facts(f + bytes(1)))
        lf = s.links_writer(ROWS)[0]
        rows = [r for r, _ in ROWS]
        self.assertIsNotNone(s.load_links(rows, lf))
        g = bytearray(lf)
        g[37] = 0
        self.assertIsNone(s.load_links(rows, bytes(g)))
        self.assertIsNone(s.load_links(rows[:2], lf))
        self.assertIsNone(s.load_links([rows[0], rows[2], rows[1]], lf))


if __name__ == "__main__":
    unittest.main()
