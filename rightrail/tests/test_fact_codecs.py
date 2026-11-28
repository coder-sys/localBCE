"""Fact record codecs (design fact-record §2.3, §2.4, §3.2): the Python twin in app/right_rail_fact_codec.py against the
golden bytes held in lean/BlindLedger/Gate/FactCodec.lean (the one place they are written; the Lean build checks the same
bytes), round trip, length and refusal of bad input (synthetic, non-PHI)."""

import random
import re
import unittest
from pathlib import Path

from app import right_rail_fact_codec as c

LEAN_FILE = Path(__file__).resolve().parents[1] / "lean" / "BlindLedger" / "Gate" / "FactCodec.lean"
M32, M40, M64 = 2**32 - 1, 2**40 - 1, 2**64 - 1


def pat(n, s):
    return bytes((s + i) & 255 for i in range(n))


def ident(w, s):
    b = s.encode()
    return bytes([len(b)]) + b + bytes(w - 1 - len(b))


def prov(s):
    return ident(21, s) + bytes(11)


def fact(kind, op, subject, sid, vstart, vstop, until, receipt, roff, **value):
    return {"kind": kind, "op": op, "subject": subject, "sid": sid, "vstart": vstart, "vstop": vstop, "until": until,
            "receipt": receipt, "roff": roff, "value": value}


FACTS = {
    "elig_basic": fact(1, 0, pat(32, 1), pat(32, 100), 20260101, 99991231, 99991231, 5, 7, status=1, basis=1,
                       program=ident(21, "MEDICAID"), aid=ident(21, ""), determined=20260105, notice=0),
    "elig_edge": fact(1, 2, pat(32, 0), pat(32, 200), 0, 0, 0, M40, M40, status=255, basis=255,
                      program=ident(21, "X" * 20), aid=ident(21, "A"), determined=M32, notice=M32),
    "death_state": fact(2, 0, pat(32, 3), pat(32, 50), 20250314, 99991231, 99991231, 9, 1, proof=2, record=pat(64, 7)),
    "death_federal": fact(2, 0, pat(32, 3), pat(32, 60), 0, M32, M32, 0, 0, proof=1, record=bytes(64)),
    "excl_basic": fact(3, 0, prov("1234567890"), pat(32, 9), 20240101, 20271231, 99991231, 3, 12, list=1,
                       type=ident(9, "1128a1"), waiver=0),
    "excl_edge": fact(3, 1, prov(""), pat(32, 0), 0, 99991231, 0, M40, M40, list=255, type=ident(9, "12345678"),
                      waiver=255),
    "pdeath_basic": fact(4, 0, prov("9876543210"), pat(32, 33), 20260301, 99991231, 99991231, 4, 2, proof=1),
    "ack_basic": fact(5, 0, pat(32, 5), pat(32, 150), 20260210, 20260210, 99991231, 6, 40, pay=pat(72, 11), status=1,
                      amount=12345, trace=ident(51, "TRN*1*ABC123")),
    "ack_edge": fact(5, 0, pat(32, 5), pat(32, 151), 0, 0, 0, 0, 0, pay=bytes(72), status=0, amount=M64,
                     trace=ident(51, "")),
    "disc_basic": fact(6, 0, pat(32, 6), pat(32, 160), 20260401, 20260401, 99991231, 7, 3, event=2, pay=pat(72, 21),
                       amount=50000, case=ident(31, "CASE-77")),
    "disc_edge": fact(6, 1, pat(32, 6), pat(32, 161), M32, M32, M32, M40, M40, event=255, pay=bytes(72), amount=M64,
                      case=ident(31, "C" * 30)),
    "recov_basic": fact(7, 0, pat(32, 7), pat(32, 170), 20260501, 20260501, 99991231, 8, 9, pay=pat(72, 31),
                        amount=7500, source=2, ref=ident(51, "PLB-REF-1")),
    "recov_edge": fact(7, 0, pat(32, 7), pat(32, 171), 0, 0, 0, 0, 0, pay=bytes(72), amount=0, source=0,
                       ref=ident(51, "")),
}
RECEIPTS = {
    "receipt_full": {"src": 3, "cover": 1, "kb": 12, "asof": 20260102, "cfrom": 20250101, "fseq": 2026010201,
                     "file": pat(64, 40), "sender": ident(21, "STATEMMIS"), "channel": 1, "key": 1, "reader": 2,
                     "reread": 0, "rows": 1000, "admitted": 990, "same": 5, "quar": 5,
                     "scope": ident(21, "MEDICAID"), "frows": 4000},
    "receipt_edge": {"src": 65535, "cover": 4, "kb": M40, "asof": 0, "cfrom": 0, "fseq": M64, "file": bytes(64),
                     "sender": ident(21, ""), "channel": 3, "key": 0, "reader": 65535, "reread": M40, "rows": M32,
                     "admitted": M32, "same": M32, "quar": M32, "scope": ident(21, "P" * 20), "frows": M64},
}
RECEIPTS["receipt_rd"] = {**RECEIPTS["receipt_full"], "rd": pat(64, 77)}


def lean_golden():
    text = LEAN_FILE.read_text("utf-8")
    table = text.split("def golden :", 1)[1].split("def goldenFacts", 1)[0]
    return {n: bytes.fromhex(h) for n, h in re.findall(r'\("([a-z0-9_]+)",\s*"([0-9a-f]+)"\)', table)}


class FactCodecTests(unittest.TestCase):
    def test_golden_vectors_are_the_leans(self):
        golden = lean_golden()
        self.assertEqual(set(golden), set(FACTS) | set(RECEIPTS))
        for name, f in FACTS.items():
            self.assertEqual(c.encode_fact(f), golden[name], name)
            self.assertEqual(c.decode_fact(golden[name]), f, name)
        for name, r in RECEIPTS.items():
            self.assertEqual(c.encode_receipt(r), golden[name], name)
            self.assertEqual(c.decode_receipt(golden[name]), r, name)

    def test_every_kind_has_a_vector_and_a_245_byte_body(self):
        self.assertEqual({f["kind"] for f in FACTS.values()}, set(c.KINDS))
        for name, b in lean_golden().items():
            self.assertEqual(len(b), 245, name)

    def test_hand_built_layout(self):
        """Offsets written out by hand from the design tables, not taken from the codec's own field list."""
        b = c.encode_fact(FACTS["ack_basic"])
        self.assertEqual(b[0], 5)
        self.assertEqual(b[1], 0)
        self.assertEqual(b[2:34], pat(32, 5))
        self.assertEqual(b[34:66], pat(32, 150))
        self.assertEqual(b[66:70], (20260210).to_bytes(4, "little"))
        self.assertEqual(b[78:83], (6).to_bytes(5, "little"))
        self.assertEqual(b[83:88], (40).to_bytes(5, "little"))
        self.assertEqual(b[88:160], pat(72, 11))
        self.assertEqual(b[160], 1)
        self.assertEqual(b[161:169], (12345).to_bytes(8, "little"))
        self.assertEqual(b[169:220], ident(51, "TRN*1*ABC123"))
        self.assertEqual(b[220:], bytes(25))
        r = c.encode_receipt(RECEIPTS["receipt_full"])
        self.assertEqual((r[0], r[1:3], r[3], r[4:9]), (0x40, (3).to_bytes(2, "little"), 1, (12).to_bytes(5, "little")))
        self.assertEqual(r[25:89], pat(64, 40))
        self.assertEqual(r[89:110], ident(21, "STATEMMIS"))
        self.assertEqual(r[120:124], (1000).to_bytes(4, "little"))
        self.assertEqual(r[136:157], ident(21, "MEDICAID"))
        self.assertEqual(r[157:165], (4000).to_bytes(8, "little"))
        self.assertEqual(r[165:], bytes(80))
        r = c.encode_receipt(RECEIPTS["receipt_rd"])
        self.assertEqual((r[165:229], r[229:]), (pat(64, 77), bytes(16)))

    def test_value_widths_are_the_kinds_table(self):
        widths = {1: 52, 2: 65, 3: 11, 4: 1, 5: 132, 6: 112, 7: 132}
        for kind, (_, fields) in c.KINDS.items():
            self.assertEqual(sum(w for _, _, w in fields), widths[kind], kind)

    def test_wrong_length_is_refused(self):
        good = c.encode_fact(FACTS["elig_basic"])
        for bad in (b"", good[:-1], good + b"\0", good + good):
            with self.assertRaises(ValueError):
                c.decode_fact(bad)
        r = c.encode_receipt(RECEIPTS["receipt_full"])
        for bad in (b"", r[:-1], r + b"\0"):
            with self.assertRaises(ValueError):
                c.decode_receipt(bad)

    def test_unknown_kind_and_wrong_tag_are_refused(self):
        good = c.encode_fact(FACTS["elig_basic"])
        for kind in (0, 8, 9, 13, 14, 63, 0x40, 0x50, 255):
            with self.assertRaises(ValueError, msg=kind):
                c.decode_fact(bytes([kind]) + good[1:])
        r = c.encode_receipt(RECEIPTS["receipt_full"])
        for tag in (0, 1, 0x41, 255):
            with self.assertRaises(ValueError, msg=tag):
                c.decode_receipt(bytes([tag]) + r[1:])
        with self.assertRaises(ValueError):
            c.decode_fact(r)

    def test_nonzero_padding_is_refused(self):
        for name in ("elig_basic", "pdeath_basic"):
            good = bytearray(c.encode_fact(FACTS[name]))
            for at in (244, 100 + len(good) - 200):
                bad = bytearray(good)
                bad[at] = 1
                if bad[at] != good[at]:
                    with self.assertRaises(ValueError):
                        c.decode_fact(bytes(bad))
        r = bytearray(c.encode_receipt(RECEIPTS["receipt_full"]))
        r[240] = 1
        with self.assertRaises(ValueError):
            c.decode_receipt(bytes(r))

    def test_bad_fields_are_refused_on_encode(self):
        f = dict(FACTS["elig_basic"])
        for field, bad in (("vstart", 2**32), ("vstart", -1), ("subject", bytes(31)), ("sid", bytes(33)), ("op", 256)):
            with self.assertRaises(ValueError, msg=field):
                c.encode_fact({**f, field: bad})
        with self.assertRaises(ValueError):
            c.encode_fact({**f, "kind": 8})
        with self.assertRaises(ValueError):
            c.encode_fact({**f, "value": {**f["value"], "program": bytes(20)}})
        with self.assertRaises(ValueError):
            c.encode_receipt({**RECEIPTS["receipt_full"], "fseq": 2**64})

    def test_non_canonical_rows_are_refused(self):
        def flip(b, at, v):
            out = bytearray(b)
            out[at] = v
            return bytes(out)

        facts = {n: c.encode_fact(FACTS[n]) for n in FACTS}
        r = c.encode_receipt(RECEIPTS["receipt_full"])
        for bad in (flip(facts["elig_basic"], 1, 3),                     # operation 3
                    flip(facts["elig_basic"], 69, 255),                  # vstart after vstop
                    flip(facts["elig_basic"], 90 + 1 + 8, 1),            # text after the program's length
                    flip(facts["elig_basic"], 90, 21),                   # length byte over the field
                    flip(facts["elig_basic"], 112, 1),                   # byte after an empty aid
                    flip(facts["excl_basic"], 89 + 1 + 6, 1),            # type
                    flip(facts["excl_basic"], 2 + 1 + 10, 1),            # provider subject, after its identifier
                    flip(facts["excl_basic"], 2 + 25, 1),                # provider subject, trailing bytes
                    flip(facts["pdeath_basic"], 2 + 31, 1),
                    flip(facts["ack_basic"], 169 + 1 + 12, 1),           # trace
                    flip(facts["disc_basic"], 169 + 1 + 7, 1),           # case
                    flip(facts["recov_basic"], 169 + 1 + 9, 1)):         # ref
            with self.assertRaises(ValueError):
                c.decode_fact(bad)
        for bad in (flip(r, 89 + 1 + 9, 1), flip(r, 136 + 1 + 8, 1), flip(r, 89, 21), flip(r, 136, 255)):
            with self.assertRaises(ValueError):
                c.decode_receipt(bad)
        for name in ("elig_basic", "excl_basic", "pdeath_basic"):  # the unchanged rows still decode
            self.assertEqual(c.encode_fact(c.decode_fact(facts[name])), facts[name])
        with self.assertRaises(ValueError):
            c.encode_fact({**FACTS["elig_basic"], "op": 3})
        with self.assertRaises(ValueError):
            c.encode_fact({**FACTS["elig_basic"], "vstart": 5, "vstop": 4})
        with self.assertRaises(ValueError):
            c.encode_fact({**FACTS["excl_basic"], "subject": ident(21, "1") + bytes([0] * 10) + bytes([1])})

    def test_an_end_row_may_stop_before_it_starts(self):
        """Design 2.4 and 3.3: a full file with cfrom 20260201 ends a statement from 20260301 with vstop 20260131."""
        end = {**FACTS["elig_basic"], "op": 2, "vstart": 20260301, "vstop": 20260131}
        self.assertEqual(c.decode_fact(c.encode_fact(end)), end)
        for op in (0, 1):
            with self.assertRaises(ValueError):
                c.encode_fact({**end, "op": op})

    def test_whatever_decodes_encodes_back_to_the_same_bytes(self):
        rng = random.Random(7)
        seen = {"fact": [0, 0], "receipt": [0, 0]}
        for name, b in lean_golden().items():
            kind = "receipt" if name.startswith("receipt") else "fact"
            dec, enc = (c.decode_receipt, c.encode_receipt) if kind == "receipt" else (c.decode_fact, c.encode_fact)
            for _ in range(400):
                bad = bytearray(b)
                for _ in range(rng.choice((1, 1, 2))):
                    bad[rng.randrange(len(bad))] = rng.choice((0, 1, 2, 3, 255, rng.randrange(256)))
                try:
                    back = dec(bytes(bad))
                except ValueError:
                    seen[kind][1] += 1
                    continue
                seen[kind][0] += 1
                self.assertEqual(enc(back), bytes(bad), name)
                if kind == "fact":  # what decodes is well formed, checked here without the encoder
                    self.assertLess(back["op"], 3, name)
                    self.assertTrue(back["op"] == 2 or back["vstart"] <= back["vstop"], name)
                    self.assertEqual(len(back["subject"]), 32, name)
        for kind in seen:
            self.assertGreater(seen[kind][0], 0)
            self.assertGreater(seen[kind][1], 0)

    def test_round_trip_at_the_edges(self):
        for name, f in FACTS.items():
            self.assertEqual(c.decode_fact(c.encode_fact(f)), f, name)
            self.assertEqual(len(c.encode_fact(f)), 245, name)

    def test_rank_orders_by_fseq_then_reader_then_roff(self):
        self.assertLess(c.rank(1, 9, 9), c.rank(2, 0, 0))
        self.assertLess(c.rank(2, 1, 9), c.rank(2, 2, 0))
        self.assertLess(c.rank(2, 2, 0), c.rank(2, 2, 1))
        self.assertEqual(c.rank(2, 2, 1), c.rank(2, 2, 1))
        # a re-read keeps its original's fseq and has a higher reader, so it outranks the reading it replaces
        self.assertGreater(c.rank(5, 3, 0), c.rank(5, 2, 999))


if __name__ == "__main__":
    unittest.main()
