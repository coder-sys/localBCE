"""The fact frame (design fact-record §2.10): the Python twin in app/right_rail_fact_frame.py against the golden bytes
held in lean/BlindLedger/Gate/FactFrame.lean (the one place they are written; the Lean build checks the same bytes and
the same refusals), the layout by hand, each refusal and the retry rule (synthetic, non-PHI)."""

import hashlib
import re
import unittest
from pathlib import Path

from app import right_rail_fact_codec as c
from app import right_rail_fact_frame as f
from tests.test_fact_codecs import FACTS, M40, RECEIPTS, pat

LEAN_FILE = Path(__file__).resolve().parents[1] / "lean" / "BlindLedger" / "Gate" / "FactFrame.lean"


def row(name, **change):
    """A wire row: the fact vector without `until` and `receipt`."""
    w = {k: v for k, v in FACTS[name].items() if k not in ("until", "receipt")}
    return {**w, **change}


R0, R1, R2 = row("elig_basic"), row("death_state"), row("excl_basic")
RECEIPT = {**RECEIPTS["receipt_full"], "kb": 0, "admitted": 0, "same": 0, "rows": 3}
REQUEST = {"shard": 7, "batch": 42, "prev": pat(64, 200), "pin": pat(64, 100), "receipt": RECEIPT,
           "rows": [R0, R1, R2]}


def body_with(rows=None, receipt=None):
    return f.encode_body(REQUEST["prev"], REQUEST["pin"], receipt or RECEIPT,
                         REQUEST["rows"] if rows is None else rows)


def patch(b, at, v):
    return b[:at] + bytes([v]) + b[at + 1:]


BODY = body_with()
RQ = hashlib.sha3_512(b"RR/GATE/FACTS/v1\x00" + BODY).digest()
ANSWER = {"shard": 7, "batch": 42, "digest": RQ, "entries": [(1, 0, 5), (3, 9, 77), (4, 0, M40)],
          "head": pat(64, 1), "root": pat(64, 2), "rs": bytes(64), "items": 0, "money": 0}


def vectors():
    return {"request": f.encode_request(REQUEST), "answer": f.encode_answer(ANSWER)}


def lean_golden():
    text = LEAN_FILE.read_text("utf-8")
    table = text.split("def golden :", 1)[1].split("def goldenOk", 1)[0]
    return {n: bytes.fromhex(h) for n, h in re.findall(r'\("([a-z0-9_]+)",\s*"([0-9a-f]+)"\)', table)}


class FactFrameTests(unittest.TestCase):
    def refusal(self, b):
        with self.assertRaises(f.Refused) as cm:
            f.decode_request(b)
        return cm.exception.word

    def test_golden_vectors_are_the_leans(self):
        golden = lean_golden()
        self.assertEqual(golden, vectors())
        self.assertEqual(f.decode_request(golden["request"]), (REQUEST, RQ))
        self.assertEqual(f.decode_answer(golden["answer"]), ANSWER)

    def test_hand_built_layout(self):
        """Offsets written out by hand from §2.10, not taken from the twin's own constants."""
        b = f.encode_request(REQUEST)
        self.assertEqual(len(b), 420 + 236 * 3)
        self.assertEqual(b[:6], b"RRDF\x01\x00")
        self.assertEqual(b[6:10], (7).to_bytes(4, "little"))
        self.assertEqual(b[10:18], (42).to_bytes(8, "little"))
        self.assertEqual(b[18:82], hashlib.sha3_512(b"RR/GATE/FACTS/v1\x00" + b[82:]).digest())
        body = b[82:]
        self.assertEqual(body[0:64], pat(64, 200))
        self.assertEqual(body[64:128], pat(64, 100))
        self.assertEqual(body[128:165], bytes(37))
        self.assertEqual(body[165:330], c.encode_receipt(RECEIPT)[:165])
        self.assertEqual(body[330:334], (3).to_bytes(4, "little"))
        for i, w in enumerate(REQUEST["rows"]):
            stored = c.encode_fact({**w, "until": 0, "receipt": 0})
            self.assertEqual(body[334 + 236 * i:334 + 236 * (i + 1)], stored[:74] + stored[83:])
        self.assertEqual(body[1042:], bytes(4))
        a = f.encode_answer(ANSWER)
        self.assertEqual(len(a), 87 + 7 * 3 + 200)
        self.assertEqual(a[:7], b"RRDA\x03\x00\x00")
        self.assertEqual(a[19:23], (3).to_bytes(4, "little"))
        self.assertEqual(a[23:87], RQ)
        self.assertEqual(a[94:101], bytes([3, 9, 77, 0, 0, 0, 0]))
        self.assertEqual(a[108:172], pat(64, 1))
        self.assertEqual(a[236:300], bytes(64))
        self.assertEqual(a[300:], bytes(8))

    def test_refusals_in_byte_order(self):
        """The same frames and words as the Lean `refusals` table."""
        b = f.encode_request(REQUEST)
        cases = {
            "short header": (b[:81], "LENGTH"),
            "magic": (b"RRDQ" + b[4:], "MAGIC"),
            "version": (b[:4] + b"\x02\x00" + b[6:], "MAGIC"),
            "digest": (b[:18] + bytes(64) + b[82:], "DIGEST"),
            "digest before order": (b[:18] + bytes(64) + body_with(rows=[R2, R1, R0]), "DIGEST"),
            "authority": (f.frame(7, 42, patch(BODY, 133, 1)), "RECORD"),
            "engine-set kb": (f.frame(7, 42, patch(BODY, 169, 1)), "RECORD"),
            "count": (f.frame(7, 42, body_with(receipt={**RECEIPT, "rows": 2})), "RECORD"),
            "end row": (f.frame(7, 42, patch(BODY, 335, 2)), "RECORD"),
            "order": (f.frame(7, 42, body_with(rows=[R2, R1, R0])), "RECORD"),
            "duplicate": (f.frame(7, 42, body_with(rows=[R0, R0, R1])), "RECORD"),
            "proofs": (f.frame(7, 42, BODY[:-4] + (1).to_bytes(4, "little")), "RECORD"),
            "short body": (f.frame(7, 42, BODY[:-1]), "LENGTH"),
            "trailing": (f.frame(7, 42, BODY + b"\x00"), "LENGTH"),
            "roff as a number": (f.frame(7, 42, body_with(rows=[row("elig_basic", roff=256),
                                                                 row("elig_basic", roff=1), R1])), "RECORD"),
        }
        for name, (frame, word) in cases.items():
            self.assertEqual(self.refusal(frame), word, name)

    def test_roff_orders_as_a_number(self):
        q = {**REQUEST, "rows": [row("elig_basic", roff=1), row("elig_basic", roff=256), R1]}
        b = f.encode_request(q)
        self.assertEqual(f.decode_request(b), (q, b[18:82]))

    def test_encode_takes_only_canonical_requests(self):
        for q in ({**REQUEST, "rows": [R1, R0, R2]}, {**REQUEST, "rows": [R0, R1]}, {**REQUEST, "prev": bytes(63)}):
            with self.assertRaises(ValueError):
                f.encode_request(q)
        with self.assertRaises(ValueError):
            f.encode_row({**R0, "op": 2})
        with self.assertRaises(ValueError):
            f.encode_receipt({**RECEIPT, "same": 1})

    def test_answer_refusals(self):
        a = f.encode_answer(ANSWER)
        for bad in (a[:-1], a + b"\x00", patch(a, 0, 0x51), patch(a, 4, 1), patch(a, 6, 1), patch(a, 87, 0),
                    patch(a, 87, 5), patch(a, 88, 1)):
            with self.assertRaises(ValueError):
                f.decode_answer(bad)
        for entries in ([(2, 1, 0)], [(0, 0, 0)], [(5, 0, 0)], [(1, 0, 2**40)]):
            with self.assertRaises(ValueError):
                f.encode_answer({**ANSWER, "entries": entries})

    def test_retry(self):
        log = [(b"d1", b"a1"), (RQ, b"a2")]
        e = {"shard": 7, "head": pat(64, 200), "log": log}

        def q(**k):
            return {**REQUEST, **k}

        self.assertEqual(f.retry(e, q(batch=2), RQ), ("replay", b"a2"))
        self.assertEqual(f.retry(e, q(batch=2), b"other"), ("refuse", "CONFLICT"))
        self.assertEqual(f.retry(e, q(batch=3), RQ), ("decide",))
        self.assertEqual(f.retry(e, q(batch=3, prev=pat(64, 1)), RQ), ("refuse", "HEAD"))
        for batch in (0, 1, 4, 2**64 - 1):
            self.assertEqual(f.retry(e, q(batch=batch), RQ), ("refuse", "NOT_NEXT"), batch)
        self.assertEqual(f.retry({**e, "log": log[:1]}, q(batch=1), b"d1"), ("refuse", "NOT_NEXT"))
        self.assertEqual(f.retry({"shard": 7, "head": None, "log": []}, q(batch=1), RQ), ("refuse", "NOT_NEXT"))
        self.assertEqual(f.retry(e, q(shard=8, batch=2), RQ), ("refuse", "SHARD"))


if __name__ == "__main__":
    unittest.main()
