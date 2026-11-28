"""State death file reader and its independent verifier (conformance/STATE_DEATH_V1.md) on synthetic data only: the
members SYN... are not real people.  Both must give byte-equal fact rows and receipts on the golden files, and refuse
every hostile file with its named cause."""

import hashlib
import io
import json
import os
import tempfile
import unittest

from app import right_rail_fact_codec as codec
from app import right_rail_fact_registry as reg
from app.right_rail_gate_ffs import member_key
from app.right_rail_reader_fixed import sid
from app.right_rail_reader_state_death import read_state_death
from app.right_rail_reader_state_death_independent import verify_state_death

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "death_vectors")


def _json(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


GOLDEN = _json("golden.json")
SECRET = GOLDEN["secret"].encode()
KW = GOLDEN["transport"]


def entry(over=None):
    e = {**GOLDEN["entry"], **(over or {})}
    e["kinds"] = reg.mask_of(e["ids"])
    e["scope"], e["name"] = reg.ident(21, e["scope"]), reg.ident(31, e["name"])
    return e


def raw(name):
    with open(os.path.join(HERE, name), "rb") as f:
        return f.read()


class Trickle:
    """A stream that returns at most 7 bytes per call, as a pipe may."""

    def __init__(self, data):
        self.b = io.BytesIO(data)

    def read(self, n):
        return self.b.read(min(n, 7))

    def readline(self, n):
        return self.b.readline(n)


def run(fn, data, e=None, stream=io.BytesIO):
    """(fact rows, receipt) from ``fn``; the scratch directory must be empty afterwards, refused or not."""
    rows = []
    with tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH")) as tmp:
        try:
            receipt = fn(stream(data), SECRET, e or entry(), rows.append, scratch=tmp, **KW)
        finally:
            left = os.listdir(tmp)
            if left:
                raise AssertionError(f"{fn.__name__} left {left} in scratch")
    return tuple(rows), receipt


class StateDeathReaderTest(unittest.TestCase):
    def test_golden_files_byte_equal(self):
        for g in GOLDEN["files"]:
            data = raw(g["name"])
            got = run(read_state_death, data)
            self.assertEqual(got, run(verify_state_death, data), g["name"])
            self.assertEqual(got, run(read_state_death, data, stream=Trickle), g["name"])
            self.assertEqual(got, run(verify_state_death, data, stream=Trickle), g["name"])
            self.assertEqual([s.hex() for s in got[0]], g["statements"], g["name"])
            self.assertEqual(got[1].hex(), g["receipt"], g["name"])

    def test_full_file_fields(self):
        data = raw("full.death")
        e = entry()
        self.assertTrue(reg.registry_ok([e]))
        statements, receipt = run(read_state_death, data, e)
        r = codec.decode_receipt(receipt)
        self.assertTrue(reg.shape_ok(e, r))
        self.assertEqual((r["src"], r["cover"], r["asof"], r["cfrom"], r["fseq"], r["rows"], r["frows"], r["quar"]),
                         (8, 1, 20261031, 20261031, 51, 4, 4, 0))
        self.assertEqual(r["file"], hashlib.sha3_512(data).digest())
        rows = [codec.decode_fact(s) for s in statements]
        key = member_key(SECRET, "SYN0000001")
        first = rows[0]
        self.assertEqual((first["kind"], first["op"], first["subject"], first["sid"], first["roff"]),
                         (2, 0, key, sid(8, 2, [key]), 1))
        self.assertEqual((first["vstart"], first["vstop"], first["until"]), (20260315, reg.OPEN, reg.OPEN))
        row = data.split(b"\n")[1]
        keyed = hashlib.sha3_512(len(SECRET).to_bytes(2, "big") + SECRET + b"RR/GATE/DEATH-RECORD/v1\x00" + row)
        self.assertEqual(first["value"], {"proof": 1, "record": keyed.digest()})
        # Unkeyed, the record could be matched by hashing guessed member ids with the date in vstart.
        self.assertNotIn(hashlib.sha3_512(row).digest(), b"".join(statements))
        self.assertEqual([f["vstart"] for f in rows], [20260315, 20240229, 19991231, 20261031])
        self.assertNotIn(b"SYN0000001", b"".join(statements))  # the raw member id never leaves the reader

    def test_change_file_proof_2(self):
        statements, receipt = run(read_state_death, raw("change.death"))
        self.assertEqual(codec.decode_fact(statements[0])["value"]["proof"], 2)
        self.assertEqual(codec.decode_receipt(receipt)["cover"], 2)

    def test_hostile_files_refused_by_both(self):
        cases = _json("hostile.json")
        self.assertEqual(len(cases), 28)
        for c in cases:
            data, e = c["data"].encode("latin-1"), entry(c.get("entry"))
            for fn in (read_state_death, verify_state_death):
                with self.subTest(case=c["name"], impl=fn.__name__):
                    with self.assertRaises(Exception) as cm:
                        run(fn, data, e)
                    self.assertEqual(getattr(cm.exception, "cause", repr(cm.exception)), c["cause"])


if __name__ == "__main__":
    unittest.main()
