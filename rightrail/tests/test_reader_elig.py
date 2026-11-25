"""Eligibility extract reader and its independent verifier (conformance/ELIG_EXTRACT_V1.md) on synthetic data only:
the members SYN... are not real people.  Both must give byte-equal fact rows and receipts on the golden files, and
refuse every hostile file with its named cause."""

import hashlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from app import right_rail_fact_codec as codec
from app import right_rail_fact_registry as reg
from app import right_rail_reader_fixed as fixed
from app import right_rail_reader_fixed_independent as indep
from app.right_rail_gate_ffs import member_key
from app.right_rail_reader_elig import read_elig
from app.right_rail_reader_elig_independent import verify_elig
from app.right_rail_reader_fixed import sid

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "elig_vectors")


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


class EligReaderTest(unittest.TestCase):
    def test_golden_files_byte_equal(self):
        for g in GOLDEN["files"]:
            data = raw(g["name"])
            got = run(read_elig, data)
            self.assertEqual(got, run(verify_elig, data), g["name"])
            self.assertEqual(got, run(read_elig, data, stream=Trickle), g["name"])  # short reads change nothing
            self.assertEqual(got, run(verify_elig, data, stream=Trickle), g["name"])
            self.assertEqual([s.hex() for s in got[0]], g["statements"], g["name"])
            self.assertEqual(got[1].hex(), g["receipt"], g["name"])

    def test_full_file_fields(self):
        data = raw("full.elig")
        e = entry()
        self.assertTrue(reg.registry_ok([e]))
        statements, receipt = run(read_elig, data, e)
        r = codec.decode_receipt(receipt)
        self.assertTrue(reg.shape_ok(e, r))  # the registry would take this receipt's shape
        self.assertEqual((r["src"], r["cover"], r["asof"], r["cfrom"], r["fseq"], r["rows"], r["frows"], r["quar"]),
                         (7, 1, 20261031, 20261031, 42, 5, 5, 0))
        self.assertEqual(r["file"], hashlib.sha3_512(data).digest())
        self.assertEqual((r["sender"], r["scope"]), (reg.ident(21, "SYNSTATE-ELIG"), e["scope"]))
        rows = [codec.decode_fact(s) for s in statements]
        first = rows[0]
        key = member_key(SECRET, "SYN0000001")
        self.assertEqual((first["kind"], first["op"], first["subject"], first["roff"], first["receipt"]), (1, 0, key, 1, 0))
        self.assertEqual(first["sid"], sid(7, 1, [key, b"SEG-0001"]))
        self.assertEqual((first["vstart"], first["vstop"], first["until"]), (20260101, reg.OPEN, reg.OPEN))
        self.assertEqual(first["value"], {"status": 1, "basis": 1, "program": reg.ident(21, "MEDICAID-FFS"),
                                          "aid": reg.ident(21, "ABD"), "determined": 20251215, "notice": 20251216})
        self.assertEqual([(f["value"]["status"], f["value"]["basis"]) for f in rows], [(1, 1), (2, 2), (3, 1), (4, 3), (1, 4)])
        self.assertEqual(len({f["sid"] for f in rows}), 5)  # one segment key under three members: three identities
        self.assertNotIn(b"SYN0000001", b"".join(statements))  # the raw member id never leaves the reader

    def test_change_and_empty_files(self):
        change = codec.decode_receipt(run(read_elig, raw("change.elig"))[1])
        self.assertEqual((change["cover"], change["cfrom"], change["rows"]), (2, 0, 1))
        statements, receipt = run(read_elig, raw("empty.elig"), entry({"cfrom_rule": 1}))
        self.assertEqual(statements, ())
        r = codec.decode_receipt(receipt)
        self.assertEqual((r["cover"], r["cfrom"], r["rows"], r["frows"]), (1, 0, 0, 0))  # all of history: cfrom 0

    def test_sid_is_the_lean_rule(self):
        # Obligations/Ident.lean: obligSidOf (pat 64 1) "pop-1" "item-1", the same rule with src 0 and kind 14.
        self.assertEqual(sid(0, 14, [bytes(range(1, 65)), b"pop-1", b"item-1"]).hex(),
                         "ab7b3e6622e26ebbd778bccea3f8b5407e06cba277b48e94c1ddf6fe2efccdbb")

    def test_verifier_merge_passes(self):
        # Runs of 2 merged 2 at a time: five identities make three runs and two merge passes; a repeat across runs is found.
        with mock.patch.object(indep, "_RUN", 2), mock.patch.object(indep, "_FAN", 2):
            self.assertEqual(run(verify_elig, raw("full.elig")), run(read_elig, raw("full.elig")))
            with self.assertRaises(indep.Refused) as cm:
                run(verify_elig, raw("full.elig"), entry({"ids": [[1, [2]]]}))
            self.assertEqual(cm.exception.cause, "duplicate_key")

    def test_size_cap(self):
        # The cap lowered to the golden file's size: that size is read, one byte less is refused by both.
        data = raw("full.elig")
        for cap, refused in ((len(data), False), (len(data) - 1, True)):
            with mock.patch.object(fixed, "MAX_FILE_BYTES", cap), mock.patch.object(indep, "_MAX_BYTES", cap):
                for fn in (read_elig, verify_elig):
                    with self.subTest(cap=cap, impl=fn.__name__):
                        if not refused:
                            self.assertEqual(len(run(fn, data)[0]), 5)
                            continue
                        with self.assertRaises(Exception) as cm:
                            run(fn, data)
                        self.assertEqual(getattr(cm.exception, "cause", None), "file_too_large")

    def test_hostile_files_refused_by_both(self):
        cases = _json("hostile.json")
        self.assertEqual(len(cases), 40)
        for c in cases:
            data, e = c["data"].encode("latin-1"), entry(c.get("entry"))
            for fn in (read_elig, verify_elig):
                with self.subTest(case=c["name"], impl=fn.__name__):
                    with self.assertRaises(Exception) as cm:
                        run(fn, data, e)
                    self.assertEqual(getattr(cm.exception, "cause", repr(cm.exception)), c["cause"])


if __name__ == "__main__":
    unittest.main()
