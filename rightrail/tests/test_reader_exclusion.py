"""Exclusion list readers and their independent verifiers (conformance/EXCLUSION_V1.md) on synthetic data only: the
providers SYN... are not real.  Each reader and its verifier must give byte-equal fact rows, set-aside entries and
receipts on the golden files, and refuse every hostile file with its named cause."""

import csv
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from app import right_rail_fact_codec as codec
from app import right_rail_fact_registry as reg
from app import right_rail_reader_federal_exclusion as fed
from app import right_rail_reader_federal_exclusion_independent as fed_indep
from app import right_rail_reader_fixed_independent as fixed_indep
from app.right_rail_gate_ffs import _by_name
from app.right_rail_reader_fixed import sid
from app.right_rail_reader_leie import read_leie
from app.right_rail_reader_state_exclusion import read_state_exclusion
from app.right_rail_reader_state_exclusion_independent import verify_state_exclusion

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "excl_vectors")


def _json(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


GOLDEN = _json("golden.json")
HOSTILE = _json("hostile.json")
KW = GOLDEN["transport"]


def entry(base, over=None):
    e = {**base, **(over or {})}
    e["kinds"] = reg.mask_of(e["ids"])
    e["scope"], e["name"] = reg.ident(21, e["scope"]), reg.ident(31, e["name"])
    return e


def raw(name):
    with open(os.path.join(HERE, name), "rb") as f:
        return f.read()


class Trickle:
    """A stream that returns at most 7 bytes per read, as a pipe may."""

    def __init__(self, data):
        self.b = io.BytesIO(data)

    def read(self, n):
        return self.b.read(min(n, 7))

    def readline(self, n):
        return self.b.readline(n)


def scratch_run(go):
    """go(tmp); the scratch directory must be empty afterwards, refused or not."""
    with tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH")) as tmp:
        try:
            return go(tmp)
        finally:
            left = os.listdir(tmp)
            if left:
                raise AssertionError(f"left {left} in scratch")


def run_state(fn, data, e=None, stream=io.BytesIO):
    rows = []
    receipt = scratch_run(lambda tmp: fn(stream(data), e or entry(GOLDEN["state_entry"]), rows.append, scratch=tmp,
                                         **KW))
    return tuple(rows), receipt


def run_fed(fn, data, e=None, args=None, stream=io.BytesIO):
    rows, aside = [], []
    a = {**GOLDEN["federal_args"], **(args or {})}
    receipt = scratch_run(lambda tmp: fn(stream(data), e or entry(GOLDEN["federal_entry"]), rows.append, aside.append,
                                         scratch=tmp, **a, **KW))
    return tuple(rows), tuple(aside), receipt


def subject(npi):
    return reg.ident(21, npi) + bytes(11)


def names(entry_bytes):
    """(line, why, type block, [last, first, middle, business]) of a set-aside entry."""
    at, out = 15, []
    for _ in range(4):
        n = int.from_bytes(entry_bytes[at:at + 2], "little")
        out.append(entry_bytes[at + 2:at + 2 + n].decode())
        at += 2 + n
    assert at == len(entry_bytes)
    return int.from_bytes(entry_bytes[:5], "little"), entry_bytes[5], entry_bytes[6:15], out


class StateExclusionTest(unittest.TestCase):
    def test_golden_files_byte_equal(self):
        for g in GOLDEN["state"]:
            data = raw(g["name"])
            got = run_state(read_state_exclusion, data)
            self.assertEqual(got, run_state(verify_state_exclusion, data), g["name"])
            self.assertEqual(got, run_state(read_state_exclusion, data, stream=Trickle), g["name"])
            self.assertEqual(got, run_state(verify_state_exclusion, data, stream=Trickle), g["name"])
            self.assertEqual([s.hex() for s in got[0]], g["statements"], g["name"])
            self.assertEqual(got[1].hex(), g["receipt"], g["name"])

    def test_full_file_fields(self):
        e = entry(GOLDEN["state_entry"])
        self.assertTrue(reg.registry_ok([e]))
        statements, receipt = run_state(read_state_exclusion, raw("full.sexc"), e)
        r = codec.decode_receipt(receipt)
        self.assertTrue(reg.shape_ok(e, r))
        self.assertEqual((r["src"], r["cover"], r["asof"], r["rows"], r["quar"], r["frows"]), (9, 1, 20261031, 4, 0, 4))
        rows = [codec.decode_fact(s) for s in statements]
        reinstated = rows[1]
        npi = reinstated["subject"][1:11].decode()
        self.assertEqual(reinstated["subject"], subject(npi))
        self.assertEqual((reinstated["kind"], reinstated["vstart"], reinstated["vstop"], reinstated["roff"]),
                         (3, 20220301, 20250630, 2))
        self.assertEqual(reinstated["value"], {"list": 2, "type": reg.ident(9, "SPI-B2"), "waiver": 0})
        self.assertEqual(reinstated["sid"], sid(9, 3, [npi.encode(), b"SPI-B2", b"20220301"]))
        self.assertEqual([(f["vstart"], f["vstop"]) for f in rows],
                         [(20240115, reg.OPEN), (20220301, 20250630), (20261031, reg.OPEN), (20190101, 20191231)])
        change = codec.decode_fact(run_state(read_state_exclusion, raw("change.sexc"))[0][0])
        self.assertEqual((change["vstart"], change["vstop"]), (20261101, 20261101))  # a one-day exclusion

    def test_hostile_files_refused_by_both(self):
        self.assertEqual(len(HOSTILE["state"]), 29)
        for c in HOSTILE["state"]:
            data, e = c["data"].encode("latin-1"), entry(GOLDEN["state_entry"], c.get("entry"))
            for fn in (read_state_exclusion, verify_state_exclusion):
                with self.subTest(case=c["name"], impl=fn.__name__):
                    with self.assertRaises(Exception) as cm:
                        run_state(fn, data, e)
                    self.assertEqual(getattr(cm.exception, "cause", repr(cm.exception)), c["cause"])


class FederalExclusionTest(unittest.TestCase):
    def test_golden_files_byte_equal(self):
        for g in GOLDEN["federal"]:
            data = raw(g["name"])
            got = run_fed(fed.read_federal_exclusion, data, args=g["args"])
            for fn, stream in ((fed_indep.verify_federal_exclusion, io.BytesIO), (fed.read_federal_exclusion, Trickle),
                               (fed_indep.verify_federal_exclusion, Trickle)):
                self.assertEqual(got, run_fed(fn, data, args=g["args"], stream=stream), (g["name"], fn.__name__))
            self.assertEqual([s.hex() for s in got[0]], g["statements"], g["name"])
            self.assertEqual([a.hex() for a in got[1]], g["aside"], g["name"])
            self.assertEqual(got[2].hex(), g["receipt"], g["name"])

    def test_full_list_rows(self):
        e = entry(GOLDEN["federal_entry"])
        self.assertTrue(reg.registry_ok([e]))
        statements, aside, receipt = run_fed(fed.read_federal_exclusion, raw("full.csv"), e)
        r = codec.decode_receipt(receipt)
        self.assertTrue(reg.shape_ok(e, r))
        self.assertEqual((r["src"], r["cover"], r["asof"], r["cfrom"], r["rows"], r["quar"], r["frows"]),
                         (10, 1, 20261031, 20261031, 22, 7, 29))
        facts = {f["roff"]: f for f in map(codec.decode_fact, statements)}
        span = {n: (f["vstart"], f["vstop"]) for n, f in facts.items()}
        forever = (10101, reg.OPEN)
        self.assertEqual(span, {1: (20200101, reg.OPEN), 2: (20180501, 20210228), 3: (20230101, reg.OPEN),
                                4: (20230101, reg.OPEN), 5: (20230101, reg.OPEN),
                                6: forever, 7: forever, 8: forever, 9: forever, 10: (20200101, reg.OPEN),
                                11: forever, 18: forever, 19: (10101, 20201231), 20: forever,
                                21: (20230101, reg.OPEN), 23: (20230101, reg.OPEN), 25: (20230101, reg.OPEN),
                                26: (20261031, reg.OPEN), 27: (20200101, 20261030), 28: (20200101, 20240229),
                                29: (20200101, reg.OPEN), 30: (20200101, reg.OPEN)})
        # On or before the start (25: on it), our state.  Rows 21 and 23 are each repeated with and without a waiver
        # (waiver 1 first, then waiver 0 first): the fact takes waiver 0 either way.  Rows 29 and 30 would have one
        # but a field the rule reads (type, reinstatement) did not read.
        self.assertEqual({n for n, f in facts.items() if f["value"]["waiver"]}, {3, 25})
        self.assertEqual(facts[10]["value"]["type"], bytes(9))  # a type of no known shape is empty
        self.assertEqual(facts[2]["value"], {"list": 1, "type": reg.ident(9, "1128b4"), "waiver": 0})
        npi = facts[2]["subject"][1:11].decode()
        self.assertEqual(facts[2]["sid"], sid(10, 3, [npi.encode(), b"1128b4", b"20180501", b"20210228"]))
        got = [names(a) for a in aside]
        self.assertEqual([(n, why) for n, why, _, _ in got],
                         [(12, 1), (13, 2), (14, 3), (15, 4), (16, 5), (22, 5), (24, 5)])
        self.assertEqual(got[1][3], ["SYNBADNPI", "KA", "", ""])
        self.assertEqual(got[2][2], bytes(9))
        # The claim path holds by name exactly the rows whose why is 2 or 3.
        leie = read_leie(raw("full.csv"), source="LEIE", as_of="2026-10-31")
        held = {r.last_name for r in leie.rows if r.offset in _by_name(leie)}
        self.assertEqual(held, {nm[0] for _, why, _, nm in got if why in (2, 3)})
        # Every claim-path row with an NPI is a fact for that NPI.
        self.assertEqual({r.npi for r in leie.rows if r.npi} - {f["subject"][1:11].decode() for f in facts.values()},
                         set())

    def test_crlf_line_ends(self):
        """CR LF line ends give the same rows and entries; only the file's hash in the receipt differs.  (The checked-in
        files are LF: the repository stores text as LF.)"""
        lf = raw("full.csv")
        crlf = lf.replace(b"\n", b"\r\n")
        for fn in (fed.read_federal_exclusion, fed_indep.verify_federal_exclusion):
            a, b = run_fed(fn, lf), run_fed(fn, crlf)
            self.assertEqual(a[:2], b[:2], fn.__name__)
            ra, rb = codec.decode_receipt(a[2]), codec.decode_receipt(b[2])
            self.assertNotEqual(ra.pop("file"), rb.pop("file"))
            self.assertEqual(ra, rb, fn.__name__)

    def test_supplement(self):
        g = GOLDEN["federal"][1]
        statements, aside, receipt = run_fed(fed.read_federal_exclusion, raw(g["name"]), args=g["args"])
        r = codec.decode_receipt(receipt)
        self.assertEqual((r["cover"], r["cfrom"], r["rows"], r["quar"], r["frows"]), (2, 0, 1, 0, 1))
        self.assertEqual(codec.decode_fact(statements[0])["value"]["type"], reg.ident(9, "BRCH CIA"))

    def test_hostile_files_refused_by_both(self):
        self.assertEqual(len(HOSTILE["federal"]), 25)
        for c in HOSTILE["federal"]:
            data, e = c["data"].encode("latin-1"), entry(GOLDEN["federal_entry"], c.get("entry"))
            for fn in (fed.read_federal_exclusion, fed_indep.verify_federal_exclusion):
                with self.subTest(case=c["name"], impl=fn.__name__):
                    with self.assertRaises(Exception) as cm:
                        run_fed(fn, data, e, c.get("args"))
                    self.assertEqual(getattr(cm.exception, "cause", repr(cm.exception)), c["cause"])

    def test_size_cap(self):
        data = raw("full.csv")
        with mock.patch.object(fed, "MAX_FILE_BYTES", len(data) - 1), \
                mock.patch.object(fed_indep, "_MAX_BYTES", len(data) - 1):
            for fn in (fed.read_federal_exclusion, fed_indep.verify_federal_exclusion):
                with self.assertRaises(Exception) as cm:
                    run_fed(fn, data)
                self.assertEqual(cm.exception.cause, "file_too_large", fn.__name__)

    def test_repeats_found_across_sorted_runs(self):
        """The verifier's on-disk sort, forced to many small runs, finds the same repeats as the reader."""
        head, row, rest = raw("full.csv").split(b"\n", 2)
        data = head + b"\n" + (row + b"\n") * 5 + rest
        with mock.patch.object(fixed_indep, "_RUN", 2), mock.patch.object(fixed_indep, "_FAN", 2):
            got = run_fed(fed_indep.verify_federal_exclusion, data)
        self.assertEqual(got, run_fed(fed.read_federal_exclusion, data))
        self.assertEqual([a[5] for a in got[1]][:4], [5, 5, 5, 5])

    def test_repeats_narrow_the_fact(self):
        """With the NPI alone as the statement identity, rows of one NPI that differ are one fact with the most
        restrictive reading: the earliest start, the latest end (none when any row has none), waiver 0 when any row
        has 0; the first row's line, identity and type stay.  Both implementations agree, with the verifier's sort
        forced to many small runs too."""
        lines = raw("full.csv").split(b"\n")
        cols = lines[0].decode().split(",")

        def variant(i, **cells):
            v = dict(zip(cols, next(csv.reader([lines[i].decode()]))))
            v.update(cells)
            s = io.StringIO()
            csv.writer(s, lineterminator="").writerow([v[c] for c in cols])
            return s.getvalue().encode()

        data = b"\n".join([lines[0],
                           variant(1, EXCLDATE="20220101", REINDATE="20240101"),  # 1: 2022-01-01 to 2023-12-31
                           variant(1, EXCLDATE="20200101", REINDATE="20230101", EXCLTYPE="1128b7"),  # 2: earlier start
                           variant(3, REINDATE="20250101"),  # 3: waiver 1, to 2024-12-31
                           variant(3, REINDATE="20240101"),  # 4: waiver 1, to 2023-12-31
                           variant(1, EXCLDATE="20210101"),  # 5: no end
                           b""])
        e = entry(GOLDEN["federal_entry"], {"ids": [[3, [1]]]})
        got = run_fed(fed.read_federal_exclusion, data, e)
        self.assertEqual(got, run_fed(fed_indep.verify_federal_exclusion, data, e))
        with mock.patch.object(fixed_indep, "_RUN", 2), mock.patch.object(fixed_indep, "_FAN", 2):
            self.assertEqual(got, run_fed(fed_indep.verify_federal_exclusion, data, e))
        a, b = map(codec.decode_fact, got[0])
        npi = a["subject"][1:11].decode()
        self.assertEqual((a["roff"], a["sid"], a["vstart"], a["vstop"], a["value"]),
                         (1, sid(10, 3, [npi.encode()]), 20200101, reg.OPEN,
                          {"list": 1, "type": reg.ident(9, "1128a1"), "waiver": 0}))
        self.assertEqual((b["roff"], b["vstart"], b["vstop"], b["value"]["waiver"]), (3, 20230101, 20241231, 1))
        self.assertEqual([names(x)[:2] for x in got[1]], [(2, 5), (4, 5), (5, 5)])
        r = codec.decode_receipt(got[2])
        self.assertEqual((r["rows"], r["quar"], r["frows"]), (2, 3, 5))


if __name__ == "__main__":
    unittest.main()
