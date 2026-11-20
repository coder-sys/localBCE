"""Tests for the eligibility (kind 7) snapshot builder, scripts/elig_snapshot.py.

Design: docs/integration/TRUNK_STEP3_ELIG_PRODUCER_DESIGN.md sections 8.1 and 8.2 (the reference-checker half; the
`gate_rules` exe half needs a Lean build and is not run here).  Synthetic, hand-written, non-PHI data only.  Generated
files go to a temporary directory; nothing is written into rightrail/.
"""

import contextlib
import datetime
import hashlib
import io
import json
import os
import random
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import elig_snapshot as esn  # noqa: E402

if esn.RIGHTRAIL not in sys.path:
    sys.path.append(esn.RIGHTRAIL)  # for app.right_rail_x12_837 (read only); appended, so it shadows nothing
_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True  # importing from rightrail/ must leave no __pycache__ there
try:
    from app import right_rail_x12_837 as r837  # noqa: E402
    try:
        from app import right_rail_gate_ffs as ffs  # noqa: E402  imports msvcrt (through right_rail_gate_decide)
    except ImportError:
        ffs = None
finally:
    sys.dont_write_bytecode = _bytecode

grd, ref = esn.gate_rules_data, esn.ref

SECRET = esn.PUBLIC_TEST_SECRET  # the in-process test secret constant (decision 15)
OTHER_SECRET = b"synthetic other tenant secret, not the fixture one"
FIXTURE = os.path.join(HERE, "fixtures", "elig", "roster_v1.json")
TODAY = 20270315
GOLDEN_PIN = ("fe10794afce9784d8769eefc3be2467bd326e68946d8021f4dd984874f9b3b92b60362b671052cf6164d5a87b6c15788fdfb2350"
              "a2894b283c07c8bb8b45a7fa")
SHARDS = os.path.join(esn.RIGHTRAIL, "tests", "gate_rules", "shards_v1.vectors")


def rec(mid, aid="13", level=1, start="2026-01-01", stop=None):
    return [mid, aid, level, start, stop]


def pad(n=19):
    """n good members, so one set-aside member stays within the 5% placeholder (1 of 20)."""
    return [rec(f"PAD{i:05d}") for i in range(n)]


def source(records=(), as_of="2027-03-14", full=True, split=()):
    return esn.FixtureSource(as_of, full, tuple(records), tuple(split))


def build(records=(), today=TODAY, split=(), **kw):
    fits = kw.pop("fits", esn.route_a_fits)
    return esn.build([source(records, split=split, **kw)], SECRET, today, fits=fits)


def key(mid, secret=SECRET):
    return esn.ident(esn.member_key(secret, mid))


def rows_of(res, mid):
    return [r for r in res.snapshot.rows if r[0] == key(mid)]


def cause_of(res, mid):
    m = key(mid)
    hexed = m.to_bytes((m.bit_length() + 7) // 8, "big").hex()
    return next((a["cause"] for a in res.set_aside if a["member_number"] == hexed), None)


def iso(o):
    return datetime.date.fromordinal(o).isoformat()


def slurp(*parts, mode="r"):
    with open(os.path.join(*parts), mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        return f.read()


class GoldenPin(unittest.TestCase):
    def test_pin_rows_reproduces_shards_v1_elig_pin(self):
        """The raw tuples of shards_v1.vectors:26-35 (members as plain numbers, not keyed) give fe10794a... (encoder only)."""
        with open(SHARDS, encoding="utf-8") as f:
            lines = f.read().splitlines()
        head = lines[24].split()
        self.assertEqual(head[:4], ["snap", "elig", "20270314", "10"])
        self.assertEqual(head[4], GOLDEN_PIN)
        rows = [tuple(int(v) for v in ln.split()[1:]) for ln in lines[25:35]]
        self.assertTrue(all(ln.startswith("elig ") for ln in lines[25:35]))
        p = esn.pin_rows(20270314, rows)
        self.assertEqual(p.pin, GOLDEN_PIN)
        self.assertEqual(p.count, 10)
        self.assertEqual(esn.pin_rows(20270314, list(reversed(rows))).pin, GOLDEN_PIN)
        self.assertEqual(esn.fragment(p).splitlines(), lines[24:35])

    def test_pin_rows_does_no_keying_normalizing_or_fits(self):
        """pin_rows accepts a row route_a_fits refuses and keeps duplicates, as the pin itself does."""
        row = (1001, 78131, 1, 19000101, 99991231)
        self.assertFalse(esn.route_a_fits(row))
        self.assertEqual(esn.pin_rows(20270314, [row, row]).count, 2)


class PinEncoding(unittest.TestCase):
    def setUp(self):
        with open(FIXTURE, "rb") as f:
            self.res = esn.build([esn.FixtureSource.from_json(f.read())], SECRET, TODAY)
        self.assertEqual(self.res.result, "snapshot")

    def test_pin_equals_gate_rules_data_and_reference_checker(self):
        p = self.res.snapshot
        text = [f"snap elig {p.as_of} {p.count} ?"] + [f"elig {' '.join(map(str, r))}" for r in p.rows]
        self.assertEqual(grd.pin(text)[0].split()[4], p.pin)
        self.assertEqual(hashlib.sha3_512(ref.pin_bytes("elig", p.as_of, p.count, list(p.rows))).hexdigest(), p.pin)
        self.assertEqual(self.res.fragment.splitlines()[0], f"snap elig 20270314 22 {p.pin}")

    def test_kind_is_7_and_level_is_one_byte(self):
        """Fails if level is pinned at 4 bytes or the kind as 5 (the two feed() pitfalls, design 2.2)."""
        p = self.res.snapshot
        enc = [esn.encode_row(r) for r in p.rows]
        self.assertTrue(all(len(e) == 267 for e in enc))
        data = esn.pin_input(p.as_of, p.count, enc)
        self.assertEqual(data[:20], b"RR/GATE/SNAPSHOT/v1\0")
        self.assertEqual(int.from_bytes(data[20:24], "big"), 7)
        wide = b"".join(sorted(b"".join(v.to_bytes(w, "big") for w, v in zip((129, 129, 4, 4, 4), r)) for r in p.rows))
        as_level4 = b"RR/GATE/SNAPSHOT/v1\0" + data[20:32] + wide
        as_kind5 = data[:20] + (5).to_bytes(4, "big") + data[24:]
        for wrong in (as_level4, as_kind5):
            self.assertNotEqual(hashlib.sha3_512(wrong).hexdigest(), p.pin)

    def test_aid_encoding(self):
        self.assertEqual(esn.ident(b"13"), 78131)
        allowed = [esn.ident(t.encode()) for t in esn.ALLOWED_AID_TEXT]
        self.assertEqual(allowed, [78131, 78387, 79155, 20000819, 20000820])
        self.assertEqual(set(allowed), ref.ALLOWED_AID)
        self.assertNotIn(esn.ident(b"105"), ref.ALLOWED_AID)
        self.assertNotIn(esn.ident(b"D3"), ref.ALLOWED_AID)

    def test_member_key_is_rightrails_own(self):
        """member_key and ident run from rightrail's source; check them against the formula its docstring states."""
        ffs = os.path.join(esn.RIGHTRAIL, "app", "right_rail_gate_ffs.py")
        with open(ffs, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("key = member_key(secret, c.subscriber_id)", src)  # the 837 request side (ffs :75)
        self.assertIn("mem = {r.member_id: ident(member_key(secret, r.member_id)) for r in rows}", src)  # the span feed
        want = hashlib.sha3_256(len(SECRET).to_bytes(2, "big") + SECRET + b"RR/GATE/MEMBER-KEY/v1\x00" + b"S1").digest()
        self.assertEqual(esn.member_key(SECRET, "S1"), want)
        self.assertEqual(key("S1"), int.from_bytes(b"\x01" + want, "big"))


def _x12_837(subscriber):
    """A minimal hand-written synthetic 837P with one claim for ``subscriber`` (envelope as rightrail's test helpers)."""
    body = ["BHT*0019*00*1*20260102*0930*CH", "HL*1**20*1", "NM1*85*2*SYNTHETIC CLINIC*****XX*1999999984", "HL*2*1*22*0",
            "SBR*P*18", f"NM1*IL*1*DOE*JANE****MI*{subscriber}", "CLM*C1*10.00***11:B:1*Y*A*Y*Y", "HI*ABK:E119", "LX*1",
            "SV1*HC:99213*10.00*UN*1***1", "DTP*472*D8*20260101"]
    isa = "*".join(["ISA", "00", " " * 10, "00", " " * 10, "ZZ", "STATE".ljust(15), "ZZ", "PLAN".ljust(15), "260101", "1200", "^",
                    "00501", "000000001", "0", "P", ":"])
    segs = [isa, "GS*HP*STATE*PLAN*20260102*0930*1*X*005010X220A1", "ST*837*0001", *body, f"SE*{len(body) + 2}*0001", "GE*1*1",
            "IEA*1*000000001"]
    return "".join(s + "~" for s in segs).encode("latin-1")


class MemberKeyParity(unittest.TestCase):
    def test_elig_member_number_equals_the_837_member_number(self):
        """The 837 reader's subscriber id, keyed as the request side keys it, is the builder's elig member number."""
        read = r837.read_837(_x12_837("S00000001"))
        self.assertTrue(read.rows)
        sub = read.rows[0].subscriber_id
        res = build([rec("S00000001")] + pad())
        self.assertEqual(rows_of(res, "S00000001")[0][0], esn.ident(esn.member_key(SECRET, sub)))
        self.assertNotEqual(key("S00000001", OTHER_SECRET), key("S00000001"))
        self.assertEqual(rows_of(res, "S00000001")[0][0] >> 256, 1)  # 0x01 then 32 key bytes

    @unittest.skipUnless(ffs is not None, "MEMBER-KEY 837 REQUEST PARITY NOT RUN: app.right_rail_gate_ffs imports msvcrt "
                                          "(Windows only); run this file with the Windows Python")
    def test_ffs_request_member_equals_the_elig_member_number(self):
        """The real 837 request side (ffs.requests_of, right_rail_gate_ffs.py:75) gives the builder's member number."""
        read = r837.read_837(_x12_837("S00000001"))
        sent, aside = ffs.requests_of([read], "T", "P", "2026-01", SECRET)
        self.assertEqual((len(sent), aside), (1, ()))
        res = build([rec("S00000001")] + pad())
        self.assertEqual(esn.ident(sent[0].member_key), rows_of(res, "S00000001")[0][0])
        other, _ = ffs.requests_of([read], "T", "P", "2026-01", OTHER_SECRET)
        self.assertNotIn(esn.ident(other[0].member_key), {r[0] for r in res.snapshot.rows})


class Normalization(unittest.TestCase):
    def one(self, record):
        res = build([record] + pad())
        self.assertEqual(res.result, "snapshot")
        return res

    def test_bad_member_ids(self):
        for mid in ("S1 ", " S1", "", "S1\t"):
            res = self.one(rec(mid))
            self.assertEqual(cause_of(res, mid), "bad_member_id", repr(mid))
            self.assertEqual(rows_of(res, mid), [])

    def test_bad_aid_text(self):
        for aid in (" 13", "013", "13 ", "ab", "Ab", "1-3", "", 1.0, True, -1, None):
            res = self.one(rec("S1", aid=aid))
            self.assertEqual(cause_of(res, "S1"), "bad_aid", repr(aid))

    def test_integer_aid_becomes_its_decimal_text(self):
        res = self.one(rec("S1", aid=53))
        self.assertEqual(rows_of(res, "S1")[0][1], esn.ident(b"53"))
        self.assertEqual(esn.ident(b"53"), 79155)

    def test_bad_level(self):
        for level in (2, -1, 255, 256, True, "1", None, 1.0):
            self.assertEqual(cause_of(self.one(rec("S1", level=level)), "S1"), "bad_level", repr(level))

    def test_bad_dates(self):
        for start, stop in (("2026-02-30", None), ("2026-07-01", "2026-06-30"), ("20260101", None), (None, None),
                            ("2026-01-01", "2026-13-01"), ("2026-1-01", None), (20260101, None), ("0000-01-01", None)):
            self.assertEqual(cause_of(self.one(rec("S1", start=start, stop=stop)), "S1"), "bad_dates", (start, stop))

    def test_open_end_only_when_stated(self):
        res = self.one(rec("S1", stop=None))
        self.assertEqual(rows_of(res, "S1")[0][4], 99991231)
        res = self.one(["S1", "13", 1, "2026-01-01"])  # a record missing its end field is a fault, never open
        self.assertEqual(cause_of(res, "S1"), "member_quarantined")

    def test_does_not_fit(self):
        res = self.one(rec("S1", aid="A" * 21))  # Route A: aid text of at most 20 bytes
        self.assertEqual(cause_of(res, "S1"), "does_not_fit")
        self.assertEqual(rows_of(self.one(rec("S1", aid="A" * 20)), "S1")[0][1], esn.ident(b"A" * 20))
        res = build([rec("S1"), rec("S2")] + pad(), fits=lambda r: r[0] != key("S2"))
        self.assertEqual((cause_of(res, "S2"), len(rows_of(res, "S1"))), ("does_not_fit", 1))


class Conflicts(unittest.TestCase):
    def test_overlap_with_an_earlier_stop_sets_the_member_aside(self):
        res = build([rec("S1"), rec("S1", stop="2026-06-30")] + pad())
        self.assertEqual(cause_of(res, "S1"), "conflicting_rows")
        self.assertEqual(rows_of(res, "S1"), [])  # so no row covers any day after the earlier stop

    def test_touching_rows_are_kept(self):
        res = build([rec("S1", stop="2026-06-30"), rec("S1", start="2026-07-01")] + pad())
        self.assertIsNone(cause_of(res, "S1"))
        self.assertEqual([(r[3], r[4]) for r in sorted(rows_of(res, "S1"), key=lambda r: r[3])],
                         [(20260101, 20260630), (20260701, 99991231)])

    def test_one_shared_day_is_an_overlap(self):
        res = build([rec("S1", stop="2026-07-01"), rec("S1", start="2026-07-01")] + pad())
        self.assertEqual(cause_of(res, "S1"), "conflicting_rows")

    def test_different_aid_or_level_overlapping(self):
        for other in (rec("S1", aid="23", start="2026-03-01"), rec("S1", level=0, start="2026-03-01", stop="2026-04-01"),
                      rec("S1", aid="105", start="2025-01-01", stop="2026-01-01")):
            res = build([rec("S1"), other] + pad())
            self.assertEqual(cause_of(res, "S1"), "conflicting_rows", other)

    def test_non_allowed_aid_is_kept(self):
        res = build([rec("S1", aid="105")] + pad())
        self.assertEqual(rows_of(res, "S1")[0][1], esn.ident(b"105"))


class WholeMemberSetAside(unittest.TestCase):
    def test_one_bad_row_sets_every_row_of_the_member_aside(self):
        for bad, cause in ((rec("S1", level=2, start="2027-01-01"), "bad_level"),
                           (["S1", "13", 1, "2027-01-01", None, "DOE JANE"], "member_quarantined"),
                           (rec("S1", aid="013"), "bad_aid")):
            res = build([rec("S1", stop="2026-12-31"), bad] + pad())
            self.assertEqual((cause_of(res, "S1"), rows_of(res, "S1")), (cause, []), cause)
            self.assertEqual(len(res.set_aside), 1)
            self.assertEqual(len(res.set_aside[0]["origins"]), 2)

    def test_a_record_naming_no_member_is_blind(self):
        res = build([rec("S1"), [17, "13", 1, "2026-01-01", None]] + pad())
        self.assertEqual((res.result, res.cause, res.fragment), ("no_snapshot", "blind", None))

    def test_set_aside_causes_are_closed(self):
        self.assertEqual(set(esn.SET_ASIDE_CAUSES), {"bad_member_id", "bad_aid", "bad_level", "bad_dates", "does_not_fit",
                                                     "member_quarantined", "conflicting_rows", "over_cap"})


JOIN_CASES = [
    ([("13", 20260101, 20261231)], [(1, 20260701, 20270630)],
     [("13", 0, 20260101, 20260630), ("13", 1, 20260701, 20261231)]),
    ([("13", 20260101, 20260331), ("23", 20260401, 20260630)], [(1, 20260301, 20260430)],
     [("13", 0, 20260101, 20260228), ("13", 1, 20260301, 20260331), ("23", 1, 20260401, 20260430), ("23", 0, 20260501, 20260630)]),
    ([("13", 20260101, 20261231)], [(0, 20260101, 20260630), (1, 20261001, 20261031)],
     [("13", 0, 20260101, 20260930), ("13", 1, 20261001, 20261031), ("13", 0, 20261101, 20261231)]),
    ([("13", 20260101, 20260131)], [(1, 20260201, 20261231)], [("13", 0, 20260101, 20260131)]),
]


def join_matches(fn):
    return all(sorted(fn(a, lv)) == sorted(want) for a, lv, want in JOIN_CASES)


def union_join(aids, levels):
    """Mutant: level 1 over the whole aid window when any level-1 window touches it."""
    return [(a, int(any(lv == 1 and s <= e1 and e >= s1 for lv, s, e in levels)), s1, e1) for a, s1, e1 in aids]


def first_level_join(aids, levels):
    """Mutant: every aid window paired with the first level window's level, whatever its dates."""
    return [(a, levels[0][0] if levels else 0, s, e) for a, s, e in aids]


def no_gap_join(aids, levels):
    """Mutant: the level-1 window's own dates, not clipped to the aid window."""
    out = []
    for a, s, e in aids:
        out += [(a, 1, ls, le) for lv, ls, le in levels if lv == 1 and ls <= e and le >= s] or [(a, 0, s, e)]
    return out


class Join(unittest.TestCase):
    def test_level_one_only_over_the_intersection(self):
        self.assertTrue(join_matches(esn.join_windows))

    def test_join_rule_mutants_are_caught(self):
        for mutant in (union_join, first_level_join, no_gap_join):
            self.assertFalse(join_matches(mutant), mutant.__name__)

    def test_join_through_build_and_mutant_through_build(self):
        split = [{"member_id": "S1", "aids": [["13", "2026-01-01", "2026-12-31"]], "levels": [[1, "2026-07-01", "2027-06-30"]]}]
        want = [(key("S1"), 78131, 0, 20260101, 20260630), (key("S1"), 78131, 1, 20260701, 20261231)]
        self.assertEqual(sorted(rows_of(build(pad(), split=split), "S1")), want)
        with mock.patch.object(esn, "join_windows", union_join):
            self.assertNotEqual(sorted(rows_of(build(pad(), split=split), "S1")), want)

    def test_overlapping_level_windows_set_the_member_aside(self):
        split = [{"member_id": "S1", "aids": [["13", "2026-01-01", "2026-12-31"]],
                  "levels": [[1, "2026-01-01", "2026-06-30"], [0, "2026-06-30", "2026-12-31"]]}]
        self.assertEqual(cause_of(build(pad(), split=split), "S1"), "conflicting_rows")

    def test_a_faulty_level_window_sets_the_member_aside(self):
        split = [{"member_id": "S1", "aids": [["13", "2026-01-01", "2026-12-31"]], "levels": [[2, "2026-01-01", "2026-06-30"]]}]
        self.assertEqual(cause_of(build(pad(), split=split), "S1"), "bad_level")


class Cap(unittest.TestCase):
    def days(self, n, mid="S1"):
        o = datetime.date(2020, 1, 1).toordinal()
        return [rec(mid, start=iso(o + i), stop=iso(o + i)) for i in range(n)]

    def test_1024_kept(self):
        res = build(self.days(1024) + pad())
        self.assertEqual((len(rows_of(res, "S1")), cause_of(res, "S1")), (1024, None))

    def test_1025_set_aside(self):
        res = build(self.days(1025) + pad())
        self.assertEqual((rows_of(res, "S1"), cause_of(res, "S1")), ([], "over_cap"))

    def test_duplicates_removed_before_the_cap(self):
        rows = self.days(1024)
        res = build(rows + rows[:5] + pad())
        self.assertEqual((len(rows_of(res, "S1")), cause_of(res, "S1")), (1024, None))
        self.assertEqual(res.snapshot.count, 1024 + 19)


class AsOf(unittest.TestCase):
    def test_future_source(self):
        self.assertEqual(build(pad(), as_of="2027-03-16").cause, "future_source")
        self.assertEqual(build(pad(), as_of="2027-03-15").result, "snapshot")

    def test_one_source_only(self):
        res = esn.build([source(pad()), source(pad())], SECRET, TODAY)
        self.assertEqual((res.result, res.cause), ("no_snapshot", "many_sources"))
        self.assertEqual(esn.build([], SECRET, TODAY).cause, "no_source")

    def test_not_full_and_no_as_of(self):
        for full in (False, None, "true", 1):
            self.assertEqual(build(pad(), full=full).cause, "not_full", full)
        for as_of in (None, "", "2027-02-30", "20270314", 20270314, "2027-03-14T00:00:00"):
            self.assertEqual(build(pad(), as_of=as_of).cause, "no_as_of", as_of)

    def test_older_source_is_never_restamped(self):
        res = build(pad(), as_of="2027-03-01")
        self.assertEqual(res.result, "snapshot")
        self.assertEqual(res.snapshot.as_of, 20270301)
        self.assertTrue(res.fragment.startswith("snap elig 20270301 19 "))
        self.assertEqual((res.sidecar["as_of"], res.sidecar["age_days"], res.sidecar["stale"]), (20270301, 14, True))
        self.assertEqual(res.sidecar["as_of_source"], "fixture.as_of")
        fresh = build(pad(), as_of="2027-03-08")
        self.assertEqual((fresh.sidecar["age_days"], fresh.sidecar["stale"]), (7, False))

    def test_empty_and_builder_error(self):
        self.assertEqual(build([]).cause, "empty")

        def boom(row):
            raise RuntimeError("PAD00001")
        res = build(pad(), fits=boom)
        self.assertEqual((res.result, res.cause, res.fragment, res.set_aside), ("no_snapshot", "builder_error", None, []))
        self.assertEqual(build(pad(), today=20270230).cause, "builder_error")


class Threshold(unittest.TestCase):
    def test_above_five_percent_gives_no_snapshot(self):
        res = build([rec("S1", level=2), rec("S2", level=2)] + pad(18))  # 2 of 20
        self.assertEqual((res.result, res.cause), ("no_snapshot", "too_many_set_aside"))
        self.assertEqual(len(res.sidecar["set_aside"]), 2)

    def test_at_five_percent_gives_a_snapshot(self):
        res = build([rec("S1", level=2)] + pad(19))  # 1 of 20
        self.assertEqual(res.result, "snapshot")
        self.assertEqual(build([rec("S1", level=2)] + pad(18)).cause, "too_many_set_aside")  # 1 of 19


def entry(mid, aids, levels):
    return {"member_id": mid, "aids": [list(a) for a in aids], "levels": [list(lv) for lv in levels]}


OPEN = None


class SplitAcrossEntries(unittest.TestCase):
    """Review finding (blocker): each split entry was joined alone, so a later entry's level facts were lost."""

    def test_a_later_entry_without_aids_sets_the_member_aside(self):
        split = [entry("S1", [("13", "2026-01-01", OPEN)], [(1, "2026-01-01", OPEN)]),
                 entry("S1", [], [(0, "2026-07-01", OPEN)])]
        res = build(pad(), split=split)
        self.assertEqual(res.result, "snapshot")
        self.assertEqual((rows_of(res, "S1"), cause_of(res, "S1")), ([], "member_quarantined"))
        self.assertEqual(len(res.set_aside[0]["origins"]), 2)

    def test_level_windows_of_all_entries_are_checked_together(self):
        split = [entry("S1", [("13", "2026-01-01", OPEN)], [(1, "2026-01-01", OPEN)]),
                 entry("S1", [("13", "2026-07-01", OPEN)], [(0, "2026-07-01", OPEN)])]
        res = build(pad(), split=split)
        self.assertEqual((rows_of(res, "S1"), cause_of(res, "S1")), ([], "conflicting_rows"))

    def test_a_record_and_a_split_entry_for_one_member(self):
        for split in ([entry("S1", [], [(0, "2026-07-01", OPEN)])],
                      [entry("S1", [("13", "2027-01-01", OPEN)], [(0, "2026-01-01", OPEN)])],
                      [entry("S1", [("13", "2027-01-01", OPEN)], [(1, "2026-06-01", "2026-06-30")])]):
            res = build([rec("S1", stop="2026-12-31")] + pad(), split=split)
            self.assertEqual(rows_of(res, "S1"), [], split)
            self.assertIn(cause_of(res, "S1"), ("member_quarantined", "conflicting_rows"), split)
        res = build([rec("S1", stop="2026-12-31")] + pad(), split=[entry("S1", [("13", "2027-01-01", OPEN)], [])])
        self.assertEqual(sorted((r[2], r[3], r[4]) for r in rows_of(res, "S1")), [(0, 20270101, 99991231), (1, 20260101, 20261231)])

    def test_entries_are_joined_together(self):
        """Aid windows from one entry and level windows from another of the same member and source are one join."""
        split = [entry("S1", [("13", "2026-01-01", "2026-12-31")], []), entry("S1", [("13", "2026-01-01", "2026-12-31")],
                                                                         [(1, "2026-07-01", "2027-06-30")]),
                 entry("S1", [("23", "2027-01-01", OPEN)], [])]
        res = build(pad(), split=split)
        self.assertEqual(sorted((r[1], r[2], r[3], r[4]) for r in rows_of(res, "S1")),
                         [(78131, 0, 20260101, 20260630), (78131, 1, 20260701, 20261231),
                          (78387, 0, 20270701, 99991231), (78387, 1, 20270101, 20270630)])

    def test_the_finding_input_holds_through_the_reference_checker(self):
        split = [entry("S1", [("13", "2026-01-01", OPEN)], [(1, "2026-01-01", OPEN)]),
                 entry("S1", [], [(0, "2026-07-01", OPEN)])]
        frag = build([rec("E01")] + pad(), split=split).fragment.splitlines()
        self.assertEqual(ref.run(vector(frag, [("S1", "HOLD PROGRAM_NOT_ELIGIBLE"), ("E01", "ALLOW -")], ["S1", "E01"])),
                         ["RULES_VECTORS=PASS checked=2 expected=2 failed=0"])


class PaddedMemberId(unittest.TestCase):
    """Review finding: a record under a padded id was set aside under its own key only, so the real member ALLOWed."""

    def test_a_padded_termination_sets_the_trimmed_member_aside(self):
        for padded in ("S1 ", " S1", "S1\t", "\nS1"):
            res = build([rec("S1"), rec(padded, stop="2026-06-30")] + pad())
            self.assertEqual(res.result, "snapshot", repr(padded))  # one member at fault: 1 of 20, within 5%
            self.assertEqual((rows_of(res, "S1"), cause_of(res, "S1"), cause_of(res, padded)), ([], "bad_member_id", "bad_member_id"))
            frag = res.fragment.splitlines()
            self.assertEqual(ref.run(vector(frag, [("S1", "HOLD PROGRAM_NOT_ELIGIBLE")], ["S1"])),
                             ["RULES_VECTORS=PASS checked=1 expected=1 failed=0"])

    def test_padded_split_entry_and_quarantined_padded_record(self):
        res = build([rec("S1")] + pad(), split=[entry(" S1", [("13", "2026-01-01", OPEN)], [])])
        self.assertEqual((rows_of(res, "S1"), cause_of(res, "S1")), ([], "bad_member_id"))
        res = build([rec("S1"), ["S1 ", "13", 1, "2026-01-01", "2026-06-30", "extra"]] + pad())
        self.assertEqual((rows_of(res, "S1"), cause_of(res, "S1")), ([], "member_quarantined"))

    def test_a_padded_id_counts_once_for_the_threshold(self):
        self.assertEqual(build([rec("S1 ")] + pad(19)).result, "snapshot")  # S1 and "S1 " are one member: 1 of 20
        self.assertEqual(build([rec("S1 "), rec("S2 ")] + pad(18)).cause, "too_many_set_aside")  # 2 of 20


class MembersWithNoRows(unittest.TestCase):
    """Review findings: split entries with no aid window added rowless members silently and inflated the threshold."""

    def test_empty_split_entries_are_faults(self):
        res = build(pad(), split=[entry(" BAD", [], [])])
        self.assertEqual(cause_of(res, " BAD"), "bad_member_id")
        res = build(pad(), split=[entry("S1", [], []), entry("S2", [], [(1, "2026-01-01", OPEN)])])
        self.assertEqual(res.cause, "too_many_set_aside")
        res = build(pad(), split=[entry("S1", [], [])])
        self.assertEqual((res.result, cause_of(res, "S1")), ("snapshot", "member_quarantined"))

    def test_empty_entries_cannot_dilute_the_threshold(self):
        records = [rec(f"L{i}", level=2) for i in range(3)] + [rec("G1"), rec("G2")]
        res = build(records, split=[entry(f"EMPTY{i:03d}", [], []) for i in range(60)])
        self.assertEqual((res.result, res.cause), ("no_snapshot", "too_many_set_aside"))

    def test_unknown_split_keys_are_a_fault(self):
        res = build(pad(), split=[{**entry("S1", [("13", "2026-01-01", OPEN)], []), "name": "DOE JANE"}])
        self.assertEqual(cause_of(res, "S1"), "member_quarantined")


class UnencodableMemberId(unittest.TestCase):
    def test_a_lone_surrogate_sets_one_member_aside(self):
        """Review finding: an id that does not encode aborted the run as builder_error instead of a set-aside."""
        res = build([rec("\ud800X")] + pad(40))
        self.assertEqual((res.result, len(res.set_aside), res.set_aside[0]["cause"]), ("snapshot", 1, "bad_member_id"))
        self.assertEqual(res.snapshot.count, 40)
        res = build([rec("\ud800X ")] + pad(40), split=[entry("\udcffY", [("13", "2026-01-01", OPEN)], [])])
        self.assertEqual(sorted(a["cause"] for a in res.set_aside), ["bad_member_id"] * 3)


def cause_table():
    """One build per cause of design table 6 that the fixture source can produce now (stand-ins included)."""
    big = [rec("S1", start=iso(datetime.date(2020, 1, 1).toordinal() + i), stop=iso(datetime.date(2020, 1, 1).toordinal() + i))
           for i in range(1025)]
    return [
        ("bad_member_id", build([rec("S1 ")] + pad())), ("bad_aid", build([rec("S1", aid="013")] + pad())),
        ("bad_level", build([rec("S1", level=2)] + pad())), ("bad_dates", build([rec("S1", start="2026-02-30")] + pad())),
        ("does_not_fit", build([rec("S1", aid="A" * 21)] + pad())),
        ("member_quarantined", build([["S1", "13", 1, "2026-01-01"]] + pad())),
        ("conflicting_rows", build([rec("S1"), rec("S1", stop="2026-06-30")] + pad())), ("over_cap", build(big + pad())),
        ("no_source", esn.build([], SECRET, TODAY)), ("many_sources", esn.build([source(pad()), source(pad())], SECRET, TODAY)),
        ("not_full", build(pad(), full=False)), ("no_as_of", build(pad(), as_of=None)),
        ("future_source", build(pad(), as_of="2027-03-16")), ("blind", build([[17, "13", 1, "2026-01-01", None]] + pad())),
        ("empty", build([])), ("too_many_set_aside", build([rec("S1", level=2), rec("S2", level=2)] + pad(18))),
        ("builder_error", build(pad(), today=20270230)),
    ]


class Causes(unittest.TestCase):
    def test_every_closed_cause_is_reached_and_nothing_else(self):
        """Review finding: the cause-list test restated the constant; this checks the causes the builder produces."""
        set_aside, no_snapshot = set(), set()
        for want, res in cause_table():
            got = res.cause if res.result == "no_snapshot" else {a["cause"] for a in res.set_aside}
            if res.result == "no_snapshot":
                self.assertEqual(got, want)
                no_snapshot.add(got)
            else:
                self.assertEqual(got, {want})
                set_aside |= got
            self.assertEqual(res.sidecar["result"], res.result)
        self.assertEqual(set_aside, set(esn.SET_ASIDE_CAUSES))
        self.assertEqual(no_snapshot, set(esn.NO_SNAPSHOT_CAUSES))

    def test_closed_lists_hold_without_assert(self):
        with mock.patch.object(esn, "SET_ASIDE_CAUSES", ()):  # a cause outside the list is caught, not asserted
            self.assertEqual(build([rec("S1", level=2)] + pad()).cause, "builder_error")
        with self.assertRaises(ValueError):
            esn._no("not_a_cause", {})

    def test_max_age_is_the_reference_checkers(self):
        self.assertEqual(esn.MAX_AGE_DAYS, ref.MAXAGE["elig"])
        with mock.patch.object(esn, "MAX_AGE_DAYS", 3):
            self.assertTrue(build(pad(), as_of="2027-03-11").sidecar["stale"])


class OrderAndDedupe(unittest.TestCase):
    def test_shuffled_input_same_output(self):
        records = [rec("S1", stop="2026-06-30"), rec("S1", start="2026-07-01", aid="23"), rec("S2", aid="105")] + pad()
        base = build(records)
        rnd = random.Random(20270315)
        for _ in range(5):
            shuffled = list(records)
            rnd.shuffle(shuffled)
            other = build(shuffled)
            self.assertEqual((other.fragment, other.sidecar["pin"]), (base.fragment, base.sidecar["pin"]))

    def test_exact_duplicates_removed_and_count_equals_rows(self):
        res = build([rec("S1"), rec("S1"), rec("S1")] + pad())
        self.assertEqual(len(rows_of(res, "S1")), 1)
        self.assertEqual(res.snapshot.count, len(res.snapshot.rows))
        self.assertEqual(res.snapshot.count, len(res.fragment.splitlines()) - 1)
        self.assertEqual(res.sidecar["count"], 20)


class FixtureSecret(unittest.TestCase):
    def test_refuses_any_other_secret(self):
        for secret in (OTHER_SECRET, SECRET + b"x", SECRET[:-1], b"", SECRET.decode(), None):
            with self.assertRaises(esn.SecretRefused) as cm:
                esn.build([source(pad())], secret, TODAY)
            self.assertEqual(str(cm.exception), esn.SecretRefused.MESSAGE)  # a fixed text: no secret byte can be in it
        self.assertEqual(esn.build([source(pad())], SECRET, TODAY).result, "snapshot")

    def test_kind_cannot_be_overridden(self):
        """Review finding: the refusal read a constructor-settable `kind`; kind=... is no longer accepted at all."""
        with self.assertRaises(TypeError):
            esn.FixtureSource("2027-03-14", True, tuple(pad()), (), b"", "production")
        with self.assertRaises(TypeError):
            esn.FixtureSource("2027-03-14", True, tuple(pad()), kind="production")
        src = source(pad())
        object.__setattr__(src, "kind", "production")  # even a forced tag changes nothing: the check is on the class
        with self.assertRaises(esn.SecretRefused):
            esn.build([src], OTHER_SECRET, TODAY)

    def test_duck_typed_source_is_refused(self):
        class Duck:
            as_of, full_roster, records, split = "2027-03-14", True, tuple(pad()), ()

            def digest(self):
                return "0" * 128
        with self.assertRaises(esn.SecretRefused):
            esn.build([Duck()], OTHER_SECRET, TODAY)
        with self.assertRaises(esn.SecretRefused):
            esn.build([], OTHER_SECRET, TODAY)
        res = esn.build([Duck()], SECRET, TODAY)
        self.assertEqual((res.result, res.cause, res.fragment), ("no_snapshot", "builder_error", None))

        class Sub(esn.FixtureSource):
            pass
        res = esn.build([Sub("2027-03-14", True, tuple(pad()))], SECRET, TODAY)
        self.assertEqual(res.cause, "builder_error")


class NoLeaks(unittest.TestCase):
    MID, NAME = "ZQXLEAKMEMBER01", "ZQXLEAKNAME"

    def texts(self, res):
        return [res.fragment or "", json.dumps(res.sidecar)]

    def test_outputs_carry_no_member_id_name_or_secret(self):
        secret_forms = [SECRET.decode(), SECRET.hex(), hashlib.sha3_512(SECRET).hexdigest()]
        cases = [build([rec(self.MID)] + pad()),
                 build([rec(self.MID, level=2)] + pad()),
                 build([[self.MID, "13", 1, "2026-01-01", None, self.NAME]] + pad()),
                 build([rec(self.MID, level=2), [self.MID + "X", "13", 1, "x", None, self.NAME]] + pad(18)),
                 build([rec(self.MID)] + pad(), fits=lambda r: (_ for _ in ()).throw(ValueError(self.MID)))]
        self.assertEqual([c.result for c in cases], ["snapshot", "snapshot", "snapshot", "no_snapshot", "no_snapshot"])
        for res in cases:
            for text in self.texts(res):
                for leak in [self.MID, self.NAME, "PAD0000"] + secret_forms:
                    self.assertNotIn(leak, text)
        self.assertNotIn(SECRET.decode(), str(esn.SecretRefused()))

    def test_cli_output_carries_no_secret_or_member_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = os.path.join(tmp, "f.json")
            with open(fixture, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"as_of": "2027-03-14", "full_roster": True, "records": [rec(self.MID)] + pad()}, f)
            secret_file = os.path.join(tmp, "s")
            with open(secret_file, "wb") as f:
                f.write(SECRET + b"\n")
            out, err, code = run_cli(["--fixture", fixture, "--today", "20270315", "--secret-file", secret_file,
                                      "--fragment", os.path.join(tmp, "frag"), "--sidecar", os.path.join(tmp, "side.json")])
            self.assertEqual(code, 0)
            written = "".join(slurp(tmp, n) for n in ("frag", "side.json"))
            for text in (out, err, written):
                self.assertNotIn(self.MID, text)
                self.assertNotIn(SECRET.decode(), text)

    def test_repr_of_a_source_carries_no_record(self):
        """Review finding: the default dataclass repr printed every record and the raw bytes."""
        records = [[self.MID, "13", 1, "2026-01-01", None, self.NAME]] + pad()
        split = [{"member_id": self.MID, "aids": [["13", "2026-01-01", None]], "levels": []}]
        raw = json.dumps({"as_of": "2027-03-14", "full_roster": True, "records": records, "split": split}).encode()
        for src in (esn.FixtureSource("2027-03-14", True, tuple(records), tuple(split)), esn.FixtureSource.from_json(raw)):
            text = repr(src) + str(src)
            for leak in (self.MID, self.NAME, "PAD0000", "raw="):
                self.assertNotIn(leak, text)

    def test_non_utf8_env_secret_leaks_nothing(self):
        """Review finding: a secret that is not UTF-8 escaped as a UnicodeEncodeError traceback naming the byte."""
        value = "ZQXSECRETPREFIX\udcffTAIL"  # the byte 0xff, as os.environ holds it (surrogateescape)
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"ELIG_SNAPSHOT_TEST_SECRET": value}):
                out, err, code = run_cli(["--fixture", FIXTURE, "--today", "20270315", "--secret-env", "ELIG_SNAPSHOT_TEST_SECRET",
                                          "--fragment", os.path.join(tmp, "frag"), "--sidecar", os.path.join(tmp, "side.json")])
            self.assertEqual(code, 2)
            for leak in ("ZQX", "TAIL", "Traceback", "udcff", "\\xff", "position", "Error"):
                self.assertNotIn(leak, out + err)
            self.assertEqual(err, f"elig_snapshot: {esn.SecretRefused.MESSAGE}\n")
            self.assertFalse(os.path.exists(os.path.join(tmp, "frag")))
            self.assertEqual(json.loads(slurp(tmp, "side.json"))["cause"], "builder_error")
            if hasattr(os, "environb"):  # POSIX: read as bytes, never decoded
                with mock.patch.dict(os.environ, {"ELIG_SNAPSHOT_TEST_SECRET": value}):
                    self.assertEqual(esn._secret(mock.Mock(secret_file=None, secret_env="ELIG_SNAPSHOT_TEST_SECRET")),
                                     b"ZQXSECRETPREFIX\xffTAIL")
            else:  # Windows: a lone surrogate that not even surrogateescape encodes is "secret unreadable"
                with mock.patch.dict(os.environ, {"ELIG_SNAPSHOT_TEST_SECRET": "ZQX\ud800TAIL"}):
                    out, err, code = run_cli(["--fixture", FIXTURE, "--today", "20270315", "--secret-env",
                                              "ELIG_SNAPSHOT_TEST_SECRET", "--fragment", os.path.join(tmp, "frag"),
                                              "--sidecar", os.path.join(tmp, "side.json")])
                self.assertEqual((code, err), (2, "elig_snapshot: secret unreadable\n"))
                self.assertNotIn("ZQX", out + err)


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = esn.main(argv)
        except SystemExit as e:
            code = e.code
    return out.getvalue(), err.getvalue(), code


class Cli(unittest.TestCase):
    def args(self, tmp, *secret):
        return ["--fixture", FIXTURE, "--today", "20270315", *secret, "--fragment", os.path.join(tmp, "frag"),
                "--sidecar", os.path.join(tmp, "side.json")]

    def test_secret_from_file_and_from_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            sf = os.path.join(tmp, "secret")
            with open(sf, "wb") as f:
                f.write(SECRET)
            out, _, code = run_cli(self.args(tmp, "--secret-file", sf))
            self.assertEqual((code, out.strip()), (0, "ELIG_SNAPSHOT=snapshot count=22"))
            frag = slurp(tmp, "frag")
            with mock.patch.dict(os.environ, {"ELIG_SNAPSHOT_TEST_SECRET": SECRET.decode()}):
                out, _, code = run_cli(self.args(tmp, "--secret-env", "ELIG_SNAPSHOT_TEST_SECRET"))
            self.assertEqual(code, 0)
            self.assertEqual(slurp(tmp, "frag"), frag)
            side = json.loads(slurp(tmp, "side.json"))
            self.assertEqual((side["result"], side["count"], side["clock"]["basis"]),
                             ("snapshot", 22, "--today argument (timezone not stated)"))
            self.assertEqual(side["source_hashes"], [hashlib.sha3_512(slurp(FIXTURE, mode="rb")).hexdigest()])
            self.assertNotIn(b"\r", slurp(tmp, "frag", mode="rb"))

    def test_secret_never_from_argv_and_usage_errors_echo_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            for extra in (["--secret", "ZQXARGVSECRET"], ["--secret=ZQXARGVSECRET"], ["--secret-f=ZQXARGVSECRET"]):
                out, err, code = run_cli(self.args(tmp) + extra)
                self.assertEqual(code, 2)
                self.assertNotIn("ZQXARGVSECRET", out + err)
            # Review finding: with a valid secret given, the only error left is the unknown or abbreviated option, so
            # these fail only if abbreviations are allowed or the usage message echoes arguments.
            sf = os.path.join(tmp, "secret")
            with open(sf, "wb") as f:
                f.write(SECRET)
            for extra in (["--secret=ZQXARGVSECRET"], ["--secret-f=ZQXARGVSECRET"], ["--frag=ZQXARGVSECRET"],
                          ["--sid", "ZQXARGVSECRET"]):
                out, err, code = run_cli(self.args(tmp, "--secret-file", sf) + extra)
                self.assertEqual((code, err), (2, "elig_snapshot: usage error (see --help)\n"), extra)
                self.assertNotIn("ZQXARGVSECRET", out + err)
                self.assertFalse(os.path.exists(os.path.join(tmp, "ZQXARGVSECRET")))

    def test_wrong_secret_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"ELIG_SNAPSHOT_TEST_SECRET": "ZQXWRONGSECRET"}):
                out, err, code = run_cli(self.args(tmp, "--secret-env", "ELIG_SNAPSHOT_TEST_SECRET"))
            self.assertEqual(code, 2)
            self.assertNotIn("ZQXWRONGSECRET", out + err)
            self.assertFalse(os.path.exists(os.path.join(tmp, "frag")))
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ELIG_SNAPSHOT_UNSET", None)
                self.assertEqual(run_cli(self.args(tmp, "--secret-env", "ELIG_SNAPSHOT_UNSET"))[2], 2)

    def test_no_snapshot_writes_sidecar_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            sf = os.path.join(tmp, "secret")
            with open(sf, "wb") as f:
                f.write(SECRET)
            args = self.args(tmp, "--secret-file", sf)
            args[3] = "20270313"  # today before the fixture's asOf
            out, _, code = run_cli(args)
            self.assertEqual((code, out.strip()), (1, "ELIG_SNAPSHOT=no_snapshot cause=future_source"))
            self.assertFalse(os.path.exists(os.path.join(tmp, "frag")))
            self.assertEqual(json.loads(slurp(tmp, "side.json"))["cause"], "future_source")

    def write(self, tmp, name, doc):
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(doc if isinstance(doc, bytes) else json.dumps(doc).encode())
        return path

    def test_a_failing_run_never_leaves_an_earlier_snapshot(self):
        """Review finding: a good run, then a failing run on the same paths, left the old fragment and sidecar."""
        with tempfile.TemporaryDirectory() as tmp:
            sf = self.write(tmp, "secret", SECRET)
            blind = self.write(tmp, "blind.json", {"as_of": "2027-03-14", "full_roster": True, "records": [[17, "13", 1, "2026-01-01", None]]})
            null = self.write(tmp, "null.json", {"as_of": "2027-03-14", "full_roster": True, "records": None})
            frag, side = os.path.join(tmp, "frag"), os.path.join(tmp, "side.json")

            def run(fixture, *secret, during=contextlib.nullcontext()):
                self.assertEqual(run_cli(self.args(tmp, "--secret-file", sf))[2], 0)  # a good run first, every time
                self.assertTrue(os.path.exists(frag))
                args = self.args(tmp, *(secret or ("--secret-file", sf)))
                args[1] = fixture
                with during:
                    out, err, code = run_cli(args)
                self.assertFalse(os.path.exists(frag), fixture)
                self.assertEqual(json.loads(slurp(side))["result"], "no_snapshot")
                self.assertNotIn("Traceback", out + err)
                return code, json.loads(slurp(side))["cause"]

            self.assertEqual(run(blind), (1, "blind"))
            self.assertEqual(run(null), (1, "builder_error"))
            with mock.patch.dict(os.environ, {"ELIG_SNAPSHOT_TEST_SECRET": "ZQXWRONGSECRET"}):
                self.assertEqual(run(FIXTURE, "--secret-env", "ELIG_SNAPSHOT_TEST_SECRET"), (2, "builder_error"))
            self.assertEqual(run(os.path.join(tmp, "missing.json")), (1, "builder_error"))
            self.assertEqual(run(FIXTURE, during=mock.patch.object(esn, "build", side_effect=RuntimeError("ZQXINTERNAL"))),
                             (3, "builder_error"))
            self.assertEqual(sorted(os.listdir(tmp)), ["blind.json", "null.json", "secret", "side.json"])  # no temp files

    def test_malformed_fixtures_give_builder_error_without_traceback(self):
        """Review findings: records null or a number crashed with a TypeError; duplicate and unknown keys were accepted."""
        good = {"as_of": "2027-03-14", "full_roster": True, "records": [rec("S1")] + pad()}
        cases = [{**good, "records": None}, {**good, "records": 5}, {**good, "split": 7}, {**good, "split": {"a": 1}},
                 {**good, "record": []}, [good],
                 b'{"as_of": "2027-03-01", "full_roster": false, "records": [["S1", "13", 1, "2026-01-01", "2026-06-30"]],'
                 b' "as_of": "2027-03-14", "full_roster": true, "records": [["S1", "13", 1, "2026-01-01", null]]}',
                 b'{"as_of": "2027-03-14", "full_roster": true, "records": [], "split": [{"member_id": "S1", "member_id": "S2",'
                 b' "aids": [], "levels": []}]}',
                 b'{"as_of": "2027-03-14", "full_roster": true, "records": [["S1", "13", 1, "2026-01-01", null]]',
                 b'\xff\xfe{}', b'[' * 100000]
        with tempfile.TemporaryDirectory() as tmp:
            sf = self.write(tmp, "secret", SECRET)
            for n, doc in enumerate(cases):
                args = self.args(tmp, "--secret-file", sf)
                args[1] = self.write(tmp, f"bad{n}.json", doc)
                out, err, code = run_cli(args)
                self.assertEqual((code, out.strip(), err), (1, "ELIG_SNAPSHOT=no_snapshot cause=builder_error", ""), n)
                self.assertEqual(json.loads(slurp(tmp, "side.json"))["cause"], "builder_error")
                self.assertFalse(os.path.exists(os.path.join(tmp, "frag")))
        self.assertEqual(esn.FixtureSource.from_json(json.dumps({**good, "_note": "x"}).encode()).as_of, "2027-03-14")
        self.assertEqual(esn.FixtureSource.from_json(b'{"as_of": "2027-03-14", "full_roster": true}').records, ())

    def test_output_paths_refused(self):
        """Review finding: --fragment and --sidecar could point into rightrail/ or at pinned files.  Each refused path
        here also names a directory that does not exist, so nothing could be written even if the check were wrong."""
        nowhere = "__elig_snapshot_no_such_dir__"
        with tempfile.TemporaryDirectory() as tmp:
            sf = self.write(tmp, "secret", SECRET)
            fixture = self.write(tmp, "fixture.json", slurp(FIXTURE, mode="rb"))  # a copy: the committed one is never an output
            side = os.path.join(tmp, "side.json")
            refused = [os.path.join(esn.RIGHTRAIL, nowhere, "frag"), os.path.join(esn.RIGHTRAIL, "tests", nowhere, "x.vectors"),
                       os.path.join(tmp, nowhere, "MANIFEST.sha256"), os.path.join(tmp, nowhere, "PROVENANCE"),
                       os.path.join(tmp, nowhere, "tcb_report.json"), os.path.join(tmp, nowhere, "STMT_PIN"),
                       sf, fixture]
            pairs = [(path, side) for path in refused] + [(os.path.join(tmp, "frag"), path) for path in refused]
            pairs.append((os.path.join(tmp, "same"), os.path.join(tmp, ".", "same")))
            for fragment, sidecar in pairs:
                with self.subTest(fragment=fragment, sidecar=sidecar):
                    args = ["--fixture", fixture, "--today", "20270315", "--secret-file", sf, "--fragment", fragment,
                            "--sidecar", sidecar]
                    out, err, code = run_cli(args)
                    self.assertEqual((code, err), (2, "elig_snapshot: output path refused\n"), (fragment, sidecar))
            self.assertEqual(sorted(os.listdir(tmp)), ["fixture.json", "secret"])  # a refused run writes and removes nothing
            self.assertEqual(slurp(fixture, mode="rb"), slurp(FIXTURE, mode="rb"))
            self.assertTrue(esn._refused_output(os.path.join(esn.ROOT, "rust-engine", "config.json"), set()))
            self.assertFalse(esn._refused_output(os.path.join(tmp, "frag"), set()))
            self.assertEqual(slurp(sf, mode="rb"), SECRET)
            self.assertFalse(os.path.exists(os.path.join(esn.RIGHTRAIL, nowhere)))

    def test_clock_basis_names_the_timezone(self):
        """Review finding: the sidecar clock recorded no timezone basis (design 4.5 and 5)."""
        with tempfile.TemporaryDirectory() as tmp:
            sf = self.write(tmp, "secret", SECRET)
            args = self.args(tmp, "--secret-file", sf)
            del args[2:4]  # no --today: the host's local date
            run_cli(args)
            basis = json.loads(slurp(tmp, "side.json"))["clock"]["basis"]
            self.assertRegex(basis, r"^host local date, timezone .+, UTC offset [+-][0-9]{2}:[0-9]{2}$")
        self.assertIn("timezone not stated", build(pad()).sidecar["clock"]["basis"])


# ---- design 8.2: full vector files through the reference checker (the exe half needs a Lean build; not run here)

PLAN, PAYEE, PROC = 501, 7001, 99213


def _snap(kind, asof, rows):
    rows = [tuple(r) for r in rows]
    pin = hashlib.sha3_512(ref.pin_bytes(kind, asof, len(rows), rows)).hexdigest()
    return [f"snap {kind} {asof} {len(rows)} {pin}"] + [f"{kind} {' '.join(map(str, r))}" for r in rows]


def vector(elig_lines, lines, members, today=TODAY, line_secret=SECRET):
    """today; released/unresolved; usable dmf, pdeath, excl and span re-keyed to the line members; the elig fragment;
    lines with hand-written expectations (design section 2); commit; end N."""
    keyed = [key(m, line_secret) for m in members]
    head = [f"today {today}"] + _snap("released", today, []) + _snap("unresolved", today, [])
    head += _snap("dmf", 20270301, [(key("ZZDEAD0001", line_secret), 20270110)]) + _snap("pdeath", 20270301, [(7701, 20270120)])
    head += _snap("excl", 20270310, [(504, 20260101, 99991231)])
    head += _snap("span", 20270314, [(k, PLAN, 20260101, 20271231) for k in keyed])
    body = []
    for n, (m, want) in enumerate(lines, 1):
        body.append(f"line {n} FFS_CLAIM {key(m, line_secret)} {PAYEE} {PAYEE} 20270305 {PROC} 1 12500 {want}")
    return "\n".join(head + list(elig_lines) + ["case elig"] + body + ["commit", f"end {len(lines)}"]) + "\n"


class ReferenceChecker(unittest.TestCase):
    MEMBERS = ["E01", "E02", "E03", "E04", "E05", "E07"]

    def roster(self, as_of="2027-03-14"):
        """E01 allowed level 1, E02 aid 105, E03 allowed aid at level 0 only, E04 left out (not in the roster), E05 two
        overlapping rows (set aside by the builder), E07 touching rows with different aids (53 to 2027-03-05, the line
        date, then 105)."""
        res = build([rec("E01"), rec("E02", aid="105"), rec("E03", level=0), rec("E05", stop="2027-03-10"),
                     rec("E05", start="2027-03-01"), rec("E07", aid="53", stop="2027-03-05"),
                     rec("E07", aid="105", start="2027-03-06")] + pad(), as_of=as_of)
        self.assertEqual(res.result, "snapshot")
        self.assertEqual([a["cause"] for a in res.set_aside], ["conflicting_rows"])
        self.assertEqual(len(rows_of(res, "E07")), 2)
        return res

    def passes(self, text, n):
        self.assertEqual(ref.run(text), [f"RULES_VECTORS=PASS checked={n} expected={n} failed=0"])

    def test_usable_snapshot_outcomes(self):
        frag = self.roster().fragment.splitlines()
        self.passes(vector(frag, [("E01", "ALLOW -"), ("E02", "HOLD PROGRAM_NOT_ELIGIBLE"), ("E03", "HOLD BENEFIT_LEVEL_MISSING"),
                                  ("E04", "HOLD PROGRAM_NOT_ELIGIBLE"), ("E05", "HOLD PROGRAM_NOT_ELIGIBLE"),
                                  ("E07", "ALLOW -")], self.MEMBERS), 6)

    def test_hand_written_split_aid_and_level_rows(self):
        """Allowed aid at level 0 plus level 1 under a non-allowed aid, overlapping: a hand-written snapshot (the builder
        would set E01 aside) gives BENEFIT_LEVEL_MISSING."""
        rows = [(key("E01"), esn.ident(b"13"), 0, 20260101, 99991231), (key("E01"), esn.ident(b"105"), 1, 20260101, 99991231)]
        self.passes(vector(esn.fragment(esn.pin_rows(20270314, rows)).splitlines(), [("E01", "HOLD BENEFIT_LEVEL_MISSING")],
                           ["E01"]), 1)
        built = build([rec("E01", aid="13", level=0), rec("E01", aid="105", level=1)] + pad())
        self.assertEqual(cause_of(built, "E01"), "conflicting_rows")

    def test_age(self):
        seven = self.roster(as_of="2027-03-08").fragment.splitlines()
        self.passes(vector(seven, [("E01", "ALLOW -")], self.MEMBERS), 1)
        eight = self.roster(as_of="2027-03-07")
        self.assertTrue(eight.sidecar["stale"])
        self.passes(vector(eight.fragment.splitlines(), [("E01", "HUMAN_REVIEW STALE_ELIGIBILITY"),
                                                         ("E04", "HUMAN_REVIEW PROGRAM_NOT_ELIGIBLE_UNVERIFIED,STALE_ELIGIBILITY"),
                                                         ("E03", "HUMAN_REVIEW BENEFIT_LEVEL_MISSING_UNVERIFIED,STALE_ELIGIBILITY")],
                           self.MEMBERS), 3)

    def test_no_snapshot_and_flipped_pin(self):
        self.passes(vector([], [("E01", "HUMAN_REVIEW STALE_ELIGIBILITY")], self.MEMBERS), 1)
        frag = self.roster().fragment.splitlines()
        f = frag[0].split()
        f[4] = f[4][:10] + ("0" if f[4][10] != "0" else "1") + f[4][11:]
        self.passes(vector([" ".join(f)] + frag[1:], [("E01", "HUMAN_REVIEW STALE_ELIGIBILITY")], self.MEMBERS), 1)

    def test_wrong_secret_on_the_837_side(self):
        frag = self.roster().fragment.splitlines()
        self.passes(vector(frag, [(m, "HOLD PROGRAM_NOT_ELIGIBLE") for m in self.MEMBERS], self.MEMBERS,
                           line_secret=OTHER_SECRET), len(self.MEMBERS))


if __name__ == "__main__":
    unittest.main()
