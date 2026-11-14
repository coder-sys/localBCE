"""Source registry and source state (design fact-record §2.3, §3.1-§3.3): the Python twin in
app/right_rail_fact_registry.py against the golden entry bytes and the scripted run held in
lean/BlindLedger/Gate/FactRegistry.lean (the one place they are written; the Lean build checks the same bytes and
the same output lines).  Synthetic, non-PHI."""

import re
import time
import unittest
from pathlib import Path

from app import right_rail_fact_registry as g

LEAN_FILE = Path(__file__).resolve().parents[1] / "lean" / "BlindLedger" / "Gate" / "FactRegistry.lean"


def pat(n, s):
    return bytes((s + i) & 255 for i in range(n))


def entry(src, cls, origin, ids, gapless, maxage, drop, oneper, scope, name, rule, full, cfrom_rule):
    return {"src": src, "cls": cls, "origin": origin, "kinds": g.mask_of(ids), "gapless": gapless, "maxage": maxage,
            "drop": drop, "oneper": oneper, "scope": g.ident(21, scope), "name": g.ident(31, name),
            "fseq_rule": rule, "full": full, "cfrom_rule": cfrom_rule, "ids": ids}


ENTRIES = {
    "e1": entry(1, 2, 7, [(1, [10, 11]), (2, [12])], 0, 90, 10, 1, "MEDICAID", "STATE ELIGIBILITY", 1, 1, 0),
    "e2": entry(2, 3, 8, [(5, [20])], 1, 7, 0, 0, "", "SECOND SOURCE", 2, 0, 0),
    "e3": entry(3, 1, 9, [(2, [1, 2, 3, 65535])], 0, 90, 50, 0, "MEDICAID", "THIRD SOURCE", 1, 1, 1),
    "e4": entry(65535, 5, 65535, [(i, [65535]) for i in range(1, 64)], 1, 65535, 50, 1, "P" * 20, "N" * 30, 2, 1, 1),
}


def rcpt(src, cover, asof, cfrom, fseq, tag, rows, frows, reader=1, reread=0, in_scope=0):
    return {"src": src, "cover": cover, "kb": 0, "asof": asof, "cfrom": cfrom, "fseq": fseq, "file": pat(64, tag),
            "sender": g.ident(21, "SENDER"), "channel": 1, "key": 1, "reader": reader, "reread": reread,
            "rows": rows, "admitted": rows, "same": 0, "quar": 0,
            "scope": g.ident(21, "MEDICAID" if cover == 1 or in_scope == 1 else ""), "frows": frows}


def run(script, reg):
    st, out = g.State(), []
    for step in script:
        op = step[0]
        if op == "adm":
            a, st = g.admit(reg, st, len(st.recs), step[1], step[2])
            out.append(a)
        elif op == "frame":
            a, st = g.admit_frame(reg, st, step[1], step[2], len(st.recs), step[3], step[4])
            out.append(a)
        elif op == "stale":
            e = g.lookup(reg, step[1])
            out.append("unregistered" if e is None else g.stale_cause(e, st, step[2]) or "fresh")
        elif op == "cut":
            out.append(str(g.late_until(g.rcpts_of(st.recs, step[1]), step[2])))
        elif op == "reuse":
            st = st.confirm_reuse(step[1])
        elif op == "drop":
            st = st.confirm_drop(step[1])
    return out


def lean_text():
    return LEAN_FILE.read_text("utf-8")


def lean_golden():
    table = lean_text().split("def goldenEntries :", 1)[1].split("def goldenEntriesOk", 1)[0]
    return {n: bytes.fromhex(h) for n, h in re.findall(r'\("(e\d)",\s*e\d,\s*"([0-9a-f]+)"\)', table)}


def lean_expected():
    block = lean_text().split("def expected :", 1)[1].split("#guard", 1)[0]
    return re.findall(r'"([^"]*)"', block)


def lean_script():
    """The scripted run as the Lean file writes it (one place), as the steps `run` takes."""
    block = lean_text().split("def script :", 1)[1].split("def expected", 1)[0]
    steps = []
    for op, pre, rc, post in re.findall(
            r"\.(stale|cut|reuse|drop|adm|frame)((?:\s+\d+)*)(?:\s*\(mkRcpt((?:\s+\d+)+)\))?((?:\s+\d+)*)", block):
        nums = [int(x) for x in pre.split()]
        if rc:
            nums.append(rcpt(*[int(x) for x in rc.split()]))
        steps.append((op, *nums, *[int(x) for x in post.split()]))
    return steps


SCRIPT = lean_script()


class RegistryTests(unittest.TestCase):
    def test_golden_entries_are_the_leans(self):
        golden = lean_golden()
        self.assertEqual(set(golden), set(ENTRIES))
        for name, e in ENTRIES.items():
            self.assertEqual(g.encode_entry(e), golden[name], name)
            back, rest = g.decode_entry(golden[name] + b"tail")
            self.assertEqual((back, rest), (e, b"tail"), name)

    def test_scripted_run_is_the_leans(self):
        reg = [ENTRIES["e1"], ENTRIES["e2"], ENTRIES["e3"]]
        self.assertEqual(run(SCRIPT, reg), lean_expected())

    def test_bad_entries_are_refused(self):
        good = g.encode_entry(ENTRIES["e1"])
        for bad in (b"", good[:-1], good[:20]):
            with self.assertRaises(ValueError):
                g.decode_entry(bad)
        for field, value in (("src", 0), ("cls", 0), ("cls", 6), ("gapless", 2), ("drop", 51), ("fseq_rule", 3),
                             ("full", 2), ("cfrom_rule", 2), ("kinds", 0), ("ids", [(2, []), (1, [])]),
                             ("ids", [(0, [])]), ("ids", [(64, [])])):
            with self.assertRaises(ValueError, msg=field):
                g.encode_entry({**ENTRIES["e1"], field: value})
        with self.assertRaises(ValueError):  # a kind with no identity field would give every row one identity
            g.encode_entry({**ENTRIES["e1"], "ids": [(3, [])], "kinds": 8})
        with self.assertRaises(ValueError):  # a gapless source must count by its own counter
            g.encode_entry({**ENTRIES["e2"], "fseq_rule": 1})

    def test_non_canonical_identifiers_and_duplicate_sources_are_refused(self):
        good = g.encode_entry(ENTRIES["e1"])
        for at, v in ((18 + 1 + 8, 1), (18, 21), (39, 31), (39 + 1 + 17, 1)):  # junk after the text, length over the block
            bad = bytearray(good)
            bad[at] = v
            with self.assertRaises(ValueError, msg=at):
                g.decode_entry(bytes(bad))
        with self.assertRaises(ValueError):
            g.encode_entry({**ENTRIES["e1"], "scope": bytes([1, 65]) + bytes([0] * 18) + bytes([1])})
        self.assertTrue(g.registry_ok([ENTRIES["e1"], ENTRIES["e2"], ENTRIES["e3"]]))
        self.assertFalse(g.registry_ok([ENTRIES["e1"], {**ENTRIES["e2"], "src": ENTRIES["e1"]["src"]}]))
        self.assertFalse(g.registry_ok([{**ENTRIES["e1"], "src": 0}]))

    def test_hand_built_layout(self):
        b = g.encode_entry(ENTRIES["e1"])
        self.assertEqual(b[0:2], (1).to_bytes(2, "little"))
        self.assertEqual(b[5:13], (6).to_bytes(8, "little"))
        self.assertEqual(b[14:16], (90).to_bytes(2, "little"))
        self.assertEqual(b[16], 10)
        self.assertEqual(b[18:39], g.ident(21, "MEDICAID"))
        self.assertEqual(b[70:74], bytes([1, 1, 0, 2]))
        self.assertEqual(b[74:], bytes([1, 2]) + (10).to_bytes(2, "little") + (11).to_bytes(2, "little")
                         + bytes([2, 1]) + (12).to_bytes(2, "little"))

    def test_fseq_rule_one_never_wraps(self):
        self.assertLess(g.fseq_date_isa(20260101, 999_999_999), g.fseq_date_isa(20260102, 0))
        self.assertLess(g.fseq_date_isa(99991231, 999_999_999), 2**64)

    def test_dates_order(self):
        self.assertEqual(g.day_num(20260401) - g.day_num(20260101), 90)
        days = [y * 10000 + m * 100 + d for y in (1999, 2000, 2024, 2025, 2100) for m in range(1, 13)
                for d in range(1, 32) if g.valid_date(y * 10000 + m * 100 + d)]
        self.assertEqual([g.day_num(a) for a in days], sorted(g.day_num(a) for a in days))
        self.assertEqual(len({g.day_num(a) for a in days}), len(days))
        self.assertFalse(g.valid_date(20261301))
        self.assertFalse(g.valid_date(20250229))

    def test_day_before_is_the_calendar_day_before(self):
        self.assertEqual(g.day_before(0), 0)
        for y in (1999, 2000, 2024, 2025, 2100):
            for m in range(1, 13):
                for d in range(1, 32):
                    date = y * 10000 + m * 100 + d
                    if g.valid_date(date):
                        before = g.day_before(date)
                        self.assertTrue(g.valid_date(before), date)
                        self.assertEqual(g.day_num(before) + 1, g.day_num(date), date)

    def test_fseq_rule_one_and_the_batch_day_are_enforced(self):
        reg = [ENTRIES["e1"], ENTRIES["e2"]]
        for fseq in (2**63 - 1, 20261301000000001, 5):  # huge, invalid date, no date
            a, st = g.admit(reg, g.State(), 0, rcpt(1, 2, 20260101, 0, fseq, 1, 0, 0), 0)
            self.assertEqual((a, st.recs), ("refused record", []), fseq)
        a, st = g.admit(reg, g.State(), 0, rcpt(1, 2, 20260101, 0, 20260101000000005, 1, 0, 0), 0)
        self.assertEqual(a, "admitted 0 0")
        # a file built after its as-of day is legitimate; only the batch day bounds the number's date
        late = rcpt(1, 2, 20260101, 0, 20260102000000001, 1, 0, 0)
        self.assertEqual(g.admit(reg, g.State(), 0, late, 0)[0], "admitted 0 0")
        self.assertEqual(g.admit_frame(reg, g.State(), 20260101, 20260102, 0, late, 0)[0], "admitted 0 0")
        a, st = g.admit_frame(reg, g.State(), 20260101, 20260101, 0, late, 0)
        self.assertEqual((a, st.recs), ("refused record", []))
        self.assertEqual(g.admit_frame(reg, g.State(), 20260101, 20260101, 0, rcpt(1, 2, 20260101, 0, 20260101000000005, 1, 0, 0), 0)[0], "admitted 0 0")
        self.assertTrue(g.fseq_date_ok(ENTRIES["e2"], rcpt(2, 2, 20260101, 0, 2**63, 1, 0, 0)))  # rule 2 has no date
        a, st = g.admit_frame(reg, g.State(), 20260105, 20260106, 0, rcpt(2, 2, 20260107, 0, 1, 1, 0, 0), 0)
        self.assertEqual((a, st.recs), ("refused record", []))
        a, _ = g.admit_frame(reg, g.State(), 20260105, 20260106, 0, rcpt(2, 2, 20260106, 0, 1, 1, 0, 0), 0)
        self.assertEqual(a, "admitted 0 0")

    def test_a_registry_that_is_not_ok_admits_nothing(self):
        r = rcpt(1, 2, 20260101, 0, 20260101000000005, 1, 0, 0)
        twice = [ENTRIES["e1"], {**ENTRIES["e2"], "src": 1}]  # two entries for src 1: the first would shadow
        for reg in (twice, [{**ENTRIES["e1"], "src": 0}]):
            a, st = g.admit_frame(reg, g.State(), 20260101, 20260101, 0, r, 0)
            self.assertEqual((a, st.recs), ("refused registry", []))
        a, _ = g.admit_frame([ENTRIES["e1"], ENTRIES["e2"]], g.State(), 20260101, 20260101, 0, r, 0)
        self.assertEqual(a, "admitted 0 0")

    def test_a_huge_gap_is_found_at_once(self):
        start = time.monotonic()
        self.assertTrue(g.gap_at([rcpt(2, 2, 20260101, 0, 5, 1, 0, 0)], 5, 2**63 - 1))
        self.assertFalse(g.gap_at([rcpt(2, 2, 20260101, 0, 6, 1, 0, 0), rcpt(2, 2, 20260101, 0, 7, 2, 0, 0)], 5, 8))
        self.assertLess(time.monotonic() - start, 1.0)

    def test_a_reread_must_match_its_original(self):
        reg = [ENTRIES["e1"]]
        d = 20260101000000100
        _, st = g.admit(reg, g.State(), 0, rcpt(1, 1, 20260101, 20260101, d, 1, 10, 10), 0)
        again = rcpt(1, 4, 20260101, 0, d, 1, 0, 0, 2, 0, 1)
        for bad in ({"file": pat(64, 99)}, {"asof": 20260102}, {"scope": g.ident(21, "")},
                    {"sender": g.ident(21, "OTHER")}, {"reread": 5}):
            a, after = g.admit(reg, st, 1, {**again, **bad}, 0)
            self.assertEqual((a, after.reused, after.recs), ("refused reread", [], st.recs), bad)  # not REUSED
        a, st2 = g.admit(reg, st, 1, again, 0)
        self.assertEqual(a, "admitted 1 0")
        self.assertEqual(g.admit(reg, st2, 2, again, 0)[0], "already 1")
        a, after = g.admit(reg, st, 1, rcpt(1, 2, 20260101, 0, d, 2, 0, 0), 0)  # a different file, same number
        self.assertEqual((a, after.reused), ("refused reused", [1]))

    def test_day_rule(self):
        self.assertTrue(g.day_ok(20260105, 20260105))
        self.assertFalse(g.day_ok(20260105, 20260104))
        self.assertFalse(g.day_ok(20260105, 20260231))

    def test_drop_check_bound(self):
        # a file that passes keeps (100 - drop) percent, and with the cap of 50 the old count is at most twice the new
        self.assertFalse(g.drop_fails(10, 90, 100))
        self.assertTrue(g.drop_fails(10, 89, 100))
        self.assertFalse(g.drop_fails(50, 50, 100))
        self.assertTrue(g.drop_fails(50, 49, 100))
        self.assertFalse(g.drop_fails(0, 0, 0))
        seen = set()
        for drop in (0, 10, 50):
            for new in range(0, 40):
                for old in range(0, 80):
                    fails = g.drop_fails(drop, new, old)
                    seen.add(fails)
                    self.assertEqual(fails, new < -(-(100 - drop) * old // 100))  # fewer than the kept share, rounded up
                    if not fails:
                        self.assertLessEqual(old * (100 - drop), new * 100)
                        self.assertLessEqual(old, 2 * new)
        self.assertEqual(seen, {True, False})

    def test_old_files_never_make_a_stale_source_fresh(self):
        reg = [ENTRIES["e1"]]
        st = g.State()
        _, st = g.admit(reg, st, 0, rcpt(1, 1, 20260101, 20260101, 20260101000000100, 1, 10, 10), 0)
        e = reg[0]
        causes = [g.stale_cause(e, st, d) for d in (20260401, 20260402, 20260403, 20260601, 20270101)]
        self.assertEqual(causes, [None, "age", "age", "age", "age"])

    def test_ends_need_a_clean_full_receipt(self):
        st = g.State(dropped=[3], reused=[7])
        full = rcpt(1, 1, 20260101, 20260101, 1, 1, 1, 1)
        self.assertTrue(g.ends_allowed(g.State(), 0, full, False))
        self.assertFalse(g.ends_allowed(st, 3, full, False))
        self.assertFalse(g.ends_allowed(st, 0, {**full, "src": 7}, False))
        self.assertFalse(g.ends_allowed(g.State(), 0, full, True))
        self.assertFalse(g.ends_allowed(g.State(), 0, rcpt(1, 2, 20260101, 0, 1, 1, 1, 1), False))

    def test_late_until_never_depends_on_arrival_order(self):
        fulls = [rcpt(1, 1, 20260301, 20260301, 300, 3, 1, 1), rcpt(1, 1, 20260401, 20260401, 400, 5, 1, 1)]
        for order in (fulls, fulls[::-1]):
            self.assertEqual(g.late_until(order, 200), 20260228)
            self.assertEqual(g.late_until(order, 300), 20260331)
            self.assertEqual(g.late_until(order, 400), g.OPEN)


if __name__ == "__main__":
    unittest.main()
