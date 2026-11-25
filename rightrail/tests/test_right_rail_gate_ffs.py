"""Fee-for-service claim lines decided by the real gate engine (synthetic members, claims and providers; non-PHI)."""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import hashlib
import json
import operator
import os
import random
import sqlite3
import string
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_deployment_slots as slots
from app import right_rail_gate_ffs as ffs
from app import right_rail_gate_producer as producer
from app import right_rail_reader_leie as leie
from app import right_rail_x12_834 as r834
from app import right_rail_x12_835 as r835
from app import right_rail_x12_837 as r837
from app.right_rail_reader_lines import name_tokens
from conformance import gate_rules_v1_ref as ref
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx
from tests import test_reader_leie as tl
from tests import test_right_rail_deployment_slots as ts
from tests import test_ruleset_admission as ra
from tests import test_ruleset_v1_codec as rs
from tests import test_x12_834 as t834
from tests import test_x12_835 as t835
from tests import test_x12_837 as t837

ROOT = Path(__file__).resolve().parents[1]

NO_ONE = leie.read_leie((tl.HEAD + tl.row(npi=tl.make_npi(1))).encode(), source="synthetic", as_of="2027-03-10")  # a list naming nobody the tests use
EXCLUDED, CLEAN = "1234567893", "1003000126"  # 10-digit NPIs: 11 bytes as Lean's identifier number, past a u64


def with_exclusion(head: list[str], npi: str) -> list[str]:
    """The vector header with ``npi`` excluded from 2026-01-01 on, the exclusion snapshot re-pinned."""
    rows = [r for r in head if r.split()[:1] == ["excl"]] + [f"excl {g.nat(npi.encode())} 20260101 99991231"]
    out = []
    for r in head:
        f = r.split()
        if f[:2] == ["snap", "excl"]:
            vals = [tuple(int(x) for x in s.split()[1:]) for s in rows]
            out += [f"snap excl {f[2]} {len(rows)} {hashlib.sha3_512(ref.pin_bytes('excl', int(f[2]), len(vals), vals)).hexdigest()}", *rows]
        elif f[:1] != ["excl"]:
            out.append(r)
    return out


def person(mid: str, last: str, first: str, born: str, **kw) -> list[str]:
    """An 834 member loop (test_x12_834.member) for ``mid`` with this name and birth date."""
    loop = t834.member(mid, **kw)
    loop[3], loop[6] = f"NM1*IL*1*{last}*{first}*Q***34*999{mid[-4:]}", f"DMG*D8*{born}*F"
    return loop


def claim(n: int, member: int, npi: str, date: int, code: str, cents: int, shard: int = 0) -> gate.DecideRequest:
    """One single-line claim billed and rendered by ``npi`` for harness member ``member`` on ``shard``."""
    key = g.member(member, shard)
    line = gate.encode_line("FFS_CLAIM", f"L{n}", key, npi, npi, date, code, 1, cents)
    return gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", f"cmd-{n}", f"pay-{n}", key, npi, cents, fx.PERIOD, (line,),
                              tuple(sorted((fx.D[2], fx.D[5]))))


class ExcludedNpiTests(fx.Scratch):
    @classmethod
    def setUpClass(cls) -> None:
        if os.name != "nt":
            raise unittest.SkipTest("the host runs the Windows exes")
        if not g.ENGINE.is_file():  # a missing pinned exe is a failure of the full suite, never a silent skip
            raise AssertionError(f"FFS LINES NOT RUN: {g.ENGINE} missing; run `lake build gate_engine` in lean/")

    def test_a_line_billed_by_an_excluded_10_digit_npi_holds_and_a_clean_one_is_allowed(self) -> None:
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            prod, worker = self.track(c.producer(0)), decider.RulesWorker(g.ENGINE)
            try:
                ans = decider.decide(g.feeds_of(with_exclusion(g._HEAD, EXCLUDED)), g.ASOF, prod,
                                     [claim(1, 1001, EXCLUDED, 20270305, "C99213", 12500), claim(2, 1002, CLEAN, 20270306, "C99214", 9800)],
                                     Path(tmp) / "idx", worker, g.GRANT, g.KEYS, c.tenant)
            finally:
                worker.close()
        self.assertEqual(ans.lines, ())
        got = {ans.owners[r.index][0]: (r.outcome, r.reasons) for r in ans.recs}
        self.assertEqual(got, {"pay-1": ("HOLD", ("PROVIDER_EXCLUDED",)), "pay-2": ("ALLOW", ())})

    def test_a_member_death_feed_with_no_rows_or_none_is_unknown_never_nobody_died(self) -> None:
        """Rules/Spec.lean ``usable``: a snapshot with no rows (an 834 with no death in it) or none at all is not usable, so a
        line is STALE_DMF review, never ALLOW: no death list is ever read as nobody died."""
        today, (_, *rest) = g.HEAD
        for dmf in (decider.feed("dmf", today, []), (bytes(77), b"")):
            with self.scratch() as tmp:
                c = g.Cluster(tmp, fx.custody(tmp))
                prod, worker = self.track(c.producer(0)), decider.RulesWorker(g.ENGINE)
                try:
                    ans = decider.decide((today, (dmf, *rest)), g.ASOF, prod, [claim(1, 1001, CLEAN, 20270305, "C99213", 12500)],
                                         Path(tmp) / "idx", worker, g.GRANT, g.KEYS, c.tenant)
                finally:
                    worker.close()
            self.assertEqual([(r.outcome, r.reasons) for r in ans.recs], [("HUMAN_REVIEW", ("STALE_DMF",))], dmf[0][:1])

    def test_a_provider_row_set_aside_for_its_dates_holds_every_claim_of_that_provider(self) -> None:
        """A death after its list's date and a reinstatement before the exclusion are reported, and the provider is sent dead
        since 0001-01-01 or excluded from then on, never dropped so that its claims are allowed."""
        listed = leie.read_leie((tl.HEAD + tl.row(npi=EXCLUDED) + tl.row(last="BACK", npi=CLEAN, excl="20260101", rein="20250101")).encode(),
                                source="synthetic", as_of="2027-03-10")
        (_, (_, pdeath, excl, _)), left = ffs.feeds(g.HEAD[0], r834.read_834(t837.file_of([t834.header() + t834.member("M1")])), listed,
                                                    ("2027-03-01", [(tl.make_npi(7), "2027-01-01"), (DEAD, "2027-03-05")]), b"s")
        self.assertEqual([(a.id, a.cause) for a in left], [(DEAD, "bad_dates"), ("BACK", "bad_dates")])
        today, (dmf, _, _, span) = g.HEAD
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            prod, worker = self.track(c.producer(0)), decider.RulesWorker(g.ENGINE)
            try:
                ans = decider.decide((today, (dmf, pdeath, excl, span)), g.ASOF, prod,
                                     [claim(1, 1001, DEAD, 20270305, "C99213", 12500), claim(2, 1002, CLEAN, 20270306, "C99214", 9800)],
                                     Path(tmp) / "idx", worker, g.GRANT, g.KEYS, c.tenant)
            finally:
                worker.close()
        got = {ans.owners[r.index][0]: (r.outcome, r.reasons) for r in ans.recs}
        self.assertEqual(got, {"pay-1": ("HOLD", ("PROVIDER_DECEASED",)), "pay-2": ("HOLD", ("PROVIDER_EXCLUDED",))})


class FeedTests(unittest.TestCase):
    def test_a_feed_from_typed_rows_is_the_vector_headers_frame_feed(self) -> None:
        today, feeds = g.HEAD
        for kind, want in zip(decider.FEED_WIDTHS, feeds):
            snap = next(r.split() for r in g._HEAD if r.startswith(f"snap {kind} "))
            rows = [tuple(map(int, r.split()[1:])) for r in g._HEAD if r.split()[:1] == [kind]]
            self.assertEqual((int(snap[3]), decider.feed(kind, int(snap[2]), rows)), (len(rows), want), kind)
        self.assertEqual(today, int(next(r for r in g._HEAD if r.startswith("today ")).split()[1]))

    def test_a_row_that_does_not_fit_its_frame_width_makes_the_feed_missing(self) -> None:
        for rows in ([(1 << 168, 20260101)], [(5,)], [(5, 1 << 32)]):
            self.assertEqual(decider.feed("pdeath", 20260101, rows), (b"\x02" + bytes(76), b""), rows)

    def test_an_834_row_with_no_plan_is_set_aside_and_the_rest_of_the_file_is_read(self) -> None:
        secret, bare, blank = b"synthetic tenant secret, 32 b..", t834.member("M1")[:7], t834.member("M3")  # M1: no coverage loop
        blank[7] = "HD*021**HLT**IND"  # M3: a coverage loop that names no plan
        read = r834.read_834(t837.file_of([t834.header() + bare + t834.member("M2") + blank]))
        (today, sent), left = ffs.feeds(20260105, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                        ("2026-01-01", []), secret)
        self.assertEqual([(a.id, a.cause) for a in left], [("M1", "no_plan"), ("M3", "no_plan")])
        span = (ffs.ident(ffs.member_key(secret, "M2")), ffs.ident(b"PLAN-A"), 20260101, 20261231)
        self.assertEqual((today, sent[3]), (20260105, decider.feed("span", 20260102, [span])))

    def test_a_cancellation_ends_the_spans_up_to_it_and_one_with_no_date_two_adds_or_a_dependent_give_none(self) -> None:
        secret, cancel = b"synthetic tenant secret, 32 b..", dict(ins03="024")
        on = t834.member("M3", end="", **cancel)
        on.insert(3, "DTP*303*D8*20260215")  # no end date: the cancellation's effective date is the first day not covered
        bare = t834.member("M4", end="", **cancel)  # no end and no effective date
        plans = t834.member("M6", end="", extra=["HD*024**HLT*PLAN-B*IND", "DTP*348*D8*20260101", "DTP*349*D8*20260430"])
        kid = t834.member("M1", death="20251201", plan="PLAN-K")  # a dependent: the subscriber's REF*0F, never the subscriber's span or death
        kid[0] = kid[0].replace("INS*Y*18", "INS*N*19")
        moved = t834.member("M7", end="20260331", **cancel) + t834.member("M7", begin="20260501", plan="PLAN-B")  # cancelled, then added again
        read = r834.read_834(t837.file_of([t834.header() + t834.member("M1") + kid + t834.member("M2", end="20260331", **cancel) + on + bare
                                           + t834.member("M5") + t834.member("M5", end="20260131", **cancel) + plans + moved
                                           + t834.member("M8") + t834.member("M8", plan="PLAN-B")]))
        (_, sent), left = ffs.feeds(20260105, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                    ("2026-01-01", []), secret)
        self.assertEqual([(a.id, a.cause) for a in left], [("M1", "dependent_member"), ("M4", "termination"), ("M8", "conflicting_rows"),
                                                           ("M8", "conflicting_rows")])
        span = lambda m, end, plan=b"PLAN-A", begin=20260101: (ffs.ident(ffs.member_key(secret, m)), ffs.ident(plan), begin, end)  # noqa: E731
        self.assertEqual(sent[3], decider.feed("span", 20260102, [span("M1", 20261231), span("M2", 20260331), span("M3", 20260214),
                                                                  span("M5", 20260131), span("M5", 20260131), span("M6", 20260430),
                                                                  span("M6", 20260430, b"PLAN-B"), span("M7", 20260331),
                                                                  span("M7", 20261231, b"PLAN-B", 20260501)]))
        self.assertEqual(sent[0], decider.feed("dmf", 20260102, []))

    def test_a_member_with_a_segment_set_aside_gives_no_span_and_a_lost_member_makes_both_member_feeds_absent(self) -> None:
        secret, listed = b"synthetic tenant secret, 32 b..", leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01")
        twice, other = t834.member("M4", extra=["DTP*349*D8*20260630"]), t834.member("M5")  # M4: a second coverage end
        other[3] = "NM1*IL*1*DOE*JANE****MI*M9"  # the name loop names another member
        lost = t834.member("M6", end="20260131", ins03="024")
        lost[0] = lost[0].replace("INS*Y", "INS*Q")  # the cancellation's INS does not read: its REF*0F still sets M6 aside
        typo = t834.member("M7", extra=["DPT*349*D8*20260630"])  # an unknown segment in a member loop may be a date mistyped
        kid = t834.member("M1", end="20261340")  # a dependent's fault: the subscriber's rows stand
        kid[0] = kid[0].replace("INS*Y*18", "INS*N*19")
        body = (t834.header() + t834.member("M1") + kid + t834.member("M2", end="20261340") + t834.member("M3", death="20261301")
                + twice + other + t834.member("M6") + lost + typo)
        (_, sent), left = ffs.feeds(20260105, r834.read_834(t837.file_of([body])), listed, ("2026-01-01", []), secret)
        self.assertEqual([(a.id, a.cause) for a in left], [("M1", "dependent_member")] + [(m, "member_quarantined") for m in ("M2", "M3", "M4", "M5", "M6", "M6", "M7")])
        self.assertEqual((sent[0], sent[3]), (decider.feed("dmf", 20260102, []),
                                              decider.feed("span", 20260102, [(ffs.ident(ffs.member_key(secret, "M1")), ffs.ident(b"PLAN-A"), 20260101, 20261231)])))
        no_id = [s for s in t834.member("M7") if not s.startswith(("REF", "NM1"))]
        garbled = t834.member("M8")
        garbled[9] = "D?P*349*D8*20261231"  # a segment that does not read: it may have opened another member
        good = t834.header() + t834.member("M1")
        for data in (t837.file_of([good + no_id]), t837.file_of([good + garbled]),
                     t837.file_of([good]) + t837.file_of([t834.header() + t834.member("M1", ins03="024")], control="000000002", se_count=3)):
            (_, sent), _ = ffs.feeds(20260105, r834.read_834(data), listed, ("2026-01-01", []), secret)
            self.assertEqual((sent[0], sent[3]), ((bytes(77), b""), (bytes(77), b"")))

    SECRET = b"synthetic tenant secret, 32 b.."

    def span_feed(self, data: bytes):
        listed = leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01")
        (_, sent), _ = ffs.feeds(20260105, r834.read_834(data), listed, ("2026-01-01", []), self.SECRET)
        return sent[0], sent[3]

    @staticmethod
    def joined(files: list):
        """Several 834 files, each read on its own and joined field by field into one read."""
        reads = [r834.read_834(f) for f in files]
        return r834.Read834(*(functools.reduce(operator.add, parts) for parts in zip(*reads)))

    def fed(self, read):
        """The member feeds and the set-asides of one 834 read (bytes are read first; a list is several files)."""
        listed = leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01")
        read = r834.read_834(read) if isinstance(read, bytes) else self.joined(read) if isinstance(read, list) else read
        (_, sent), left = ffs.feeds(20260105, read, listed, ("2026-01-01", []), self.SECRET)
        return sent[0], sent[3], sorted((a.id, a.cause) for a in left)

    def key(self, m: str) -> int:
        return ffs.ident(ffs.member_key(self.SECRET, m))

    def spans(self, asof: int, *covered: str, plans: dict | None = None) -> bytes:
        """The span feed's descriptor: its count and the pin over its sorted rows, so it does not depend on file order."""
        return decider.feed("span", asof, [(self.key(m), ffs.ident((plans or {}).get(m, "PLAN-A").encode()), 20260101, 20261231) for m in covered])[0]

    def plans(self, asof: int, *pairs: tuple) -> bytes:
        """The span feed's descriptor for (member, plan) pairs, each covered for all of 2026."""
        return decider.feed("span", asof, [(self.key(m), ffs.ident(p.encode()), 20260101, 20261231) for m, p in pairs])[0]

    def check(self, data: bytes, asof: int, covered: list, older: list) -> None:
        """Only the newest full roster's rows make the span feed; each older file is one ``mixed_file_times`` item, named by its
        interchange and time; whoever the newest leaves out has no span."""
        dmf, span, left = self.fed(data)
        self.assertEqual((dmf, span[0]), (decider.feed("dmf", asof, []), self.spans(asof, *covered)))
        self.assertEqual(left, sorted((f, "mixed_file_times") for f in older))

    def test_the_newest_of_two_files_one_day_apart_gives_the_feed_and_the_older_file_is_one_item(self) -> None:
        old = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        new = t837.file_of([t834.header() + t834.member("M1")], control="000000002")  # M2 is absent from the newer roster: no span, so it holds
        self.check([old, new], 20260102, ["M1"], ["interchange 0 made 2025-12-01T09:30:00"])
        self.check([new, old], 20260102, ["M1"], ["interchange 0 made 2025-12-01T09:30:00"])

    def test_the_newest_of_two_files_made_on_one_day_gives_the_feed_in_either_order(self) -> None:
        one = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201", gs_time="0800")
        two = t837.file_of([t834.header() + t834.member("M1")], control="000000002", gs_date="20251201", gs_time="1830")
        self.check([one, two], 20251201, ["M1"], ["interchange 0 made 2025-12-01T08:00:00"])
        self.check([two, one], 20251201, ["M1"], ["interchange 0 made 2025-12-01T08:00:00"])

    def test_a_full_roster_split_inside_one_file_on_one_day_is_one_roster_whatever_its_times_in_either_order(self) -> None:
        """Ruled behaviour (it replaces the rule that only the newest group of a file counted): the full rosters of one file made
        on one day are one roster, dated at the newest of their interchanges and groups."""
        groups = t837.file_of([], groups=[[t834.header() + t834.member("M1")], [t834.header() + t834.member("M2")]])
        for data in (groups.replace(b"*20260102*0930*2*", b"*20260102*1830*2*"), groups.replace(b"*20260102*0930*1*", b"*20260102*1830*1*")):
            self.check(data, 20260102, ["M1", "M2"], [])
        one = t837.file_of([t834.header() + t834.member("M1")], gs_date="20251201", gs_time="080000")
        two = t837.file_of([t834.header() + t834.member("M2")], control="000000002", gs_date="20251201", gs_time="080005")
        old = t837.file_of([t834.header() + t834.member("M3")], gs_date="20251130")
        for data in (one + two, two + one):
            self.check(data, 20251201, ["M1", "M2"], [])
            self.check([old, data], 20251201, ["M1", "M2"], ["interchange 0 made 2025-11-30T09:30:00"])

    def test_a_full_roster_of_an_earlier_day_inside_one_file_is_an_older_roster_in_either_order(self) -> None:
        dec1 = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        dec2 = t837.file_of([t834.header() + t834.member("M1")], control="000000002", gs_date="20251202")  # M2 is not paid
        self.check(dec1 + dec2, 20251202, ["M1"], ["interchange 0 made 2025-12-01T09:30:00"])
        self.check(dec2 + dec1, 20251202, ["M1"], [f"interchange {len(dec2)} made 2025-12-01T09:30:00"])

    def test_a_death_in_an_older_file_stays_in_the_death_feed_in_either_order(self) -> None:
        old = t837.file_of([t834.header() + t834.member("M1", death="20251115") + t834.member("M2")], gs_date="20251201")
        new = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], control="000000002", gs_date="20251202")
        for data in ([old, new], [new, old]):
            dmf, span, _ = self.fed(data)
            self.assertEqual((dmf, span[0]), (decider.feed("dmf", 20251202, [(self.key("M1"), 20251115)]), self.spans(20251202, "M1", "M2")))

    def test_a_death_after_the_as_of_in_an_older_file_holds_that_member_in_either_order(self) -> None:
        old = t837.file_of([t834.header() + t834.member("M1", death="20521115") + t834.member("M2")], gs_date="20251201")
        new = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], control="000000002", gs_date="20251202")
        for data in ([old, new], [new, old]):
            dmf, span, left = self.fed(data)
            self.assertEqual(span[0], self.spans(20251202, "M2"))
            self.assertEqual(left, [("M1", "bad_dates"), ("interchange 0 made 2025-12-01T09:30:00", "mixed_file_times")])

    def test_a_dead_member_absent_from_the_newest_roster_stays_dead(self) -> None:
        old = t837.file_of([t834.header() + t834.member("M1", death="20251115") + t834.member("M2")], gs_date="20251201")
        new = t837.file_of([t834.header() + t834.member("M2")], control="000000002", gs_date="20251202")
        for data in ([old, new], [new, old]):
            dmf, span, left = self.fed(data)
            self.assertEqual((dmf, span[0]), (decider.feed("dmf", 20251202, [(self.key("M1"), 20251115)]), self.spans(20251202, "M2")))
            self.assertEqual([c for _, c in left], ["mixed_file_times"])

    def test_two_death_dates_for_one_member_both_reach_the_death_feed_unless_one_is_after_the_as_of(self) -> None:
        old = t837.file_of([t834.header() + t834.member("M1", death="20251115") + t834.member("M2")], gs_date="20251201")
        new = t837.file_of([t834.header() + t834.member("M1", death="20251120") + t834.member("M2")], control="000000002", gs_date="20251202")
        for data in ([old, new], [new, old]):
            dmf, span, _ = self.fed(data)
            self.assertEqual(dmf[0], decider.feed("dmf", 20251202, [(self.key("M1"), 20251115), (self.key("M1"), 20251120)])[0])
            self.assertEqual(span[0], self.spans(20251202, "M1", "M2"))
        late = t837.file_of([t834.header() + t834.member("M1", death="20521115") + t834.member("M2")], gs_date="20251201")
        for data in ([late, new], [new, late]):  # the older death cannot be read against the as-of: the member holds, its other death stays
            dmf, span, left = self.fed(data)
            self.assertEqual((dmf, span[0]), (decider.feed("dmf", 20251202, [(self.key("M1"), 20251120)]), self.spans(20251202, "M2")))
            self.assertEqual([c for _, c in left], ["bad_dates", "mixed_file_times"])

    def test_two_interchanges_made_at_one_time_are_combined_and_agreeing_rows_give_one_span(self) -> None:
        """Ruled tie behaviour (it replaces the earlier rule that held every member of a tie): HHMM and HHMMSS spell one time."""
        one = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201", gs_time="0800")
        two = t837.file_of([t834.header() + t834.member("M1")], control="000000002", gs_date="20251201", gs_time="080000")  # M2 is only in the first
        for data in ([one, two], [two, one]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (self.spans(20251201, "M1", "M2"), []))

    def test_a_roster_split_over_two_interchanges_of_one_time_covers_everyone(self) -> None:
        one = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201", gs_time="0800")
        two = t837.file_of([t834.header() + t834.member("M3") + t834.member("M4")], control="000000002", gs_date="20251201", gs_time="0800")
        for data in ([one, two], [two, one]):
            self.check(data, 20251201, ["M1", "M2", "M3", "M4"], [])

    def test_two_interchanges_of_one_time_that_disagree_on_a_member_hold_that_member_only(self) -> None:
        one = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201", gs_time="0800")
        other = t837.file_of([t834.header() + t834.member("M1", plan="PLAN-B")], control="000000002", gs_date="20251201", gs_time="0800")
        cancel = t837.file_of([t834.header() + t834.member("M1", ins03="024", end="20260331")], control="000000002", gs_date="20251201", gs_time="0800")
        for data in ([one, other], [other, one], [one, cancel], [cancel, one]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (self.spans(20251201, "M2"), [("M1", "tied_files_disagree")]))

    def test_a_later_change_file_replaces_only_the_members_it_names(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        change = t837.file_of([["BGN*00*F2*20251202*0930****2", t834.header()[1]] + t834.member("M2", plan="PLAN-B")], control="000000002", gs_date="20251202")
        for data in ([full, change], [change, full]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (self.plans(20251202, ("M1", "PLAN-A"), ("M2", "PLAN-A"), ("M2", "PLAN-B")), []))  # a new plan: PLAN-A stays

    def test_change_files_with_no_full_roster_apply_in_time_order(self) -> None:
        head = lambda: ["BGN*00*F2*20251201*0930****2", t834.header()[1]]  # noqa: E731  BGN08 2: a change file
        first = t837.file_of([head() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        later = t837.file_of([head() + t834.member("M1", plan="PLAN-B")], control="000000002", gs_date="20251202")
        for data in ([first, later], [later, first]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (self.plans(20251202, ("M1", "PLAN-A"), ("M1", "PLAN-B"), ("M2", "PLAN-A")), []))

    def test_an_empty_newest_full_roster_makes_the_span_feed_absent_in_either_order(self) -> None:
        old = t837.file_of([t834.header() + t834.member("M1")], gs_date="20251201")
        empty = t837.file_of([t834.header()], control="000000002", gs_date="20251202")
        for data in ([old, empty], [empty, old]):
            dmf, span, left = self.fed(data)
            self.assertEqual(span, (bytes(77), b""))
            self.assertEqual(sorted(c for _, c in left), ["empty_roster", "mixed_file_times"])
            self.assertIn(("interchange 0 made 2025-12-02T09:30:00", "empty_roster"), left)

    def test_an_empty_full_roster_tied_with_a_full_one_makes_the_span_feed_absent(self) -> None:
        one = t837.file_of([t834.header() + t834.member("M1")], gs_date="20251201", gs_time="0800")
        empty = t837.file_of([t834.header()], control="000000002", gs_date="20251201", gs_time="0800")
        for data in ([one, empty], [empty, one]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span, [c for _, c in left]), ((bytes(77), b""), ["empty_roster"]))

    def test_an_empty_change_file_changes_nothing(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1")], gs_date="20251201")
        empty = t837.file_of([["BGN*00*F2*20251202*0930****2", t834.header()[1]]], control="000000002", gs_date="20251202")
        for data in ([full, empty], [empty, full]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (self.spans(20251202, "M1"), []))

    def test_a_fault_in_an_older_file_holds_its_member_and_one_outside_every_member_loop_makes_the_member_feeds_absent(self) -> None:
        """Ruled behaviour (it replaces the rule that an older file's faults were set aside with it and hurt no one): a fault
        may hide a death, and a death never reverses."""
        new = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], control="000000002", gs_date="20251202")
        inside = t837.file_of([t834.header() + t834.member("M1", extra=["QQ*2"]) + t834.member("M2")], gs_date="20251201")
        for data in ([inside, new], [new, inside]):
            dmf, span, left = self.fed(data)
            self.assertEqual((dmf, span[0], left), (decider.feed("dmf", 20251202, []), self.spans(20251202, "M2"),
                                                    [("M1", "member_quarantined"), ("interchange 0 made 2025-12-01T09:30:00", "mixed_file_times")]))
        outside = t837.file_of([t834.header() + ["QQ*1"] + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        bad_new = t837.file_of([t834.header() + ["QQ*1"] + t834.member("M1")], control="000000002", gs_date="20251202")
        for data in ([outside, new], [new, outside], [inside, bad_new]):
            self.assertEqual(self.fed(data)[:2], ((bytes(77), b""), (bytes(77), b"")))

    def test_a_death_that_does_not_read_in_an_older_file_holds_that_member_in_either_order(self) -> None:
        old = t837.file_of([t834.header() + t834.member("M1", death="20251115") + t834.member("M2")], gs_date="20251201")
        new = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], control="000000002", gs_date="20251202")
        for bad in (old.replace(b"D8*20251115", b"XX*20251115"), old.replace(b"D8*20251115", b"D8*20251315"), old.replace(b"INS*Y*", b"INS*Q*", 1)):
            for data in ([bad, new], [new, bad]):
                dmf, span, left = self.fed(data)
                self.assertEqual((dmf, span[0], left), (decider.feed("dmf", 20251202, []), self.spans(20251202, "M2"),
                                                        [("M1", "member_quarantined"), ("interchange 0 made 2025-12-01T09:30:00", "mixed_file_times")]))

    def test_a_cancellation_with_only_an_end_date_in_a_later_change_file_pays_up_to_that_end_as_in_one_full_file(self) -> None:
        """A change row that states no begin date keeps the base's begin and cuts its span at the end it states, never lengthening
        it.  An end that shortened the span was applied, so the row is not listed, as in one file; an end at or after the span's
        end changed nothing, so the row is listed (ruled)."""
        span = lambda m, end: (self.key(m), ffs.ident(b"PLAN-A"), 20260101, end)  # noqa: E731
        term = lambda end: [s for s in t834.member("M1", ins03="024", end=end) if not s.startswith(("DTP*348", "DTP*356"))]  # noqa: E731
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        for end, paid in (("20260331", 20260331), ("20271231", 20261231), ("20261231", 20261231)):
            change = t837.file_of([["BGN*00*F2*20251202*0930****2", t834.header()[1]] + term(end)], control="000000002", gs_date="20251202")
            for data in ([full, change], [change, full]):
                dmf, sent, left = self.fed(data)
                self.assertEqual((sent[0], left), (decider.feed("span", 20251202, [span("M1", paid), span("M2", 20261231)])[0],
                                                   [] if paid < 20261231 else [("M1", "no_dates")]))
        one = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2") + term("20260331")], gs_date="20251201")
        dmf, sent, left = self.fed(one)  # the cancellation's own row has no begin, and its cut was applied
        self.assertEqual((sent[0], left), (decider.feed("span", 20251201, [span("M1", 20260331), span("M2", 20261231)])[0], []))

    def test_a_change_row_with_no_coverage_loop_keeps_the_coverage_as_it_was(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        moved = [s.replace("N3*1 SYNTHETIC ST*APT 2", "N3*2 OTHER ST") for s in t834.member("M1", ins03="001") if not s.startswith(("HD", "DTP*348", "DTP*349"))]
        change = t837.file_of([["BGN*00*F2*20251202*0930****2", t834.header()[1]] + moved], control="000000002", gs_date="20251202")
        for data in ([full, change], [change, full]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (self.spans(20251202, "M1", "M2"), []))

    def change(self, rows: list, gs_date: str = "20251202", control: str = "000000002") -> bytes:
        return t837.file_of([[f"BGN*00*F2*{gs_date}*0930****2", t834.header()[1]] + rows], control=control, gs_date=gs_date)

    def test_a_delete_with_no_coverage_begin_in_a_later_change_file_holds_the_member_in_either_order(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        undated = lambda **kw: [s for s in t834.member("M1", **kw) if not s.startswith(("DTP*348", "DTP*356"))]  # noqa: E731
        for rows in (undated(ins03="002"), [s.replace("HD*021", "HD*002") for s in undated(ins03="001")]):  # the member deleted, its coverage deleted
            for data in ([full, self.change(rows)], [self.change(rows), full]):
                dmf, span, left = self.fed(data)
                self.assertEqual((span[0], left), (self.spans(20251202, "M2"), [("M1", "deleted")]))

    def test_a_later_cancellation_with_no_date_or_an_end_before_the_begin_pays_the_member_nothing(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        bare = [s for s in t834.member("M1", ins03="024") if not s.startswith(("DTP*348", "DTP*349", "DTP*356"))]
        early = [s for s in t834.member("M1", ins03="024", end="20251215") if not s.startswith(("DTP*348", "DTP*356"))]
        for rows in (bare, early):
            for data in ([full, self.change(rows)], [self.change(rows), full]):
                dmf, span, left = self.fed(data)
                self.assertEqual((span[0], left), (self.spans(20251202, "M2"), [("M1", "termination")]))  # one item: the cancel was applied

    def test_two_change_files_apply_in_time_order_whether_the_later_one_restates_or_updates(self) -> None:
        span = lambda plan, end: (self.key("M1"), ffs.ident(plan), 20260101, end)  # noqa: E731
        term = [s for s in t834.member("M1", ins03="024", end="20260331") if not s.startswith(("DTP*348", "DTP*356"))]
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        moved = t834.member("M1", plan="PLAN-B")
        for first, second, b_end in ((term, moved, 20261231), (moved, term, 20260331)):  # a cut reaches only rows filed before it; PLAN-A stays
            files = [full, self.change(first), self.change(second, "20251203", "000000003")]
            for data in (files, files[::-1]):
                dmf, sent, left = self.fed(data)
                self.assertEqual((sent[0], left), (decider.feed("span", 20251203, [span(b"PLAN-A", 20260331), span(b"PLAN-B", b_end),
                                                                                  (self.key("M2"), ffs.ident(b"PLAN-A"), 20260101, 20261231)])[0], []))

    def test_a_later_row_naming_a_plan_with_no_coverage_begin_is_set_aside_at_its_ins_and_the_earlier_span_stays(self) -> None:
        listed = leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01")
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        newplan = lambda end: [s for s in t834.member("M1", ins03="001", plan="PLAN-B", end=end) if not s.startswith("DTP*348")]  # noqa: E731
        bare = [s for s in newplan("") if not s.startswith("DTP*349")]
        twice = bare + ["HD*021**HLT*PLAN-C*IND"]  # two plan loops in one member loop: one item
        for rows, until in ((bare, 20261231), (twice, 20261231), (newplan("20260630"), 20260630)):  # the end was applied: no item
            change = self.change(rows)
            for data in ([full, change], [change, full]):
                (_, sent), left = ffs.feeds(20260105, self.joined(data), listed, ("2026-01-01", []), self.SECRET)
                self.assertEqual((sent[3][0], left), (decider.feed("span", 20251202, [(self.key("M1"), ffs.ident(b"PLAN-A"), 20260101, until),
                                                                                      (self.key("M2"), ffs.ident(b"PLAN-A"), 20260101, 20261231)])[0],
                                                      () if until < 20261231 else (ffs.SetAside("M1", "no_dates", 0, change.index(b"INS*Y*18*001")),)))

    def test_a_later_eligibility_begin_with_no_coverage_begin_starts_the_span_later_never_earlier_in_either_order(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        floor = lambda day: [s.replace("DTP*356*D8*20260101", f"DTP*356*D8*{day}") for s in t834.member("M1", ins03="001")  # noqa: E731
                             if not s.startswith(("DTP*348", "DTP*349"))]
        m2 = (self.key("M2"), ffs.ident(b"PLAN-A"), 20260101, 20261231)
        for day, m1, left_want in (("20260601", [(self.key("M1"), ffs.ident(b"PLAN-A"), 20260601, 20261231)], []),
                                   ("20270101", [], []),  # past the end: no span, so the member holds as not enrolled
                                   ("20251201", [(self.key("M1"), ffs.ident(b"PLAN-A"), 20260101, 20261231)], [("M1", "no_dates")])):  # changes nothing
            for data in ([full, self.change(floor(day))], [self.change(floor(day)), full]):
                dmf, span, left = self.fed(data)
                self.assertEqual((span[0], left), (decider.feed("span", 20251202, m1 + [m2])[0], left_want))
        kid = t834.member("M1")  # a dependent's loop carries M1's REF*0F and gives no span: a floor that moves only it changed nothing
        kid[0] = kid[0].replace("INS*Y*18", "INS*N*19")
        late = t837.file_of([t834.header() + t834.member("M1", begin="20260601") + kid + t834.member("M2")], gs_date="20251201")
        for data in ([late, self.change(floor("20260301"))], [self.change(floor("20260301")), late]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (decider.feed("span", 20251202, [(self.key("M1"), ffs.ident(b"PLAN-A"), 20260601, 20261231), m2])[0],
                                               [("M1", "dependent_member"), ("M1", "no_dates")]))

    def test_a_restated_plan_replaces_only_that_plan_and_the_members_other_plan_stays_in_either_order(self) -> None:
        both = t834.member("M1", extra=["HD*021**HLT*PLAN-B*IND", "DTP*348*D8*20260101", "DTP*349*D8*20261231"])
        full = t837.file_of([t834.header() + both + t834.member("M2")], gs_date="20251201")
        change = self.change(t834.member("M1", ins03="001", plan="PLAN-B", begin="20260301"))
        for data in ([full, change], [change, full]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (decider.feed("span", 20251202, [
                (self.key("M1"), ffs.ident(b"PLAN-A"), 20260101, 20261231), (self.key("M1"), ffs.ident(b"PLAN-B"), 20260301, 20261231),
                (self.key("M2"), ffs.ident(b"PLAN-A"), 20260101, 20261231)])[0], []))

    def test_an_end_alone_in_a_change_file_cuts_the_earlier_files_and_never_a_plan_its_own_file_begins_in_either_order(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        loop = t834.member("M1", ins03="001", plan="PLAN-B") + ["HD*021**HLT*PLAN-A*IND", "DTP*349*D8*20260331"]  # B begins, A ends
        for data in ([full, self.change(loop)], [self.change(loop), full]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (decider.feed("span", 20251202, [
                (self.key("M1"), ffs.ident(b"PLAN-A"), 20260101, 20260331), (self.key("M1"), ffs.ident(b"PLAN-B"), 20260101, 20261231),
                (self.key("M2"), ffs.ident(b"PLAN-A"), 20260101, 20261231)])[0], []))

    def test_a_row_a_later_file_replaces_gives_no_item_in_any_file_order(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        named = [s for s in t834.member("M1", ins03="001") if not s.startswith(("DTP*348", "DTP*349"))]  # changes nothing: an item alone
        files = [full, self.change(named), self.change(t834.member("M1", ins03="001"), "20251203", "000000003")]  # restated on Dec 3
        for data in (files, files[::-1], [files[1], files[0], files[2]]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (self.spans(20251203, "M1", "M2"), []))
        bare = [s for s in t834.member("M1", ins03="024") if not s.startswith(("DTP*348", "DTP*349", "DTP*356"))]
        for cancelled in (bare, [s for s in bare if not s.startswith("HD")]):  # under its plan, or under no plan
            base = t837.file_of([t834.header() + cancelled + t834.member("M2")], gs_date="20251201")
            readd = self.change(t834.member("M1"))
            for data in ([base, readd], [readd, base]):
                dmf, span, left = self.fed(data)
                self.assertEqual((span[0], left), (self.spans(20251202, "M1", "M2"), []))
            self.assertEqual(self.fed([base])[2], [("M1", "termination")])  # in force without the re-add

    def test_a_replaced_row_with_no_plan_keeps_its_cut_and_its_delete_and_gives_no_item_in_either_order(self) -> None:
        full = lambda *extra: t837.file_of([t834.header() + t834.member("M1", extra=list(extra)) + t834.member("M2")], gs_date="20251201")  # noqa: E731
        planb = self.change(t834.member("M1", ins03="001", plan="PLAN-B"))  # gives M1 a plan: its earlier rows with none are replaced
        a, b = ((self.key("M1"), ffs.ident(p), 20260101, 20261231) for p in (b"PLAN-A", b"PLAN-B"))
        m2 = (self.key("M2"), ffs.ident(b"PLAN-A"), 20260101, 20261231)
        for extra, alone, kept, left_want in ((["HD*024**HLT**IND"], [("M1", "termination")] * 2, [], [("M1", "termination")]),  # plan A stays cut
                                              (["HD*021**HLT**IND", "DTP*348*D8*20260101"], [("M1", "no_plan")], [a], []),
                                              (["HD*002**HLT**IND"], [("M1", "deleted")], [a], [])):
            self.assertEqual(self.fed([full(*extra)])[2], alone)  # in force without plan B
            for data in ([full(*extra), planb], [planb, full(*extra)]):
                dmf, span, left = self.fed(data)
                self.assertEqual((span[0], left), (decider.feed("span", 20251202, kept + [b, m2])[0], left_want))
        deleted = [s for s in t834.member("M1", ins03="002") if not s.startswith(("HD", "DTP*348", "DTP*349"))]  # the member deleted, no plan
        gone = t837.file_of([t834.header() + t834.member("M1") + deleted + t834.member("M2")], gs_date="20251201")
        for data in ([gone, planb], [planb, gone]):  # plan A stays deleted and is listed; the delete row itself is not
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (decider.feed("span", 20251202, [b, m2])[0], [("M1", "deleted")]))

    def test_a_cancellation_in_one_file_is_applied_as_filed_and_never_asks_for_dates(self) -> None:
        """Ruled: in one file a cancellation with no begin gives no ``no_dates`` item, whether or not it shortens a span."""
        lone = [s for s in t834.member("M1", ins03="024", end="20260331") if not s.startswith(("DTP*348", "DTP*356"))]
        for m1, rows, left_want in (([], lone, []),  # nothing to shorten: no span, nothing for staff to do
                                    ([], [s for s in lone if not s.startswith("DTP*349")], [("M1", "termination")]),  # a plain termination
                                    (["M1"], t834.member("M1") + [s.replace("20260331", "20271231") for s in lone], [])):  # ends after the span
            dmf, span, left = self.fed(t837.file_of([t834.header() + rows + t834.member("M2")], gs_date="20251201"))
            self.assertEqual((span[0], left), (self.spans(20251201, *m1, "M2"), left_want))

    def test_per_read_fault_counts_that_do_not_add_up_place_every_fault_outside_every_member_loop(self) -> None:
        read = r834.read_834(t837.file_of([t834.header() + t834.member("M1", extra=["QQ*2"]) + t834.member("M2")], gs_date="20251201"))
        (sha, nq, nf), = read.reads
        self.assertEqual(self.fed(read)[1][0], self.spans(20251201, "M2"))  # counts that add up: only M1 holds
        for reads in (((sha, nq + 1, nf),), ((sha, nq, nf + 1),), ((sha, -1, nf + nq + 1),), ((sha, nq, nf), (sha, 0, 0), ("", 1, 0)), (),
                      ((sha, float(nq), nf),), ((sha, nq),), ((sha, nq, nf, 0),), ([sha, nq, nf],)):  # never raises
            self.assertEqual(self.fed(read._replace(reads=reads))[:2], ((bytes(77), b""), (bytes(77), b"")))

    def test_per_read_fault_counts_that_do_not_add_up_never_match_a_member_loop_with_no_identifier_by_its_name(self) -> None:
        """Unplaced, a loop with no identifier is in no member loop: neither it nor a fault after it is matched to a member by its name."""
        nameless = [s for s in person("M9", "DOE", "JANE", "19800229", ins03="024", end="20260131") if not s.startswith("REF*0F")]
        jane, pat = person("M1", "DOE", "JANE", "19800229"), person("M2", "SMITH", "PAT", "19700101")
        first = r834.read_834(t837.file_of([t834.header() + nameless + jane + pat[:-1] + ["QQ*2", pat[-1]]], gs_date="20251201"))  # a later fault in M2's loop
        last = r834.read_834(t837.file_of([t834.header() + jane + pat + nameless], gs_date="20251201"))  # no other fault
        for read, covered in ((first, ()), (last, ("M2",))):
            (sha, nq, nf), = read.reads
            dmf, span, left = self.fed(read)  # placed: the loop is matched by its name, and the feeds stay
            self.assertEqual((dmf, span[0]), (decider.feed("dmf", 20251201, []), self.spans(20251201, *covered)))
            for reads in ((((sha, nq + 1, nf),), ()) if read is first else ((),)):
                dmf, span, left = self.fed(read._replace(reads=reads))
                self.assertEqual((dmf, span), ((bytes(77), b""),) * 2, reads)
                self.assertIn((f"member loop {next(q.offset for q in read.quarantines if q.cause == 'no_member_id')}", "no_member_id"), left)

    def test_a_newest_full_roster_more_than_45_days_older_than_the_newest_file_makes_the_span_feed_absent(self) -> None:
        """A lost change file cannot be seen, so the span feed stands only on a recent full roster."""
        for made, fresh in (("20251017", True), ("20251016", False), ("20251001", False)):
            full = t837.file_of([t834.header() + t834.member("M1")], gs_date=made)
            for data in ([full, self.change([], "20251201")], [self.change([], "20251201"), full]):
                dmf, span, left = self.fed(data)
                self.assertEqual(dmf, decider.feed("dmf", 20251201, []))
                self.assertEqual((span[0], left), (self.spans(20251201, "M1"), []) if fresh else
                                 (bytes(77), [(f"interchange 0 made {made[:4]}-{made[4:6]}-{made[6:]}T09:30:00", "stale_roster")]))
        empty = t837.file_of([t834.header()], gs_date="20251001")  # empty and stale: one item
        for data in ([empty, self.change(t834.member("M2"), "20251201")], [self.change(t834.member("M2"), "20251201"), empty]):
            dmf, span, left = self.fed(data)
            self.assertEqual((dmf, span, left), (decider.feed("dmf", 20251201, []), (bytes(77), b""),
                                                 [("interchange 0 made 2025-10-01T09:30:00", "stale_roster")]))

    def test_a_fault_in_one_read_never_lands_on_a_row_of_another_read_at_the_same_offset(self) -> None:
        one = r834.read_834(t837.file_of([t834.header() + t834.member("M1", extra=["QQ*2"])], gs_date="20251201", gs_time="0800"))
        two = r834.read_834(t837.file_of([t834.header() + t834.member("M2")], control="000000002", gs_date="20251201", gs_time="0800"))
        self.assertEqual(one.rows[0].offsets[0], two.rows[0].offsets[0])  # both member loops open at one offset
        for read in (r834.Read834(*(a + b for a, b in zip(one, two))), r834.Read834(*(b + a for a, b in zip(one, two)))):
            dmf, span, left = self.fed(read)
            self.assertEqual((dmf, span[0], left), (decider.feed("dmf", 20251201, []), self.spans(20251201, "M2"), [("M1", "member_quarantined")]))

    def test_only_a_whole_bgn08_of_exactly_2_makes_a_change_file(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        bgn = lambda code: f"BGN*00*F2*20251202*0930****{code}"  # noqa: E731
        for head in ([bgn("2:RX")], [bgn("4")], [bgn("2"), bgn("RX")], [bgn("RX"), bgn("2")], [bgn("2"), "BGN*00*F3*20251202*0930"]):
            newer = t837.file_of([head + [t834.header()[1]] + t834.member("M1")], control="000000002", gs_date="20251202")  # a full roster
            self.check([full, newer], 20251202, ["M1"], ["interchange 0 made 2025-12-01T09:30:00"])
            self.check([newer, full], 20251202, ["M1"], ["interchange 0 made 2025-12-01T09:30:00"])
        both = t837.file_of([[bgn("2"), bgn("2"), t834.header()[1]] + t834.member("M1", plan="PLAN-B")], control="000000002", gs_date="20251202")
        for data in ([full, both], [both, full]):
            dmf, span, left = self.fed(data)
            self.assertEqual((span[0], left), (self.plans(20251202, ("M1", "PLAN-A"), ("M1", "PLAN-B"), ("M2", "PLAN-A")), []))

    def test_a_change_file_made_before_the_newest_full_roster_is_set_aside_in_either_order(self) -> None:
        full = t837.file_of([t834.header() + t834.member("M1") + t834.member("M2")], gs_date="20251201")
        early = t837.file_of([["BGN*00*F2*20251130*0930****2", t834.header()[1]] + t834.member("M1", ins03="024", end="20251231")],
                             control="000000002", gs_date="20251130")
        self.check([full, early], 20251201, ["M1", "M2"], ["interchange 0 made 2025-11-30T09:30:00"])
        self.check([early, full], 20251201, ["M1", "M2"], ["interchange 0 made 2025-11-30T09:30:00"])

    def test_files_from_two_reads_are_never_one_interchange(self) -> None:
        """Both files start their ISA at offset 0: only the file hash tells them apart, so the empty one is not hidden by the other."""
        one = r834.read_834(t837.file_of([t834.header() + t834.member("M1")], gs_date="20251201", gs_time="0800"))
        empty = r834.read_834(t837.file_of([t834.header()], control="000000002", gs_date="20251201", gs_time="0800"))
        dmf, span, left = self.fed(r834.Read834(*(a + b for a, b in zip(one, empty))))
        self.assertEqual((span, left), ((bytes(77), b""), [("interchange 0 made 2025-12-01T08:00:00", "empty_roster")]))

    def test_two_transaction_sets_in_one_interchange_are_not_a_tie(self) -> None:
        data = t837.file_of([t834.header() + t834.member("M1"), t834.header() + t834.member("M2")], gs_date="20251201", gs_time="0800")
        self.check(data, 20251201, ["M1", "M2"], [])

    def test_rows_with_the_identical_file_time_still_give_one_feed_and_no_set_aside(self) -> None:
        one = t837.file_of([], gs_date="20251201", gs_time="0800", groups=[[t834.header() + t834.member("M1")], [t834.header() + t834.member("M2")]])
        self.check(one, 20251201, ["M1", "M2"], [])

    def test_an_interchange_sent_twice_gives_no_member_feed_as_before_never_a_wider_one(self) -> None:
        one = t837.file_of([t834.header() + t834.member("M1")])
        self.assertNotEqual(self.span_feed(one)[1], (bytes(77), b""))
        self.assertEqual(self.span_feed(one + one), ((bytes(77), b""), (bytes(77), b"")))

    def test_a_cancellation_cuts_each_span_begun_by_its_end_in_any_file_order_and_a_later_span_stands(self) -> None:
        secret, cancel, later = b"synthetic tenant secret, 32 b..", dict(ins03="024", end="20260331"), dict(begin="20260501", plan="PLAN-B")
        change = t834.member("M3", end="20260331", extra=["HD*021**HLT*PLAN-B*IND", "DTP*348*D8*20260501", "DTP*349*D8*20261231"])
        change[7] = "HD*024**HLT*PLAN-A*IND"  # a plan change: PLAN-A ends, PLAN-B begins later
        read = r834.read_834(t837.file_of([t834.header() + t834.member("M1", **cancel) + t834.member("M1") + t834.member("M2", **later)
                                           + t834.member("M2", **cancel) + change]))
        (_, sent), left = ffs.feeds(20260105, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                    ("2026-01-01", []), secret)
        span = lambda m, end, plan=b"PLAN-A", begin=20260101: (ffs.ident(ffs.member_key(secret, m)), ffs.ident(plan), begin, end)  # noqa: E731
        self.assertEqual(([(a.id, a.cause) for a in left], sent[3]),  # M2: B was added before the cancellation that cuts before it begins: held
                         ([("M2", "termination")], decider.feed("span", 20260102, [span("M1", 20260331), span("M1", 20260331), span("M2", 20260331),
                                                                                   span("M3", 20260331), span("M3", 20261231, b"PLAN-B", 20260501)])))

    def test_a_cancellation_later_in_the_file_than_a_span_that_begins_after_its_cut_holds_that_span(self) -> None:
        later = t834.member("M1", ins03="024", begin="20270101", end="")  # cancelled from 2027-04-01 by a later loop
        later.insert(3, "DTP*303*D8*20270401")
        read = r834.read_834(t837.file_of([t834.header() + t834.member("M1", begin="20270401", end="20271231") + later]))
        (_, sent), left = ffs.feeds(20270415, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2027-01-01"), ("2027-01-01", []), b"s")
        self.assertEqual(([(a.id, a.cause) for a in left], sent[3]), ([("M1", "termination")], decider.feed("span", 20260102, [
            (ffs.ident(ffs.member_key(b"s", "M1")), ffs.ident(b"PLAN-A"), 20270101, 20270331)])))  # no span covers 2027-04-15

    def test_a_cancellation_whose_own_span_begins_after_its_own_cut_holds_that_span_and_a_plan_change_in_one_loop_keeps_the_new_plan(self) -> None:
        own = t834.member("M1", ins03="024", begin="20270401", end="")  # cancelled from 2027-04-01, and its own plan begins that day
        own.insert(3, "DTP*303*D8*20270401")
        (_, sent), left = ffs.feeds(20270415, r834.read_834(t837.file_of([t834.header() + own])),
                                    leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2027-01-01"), ("2027-01-01", []), b"s")
        self.assertEqual(([(a.id, a.cause) for a in left], sent[3]), ([("M1", "termination")], decider.feed("span", 20260102, [])))

    def test_a_plan_cancelled_at_a_cut_and_the_next_plan_beginning_there_keeps_the_next_plan(self) -> None:
        old = t834.member("M1", ins03="024", begin="20270101", end="")  # plan A cancelled from 2027-04-01
        old.insert(3, "DTP*303*D8*20270401")
        new = t834.member("M1", begin="20270401", end="20271231", plan="PLAN-B")  # plan B begins that day, filed after
        (_, sent), left = ffs.feeds(20270415, r834.read_834(t837.file_of([t834.header() + old + new])),
                                    leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2027-01-01"), ("2027-01-01", []), b"s")
        m = ffs.ident(ffs.member_key(b"s", "M1"))
        self.assertEqual((left, sent[3]), ((), decider.feed("span", 20260102, [
            (m, ffs.ident(b"PLAN-A"), 20270101, 20270331), (m, ffs.ident(b"PLAN-B"), 20270401, 20271231)])))

    def test_a_segment_the_reader_does_not_read_in_a_name_loop_sets_its_member_aside(self) -> None:
        late = t834.member("M1", begin="20270101", end="")
        late.insert(4, "DTP*357*D8*20270131")  # the eligibility end, after the member's name: not read, and the span would run on
        (_, sent), left = ffs.feeds(20270415, r834.read_834(t837.file_of([t834.header() + late])),
                                    leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2027-01-01"), ("2027-01-01", []), b"s")
        self.assertEqual(([(a.id, a.cause) for a in left], sent[3]), ([("M1", "member_quarantined")], decider.feed("span", 20260102, [])))

    def test_a_fault_in_a_set_header_or_a_loop_with_no_member_id_never_lands_on_the_member_before_it(self) -> None:
        nameless = [s for s in t834.member("M7") if not s.startswith(("REF", "NM1"))]
        nameless[1] = "DTP*356*D8*20261340"  # a date on no calendar day, in a loop that names no member
        first = t834.header() + t834.member("M1")
        for data, loops in ((t837.file_of([first, t834.header() + ["ZZZ*X"] + t834.member("M2")]), []), (t837.file_of([first + nameless]), ["no_member_id"])):
            (_, sent), left = ffs.feeds(20260105, r834.read_834(data), leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                        ("2026-01-01", []), b"s")
            self.assertEqual(([a.cause for a in left], sent[0], sent[3]), (loops, (bytes(77), b""), (bytes(77), b"")))  # unknown: every line to review, M1 not held for it

    def test_a_member_carrying_the_standard_ec_dsb_and_prv_segments_is_read_whole(self) -> None:
        full = t834.member("M1", extra=["PRV*PE*PXC*207Q00000X"])  # the primary care provider loop of the coverage
        full[2:2] = ["EC*01*A*A", "DSB*1"]  # employment class and disability: standard 834 member segments
        (_, sent), left = ffs.feeds(20260105, r834.read_834(t837.file_of([t834.header() + full])),
                                    leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"), ("2026-01-01", []), b"s")
        self.assertEqual((left, sent[3]), ((), decider.feed("span", 20260102, [(ffs.ident(ffs.member_key(b"s", "M1")), ffs.ident(b"PLAN-A"), 20260101, 20261231)])))

    def test_a_span_with_two_date_sources_begins_at_the_later_begin_and_ends_at_the_earlier_end(self) -> None:
        secret = b"synthetic tenant secret, 32 b.."
        both = t834.member("M1")  # coverage 2026-01-01 to 2026-12-31, eligibility 2026-03-01 to 2026-06-30
        both[2:3] = ["DTP*356*D8*20260301", "DTP*357*D8*20260630"]
        cancel = t834.member("M2", ins03="024", end="20260331")
        cancel.insert(3, "DTP*357*D8*20260228")
        read = r834.read_834(t837.file_of([t834.header() + both + t834.member("M2") + cancel]))
        (_, sent), left = ffs.feeds(20260105, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                    ("2026-01-01", []), secret)
        span = lambda m, begin, end: (ffs.ident(ffs.member_key(secret, m)), ffs.ident(b"PLAN-A"), begin, end)  # noqa: E731
        self.assertEqual((left, sent[3]), ((), decider.feed("span", 20260102, [span("M1", 20260301, 20260630), span("M2", 20260101, 20260228),
                                                                              span("M2", 20260101, 20260228)])))

    def test_a_deleted_member_or_coverage_gives_no_span_and_is_reported(self) -> None:
        secret = b"synthetic tenant secret, 32 b.."  # 002: HD01 deletes the coverage; INS03 has no 002, so the loop gives none
        deleted = t834.member("M2", extra=["HD*002**HLT*PLAN-B*IND", "DTP*348*D8*20260101", "DTP*349*D8*20261231"])
        read = r834.read_834(t837.file_of([t834.header() + t834.member("M1", ins03="002") + deleted]))
        (_, sent), left = ffs.feeds(20260105, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                    ("2026-01-01", []), secret)
        self.assertEqual([(a.id, a.cause) for a in left], [("M1", "deleted"), ("M2", "deleted")])
        self.assertEqual(sent[3], decider.feed("span", 20260102, [(ffs.ident(ffs.member_key(secret, "M2")), ffs.ident(b"PLAN-A"), 20260101, 20261231)]))

    def test_a_member_added_and_deleted_in_one_file_is_deleted_and_holds(self) -> None:
        read = r834.read_834(t837.file_of([t834.header() + t834.member("M1") + t834.member("M1", ins03="002")]))
        (_, sent), left = ffs.feeds(20260105, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                    ("2026-01-01", []), b"s")
        self.assertEqual(([(a.id, a.cause) for a in left], sent[3]), ([("M1", "deleted"), ("M1", "deleted")], decider.feed("span", 20260102, [])))

    def test_a_provider_death_list_whose_as_of_is_no_calendar_day_sets_its_rows_aside_and_sends_no_feed(self) -> None:
        for asof in ("2026-02-30", "soon", ""):
            (_, sent), left = ffs.feeds(20260105, r834.read_834(t837.file_of([t834.header() + t834.member("M1")])),
                                        leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                        (asof, [(DEAD, "2025-12-01"), ("0" + DEAD, "2025-12-01")]), b"s")
            self.assertEqual(([(a.id, a.cause) for a in left], sent[1]), ([(DEAD, "bad_as_of"), ("0" + DEAD, "bad_npi")], (bytes(77), b"")), asof)

    def test_a_supplement_exclusion_file_gives_no_feed_and_no_set_asides(self) -> None:
        extra = leie.read_leie((tl.HEAD + tl.row(last="NONE") + tl.row(last="BACK", npi=CLEAN, rein="20250115")).encode(), source="synthetic",
                               as_of="2026-01-01", kind="exclusions")
        (_, sent), left = ffs.feeds(20260105, r834.read_834(t837.file_of([t834.header() + t834.member("M1")])), extra,
                                    ("2026-01-01", [(DEAD, "2025-12-01")]), b"s")
        self.assertEqual((sent[2], left), ((bytes(77), b""), ()))

    def test_a_row_with_dates_that_would_void_its_whole_feed_is_set_aside_and_the_feed_is_sent(self) -> None:
        secret = b"synthetic tenant secret, 32 b.."
        read = r834.read_834(t837.file_of([t834.header() + t834.member("M1") + t834.member("M2", death="20260301")  # after the file
                                           + t834.member("M3", end="20251231")]))  # ends before it begins
        listed = leie.read_leie((tl.HEAD + tl.row(npi=EXCLUDED) + tl.row(last="BACK", npi=CLEAN, rein="20250115")).encode(),
                                source="synthetic", as_of="2026-01-01")  # reinstated the day of exclusion: reported, and held as excluded from then on
        (_, sent), left = ffs.feeds(20260105, read, listed, ("2026-01-01", [(DEAD, "2025-12-01"), (CLEAN, "2026-02-01")]), secret)
        self.assertEqual([(a.id, a.cause) for a in left], [("M2", "bad_dates"), ("M3", "bad_dates"), (CLEAN, "bad_dates"), ("BACK", "bad_dates")])
        self.assertEqual(sent[1:], (decider.feed("pdeath", 20260101, [(ffs.ident(DEAD.encode()), 20251201), (ffs.ident(CLEAN.encode()), 10101)]),
                                    decider.feed("excl", 20260101, [(ffs.ident(EXCLUDED.encode()), 20250115, 99991231),
                                                                    (ffs.ident(CLEAN.encode()), 10101, 99991231)]),
                                    decider.feed("span", 20260102, [(ffs.ident(ffs.member_key(secret, "M1")), ffs.ident(b"PLAN-A"), 20260101, 20261231)])))
        self.assertEqual(sent[0], decider.feed("dmf", 20260102, []))  # no death left: the engine holds it unknown, never nobody died

    def test_a_provider_death_on_no_calendar_day_is_set_aside_and_the_provider_holds(self) -> None:
        deaths = [(DEAD, "2025-02-30"), (CLEAN, ""), (EXCLUDED, "2025-12-01")]
        (_, sent), left = ffs.feeds(20260105, r834.read_834(t837.file_of([t834.header() + t834.member("M1")])),
                                    leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"), ("2026-01-01", deaths), b"s")
        self.assertEqual([(a.id, a.cause) for a in left], [(DEAD, "bad_dates"), (CLEAN, "bad_dates")])
        self.assertEqual(sent[1], decider.feed("pdeath", 20260101, [(ffs.ident(DEAD.encode()), 10101), (ffs.ident(CLEAN.encode()), 10101),
                                                                    (ffs.ident(EXCLUDED.encode()), 20251201)]))

    def test_provider_rows_without_a_valid_npi_are_set_aside_never_dropped(self) -> None:
        listed = leie.read_leie((tl.HEAD + tl.row(npi=EXCLUDED) + tl.row(last="NONE") + tl.row(last="WRONG", npi=tl.wrong(CLEAN))).encode(),
                                source="synthetic", as_of="2026-01-01")
        (_, sent), left = ffs.feeds(20260105, r834.read_834(t837.file_of([t834.header() + t834.member("M1")])), listed,
                                    ("2026-01-01", [(DEAD, "2025-12-01"), ("0" + DEAD, "2025-12-01"), (CLEAN + " ", "2025-12-01")]), b"s")
        self.assertEqual([(a.id, a.cause) for a in left], [("0" + DEAD, "bad_npi"), (CLEAN + " ", "bad_npi"), ("NONE", "no_npi"), ("WRONG", "exclusion_npi_unreadable")])
        self.assertEqual((sent[1], sent[2]), (decider.feed("pdeath", 20260101, [(ffs.ident(DEAD.encode()), 20251201)]),
                                              decider.feed("excl", 20260101, [(ffs.ident(EXCLUDED.encode()), 20250115, 99991231)])))

    def test_a_row_naming_no_one_is_one_item_and_the_feed_stays_while_a_named_row_with_no_type_is_an_exclusion(self) -> None:
        listed = leie.read_leie((tl.HEAD + tl.row(npi=EXCLUDED) + tl.row(last="", bus="", npi="0") + tl.row(last="SMITH", first="JOHN", npi="0", typ="")).encode(),
                                source="synthetic", as_of="2026-01-01")
        nobody = next(q.offset for q in listed.quarantined if q.cause == "no_name")
        (_, sent), left = ffs.feeds(20260105, r834.read_834(t837.file_of([t834.header() + t834.member("M1")])), listed, ("2026-01-01", [(DEAD, "2025-12-01")]), b"s")
        self.assertEqual(sent[2], decider.feed("excl", 20260101, [(ffs.ident(EXCLUDED.encode()), 20250115, 99991231)]))  # the feed is not blanked by a row that names no one
        self.assertEqual([(a.id, a.cause) for a in left], [("SMITH", "exclusion_npi_unreadable"), (f"row {nobody}", "unreadable_row")])

    def test_a_row_that_does_not_read_holds_only_what_its_npis_or_name_columns_name_and_one_naming_nothing_blanks_the_feed(self) -> None:
        short = tl.row(npi=EXCLUDED).rsplit(",", 1)[0] + "\n"  # a cell short: its NPI is held wherever the cells moved
        latin = tl.row(last="ROE", first="RAY").encode().replace(b"NOWHERE", b"NOWH\xc9RE")  # not UTF-8, no NPI: held by its name columns only
        long = tl.row(last="ROE", first="RAY").rstrip("\n") + ",EXTRA\n"  # no NPI and a cell too many: which cells are its name cannot be told
        quoted = tl.row(last="ROE", first="RAY").replace("ROE", '"ROE"X', 1)  # no NPI and quoting that does not read: the same
        nameless = tl.row(last="", first="").encode().replace(b"NOWHERE", b"NOWH\xc9RE")  # not UTF-8 and no name: nothing to hold
        misspelt = tl.row(last="ROE", first="RAY").encode().replace(b"ROE", b"R\xd6E", 1)  # not UTF-8 inside its name: the name cannot be read
        roster = r834.read_834(t837.file_of([t834.header() + t834.member("M1")]))

        def read(*rows: bytes):
            return leie.read_leie((tl.HEAD + tl.row(last="FINE", npi=DEAD)).encode() + b"".join(rows), source="synthetic", as_of="2026-01-01")  # a list none of whose rows read is no list
        listed = read(short.encode(), latin)
        (_, sent), left = ffs.feeds(20260105, roster, listed, ("2026-01-01", []), b"s")
        self.assertEqual(sent[2], decider.feed("excl", 20260101, [(ffs.ident(DEAD.encode()), 20250115, 99991231), (ffs.ident(EXCLUDED.encode()), 10101, 99991231)]))
        self.assertEqual([(a.id, a.cause, a.offset) for a in left], [(EXCLUDED, "column_count", listed.quarantined[0].offset),
                                                                      ("ROE,RAY,,", "not_utf8", listed.quarantined[1].offset)])
        claims = [t837.claim("C1", 1)]
        for cid, name in (("C2", "1*ROE*RAY"), ("C3", "2*NOWHERE FAMILY CLINIC*"), ("C4", "2*RAY PHARMACY*"), ("C5", "2*ZZ HOSPITAL*"), ("C6", "2*X Y SERVICES*")):
            claims.append(t837.claim(cid, 1))
            claims[-1][1:1] = [f"NM1*82*{name}****XX*{CLEAN}"]  # its city, state, general and specialty cells name no one
        sent, aside = ffs.requests_of([claims_file(*claims)], fx.TENANT, fx.PROGRAM, fx.PERIOD, b"s", listed)
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause, a.reader) for a in aside]),
                         ([ffs.canonical_id("C", "1999999984", c) for c in ("C1", "C3", "C4", "C5", "C6")],
                          [("C2", "exclusion_npi_unreadable", f'exclusion row {listed.quarantined[1].offset} ("ROE,RAY,,", not_utf8) names this provider')]))
        for row in (long.encode(), quoted.encode(), nameless, misspelt):
            (_, sent), left = ffs.feeds(20260105, roster, read(short.encode(), row), ("2026-01-01", []), b"s")
            self.assertEqual((sent[2], [a.cause for a in left]), ((bytes(77), b""), ["column_count", "unreadable_row"]))

    def test_a_member_loop_with_no_identifier_holds_every_member_its_name_may_be_and_one_it_may_be_no_one_blinds(self) -> None:
        people = (("M1", "DOE", "JANE", "19800229"), ("M2", "SMITH", "PAT", "19700101"), ("M3", "O'BRIEN", "KIM", "19600101"), ("M4", "MCDONALD", "LEE", "19500101"))
        key = lambda m: ffs.ident(ffs.member_key(b"s", m))  # noqa: E731
        for (last, first, born), held, extra in (
                (("DOE", "JANE", "19800229"), ["M1"], ()), (("DOE", "", "19800229"), ["M1"], ()),
                (("DOE", "JANE", "19800228"), ["M1"], ()),  # the same name, a birth date one digit away
                (("LEE", "ANN", "19560312"), ["M7"], (("M7", "LEE", "ANN", "19650312"),)),  # two neighbouring digits swapped
                (("LEE", "ANN", "19651203"), ["M7"], (("M7", "LEE", "ANN", "19650312"),)),  # day and month swapped
                (("DOE", "JANE", "19790101"), None, ()),  # the same name, another birth date: it may be no member on the roster
                (("DOE", "JANE", "19800229"), ["M1"], (("M6", "DOE", "JOHN", "19550101"),)),  # one of the three only: not held
                (("OBRIEN", "KIM", "19600101"), ["M3"], ()), (("MC DONALD", "LEE", "19500101"), ["M4"], ()),  # punctuation and spaces
                (("PAT", "SMITH", "19700101"), ["M2"], ()),  # last and first swapped
                (("JONES", "PAT", "19700101"), ["M2"], ()),  # a changed last name: the first name and birth date
                (("DOE", "JANE", "19800229"), ["M1"], (("M5", "", "ANN", "19900101"),)),  # a member with no last name may be anyone: held beside it
                (("NOBODY", "ZED", "20000101"), None, (("M5", "", "ANN", "19900101"),)),  # and still it may be no member on the roster
                (("NOBODY", "ANN", "19010101"), None, (("M5", "", "ANN", ""),)),  # a member with no last name and no birth date agrees with nothing: a blank is not agreement
                (("NOBODY", "ZED", "19900101"), None, (("M5", "", "", "19900101"),)),  # nor one with no first name, though the birth date is its own
                (("NOBODY", "ZED", "20000101"), None, (("M5", "", "", ""),)),  # nor one with neither
                (("NOBODY", "ANN", "19010101"), None, (("M6", "ROE", "ANN", ""),)),  # nor does any member's blank birth date: the first name alone is no match
                (("NOBODY", "", "19010101"), None, (("M6", "ROE", "ANN", ""),)),  # a birth date sent alone matches no member who sent none
                (("ROE", "ZED", "20000101"), None, (("M6", "ROE", "ANN", ""),)),  # nor does the last name alone
                (("ROE", "ANN", "19800228"), None, (("M6", "ROE", "", "19800229"),)),  # nor does a blank first name, beside a birth date a typo away
                (("NOBODY", "ANN", "19900101"), [], (("M5", "", "ANN", "19900101"),)),  # but one that shares first name and birth date is who it may be: held, the feeds stay
                (("NOBODY", "ZED", "20000101"), None, ())):  # it may be no member on the roster: it may hide a death, so the member feeds are absent
            loop = [s for s in person("M9", last, first, born, ins03="024", end="20260131") if not s.startswith("REF*0F")]
            loop.insert(2, "DTP*356*D8*20261340")  # a fault inside it lands on the same members
            read = r834.read_834(t837.file_of([t834.header() + [s for p in people + extra for s in person(*p)] + loop]))
            (_, sent), left = ffs.feeds(20260105, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"), ("2026-01-01", []), b"s")
            start = next(q.offset for q in read.quarantines if q.cause == "no_member_id")
            open_ = [m for m, last_name, *_ in extra if not last_name]
            self.assertEqual(sorted((a.id, a.cause) for a in left), sorted([(m, "member_quarantined") for m in (held or []) + open_] + [(f"member loop {start}", "no_member_id")]), last)
            self.assertEqual((sent[0], sent[3]), ((bytes(77), b""),) * 2 if held is None else (decider.feed("dmf", 20260102, []), decider.feed("span", 20260102, [
                (key(m), ffs.ident(b"PLAN-A"), 20260101, 20261231) for m, *_ in people + extra if m not in held + open_])), last)


    def test_a_member_with_both_names_and_no_birth_date_is_held_by_a_nameless_loop_with_both_names_but_never_keeps_the_feeds_live(self) -> None:
        people = (("M1", "DOE", "JANE", "19800229"), ("M2", "SMITH", "PAT", "19700101"))
        weak = ("M6", "ROE", "ANN", "")  # both names, no birth date
        key = lambda m: ffs.ident(ffs.member_key(b"s", m))  # noqa: E731
        for (last, first, born), held, live, extra in (
                (("ROE", "ANN", "19010101"), ["M6"], False, (weak,)),  # alone: held, and the feeds are absent, since it may be no member on the roster
                (("ANN", "ROE", "19010101"), ["M6"], False, (weak,)),  # the names the other way round
                (("ROE", "A", "19010101"), ["M6"], False, (weak,)),  # an initial agrees
                (("ROE", "ANN", "19010101"), ["M6", "M7"], True, (weak, ("M7", "ROE", "ANN", "19010101"))),  # beside a member that shares both names and the birth date: both held, the feeds stay
                (("ROE", "ZED", "19010101"), [], False, (weak,)),  # another first name: not held
                (("ZED", "ANN", "19010101"), [], False, (weak,)),  # another last name: not held
                (("ROE", "", "19010101"), [], False, (weak,)),  # no first name sent: the last name alone is no match
                (("ROE", "ANN", "19010101"), [], False, (("M6", "ROE", "", ""),))):  # no first name on the roster: not held
            loop = [s for s in person("M9", last, first, born, ins03="024", end="20260131") if not s.startswith("REF*0F")]
            loop.insert(2, "DTP*356*D8*20261340")  # a fault inside it lands on the same members
            read = r834.read_834(t837.file_of([t834.header() + [s for p in people + extra for s in person(*p)] + loop]))
            (_, sent), left = ffs.feeds(20260105, read, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"), ("2026-01-01", []), b"s")
            start = next(q.offset for q in read.quarantines if q.cause == "no_member_id")
            self.assertEqual(sorted((a.id, a.cause) for a in left), sorted([(m, "member_quarantined") for m in held] + [(f"member loop {start}", "no_member_id")]), (last, first, extra))
            self.assertEqual((sent[0], sent[3]), (decider.feed("dmf", 20260102, []), decider.feed("span", 20260102, [
                (key(m), ffs.ident(b"PLAN-A"), 20260101, 20261231) for m, *_ in people + extra if m not in held])) if live else ((bytes(77), b""),) * 2, (last, first, extra))

    def test_a_lookup_of_the_members_a_nameless_loop_may_be_costs_the_same_on_a_roster_fifty_times_larger(self) -> None:
        word = lambda i: "".join(string.ascii_uppercase[i // 26 ** k % 26] for k in range(4))  # noqa: E731  a distinct name per number
        day = lambda i, d: f"{1940 + i % 60}-{1 + i % 12:02d}-{d:02d}"  # noqa: E731
        best = {}
        for n in (1000, 50000):
            rows = [SimpleNamespace(member_id=f"M{i}", last_name="Q" + word(i), first_name="F" + word(i * 7 % n), birth_date=day(i, 1 + i % 28), name_raw_hex="")
                    for i in range(n)]
            names = [q for k in range(100) for q in (f"Q{word(k)}*OTHER*", f"NOBODY*F{word(k * 7 % n)}*", f"Q{word(k)}*F{word(k * 7 % n)}*{day(k, 2 + k % 27)}")]
            for _ in range(3):  # a fresh roster index each time: a name is looked up once
                _, may, _ = ffs._namesakes(rows)
                t = time.perf_counter()
                found = [may(q) for q in names]
                best[n] = min(time.perf_counter() - t, best.get(n, 1e9))
            self.assertEqual(found[:3], [{"M0"}, {"M0"}, {"M0"}])  # its last name, its first name, both names a birth date typo away
        print(f"[m] namesake lookups: {best[1000]:.4f}s on 1,000 members, {best[50000]:.4f}s on 50,000")
        self.assertLess(best[50000], 4 * best[1000])

def claims_file(*claims: list[str], sub: str = "S00000001", npi: str = "1999999984") -> r837.Read837:
    """An 837 of ``claims`` (test_x12_837.claim, whole units) for subscriber ``sub`` billed by ``npi``."""
    body = t837.head(npi, sub) + [s.replace("UN*1.5", "UN*1") for c in claims for s in c]
    return r837.read_837(t837.file_of([body], kind="837"))


class RequestTests(unittest.TestCase):
    SECRET = b"synthetic tenant secret, 32 b.."

    def requests(self, read: r837.Read837):
        return ffs.requests_of([read], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE)

    def test_a_file_cut_short_holds_only_the_set_it_ends_in(self) -> None:
        data = t837.file_of([t837.head() + [s.replace("UN*1.5", "UN*1") for s in t837.claim(cid, 1)] for cid in ("C1", "C2")], kind="837")
        read = r837.read_837(data[:data.rindex(b"SV1") + 7])  # the last line stops mid-segment: no SE, GE or IEA
        sent, aside = self.requests(read)
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause, a.reader) for a in aside]),  # the interchange is its own item: a void cut off with the tail cannot be seen
                         ([ffs.canonical_id("C", "1999999984", "C1")], [("C2", "quarantined", "unterminated_segment"),
                                                                        (f"interchange {read.claims[0].interchange}", "quarantined", "iea_missing")]))
        self.assertEqual([q.cause for q in read.quarantines], ["unterminated_segment", "set_unclosed", "group_unclosed", "iea_missing"])

    def test_one_request_per_claim_with_ids_that_a_resubmission_repeats(self) -> None:
        dated = t837.claim("C5", 1)
        dated[-1] = "DTP*472*RD8*20260105-20260107"
        dependent = t837.head() + ["HL*3*2*23*0", "NM1*QC*1*DOE*KID****MI*D1"] + t837.claim("C6", 1)
        half = t837.claim("C3", 1)
        half[3] = "SV1*HC:99213*10.00*UN*0.5"
        later = [s.replace("D8*202601", "D8*202603") for s in t837.claim("C2", freq="7", ref="C0")]  # naming no claim read, it holds only those its days meet
        read = claims_file(t837.claim("C1", 2), later, half, dated, dependent[6:])
        sent, aside = self.requests(read)
        (req,) = sent
        key = ffs.member_key(self.SECRET, "S00000001")
        line = lambda n, day: gate.encode_line("FFS_CLAIM", ffs.canonical_id("L", "1999999984", "C1", n), key, "1999999984", "1999999984", day, "99213:25:GT", 1, 1000)
        self.assertEqual(req, gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", req.payment_id, req.payment_id, key, "1999999984", 2000, fx.PERIOD,
                                                 (line("1", 20260101), line("2", 20260102)), (bytes.fromhex(read.rows[0].file_sha3_512),)))
        self.assertEqual(req.payment_id, ffs.canonical_id("C", "1999999984", "C1"))
        self.assertEqual([(a.id, a.cause, a.cents) for a in aside],
                         [("C2", "replacement_or_void", 2000), ("C3", "units", 1000), ("C5", "service_date", 1000), ("C6", "dependent_patient", 1000)])
        again, _ = self.requests(claims_file(t837.claim("C1", 2), t837.claim("C9", 1)))
        self.assertEqual(again[0].payment_id, req.payment_id)
        self.assertEqual(again[0].lines, req.lines)
        self.assertNotEqual(again[0].evidence_refs, req.evidence_refs)  # the same claim in another file: same ids, its own file cited

    def test_a_dependent_patient_with_or_without_an_identifier_sets_the_claim_aside(self) -> None:
        above = {"C1": ["HL*3*2*23*0", "NM1*QC*1*DOE*KID"], "C2": ["NM1*QC*1*DOE*KID"], "C3": ["HL*3*2*23*0"]}  # 5010 sends NM1*QC with no id
        for cid, segs in above.items():
            sent, aside = self.requests(claims_file(segs + t837.claim(cid, 1)))
            self.assertEqual((sent, [(a.id, a.cause) for a in aside]), ((), [(cid, "dependent_patient")]), cid)

    def test_a_field_the_codec_refuses_sets_the_claim_aside(self) -> None:
        spaced = t837.claim("C1", 1)
        spaced[3] = "SV1*HC:99 213*10.00*UN*1"
        sent, aside = self.requests(claims_file(spaced, t837.claim("C2", 1)))
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause) for a in aside]), ([ffs.canonical_id("C", "1999999984", "C2")], [("C1", "field")]))

    def test_a_billing_or_rendering_npi_that_is_not_ten_digits_with_its_check_digit_sets_the_claim_aside(self) -> None:
        padded = t837.claim("C2", 1, extra=["NM1*82*1*ROE*RAY****XX*01999999984"])  # the line's rendering provider
        sent, aside = self.requests(claims_file(t837.claim("C1", 1), padded))
        bad, _ = self.requests(claims_file(t837.claim("C3", 1), npi="1999999985"))
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause) for a in aside], bad),
                         ([ffs.canonical_id("C", "1999999984", "C1")], [("C2", "bad_npi")], ()))

    def test_a_claim_with_a_line_set_aside_or_a_total_unlike_its_lines_is_set_aside_whole(self) -> None:
        lost = t837.claim("C1", 2)
        lost[6] = "SV1*HC:99213*10.00*UN*X"  # the second line's units do not read: that line is quarantined
        sent, aside = self.requests(claims_file(lost, t837.claim("C2", 1, total="100.00"), t837.claim("C3", 1)))
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause, a.cents) for a in aside]),
                         ([ffs.canonical_id("C", "1999999984", "C3")], [("C1", "partial", 1000), ("C2", "total_mismatch", 1000)]))

    def test_a_claim_with_a_segment_set_aside_inside_it_is_set_aside_whole_never_sent_with_the_first_copy(self) -> None:
        twice = {"C1": (2, [f"NM1*82*1*SMITH*ANN****XX*{EXCLUDED}", f"NM1*82*1*ROE*RAY****XX*{CLEAN}"]), "C2": (5, ["DTP*472*D8*20260109"]),
                 "C3": (4, ["SV1*HC:99214*10.00*UN*1"]), "C4": (2, ["REF*F8*OTHER"]), "C5": (4, ["ZZZ*1"])}  # C4: after its REF*F8*FIRST
        claims = [(c := t837.claim(cid, 1, ref="FIRST" if cid == "C4" else ""))[:at] + segs + c[at:] for cid, (at, segs) in twice.items()]
        sent, aside = self.requests(claims_file(*claims, t837.claim("C6", 1)))
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause) for a in aside]),
                         ([ffs.canonical_id("C", "1999999984", "C6")], [(c, "partial") for c in twice]))
        end = t837.claim("C7", 1)  # an unknown segment after a claim's last one may head the next claim: both are held
        sent, aside = self.requests(claims_file(t837.claim("C6", 1), end + ["ZZZ*1"], t837.claim("C8", 1)))
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause, a.reader) for a in aside]),
                         ([ffs.canonical_id("C", "1999999984", "C6")], [("C7", "partial", ""), ("C8", "quarantined", "unknown_segment")]))

    def test_a_claim_whose_provider_name_may_be_a_row_with_an_unreadable_number_is_held_naming_the_row(self) -> None:
        """Each way the same provider's name is written differently in the two files (the reviewer's table); a different provider is not held."""
        def named(code: str, spec: tuple, npi: str) -> str:
            kind, last, first, mid = (*spec, "", "", "")[:4]
            return f"NM1*{code}*{kind}*{last}*{first}*{mid}***XX*{npi}"

        def verdict(row: dict, billing: tuple, rendering: tuple | None = None) -> tuple:
            head = ["BHT*0019*00*1*20260102*0930*CH", "HL*1**20*1", named("85", billing, CLEAN), "HL*2*1*22*0", "SBR*P*18", "NM1*IL*1*DOE*JANE****MI*S1"]
            claim = [x.replace("UN*1.5", "UN*1") for x in t837.claim("C1", 1)]
            claim = claim[:1] + ([named("82", rendering, CLEAN)] if rendering else []) + claim[1:]
            listed = leie.read_leie((tl.HEAD + tl.row(npi=tl.make_npi(1)) + tl.row(npi=CLEAN + "0", **row)).encode(), source="synthetic", as_of="2027-03-10")
            sent, aside = ffs.requests_of([r837.read_837(t837.file_of([head + claim], kind="837"))], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, listed)
            return bool(sent), [(a.cause, a.reader) for a in aside]

        person = {"last": "SMITH", "first": "JOHN"}
        table = [("the same words", person, ("1", "SMITH", "JOHN")), ("lower case and punctuation", person, ("1", "smith-j.", "john")),
                 ("a middle initial in the claim's first name", person, ("1", "SMITH", "JOHN Q")), ("a middle name in the row", {**person, "mid": "Q"}, ("1", "SMITH", "JOHN")),
                 ("written as one organization name", person, ("2", "JOHN SMITH MD")), ("a suffix in the last name", person, ("1", "SMITH JR", "JOHN")), ("a suffix in the row", {**person, "last": "SMITH JR"}, ("1", "SMITH", "JOHN")),
                 ("a company word added", {"last": "", "bus": "ACME HOME CARE"}, ("2", "ACME HOME CARE LLC")),
                 ("another case", {"last": "", "bus": "ACME HOME CARE"}, ("2", "Acme Home Care")),
                 ("a word written apart", {"last": "", "bus": "ACME HOMECARE"}, ("2", "ACME HOME CARE")), ("with other words in the claim", {"last": "", "bus": "ACME HOMECARE"}, ("2", "ACME HOME CARE SERVICES")), ("words written together", {"last": "", "bus": "ACME HOME CARE"}, ("2", "ACME HOMECARE")),
                 ("an accent", {"last": "PEREZ", "first": "JOSE"}, ("1", "PEREZ", "JOSÉ")), ("a longer first name", person, ("1", "SMITH", "JOHNNY")),
                 ("a hyphen made a space", {"last": "SMITH-JONES", "first": "ANN"}, ("1", "SMITH JONES", "ANN")),
                 ("a row with no first name", {"last": "SMITH", "first": ""}, ("1", "SMITH", "JOHN")),
                 ("a surname that is a suffix word", {"last": "DO", "first": "JOHN"}, ("1", "DO", "JOHN")), ("a suffix word, another", {"last": "PA", "first": "ANN"}, ("1", "PA", "ANN")),
                 ("a business named by a company word", {"last": "", "bus": "CO"}, ("2", "CO")),
                 ("a surname written apart in the claim", {"last": "OBRIEN", "first": "PAT"}, ("1", "O'BRIEN", "PAT")), ("a surname written apart in the row", {"last": "O'BRIEN", "first": "PAT"}, ("1", "OBRIEN", "PAT")),
                 ("Mc written apart in the claim", {"last": "MCDONALD", "first": "JOHN"}, ("1", "MC DONALD", "JOHN")), ("Mc written apart in the row", {"last": "MC DONALD", "first": "JOHN"}, ("1", "MCDONALD", "JOHN")),
                 ("a business word written apart in the claim", {"last": "", "bus": "HOMECARE"}, ("2", "HOME CARE INC")), ("a business word written apart in the row", {"last": "", "bus": "HOME CARE INC"}, ("2", "HOMECARE")),
                 ("a hyphenated first name, its second part", {"last": "SMITH", "first": "MARY-ANN"}, ("1", "SMITH", "ANN")),
                 ("a hyphenated first name, its first part", {"last": "SMITH", "first": "MARY-ANN"}, ("1", "SMITH", "MARY")), ("a hyphenated first name, all of it", {"last": "SMITH", "first": "MARY-ANN"}, ("1", "SMITH", "MARY ANN")),
                 ("the same first initial as the last name", {"last": "SMITH", "first": "SAM"}, ("1", "SMITH", "SAM"))]
        for what, row, billing in table:
            with self.subTest(what):
                sent, why = verdict(row, billing)
                self.assertEqual((sent, [c for c, _ in why]), (False, ["exclusion_npi_unreadable"]))
                self.assertTrue(why[0][1].startswith("exclusion row "), "the hold names the row")
        sent, why = verdict(person, ("2", "BIG CLINIC"), ("1", "SMITH", "JOHN", "Q"))  # the rendering provider's name counts too
        self.assertEqual((sent, [c for c, _ in why]), (False, ["exclusion_npi_unreadable"]))
        for what, row, billing in (("another person", person, ("1", "JONES", "MARY")), ("the last name with another initial", person, ("1", "SMITH", "ANN")),
                                   ("another business", {"last": "", "bus": "ACME HOME CARE"}, ("2", "BIG CLINIC")),
                                   ("a longer last name", person, ("1", "SMITHSON", "MARY")),
                                   ("a first initial that is the last name's letter", {"last": "SMITH", "first": "SAM"}, ("1", "SMITH", "ANN")),
                                   ("the claim's initial that is the last name's letter", {"last": "SMITH", "first": "ANN"}, ("1", "SMITH", "SAM")),
                                   ("a one-word row inside another surname", {"last": "BRIEN", "first": "PAT"}, ("1", "OBRIENS", "PAT"))):
            self.assertEqual(verdict(row, billing), (True, []), what)

    def test_a_claim_with_no_line_and_a_lost_header_holds_the_next_claim_which_would_otherwise_be_read_under_its_member(self) -> None:
        lost = ["H?*3*1*22*0", "SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S00000002"]  # the next claim's HL is dropped; its SBR and NM1*IL look like the first claim's other payer
        read = r837.read_837(t837.file_of([t837.head() + t837.claim("C1", 0) + lost + t837.claim("C2", 1), ], kind="837"))
        sent, aside = self.requests(read)
        self.assertEqual(([r.payment_id for r in sent], sorted(a.id for a in aside)), ([], ["C1", "C2"]))

    def test_a_claim_by_the_name_of_a_row_with_no_number_and_no_exclusion_type_is_held_and_another_provider_is_paid(self) -> None:
        listed = leie.read_leie((tl.HEAD + tl.row(npi=tl.make_npi(1)) + tl.row(last="SMITH", first="JOHN", npi="0", typ="")).encode(), source="synthetic", as_of="2027-03-10")
        for name, held in (("SMITH*JOHN", True), ("ROE*RAY", False)):
            body = [h.replace("NM1*85*2*SYNTHETIC CLINIC*****XX", f"NM1*85*1*{name}****XX") for h in t837.head()] + [s.replace("UN*1.5", "UN*1") for s in t837.claim("C1", 1)]
            sent, aside = ffs.requests_of([r837.read_837(t837.file_of([body], kind="837"))], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, listed)
            self.assertEqual((bool(sent), [a.cause for a in aside]), (not held, ["exclusion_npi_unreadable"] * held), name)

    def test_a_claim_sent_twice_is_one_claim_and_two_claims_under_one_id_are_both_held(self) -> None:
        sent, aside = self.requests(claims_file(t837.claim("C1", 1), t837.claim("C2", 1), t837.claim("C1", 1), t837.claim("C2", 2), t837.claim("C3", 1)))
        self.assertEqual([r.payment_id for r in sent], [ffs.canonical_id("C", "1999999984", c) for c in ("C1", "C3")])
        self.assertEqual([(a.id, a.cause, a.cents) for a in aside],
                         [("C1", "retry", 1000), ("C2", "payment_id_conflict", 1000), ("C2", "payment_id_conflict", 2000)])

    def test_a_claim_a_replacement_or_void_names_is_never_sent_in_any_order_or_file(self) -> None:
        c1, c4 = t837.claim("C1", 1), t837.claim("C4", 1)
        void, repl = t837.claim("C2", freq="8", ref="C1"), t837.claim("C3", freq="7", ref="C4")
        want = [("C1", "replaced_or_voided", "named by claim C2"), ("C2", "replacement_or_void", ""), ("C3", "replacement_or_void", ""),
                ("C4", "replaced_or_voided", "named by claim C3")]
        for name, reads in (("after", [claims_file(c1, c4, void, repl)]), ("before", [claims_file(void, repl, c1, c4)]),
                            ("other file", [claims_file(c1, c4), claims_file(void, repl)]), ("other file first", [claims_file(void, repl), claims_file(c1, c4)])):
            sent, aside = ffs.requests_of(reads, fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE)
            self.assertEqual((sent, sorted((a.id, a.cause, a.reader) for a in aside)), ((), want), name)
        other = claims_file(void, npi="1999999992", sub="S00000002")  # another provider's void for another member names its own claim C1, not this one
        sent, aside = ffs.requests_of([claims_file(c1), other], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE)
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause) for a in aside]),
                         ([ffs.canonical_id("C", "1999999984", "C1")], [("C2", "replacement_or_void")]))

    def test_a_void_or_replacement_that_did_not_read_still_holds_the_claim_it_names(self) -> None:
        whole = lambda segs: [s.replace("UN*1.5", "UN*1") for s in segs]  # noqa: E731
        c1, c2 = whole(t837.claim("C1", 1)), whole(t837.claim("C2", 1))
        c2[-1] = "DTP*472*D8*20260201"  # the same provider and member, another day
        void, head = whole(t837.claim("V1", 1, freq="8", ref="C1")), t837.head()

        def read(*sets: list[str], cut: bool = False, off: bool = False) -> r837.Read837:
            data = t837.file_of([head + c1 + c2] + list(sets), kind="837")
            if off:  # the last set's SE count is wrong: the set is taken back whole
                at = data.rindex(b"SE*")
                data = data[:at] + b"SE*99" + data[data.index(b"*", at + 3):]
            return r837.read_837(data[:data.rindex(b"SV1") + 7] if cut else data)
        cases = {"no lines": read(head + void[:3]), "every line bad": read(head + [s.replace("*10.00*", "*X*") for s in void]),
                 "no subscriber": read(head[:5] + void), "set count off": read(head + void, off=True), "set the file ends in": read(head + void, cut=True),
                 "no REF*F8": read(head + whole(t837.claim("V1", 1, freq="8")))}
        for name, got in cases.items():
            sent, aside = self.requests(got)
            self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause) for a in aside if a.id == "C1"]),
                             ([ffs.canonical_id("C", "1999999984", "C2")], [("C1", "replaced_or_voided")]), name)

    def test_a_void_names_its_claim_by_id_however_written_under_its_provider_or_member_or_the_payers_number(self) -> None:
        moved = lambda segs: [s.replace("D8*20260101", "D8*20260301") for s in segs]  # noqa: E731  another day: only the id ties it to C1
        c1 = t837.claim("C1", 1)
        paid = r835.read_835(t837.file_of([t835.head() + t835.clp("C1")], kind="835"))  # the payer's number for C1 is PCN-C1 (CLP07)
        cases = (("case", [claims_file(c1), claims_file(moved(t837.claim("V1", 1, freq="8", ref="c1")))], None, True),
                 ("spaces", [claims_file(t837.claim("C1 ", 1)), claims_file(moved(t837.claim("V1", 1, freq="8", ref="C1")))], None, True),
                 ("corrected provider", [claims_file(c1), claims_file(moved(t837.claim("V1", 1, freq="7", ref="C1")), npi="1999999992")], None, True),
                 ("payer number", [claims_file(c1), claims_file(moved(t837.claim("V1", 1, freq="7", ref="PCN-C1")))], [paid], True),
                 ("payer number not known", [claims_file(c1), claims_file(moved(t837.claim("V1", 1, freq="7", ref="PCN-C1")))], None, False))
        for name, reads, remit, held in cases:
            sent, aside = ffs.requests_of(reads, fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE, *([remit] if remit else []))
            self.assertEqual([a.cause for a in aside if a.id.strip() == "C1"], ["replaced_or_voided"] if held else [], name)

    def test_a_void_meets_its_original_whatever_the_case_or_spacing_of_the_subscriber_id(self) -> None:
        moved = lambda segs: [s.replace("D8*20260101", "D8*20260301") for s in segs]  # noqa: E731
        for sub in ("s00000001", "S0000 0001", " s0000000 1"):
            for name, void, npi in (("no REF*F8", t837.claim("V1", 1, freq="8"), "1999999984"),
                                    ("REF*F8, corrected provider", moved(t837.claim("V1", 1, freq="8", ref="C1")), "1999999992")):
                sent, aside = ffs.requests_of([claims_file(t837.claim("C1", 1)), claims_file(void, sub=sub, npi=npi)], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE)
                self.assertEqual(([r.payment_id for r in sent], [a.cause for a in aside if a.id == "C1"]), ([], ["replaced_or_voided"]), (sub, name))

    def test_a_void_with_two_REF_F8_holds_each_claim_it_names(self) -> None:
        on = lambda day, segs: [s.replace("D8*20260101", f"D8*{day}") for s in segs]  # noqa: E731  other days: only the ids tie them
        void = on("20260501", t837.claim("V1", 1, freq="8", ref="C9"))
        at = next(k for k, s in enumerate(void) if s.startswith("REF*F8"))
        for second in ("C1", "NONE"):  # the second names the other claim, or no claim read: then each it overlaps is held
            two = void[:at + 1] + [f"REF*F8*{second}"] + void[at + 1:]
            c1 = t837.claim("C1", 1) if second == "C1" else on("20260501", t837.claim("C1", 1))
            sent, aside = ffs.requests_of([claims_file(c1), claims_file(on("20260301", t837.claim("C9", 1))), claims_file(two)],
                                          fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE)
            self.assertEqual(([r.payment_id for r in sent], sorted((a.id, a.cause) for a in aside if a.id != "V1")),
                             ([], [("C1", "replaced_or_voided"), ("C9", "replaced_or_voided")]), second)

    def test_a_void_naming_no_claim_with_a_line_whose_day_did_not_read_may_be_any_day_of_its_provider_and_member(self) -> None:
        on = lambda day, segs: [s.replace("D8*20260101", f"D8*{day}") for s in segs]  # noqa: E731
        void = [s.replace("D8*20260101", "D8*20260301") for s in t837.claim("V1", 2, freq="8")]  # no REF*F8: it may be any claim its days meet
        originals = claims_file(on("20260301", t837.claim("C0", 1)), on("20260320", t837.claim("C1", 1)))
        for name, lines in (("a day that does not read", [s.replace("D8*20260102", "D8*2026032X") for s in void]),
                            ("no day sent", [s for s in void if s != "DTP*472*D8*20260102"])):
            sent, aside = ffs.requests_of([originals, claims_file(lines)], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE)
            self.assertEqual(([r.payment_id for r in sent], sorted((a.id, a.cause) for a in aside if a.id != "V1")),
                             ([], [("C0", "replaced_or_voided"), ("C1", "replaced_or_voided")]), name)

    def test_a_payer_number_the_remittance_gives_two_claims_holds_both_and_their_items_say_so(self) -> None:
        both = [s.replace("PCN-C1", "PCN-X") for s in t835.clp("C1")] + [s.replace("PCN-C2", "PCN-X") for s in t835.clp("C2")]
        paid = r835.read_835(t837.file_of([t835.head(total="160.00") + both], kind="835"))
        void = [s.replace("D8*20260101", "D8*20260301") for s in t837.claim("V1", 1, freq="8", ref="pcn-x")]
        sent, aside = ffs.requests_of([claims_file(t837.claim("C1", 1), t837.claim("C2", 1)), claims_file(void)], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE, [paid])
        note = "named by claim V1; the payer's claim number PCN-X is given to claims C1 C2 in the remittance"
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause, a.reader) for a in aside if a.id != "V1"]),
                         ([], [("C1", "replaced_or_voided", note), ("C2", "replaced_or_voided", note)]))
        spelt = [r835.read_835(t837.file_of([t835.head(total=total) + [s.replace(f"PCN-{c}", pcn) for s in t835.clp(c)]], kind="835"))
                 for c, pcn, total in (("C1", "PCN-X", "80.00"), ("C2", "pcn-x", "80.00"))]  # one payer number spelled two ways in two remittances
        for paid in (spelt, spelt[::-1]):
            sent, aside = ffs.requests_of([claims_file(t837.claim("C1", 1), t837.claim("C2", 1)), claims_file(void)], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE, paid)
            self.assertEqual([(a.id, a.cause, a.reader) for a in aside if a.id != "V1"], [("C1", "replaced_or_voided", note), ("C2", "replaced_or_voided", note)])

    def test_a_copy_of_a_claim_set_aside_keeps_its_cause_and_a_zero_unit_line_is_set_aside(self) -> None:
        zero = t837.claim("C1", 1)
        zero[3] = "SV1*HC:99213*10.00*UN*0"
        later = [s.replace("D8*202601", "D8*202603") for s in t837.claim("C2", freq="7", ref="C0")]  # naming no claim read, it holds only those its days meet
        sent, aside = self.requests(claims_file(zero, later, zero, later))
        self.assertEqual((sent, [(a.id, a.cause) for a in aside]),
                         ((), [("C1", "units"), ("C1", "units"), ("C2", "replacement_or_void"), ("C2", "replacement_or_void")]))

    def test_a_copy_the_reader_set_a_segment_of_aside_is_not_alike_a_whole_copy(self) -> None:
        unread = t837.claim("C1", 1)
        unread.insert(5, "ZZZ*1")
        for order in ((unread, t837.claim("C1", 1)), (t837.claim("C1", 1), unread)):
            sent, aside = self.requests(claims_file(*order))
            self.assertEqual((sent, [(a.id, a.cause) for a in aside]), ((), [("C1", "payment_id_conflict")] * 2))

    def test_one_file_read_twice_and_its_claim_in_another_file_are_retries_never_one_merged_claim(self) -> None:
        read, other = claims_file(t837.claim("C1", 2), t837.claim("C2", 1)), claims_file(t837.claim("C9", 1), t837.claim("C1", 2))
        sent, aside = ffs.requests_of([read, other, read], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, NO_ONE)
        self.assertEqual([(r.payment_id, len(r.lines), r.amount_cents) for r in sent],
                         [(ffs.canonical_id("C", "1999999984", c), n, n * 1000) for c, n in (("C1", 2), ("C2", 1), ("C9", 1))])
        self.assertEqual([(a.id, a.cause, a.cents) for a in aside], [("C1", "retry", 2000), ("C1", "retry", 2000), ("C2", "retry", 1000)])

    def test_modifiers_in_any_order_give_one_procedure_key(self) -> None:
        swapped = t837.claim("C1", 1)
        swapped[3] = "SV1*HC:99213:GT:25*10.00*UN*1***1"
        self.assertEqual(self.requests(claims_file(swapped))[0][0].lines, self.requests(claims_file(t837.claim("C1", 1)))[0][0].lines)
        self.assertEqual([(a.id, a.cause) for a in self.requests(claims_file(t837.claim("C1", 1), swapped))[1]], [("C1", "retry")])

    def test_two_requests_under_one_payment_id_are_refused_before_any_is_decided(self) -> None:
        sent, _ = self.requests(claims_file(t837.claim("C1", 1)))
        with self.assertRaises(decider.GateDecideError) as refused:  # never one kept and the other dropped
            ffs.decide_claims(sent * 2, None, (None, None), {}, {}, b"", None, fx.PROGRAM, 0)
        self.assertEqual((refused.exception.args[0], refused.exception.sealed), ("request_malformed", []))

    def test_the_shard_count_is_the_key_certificates_and_every_shard_must_be_open(self) -> None:
        sent, _ = self.requests(claims_file(t837.claim("C1", 1)))
        prod = lambda n: SimpleNamespace(_cert=fx.certify(gate.encode_key_cert(fx.TENANT, fx.EPOCH, fx.link_digest(fx.TENANT), (n,), bytes(gate.ML_DSA_87_PUBLIC_KEY),
                                                   bytes(gate.ML_DSA_87_PUBLIC_KEY)), fx.TENANT))  # noqa: E731
        for shards in ({0: prod(2)}, {0: prod(1), 1: prod(2)}, {1: prod(1)}, {}):  # a subset, two counts, another number, none
            with self.assertRaises(decider.GateDecideError) as refused:
                ffs.decide_claims(sent, None, (SimpleNamespace(tenant=fx.TENANT), None), shards, {}, b"", None, fx.PROGRAM, 0)
            self.assertEqual((refused.exception.args[0], refused.exception.sealed), ("tenant_shards", []), shards)


DEAD = "1588667638"  # a 10-digit NPI that dies 2025-12-01


class NameFinderTests(unittest.TestCase):
    def test_the_finder_holds_exactly_the_claims_a_check_of_every_row_in_order_holds(self) -> None:
        """Random names and rows over words that join, split and share initials: the finder and a brute-force walk of the same match functions agree on the first row."""
        rng = random.Random(11)
        vocab = ["A", "B", "AB", "BA", "ABC", "O", "BRIEN", "OBRIEN", "MC", "DONALD", "MCDONALD", "SMITH", "JO", "JOHN", "J", "DO", "CO", "LLC", "MD"]
        say = lambda low, high: " ".join(rng.choice(vocab) for _ in range(rng.randint(low, high)))  # noqa: E731
        rows = [(1000 + n, SimpleNamespace(last_name=say(1, 2) if kind else "", first_name=say(0, 2) if kind else "", business_name="" if kind else say(1, 3)))
                for n, kind in enumerate(rng.random() < 0.7 for _ in range(60))]
        find = ffs._row_finder(rows)
        matched = 0
        for _ in range(3000):
            names = name_tokens(say(1, 6))
            expected = None
            for at, row in rows:
                words, _, _, match = ffs._row_match(row)
                pool = names.every if words.bare else names.order
                if words and match(pool, frozenset(pool), "".join(pool), lambda: ffs._spans(pool)):
                    expected = at
                    break
            self.assertEqual(find(names), expected, (names.order, names.every))
            matched += expected is not None
        self.assertTrue(300 < matched < 2900, matched)  # the walk is not vacuous: some names match and some do not


HIST = g.ENGINE.with_name("gate_hist3.exe")  # the rows-file engine, which runs a runnable rule set
# the genesis key set and its step to epoch 1, which adds the POLICY keys that sign rule sets
POLICY_KEYS = decider.Keys(au.genesis()[1], ((au.TODAY, au.keyset_doc(au.keyset_body(1, au.genesis()[0], 20270310, 20270409,
                                                                                      extra=ra.POLICY_KEYS))),))
RUN_DOC = rs.with_(ra.BASE, version=1, prev=bytes(64), eff_from=10101, eff_to=99991231)  # runnable: pack 1 for all time
RUN, RUN_ID = ra.sign(RUN_DOC), ra.digest(RUN_DOC)
V2 = ra.sign(rs.with_(RUN_DOC, version=2, prev=RUN_ID, eff_from=20270701, ends=[(1, 20270630)]))  # ends version 1


class RuleSetTests(fx.Scratch):
    """The tenant's signed rule sets from its deployment folder (``open_host``), through ``decide_claims`` to the real
    engines (conformance/RULESET_V1.md section 9)."""

    setUpClass = ExcludedNpiTests.setUpClass

    def _steps(self, engine: Path, steps: list[dict]) -> list:
        """The host opened on ``engine`` (the rows-file engine's hash taken as the committed pin) with an empty rule-set
        folder.  For each step, its files placed in the folder (None: removed), then one claim per shard decided: the
        (outcome, reasons) of each line and the tenant's rule-set floors after."""
        if not engine.is_file():
            raise AssertionError(f"RULE SETS NOT RUN: {engine} missing; run `lake build gate_engine gate_hist3` in lean/")
        pack, out = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}, []
        pin = (mock.patch.object(decider, "committed_pin", lambda: hashlib.sha256(engine.read_bytes()).digest())
               if engine == HIST else contextlib.nullcontext())
        with self.scratch() as tmp, pin:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor, folder = Path(tmp) / "tenant.floor", Path(tmp) / "rulesets"
            folder.mkdir()
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), engine, ruleset_folder=folder)
            flats = {k: Path(tmp) / f"idx{k}" for k in shards}
            try:
                for n, files in enumerate(steps):
                    for name, record in files.items():
                        (folder / name).unlink() if record is None else (folder / name).write_bytes(record)
                    sent = [claim(2 * n + k + 1, 1001 + k, CLEAN, 20270305 + n, "C99213", 12500, k) for k in range(2)]
                    rows = ffs.decide_claims(sent, g.HEAD, host, shards, flats, g.GRANT, POLICY_KEYS, fx.PROGRAM, fx.NOW)[0]
                    out.append(([(o, w) for _, _, o, w in rows], decider.TenantAuthority.floors_in(floor, fx.TENANT)[2:]))
            finally:
                host[1].close()
        return out

    def test_a_tenant_takes_up_its_first_rule_set_and_holds_a_later_version(self) -> None:
        """No rule set: decided as today.  The state's first record placed in the folder: the next batch on each shard
        admits it (the first shard as its first record, the other as a shard behind the tenant) and decides as before;
        the tenant's floors carry it.  A version 2 placed there: the gate cannot run it, so every line holds
        ``ruleset_newer`` and nothing is sealed; removed, the shards decide under version 1 again."""
        allowed, zero = [("ALLOW", ())] * 2, (0, bytes(64))
        self.assertEqual(self._steps(HIST, [{}, {"first.rec": RUN}, {}, {"second.rec": V2}, {"second.rec": None}]),
                         [(allowed, zero), (allowed, (1, RUN_ID)), (allowed, (1, RUN_ID)),
                          ([("HOLD", ("ruleset_newer",))] * 2, (1, RUN_ID)), (allowed, (1, RUN_ID))])

    def test_the_pinned_engine_holds_every_line_for_a_rule_set_it_cannot_run(self) -> None:
        """The pinned engine runs no rule set: once the first record is in the folder, every line holds
        ``grant_ruleset_not_run``, nothing is admitted, and the host goes on."""
        self.assertEqual(self._steps(g.ENGINE, [{"first.rec": RUN}, {"first.rec": None}]),
                         [([("HOLD", ("grant_ruleset_not_run",))] * 2, (0, bytes(64))), ([("ALLOW", ())] * 2, (0, bytes(64)))])


class FileToDecisionTests(fx.Scratch):
    """Synthetic 837, 834 and LEIE files and provider death rows, through the slot check and the pinned engine, to one
    decision per line grouped by cause."""

    setUpClass = ExcludedNpiTests.setUpClass

    def test_each_claim_line_is_decided_by_the_engine_and_grouped_by_cause(self) -> None:
        def sent(npi: str, sub: str, cid: str, day: int, *extra: str) -> list[str]:
            c = t837.claim(cid, 1)
            c[-1], c[1:1] = f"DTP*472*D8*202703{day:02d}", extra
            return t837.head(npi, sub) + [s.replace("UN*1.5", "UN*1") for s in c]
        claims = r837.read_837(t837.file_of([sent(CLEAN, "M1", "C1", 1), sent(EXCLUDED, "M1", "C2", 2), sent(CLEAN, "M2", "C3", 3),
                                             sent(CLEAN, "M3", "C4", 4), sent(CLEAN, "M1", "C5", 3, f"NM1*82*1*ROE*RAY****XX*{DEAD}"),
                                             t837.head(CLEAN, "M1") + t837.claim("C6", 1, freq="8", ref="C0"), sent(CLEAN, "M4", "C7", 5),
                                             sent(CLEAN, "M1", "C8", 6, f"NM1*82*1*ROE*RAY****XX*{EXCLUDED} *"),
                                             sent(CLEAN, "M1", "C9", 7, f"NM1*82*1*ROE*RAY****XX*0{EXCLUDED}")],
                                            kind="837"))
        span = {"begin": "20270101", "end": "20271231"}  # today (the test key set's life) within each feed's maximum age
        cancelled = t834.member("M4", **span) + t834.member("M4", ins03="024", begin="20270101", end="20270228")  # added and cancelled
        enrolled = r834.read_834(t837.file_of([t834.header() + t834.member("M1", **span) + t834.member("M2", death="20270302", **span)
                                               + cancelled], gs_date="20270314"))
        listed = leie.read_leie((tl.HEAD + tl.row(npi=EXCLUDED) + tl.row(last="BACK", npi=CLEAN, excl="20200101", rein="20210101")).encode(),
                                source="synthetic", as_of="2027-03-10")
        secret = b"synthetic tenant secret, 32 b.."
        sent_, aside = ffs.requests_of([claims], fx.TENANT, fx.PROGRAM, fx.PERIOD, secret, listed)
        read, left = ffs.feeds(au.TODAY, enrolled, listed, ("2027-03-01", [(DEAD, "2027-02-01")]), secret)
        supplement = leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2027-03-10", kind="exclusions")
        self.assertEqual(ffs.feeds(au.TODAY, enrolled, supplement, ("2027-03-01", []), secret)[0][1][2], (bytes(77), b""))
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            with self.assertRaises(slots.SlotError) as empty:
                ffs.open_host(slots.Slots({}), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            try:
                rows, groups, sealed = ffs.decide_claims(sent_, read, host, shards, {k: Path(tmp) / f"idx{k}" for k in shards},
                                                         g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)
            finally:
                host[1].close()
        self.assertEqual(empty.exception.args[0], "slots_unauthored")
        claim_of = {r.payment_id: cid for r, cid in zip(sent_, ("C1", "C2", "C3", "C4", "C5", "C7"))}
        self.assertEqual(sorted((claim_of[p], i, o, w) for p, i, o, w in rows),
                         [("C1", 0, "ALLOW", ()), ("C2", 0, "HOLD", ("PROVIDER_EXCLUDED",)), ("C3", 0, "HOLD", ("MEMBER_DECEASED",)),
                          ("C4", 0, "HOLD", ("MEMBER_NOT_ENROLLED",)), ("C5", 0, "HOLD", ("PROVIDER_DECEASED",)),
                          ("C7", 0, "HOLD", ("MEMBER_NOT_ENROLLED",))])
        self.assertEqual(groups, {("ALLOW", ()): (1, 1000), ("HOLD", ("PROVIDER_EXCLUDED",)): (1, 1000), ("HOLD", ("MEMBER_DECEASED",)): (1, 1000),
                                  ("HOLD", ("MEMBER_NOT_ENROLLED",)): (2, 2000), ("HOLD", ("PROVIDER_DECEASED",)): (1, 1000)})
        self.assertEqual([(a.id, a.cause, a.cents) for a in aside],  # an excluded rendering NPI padded with a space or a zero is never allowed
                         [("C6", "replacement_or_void", 1000), ("C8", "bad_npi", 1000), ("C9", "bad_npi", 1000)])
        self.assertEqual(left, ())  # M4's later cancellation ends its added span before C7's day
        self.assertEqual(sum(len(t) for _, t, _ in sealed), 6)

    def test_an_834_fault_holds_its_member_and_a_voided_set_sends_every_line_to_review(self) -> None:
        """A coverage end or a death on no calendar day sets its member aside, so the member's claims hold, never paid as covered
        with no end or alive; a voided set of the file may hold a cancellation, so the enrollment is unknown: every line is reviewed."""
        def claims(*pairs: tuple[str, str]) -> tuple:
            body = []
            for sub, cid in pairs:
                c = t837.claim(cid, 1)
                c[-1] = "DTP*472*D8*20270305"
                body.append(t837.head(CLEAN, sub) + [s.replace("UN*1.5", "UN*1") for s in c])
            return ffs.requests_of([r837.read_837(t837.file_of(body, kind="837"))], fx.TENANT, fx.PROGRAM, fx.PERIOD, secret, NO_ONE)[0]
        secret, span = b"synthetic tenant secret, 32 b..", {"begin": "20270101", "end": "20271231"}
        good = t837.file_of([t834.header() + t834.member("M1", **span) + t834.member("M2", begin="20270101", end="20271340")
                             + t834.member("M3", death="20271301", **span) + t834.member("M4", death="20270302", **span)
                             + t834.member("M5", **span)], gs_date="20270314")
        voided = good + t837.file_of([t834.header() + t834.member("M5", ins03="024", begin="20270101", end="20270228")], control="000000002",
                                     gs_date="20270314", se_count=3)
        listed = leie.read_leie((tl.HEAD + tl.row(npi=EXCLUDED)).encode(), source="synthetic", as_of="2027-03-10")
        read_set = lambda data: ffs.feeds(au.TODAY, r834.read_834(data), listed, ("2027-03-01", [(DEAD, "2027-02-01")]), secret)[0]  # noqa: E731
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            flats = {k: Path(tmp) / f"idx{k}" for k in shards}
            try:
                first, later = claims(("M1", "C1"), ("M2", "C2"), ("M3", "C3")), claims(("M5", "C4"))
                held = ffs.decide_claims(first, read_set(good), host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)[0]
                review = ffs.decide_claims(later, read_set(voided), host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)[0]
            finally:
                host[1].close()
        claim_of = {r.payment_id: cid for r, cid in zip(first, ("C1", "C2", "C3"))}
        self.assertEqual(sorted((claim_of[p], o, w) for p, _, o, w in held),
                         [("C1", "ALLOW", ()), ("C2", "HOLD", ("MEMBER_NOT_ENROLLED",)), ("C3", "HOLD", ("MEMBER_NOT_ENROLLED",))])
        self.assertEqual([(o, {"STALE_DMF", "STALE_ENROLLMENT"} <= set(w)) for _, _, o, w in review], [("HUMAN_REVIEW", True)])

    def test_a_later_batch_that_fails_returns_the_tokens_sealed_before_it_and_a_resend_never_pays_them_twice(self) -> None:
        real = decider.decide

        def decide(feeds, asof, prod, *rest, **kw):
            if prod.shard == 1:
                raise decider.GateDecideError("rules_refused")
            return real(feeds, asof, prod, *rest, **kw)
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            sent, flats = [claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1002, CLEAN, 20270306, "C99214", 9800, 1)], {k: Path(tmp) / f"idx{k}" for k in shards}
            try:
                with mock.patch.object(decider, "decide", decide), self.assertRaises(decider.GateDecideError) as failed:
                    ffs.decide_claims(sent, g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)
                rows, _, sealed = ffs.decide_claims(sent, g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)
            finally:
                host[1].close()
        self.assertEqual((failed.exception.args[0], [len(t) for _, t, _ in failed.exception.sealed]), ("rules_refused", [1]))
        self.assertEqual([len(t) for _, t, _ in sealed], [1, 1])  # the sealed batch is given again, not decided again: no second payment
        self.assertEqual([(p, o, w) for p, _, o, w in rows], [("pay-1", "ALLOW", ()), ("pay-2", "ALLOW", ())])
        self.assertEqual(sealed[0], failed.exception.sealed[0])

    def test_an_exact_resend_after_a_normal_seal_returns_the_first_tokens_and_commits_nothing(self) -> None:
        """CONSTITUTION III.3, a response lost after the commit: the same requests again give the same signed checkpoint and tokens."""
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        real, commits = decider.commit, []
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            flats, sent = {k: Path(tmp) / f"idx{k}" for k in shards}, [claim(1, 1001, CLEAN, 20270305, "C99213", 12500)]
            run = lambda: ffs.decide_claims(sent, g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)  # noqa: E731
            try:
                with mock.patch.object(decider, "commit", lambda *a, **k: commits.append(1) or real(*a, **k)):
                    first, again = run(), run()
            finally:
                host[1].close()
        self.assertEqual(([(p, o, w) for p, _, o, w in first[0]], len(commits)), ([("pay-1", "ALLOW", ())], 1))
        self.assertEqual((again[0], again[1], again[2]), ([("pay-1", 0, "ALLOW", ())], {("ALLOW", ()): (1, 12500)}, first[2]))

    def test_an_exact_resend_of_a_batch_another_request_sealed_returns_its_tokens(self) -> None:
        """A batch whose commit failed is sealed by the next request on its shard, its tokens filed for its own requests:
        sending those again returns each payment as its token says, and its signed checkpoint and tokens."""
        def broken(*_: object, **__: object) -> None:
            raise decider.MachineFault("store_unavailable")
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            flats, first = {k: Path(tmp) / f"idx{k}" for k in shards}, [claim(1, 1001, CLEAN, 20270305, "C99213", 12500)]
            run = lambda sent: ffs.decide_claims(sent, g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)  # noqa: E731
            try:
                with mock.patch.object(decider, "commit", broken), self.assertRaises(decider.MachineFault) as failed:
                    run(first)
                run([claim(2, 1002, CLEAN, 20270306, "C99214", 9800)])
                rows, groups, sealed = run(first)
            finally:
                host[1].close()
        self.assertEqual((failed.exception.sealed, rows, groups), ([], [("pay-1", 0, "ALLOW", ())], {("ALLOW", ()): (1, 12500)}))
        self.assertEqual([len(t) for _, t, _ in sealed], [1])

    def resend(self, *sends: list) -> tuple:
        """The rows, groups and sealed batches of each of ``sends`` in turn, on one store."""
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            flats = {k: Path(tmp) / f"idx{k}" for k in shards}
            try:
                return tuple(ffs.decide_claims(s, g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW) for s in sends)
            finally:
                host[1].close()

    def test_a_resend_in_another_order_returns_the_sealed_tokens_not_already_decided(self) -> None:
        sent = [claim(n, 1000 + n, CLEAN, 20270305 + n, "C99213", 12500) for n in (1, 2, 3)]
        first, again = self.resend(sent, sent[::-1])
        self.assertEqual(sorted(again[2]), sorted(first[2]))
        self.assertEqual(sorted((p, o) for p, _, o, _ in again[0]), sorted((p, o) for p, _, o, _ in first[0]))
        self.assertNotIn("ALREADY_DECIDED", [x for *_, w in again[0] for x in w])

    def test_a_resend_reports_each_payment_as_its_signed_token_says_and_holds_keep_a_cause_row(self) -> None:
        sent = [claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1001, CLEAN, 20270305, "C99213", 12500)]  # the second repeats the first
        first, again = self.resend(sent, sent)
        self.assertEqual([(p, o) for p, _, o, _ in first[0]], [("pay-1", "ALLOW"), ("pay-2", "HOLD")])
        self.assertEqual([(p, o, w) for p, _, o, w in again[0]], [("pay-1", "ALLOW", ()), ("pay-2", "HOLD", ("held_in_first_answer",))])
        self.assertEqual(again[1], {("ALLOW", ()): (1, 12500), ("HOLD", ("held_in_first_answer",)): (1, 12500)})
        row = next(r for r in json.loads((ROOT / "app" / "cause_actions.json").read_text("utf-8")) if r["code"] == "held_in_first_answer")
        self.assertFalse(any(w in row["action"] for w in (" or ", "investigate", ";")))

    def test_an_exact_retry_of_a_sealed_batch_with_an_answered_payment_is_given_the_same_answer(self) -> None:
        """Constitution I.4: pay-2 repeats paid pay-1 in every field but the line id, so it is answered at once with the
        earlier payment; its exact retry is given the same signed checkpoint, tokens and earlier list, and reports ANSWERED."""
        paid, repeat = claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1001, CLEAN, 20270305, "C99213", 12500)
        first, answered, again = self.resend([paid], [repeat], [repeat])
        earlier = (("L2", fx.PROGRAM, "pay-1", "L1"),)
        self.assertEqual(first[0], [("pay-1", 0, "ALLOW", ())])
        self.assertEqual([len(t) for _, t, _ in answered[2]], [1])
        self.assertEqual(answered[2][0][2], (earlier,))
        self.assertEqual(gate.read_token(answered[2][0][1][0])[1:], ("ANSWERED", ("FFS_DUPLICATE_LINE",), gate.earlier_root(earlier)))
        self.assertEqual(again[2], answered[2])  # byte for byte: nothing decided or sealed again
        self.assertEqual(ffs.given(again[2][0][1]), {"pay-2": ("ANSWERED", ("FFS_DUPLICATE_LINE",))})
        self.assertEqual(again[:2], answered[:2])  # the first answer and its retry report the same rows and groups
        self.assertEqual(again[:2], ([("pay-2", 0, "ANSWERED", ("FFS_DUPLICATE_LINE",))], {("ANSWERED", ("FFS_DUPLICATE_LINE",)): (1, 12500)}))

    def test_a_two_line_payment_with_one_repeated_line_is_answered_whole_and_its_retry_is_given_the_same_answer(self) -> None:
        """Row level: pay-2 has a line that repeats paid pay-1 (L2) and a fresh one (L3).  The payment is ANSWERED at once, never
        paid; each of its two lines reports that outcome, the earlier list names only the repeated line, and the retry is given
        the same signed checkpoint, token and list."""
        paid, repeat = claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1001, CLEAN, 20270305, "C99213", 12500)
        key = repeat.member_key
        fresh = gate.encode_line("FFS_CLAIM", "L3", key, CLEAN, CLEAN, 20270306, "C99214", 1, 9800)
        mixed = gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", "cmd-2", "pay-2", key, CLEAN, 12500 + 9800, fx.PERIOD,
                                   (repeat.lines[0], fresh), repeat.evidence_refs)
        first, answered, again = self.resend([paid], [mixed], [mixed])
        earlier = (("L2", fx.PROGRAM, "pay-1", "L1"),)
        reasons = ("FFS_DUPLICATE_LINE",)
        self.assertEqual(first[0], [("pay-1", 0, "ALLOW", ())])
        self.assertEqual(answered[0], [("pay-2", 0, "ANSWERED", reasons), ("pay-2", 1, "ANSWERED", reasons)])
        self.assertEqual(answered[1], {("ANSWERED", reasons): (2, 12500 + 9800)})
        self.assertEqual([len(t) for _, t, _ in answered[2]], [1])
        self.assertEqual(answered[2][0][2], (earlier,))
        self.assertEqual(again[2], answered[2])
        self.assertEqual(again[:2], answered[:2])

    def upgraded(self, sends: list, retries: list, edit=lambda db: None, old: bool = True) -> list:
        """The results of ``sends`` on one store, then of each of ``retries`` (an exception is a result) after shard 0's
        store is made one sealed before earlier lists were stored (``g.before_lists``; with ``old`` false, its sealed
        rows kept and only its ``earlier`` rows deleted), and ``edit`` run on it with the frame triggers dropped (and, for
        an old store, ``batches_fixed``)."""
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        out = []
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            floor, flats = Path(tmp) / "tenant.floor", {k: Path(tmp) / f"idx{k}" for k in range(fx.SHARDS)}
            for phase in (sends, retries):
                shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
                if phase is sends:
                    decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
                host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
                try:
                    for sent in phase:
                        try:
                            out.append(ffs.decide_claims(sent, g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW))
                        except Exception as error:
                            out.append(error)
                finally:
                    host[1].close()
                    for p in shards.values():
                        p.close()
                if phase is sends:
                    with contextlib.closing(sqlite3.connect(c.store(0))) as db:
                        if old:
                            g.before_lists(db, c.custody[0], (fx.TENANT, 0))
                        else:
                            db.executescript("DROP TRIGGER earlier_void; DELETE FROM earlier;")
                        db.executescript("DROP TRIGGER records_fixed; DROP TRIGGER records_void;")
                        edit(db)
                        db.commit()
        return out

    def test_an_exact_retry_of_a_batch_answered_before_lists_were_stored_is_given_the_same_list(self) -> None:
        """Constitution I.4 across the store upgrade: a batch answered and sealed before earlier lists were stored has its
        lists rebuilt from the stored frames; each exact retry is given the bytes it was given first: a one-line repeat, and
        a two-line payment with one repeated line and one new."""
        key = g.member(1001, 0)
        line = lambda n, date, code, cents: gate.encode_line("FFS_CLAIM", f"L{n}", key, CLEAN, CLEAN, date, code, 1, cents)  # noqa: E731
        paid, repeat = claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1001, CLEAN, 20270305, "C99213", 12500)
        two = dataclasses.replace(paid, command_key="cmd-3", payment_id="pay-3", amount_cents=22300,
                                  lines=(line(3, 20270305, "C99213", 12500), line(4, 20270306, "C99214", 9800)))
        first, answered, both, again, again_both = self.upgraded([[paid], [repeat], [two]], [[repeat], [two]])
        self.assertEqual(first[0], [("pay-1", 0, "ALLOW", ())])
        self.assertEqual((answered[2][0][2], both[2][0][2]), (((("L2", fx.PROGRAM, "pay-1", "L1"),),), ((("L3", fx.PROGRAM, "pay-1", "L1"),),)))
        self.assertEqual(again, answered)  # rows, groups, signed checkpoint, tokens and earlier list, byte for byte
        self.assertEqual(again_both, both)

    def test_a_deleted_list_of_a_batch_sealed_with_its_list_is_tampered_never_rebuilt(self) -> None:
        """The same answered batch, sealed after lists were stored, whose stored list was later deleted: its pledged row
        says the list was stored, so each exact retry is ``store_tampered``, though the frames would rebuild it."""
        paid, repeat = claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1001, CLEAN, 20270305, "C99213", 12500)
        *_, refused, again = self.upgraded([[paid], [repeat]], [[repeat], [repeat]], old=False)
        self.assertEqual([(type(e), str(e)) for e in (refused, again)], [(producer.GateProducerError, "store_tampered")] * 2)

    def test_an_old_batch_whose_stored_frames_were_changed_is_tampered_and_a_near_copy_is_decided_afresh(self) -> None:
        """A retry of a batch sealed before lists were stored whose own frame, or the paid batch's, was removed, changed or
        made unreadable, or whose paid batch was removed, had its token's outcome changed, or had its line and token rewritten
        to match each other (its signed header kept), is ``store_tampered``, never
        answered and never ``store_version_earlier``; first twins that match need no search, so no search bound refuses
        them; a request that differs from the answered one in one field is not its exact retry and gets no stored answer."""
        paid, repeat = claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1001, CLEAN, 20270305, "C99213", 12500)
        near = claim(2, 1001, CLEAN, 20270305, "C99213", 12600)

        def changed(batch):
            def edit(db):
                frame = db.execute("SELECT frame FROM records WHERE batch_id=?", (batch,)).fetchone()[0]
                line = (paid if batch == 1 else repeat).lines[0]
                at = frame.index(line) + len(line) - 1  # the last byte of the line's cents
                db.execute("UPDATE records SET frame=? WHERE batch_id=?", (frame[:at] + bytes([frame[at] ^ 1]) + frame[at + 1 :], batch))
            return edit

        def held_back(db):  # the paid payment's signed outcome made HOLD in its stored token
            tokens = db.execute("SELECT tokens FROM batches WHERE id=1").fetchone()[0]
            at = tokens.index(gate.lines_root(paid.lines)) + gate.DIGEST
            db.execute("UPDATE batches SET tokens=? WHERE id=1", (tokens[:at] + bytes([gate.OUTCOMES.index("HOLD") + 1]) + tokens[at + 1 :],))

        def rewritten(db):  # the paid line's cents changed in its frame and its token's lines root made to match; the header kept
            line = paid.lines[0]
            other = line[:-1] + bytes([line[-1] ^ 1])
            frame = db.execute("SELECT frame FROM records WHERE batch_id=1").fetchone()[0]
            tokens = db.execute("SELECT tokens FROM batches WHERE id=1").fetchone()[0]
            db.execute("UPDATE records SET frame=? WHERE batch_id=1", (frame.replace(line, other),))
            db.execute("UPDATE batches SET tokens=? WHERE id=1", (tokens.replace(gate.lines_root([line]), gate.lines_root([other])),))
        for name, edit in (("the paid batch's frame removed", lambda db: db.execute("DELETE FROM records WHERE batch_id=1")),
                           ("the answered batch's frame removed", lambda db: db.execute("DELETE FROM records WHERE batch_id=2")),
                           ("the paid line changed in its frame", changed(1)), ("the answered line changed in its frame", changed(2)),
                           ("the paid batch's frame made unreadable", lambda db: db.execute(  # a byte after its last request
                               "UPDATE records SET frame=? WHERE batch_id=1", (db.execute("SELECT frame FROM records WHERE batch_id=1").fetchone()[0] + b"\x00",))),
                           ("the paid batch removed", lambda db: db.executescript(
                               "DROP TRIGGER batches_void; DELETE FROM records WHERE batch_id=1; DELETE FROM batches WHERE id=1;")),
                           ("the paid payment's outcome changed", held_back),
                           ("the paid line and its token rewritten to match", rewritten)):
            with self.subTest(name):
                *_, refused = self.upgraded([[paid], [repeat]], [[repeat]], edit)
                self.assertIsInstance(refused, producer.GateProducerError)
                self.assertEqual(str(refused), "store_tampered")
        with mock.patch.object(producer, "_SEARCH", 0):  # the first twins match: answered with no search at all
            _, answered, again = self.upgraded([[paid], [repeat]], [[repeat]])
        self.assertEqual(again, answered)
        _, answered, fresh = self.upgraded([[paid], [repeat]], [[near]])
        self.assertNotIsInstance(fresh, Exception)
        self.assertNotEqual(fresh[2], answered[2])  # decided again, not the stored answer
        self.assertNotIn("ANSWERED", [o for _, _, o, _ in fresh[0]])

    def test_a_rebuilt_list_is_only_the_one_its_root_signs_and_is_stored_once_found(self) -> None:
        """An earlier paid line made to look the same as the answered one (pay-5's, first in store order) is a twin the answer
        did not name: the first twins do not have the signed root, so the other choices are tried, and only the answered list
        is given; past the search bound, or with the answered twin hidden, a store whose checks pass refuses
        ``store_version_earlier``.  A list once rebuilt is stored, so the next exact retry reads it and rebuilds nothing."""
        other, paid = claim(5, 1001, CLEAN, 20270301, "C99215", 5000), claim(1, 1001, CLEAN, 20270305, "C99213", 12500)
        repeat = claim(2, 1001, CLEAN, 20270305, "C99213", 12500)
        real, same = producer._twin_key, producer._twin_key(paid.lines[0])[1]

        def looks(*hidden):  # pay-5's line keyed as the answered line's; each hidden line keyed as no other
            def key(line):
                line_id, k = real(line)
                return line_id, same if line_id == "L5" else k + b"!" if line_id in hidden else k
            return mock.patch.object(producer, "_twin_key", key)
        with looks():
            five, _, answered, again = self.upgraded([[other], [paid], [repeat]], [[repeat]])
        self.assertEqual(five[0], [("pay-5", 0, "ALLOW", ())])  # paid, so its line is a candidate
        self.assertEqual(answered[2][0][2], ((("L2", fx.PROGRAM, "pay-1", "L1"),),))
        self.assertEqual(again, answered)
        for name, patches in (("past the search bound", (looks(), mock.patch.object(producer, "_SEARCH", 0))),
                              ("the answered twin hidden", (looks("L1"),))):
            with self.subTest(name), contextlib.ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                *_, refused = self.upgraded([[other], [paid], [repeat]], [[repeat]])
                self.assertEqual((type(refused), str(refused)), (producer.GateProducerError, "store_version_earlier"))
        with mock.patch.object(producer.ShardProducer, "_rebuilt", autospec=True, side_effect=producer.ShardProducer._rebuilt) as rebuilt:
            _, answered, again, twice = self.upgraded([[paid], [repeat]], [[repeat], [repeat]])
        self.assertEqual((again, twice, rebuilt.call_count), (answered, answered, 1))

    def test_a_claim_no_grant_entry_covers_holds_each_line_for_scope_and_never_vanishes(self) -> None:
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            sent = [claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1002, CLEAN, 20270306, "C99214", 9800, 1)]
            try:  # the grant covers SDP only, not FFS_CLAIM
                rows, groups, _ = ffs.decide_claims(sent, g.HEAD, host, shards, {k: Path(tmp) / f"idx{k}" for k in shards},
                                                    au.grant([(fx.PROGRAM, 1 << 3, 3, 0)]), g.KEYS, fx.PROGRAM, fx.NOW)
            finally:
                host[1].close()
        self.assertEqual((rows, groups), ([("pay-1", 0, "HOLD", ("SCOPE",)), ("pay-2", 0, "HOLD", ("SCOPE",))], {("HOLD", ("SCOPE",)): (2, 22300)}))


    def test_a_resend_under_a_new_covering_grant_is_decided_afresh_and_the_same_grant_again_returns_those_tokens(self) -> None:
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        real, commits = decider.commit, []
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            flats, sent = {k: Path(tmp) / f"idx{k}" for k in shards}, [claim(1, 1001, CLEAN, 20270305, "C99213", 12500)]
            run = lambda grant: ffs.decide_claims(sent, g.HEAD, host, shards, flats, grant, g.KEYS, fx.PROGRAM, fx.NOW)  # noqa: E731
            try:
                with mock.patch.object(decider, "commit", lambda *a, **k: commits.append(1) or real(*a, **k)):
                    held, paid = run(au.grant([(fx.PROGRAM, 1 << 3, 3, 0)])), run(g.GRANT)  # the grant covered SDP only, then FFS_CLAIM
                    again = run(g.GRANT)
            finally:
                host[1].close()
        self.assertEqual(([(p, o, w) for p, _, o, w in held[0]], [(p, o, w) for p, _, o, w in paid[0]]),
                         ([("pay-1", "HOLD", ("SCOPE",))], [("pay-1", "ALLOW", ())]))
        self.assertEqual((len(commits), again[0], again[2]), (2, [("pay-1", 0, "ALLOW", ())], paid[2]))  # no third commit

    def test_a_resend_with_a_signed_bypass_is_decided_afresh_and_the_same_bypass_again_returns_those_tokens(self) -> None:
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        a, b = claim(1, 1001, CLEAN, 20270305, "C99213", 12500), claim(2, 1001, "1999999984", 20270305, "C99213", 12500)
        b = dataclasses.replace(b, lines=(gate.encode_line("FFS_CLAIM", "L2", b.member_key, "1999999984", CLEAN, 20270305, "C99213", 1, 12500),))  # a near duplicate of a: another payee
        bypass = au.bypass(fx.PROGRAM, "pay-2", au.digest(gate.encode_decide_request(b)), 1 << decider.REASON_IDX["FFS_NEAR_DUPLICATE"])
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            flats = {k: Path(tmp) / f"idx{k}" for k in shards}
            try:
                ffs.decide_claims([a], g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)
                held, _, _ = ffs.decide_claims([b], g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW)
                send = lambda: decider.decide(g.HEAD, g.HEAD[0], shards[0], [b], flats[0], host[1], g.GRANT, g.KEYS, host[0],  # noqa: E731
                                              bypasses=(bypass,), seal=(fx.PROGRAM, fx.NOW))
                released = send()
                decider.commit(shards[0], fx.PROGRAM, released, fx.NOW, host[0])
                again = send()
            finally:
                host[1].close()
        self.assertEqual([(o, w) for _, _, o, w in held], [("HUMAN_REVIEW", ("FFS_NEAR_DUPLICATE",))])
        self.assertEqual(([(y.payment_id, y.outcome) for y in released.pays], bool(again.sealed)), ([("pay-2", "ALLOW")], True))  # the line keeps its finding


if __name__ == "__main__":
    unittest.main()
