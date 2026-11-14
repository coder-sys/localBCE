"""Fee-for-service claim lines decided by the real gate engine (synthetic members, claims and providers; non-PHI)."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_deployment_slots as slots
from app import right_rail_gate_ffs as ffs
from app import right_rail_reader_leie as leie
from app import right_rail_x12_834 as r834
from app import right_rail_x12_837 as r837
from conformance import gate_rules_v1_ref as ref
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx
from tests import test_reader_leie as tl
from tests import test_right_rail_deployment_slots as ts
from tests import test_x12_834 as t834
from tests import test_x12_837 as t837

ROOT = Path(__file__).resolve().parents[1]

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
        for data in (t837.file_of([first, t834.header() + ["ZZZ*X"] + t834.member("M2")]), t837.file_of([first + nameless])):
            (_, sent), left = ffs.feeds(20260105, r834.read_834(data), leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-01-01"),
                                        ("2026-01-01", []), b"s")
            self.assertEqual((left, sent[0], sent[3]), ((), (bytes(77), b""), (bytes(77), b"")))  # unknown: every line to review, M1 not held for it

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
        self.assertEqual([(a.id, a.cause) for a in left], [("0" + DEAD, "bad_npi"), (CLEAN + " ", "bad_npi"), ("NONE", "no_npi"), ("WRONG", "no_npi")])
        self.assertEqual((sent[1], sent[2]), (decider.feed("pdeath", 20260101, [(ffs.ident(DEAD.encode()), 20251201)]),
                                              decider.feed("excl", 20260101, [(ffs.ident(EXCLUDED.encode()), 20250115, 99991231)])))


def claims_file(*claims: list[str], sub: str = "S00000001", npi: str = "1999999984") -> r837.Read837:
    """An 837 of ``claims`` (test_x12_837.claim, whole units) for subscriber ``sub`` billed by ``npi``."""
    body = t837.head(npi, sub) + [s.replace("UN*1.5", "UN*1") for c in claims for s in c]
    return r837.read_837(t837.file_of([body], kind="837"))


class RequestTests(unittest.TestCase):
    SECRET = b"synthetic tenant secret, 32 b.."

    def requests(self, read: r837.Read837):
        return ffs.requests_of([read], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET)

    def test_one_request_per_claim_with_ids_that_a_resubmission_repeats(self) -> None:
        dated = t837.claim("C5", 1)
        dated[-1] = "DTP*472*RD8*20260105-20260107"
        dependent = t837.head() + ["HL*3*2*23*0", "NM1*QC*1*DOE*KID****MI*D1"] + t837.claim("C6", 1)
        half = t837.claim("C3", 1)
        half[3] = "SV1*HC:99213*10.00*UN*0.5"
        read = claims_file(t837.claim("C1", 2), t837.claim("C2", freq="7", ref="C1"), half, dated, dependent[6:])
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
                 "C3": (4, ["SV1*HC:99214*10.00*UN*1"]), "C4": (2, ["REF*F8*OTHER"]), "C5": (5, ["ZZZ*1"])}  # C4: after its REF*F8*FIRST
        claims = [(c := t837.claim(cid, 1, ref="FIRST" if cid == "C4" else ""))[:at] + segs + c[at:] for cid, (at, segs) in twice.items()]
        sent, aside = self.requests(claims_file(*claims, t837.claim("C6", 1)))
        self.assertEqual(([r.payment_id for r in sent], [(a.id, a.cause) for a in aside]),
                         ([ffs.canonical_id("C", "1999999984", "C6")], [(c, "partial") for c in twice]))

    def test_a_claim_sent_twice_is_one_claim_and_two_claims_under_one_id_are_both_held(self) -> None:
        sent, aside = self.requests(claims_file(t837.claim("C1", 1), t837.claim("C2", 1), t837.claim("C1", 1), t837.claim("C2", 2), t837.claim("C3", 1)))
        self.assertEqual([r.payment_id for r in sent], [ffs.canonical_id("C", "1999999984", c) for c in ("C1", "C3")])
        self.assertEqual([(a.id, a.cause, a.cents) for a in aside],
                         [("C1", "retry", 1000), ("C2", "payment_id_conflict", 1000), ("C2", "payment_id_conflict", 2000)])

    def test_a_copy_of_a_claim_set_aside_keeps_its_cause_and_a_zero_unit_line_is_set_aside(self) -> None:
        zero = t837.claim("C1", 1)
        zero[3] = "SV1*HC:99213*10.00*UN*0"
        sent, aside = self.requests(claims_file(zero, t837.claim("C2", freq="7", ref="C0"), zero, t837.claim("C2", freq="7", ref="C0")))
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
        sent, aside = ffs.requests_of([read, other, read], fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET)
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
        prod = lambda n: SimpleNamespace(_cert=gate.encode_key_cert(fx.TENANT, fx.EPOCH, n, bytes(gate.ML_DSA_87_PUBLIC_KEY)))  # noqa: E731
        for shards in ({0: prod(2)}, {0: prod(1), 1: prod(2)}, {1: prod(1)}, {}):  # a subset, two counts, another number, none
            with self.assertRaises(decider.GateDecideError) as refused:
                ffs.decide_claims(sent, None, (SimpleNamespace(tenant=fx.TENANT), None), shards, {}, b"", None, fx.PROGRAM, 0)
            self.assertEqual((refused.exception.args[0], refused.exception.sealed), ("tenant_shards", []), shards)


DEAD = "1588667638"  # a 10-digit NPI that dies 2025-12-01


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
                                             t837.head(CLEAN, "M1") + t837.claim("C6", 1, freq="8", ref="C1"), sent(CLEAN, "M4", "C7", 5),
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
        sent_, aside = ffs.requests_of([claims], fx.TENANT, fx.PROGRAM, fx.PERIOD, secret)
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
        self.assertEqual(sum(len(t) for _, t in sealed), 6)

    def test_an_834_fault_holds_its_member_and_a_voided_set_sends_every_line_to_review(self) -> None:
        """A coverage end or a death on no calendar day sets its member aside, so the member's claims hold, never paid as covered
        with no end or alive; a voided set of the file may hold a cancellation, so the enrollment is unknown: every line is reviewed."""
        def claims(*pairs: tuple[str, str]) -> tuple:
            body = []
            for sub, cid in pairs:
                c = t837.claim(cid, 1)
                c[-1] = "DTP*472*D8*20270305"
                body.append(t837.head(CLEAN, sub) + [s.replace("UN*1.5", "UN*1") for s in c])
            return ffs.requests_of([r837.read_837(t837.file_of(body, kind="837"))], fx.TENANT, fx.PROGRAM, fx.PERIOD, secret)[0]
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
        self.assertEqual((failed.exception.args[0], [len(t) for _, t in failed.exception.sealed]), ("rules_refused", [1]))
        self.assertEqual([len(t) for _, t in sealed], [1, 1])  # the sealed batch is given again, not decided again: no second payment
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
        self.assertEqual([len(t) for _, t in sealed], [1])

    def resend(self, first: list, second: list) -> tuple:
        """The rows, groups and sealed batches of ``first`` and then of ``second``, on one store."""
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            flats = {k: Path(tmp) / f"idx{k}" for k in shards}
            try:
                return tuple(ffs.decide_claims(s, g.HEAD, host, shards, flats, g.GRANT, g.KEYS, fx.PROGRAM, fx.NOW) for s in (first, second))
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
        bypass = au.bypass(fx.PROGRAM, "pay-2", au.digest(gate.encode_decide_request(b)), 1 << decider.REASONS.index("FFS_NEAR_DUPLICATE"))
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
