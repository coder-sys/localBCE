"""837 reader on synthetic files: professional and institutional lines, replacement and void kept unapplied, quarantine at the claim or line."""

import gc
import math
import random
import string
import time
import tracemalloc
import unittest
from types import SimpleNamespace
from unittest import mock

from app import right_rail_x12_837 as r837
from tests._time_bound import timed
from tests.test_x12 import file_of


def head(npi="1999999984", sub="S00000001"):
    return ["BHT*0019*00*1*20260102*0930*CH", "HL*1**20*1", f"NM1*85*2*SYNTHETIC CLINIC*****XX*{npi}" if npi else "NM1*85*2*SYNTHETIC CLINIC",
            "HL*2*1*22*0", "SBR*P*18", f"NM1*IL*1*DOE*JANE****MI*{sub}"]


def claim(cid, lines=2, *, freq="1", ref="", total=None, kind="P", charge="10.00", dx="ABK:E119*ABF:I10", extra=()):
    total = total or f"{lines * 10}.00"
    segs = [f"CLM*{cid}*{total}***{'11' if kind == 'P' else '13'}:{'B' if kind == 'P' else 'A'}:{freq}*Y*A*Y*Y"]
    if ref:
        segs.append(f"REF*F8*{ref}")
    segs.append(f"HI*{dx}")
    for n in range(1, lines + 1):
        segs.append(f"LX*{n}")
        segs.append(f"SV1*HC:99213:25:GT*{charge}*UN*1.5***1" if kind == "P" else f"SV2*045{n}*HC:99285*{charge}*UN*1")
        segs.append(f"DTP*472*D8*202601{n:02d}")
    return segs + list(extra)


class Reader837Tests(unittest.TestCase):
    def read(self, *claims, npi="1999999984", **kwargs):
        data = file_of([head(npi) + [s for c in claims for s in c]], kind="837", **kwargs)
        return data, r837.read_837(data)

    def causes(self, got):
        return [(q.unit, q.cause) for q in got.quarantines]

    def test_clean_professional_claim(self):
        data, got = self.read(claim("C1"))
        self.assertEqual((got.refused, got.quarantines), ("", ()))
        a, b = got.rows
        self.assertEqual((a.claim_id, a.line_number, a.form, a.billing_npi, a.subscriber_id, a.patient_id), ("C1", "1", "P", "1999999984", "S00000001", ""))
        self.assertEqual((a.total_charge_cents, a.line_charge_cents, a.units_milli), (2000, 1000, 1500))
        self.assertEqual((a.facility_code, a.frequency_code, a.original_claim_ref), ("11", "1", ""))
        self.assertEqual((a.diagnoses, a.procedure_qualifier, a.procedure, a.modifiers, a.revenue_code), ((("ABK", "E119"), ("ABF", "I10")), "HC", "99213", ("25", "GT"), ""))
        self.assertEqual((a.service_begin, a.service_end, b.service_begin), ("2026-01-01", "2026-01-01", "2026-01-02"))
        self.assertEqual(a.file_at, "2026-01-02T09:30:00")
        self.assertEqual(a.file_sha3_512, r837.x12.parse(data).sha3_512)
        self.assertEqual([data[o:o + 3] for o in a.offsets], [b"CLM", b"NM1", b"NM1", b"HI*", b"LX*", b"SV1", b"DTP"])

    def test_institutional_claim(self):
        _, got = self.read(claim("I1", 1, kind="I"))
        (row,) = got.rows
        self.assertEqual((row.form, row.revenue_code, row.procedure, row.facility_code, row.units_milli, row.line_charge_cents), ("I", "0451", "99285", "13", 1000, 1000))

    def test_void_and_replacement_keep_the_original_reference_and_are_not_applied(self):
        _, got = self.read(claim("C1"), claim("C2", freq="8", ref="C1"), claim("C3", freq="7", ref="C1"), claim("C4", freq="7"))
        self.assertEqual([(r.claim_id, r.frequency_code, r.original_claim_ref) for r in got.rows if r.line_number == "1"],
                         [("C1", "1", ""), ("C2", "8", "C1"), ("C3", "7", "C1")])
        self.assertEqual(self.causes(got), [("loop", "missing_original_ref")])
        self.assertEqual(len(got.rows), 6)

    def test_bad_line_and_claim_amounts_are_quarantined_at_their_unit(self):
        _, got = self.read(claim("C1", charge="1,000.00"), claim("C2", total="x"), claim("C3"))
        self.assertEqual([r.claim_id for r in got.rows], ["C3", "C3"])
        self.assertEqual(self.causes(got), [("loop", "bad_line_charge")] * 2 + [("loop", "no_service_lines"), ("loop", "bad_total_charge")])
        mixed = claim("C4")
        mixed[6] = "SV1*HC:99213*1.234.5*UN*1"
        _, got = self.read(mixed)
        self.assertEqual(([r.line_number for r in got.rows], self.causes(got)), (["1"], [("loop", "bad_line_charge")]))

    def test_claim_faults_do_not_stop_the_file(self):
        _, got = self.read(claim("C1"), npi="")
        self.assertEqual((got.rows, self.causes(got)), ((), [("loop", "no_billing_npi")]))
        _, got = self.read(claim("C1", extra=["ZZZ*1"]), ["CLM**10.00***11:B:1"], ["CLM*C9*10.00***11:B:1", "HI*ABK:E119"])
        self.assertEqual(len(got.rows), 2)
        self.assertEqual(self.causes(got), [("segment", "unknown_segment"), ("loop", "no_claim_id"), ("loop", "no_service_lines")])
        _, got = self.read(claim("C1", extra=["SV1*HC:1*5.00", "LX*3", "SV1*HC:1*5.00*UN*1", "DTP*472*D8*20260230"]))
        self.assertEqual([c for _, c in self.causes(got)], ["repeated_segment", "bad_date", "bad_service_date"])

    def test_subscriber_and_billing_follow_the_hierarchy(self):
        body = head() + claim("C1", 1) + ["HL*3*1*22*0", "SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S00000002", "HL*4*3*23*0", "NM1*QC*1*ROE*KID****MI*D00000003"] + claim("C2", 1)
        got = r837.read_837(file_of([body], kind="837"))
        self.assertEqual([(r.claim_id, r.subscriber_id, r.patient_id) for r in got.rows], [("C1", "S00000001", ""), ("C2", "S00000002", "D00000003")])

    def test_the_rendering_provider_is_the_lines_else_the_claims_else_the_billing_provider(self):
        named = claim("C1", 3)  # CLM HI, then LX SV1 DTP per line: 2310B after HI, 2420A after line 2's DTP
        named[2:2] = ["NM1*82*1*SMITH*ANN****XX*1234567893"]
        named[9:9] = ["NM1*82*1*ROE*RAY****XX*1003000126"]
        unnamed, no_npi, line_no_npi = claim("C2", 1), claim("C3", 1), claim("C4", 2)
        no_npi[2:2] = ["NM1*82*1*SMITH*ANN"]
        line_no_npi[5:5] = ["NM1*82*1*ROE*RAY****XX*"]
        data, got = self.read(named, unnamed, no_npi, line_no_npi)
        self.assertEqual([(r.claim_id, r.line_number, r.rendering_npi) for r in got.rows],
                         [("C1", "1", "1234567893"), ("C1", "2", "1003000126"), ("C1", "3", "1234567893"), ("C2", "1", "1999999984"), ("C4", "2", "1999999984")])
        self.assertEqual(self.causes(got), [("loop", "no_rendering_npi")] * 2)
        offsets = got.rows[1].offsets
        self.assertEqual([data[o:o + 3] for o in offsets], [b"CLM", b"NM1", b"NM1", b"HI*", b"NM1", b"LX*", b"SV1", b"DTP", b"NM1"])
        self.assertEqual({data[offsets[i]:offsets[i] + 6] for i in (4, 8)}, {b"NM1*82"})

    def test_a_lost_hierarchy_level_never_leaves_a_claim_on_the_previous_member(self):
        dropped = ["H?*3*1*22*0", "SBR*P*18", "N?*IL*1*ROE*JOHN****MI*S00000002", "HL*4*3*23*0", "NM1*QC*1*ROE*KID****MI*D00000003"]
        got = r837.read_837(file_of([head() + claim("C1", 1) + dropped + claim("C2", 1)], kind="837"))
        self.assertEqual([r.claim_id for r in got.rows], ["C1"])
        self.assertEqual([q.cause for q in got.quarantines], ["bad_segment_id", "bad_segment_id", "header_without_hl", "bad_hl", "no_billing_npi"])  # the SBR met with C1 open closes it
        for bad_hl in ("HL*3*1*99*0", "HL*3*9*22*0", "HL*2*1*22*0", "HL*x*1*22*0"):
            got = r837.read_837(file_of([head() + claim("C1", 1) + [bad_hl, "SBR*P*18"] + claim("C2", 1)], kind="837"))
            self.assertEqual(([r.claim_id for r in got.rows], [q.cause for q in got.quarantines]), (["C1"], ["bad_hl", "no_billing_npi"]), bad_hl)

    def test_other_payer_loops_belong_to_the_claim_and_a_header_after_a_line_is_a_fault(self):
        cob = ["SBR*S*01", "NM1*IL*1*ROE*JOHN****MI*Z0001", "NM1*PR*2*OTHER INSURER*****PI*99999"]
        first, second = claim("C1", 1), claim("C2", 1)
        first[1:1], second[1:1] = cob, cob
        _, got = self.read(first, second)  # two claims under one HL, each with other-payer loops
        self.assertEqual((got.refused, got.quarantines, [(r.claim_id, r.subscriber_id) for r in got.rows]), ("", (), [("C1", "S00000001"), ("C2", "S00000001")]))
        for seg in ("SBR*S*01", "NM1*IL*1*ROE*JOHN****MI*Z0001", "NM1*QC*1*ROE*KID****MI*D1", "PAT*19", "NM1*85*2*OTHER CLINIC*****XX*1999999984"):
            c = claim("C1", 1)
            c.append(seg)  # after the first line
            _, got = self.read(c, claim("C2", 1))
            self.assertIn("header_without_hl", [q.cause for q in got.quarantines], seg)
        for seg in ("PAT*19", "NM1*85*2*OTHER CLINIC*****XX*1999999984"):
            c = claim("C1", 1)
            c[1:1] = [seg]  # before the first LX, still not the claim's
            _, got = self.read(c)
            self.assertIn("header_without_hl", [q.cause for q in got.quarantines], seg)

    def test_after_a_claims_other_payer_subscriber_every_name_loop_is_that_loops_and_a_patient_name_is_never_one(self):
        loop = ["SBR*S*01", "NM1*IL*1*ROE*JOHN****MI*Z0001", "NM1*PR*2*OTHER INSURER*****PI*99999", "NM1*82*1*ROE*RAY****XX*1003000126",
                "NM1*85*2*OTHER CLINIC*****XX*1234567893", "NM1*DN*1*DOC*DAN", "NM1*77*2*SOME PLACE"]  # 2320 and its 2330 loops, before the first LX
        c = claim("C1", 1)
        c[2:2] = loop
        _, got = self.read(c)
        self.assertEqual((got.quarantines, [(r.rendering_npi, r.names[0]) for r in got.rows]), ((), [("1999999984", r837.name_tokens("SYNTHETIC CLINIC"))]))  # not the claim's rendering or billing provider
        qc = "NM1*QC*1*ROE*KID****MI*D1"  # 2330 has no patient loop: before the first SBR, in an other-payer loop, or after a line, it is a header with no HL
        for at, put in ((1, [qc]), (2, ["SBR*S*01", qc]), (5, [qc])):
            c = claim("C1", 1)
            c[at:at] = put
            _, got = self.read(c)
            self.assertIn("header_without_hl", [q.cause for q in got.quarantines], (at, put))

    def test_one_bad_hl_loses_its_own_claims_and_its_children_but_not_the_later_ones(self):
        c = [claim(f"C{i}", 1) for i in range(1, 6)]
        body = (head() + c[0] + ["HL*3*1*99*0", "SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S2"] + c[1] + ["HL*4*1*22*0", "SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S3"] + c[2]
                + ["HL*5*3*23*0", "NM1*QC*1*ROE*KID****MI*D4"] + c[3] + ["HL*6*1*22*0", "SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S5"] + c[4])
        got = r837.read_837(file_of([body], kind="837"))
        self.assertEqual(sorted({r.claim_id for r in got.rows}), ["C1", "C3", "C5"])
        self.assertEqual(sorted(self.causes(got)), [("loop", "no_billing_npi")] * 2 + [("segment", "bad_hl")] * 2)  # HL 3 and its child HL 5; the claims under them
        self.assertEqual([(r.claim_id, r.subscriber_id, r.billing_npi) for r in got.rows if r.claim_id != "C1"], [("C3", "S3", "1999999984"), ("C5", "S5", "1999999984")])

    def test_a_garbled_hl_number_loses_its_own_claim_only_and_the_next_hl_is_judged_by_the_number_it_should_follow(self):
        """HL*5 for the third HL and a non-digit number hold their own claim; the HL*4 after each is read (it was held for the garbled one)."""
        for garbled in ("HL*5*1*22*0", "HL*x*1*22*0", "HL*" + "9" * 13 + "*1*22*0"):
            body = (head() + claim("C1", 1) + [garbled, "SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S2"] + claim("C2", 1)
                    + ["HL*4*1*22*0", "SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S3"] + claim("C3", 1))
            got = r837.read_837(file_of([body], kind="837"))
            self.assertEqual(([(r.claim_id, r.subscriber_id) for r in got.rows], sorted(self.causes(got))),
                             ([("C1", "S00000001"), ("C3", "S3")], [("loop", "no_billing_npi"), ("segment", "bad_hl")]), garbled)

    def test_a_repeated_hl_number_is_held_and_the_later_hls_are_still_read(self):
        sub = ["SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S"]
        body = (head() + claim("C1", 1) + ["HL*2*1*22*0", sub[0], sub[1] + "2"] + claim("C2", 1) + ["HL*3*1*22*0", sub[0], sub[1] + "3"] + claim("C3", 1)
                + ["HL*4*1*22*0", sub[0], sub[1] + "4"] + claim("C4", 1))
        got = r837.read_837(file_of([body], kind="837"))
        self.assertEqual(([(r.claim_id, r.subscriber_id) for r in got.rows], sorted(self.causes(got))),
                         ([("C1", "S00000001"), ("C3", "S3"), ("C4", "S4")], [("loop", "no_billing_npi"), ("segment", "bad_hl")]))

    def test_an_hl_number_of_thousands_of_digits_is_a_bad_hl_never_a_crash(self):
        for number in ("9" * 5000, "1" * 4301, "0" * 5000):
            body = head() + claim("C1", 1) + [f"HL*{number}*1*22*0", "SBR*P*18", "NM1*IL*1*ROE*JOHN****MI*S2"] + claim("C2", 1)
            got = r837.read_837(file_of([body], kind="837"))
            self.assertEqual(([r.claim_id for r in got.rows], sorted(self.causes(got))), (["C1"], [("loop", "no_billing_npi"), ("segment", "bad_hl")]), len(number))

    def test_repeated_claim_ids_are_reported_with_every_row_kept(self):
        _, got = self.read(claim("C1", 1), claim("C2", 1), claim("C1", 1))
        self.assertEqual((len(got.rows), [(c, len(o)) for c, o in got.duplicates]), (3, [("C1", 2)]))

    def test_claim_total_against_its_lines_is_a_finding_only(self):
        _, got = self.read(claim("C1", 2, total="25.00"), claim("C2", 2), claim("C3", 2, charge="x"))
        self.assertEqual([(f.cause, f.detail) for f in got.findings], [("total_mismatch", "CLM02=2500 lines=2000")])
        self.assertEqual([r.total_charge_cents for r in got.rows], [2500, 2500, 2000, 2000])

    def test_service_date_range_truncation_and_envelope(self):
        c = claim("C1", 1)
        c[-1] = "DTP*472*RD8*20260105-20260107"
        data, got = self.read(c)
        self.assertEqual((got.rows[0].service_begin, got.rows[0].service_end), ("2026-01-05", "2026-01-07"))
        cut = r837.read_837(data[:data.index(b"SV1") + 5])
        self.assertEqual((cut.rows, [q.cause for q in cut.quarantines][0]), ((), "unterminated_segment"))
        _, got = self.read(claim("C1"), se_count=4)
        self.assertEqual((got.rows, self.causes(got)), ((), [("set", "se_count_mismatch")]))

    def test_two_hundred_thousand_lines_in_linear_time_and_bounded_memory(self):
        def build(claims):
            return file_of([head() + [s for i in range(claims) for s in claim(f"C{i:06d}", 5)]], kind="837")
        small, big = build(4000), build(40000)
        t_small, _ = timed(lambda: r837.read_837(small), 3)
        t_big, _ = timed(lambda: r837.read_837(big), t_small * 10)
        tracemalloc.start()
        got = r837.read_837(big)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        print(f"x12 837 200k lines: {len(big)} bytes, {t_small:.2f}s for 20k, {t_big:.2f}s for 200k, traced peak {peak} bytes")
        self.assertEqual((len(got.rows), got.quarantines), (200000, ()))
        self.assertLess(t_big, t_small * 10 * 3 + 1.0)
        self.assertLess(peak / len(big), PEAK_PER_BYTE)
        self.assertLess(peak, 1024 * 1024 * 1024)


CPU_TICK_RUN = 0.5  # the clock Windows keeps for a thread moves in steps of about 16 ms, so a sample is repeated until it holds half a second of CPU: the step is then a few percent of it


def cpu_timed(call, expected: float = 3.0):
    """The CPU seconds one ``call()`` takes the timed thread (same wall bound as ``timed``, for one call): a busy machine takes turns away from the run but adds nothing to its CPU time."""
    def counted():
        start, calls = time.thread_time(), 0
        while True:
            call()
            calls += 1
            if time.thread_time() - start >= CPU_TICK_RUN:
                return (time.thread_time() - start) / calls
    return timed(counted, expected)[1]


class HostileFileTimeTests(unittest.TestCase):
    """A file or list written to be slow costs time in proportion to its size: the time per unit at 10 times the size (below the smaller size the machine cache hides it) is at most 1.3 times
    the time per unit at the smaller one.  The seconds are printed with an [m] mark."""
    SMALL, BIG, LIMIT = 30000, 300000, 1.3

    def per_unit(self, label, build, run, sorted_feed=False, small=None, hot=()):
        small = small or self.SMALL  # the big size is ten times the small
        big = small * (self.BIG // self.SMALL)
        made = {n: build(n) for n in (small, big)}
        times = {}
        for _ in range(5):  # the two sizes take turns, so a slow stretch of the machine falls on both, and the least of five runs at each size drops it
            for n in (small, big):
                gc.collect()
                gc.disable()  # the collector's cost grows with the heap, whatever the code does
                try:
                    took = cpu_timed(lambda: run(made[n]), 3 if n == small else times[small] * 3)  # bound 30 times the small time: linear code takes 10 to 13 times, a squared cost 100 times, so a quadratic change fails here and never runs on
                finally:
                    gc.enable()
                times[n] = took if n not in times else min(times[n], took)
        ratio = (times[big] / big) / (times[small] / small)
        if sorted_feed:  # a sort costs n log n: its per-unit time grows by log2(n), which is not a hostile file's doing
            ratio /= math.log2(big) / math.log2(small)
        print(f"[m] {label}: {small} units {times[small]:.2f}s, {big} units {times[big]:.2f}s, per-unit ratio {ratio:.2f}")
        self.assertLess(ratio, self.LIMIT, label)
        self.exact_calls(label, build, run, small, hot)

    def exact_calls(self, label, build, run, small, hot):
        from app import right_rail_gate_ffs as ffs
        reads = {n: build(n) for n in (small // 10, small)}
        for name in hot:  # exact counts, which a busy or a quiet machine does not move, at sizes a tenth of the timed ones: a function called per claim, or per fault to find its claims, is called as often per unit at ten times the size
            owner, _, attr = name.rpartition(".")
            owner = getattr(ffs, owner) if owner else ffs
            calls = {}
            for n in (small // 10, small):
                count, inner = [0], getattr(owner, attr)

                def counting(*a, _inner=inner, _count=count, **k):
                    _count[0] += 1
                    return _inner(*a, **k)
                with mock.patch.object(owner, attr, counting):
                    run(reads[n])
                calls[n] = count[0]
            self.assertGreater(calls[small // 10], 0, name)
            self.assertEqual(calls[small], calls[small // 10] * 10, f"{label}: calls of {name}")

    def held(self, read):
        from app import right_rail_gate_ffs as ffs
        from app import right_rail_reader_leie as leie
        from tests import test_reader_leie as tl
        listed = leie.read_leie((tl.HEAD + tl.row(npi=tl.make_npi(1))).encode(), source="synthetic", as_of="2027-03-10")
        sent, aside = ffs.requests_of([read], "nc-dhhs", "medicaid-ffs", "2026-09", b"s", listed)
        self.assertEqual((len(sent), len(aside)), (0, len(read.claims)))

    def test_claims_each_with_one_unknown_segment_are_held_in_time_linear_in_their_number(self):
        def build(n):
            read = r837.read_837(file_of([head() + [s for i in range(n) for s in claim(f"C{i:06d}", 1, extra=["ZZZ*1"])]], kind="837"))
            self.assertEqual((len(read.rows), len(read.quarantines)), (n, n))
            return read
        self.per_unit("837 claims with one unknown segment each", build, self.held, hot=("canonical_id", "SetAside", "bisect.bisect_right"))

    def test_claims_in_sets_that_each_fail_their_count_are_held_in_time_linear_in_their_number(self):
        def build(n):
            read = r837.read_837(file_of([head() + claim(f"C{i:06d}", 1) for i in range(n)], kind="837", se_count=99))
            self.assertEqual((len(read.claims), len(read.quarantines)), (n, n))
            return read
        self.per_unit("837 claims, each in a set that fails its count", build, self.held, small=100000, hot=("SetAside", "bisect.bisect_left", "bisect.bisect_right"))  # at 30,000 the small run is 0.1 s and a pause shows as a ratio over the limit

    def test_exclusion_rows_dated_after_the_lists_day_are_held_in_time_linear_in_their_number(self):
        from app import right_rail_gate_ffs as ffs
        from app import right_rail_reader_leie as leie
        from app import right_rail_x12_834 as r834
        from tests import test_reader_leie as tl
        from tests import test_x12_834 as t834
        enrolled = r834.read_834(file_of([t834.header() + t834.member("M1")]))

        def build(n):
            return leie.read_leie((tl.HEAD + "".join(tl.row(npi=tl.make_npi(i), excl="20270401") for i in range(n))).encode(), source="synthetic", as_of="2027-03-10")

        def run(listed):
            _, left = ffs.feeds(20270311, enrolled, listed, ("2027-03-01", [(tl.make_npi(2), "2027-02-01")]), b"s")
            self.assertEqual(len(left), len(listed.rows))
        self.per_unit("exclusion rows dated after the list's day", build, run, sorted_feed=True)

    ROWS = 7000

    def whole(self, cid):
        """A claim the gate sends: whole units."""
        return [x.replace("UN*1.5", "UN*1") for x in claim(cid, 1)]

    def spoiled_rows(self, rows):
        """An exclusion list of ``rows`` people whose NPI Excel wrote as 1.23E+09: each is held by name, none has a number."""
        from app import right_rail_reader_leie as leie
        from tests import test_reader_leie as tl
        rng = random.Random(7)
        word = lambda: "".join(rng.choice(string.ascii_uppercase) for _ in range(7))  # noqa: E731
        listed = leie.read_leie((tl.HEAD + "".join(tl.row(last=word(), first=word(), npi="1.23E+09") for _ in range(rows))).encode(), source="synthetic", as_of="2027-03-10")
        self.assertEqual(len(listed.quarantined), rows)
        return listed

    def sent_whole(self, read, listed, claims):
        from app import right_rail_gate_ffs as ffs
        sent, aside = ffs.requests_of([read], "nc-dhhs", "medicaid-ffs", "2026-09", b"s", listed)
        self.assertEqual((len(sent), len(aside)), (claims, 0))

    def test_claims_checked_against_thousands_of_rows_held_by_name_cost_no_more_than_five_times_their_cost_against_one_row(self):
        """The same 3,000 claims against 7,000 rows and against one row: a check of every row for every claim would cost far more than five times."""
        rng = random.Random(8)
        named = [s for i in range(3000) for s in (lambda c, nm: c[:1] + [f"NM1*82*1*{nm}*{nm[::-1]}****XX*1999999984"] + c[1:])(
            self.whole(f"C{i:06d}"), "".join(rng.choice(string.ascii_uppercase) for _ in range(7)))]
        read = r837.read_837(file_of([head() + named], kind="837"))
        self.assertEqual((len(read.rows), len(read.quarantines)), (3000, 0))
        many, one = self.spoiled_rows(self.ROWS), self.spoiled_rows(1)
        best = {}
        for label, listed in (("one", one), ("many", many)) * 3:  # the least of a few runs each
            took = cpu_timed(lambda: self.sent_whole(read, listed, len(read.claims)), 3)
            best[label] = min(took, best.get(label, took))
        print(f"[m] 837 3000 claims: {best['one']:.2f}s against 1 row, {best['many']:.2f}s against {self.ROWS} rows")
        self.assertLess(best["many"], 5 * best["one"])  # the finder's build over the rows is in the timed call, so healthy code takes 1.6 to 2 times; every row checked for every claim takes 100 times

    def test_a_claim_name_of_many_one_letter_words_costs_time_in_proportion_to_its_words_against_thousands_of_rows_sharing_its_letters(self):
        """7,000 four-letter one-word rows over 25 initial letters, each with a first name whose initial (Z) is in no claim word: every row's word
        is a run of consecutive claim words, so a search that tries each word against each row costs the square of the words.  Four times the words
        cost at most 1.5 times as much per word and less than four times in all."""
        from app import right_rail_gate_ffs as ffs
        from app.right_rail_reader_lines import name_tokens
        letters = string.ascii_uppercase[:25]
        rng = random.Random(5)
        rows = [(n, SimpleNamespace(last_name="".join(rng.choice(letters) for _ in range(4)), first_name="ZED", business_name="")) for n in range(7000)]
        best = {}
        for words in (10000, 40000):
            names = name_tokens(" ".join(rng.choice(letters) for _ in range(words)))
            for _ in range(3):  # the least of a few runs: a pause in the machine is not the code's cost
                took = cpu_timed(lambda: ffs._row_finder(rows)(names), 3)  # 30 s bound: linear code takes under a second, the squared cost 6 s at 10,000 words and 100 s at 40,000, and fails there and never runs on
                best[words] = min(took, best.get(words, took))
        print(f"[m] one-letter-word claim name against 7000 rows: 10000 words {best[10000]:.2f}s, 40000 words {best[40000]:.2f}s")
        self.assertLess(best[40000] / 40000, 1.5 * best[10000] / 10000)
        self.assertLess(best[40000], 4 * best[10000])

    def test_one_claim_with_a_name_of_a_million_bytes_of_one_letter_words_is_decided_in_time_linear_in_its_words(self):
        from tests import test_reader_leie as tl
        from app import right_rail_reader_leie as leie
        rows = ("ZZZZ", "JO"), ("ABCD", "ZED"), ("PPPP", "")  # none is in the claim's name: a row of one word with a first initial that is nowhere, one that is only in the run's own words
        listed = leie.read_leie((tl.HEAD + "".join(tl.row(last=a, first=b, npi="1.23E+09") for a, b in rows)).encode(), source="synthetic", as_of="2027-03-10")

        def build(words):
            name = " ".join("ABCDEFGHIJKLMNO"[i % 15] for i in range(words))
            c = self.whole("C1")
            read = r837.read_837(file_of([head() + c[:1] + [f"NM1*82*1*{name}*****XX*1999999984"] + c[1:]], kind="837"))
            self.assertEqual((len(read.rows), len(read.quarantines)), (1, 0))
            return read
        self.per_unit("837 claim with one long name", build, lambda read: self.sent_whole(read, listed, 1))


PEAK_PER_BYTE = 60  # traced bytes at the peak per input byte (measured 37 and 46)


if __name__ == "__main__":
    unittest.main()
