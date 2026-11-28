"""820 reader on synthetic files: integer cents only, coverage month, quarantine at the line, never an inferred amount."""

import io
import tracemalloc
import unittest

from app import right_rail_x12_820 as r820
from tests.test_x12 import file_of


def payment(lines, *, total="300.00", trace="TRACE1", date="20260105", direction="C", plan="PLAN-A", trn="3"):
    head = [f"BPR*C*{total}*{direction}*ACH*CCP*01*000*DA*1*2**01*000*DA*1*{date}", f"TRN*{trn}*{trace}*1000000000", "N1*PR*SYNTHETIC STATE", f"N1*PE*SYNTHETIC PLAN*FI*{plan}"]
    return head + [s for line in lines for s in line]


def line(member, amount, period="20260101-20260131", name=True):
    who = [f"NM1*IL*1*DOE*JOHN****34*{member}"] if name else []
    return [f"ENT*1*2J*ZZ*{member}"] + who + [f"RMR*11*{member}**{amount}"] + ([f"DTM*582****RD8*{period}"] if period else [])


class Reader820Tests(unittest.TestCase):
    def read(self, lines, **kwargs):
        data = file_of([payment(lines, **kwargs)], kind="820")
        return data, r820.read_820(data)

    def test_cents_table(self):
        for text, want in (("0", 0), ("12", 1200), ("12.5", 1250), ("12.50", 1250), ("12.500", 1250), (".75", 75), ("-3.10", -310),
                           ("1234567890123.99", 123456789012399)):
            self.assertEqual(r820.x12.cents(text), want, text)
        for text in ("", "-", ".", "1.", "12.505", "1e2", "1,200.00", "$5", "5 ", " 5", "--5", "+5", "NaN", "1.2.3", "٣", "12.5\n"):
            self.assertIsNone(r820.x12.cents(text), text)

    def test_clean_file_lines_and_payment(self):
        data, got = self.read([line("S000001", "100.00"), line("S000002", "200.00", "20260301-20260331")])
        self.assertEqual((got.refused, got.quarantines), ("", ()))
        self.assertEqual([(l.plan, l.member_id, l.coverage_month, l.amount_cents) for l in got.lines],
                         [("PLAN-A", "S000001", "2026-01", 10000), ("PLAN-A", "S000002", "2026-03", 20000)])
        first = got.lines[0]
        self.assertEqual((first.trace, first.payment_date, first.direction, first.file_at), ("TRACE1", "2026-01-05", "C", "2026-01-02T09:30:00"))
        self.assertEqual(first.file_sha3_512, r820.x12.parse(data).sha3_512)
        self.assertEqual([data[o:o + 3] for o in first.offsets], [b"RMR", b"NM1", b"DTM"])
        self.assertTrue(all(type(l.amount_cents) is int for l in got.lines))
        (pay,) = got.payments
        self.assertEqual((pay.total_cents, pay.lines_cents, pay.lines, pay.trace, pay.plan), (30000, 30000, 2, "TRACE1", "PLAN-A"))

    def test_unparseable_amount_quarantines_that_line_only(self):
        for bad in ("", "1,000.00", "12.505", "abc", "1e3"):
            _, got = self.read([line("S000001", "100.00"), line("S000002", bad), line("S000003", "50")])
            self.assertEqual([l.member_id for l in got.lines], ["S000001", "S000003"], bad)
            self.assertEqual([(q.unit, q.cause) for q in got.quarantines], [("segment", "bad_amount")], bad)
            self.assertEqual(got.payments[0].lines_cents, 15000)  # reported beside the 300.00 the payment says

    def test_negative_amounts_stay_negative(self):
        _, got = self.read([line("S000001", "-25.00")])
        self.assertEqual(got.lines[0].amount_cents, -2500)

    def test_coverage_period_must_be_one_month_or_the_line_is_quarantined(self):
        _, got = self.read([line("S000001", "1.00", "20260101-20260228"), line("S000002", "1.00", None), line("S000003", "1.00", "20260230-20260231"),
                            line("S000004", "1.00", "20260215-20260228")])
        self.assertEqual([l.member_id for l in got.lines], ["S000004"])
        self.assertEqual([q.cause for q in got.quarantines], ["bad_report_period"] * 3)

    def test_member_conflict_and_missing_plan(self):
        conflict = line("S000001", "1.00")
        conflict[1] = "NM1*IL*1*DOE*JOHN****34*S999999"
        _, got = self.read([conflict, line("S000002", "1.00", name=False)])
        self.assertEqual([l.member_id for l in got.lines], ["S000002"])
        self.assertEqual([q.cause for q in got.quarantines], ["member_conflict"])
        _, got = self.read([line("S000001", "1.00")], plan="")
        self.assertEqual((got.lines, [q.cause for q in got.quarantines]), ((), ["no_plan"]))

    def test_bad_total_missing_header_unknown_and_envelope_faults(self):
        _, got = self.read([line("S000001", "1.00")], total="x")
        self.assertEqual((len(got.lines), got.payments[0].total_cents, [q.cause for q in got.quarantines]), (1, None, ["bad_amount"]))
        no_trn = [s for s in payment([line("S000001", "1.00")]) if not s.startswith("TRN")]
        got = r820.read_820(file_of([no_trn], kind="820"))
        self.assertEqual((len(got.lines), got.lines[0].trace, got.quarantines), (1, "", ()))
        self.assertEqual([(f.cause, f.detail) for f in got.findings][0], ("no_payment_header", "1 lines kept without a trace or payment header"))
        _, got = self.read([line("S000001", "1.00"), ["WAT*1"]])
        self.assertEqual((len(got.lines), [q.cause for q in got.quarantines]), (1, ["unknown_segment"]))
        got = r820.read_820(file_of([payment([line("S000001", "1.00")])], kind="820", se_count=1))
        self.assertEqual((got.lines, [q.cause for q in got.quarantines]), ((), ["se_count_mismatch"]))
        got = r820.read_820(file_of([payment([])], kind="834"))
        self.assertEqual([q.cause for q in got.quarantines], ["not_820"])

    def test_each_name_above_an_rmr_belongs_to_that_rmr(self):
        pair = lambda who, amount: [f"NM1*IL*1*DOE*JOHN****34*{who}", f"RMR*11*{who}**{amount}", "DTM*582****RD8*20260101-20260131"]
        _, got = self.read([pair("S000001", "1.00") + pair("S000002", "2.00")])
        self.assertEqual([(l.member_id, l.amount_cents) for l in got.lines], [("S000001", 100), ("S000002", 200)])
        _, got = self.read([["RMR*11*S000001**1.00", "DTM*582****RD8*20260101-20260131", "NM1*IL*1*DOE*JOHN****34*S000002"]])
        self.assertEqual(([q.cause for q in got.quarantines], got.lines), (["no_member", "misplaced_segment"], ()))

    def test_ent_qualifiers_and_trace_type(self):
        for qualifier, ok in (("2J*ZZ", True), ("IL*34", True), ("2J*XX", False), ("QD*34", False), ("2J*", False)):
            _, got = self.read([[f"ENT*1*{qualifier}*S000001", "RMR*11*S000001**1.00", "DTM*582****RD8*20260101-20260131"]])
            self.assertEqual((len(got.lines), [q.cause for q in got.quarantines]), (1, []) if ok else (0, ["bad_member_qualifier"]), qualifier)
        _, got = self.read([line("S000001", "1.00")], trn="1")
        self.assertEqual((len(got.lines), got.lines[0].trace, got.quarantines), (1, "", ()))
        self.assertEqual([f.cause for f in got.findings], ["bad_trace_type", "total_mismatch"])
        self.assertEqual(got.findings[0].detail, "1 lines kept without a trace or payment header")

    def test_a_single_day_report_period_is_that_day(self):
        _, got = self.read([["ENT*1*2J*ZZ*S000001", "RMR*11*S000001**1.00", "DTM*582*20260115"]])
        (one,) = got.lines
        self.assertEqual((one.coverage_month, one.period_begin, one.period_end, got.quarantines), ("2026-01", "2026-01-15", "2026-01-15", ()))
        _, got = self.read([line("S000002", "1.00")])
        self.assertEqual((got.lines[0].period_begin, got.lines[0].period_end), ("2026-01-01", "2026-01-31"))

    def test_total_against_lines_is_a_finding_and_never_changes_amounts(self):
        _, got = self.read([line("S000001", "100.00"), line("S000002", "150.00")])
        self.assertEqual([(f.cause, f.detail) for f in got.findings], [("total_mismatch", "BPR02=30000 lines=25000")])
        self.assertEqual([l.amount_cents for l in got.lines], [10000, 15000])
        _, got = self.read([line("S000001", "100.00"), line("S000002", "x")])
        self.assertEqual([f.cause for f in got.findings], ["total_unchecked"])
        _, got = self.read([line("S000001", "100.00"), line("S000002", "200.00")])
        self.assertEqual(got.findings, ())

    def test_truncated_file_and_repairs(self):
        data, clean = self.read([line("S000001", "1.00")])
        cut = r820.read_820(data[:-6])  # cut in the IEA: the set before it was closed whole by its SE, so its line is kept
        self.assertEqual(([l._replace(file_sha3_512="") for l in cut.lines], cut.refused), ([l._replace(file_sha3_512="") for l in clean.lines], ""))
        self.assertEqual([q.cause for q in cut.quarantines], ["unterminated_segment", "iea_missing"])
        cut = r820.read_820(data[:data.index(b"SE*")])
        self.assertEqual((cut.lines, cut.refused), ((), "iea_missing"))
        dirty = r820.read_820(b"\xef\xbb\xbf" + data.replace(b"~", b"~\r\n"))
        self.assertEqual(dirty.lines[0][:5], clean.lines[0][:5])
        self.assertEqual({r for r, _ in dirty.repairs}, {"bom", "whitespace"})

    def test_lines_stream_out_as_soon_as_the_header_is_seen_and_hold_only_a_fixed_number_when_it_is_late(self):
        body = payment([line("S000001", "1.00")])
        late = body[3:] + body[:2]  # the plan, the lines, then the payment header
        _, got = self.read([line("S000001", "1.00")])
        self.assertEqual([l.trace for l in got.lines], ["TRACE1"])
        got = r820.read_820(file_of([late], kind="820"))
        self.assertEqual(([l.trace for l in got.lines], got.quarantines), (["TRACE1"], ()))
        many = [line(f"S{i:06d}", "1.00") for i in range(r820._HELD + 5)]
        got = r820.read_820(file_of([payment(many)[3:]], kind="820"))
        self.assertEqual((len(got.lines), [q.cause for q in got.quarantines], got.payments), (r820._HELD, ["header_late"], ()))

    def test_a_multi_megabyte_file_streams_in_bounded_memory(self):
        class Count(r820.x12.Sink):
            lines = 0

            def add(self, ts, kind, item):
                self.lines += kind == "line"

        def peak_of(n):
            data = file_of([payment([line(f"S{i:06d}", "1.00") for i in range(n)], total=f"{n}.00")], kind="820")
            sink = Count()
            tracemalloc.start()
            self.assertEqual(r820.stream_820(io.BytesIO(data), sink), "")
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            self.assertEqual(sink.lines, n)
            return len(data), peak
        (_, small), (big_bytes, big) = peak_of(30000), peak_of(90000)
        self.assertGreater(big_bytes, 8 * 1024 * 1024)
        self.assertLess(big, 6 * 1024 * 1024)
        self.assertLess(big, small * 1.25 + 512 * 1024)


if __name__ == "__main__":
    unittest.main()
