"""837 reader on synthetic files: professional and institutional lines, replacement and void kept unapplied, quarantine at the claim or line."""

import time
import tracemalloc
import unittest

from app import right_rail_x12_837 as r837
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
        self.assertEqual([q.cause for q in got.quarantines], ["bad_segment_id", "bad_segment_id", "bad_hl", "no_billing_npi"])
        for bad_hl in ("HL*3*1*99*0", "HL*3*9*22*0", "HL*2*1*22*0", "HL*x*1*22*0"):
            got = r837.read_837(file_of([head() + claim("C1", 1) + [bad_hl, "SBR*P*18"] + claim("C2", 1)], kind="837"))
            self.assertEqual(([r.claim_id for r in got.rows], [q.cause for q in got.quarantines]), (["C1"], ["bad_hl", "no_billing_npi"]), bad_hl)

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
        t0 = time.perf_counter()
        r837.read_837(small)
        t_small = time.perf_counter() - t0
        t0 = time.perf_counter()
        r837.read_837(big)
        t_big = time.perf_counter() - t0
        tracemalloc.start()
        got = r837.read_837(big)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        print(f"x12 837 200k lines: {len(big)} bytes, {t_small:.2f}s for 20k, {t_big:.2f}s for 200k, traced peak {peak} bytes")
        self.assertEqual((len(got.rows), got.quarantines), (200000, ()))
        self.assertLess(t_big, t_small * 10 * 3 + 1.0)
        self.assertLess(peak / len(big), PEAK_PER_BYTE)
        self.assertLess(peak, 1024 * 1024 * 1024)


PEAK_PER_BYTE = 60  # traced bytes at the peak per input byte (measured 37 and 46)


if __name__ == "__main__":
    unittest.main()
