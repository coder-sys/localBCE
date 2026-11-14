"""835 reader on synthetic files: claim and service payments, repeated CAS triples, PLB, total check as a finding, quarantine units."""

import io
import time
import tracemalloc
import unittest

from app import right_rail_x12_835 as r835
from tests.test_x12 import file_of


def head(total="190.00", trace="T835", payee="1999999984"):
    return [f"BPR*I*{total}*C*ACH*CCP*01*1*DA*2*3**01*1*DA*2*20260110", f"TRN*1*{trace}*1999999984", "N1*PR*SYNTHETIC STATE*PI*PAYER1",
            f"N1*PE*SYNTHETIC CLINIC*XX*{payee}"]


def clp(cid, charge="125.50", paid="80.00", pr="25.50", cas=("CAS*PR*1*25.50", "CAS*CO*45*15.00**96*5.00"), svc=True):
    segs = [f"CLP*{cid}*1*{charge}*{paid}*{pr}*MC*PCN-{cid}*11*1", *cas, "NM1*QC*1*DOE*JANE****MI*S00000001"]
    if svc:
        segs += ["SVC*HC:99213:25*125.50*80.00**1.5", "DTM*472*20260115", "CAS*CO*45*20.00"]
    return segs


BODY = head() + ["LX*1"] + clp("C1") + clp("C2", "120.00", "120.00", "0.00", cas=(), svc=False) + ["PLB*1999999984*20261231*WO:REF9*10.00"]


class Reader835Tests(unittest.TestCase):
    def read(self, body=BODY, **kwargs):
        data = file_of([body], kind="835", **kwargs)
        return data, r835.read_835(data)

    def causes(self, got):
        return [(q.unit, q.cause) for q in got.quarantines]

    def test_clean_file(self):
        data, got = self.read()
        self.assertEqual((got.refused, got.quarantines, got.findings), ("", (), ()))
        c1, c2 = got.claims
        self.assertEqual((c1.trace, c1.payer_id, c1.payee_npi, c1.claim_id, c1.status, c1.payer_claim_control), ("T835", "PAYER1", "1999999984", "C1", "1", "PCN-C1"))
        self.assertEqual((c1.charge_cents, c1.paid_cents, c1.patient_responsibility_cents, c2.paid_cents), (12550, 8000, 2550, 12000))
        self.assertEqual(c1.file_sha3_512, r835.x12.parse(data).sha3_512)
        self.assertEqual([data[o:o + 3] for o in c1.offsets], [b"CLP", b"CAS", b"CAS"])
        (svc,) = got.services
        self.assertEqual((svc.claim_id, svc.procedure, svc.modifiers, svc.charge_cents, svc.paid_cents, svc.units_milli, svc.service_date),
                         ("C1", "99213", ("25",), 12550, 8000, 1500, "2026-01-15"))
        self.assertEqual(svc.adjustments, (("CO", "45", 2000, ""),))
        (pay,) = got.payments
        self.assertEqual((pay.total_cents, pay.direction, pay.payment_date, pay.paid_cents, pay.provider_adjustment_cents), (19000, "C", "2026-01-10", 20000, 1000))

    def test_cas_triples_repeat_in_order(self):
        _, got = self.read()
        self.assertEqual(got.claims[0].adjustments, (("PR", "1", 2550, ""), ("CO", "45", 1500, ""), ("CO", "96", 500, "")))

    def test_plb(self):
        data, got = self.read()
        (plb,) = got.provider_adjustments
        self.assertEqual((plb.provider_id, plb.fiscal_period, plb.reason_code, plb.reference, plb.amount_cents), ("1999999984", "2026-12-31", "WO", "REF9", 1000))
        self.assertEqual(data[plb.offset:plb.offset + 3], b"PLB")
        body = BODY[:-1] + ["PLB*1999999984*20261231*WO:REF9*10.00*L6:REF8*-4.50"]
        got = self.read(body)[1]
        self.assertEqual([(p.reason_code, p.amount_cents) for p in got.provider_adjustments], [("WO", 1000), ("L6", -450)])
        self.assertEqual((got.findings[0].cause, got.payments[0].provider_adjustment_cents), ("total_mismatch", 550))

    def test_total_mismatch_is_a_finding_not_a_refusal(self):
        _, got = self.read(head("191.00") + BODY[len(head()):])
        self.assertEqual((len(got.claims), got.quarantines, got.refused), (2, (), ""))
        (finding,) = got.findings
        self.assertEqual((finding.unit, finding.cause, finding.detail), ("set", "total_mismatch", "BPR02=19100 claims=20000 plb=1000"))

    def test_bad_amounts_quarantine_the_smallest_unit(self):
        body = head() + clp("C1", paid="8O.00") + clp("C2", "120.00", "120.00", "0.00", cas=("CAS*CO*45*1,5",), svc=False) + ["PLB*1999999984*20261231*WO:REF9*10.00"]
        _, got = self.read(body)
        self.assertEqual([c.claim_id for c in got.claims], ["C2"])
        self.assertEqual(got.services, ())  # C1's service line goes with its claim
        self.assertEqual(got.claims[0].adjustments, ())
        self.assertEqual(self.causes(got), [("loop", "bad_clp"), ("segment", "bad_cas")])
        self.assertEqual([f.cause for f in got.findings], ["total_unchecked"])
        body = head() + clp("C1", svc=False) + ["SVC*HC:99213*x*80.00", "CAS*CO*45*1.00", "PLB*1999999984*20261231*WO:REF9*ten"]
        got = self.read(body)[1]
        self.assertEqual(self.causes(got), [("loop", "bad_svc"), ("segment", "cas_without_target"), ("segment", "bad_plb")])
        self.assertEqual((len(got.claims), got.services, got.provider_adjustments), (1, (), ()))

    def test_claim_paid_against_service_paid_is_a_finding_only(self):
        body = head() + clp("C1", paid="70.00") + clp("C2", "120.00", "120.00", "0.00", cas=(), svc=False) + ["PLB*1999999984*20261231*WO:REF9*10.00"]
        _, got = self.read(head("180.00") + body[len(head()):])
        self.assertEqual([(f.unit, f.cause, f.detail) for f in got.findings], [("loop", "total_mismatch", "CLP04=7000 svc=8000")])
        self.assertEqual((got.claims[0].paid_cents, got.services[0].paid_cents), (7000, 8000))

    def test_repeated_claim_ids_are_reported_with_every_row_kept(self):
        _, got = self.read(head("360.00") + clp("C1", svc=False) + clp("C2", "120.00", "120.00", "0.00", cas=(), svc=False) + clp("C1", svc=False))
        self.assertEqual((len(got.claims), [(c, len(o)) for c, o in got.duplicates]), (3, [("C1", 2)]))

    def test_bad_payment_date_is_set_aside_and_left_empty(self):
        body = BODY[:]
        body[0] = body[0].replace("20260110", "20261340")
        _, got = self.read(body)
        self.assertEqual((self.causes(got), got.payments[0].payment_date, len(got.claims)), ([("segment", "bad_date")], "", 2))

    def test_header_unknown_envelope_and_truncation(self):
        got = self.read([s for s in BODY if not s.startswith("TRN")])[1]
        self.assertEqual((len(got.claims), {c.trace for c in got.claims}, got.quarantines, len(got.payments)), (2, {""}, (), 1))
        self.assertEqual([(f.cause, f.detail) for f in got.findings][0], ("no_payment_header", "2 claims kept without BPR or TRN02"))

    def test_a_claim_without_patient_responsibility_is_still_read(self):
        body = BODY[:]
        body[BODY.index("CLP*C2*1*120.00*120.00*0.00*MC*PCN-C2*11*1")] = "CLP*C2*1*120.00*120.00**MC*PCN-C2*11*1"
        got = self.read(body)[1]
        self.assertEqual((len(got.claims), got.claims[1].patient_responsibility_cents, got.claims[0].patient_responsibility_cents, got.quarantines), (2, None, 2550, ()))
        got = self.read(BODY + ["WAT*1"])[1]
        self.assertEqual((len(got.claims), self.causes(got)), (2, [("segment", "unknown_segment")]))
        self.assertEqual(self.read(se_count=2)[1].claims, ())
        data = file_of([BODY], kind="835")
        cut = r835.read_835(data[:data.index(b"PLB") + 6])
        self.assertEqual((cut.claims, cut.refused, self.causes(cut)[0]), ((), "iea_missing", ("segment", "unterminated_segment")))
        self.assertEqual(self.causes(r835.read_835(file_of([BODY], kind="837")))[0], ("set", "not_835"))

    def test_records_stream_out_as_soon_as_the_header_is_seen_and_hold_only_a_fixed_number_when_it_is_late(self):
        late = BODY[4:] + BODY[:2]  # the claims, then BPR and TRN
        got = self.read(late)[1]
        self.assertEqual(([c.trace for c in got.claims], len(got.services), len(got.payments), got.quarantines), (["T835"] * 2, 1, 1, ()))
        many = [s for i in range(r835._HELD + 5) for s in clp(f"C{i:06d}", svc=False)]
        got = self.read(many)[1]
        self.assertEqual((len(got.claims), [q.cause for q in got.quarantines], [f.cause for f in got.findings]), (r835._HELD, ["header_late"], ["no_payment_header"]))

    def test_a_multi_megabyte_file_streams_in_bounded_memory(self):
        class Count(r835.x12.Sink):
            rows = 0

            def add(self, ts, kind, item):
                self.rows += kind in ("claim", "service")

        def peak_of(claims):
            body = []
            for i in range(claims):
                body.append(f"CLP*C{i:06d}*1*50.00*40.00*10.00*MC*P{i}*11*1")
                for n in range(5):
                    body += ["SVC*HC:99213*10.00*8.00**1", "DTM*472*20260115", "CAS*CO*45*2.00"]
            data = file_of([head(f"{claims * 40}.00") + body], kind="835")
            sink = Count()
            tracemalloc.start()
            self.assertEqual(r835.stream_835(io.BytesIO(data), sink), "")
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            self.assertEqual(sink.rows, claims * 6)
            return len(data), peak
        (_, small), (big_bytes, big) = peak_of(10000), peak_of(30000)
        self.assertGreater(big_bytes, 8 * 1024 * 1024)
        self.assertLess(big, 6 * 1024 * 1024)
        self.assertLess(big, small * 1.25 + 512 * 1024)

    def test_two_hundred_thousand_lines_in_linear_time_and_bounded_memory(self):
        def build(claims):
            body = []
            for i in range(claims):
                body.append(f"CLP*C{i:06d}*1*50.00*40.00*10.00*MC*P{i}*11*1")
                for n in range(5):
                    body += ["SVC*HC:99213*10.00*8.00**1", "DTM*472*20260115", "CAS*CO*45*2.00"]
            return file_of([head(f"{claims * 40}.00") + body], kind="835")
        small, big = build(4000), build(40000)
        t0 = time.perf_counter()
        r835.read_835(small)
        t_small = time.perf_counter() - t0
        t0 = time.perf_counter()
        r835.read_835(big)
        t_big = time.perf_counter() - t0
        tracemalloc.start()
        got = r835.read_835(big)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        print(f"x12 835 200k lines: {len(big)} bytes, {t_small:.2f}s for 20k, {t_big:.2f}s for 200k, traced peak {peak} bytes")
        self.assertEqual((len(got.services), len(got.claims), got.quarantines, got.findings), (200000, 40000, (), ()))
        self.assertLess(t_big, 30 * t_small + 1.0)  # ten times the lines, at most three times linear
        self.assertLess(peak / len(big), PEAK_PER_BYTE)
        self.assertLess(peak, 1024 * 1024 * 1024)


PEAK_PER_BYTE = 60  # traced bytes at the peak per input byte (measured 37 and 46)


if __name__ == "__main__":
    unittest.main()
