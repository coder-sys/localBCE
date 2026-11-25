"""834 reader on synthetic files: fields, offsets, both dates, absorb-and-quarantine, duplicates, and 50,000 members."""

import io
import time
import tracemalloc
import unittest

from app import right_rail_x12 as x12
from app import right_rail_x12_834 as r834
from tests.test_x12 import file_of


def member(mid, *, ins03="021", reason="", death="", begin="20260101", end="20261231", plan="PLAN-A", extra=()):
    fields = ["INS", "Y", "18", ins03, reason, "A", "", "", "FT", "", ""] + (["D8", death] if death else [])
    ins = "*".join(fields)
    return [ins, f"REF*0F*{mid}", "DTP*356*D8*20260101", f"NM1*IL*1*DOE{mid}*JANE*Q***34*999{mid[-4:]}",
            "N3*1 SYNTHETIC ST*APT 2", "N4*SPRINGFIELD*XX*00000", "DMG*D8*19800229*F",
            f"HD*021**HLT*{plan}*IND", f"DTP*348*D8*{begin}", f"DTP*349*D8*{end}", *extra]


def header():
    return ["BGN*00*F1*20260102*0930", "N1*P5*SYNTHETIC STATE*FI*000000000"]


class Reader834Tests(unittest.TestCase):
    def read(self, members, **kwargs):
        body = header() + [s for m in members for s in m]
        data = file_of([body], **kwargs)
        return data, r834.read_834(data)

    def test_each_set_gives_its_roster_with_its_whole_bgn08_with_or_without_a_member(self):
        change, n1 = "BGN*00*F2*20260102*0930****2", header()[1]
        data = file_of([[change, n1] + member("M1"), header(), [change, "BGN*00*F3*20260102*0930****RX", n1], ["BGN*00*F4*20260102*0930****rx "],
                        ["BGN*00*F5*20260102*0930****2:RX"], [change, change]])
        got = r834.read_834(data)
        self.assertEqual(got.rosters, tuple(r834.Roster("2026-01-02T09:30:00", x12.digest(io.BytesIO(data)), 0, action, data.index(f"ST*834*{n:04d}".encode()))
                                            for n, action in zip(range(1, 7), ("2", "", "", "RX", "2:RX", "2"))))

    def test_clean_member_fields_offsets_and_both_dates(self):
        data, got = self.read([member("M0000001", reason="08")])
        self.assertEqual((got.refused, got.quarantines, got.duplicates), ("", (), ()))
        (row,) = got.rows
        self.assertEqual((row.member_id, row.maintenance_type, row.maintenance_reason, row.subscriber, row.benefit_status),
                         ("M0000001", "021", "08", "Y", "A"))
        self.assertEqual((row.plan, row.coverage_line, row.coverage_begin, row.coverage_end), ("PLAN-A", "HLT", "2026-01-01", "2026-12-31"))
        self.assertEqual((row.eligibility_begin, row.eligibility_end, row.death_date), ("2026-01-01", "", ""))
        self.assertEqual((row.last_name, row.first_name, row.birth_date, row.gender), ("DOEM0000001", "JANE", "1980-02-29", "F"))
        self.assertEqual((row.street, row.city, row.state, row.zip), ("1 SYNTHETIC ST APT 2", "SPRINGFIELD", "XX", "00000"))
        self.assertEqual(row.file_at, "2026-01-02T09:30:00")
        self.assertEqual(row.file_sha3_512, r834.x12.parse(data).sha3_512)
        self.assertEqual(data[row.offsets[0]:row.offsets[0] + 3], b"INS")
        self.assertEqual([data[o:o + 3] for o in row.offsets], [b"INS", b"REF", b"DTP", b"NM1", b"N3*", b"N4*", b"DMG", b"HD*", b"DTP", b"DTP"])

    def test_death_date_after_coverage_is_reported_as_sent(self):
        _, got = self.read([member("M0000002", ins03="024", reason="03", death="20270315", end="20261231")])
        (row,) = got.rows
        self.assertEqual((row.death_date, row.coverage_end, row.maintenance_reason), ("2027-03-15", "2026-12-31", "03"))
        self.assertEqual(got.quarantines, ())

    def test_bad_death_and_other_dates_are_quarantined_not_repaired(self):
        bad = member("M0000003", death="20271301", extra=["DTP*349*D8*20270101"])
        bad[2] = "DTP*356*D8*20260230"
        _, got = self.read([bad])
        (row,) = got.rows
        self.assertEqual((row.death_date, row.eligibility_begin), ("", ""))
        self.assertEqual(sorted(q.cause for q in got.quarantines), ["bad_date", "bad_death_date", "repeated_segment"])
        self.assertEqual(row.coverage_end, "2026-12-31")  # the first one stands

    def test_duplicate_member_in_one_file_keeps_both_and_reports(self):
        data, got = self.read([member("M0000004"), member("M0000005"), member("M0000004", plan="PLAN-B")])
        self.assertEqual([(r.member_id, r.plan) for r in got.rows], [("M0000004", "PLAN-A"), ("M0000005", "PLAN-A"), ("M0000004", "PLAN-B")])
        ((who, offsets),) = got.duplicates
        self.assertEqual((who, len(offsets)), ("M0000004", 2))
        self.assertTrue(all(data[o:o + 3] == b"INS" for o in offsets))

    def test_repeated_loops_and_unknown_segments_are_quarantined_alone(self):
        twice = member("M0000006", extra=["NM1*IL*1*OTHER*NAME", "N4*ELSEWHERE*YY*11111", "ZZZ*1"])
        _, got = self.read([twice, member("M0000007")])
        self.assertEqual([r.member_id for r in got.rows], ["M0000006", "M0000007"])
        self.assertEqual(got.rows[0].last_name, "DOEM0000006")
        self.assertEqual(got.rows[0].city, "SPRINGFIELD")
        self.assertEqual([(q.unit, q.cause) for q in got.quarantines], [("loop", "repeated_loop"), ("segment", "unknown_segment")])

    def test_a_broker_account_in_the_header_is_a_known_segment(self):
        body = header() + ["N1*BO*SYNTHETIC BROKER*94*000000001", "ACT*1234567"] + member("M0000019")  # the TPA or broker loop
        got = r834.read_834(file_of([body]))
        self.assertEqual((got.refused, got.quarantines, [r.member_id for r in got.rows]), ("", (), ["M0000019"]))

    def test_member_without_id_is_quarantined_and_one_with_bad_ins_is_still_read_others_read(self):
        no_id = [s for s in member("M0000008") if not s.startswith("REF") and not s.startswith("NM1")]
        bad_ins = member("M0000009")
        bad_ins[0] = "INS*Q*18"
        _, got = self.read([no_id, bad_ins, member("M0000010")])
        self.assertEqual([(r.member_id, r.subscriber, r.maintenance_type) for r in got.rows], [("M0000009", "Q", ""), ("M0000010", "Y", "021")])
        self.assertEqual([(q.unit, q.cause) for q in got.quarantines], [("loop", "no_member_id"), ("segment", "bad_ins")])

    def test_a_date_in_the_wrong_loop_is_set_aside_never_dropped(self):
        late = member("M0000016", extra=["DTP*357*D8*20260131"])  # eligibility end after the coverage loop's HD
        early = member("M0000017")
        early.insert(2, "DTP*349*D8*20260131")  # coverage end before any HD
        start = member("M0000018", extra=["DTP*356*D8*20260101"])  # eligibility begin after HD
        for m, seg in ((late, "DTP"), (early, "DTP"), (start, "DTP")):
            _, got = self.read([m])
            self.assertEqual([(q.cause, q.detail[:3]) for q in got.quarantines], [("unread_segment", seg)], m)

    def test_name_loop_leftovers_and_id_disagreement_are_reported(self):
        m = member("M0000015", extra=[])
        m.insert(m.index("N3*1 SYNTHETIC ST*APT 2"), "PER*IP**TE*5550100")
        m.insert(m.index("N3*1 SYNTHETIC ST*APT 2"), "REF*17*X")
        _, got = self.read([m])
        self.assertEqual([(q.cause, q.detail) for q in got.quarantines], [("unread_segment", "PER in the member name loop"), ("unread_segment", "REF in the member name loop")])
        self.assertEqual(got.rows[0].member_id, "M0000015")
        named = member("M0000016")
        named[3] = "NM1*IL*1*DOE*JANE****MI*MA"
        later = [s for s in named if not s.startswith("REF")]
        later.insert(later.index("N3*1 SYNTHETIC ST*APT 2"), "REF*0F*MB")
        for body in (named[:1] + [named[1].replace("M0000016", "MB")] + named[2:], later):
            _, got = self.read([body])
            self.assertEqual(([r.member_id for r in got.rows], [f.cause for f in got.findings], got.quarantines), (["MB"], ["member_id_conflict"], ()))

    def test_second_coverage_loop_and_second_name_loop_after_other_loops(self):
        m = member("M0000011", extra=["HD*021**DEN*PLAN-D*IND", "DTP*348*D8*20260201", "NM1*31*1*INCORRECT*NAME", "DMG*D8*19000101*M"])
        _, got = self.read([m])
        self.assertEqual([(r.plan, r.coverage_begin) for r in got.rows], [("PLAN-A", "2026-01-01"), ("PLAN-D", "2026-02-01")])
        self.assertEqual(got.rows[0].birth_date, "1980-02-29")  # a later loop's DMG is not this member's

    def test_envelope_faults_pass_through_and_other_set_kinds_are_quarantined(self):
        _, got = self.read([member("M0000012")], se_count=3)
        self.assertEqual((got.rows, [q.cause for q in got.quarantines]), ((), ["se_count_mismatch"]))
        got = r834.read_834(file_of([header()], kind="820"))
        self.assertEqual([(q.cause, q.detail) for q in got.quarantines], [("not_834", "")])
        data, got = self.read([member("M0000013")])
        cut = r834.read_834(data[:data.index(b"DMG")] + b"DM")
        self.assertEqual((cut.rows, cut.refused), ((), "iea_missing"))
        self.assertEqual(cut.quarantines[0].cause, "unterminated_segment")

    def test_repairs_apply_and_rows_match_the_clean_file(self):
        data, clean = self.read([member("M0000014")])
        dirty = r834.read_834(b"\xef\xbb\xbf" + data.replace(b"~", b"~\r\n"))
        self.assertEqual([r[:21] for r in dirty.rows], [r[:21] for r in clean.rows])
        self.assertEqual({r for r, _ in dirty.repairs}, {"bom", "whitespace"})

    def test_names_are_utf8_and_bad_bytes_are_kept_as_hex_not_rewritten(self):
        data, _ = self.read([member("M0000015")])
        good = r834.read_834(data.replace(b"DOEM0000015", "DOEÑEZ".encode("utf-8")))
        self.assertEqual((good.rows[0].last_name, good.rows[0].name_raw_hex, good.repairs), ("DOEÑEZ", "", ()))
        raw = b"DOE" + bytes([0xE9]) + b"Z" + bytes([0xFF]) + b"EZ"
        bad = r834.read_834(data.replace(b"DOEM0000015", raw))
        (row,) = bad.rows
        self.assertEqual(bad.quarantines, ())
        self.assertEqual([r for r, _ in bad.repairs], ["bad_utf8"])
        self.assertIn(raw.hex(), row.name_raw_hex)  # nothing lost; the name text is marked, not guessed

    def test_two_different_ids_with_bad_bytes_never_read_as_one(self):
        data, _ = self.read([member("M0000018"), member("M0000019")])
        data = data.replace(b"REF*0F*M0000018", b"REF*0F*A" + bytes([0xE9])).replace(b"REF*0F*M0000019", b"REF*0F*A" + bytes([0xFF]))
        got = r834.read_834(data)
        ids = [r.member_id for r in got.rows]
        self.assertEqual((len(set(ids)), got.duplicates), (2, ()))
        self.assertTrue(all(i.endswith("]") and "\ufffd" in i for i in ids))

    def test_a_failed_envelope_takes_back_rows_already_streamed(self):
        data, clean = self.read([member("M0000016"), member("M0000017")])
        for bad in (data.replace(b"SE*", b"SE*9", 1), data.replace(b"GE*1*1", b"GE*2*1"), data.replace(b"IEA*1*", b"IEA*2*")):
            got = r834.read_834(bad)
            self.assertEqual((got.rows, got.duplicates, got.findings), ((), (), ()))
            self.assertEqual(len(got.quarantines), 1)
        self.assertEqual(len(clean.rows), 2)

    def test_a_multi_megabyte_file_streams_in_bounded_memory(self):
        class Count(x12.Sink):
            rows = 0

            def add(self, ts, kind, item):
                self.rows += kind == "row"

        def peak_of(n):
            data = file_of([header() + [s for i in range(n) for s in member(f"M{i:07d}")]])
            sink, source = Count(), io.BytesIO(data)
            tracemalloc.start()
            self.assertEqual(r834.stream_834(source, sink), "")
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            self.assertEqual(sink.rows, n)
            return len(data), peak
        (small_bytes, small), (big_bytes, big) = peak_of(15000), peak_of(45000)
        print(f"x12 834 stream: {small_bytes} bytes peak {small}; {big_bytes} bytes peak {big}")
        self.assertGreater(big_bytes, 8 * 1024 * 1024)
        self.assertLess(big, 6 * 1024 * 1024)  # a few chunks, whatever the size of the file
        self.assertLess(big, small * 1.25 + 512 * 1024)  # three times the file, no more memory

    def test_fifty_thousand_members_in_linear_time_and_bounded_memory(self):
        def build(n):
            body = header() + [s for i in range(n) for s in member(f"M{i:07d}")]
            return file_of([body])
        small, big = build(5000), build(50000)
        t0 = time.perf_counter()
        r834.read_834(small)
        t_small = time.perf_counter() - t0
        t0 = time.perf_counter()
        r834.read_834(big)
        t_big = time.perf_counter() - t0
        tracemalloc.start()
        got = r834.read_834(big)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        print(f"x12 834 50k members: {len(big)} bytes, {t_small:.2f}s for 5k, {t_big:.2f}s for 50k, traced peak {peak} bytes")
        self.assertEqual((len(got.rows), got.quarantines, got.duplicates), (50000, (), ()))
        self.assertLess(t_big, t_small * 10 * 3 + 1.0)  # ten times the members, at most three times linear
        self.assertLess(peak / len(big), 50)  # traced bytes at the peak per input byte (measured 30)
        self.assertLess(peak, 450 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
