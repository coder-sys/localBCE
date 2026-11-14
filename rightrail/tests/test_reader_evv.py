"""Visit record reader on synthetic data only: clean, repaired, quarantined and checked files."""

import hashlib
import json
import time
import tracemalloc
import unittest

from app.right_rail_reader_evv import read_evv
from app.right_rail_reader_lines import ReaderError

HEAD = "member_id,provider_id,service_code,visit_date,start,end,latitude,longitude,address\n"


def line(m="M1", p="P1", s="T1019", d="2026-03-01", a="2026-03-01T08:00:00-05:00", b="2026-03-01T09:00:00-05:00",
         lat="40.123456", lon="-75.5", addr=""):
    return f"{m},{p},{s},{d},{a},{b},{lat},{lon},{addr}\n"


def kinds(res):
    return [f.kind for f in res.findings]


class EvvReaderTest(unittest.TestCase):
    def test_clean_csv(self):
        data = (HEAD + line() + line(m="M2", p="P2", lat="", lon="", addr="1 Test St")).encode()
        r = read_evv(data, "csv")
        self.assertEqual(r.quarantined, [])
        a, b = r.rows
        self.assertEqual((a.lat_e6, a.lon_e6, a.start_offset_min, a.end_s - a.start_s), (40123456, -75500000, -300, 3600))
        self.assertEqual(a.start_s, 1772370000)
        self.assertEqual((b.address, b.lat_e6), ("1 Test St", None))
        self.assertEqual(a.source_sha3_512, hashlib.sha3_512(data).hexdigest())
        self.assertEqual(a.offset, len(HEAD))
        self.assertEqual(kinds(r), ["coverage_unknown"] * 2)

    def test_clean_jsonl(self):
        rec = {"member_id": "M1", "provider_id": "P1", "service_code": "T1019", "visit_date": "2026-03-01",
               "start": "2026-03-01T13:00:00Z", "end": "2026-03-01T14:00:00Z", "latitude": 40.5, "longitude": -75,
               "address": ""}
        r = read_evv((json.dumps(rec) + "\n").encode(), "jsonl")
        self.assertEqual((r.rows[0].lat_e6, r.rows[0].lon_e6, r.rows[0].start_offset_min), (40500000, -75000000, 0))

    def test_bom_crlf_padding_trailing_blank_line_and_header_case(self):
        body = HEAD.upper() + line() + line(m="  M2  ", a="2026-03-01T10:00:00-05:00", b="2026-03-01T11:00:00-05:00")
        data = b"\xef\xbb\xbf" + body.replace("\n", "\r\n").encode() + b"\r\n"
        r = read_evv(data, "csv")
        self.assertEqual([x.member_id for x in r.rows], ["M1", "M2"])
        self.assertEqual(r.quarantined, [])
        self.assertEqual(r.repairs, {"bom": 1, "crlf": 4, "header_case": 1, "padding": 1, "trailing_blank_line": 1})

    def test_truncated_last_record_and_bad_values(self):
        data = (HEAD + line() + line(d="2026-02-30") + line(a="2026-03-01 08:00") + line(lat="91")
                + line(lat="1.1234567") + "M3,P3,T10\n" + line(m="M4", lon="-75.5")[:-4]).encode()
        r = read_evv(data, "csv")
        self.assertEqual(len(r.rows), 5)
        self.assertEqual([(q.field, q.cause) for q in r.quarantined],
                         [("visit_date", "bad_date"), ("start", "bad_time"), ("latitude", "bad_coordinate"),
                          ("latitude", "bad_coordinate"), (None, "column_count"), (None, "unterminated_record")])
        self.assertEqual(kinds(r).count("missing_data_point"), 4)

    def test_last_line_without_line_feed_is_never_read_as_a_value(self):
        # -75.5 cut to -75 would still parse; the reader must not take it
        r = read_evv((HEAD + line() + line(m="M2", lon="-75.5")[:-4]).encode(), "csv")
        self.assertEqual([x.member_id for x in r.rows], ["M1"])
        self.assertEqual([q.cause for q in r.quarantined], ["unterminated_record"])

    def test_unreadable_text_set_aside(self):
        bad = ["\\ud800", "a\\u0085b", "a\\u2028b", "a\\u2029b", "a\\u0001b", "a\\u007fb"]
        data = "".join('{"member_id": "%s", "provider_id": "P"}\n' % b for b in bad).encode()
        r = read_evv(data, "jsonl")
        self.assertEqual([(q.field, q.cause) for q in r.quarantined], [("member_id", "bad_text")] * len(bad))
        self.assertEqual([x.member_id for x in r.rows], [None] * len(bad))

    def test_jsonl_wrong_keys_and_non_integer_ids(self):
        data = b'{"foo": 1}\n{"member_id": 123.0, "provider_id": 7}\n{"member_id": 1e3}\n'
        r = read_evv(data, "jsonl")
        self.assertEqual([(q.offset, q.field, q.cause) for q in r.quarantined],
                         [(0, None, "no_known_field"), (11, "member_id", "non_integer_number"),
                          (50, "member_id", "non_integer_number")])
        self.assertEqual([(x.member_id, x.provider_id) for x in r.rows], [(None, "7"), (None, None)])

    def test_header_only_csv_has_no_rows(self):
        r = read_evv(HEAD.encode(), "csv")
        self.assertEqual((r.rows, r.quarantined, r.findings), ([], [], []))

    def test_bad_records_quarantined_rest_applied(self):
        data = (b'{"member_id": "M1"}\nnot json\n[1]\n\n{"member_id":"a","member_id":"b"}\n\xff\xfe\n'
                + json.dumps({"member_id": "M9"}).encode() + b"\n")
        r = read_evv(data, "jsonl")
        self.assertEqual([q.cause for q in r.quarantined],
                         ["unparseable", "not_an_object", "blank_record", "duplicate_key", "not_utf8"])
        self.assertEqual([x.member_id for x in r.rows], ["M1", "M9"])

    def test_missing_data_point_names_it(self):
        r = read_evv((HEAD + line(s="", lat="", lon="")).encode(), "csv")
        f = [x for x in r.findings if x.kind == "missing_data_point"]
        self.assertEqual(f[0].detail, "service,location")

    def test_end_before_start_and_over_24h(self):
        data = (HEAD + line(a="2026-03-01T09:00:00-05:00", b="2026-03-01T08:00:00-05:00")
                + line(m="M2", p="P2", b="2026-03-02T08:00:01-05:00"))
        r = read_evv(data.encode(), "csv")
        self.assertEqual(sorted(set(kinds(r)) - {"coverage_unknown"}), ["end_before_start", "over_24h"])
        r = read_evv((HEAD + line(b="2026-03-02T08:00:00-05:00")).encode(), "csv")
        self.assertNotIn("over_24h", kinds(r))

    def test_overlap_per_caregiver(self):
        def t(h):
            return f"2026-03-01T{h:02d}:00:00-05:00"
        l1, l2 = line(m="M1", a=t(8), b=t(10)), line(m="M2", a=t(9), b=t(11))
        data = HEAD + l1 + l2 + line(m="M3", a=t(11), b=t(12)) + line(m="M4", p="P2", a=t(9), b=t(11))
        r = read_evv(data.encode(), "csv")
        ov = [f for f in r.findings if f.kind == "overlap"]
        self.assertEqual([(f.offset, f.detail) for f in ov], [(len(HEAD + l1), f"with {len(HEAD)}")])

    def test_duplicate_row_is_flagged_not_overlap(self):
        r = read_evv((HEAD + line() + line()).encode(), "csv")
        self.assertIn("duplicate_row", kinds(r))
        self.assertNotIn("overlap", kinds(r))
        self.assertEqual(len(r.rows), 2)

    def test_coverage_hook(self):
        data = (HEAD + line() + line(m="M2", p="P2") + line(m="M3", p="P3")).encode()
        known = {"M1": True, "M2": False}
        r = read_evv(data, "csv", coverage=lambda m, d: known.get(m))
        self.assertEqual(kinds(r), ["outside_coverage", "coverage_unknown"])

    def test_refused_whole_files(self):
        for data in (b"", b"\xff\n", b"a,b\n1,2\n", b"member_id,member_id\n", b"member_id\n1\n",
                     b"member_id,provider_id,service_code,visit_date,start,end\n"):
            with self.assertRaises(ReaderError):
                read_evv(data, "csv")
        with self.assertRaises(ReaderError) as c:
            read_evv(HEAD.encode(), "csv", expected_sha3_512="0" * 128)
        self.assertEqual(c.exception.cause, "hash_mismatch")
        with self.assertRaises(ReaderError) as c:
            read_evv(b"member_id," + b"x" * 70000 + b"\n" + line().encode(), "csv")
        self.assertEqual(c.exception.cause, "header_too_long")

    def test_large_file_linear_and_bounded(self):
        def build(n):
            rows = [HEAD]
            for i in range(n):
                day, hour = 1 + i % 28, (i // 28) % 20
                rows.append(line(m=f"M{i}", p=f"P{i % 500}", d=f"2026-03-{day:02d}",
                                 a=f"2026-03-{day:02d}T{hour:02d}:00:00-05:00", b=f"2026-03-{day:02d}T{hour:02d}:30:00-05:00"))
            return "".join(rows).encode()
        small, big = build(20_000), build(100_000)

        def best(data):
            times = []
            for _ in range(2):
                t = time.perf_counter()
                r = read_evv(data, "csv")
                times.append(time.perf_counter() - t)
            return min(times), r
        t_small, _ = best(small)
        t_big, r = best(big)
        tracemalloc.start()
        read_evv(small, "csv")
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(len(r.rows), 100_000)
        self.assertLess(peak, 40_000_000)  # for 20,000 rows; the large run is 5x that
        self.assertLess(t_big / max(t_small, 1e-6), 15)  # 5x the rows: about 5x when linear, 25x when quadratic

if __name__ == "__main__":
    unittest.main()
