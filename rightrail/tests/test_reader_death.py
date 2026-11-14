"""Death file reader on synthetic data only: SSNs are in the 9xx test range and are not real people."""

import hashlib
import time
import tracemalloc
import unittest

from app.right_rail_reader_death import DMF_LAYOUT, Layout, PartialDate, read_death, ssn_hash
from app.right_rail_reader_lines import ReaderError

KEY = b"synthetic-tenant-key-0001"
KW = {"source": "synthetic test file", "as_of": "2026-10-31"}


def rec(ssn="900000001", last="TESTER", first="ALEX", dod="03152026", dob="07041950", ver="V", upd=" "):
    return f"{upd}{ssn}{last:<20}{'':<4}{first:<15}{'':<15}{ver}{dod:<8}{dob:<8}".ljust(100)


def blob(*records, eol="\n"):
    return (eol.join(records) + eol).encode()


class DeathReaderTest(unittest.TestCase):
    def test_clean_file(self):
        data = blob(rec(), rec(ssn="900000002", last="SAMPLE", first="PAT", ver=" "))
        r = read_death(data, KEY, **KW)
        a, b = r.rows
        self.assertEqual(a.ssn_hash, ssn_hash(KEY, "900000001"))
        self.assertEqual((a.last_name, a.first_name, a.verification, a.offset), ("TESTER", "ALEX", "V", 0))
        self.assertEqual(a.death_date, PartialDate(2026, 3, 15, "day"))
        self.assertEqual(a.birth_date, PartialDate(1950, 7, 4, "day"))
        self.assertEqual((b.verification, b.offset), ("", 101))
        self.assertEqual(a.source_sha3_512, hashlib.sha3_512(data).hexdigest())
        self.assertEqual((r.quarantined, r.findings, r.repairs), ([], [], {}))
        self.assertEqual(r.coverage, ("synthetic test file", "2026-10-31"))

    def test_no_raw_ssn_in_output(self):
        r = read_death(blob(rec(), rec(ssn="900000002", last="SAMPLE"), rec(ssn="12345")), KEY, **KW)
        self.assertEqual(len(r.rows), 2)
        for row in r.rows:
            for value in row:
                if isinstance(value, str):
                    self.assertNotIn("900000001", value)
                    self.assertNotIn("900000002", value)
        for item in list(r.findings) + list(r.quarantined):
            self.assertFalse(any(isinstance(v, str) and "9000000" in v for v in item))

    def test_key_changes_hash(self):
        self.assertNotEqual(ssn_hash(KEY, "900000001"), ssn_hash(KEY + b"x", "900000001"))
        with self.assertRaises(ValueError):
            ssn_hash(b"short", "900000001")

    def test_bom_crlf_padding(self):
        data = b"\xef\xbb\xbf" + blob(rec() + "   ", rec(ssn="900000002"), "", eol="\r\n")
        r = read_death(data, KEY, **KW)
        self.assertEqual(len(r.rows), 2)
        self.assertEqual(r.quarantined, [])
        self.assertEqual(r.repairs, {"bom": 1, "crlf": 3, "padding": 1, "trailing_blank_line": 1})
        self.assertEqual(r.rows[0].offset, 3)

    def test_truncated_and_bad_records(self):
        data = blob(rec(), "", rec(ssn="90000000X"), rec() + "junk", rec(ssn="900000002")[:70])
        r = read_death(data, KEY, **KW)
        self.assertEqual(len(r.rows), 2)
        self.assertEqual([(q.field, q.cause) for q in r.quarantined],
                         [(None, "blank_record"), (None, "bad_ssn"), (None, "record_too_long"), ("death_date", "bad_date")])
        self.assertEqual(r.repairs, {"short_record_padded": 1})
        self.assertIsNone(r.rows[1].death_date)

    def test_truncated_last_record_without_line_end(self):
        r = read_death(blob(rec()) + rec(ssn="900000002")[:50].encode(), KEY, **KW)
        self.assertEqual(len(r.rows), 1)
        self.assertEqual([q.cause for q in r.quarantined], ["unterminated_record"])

    def test_last_record_cut_in_final_field_is_never_read(self):
        # a line with no line feed may be cut anywhere, so it is never read, whatever it holds
        r = read_death(blob(rec()) + rec(ssn="900000002", dob="07041950").rstrip().encode(), KEY, **KW)
        self.assertEqual(len(r.rows), 1)
        self.assertEqual([q.cause for q in r.quarantined], ["unterminated_record"])

    def test_no_coverage_when_nothing_was_read(self):
        for data in (b"", rec().encode(), blob(rec(ssn="BAD000000")), blob("")):
            r = read_death(data, KEY, **KW)
            self.assertEqual((r.rows, r.coverage), ([], None))

    def test_code_n_blank_name_and_non_ascii_name(self):
        data = blob(rec(ver="N", last=""), rec(ssn="900000002", last="CAF?")).replace(b"CAF?", b"CAF\xc3")
        r = read_death(data, KEY, **KW)
        self.assertEqual((r.rows[0].verification, r.rows[0].last_name), ("N", None))
        self.assertEqual([(q.field, q.cause) for q in r.quarantined], [("last_name", "bad_text")])

    def test_death_after_as_of_and_before_birth_at_common_precision(self):
        r = read_death(blob(rec(dod="11012026"), rec(ssn="900000002", dod="11002026"), rec(ssn="900000003", dod="00002027"),
                            rec(ssn="900000004", dod="10312026"), rec(ssn="900000005", dod="00001949", dob="07041950"),
                            rec(ssn="900000006", dod="07001950", dob="07041950")), KEY, **KW)
        self.assertEqual([(f.kind, f.offset // 101) for f in r.findings],
                         [("death_after_as_of", 0), ("death_after_as_of", 1), ("death_after_as_of", 2), ("death_before_birth", 4)])

    def test_partial_and_bad_dates(self):
        data = blob(rec(dod="03002026"), rec(ssn="900000002", dod="00002026"), rec(ssn="900000003", dod="00152026"),
                    rec(ssn="900000004", dod="02302026"), rec(ssn="900000005", dod="13012026", dob="0704ABCD"),
                    rec(ssn="900000006", dod="00000000", dob=""))
        r = read_death(data, KEY, **KW)
        self.assertEqual([x.death_date for x in r.rows],
                         [PartialDate(2026, 3, 0, "month"), PartialDate(2026, 0, 0, "year"), None, None, None, None])
        self.assertIsNone(r.rows[5].birth_date)
        self.assertEqual({q.cause for q in r.quarantined}, {"bad_date"})
        self.assertEqual(sorted(q.field for q in r.quarantined), ["birth_date"] + ["death_date"] * 4)

    def test_death_before_birth(self):
        r = read_death(blob(rec(dod="01011950", dob="01021950")), KEY, **KW)
        self.assertEqual([f.kind for f in r.findings], ["death_before_birth"])

    def test_duplicates(self):
        r = read_death(blob(rec(), rec(), rec(dod="03162026")), KEY, **KW)
        self.assertEqual([f.kind for f in r.findings], ["duplicate_record", "conflicting_duplicate"])
        self.assertEqual(len(r.rows), 3)

    def test_bad_code_and_name_fields_set_aside(self):
        r = read_death(blob(rec(ver="Z"), rec(ssn="900000002", last="B\x01D")), KEY, **KW)
        self.assertEqual([(q.field, q.cause) for q in r.quarantined],
                         [("verification", "bad_code"), ("last_name", "bad_text")])
        self.assertEqual(len(r.rows), 2)

    def test_each_row_is_keyed_by_its_hashed_ssn(self):
        res = read_death(blob(rec(), rec(ssn="900000002")), KEY, **KW)
        self.assertEqual([r.ssn_hash for r in res.rows], [ssn_hash(KEY, "900000001"), ssn_hash(KEY, "900000002")])

    def test_coverage_required_and_hash_checked(self):
        for kw in ({"source": "", "as_of": "2026-10-31"}, {"source": "x", "as_of": "2026-13-01"},
                   {"source": "x", "as_of": "2026-W45-1"}, {"source": "x", "as_of": "2026-1-01"},
                   {"source": "x", "as_of": "2026-10-31\n"}, {"source": "x", "as_of": None}, {"source": 5, "as_of": "2026-10-31"}):
            with self.assertRaises(ReaderError):
                read_death(b"", KEY, **kw)
        with self.assertRaises(ReaderError):
            read_death(b"", KEY, expected_sha3_512="0" * 128, **KW)

    def test_swappable_layout(self):
        lay = Layout((("ssn", 0, 9), ("death_date", 9, 17)), 17)
        r = read_death(b"90000000103152026\n", KEY, layout=lay, **KW)
        self.assertEqual((r.rows[0].death_date, r.rows[0].last_name), (PartialDate(2026, 3, 15, "day"), None))
        self.assertNotEqual(lay, DMF_LAYOUT)

    def test_large_file_linear_and_bounded(self):
        def build(n):
            return blob(*(rec(ssn=f"9{i:08d}") for i in range(n)))
        small, big = build(20_000), build(100_000)

        def best(data):
            times = []
            for _ in range(2):
                t = time.perf_counter()
                r = read_death(data, KEY, **KW)
                times.append(time.perf_counter() - t)
            return min(times), r
        t_small, _ = best(small)
        t_big, r = best(big)
        tracemalloc.start()
        read_death(small, KEY, **KW)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(len(r.rows), 100_000)
        self.assertLess(peak, 60_000_000)  # for 20,000 rows; the large run is 5x that
        self.assertLess(t_big / max(t_small, 1e-6), 15)  # 5x the rows: about 5x when linear, 25x when quadratic

if __name__ == "__main__":
    unittest.main()
