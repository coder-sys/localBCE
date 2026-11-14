"""Exclusion list reader on synthetic data only: invented names, and NPIs built from the check-digit rule."""

import hashlib
import time
import tracemalloc
import unittest

from app.right_rail_reader_lines import ReaderError
from app.right_rail_reader_leie import LEIE_COLUMNS, KINDS, npi_ok, read_leie

HEAD = ",".join(LEIE_COLUMNS) + "\n"
KW = {"source": "synthetic test file", "as_of": "2026-10-31"}


def make_npi(n):
    """Nine digits from n, plus the check digit found by trying all ten (Luhn over 80840 + the ten digits)."""
    nine = f"{n:09d}"
    for c in "0123456789":
        full = "80840" + nine + c
        s = sum(sum(divmod(int(d) * 2, 10)) if i % 2 else int(d) for i, d in enumerate(reversed(full)))
        if s % 10 == 0:
            return nine + c
    raise AssertionError


def wrong(npi):
    return npi[:9] + str((int(npi[9]) + 3) % 10)


def row(last="TESTER", first="ALEX", mid="", bus="", npi="0000000000", typ="1128a1", excl="20250115",
        rein="00000000", waiver="00000000", wst=""):
    cells = dict(LASTNAME=last, FIRSTNAME=first, MIDNAME=mid, BUSNAME=bus, GENERAL="X", SPECIALTY="Y", UPIN="",
                 NPI=npi, DOB="19700101", ADDRESS="1 TEST ST", CITY="NOWHERE", STATE="ZZ", ZIP="00000",
                 EXCLTYPE=typ, EXCLDATE=excl, REINDATE=rein, WAIVERDATE=waiver, WVRSTATE=wst)
    return ",".join(cells[c] for c in LEIE_COLUMNS) + "\n"


def kinds(r):
    return [f.kind for f in r.findings]


class LeieReaderTest(unittest.TestCase):
    def test_npi_builder_and_check(self):
        n = make_npi(123456789)
        self.assertTrue(npi_ok(n))
        self.assertFalse(npi_ok(wrong(n)))
        self.assertFalse(npi_ok(n[:9]))
        self.assertFalse(npi_ok("12345678ab"))

    def test_clean_file_individual_and_entity(self):
        n = make_npi(1)
        data = (HEAD + row(npi=n, mid="Q") + row(last="", first="", bus="SAMPLE SUPPLY CO", typ="1128b4",
                                                 rein="20260301", waiver="20260401", wst="ZZ")).encode()
        r = read_leie(data, **KW)
        a, b = r.rows
        self.assertEqual((a.who, a.last_name, a.first_name, a.middle_name, a.business_name, a.npi),
                         ("individual", "TESTER", "ALEX", "Q", None, n))
        self.assertEqual((a.exclusion_type, a.exclusion_date, a.reinstatement_date, a.waiver_date, a.waiver_state),
                         ("1128a1", "2025-01-15", None, None, None))
        self.assertEqual((b.who, b.last_name, b.business_name, b.npi, b.exclusion_type),
                         ("entity", None, "SAMPLE SUPPLY CO", None, "1128b4"))
        self.assertEqual((b.reinstatement_date, b.waiver_date, b.waiver_state), ("2026-03-01", "2026-04-01", "ZZ"))
        self.assertEqual((a.offset, a.source_sha3_512), (len(HEAD), hashlib.sha3_512(data).hexdigest()))
        self.assertEqual((r.quarantined, r.findings, r.repairs), ([], [], {}))
        self.assertEqual(r.coverage, ("synthetic test file", "2026-10-31", "full"))

    def test_header_case_bom_crlf_padding_and_extra_column(self):
        body = HEAD.lower().rstrip("\n") + ",extra\n" + row(last="  TESTER  ").rstrip("\n") + ",z\n"
        data = b"\xef\xbb\xbf" + body.replace("\n", "\r\n").encode() + b"\r\n"
        r = read_leie(data, **KW)
        self.assertEqual([x.last_name for x in r.rows], ["TESTER"])
        self.assertEqual(r.quarantined, [])
        self.assertEqual(r.repairs, {"bom": 1, "crlf": 3, "header_case": 1, "padding": 1, "trailing_blank_line": 1})

    def test_bad_npi_check_digit_is_set_aside_zero_is_none(self):
        good = make_npi(5)
        bad = wrong(good)
        r = read_leie((HEAD + row(npi=bad) + row(npi="0000000000") + row(npi="0") + row(npi="12345") + row(npi=good)).encode(), **KW)
        self.assertEqual([x.npi for x in r.rows], [None, None, None, None, good])
        self.assertEqual([(q.field, q.cause) for q in r.quarantined], [("npi", "bad_npi")] * 2)
        for item in list(r.findings) + list(r.quarantined):
            self.assertFalse(any(isinstance(v, str) and (bad in v or good in v) for v in item))

    def test_zero_dates_are_none_and_bad_dates_set_aside(self):
        data = HEAD + row(excl="0", rein="0", waiver="0") + row(excl="20250230") + row(rein="2025011") + row(rein="abcdefgh")
        r = read_leie(data.encode(), **KW)
        self.assertEqual([x.exclusion_date for x in r.rows], [None, None, "2025-01-15", "2025-01-15"])
        self.assertEqual([x.reinstatement_date for x in r.rows], [None] * 4)
        self.assertEqual([(q.field, q.cause) for q in r.quarantined],
                         [("excldate", "bad_date"), ("reindate", "bad_date"), ("reindate", "bad_date")])

    def test_whole_rows_set_aside(self):
        data = HEAD + row(last="", bus="") + row(typ="") + "a,b\n" + "\n" + row()
        r = read_leie(data.encode(), **KW)
        self.assertEqual([(q.field, q.cause) for q in r.quarantined],
                         [(None, "no_name"), (None, "no_exclusion_type"), (None, "column_count"), (None, "blank_record")])
        self.assertEqual(len(r.rows), 1)

    def test_exclusion_type_shape(self):
        types = ["1128a1", "1128b14", "1128Aa", "1156", "1160", "BRCH SA", "1128c1", "1128a", "1999", "x1128a1"]
        r = read_leie((HEAD + "".join(row(typ=t) for t in types)).encode(), **KW)
        self.assertEqual([x.exclusion_type for x in r.rows], types[:7 - 1] + [None] * 4)
        self.assertEqual([(q.field, q.cause) for q in r.quarantined], [("excltype", "unknown_exclusion_type")] * 4)

    def test_text_set_aside(self):
        bad = ["A\x01B", "A B", "A B", "A\u0085B", "A\ud800B", "A\x7fB"]
        data = HEAD + "".join(row(first=b) for b in bad)
        r = read_leie(data.encode("utf-8", "surrogatepass"), **KW)
        # a lone surrogate is not UTF-8 at all, so that whole record is set aside
        self.assertEqual([(q.field, q.cause) for q in r.quarantined],
                         [("firstname", "bad_text")] * 4 + [(None, "not_utf8"), ("firstname", "bad_text")])
        self.assertEqual([x.first_name for x in r.rows], [None] * 4 + [None])
        r = read_leie(HEAD.encode() + row().encode().replace(b"TESTER", b"T\xff"), **KW)
        self.assertEqual(([q.cause for q in r.quarantined], r.rows), (["not_utf8"], []))

    def test_unterminated_last_line_never_read(self):
        r = read_leie((HEAD + row() + row(first="PAT")[:-1]).encode(), **KW)
        self.assertEqual([x.first_name for x in r.rows], ["ALEX"])
        self.assertEqual([q.cause for q in r.quarantined], ["unterminated_record"])

    def test_findings(self):
        data = HEAD + (row(excl="20250115", rein="20240101") + row(excl="20261101") + row(waiver="20250601", wst="")
                       + row(excl="20261031", rein="20261031", waiver="20250601", wst="ZZ"))
        r = read_leie(data.encode(), **KW)
        self.assertEqual(kinds(r), ["reinstated_before_excluded", "excluded_after_as_of", "waiver_without_state"])
        self.assertEqual(len(r.rows), 4)

    def test_missing_exclusion_date_is_a_finding(self):
        r = read_leie((HEAD + row(excl="0") + row(excl="", last="B") + row(excl="00000000", last="C")).encode(), **KW)
        self.assertEqual((kinds(r), len(r.rows)), (["exclusion_date_missing"] * 3, 3))

    def test_reinstatement_and_waiver_after_as_of(self):
        r = read_leie((HEAD + row(rein="20261101", waiver="20261101", wst="ZZ") + row(rein="20261031")).encode(), **KW)
        self.assertEqual(kinds(r), ["reinstated_after_as_of", "waiver_after_as_of"])

    def test_duplicate_rows_and_one_npi_two_names(self):
        n = make_npi(9)
        a, b = row(npi=n), row(npi=n, last="OTHERNAME")
        r = read_leie((HEAD + a + a + b + b).encode(), **KW)
        self.assertEqual(len(r.rows), 4)
        self.assertEqual([(f.kind, f.offset, f.detail) for f in r.findings],
                         [("duplicate_row", len(HEAD + a), f"same as {len(HEAD)}"),
                          ("npi_two_names", len(HEAD + a + a), f"same NPI as {len(HEAD)}"),
                          ("duplicate_row", len(HEAD + a + a + b), f"same as {len(HEAD + a + a)}")])
        r = read_leie((HEAD + row() + row(last="OTHERNAME")).encode(), **KW)  # no NPI: two people, not a conflict
        self.assertEqual(r.findings, [])

    def test_supplement_kinds(self):
        data = (HEAD + row(rein="20250301") + row()).encode()
        self.assertEqual(kinds(read_leie(data, kind="exclusions", **KW)), ["reinstated_in_exclusion_file"])
        r = read_leie(data, kind="reinstatements", **KW)
        self.assertEqual(kinds(r), ["no_reinstatement_in_reinstatement_file"])
        self.assertEqual(r.coverage.kind, "reinstatements")
        self.assertEqual(KINDS, ("full", "exclusions", "reinstatements"))

    def test_header_only_and_no_coverage(self):
        r = read_leie(HEAD.encode(), **KW)
        self.assertEqual((r.rows, r.quarantined, r.findings, r.coverage), ([], [], [], ("synthetic test file", "2026-10-31", "full")))
        for kind in ("exclusions", "reinstatements"):  # an empty month is a normal supplement
            self.assertEqual(read_leie(HEAD.encode(), kind=kind, **KW).coverage.kind, kind)
        for data in (HEAD + row(last="", bus=""), HEAD + row()[:-1]):  # records present, none readable
            r = read_leie(data.encode(), **KW)
            self.assertEqual((r.rows, r.coverage), ([], None))

    def test_status_and_a_zero_npi_is_no_key(self):
        n, m = make_npi(11), make_npi(12)
        data = (HEAD + row(npi=n, rein="20260301") + row(npi=m, rein="20260301") + row(npi=m, last="OTHERNAME")
                + row(npi=make_npi(13), rein="20261101") + row(npi="0000000000")).encode()
        r = read_leie(data, **KW)
        self.assertEqual([(x.npi, x.status) for x in r.rows], [(n, "reinstated"), (m, "reinstated"), (m, "excluded"), (make_npi(13), "excluded"), (None, "excluded")])

    def test_refused_whole_files(self):
        for data in (b"", b"\xff\n", b"a,b\n1,2\n", HEAD.replace("NPI", "NPX").encode(),
                     HEAD.replace("NPI", "LASTNAME").encode()):
            with self.assertRaises(ReaderError):
                read_leie(data, **KW)
        with self.assertRaises(ReaderError) as c:
            read_leie(HEAD.encode(), expected_sha3_512="0" * 128, **KW)
        self.assertEqual(c.exception.cause, "hash_mismatch")
        with self.assertRaises(ReaderError) as c:
            read_leie(b"LASTNAME," + b"x" * 70000 + b"\n", **KW)
        self.assertEqual(c.exception.cause, "header_too_long")

    def test_coverage_required(self):
        for kw in ({"source": "", "as_of": "2026-10-31"}, {"source": "x", "as_of": "2026-13-01"},
                   {"source": "x", "as_of": "2026-1-01"}, {"source": "x", "as_of": "2026-10-31\n"},
                   {"source": "x", "as_of": None}, {"source": 5, "as_of": "2026-10-31"},
                   {"source": "x", "as_of": "2026-10-31", "kind": "other"}):
            with self.assertRaises(ReaderError):
                read_leie(HEAD.encode(), **kw)

    def test_large_file_linear_and_bounded(self):
        def build(n):
            return (HEAD + "".join(row(last=f"NAME{i}", npi=make_npi(i) if i % 2 else "0000000000")
                                   for i in range(n))).encode()
        small, big = build(20_000), build(100_000)

        def best(data):
            times = []
            for _ in range(2):
                t = time.perf_counter()
                r = read_leie(data, **KW)
                times.append(time.perf_counter() - t)
            return min(times), r
        t_small, _ = best(small)
        t_big, r = best(big)
        tracemalloc.start()
        read_leie(small, **KW)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(len(r.rows), 100_000)
        self.assertLess(peak, 40_000_000)  # for 20,000 rows; the large run is 5x that
        self.assertLess(t_big / max(t_small, 1e-6), 15)  # 5x the rows: about 5x when linear, 25x when quadratic


if __name__ == "__main__":
    unittest.main()
