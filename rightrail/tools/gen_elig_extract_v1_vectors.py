"""Deterministic generator of the eligibility extract vectors (conformance/ELIG_EXTRACT_V1.md).

python tools/gen_elig_extract_v1_vectors.py  writes tests/elig_vectors/: three golden files (full, change, empty), golden.json
with the fact rows and receipts the reader and the independent verifier both produce (they must agree), and hostile.json,
single-fault files with the cause both must refuse them with.  Synthetic, non-PHI: the members SYN... are not real people."""
import os

from gen_vector_common import T, TREE, blob, case, sub, write  # noqa: E402
from app.right_rail_reader_elig import read_elig  # noqa: E402
from app.right_rail_reader_elig_independent import verify_elig  # noqa: E402

OUT = os.path.join(TREE, "tests", "elig_vectors")


def H(fseq, asof, cover, layout="RRELIG01", sender="SYNSTATE-ELIG", scope="SYNTHETIC-STATE"):
    return f"H{layout:<8}{sender:<20}{fseq:012d}{asof}{cover}{scope:<20}".ljust(120)


def D(member, seg, st, ba, prog, aid, start, end, det, note):
    return f"D{member:<20}{seg:<20}{st}{ba}{prog:<20}{aid:<10}{start}{end}{det}{note}".ljust(120)


ROWS = [
    D("SYN0000001", "SEG-0001", "E", "G", "MEDICAID-FFS", "ABD", "20260101", "99991231", "20251215", "20251216"),
    D("SYN0000001", "SEG-0002", "N", "R", "MEDICAID-FFS", "ABD", "20250701", "20251231", "20251201", "20251203"),
    D("SYN0000002", "SEG-0001", "P", "G", "MEDICAID-FFS", "FAM", "20261001", "20261031", "20261001", "20261002"),
    D("SYN0000003", "SEG-0007", "R", "P", "MEDICAID-FFS", "PE", "20261015", "20261130", "20261015", "20261015"),
    D("SYN0000004", "SEG-0001", "E", "C", "CHIP-FFS", "CHILD", "20240229", "20261231", "20231120", "20231121"),
]
FULL = [H(42, "20261031", "F")] + ROWS + [T(5)]
CHANGE = [H(43, "20261107", "C"),
          D("SYN0000002", "SEG-0001", "E", "G", "MEDICAID-FFS", "FAM", "20261001", "99991231", "20261107", "20261108"),  # determined on the as-of day, notice after it
          T(1)]
EMPTY = [H(44, "20261130", "F"), T(0)]

ENTRY = {"src": 7, "cls": 1, "origin": 7, "ids": [[1, [1, 2]]], "gapless": 0, "maxage": 35, "drop": 10, "oneper": 1,
         "scope": "SYNTHETIC-STATE", "name": "SYNTHETIC ELIGIBILITY SYSTEM", "fseq_rule": 2, "full": 1, "cfrom_rule": 0}


F = FULL
hostile = [
    case("empty file", "unterminated_record", b""),
    case("no final line feed", "unterminated_record", blob(F)[:-1]),
    case("carriage returns", "bad_record_length", ("\r\n".join(F) + "\r\n").encode()),
    case("row one byte short", "bad_record_length", blob(F[:2] + [F[2][:119]] + F[3:])),
    case("blank line", "bad_record_length", blob(F[:3] + [""] + F[3:])),
    case("row of 130 bytes", "bad_record_length", blob(F[:2] + [F[2] + "X" * 10] + F[3:])),
    case("first record a row", "no_header", blob(F[1:])),
    case("no trailer", "no_trailer", blob(F[:-1])),
    case("header only", "no_trailer", blob(F[:1])),
    case("unknown record type", "unknown_record_type", blob(sub(F, 3, 0, "X"))),
    case("second header", "unknown_record_type", blob(F[:3] + [F[0]] + F[3:-1] + [T(6)])),
    case("second trailer", "unknown_record_type", blob(F + [F[-1]])),
    case("other layout", "unknown_layout", blob(sub(F, 0, 1, "RRELIG02"))),
    case("space inside member id", "bad_text", blob(sub(F, 1, 1, "SYN 0000001"))),
    case("leading space in program", "bad_text", blob(sub(F, 2, 43, " MEDICAID-FFS"))),
    case("non-ASCII byte in aid", "bad_text", blob(sub(F, 3, 63, "\xe9"))),
    case("blank segment", "bad_text", blob(sub(F, 4, 21, " " * 20))),
    case("blank sender", "bad_text", blob(sub(F, 0, 9, " " * 20))),
    case("letter in fseq", "bad_number", blob(sub(F, 0, 29, "00000000004O"))),
    case("space in trailer count", "bad_number", blob(sub(F, 6, 1, " 00000005"))),
    case("30 February", "bad_date", blob(sub(F, 1, 73, "20260230"))),
    case("29 February not leap", "bad_date", blob(sub(F, 5, 73, "20250229"))),
    case("year zero", "bad_date", blob(sub(F, 2, 89, "00000101"))),
    case("month 13", "bad_date", blob(sub(F, 3, 97, "20261301"))),
    case("letter in as-of", "bad_date", blob(sub(F, 0, 41, "2026103l"))),
    case("blank end date", "bad_date", blob(sub(F, 1, 81, " " * 8))),
    case("unknown status", "unknown_code", blob(sub(F, 1, 41, "X"))),
    case("lower-case basis", "unknown_code", blob(sub(F, 2, 42, "g"))),
    case("unknown cover", "unknown_code", blob(sub(F, 0, 49, "D"))),
    case("row filler", "bad_filler", blob(sub(F, 3, 119, "Z"))),
    case("header filler", "bad_filler", blob(sub(F, 0, 70, "X"))),
    case("trailer filler", "bad_filler", blob(sub(F, 6, 10, "0"))),
    case("span backwards", "span_backwards", blob(sub(F, 4, 73, "20261201"))),
    case("determined after as-of", "determined_after_as_of", blob(sub(F, 4, 89, "20261101"))),
    case("same member and segment twice", "duplicate_key",
         blob(F[:2] + [sub(F, 1, 41, "N")[1]] + F[2:-1] + [T(6)])),
    case("count too high", "count_mismatch", blob(F[:-1] + [T(6)])),
    case("count too low", "count_mismatch", blob(F[:-1] + [T(4)])),
    case("no identity for kind 1", "kind_not_registered", blob(F), {"ids": [[2, [1]]]}),
    case("identity code 3", "unknown_identity_field", blob(F), {"ids": [[1, [1, 3]]]}),
    case("segment-only identity repeats", "duplicate_key", blob(F), {"ids": [[1, [2]]]}),
]
write(OUT, (("full.elig", FULL), ("change.elig", CHANGE), ("empty.elig", EMPTY)), hostile,
      (read_elig, verify_elig), ENTRY)
