"""Deterministic generator of the provider death list vectors (conformance/PROVIDER_DEATH_V1.md).

python tools/gen_provider_death_v1_vectors.py  writes tests/provdeath_vectors/: three golden files (full, change,
empty), golden.json with the fact rows and receipts the reader and the independent verifier both produce (they must
agree), and hostile.json, single-fault files with the cause both must refuse them with.  Synthetic, non-PHI: the
providers' NPIs are made to pass the check and belong to no one."""
import os

from gen_vector_common import T, TREE, bad_npi, blob, case, framing, npi, sub, write  # noqa: E402
from app.right_rail_reader_provider_death import read_provider_death  # noqa: E402
from app.right_rail_reader_provider_death_independent import verify_provider_death  # noqa: E402

OUT = os.path.join(TREE, "tests", "provdeath_vectors")


def H(fseq, asof, cover, layout="RRPDTH01", sender="SYNSTATE-PE", scope="SYNTHETIC-STATE"):
    return f"H{layout:<8}{sender:<20}{fseq:012d}{asof}{cover}{scope:<20}".ljust(120)


def D(n, death, raw=None):
    return f"D{raw or npi(n):<10}{death}".ljust(120)


ROWS = [D(1, "20260315"), D(2, "20240229"), D(5, "19991231"), D(7, "20261031")]  # the last on the as-of day
FULL = [H(61, "20261031", "F")] + ROWS + [T(4)]
CHANGE = [H(62, "20261107", "C"), D(3, "20261107"), T(1)]
EMPTY = [H(63, "20261130", "F"), T(0)]

# The reader and the verifier take no tenant secret (an NPI is public); the shared writer passes one, so these drop it.
def read(stream, secret, entry, sink, **kw):
    return read_provider_death(stream, entry, sink, **kw)


def verify(stream, secret, entry, sink, **kw):
    return verify_provider_death(stream, entry, sink, **kw)


ENTRY = {"src": 11, "cls": 1, "origin": 11, "ids": [[4, [1]]], "gapless": 0, "maxage": 35, "drop": 10, "oneper": 1,
         "scope": "SYNTHETIC-STATE", "name": "SYNTHETIC PROVIDER ENROLLMENT", "fseq_rule": 2, "full": 1,
         "cfrom_rule": 0}

F = FULL
hostile = framing(F) + [
    case("truncated inside a row", "unterminated_record", blob(F)[:121 + 121 + 60]),
    case("eligibility layout", "unknown_layout", blob(sub(F, 0, 1, "RRELIG01"))),
    case("state death layout", "unknown_layout", blob(sub(F, 0, 1, "RRDETH01"))),
    case("state exclusion layout", "unknown_layout", blob(sub(F, 0, 1, "RRSEXC01"))),
    case("NPI check digit wrong", "bad_npi", blob(F[:1] + [D(1, "20260315", raw=bad_npi(1))] + F[2:])),
    case("NPI of nine digits", "bad_npi", blob(sub(F, 1, 1, npi(1)[:9] + " "))),
    case("NPI with a letter", "bad_npi", blob(sub(F, 1, 1, "A" + npi(1)[1:]))),
    case("blank NPI", "bad_text", blob(sub(F, 2, 1, " " * 10))),
    case("partial date, day unknown", "bad_date", blob(sub(F, 1, 11, "20260300"))),
    case("partial date, month and day unknown", "bad_date", blob(sub(F, 2, 11, "20240000"))),
    case("blank date of death", "bad_date", blob(sub(F, 3, 11, " " * 8))),
    case("30 February", "bad_date", blob(sub(F, 4, 11, "20260230"))),
    case("death after as-of", "death_after_as_of", blob(sub(F, 4, 11, "20261101"))),
    case("same NPI twice with two dates", "duplicate_key", blob(F[:2] + [D(1, "20260316")] + F[2:-1] + [T(5)])),
    case("same NPI twice with one date", "duplicate_key", blob(F[:2] + [D(1, "20260315")] + F[2:-1] + [T(5)])),
    case("count too high", "count_mismatch", blob(F[:-1] + [T(5)])),
    case("count too low", "count_mismatch", blob(F[:-1] + [T(3)])),
    case("row filler", "bad_filler", blob(sub(F, 2, 119, "Z"))),
    case("header filler", "bad_filler", blob(sub(F, 0, 70, "V"))),
    case("letter in fseq", "bad_number", blob(sub(F, 0, 29, "00000000006O"))),
    case("as-of on no calendar day", "bad_date", blob(sub(F, 0, 41, "20261331"))),
    case("as-of with a month of zero", "bad_date", blob(sub(F, 0, 41, "20261000"))),
    case("blank as-of", "bad_date", blob(sub(F, 0, 41, " " * 8))),
    case("unknown cover byte", "unknown_code", blob(sub(F, 0, 49, "X"))),
    case("blank sender", "bad_text", blob(sub(F, 0, 9, " " * 20))),
    case("blank scope", "bad_text", blob(sub(F, 0, 50, " " * 20))),
    case("letter in the trailer count", "bad_number", blob(F[:-1] + [T(4)[:9] + "X" + T(4)[10:]])),
    case("no identity for kind 4", "kind_not_registered", blob(F), {"ids": [[2, [1]]]}),
    case("identity code 2", "unknown_identity_field", blob(F), {"ids": [[4, [1, 2]]]}),
]
write(OUT, (("full.pdeath", FULL), ("change.pdeath", CHANGE), ("empty.pdeath", EMPTY)), hostile,
      (read, verify), ENTRY)
