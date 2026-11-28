"""Deterministic generator of the state death file vectors (conformance/STATE_DEATH_V1.md).

python tools/gen_state_death_v1_vectors.py  writes tests/death_vectors/: three golden files (full, change, empty),
golden.json with the fact rows and receipts the reader and the independent verifier both produce (they must agree),
and hostile.json, single-fault files with the cause both must refuse them with.  Synthetic, non-PHI: the members
SYN... are not real people."""
import os

from gen_vector_common import T, TREE, blob, case, framing, sub, write  # noqa: E402
from app.right_rail_reader_state_death import read_state_death  # noqa: E402
from app.right_rail_reader_state_death_independent import verify_state_death  # noqa: E402

OUT = os.path.join(TREE, "tests", "death_vectors")


def H(fseq, asof, cover, proof, layout="RRDETH01", sender="SYNSTATE-VITAL", scope="SYNTHETIC-STATE"):
    return f"H{layout:<8}{sender:<20}{fseq:012d}{asof}{cover}{scope:<20}{proof}".ljust(120)


def D(member, death):
    return f"D{member:<20}{death}".ljust(120)


ROWS = [D("SYN0000001", "20260315"), D("SYN0000002", "20240229"), D("SYN0000005", "19991231"),
        D("SYN0000007", "20261031")]  # the last on the as-of day
FULL = [H(51, "20261031", "F", "V")] + ROWS + [T(4)]
CHANGE = [H(52, "20261107", "C", "E"), D("SYN0000003", "20261107"), T(1)]
EMPTY = [H(53, "20261130", "F", "V"), T(0)]

ENTRY = {"src": 8, "cls": 1, "origin": 8, "ids": [[2, [1]]], "gapless": 0, "maxage": 35, "drop": 10, "oneper": 1,
         "scope": "SYNTHETIC-STATE", "name": "SYNTHETIC VITAL RECORDS", "fseq_rule": 2, "full": 1, "cfrom_rule": 0}


F = FULL
hostile = framing(F) + [
    case("eligibility layout", "unknown_layout", blob(sub(F, 0, 1, "RRELIG01"))),
    case("blank proof", "unknown_code", blob(sub(F, 0, 70, " "))),
    case("proof 0", "unknown_code", blob(sub(F, 0, 70, "0"))),
    case("federal proof letter", "unknown_code", blob(sub(F, 0, 70, "S"))),
    case("partial date, day unknown", "bad_date", blob(sub(F, 1, 21, "20260300"))),
    case("partial date, month and day unknown", "bad_date", blob(sub(F, 2, 21, "20240000"))),
    case("blank date of death", "bad_date", blob(sub(F, 3, 21, " " * 8))),
    case("30 February", "bad_date", blob(sub(F, 4, 21, "20260230"))),
    case("space inside member id", "bad_text", blob(sub(F, 1, 1, "SYN 0000001"))),
    case("blank member id", "bad_text", blob(sub(F, 2, 1, " " * 20))),
    case("death after as-of", "death_after_as_of", blob(sub(F, 4, 21, "20261101"))),
    case("same member twice", "duplicate_key", blob(F[:2] + [D("SYN0000001", "20260316")] + F[2:-1] + [T(5)])),
    case("count too high", "count_mismatch", blob(F[:-1] + [T(5)])),
    case("count too low", "count_mismatch", blob(F[:-1] + [T(3)])),
    case("row filler", "bad_filler", blob(sub(F, 2, 119, "Z"))),
    case("header filler", "bad_filler", blob(sub(F, 0, 71, "X"))),
    case("letter in fseq", "bad_number", blob(sub(F, 0, 29, "00000000005O"))),
    case("no identity for kind 2", "kind_not_registered", blob(F), {"ids": [[1, [1]]]}),
    case("identity code 2", "unknown_identity_field", blob(F), {"ids": [[2, [1, 2]]]}),
]
write(OUT, (("full.death", FULL), ("change.death", CHANGE), ("empty.death", EMPTY)), hostile,
      (read_state_death, verify_state_death), ENTRY)
