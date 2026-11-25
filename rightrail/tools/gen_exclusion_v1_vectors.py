"""Deterministic generator of the exclusion list vectors (conformance/EXCLUSION_V1.md).

python tools/gen_exclusion_v1_vectors.py  writes tests/excl_vectors/: the state list's golden files (*.sexc), the
federal list's golden files (*.csv), golden.json with the fact rows, set-aside entries and receipts the readers and
the independent verifiers both produce (they must agree), and hostile.json, single-fault files with the cause both must
refuse them with.  Synthetic, non-PHI: the providers SYN... are not real, and their NPIs are made to pass the check."""
import csv
import io
import json
import os
import sys
import tempfile

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TREE)
from gen_vector_common import bad_npi, npi  # noqa: E402
from app import right_rail_fact_registry as reg  # noqa: E402
from app.right_rail_reader_federal_exclusion import read_federal_exclusion  # noqa: E402
from app.right_rail_reader_federal_exclusion_independent import verify_federal_exclusion  # noqa: E402
from app.right_rail_reader_leie import LEIE_COLUMNS  # noqa: E402
from app.right_rail_reader_state_exclusion import read_state_exclusion  # noqa: E402
from app.right_rail_reader_state_exclusion_independent import verify_state_exclusion  # noqa: E402

OUT = os.path.join(TREE, "tests", "excl_vectors")
os.makedirs(OUT, exist_ok=True)


# The state list: fixed-width records of 120 bytes.
def H(fseq, asof, cover, layout="RRSEXC01", sender="SYNSTATE-PI", scope="SYNTHETIC-STATE"):
    return f"H{layout:<8}{sender:<20}{fseq:012d}{asof}{cover}{scope:<20}".ljust(120)


def D(n, authority, start, back="99991231", raw=None):
    return f"D{raw or npi(n):<10}{authority:<8}{start}{back}".ljust(120)


def T(n):
    return f"T{n:09d}".ljust(120)


def blob(recs):
    return ("\n".join(recs) + "\n").encode("latin-1")


SROWS = [D(1, "SPI-A1", "20240115"), D(2, "SPI-B2", "20220301", "20250701"), D(3, "SPI-A1", "20261031"),
         D(1, "SPI-C3", "20190101", "20200101")]  # one provider under two authorities; one excluded on the as-of day
SFULL = [H(61, "20261031", "F")] + SROWS + [T(4)]
SCHANGE = [H(62, "20261107", "C"), D(4, "SPI-A1", "20261101", "20261102"), T(1)]  # a one-day exclusion
SEMPTY = [H(63, "20261130", "F"), T(0)]


# The federal list: the published CSV.
def R(last="", first="", mid="", bus="", n=None, typ="1128a1", excl="20200101", back="00000000", wdate="00000000",
      wstate="", raw_npi=None, address="1 SYNTHETIC WAY"):
    v = {c: "" for c in LEIE_COLUMNS}
    v.update(LASTNAME=last, FIRSTNAME=first, MIDNAME=mid, BUSNAME=bus, GENERAL="SYNTHETIC", NPI=raw_npi or
             (npi(n) if n is not None else "0000000000"), DOB="00000000", ADDRESS=address, CITY="SYNCITY", STATE="ZZ",
             ZIP="00000", EXCLTYPE=typ, EXCLDATE=excl, REINDATE=back, WAIVERDATE=wdate, WVRSTATE=wstate, UPIN="")
    s = io.StringIO()
    csv.writer(s, lineterminator="").writerow([v[c] for c in LEIE_COLUMNS])
    return s.getvalue()


HEAD = ",".join(LEIE_COLUMNS)
FROWS = [
    R("SYNLAST", "ANA", n=11),  # 1 trusted, open
    R("SYNREIN", "BO", n=12, typ="1128b4", excl="20180501", back="20210301"),  # 2 reinstated: ends 2021-02-28
    R(bus="SYN CLINIC, LLC", n=13, typ="1128b7", excl="20230101", wdate="20221201", wstate="ZZ"),  # 3 waiver 1
    R("SYNWAIVE", "CY", n=14, excl="20230101", wdate="20230201", wstate="ZZ"),  # 4 waiver after start: 0
    R("SYNOTHER", "DI", n=15, excl="20230101", wdate="20221201", wstate="ZY"),  # 5 another state's waiver: 0
    R(n=16),  # 6 no name: from 0001-01-01, open
    R("SYNNOTYPE", "ED", n=17, typ=""),  # 7 no exclusion type: from 0001-01-01, open
    R("SYNLATE", "FA", n=18, excl="20261101"),  # 8 excluded after the as-of: from 0001-01-01, open
    R("SYNBACK", "GU", n=19, excl="20200101", back="20200101"),  # 9 reinstated on its start: from 0001-01-01, open
    R("SYNSHAPE", "HO", n=20, typ="9999X"),  # 10 type of no known shape: type empty, trusted
    R("SYNBADDATE", "IV", n=21, excl="20200230"),  # 11 exclusion date on no day: from 0001-01-01
    R("SYNNONPI", "JO"),  # 12 why 1
    R("SYNBADNPI", "KA", raw_npi=bad_npi(28)),  # 13 why 2
    R("SYNNONPINOTYPE", "LI", typ=""),  # 14 why 3
    R(),  # 15 why 4
    R("SYNLAST", "ANA", n=11),  # 16 the same as row 1: why 5
    "",  # a blank line
    R("SYNREINLATE", "MO", n=22, excl="20200101", back="20261201"),  # 18 reinstated after the as-of: 0001-01-01, open
    R("SYNNOEXCL", "NU", n=23, excl="0", back="20210101"),  # 19 no exclusion date, reinstated: 0001-01-01 to 2020-12-31
    R("SYN\x07BELL", "QU", n=30),  # 20 a last name with a control character does not read: no name
    R("SYNWAIVEFIRST", "RA", n=31, excl="20230101", wdate="20221201", wstate="ZZ"),  # 21 waiver 1, then
    R("SYNWAIVEFIRST", "RA", n=31, excl="20230101"),  # 22 the same without it: why 5, and row 21's fact has waiver 0
    R("SYNWAIVELAST", "SU", n=32, excl="20230101"),  # 23 waiver 0, then
    R("SYNWAIVELAST", "SU", n=32, excl="20230101", wdate="20221201", wstate="ZZ"),  # 24 with one: why 5, waiver stays 0
    R("SYNWAIVEDAY", "TE", n=33, excl="20230101", wdate="20230101", wstate="ZZ"),  # 25 waiver on the exclusion day: 1
    R("SYNASOF", "UL", n=34, excl="20261031"),  # 26 excluded on the as-of date: trusted, from 2026-10-31
    R("SYNBACKASOF", "VA", n=35, back="20261031"),  # 27 reinstated on the as-of date: trusted, to 2026-10-30
    R("SYNLEAP", "WE", n=36, back="20240301"),  # 28 reinstated the day after a leap day: to 2024-02-29
    R("SYNWAIVESHAPE", "XO", n=37, typ="9999X", wdate="20190101", wstate="ZZ"),  # 29 type not read: waiver 0
    R("SYNWAIVEBACK", "YA", n=38, back="20211340", wdate="20190101", wstate="ZZ"),  # 30 reinstatement not read: 0
]
FFULL = [HEAD] + FROWS
FSUPP = [HEAD.lower(), R("SYNSUPP", "OLA", n=24, typ="BRCH CIA", excl="20261015"), ""]
FEMPTY = [HEAD]

STATE_ENTRY = {"src": 9, "cls": 1, "origin": 9, "ids": [[3, [1, 2, 3]]], "gapless": 0, "maxage": 35, "drop": 10,
               "oneper": 1, "scope": "SYNTHETIC-STATE", "name": "SYNTHETIC STATE EXCLUSIONS", "fseq_rule": 2,
               "full": 1, "cfrom_rule": 0}
FED_ENTRY = {"src": 10, "cls": 1, "origin": 10, "ids": [[3, [1, 2, 3, 4]]], "gapless": 0, "maxage": 35, "drop": 10,
             "oneper": 1, "scope": "FEDERAL", "name": "FEDERAL EXCLUSION LIST", "fseq_rule": 2, "full": 1,
             "cfrom_rule": 0}
TRANSPORT = {"channel": 1, "key": 0, "reader": 1}
FED_ARGS = {"asof": 20261031, "cover": 1, "fseq": 20261031, "sender": "HHS-OIG", "scope": "FEDERAL", "state": "ZZ"}


def entry(base, over=None):
    e = {**base, **(over or {})}
    e["kinds"] = reg.mask_of(e["ids"])
    e["scope"], e["name"] = reg.ident(21, e["scope"]), reg.ident(31, e["name"])
    return e


def call_state(fn, data, over=None, args=None):
    rows = []
    with tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH")) as tmp:
        receipt = fn(io.BytesIO(data), entry(STATE_ENTRY, over), rows.append, scratch=tmp, **TRANSPORT)
    return rows, receipt


def call_fed(fn, data, over=None, args=None):
    rows, aside = [], []
    with tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH")) as tmp:
        receipt = fn(io.BytesIO(data), entry(FED_ENTRY, over), rows.append, aside.append, scratch=tmp,
                     **{**FED_ARGS, **(args or {})}, **TRANSPORT)
    return rows, aside, receipt


def text(lines, end="\n", bom=b""):
    return bom + (end.join(lines) + end).encode("utf-8")


golden = {"state_entry": STATE_ENTRY, "federal_entry": FED_ENTRY, "transport": TRANSPORT, "federal_args": FED_ARGS,
          "state": [], "federal": []}
for name, recs in (("full.sexc", SFULL), ("change.sexc", SCHANGE), ("empty.sexc", SEMPTY)):
    data = blob(recs)
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    rows, receipt = call_state(read_state_exclusion, data)
    assert (rows, receipt) == call_state(verify_state_exclusion, data), ("reader and verifier differ", name)
    golden["state"].append({"name": name, "statements": [s.hex() for s in rows], "receipt": receipt.hex()})
for name, data, args in (("full.csv", text(FFULL), {}),
                         ("supplement.csv", text(FSUPP, bom=b"\xef\xbb\xbf"), {"cover": 2, "asof": 20261107,
                                                                                  "fseq": 20261107}),
                         ("empty-supplement.csv", text(FEMPTY), {"cover": 2, "asof": 20261130, "fseq": 20261130})):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    rows, aside, receipt = call_fed(read_federal_exclusion, data, args=args)
    assert (rows, aside, receipt) == call_fed(verify_federal_exclusion, data, args=args), ("differ", name)
    golden["federal"].append({"name": name, "args": args, "statements": [s.hex() for s in rows],
                              "aside": [a.hex() for a in aside], "receipt": receipt.hex()})


def sub(recs, i, at, new):
    recs = list(recs)
    recs[i] = recs[i][:at] + new + recs[i][at + len(new):]
    return recs


def case(name, cause, data, over=None, args=None):
    return {"name": name, "cause": cause, "data": data.decode("latin-1"), **({"entry": over} if over else {}),
            **({"args": args} if args else {})}


F = SFULL
state_hostile = [
    case("empty file", "unterminated_record", b""),
    case("no final line feed", "unterminated_record", blob(F)[:-1]),
    case("carriage returns", "bad_record_length", ("\r\n".join(F) + "\r\n").encode()),
    case("row of 130 bytes", "bad_record_length", blob(F[:2] + [F[2] + "X" * 10] + F[3:])),
    case("first record a row", "no_header", blob(F[1:])),
    case("no trailer", "no_trailer", blob(F[:-1])),
    case("second trailer", "unknown_record_type", blob(F + [F[-1]])),
    case("unknown record type", "unknown_record_type", blob(sub(F, 3, 0, "X"))),
    case("death layout", "unknown_layout", blob(sub(F, 0, 1, "RRDETH01"))),
    case("header filler", "bad_filler", blob(sub(F, 0, 70, "V"))),
    case("row filler", "bad_filler", blob(sub(F, 2, 119, "Z"))),
    case("NPI check digit wrong", "bad_npi", blob(F[:1] + [D(0, "SPI-A1", "20240115", raw=bad_npi(1))] + F[2:])),
    case("NPI of nine digits", "bad_npi", blob(sub(F, 1, 1, npi(1)[:9] + " "))),
    case("NPI with a letter", "bad_npi", blob(sub(F, 1, 1, "A" + npi(1)[1:]))),
    case("blank NPI", "bad_text", blob(sub(F, 1, 1, " " * 10))),
    case("space inside authority", "bad_text", blob(sub(F, 1, 11, "SPI A1  "))),
    case("blank authority", "bad_text", blob(sub(F, 1, 11, " " * 8))),
    case("start on no day", "bad_date", blob(sub(F, 1, 19, "20240230"))),
    case("blank reinstatement", "bad_date", blob(sub(F, 1, 27, " " * 8))),
    case("excluded after as-of", "excluded_after_as_of", blob(sub(F, 3, 19, "20261101"))),
    case("reinstated after as-of", "reinstated_after_as_of", blob(sub(F, 2, 27, "20261101"))),
    case("reinstated on its start", "span_backwards", blob(sub(F, 2, 27, "20220301"))),
    case("reinstated before its start", "span_backwards", blob(sub(F, 2, 27, "20220228"))),
    case("same row twice", "duplicate_key", blob(F[:2] + [F[1]] + F[2:-1] + [T(5)])),
    case("count too low", "count_mismatch", blob(F[:-1] + [T(3)])),
    case("letter in fseq", "bad_number", blob(sub(F, 0, 29, "00000000006O"))),
    case("no identity for kind 3", "kind_not_registered", blob(F), {"ids": [[2, [1]]]}),
    case("identity code 5", "unknown_identity_field", blob(F), {"ids": [[3, [1, 5]]]}),
    case("kind 3 named twice", "bad_entry", blob(F), {"ids": [[3, [1]], [3, [1, 2, 3]]]}),
]

G = FFULL
long_row = R("SYNLONG", "PA", n=25, address="X" * 65537)
federal_hostile = [
    case("bad as-of", "bad_coverage", text(G), args={"asof": 20260230}),
    case("as-of not a number", "bad_coverage", text(G), args={"asof": "20261031"}),
    case("cover 3", "bad_coverage", text(G), args={"cover": 3}),
    case("negative fseq", "bad_coverage", text(G), args={"fseq": -1}),
    case("blank sender", "bad_coverage", text(G), args={"sender": ""}),
    case("space in scope", "bad_coverage", text(G), args={"scope": "FEDERAL LIST"}),
    case("state in lower case", "bad_coverage", text(G), args={"state": "zz"}),
    case("no identity for kind 3", "kind_not_registered", text(G), {"ids": [[2, [1]]]}),
    case("identity code 5", "unknown_identity_field", text(G), {"ids": [[3, [1, 5]]]}),
    case("kind 3 named twice", "bad_entry", text(G), {"ids": [[3, [1]], [3, [1, 2, 3, 4]]]}),
    case("an identity without the NPI merges two providers", "identity_merges_npis",
         text([HEAD, R("SYNFIRSTNPI", "ZA", raw_npi="1999900115"), R("SYNSECONDNPI", "ZE", raw_npi="1999900123")]),
         {"ids": [[3, [2, 3, 4]]]}),
    case("empty file", "no_header", b""),
    case("header not UTF-8", "no_header", b"\xff" + text(G)),
    case("header with an open quote", "no_header", text(['"' + HEAD] + G[1:])),
    case("no NPI column", "bad_header", text([HEAD.replace("NPI", "NPX")] + G[1:])),
    case("a column twice", "bad_header", text([HEAD.replace("UPIN", "NPI")] + G[1:])),
    case("no final line feed", "unterminated_record", text(G)[:-1]),
    case("line too long", "line_too_long", text(G[:3] + [long_row] + G[3:])),
    case("row not UTF-8", "not_utf8", text(G[:2]) + R("SYN\xff", n=26).encode("latin-1") + b"\n" + text(G[2:])),
    case("row with an open quote", "unparseable", text(G[:2] + ['"' + G[2]] + G[3:])),
    case("row with a cell short", "column_count", text(G[:2] + [G[2].rsplit(",", 1)[0]] + G[3:])),
    case("no name and an NPI that does not read", "unholdable_row", text(G + [R(raw_npi=bad_npi(29))])),
    case("full list with no row", "no_rows", text([HEAD])),
    case("full list with no named row", "no_rows", text([HEAD, R(n=27), R()])),
    case("supplement with no named row", "no_rows", text([HEAD, R(n=27)]), args={"cover": 2}),
]
for group, fn_pair, call in (("state", (read_state_exclusion, verify_state_exclusion), call_state),
                             ("federal", (read_federal_exclusion, verify_federal_exclusion), call_fed)):
    for c in state_hostile if group == "state" else federal_hostile:
        data = c["data"].encode("latin-1")
        for fn in fn_pair:
            try:
                call(fn, data, c.get("entry"), c.get("args"))
            except Exception as e:  # noqa: BLE001
                got = getattr(e, "cause", repr(e))
            else:
                got = "accepted"
            assert got == c["cause"], (group, c["name"], fn.__name__, got)

with open(os.path.join(OUT, "golden.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump(golden, f, indent=1)
    f.write("\n")
with open(os.path.join(OUT, "hostile.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump({"state": state_hostile, "federal": federal_hostile}, f, indent=1)
    f.write("\n")
print("state", [(g["name"], len(g["statements"])) for g in golden["state"]],
      "federal", [(g["name"], len(g["statements"]), len(g["aside"])) for g in golden["federal"]],
      "hostile", len(state_hostile), len(federal_hostile))
