"""Pieces shared by the fixed-width reader vector generators (ELIG, state death, provider death, exclusion): the trailer
row, the encoder, synthetic NPIs, the framing refusals, the single-fault helpers, the call into a reader or verifier, and the golden and hostile files they write."""
import io
import json
import os
import sys
from tempfile import TemporaryDirectory

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TREE)
from app import right_rail_fact_registry as reg  # noqa: E402
from app.right_rail_reader_leie import npi_ok  # noqa: E402

SECRET = "synthetic-tenant-secret-0001"
TRANSPORT = {"channel": 1, "key": 0, "reader": 1}


def T(n):
    return f"T{n:09d}".ljust(120)


def blob(recs):
    return ("\n".join(recs) + "\n").encode("latin-1")


def sub(recs, i, at, new):
    recs = list(recs)
    recs[i] = recs[i][:at] + new + recs[i][at + len(new):]
    return recs


def case(name, cause, data, over=None):
    return {"name": name, "cause": cause, "data": data.decode("latin-1"), **({"entry": over} if over else {})}


def npi(n):
    """A ten-digit number 19999 + n + its check digit."""
    base = f"19999{n:04d}"
    return next(base + d for d in "0123456789" if npi_ok(base + d))


def bad_npi(n):
    """npi(n) with its check digit one off."""
    good = npi(n)
    return good[:-1] + str((int(good[-1]) + 1) % 10)


def framing(F):
    """The must-refuse cases of the fixed-width framing, for a file F of a header, detail rows and a trailer."""
    return [
        case("empty file", "unterminated_record", b""),
        case("no final line feed", "unterminated_record", blob(F)[:-1]),
        case("carriage returns", "bad_record_length", ("\r\n".join(F) + "\r\n").encode()),
        case("row one byte short", "bad_record_length", blob(F[:2] + [F[2][:119]] + F[3:])),
        case("row of 130 bytes", "bad_record_length", blob(F[:2] + [F[2] + "X" * 10] + F[3:])),
        case("first record a row", "no_header", blob(F[1:])),
        case("no trailer", "no_trailer", blob(F[:-1])),
        case("second trailer", "unknown_record_type", blob(F + [F[-1]])),
        case("unknown record type", "unknown_record_type", blob(sub(F, 3, 0, "X"))),
    ]


def call(fn, data, base, over=None):
    e = {**base, **(over or {})}
    e["kinds"] = reg.mask_of(e["ids"])
    e["scope"], e["name"] = reg.ident(21, e["scope"]), reg.ident(31, e["name"])
    rows = []
    with TemporaryDirectory(dir=os.environ.get("E3_SCRATCH")) as tmp:
        receipt = fn(io.BytesIO(data), SECRET.encode(), e, rows.append, scratch=tmp, **TRANSPORT)
    return rows, receipt


def both(readers, data, base, over=None):
    a = call(readers[0], data, base, over)
    assert a == call(readers[1], data, base, over), "reader and verifier differ"
    return a


def write(out, golden_files, hostile, readers, base):
    """Write the golden files (name, records), refuse-check every hostile case in both readers, write the two json files."""
    os.makedirs(out, exist_ok=True)
    golden = {"secret": SECRET, "entry": base, "transport": TRANSPORT, "files": []}
    for name, recs in golden_files:
        data = blob(recs)
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        rows, receipt = both(readers, data, base)
        golden["files"].append({"name": name, "statements": [s.hex() for s in rows], "receipt": receipt.hex()})
    for c in hostile:
        for fn in readers:
            try:
                call(fn, c["data"].encode("latin-1"), base, c.get("entry"))
            except Exception as e:  # noqa: BLE001
                got = getattr(e, "cause", repr(e))
            else:
                got = "accepted"
            assert got == c["cause"], (c["name"], fn.__name__, got)
    for name, doc in (("golden.json", golden), ("hostile.json", hostile)):
        with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
    print("golden", [(g["name"], len(g["statements"])) for g in golden["files"]], "hostile", len(hostile))
