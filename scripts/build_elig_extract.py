#!/usr/bin/env python3
"""Write a synthetic eligibility roster as a RightRail eligibility extract (RRELIG01).  Synthetic data only.

Layout: rightrail/conformance/ELIG_EXTRACT_V1.md.  Design: docs/integration/ELIG_EXTRACT_AND_WIRING_DESIGN.md part 1.

The writer states what the roster says and nothing else.  It does not key member ids, pin, sort, decide whether a
roster is fresh, or settle rows that disagree: in RightRail those belong to the reader, the fact store and the gate.
It never writes a file RightRail's reader would refuse: a roster that cannot be written whole is refused whole, with
a named cause and the position of the record, and nothing is written.  No record is dropped or repaired.  An error
never carries a member id or any other field value.

Roster (JSON): `synthetic: true` (required), `sender`, `scope`, `as_of`, `full_roster`, an optional `program` that
states the program of every record that names none, and `records`.  A record is an object.  It must supply
`member_id`, `aid`, `start`, `segment`, `status`, `basis`, `determined` and `notice`, and `program` unless the roster
states one; `end` is optional (none is the open end); `benefit_level` is accepted and dropped.  Dates are
`YYYY-MM-DD`.  A record that lacks a required field is refused (`missing_field`).  The parked builder's array form
`[member_id, aid, benefit_level, start, end]` is not accepted: it carries no status.

**Test mode** (`test_placeholders=True`, `--test-placeholders`): a record may leave out `segment`, `basis`,
`determined` and `notice`, and each gets a stated placeholder, counted in the report: segment = the aid code, a dash
and the start date; basis `G` (regular); determined and notice = the as-of date.  Placeholders are synthetic, not
facts, and the report says the file was made in test mode.  **A missing status is refused in every mode: it never
defaults to eligible.**

**Benefit level has no field in the extract and is dropped** (counted in the report): the eligibility fact carries
none.

The file counter (`fseq`) is the source's own and is passed in; the writer keeps no state.  Not legally verified,
nonpayment, never a production feed.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD_LEN = 120
LAYOUT = "RRELIG01"
OPEN_END = 99991231
STATUS = ("E", "N", "P", "R")  # eligible, not eligible, pending, presumptive
BASIS = ("G", "R", "P", "C")  # regular, retroactive, presumptive, continuous
RECORD_KEYS = frozenset(("member_id", "aid", "start", "end", "segment", "status", "basis", "program", "determined",
                         "notice", "benefit_level"))
REQUIRED = ("member_id", "aid", "start", "segment", "status", "basis", "program", "determined", "notice")
PLACEHOLDERS = ("segment", "basis", "determined", "notice")  # test mode only; never status
MAX_ROWS = 10 ** 9 - 1
MAX_FSEQ = 10 ** 12 - 1


class ExtractRefused(ValueError):
    """The roster cannot be written whole.  `cause` uses the reader's names where the reader has one; `where` is
    "header" or "record N" (counted from 1).  Neither holds a field value."""

    def __init__(self, cause: str, where: str):
        super().__init__(f"{cause} at {where}")
        self.cause, self.where = cause, where


def _text(value, width: int, where: str) -> bytes:
    """Printable ASCII without spaces, never empty, at most `width` bytes; padded with spaces."""
    if not isinstance(value, str):
        raise ExtractRefused("bad_text", where)
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        raise ExtractRefused("bad_text", where) from None
    if not raw or any(c < 0x21 or c > 0x7E for c in raw):
        raise ExtractRefused("bad_text", where)
    if len(raw) > width:
        raise ExtractRefused("too_wide", where)
    return raw.ljust(width)


def _day(value, where: str) -> int:
    """A `YYYY-MM-DD` calendar day, year 1 to 9999, as yyyymmdd."""
    if not isinstance(value, str) or len(value) != 10 or value[4] != "-" or value[7] != "-":
        raise ExtractRefused("bad_date", where)
    y, m, d = value[:4], value[5:7], value[8:]
    if not (y + m + d).isascii() or not (y + m + d).isdigit():
        raise ExtractRefused("bad_date", where)
    try:
        datetime.date(int(y), int(m), int(d))
    except ValueError:
        raise ExtractRefused("bad_date", where) from None
    return int(y + m + d)


def _code(value, allowed: tuple, where: str) -> bytes:
    if value not in allowed:
        raise ExtractRefused("unknown_code", where)
    return value.encode()


def _record(text: bytes) -> bytes:
    return text.ljust(RECORD_LEN) + b"\n"


def build(roster: dict, fseq, test_placeholders: bool = False) -> tuple[bytes, dict]:
    """The extract's bytes and a report of what was written.  `test_placeholders`: test mode (module docstring)."""
    if type(test_placeholders) is not bool:
        raise ExtractRefused("bad_record", "header")
    if not isinstance(roster, dict) or roster.get("synthetic") is not True:
        raise ExtractRefused("not_synthetic", "header")
    if type(fseq) is not int or not 0 <= fseq <= MAX_FSEQ:
        raise ExtractRefused("bad_number", "header")
    if type(roster.get("full_roster")) is not bool:
        raise ExtractRefused("unknown_code", "header")
    records = roster.get("records")
    if not isinstance(records, list):
        raise ExtractRefused("bad_record", "header")
    if len(records) > MAX_ROWS:
        raise ExtractRefused("too_many_rows", "header")
    asof = _day(roster.get("as_of"), "header")
    out = [_record(b"H" + LAYOUT.encode() + _text(roster.get("sender"), 20, "header") + b"%012d" % fseq
                   + b"%08d" % asof + (b"F" if roster["full_roster"] else b"C") + _text(roster.get("scope"), 20, "header"))]
    used = dict.fromkeys(PLACEHOLDERS, 0)
    dropped, seen = 0, set()
    for n, raw in enumerate(records, 1):
        where = f"record {n}"
        if not isinstance(raw, dict) or not set(raw) <= RECORD_KEYS:
            raise ExtractRefused("bad_record", where)
        rec = dict(raw)
        if rec.get("program") is None:  # the roster may state one program for every record that names none
            rec["program"] = roster.get("program")
        for name in REQUIRED:
            if rec.get(name) is None and not (test_placeholders and name in PLACEHOLDERS):
                raise ExtractRefused("missing_field", where)

        def field(name, placeholder):
            if rec.get(name) is None:
                used[name] += 1
                return placeholder
            return rec[name]

        member, aid = _text(rec["member_id"], 20, where), _text(rec["aid"], 10, where)
        start = _day(rec["start"], where)
        end = OPEN_END if rec.get("end") is None else _day(rec["end"], where)
        segment = _text(field("segment", f"{aid.decode().rstrip()}-{start:08d}"), 20, where)
        status, basis = _code(rec["status"], STATUS, where), _code(field("basis", "G"), BASIS, where)
        program = _text(rec["program"], 20, where)
        determined = _day(field("determined", roster["as_of"]), where)
        notice = _day(field("notice", roster["as_of"]), where)
        if start > end:
            raise ExtractRefused("span_backwards", where)
        if determined > asof:
            raise ExtractRefused("determined_after_as_of", where)
        if (member, segment) in seen:  # the statement identity: the member and the segment key
            raise ExtractRefused("duplicate_key", where)
        seen.add((member, segment))
        dropped += rec.get("benefit_level") is not None
        out.append(_record(b"D" + member + segment + status + basis + program + aid + b"%08d%08d%08d%08d"
                           % (start, end, determined, notice)))
    out.append(_record(b"T%09d" % len(records)))
    data = b"".join(out)
    report = {
        "schema": "localbce.elig_extract_report.v1",
        "synthetic": True, "not_legally_verified": True, "nonpayment": True,
        "layout": LAYOUT, "fseq": fseq, "as_of": asof, "cover": "F" if roster["full_roster"] else "C",
        "rows": len(records), "bytes": len(data),
        "file_sha3_512": hashlib.sha3_512(data).hexdigest(),
        "test_placeholders": test_placeholders,
        "placeholders_used": used,
        "benefit_level_dropped": dropped,
    }
    return data, report


def _refused_output(path: Path) -> bool:
    """Nothing is written under rightrail/ or parked/."""
    p = path.resolve()
    return any(p == base or base in p.parents for base in ((ROOT / "rightrail").resolve(), (ROOT / "parked").resolve()))


def _write_atomic(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def main(argv=None) -> int:
    """Exit 0 written; 1 refused (the cause and position are printed, nothing is written); 2 usage."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--roster", required=True, type=Path)
    ap.add_argument("--fseq", required=True, type=int, help="the source's own file counter")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--test-placeholders", action="store_true",
                    help="test mode: fill a missing segment, basis, determined or notice with a stated placeholder")
    args = ap.parse_args(argv)
    outputs = [p for p in (args.out, args.report) if p]
    if any(_refused_output(p) for p in outputs) or len({p.resolve() for p in outputs + [args.roster]}) != len(outputs) + 1:
        print("refused: output path", file=sys.stderr)
        return 2
    try:
        data, report = build(json.loads(args.roster.read_text("utf-8")), args.fseq, args.test_placeholders)
    except ExtractRefused as e:
        print(f"refused: {e.cause} at {e.where}", file=sys.stderr)
        return 1
    _write_atomic(args.out, data)
    if args.report:
        _write_atomic(args.report, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({k: report[k] for k in ("rows", "bytes", "test_placeholders", "placeholders_used", "benefit_level_dropped")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
