"""Electronic visit verification reader: home-care visit records to typed source facts.

Each visit carries the six data points the 21st Century Cures Act (section 12006) requires: the type of service, the
person receiving it, the date, the location, the person providing it, and the start and end times. The reader turns CSV
or JSON-lines records into typed rows and attaches the four checks the Office of Inspector General names for this data
as findings on rows, never as refusals: a missing data point; an end before the start or a visit over 24 hours;
overlapping visits for one caregiver; and a visit outside the member's coverage. The coverage check needs a lookup
supplied by the caller. Without one the finding is "coverage_unknown"; it is never "not covered".

Repairs are the fixed list in right_rail_reader_lines. A bad field is set aside with a cause and the row is kept with
that point missing; a record that cannot be read is set aside whole; a value is never guessed. Times must carry an
explicit offset. Latitude and longitude are fixed-point integers in millionths of a degree; more than six decimals
is set aside, never rounded. Records are one per line (no line breaks inside a quoted field). A last line with no line feed may be cut short and
is set aside. Column names are matched without regard to case. The whole file is held in memory; it must stream
before it is wired in.
"""

import csv
from datetime import date, datetime, timedelta, timezone
import json
import re
from typing import Callable, NamedTuple

from app.right_rail_reader_lines import Finding, Quarantine, ReaderError, ReadResult, csv_header, is_clean, lines, open_source

REQUIRED = {"member_id", "provider_id", "service_code", "visit_date", "start", "end"}
COLUMNS = ("member_id", "provider_id", "service_code", "visit_date", "start", "end", "latitude", "longitude", "address")
MAX_VISIT_SECONDS = 24 * 3600
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_TIME = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})(Z|[+-][0-9]{2}:[0-9]{2})\Z")
_COORD = re.compile(r"(-?)([0-9]{1,3})(?:\.([0-9]{1,6}))?\Z")


class EvvRow(NamedTuple):
    member_id: str | None
    provider_id: str | None
    service_code: str | None
    visit_date: str | None  # YYYY-MM-DD
    start_s: int | None  # UTC seconds since 1970
    start_offset_min: int | None
    end_s: int | None
    end_offset_min: int | None
    lat_e6: int | None
    lon_e6: int | None
    address: str | None
    source_sha3_512: str
    offset: int


class _Bad(Exception):
    pass


class _Number(str):
    """A JSON number written with a fraction or exponent; fine for a coordinate, never an identifier."""


def _text(v):
    if isinstance(v, _Number):
        raise _Bad("non_integer_number")
    if not isinstance(v, str) or not 1 <= len(v) <= 256 or not is_clean(v):
        raise _Bad("bad_text")
    return v


def _day(v):
    if not isinstance(v, str) or not _DATE.match(v):
        raise _Bad("bad_date")
    try:
        date.fromisoformat(v)
    except ValueError:
        raise _Bad("bad_date") from None
    return v


def _moment(v):
    m = _TIME.match(v) if isinstance(v, str) else None
    if not m:
        raise _Bad("bad_time")
    zone = m.group(3)
    minutes = 0 if zone == "Z" else (1 if zone[0] == "+" else -1) * (int(zone[1:3]) * 60 + int(zone[4:6]))
    if abs(minutes) > 14 * 60 or (zone != "Z" and int(zone[4:6]) > 59):
        raise _Bad("bad_time")
    try:
        d = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}").replace(tzinfo=timezone(timedelta(minutes=minutes)))
    except ValueError:
        raise _Bad("bad_time") from None
    return int(d.timestamp()), minutes


def _coord(v, limit):
    m = _COORD.match(v) if isinstance(v, str) else None
    if not m:
        raise _Bad("bad_coordinate")
    e6 = int(m.group(2)) * 1_000_000 + int((m.group(3) or "").ljust(6, "0"))
    if e6 > limit * 1_000_000:
        raise _Bad("bad_coordinate")
    return -e6 if m.group(1) else e6


def _no_dups(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _Bad("duplicate_key")
        out[k] = v
    return out


def read_evv(data: bytes, fmt: str, *, coverage: Callable[[str, str], bool | None] | None = None,
             expected_sha3_512: str | None = None) -> ReadResult:
    """fmt is "csv" (first line is a header naming columns) or "jsonl". coverage(member_id, visit_date) returns
    True, False or None (unknown)."""
    if fmt not in ("csv", "jsonl"):
        raise ValueError("fmt must be csv or jsonl")
    res = open_source(data, expected_sha3_512)
    header = None
    padded = 0
    for off, line in lines(data, res):
        if fmt == "csv" and header is None:
            header = csv_header(line, res, str.lower)
            if len(set(header)) != len(header) or not set(header) >= REQUIRED or not (
                    "address" in header or {"latitude", "longitude"} <= set(header)):
                raise ReaderError("bad_header")
            continue
        if line is None:
            continue
        if not line.strip():
            res.quarantined.append(Quarantine(off, None, "blank_record"))
            continue
        try:
            text = line.decode("utf-8")
            if fmt == "csv":
                cells = next(csv.reader([text], strict=True))
                if len(cells) != len(header):
                    raise _Bad("column_count")
                rec = dict(zip(header, cells))
            else:
                rec = json.loads(text, object_pairs_hook=_no_dups, parse_float=_Number)
                if not isinstance(rec, dict):
                    raise _Bad("not_an_object")
            if not set(rec) & set(COLUMNS):
                raise _Bad("no_known_field")
        except _Bad as e:
            res.quarantined.append(Quarantine(off, None, str(e)))
            continue
        except UnicodeDecodeError:
            res.quarantined.append(Quarantine(off, None, "not_utf8"))
            continue
        except (csv.Error, ValueError, RecursionError):
            res.quarantined.append(Quarantine(off, None, "unparseable"))
            continue
        vals = {}
        for name in COLUMNS:
            v = rec.get(name)
            if isinstance(v, int) and not isinstance(v, bool):
                v = str(v)
            if isinstance(v, str) and not isinstance(v, _Number):
                s = v.strip()
                padded += s != v
                v = s
            if v is None or v == "":
                continue
            try:
                if name in ("member_id", "provider_id", "service_code", "address"):
                    vals[name] = _text(v)
                elif name == "visit_date":
                    vals[name] = _day(v)
                elif name in ("start", "end"):
                    vals[name] = _moment(v)
                else:
                    vals[name] = _coord(v, 90 if name == "latitude" else 180)
            except _Bad as e:
                res.quarantined.append(Quarantine(off, name, str(e)))
        st, en = vals.get("start"), vals.get("end")
        res.rows.append(EvvRow(
            vals.get("member_id"), vals.get("provider_id"), vals.get("service_code"), vals.get("visit_date"),
            st and st[0], st and st[1], en and en[0], en and en[1],
            vals.get("latitude"), vals.get("longitude"), vals.get("address"), res.source_sha3_512, off))
    if fmt == "csv" and header is None:
        raise ReaderError("no_header")
    res.repair("padding", padded)
    _check(res, coverage)
    return res


def _check(res: ReadResult, coverage) -> None:
    out = res.findings
    seen = {}
    by_provider = {}
    for r in res.rows:
        missing = [n for n, ok in (
            ("service", r.service_code), ("member", r.member_id), ("date", r.visit_date),
            ("location", (r.lat_e6 is not None and r.lon_e6 is not None) or r.address),
            ("provider", r.provider_id), ("start", r.start_s is not None), ("end", r.end_s is not None)) if not ok]
        if missing:
            out.append(Finding("missing_data_point", r.offset, ",".join(missing)))
        if r.start_s is not None and r.end_s is not None:
            if r.end_s < r.start_s:
                out.append(Finding("end_before_start", r.offset, ""))
            elif r.end_s - r.start_s > MAX_VISIT_SECONDS:
                out.append(Finding("over_24h", r.offset, ""))
        if r.member_id and r.visit_date:
            covered = coverage(r.member_id, r.visit_date) if coverage else None
            if covered is None:
                out.append(Finding("coverage_unknown", r.offset, ""))
            elif not covered:
                out.append(Finding("outside_coverage", r.offset, ""))
        key = r[:11]
        if key in seen:
            out.append(Finding("duplicate_row", r.offset, f"same as {seen[key]}"))
            continue
        seen[key] = r.offset
        if r.provider_id and r.start_s is not None and r.end_s is not None and r.end_s >= r.start_s:
            by_provider.setdefault(r.provider_id, []).append((r.start_s, r.end_s, r.offset))
    for visits in by_provider.values():
        visits.sort()
        top_end, top_off = visits[0][1], visits[0][2]
        for s, e, o in visits[1:]:
            if s < top_end:
                out.append(Finding("overlap", o, f"with {top_off}"))
            if e > top_end:
                top_end, top_off = e, o
    out.sort(key=lambda f: (f.offset, f.kind))
