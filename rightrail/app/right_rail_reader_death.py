"""Enrollee death file reader: a fixed-width death record file to source facts.

The layout is the public Social Security Administration Death Master File record, held in one table (DMF_LAYOUT) that a
state vital-records layout can replace. The reader never outputs a raw SSN. It keeps a SHA3-256 key lookup of the SSN
under a key the tenant supplies, with the name fields, dates, verification code, source hash and byte offset.

A date with a zero month or day is kept as partial, with its precision, and is never filled in. The file covers only
what its source and as-of date say: a member who is not in it is not known to be alive. Repairs are the fixed
list in right_rail_reader_lines; a bad field is set aside with a cause, a bad record is set aside whole. A record
shorter than the layout is padded with spaces and recorded as a repair; a field cut short then fails its own check.
A file with no readable record claims no coverage. The whole file is held in memory; it must stream before it is
wired in.
"""

import re

import hashlib
from datetime import date
from typing import NamedTuple

from app.right_rail_reader_lines import Finding, Quarantine, ReaderError, ReadResult, lines, open_source


class Layout(NamedTuple):
    fields: tuple  # (name, start, end) with zero-based start and end-exclusive byte positions
    record_len: int  # bytes after the last field up to here are filler


# Positions and the 100-byte record follow the published SSA layouts (2001 and November 2011 specifications).
DMF_LAYOUT = Layout((
    ("update_code", 0, 1), ("ssn", 1, 10), ("last_name", 10, 30), ("suffix", 30, 34), ("first_name", 34, 49),
    ("middle_name", 49, 64), ("verification", 64, 65), ("death_date", 65, 73), ("birth_date", 73, 81)), 100)

_CODES = {"update_code": {b" ": "", b"A": "A", b"C": "C", b"D": "D"}, "verification": {b" ": "", b"V": "V", b"P": "P", b"N": "N"}}


class PartialDate(NamedTuple):
    year: int
    month: int  # 0 when unknown
    day: int  # 0 when unknown
    precision: str  # "day", "month" or "year"


class Coverage(NamedTuple):
    source: str
    as_of: str  # YYYY-MM-DD


class DeathRow(NamedTuple):
    ssn_hash: str  # SHA3-256 hex of the tenant key and the SSN digits
    update_code: str | None
    last_name: str | None
    suffix: str | None
    first_name: str | None
    middle_name: str | None
    verification: str | None
    death_date: PartialDate | None
    birth_date: PartialDate | None
    source_sha3_512: str
    offset: int


_ISO = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_RANK = {"day": 3, "month": 2, "year": 1}


class _Bad(Exception):
    pass


def ssn_hash(key: bytes, ssn: str) -> str:
    """The key lookup for one SSN (nine digits). Callers hash their own members the same way."""
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("tenant key must be at least 16 bytes")
    if len(ssn) != 9 or not ssn.isascii() or not ssn.isdigit():
        raise ValueError("ssn must be nine digits")
    return hashlib.sha3_256(len(key).to_bytes(2, "big") + key + ssn.encode()).hexdigest()


def _name(raw: bytes):
    try:
        s = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise _Bad("bad_text") from None
    if not s.isprintable():
        raise _Bad("bad_text")
    return s or None


def _partial(raw: bytes):
    if not raw.strip():
        return None
    if len(raw) != 8 or not raw.isdigit():
        raise _Bad("bad_date")
    m, d, y = int(raw[:2]), int(raw[2:4]), int(raw[4:])
    if y == 0 or m > 12 or d > 31:
        raise _Bad("bad_date")
    if m == 0:
        if d:
            raise _Bad("bad_date")
        return PartialDate(y, 0, 0, "year")
    if d == 0:
        return PartialDate(y, m, 0, "month")
    try:
        date(y, m, d)
    except ValueError:
        raise _Bad("bad_date") from None
    return PartialDate(y, m, d, "day")


def read_death(data: bytes, key: bytes, *, source: str, as_of: str, layout: Layout = DMF_LAYOUT,
               expected_sha3_512: str | None = None) -> ReadResult:
    """One record per line. source and as_of state what the file covers; as_of is YYYY-MM-DD."""
    if not isinstance(source, str) or not source or not isinstance(as_of, str) or not _ISO.fullmatch(as_of):
        raise ReaderError("bad_coverage", "source and as_of (YYYY-MM-DD) are required")
    try:
        limit = date.fromisoformat(as_of)
    except ValueError:
        raise ReaderError("bad_coverage", "as_of must be a real date") from None
    limit = (limit.year, limit.month, limit.day)
    ssn_hash(key, "000000000")  # validates the key
    res = open_source(data, expected_sha3_512)
    res.coverage = Coverage(source, as_of)
    min_len = max(end for _, _, end in layout.fields)
    padded = short = 0
    seen = {}
    for off, line in lines(data, res):
        if line is None:
            continue
        if not line.strip():
            res.quarantined.append(Quarantine(off, None, "blank_record"))
            continue
        if len(line) < min_len:
            line = line.ljust(min_len)
            short += 1
        if len(line) > layout.record_len:
            if line[layout.record_len:].strip():
                res.quarantined.append(Quarantine(off, None, "record_too_long"))
                continue
            padded += 1
        raw = {name: line[a:b] for name, a, b in layout.fields}
        digits = raw.get("ssn", b"")
        if len(digits) != 9 or not digits.isdigit():
            res.quarantined.append(Quarantine(off, None, "bad_ssn"))
            continue
        vals = dict.fromkeys(DeathRow._fields)
        for name, value in raw.items():
            if name == "ssn":
                continue
            try:
                if name in _CODES:
                    vals[name] = _CODES[name].get(value)
                    if vals[name] is None:
                        raise _Bad("bad_code")
                else:
                    vals[name] = (_partial if name.endswith("_date") else _name)(value)
            except _Bad as e:
                res.quarantined.append(Quarantine(off, name, str(e)))
        vals.update(ssn_hash=ssn_hash(key, digits.decode()), source_sha3_512=res.source_sha3_512, offset=off)
        row = DeathRow(**vals)
        res.rows.append(row)
        dod, dob = row.death_date, row.birth_date
        if dod and dob and dod[:min(_RANK[dod[3]], _RANK[dob[3]])] < dob[:min(_RANK[dod[3]], _RANK[dob[3]])]:
            res.findings.append(Finding("death_before_birth", off, ""))
        if dod and dod[:_RANK[dod[3]]] > limit[:_RANK[dod[3]]]:
            res.findings.append(Finding("death_after_as_of", off, ""))
        first = seen.setdefault(row.ssn_hash, row)
        if first is not row:
            same = first[:-1] == row[:-1]
            res.findings.append(Finding("duplicate_record" if same else "conflicting_duplicate", off,
                                        f"same person as {first.offset}"))
    res.repair("padding", padded)
    res.repair("short_record_padded", short)
    if not res.rows:
        res.coverage = None  # nothing was read, so nothing is known
    return res
