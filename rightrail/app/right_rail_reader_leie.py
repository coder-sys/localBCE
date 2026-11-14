"""Exclusion list reader: the HHS-OIG List of Excluded Individuals/Entities (LEIE) monthly file to source facts.

Input is the full file (UPDATED.csv) or one of the monthly supplements (new exclusions, or reinstatements); all three
share the column layout in LEIE_COLUMNS. The header row names the columns and is matched without regard to case.
Each row is an individual (has a last name) or an entity (business name only), with its exclusion type kept as text
(a statute code such as 1128a1, of a known shape), its dates as YYYY-MM-DD, and its NPI (10 digits, check digit validated). None is written 0 in the live file
(also accepted: 00000000 and 0000000000, or blank); it is never a match key. A bad field is set aside with a cause and the row is
kept with that value missing; a row with no name or no exclusion type is set aside whole. Nothing is guessed.
Findings: a missing exclusion date, reinstatement before exclusion, exclusion, reinstatement or waiver after the as-of date, waiver without a state, a duplicate row, one NPI under two names, and a supplement
row that does not fit its file kind.

A file with a header and no records is read correctly as empty and keeps its coverage; one whose records
are all set aside claims none.

Absence is not clearance: many listed parties carry no NPI, and a supplement is a change file, so it says nothing about
who is not on it. Who is excluded on a date is the gate engine's rule (PROVIDER_EXCLUDED), not this reader's.
Repairs are the fixed list in right_rail_reader_lines. The whole file is held in memory; it must stream before it
is wired in.
"""

import csv
from datetime import date
import re
from typing import NamedTuple

from app.right_rail_reader_lines import Finding, Quarantine, ReaderError, ReadResult, csv_header, is_clean, lines, open_source

# Column names as published by OIG; checked 2026-11-09 against the header row of the live UPDATED.csv.
LEIE_COLUMNS = (
    "LASTNAME", "FIRSTNAME", "MIDNAME", "BUSNAME", "GENERAL", "SPECIALTY", "UPIN", "NPI", "DOB", "ADDRESS", "CITY",
    "STATE", "ZIP", "EXCLTYPE", "EXCLDATE", "REINDATE", "WAIVERDATE", "WVRSTATE")
_WANTED = ("LASTNAME", "FIRSTNAME", "MIDNAME", "BUSNAME", "NPI", "EXCLTYPE", "EXCLDATE", "REINDATE", "WAIVERDATE", "WVRSTATE")
KINDS = ("full", "exclusions", "reinstatements")
_ISO = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_NPI = re.compile(r"[0-9]{10}\Z")
_NONE_NPI = ("", "0", "0000000000")
_NONE_DAY = ("", "0", "00000000")
_DAY = re.compile(r"[0-9]{8}\Z")
# Statute codes seen in the live file: section 1128(a) and (b) paragraphs, 1128Aa, 1156, 1160, breach of an agreement.
_TYPE = re.compile(r"1128[ab][0-9]{1,2}|1128Aa|11[3-9][0-9]|BRCH (CIA|SA)")


class Coverage(NamedTuple):
    source: str
    as_of: str  # YYYY-MM-DD
    kind: str  # full, exclusions or reinstatements


class LeieRow(NamedTuple):
    who: str  # "individual" or "entity"
    last_name: str | None
    first_name: str | None
    middle_name: str | None
    business_name: str | None
    npi: str | None
    exclusion_type: str | None  # None when the code is not a known shape
    exclusion_date: str | None  # YYYY-MM-DD
    reinstatement_date: str | None
    waiver_date: str | None
    waiver_state: str | None
    status: str  # "reinstated" when the reinstatement date is on or before the file's as-of date, else "excluded"
    source_sha3_512: str
    offset: int


class _Bad(Exception):
    pass


def npi_ok(npi: str) -> bool:
    """Ten digits whose Luhn sum with the 80840 prefix is a multiple of ten."""
    if not _NPI.match(npi):
        return False
    total = 0
    for i, c in enumerate(reversed("80840" + npi)):
        d = int(c) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def _text(v):
    if len(v) > 256 or not is_clean(v):
        raise _Bad("bad_text")
    return v or None


def _type(v):
    if v and not _TYPE.fullmatch(v):
        raise _Bad("unknown_exclusion_type")
    return v or None


def _npi(v):
    if v in _NONE_NPI:
        return None
    if not npi_ok(v):
        raise _Bad("bad_npi")
    return v


def _day(v):
    if v in _NONE_DAY:
        return None
    if not _DAY.match(v):
        raise _Bad("bad_date")
    try:
        return date(int(v[:4]), int(v[4:6]), int(v[6:])).isoformat()
    except ValueError:
        raise _Bad("bad_date") from None


def read_leie(data: bytes, *, source: str, as_of: str, kind: str = "full",
              expected_sha3_512: str | None = None) -> ReadResult:
    """source and as_of state what the file covers; as_of is YYYY-MM-DD. kind is "full", "exclusions" or "reinstatements"."""
    if not isinstance(source, str) or not source or not isinstance(as_of, str) or not _ISO.match(as_of) or kind not in KINDS:
        raise ReaderError("bad_coverage", "source, as_of (YYYY-MM-DD) and a known kind are required")
    try:
        date.fromisoformat(as_of)
    except ValueError:
        raise ReaderError("bad_coverage", "as_of must be a real date") from None
    res = open_source(data, expected_sha3_512)
    res.coverage = Coverage(source, as_of, kind)
    header = None
    padded = 0
    for off, line in lines(data, res):
        if header is None:
            header = csv_header(line, res, str.upper)
            if len(set(header)) != len(header) or not set(header) >= set(_WANTED):
                raise ReaderError("bad_header")
            continue
        if line is None:
            continue
        if not line.strip():
            res.quarantined.append(Quarantine(off, cause="blank_record", field=None))
            continue
        try:
            cells = next(csv.reader([line.decode("utf-8")], strict=True))
        except UnicodeDecodeError:
            res.quarantined.append(Quarantine(off, None, "not_utf8"))
            continue
        except (csv.Error, StopIteration):
            res.quarantined.append(Quarantine(off, None, "unparseable"))
            continue
        if len(cells) != len(header):
            res.quarantined.append(Quarantine(off, None, "column_count"))
            continue
        raw = dict(zip(header, cells))
        vals = {}
        for name in _WANTED:
            s = raw[name].strip()
            padded += s != raw[name]
            try:
                if name == "NPI":
                    vals[name] = _npi(s)
                elif name == "EXCLTYPE":
                    vals[name] = _type(s)
                elif name.endswith("DATE"):
                    vals[name] = _day(s)
                else:
                    vals[name] = _text(s)
            except _Bad as e:
                vals[name] = None
                res.quarantined.append(Quarantine(off, name.lower(), str(e)))
        if not vals["LASTNAME"] and not vals["BUSNAME"]:
            res.quarantined.append(Quarantine(off, None, "no_name"))
            continue
        if not raw["EXCLTYPE"].strip():
            res.quarantined.append(Quarantine(off, None, "no_exclusion_type"))
            continue
        row = LeieRow("individual" if vals["LASTNAME"] else "entity", vals["LASTNAME"], vals["FIRSTNAME"],
                      vals["MIDNAME"], vals["BUSNAME"], vals["NPI"], vals["EXCLTYPE"], vals["EXCLDATE"],
                      vals["REINDATE"], vals["WAIVERDATE"], vals["WVRSTATE"],
                      "reinstated" if vals["REINDATE"] and vals["REINDATE"] <= as_of else "excluded", res.source_sha3_512, off)
        res.rows.append(row)
        if row.reinstatement_date and row.exclusion_date and row.reinstatement_date < row.exclusion_date:
            res.findings.append(Finding("reinstated_before_excluded", off, ""))
        if not row.exclusion_date:
            res.findings.append(Finding("exclusion_date_missing", off, ""))
        elif row.exclusion_date > as_of:
            res.findings.append(Finding("excluded_after_as_of", off, ""))
        for what, day in (("reinstated", row.reinstatement_date), ("waiver", row.waiver_date)):
            if day and day > as_of:
                res.findings.append(Finding(f"{what}_after_as_of", off, ""))
        if row.waiver_date and not row.waiver_state:
            res.findings.append(Finding("waiver_without_state", off, ""))
        if kind == "exclusions" and row.reinstatement_date:
            res.findings.append(Finding("reinstated_in_exclusion_file", off, ""))
        if kind == "reinstatements" and not row.reinstatement_date:
            res.findings.append(Finding("no_reinstatement_in_reinstatement_file", off, ""))
    if header is None:
        raise ReaderError("no_header")
    res.repair("padding", padded)
    seen, owner = {}, {}
    for r in res.rows:  # both rows are kept; the second is flagged
        if seen.setdefault(r[:-2], r.offset) != r.offset:
            res.findings.append(Finding("duplicate_row", r.offset, f"same as {seen[r[:-2]]}"))
        elif r.npi and owner.setdefault(r.npi, (r.offset, r[1:5]))[1] != r[1:5]:
            res.findings.append(Finding("npi_two_names", r.offset, f"same NPI as {owner[r.npi][0]}"))
    res.findings.sort(key=lambda f: (f.offset, f.kind))
    if not res.rows and res.quarantined:
        res.coverage = None  # records were there and none could be read, so nothing is known
    return res
