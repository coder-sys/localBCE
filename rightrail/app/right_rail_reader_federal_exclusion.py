"""Federal exclusion list reader: the HHS-OIG exclusion list (LEIE, full file or a monthly supplement) to exclusion
fact rows (kind 3, list 1), a list of the rows that give no fact, and the file's receipt (conformance/EXCLUSION_V1.md §2).

The columns and the reading of every field are app/right_rail_reader_leie.py's (its header check and its NPI,
exclusion type, date and text parsers), so a field reads here as it does on the claim path.  The file streams: one
line is held at a time, set-aside entries go to the caller's sink as they are met, and the facts are kept in the
fixed-width readers' SQLite file under the caller's scratch directory, then handed over in file order once the whole
file has passed, because a later repeat of a fact's statement identity can still narrow it.

Only a fault in the file's structure refuses it whole (ReaderError.cause), as a fault the claim path cannot place drops
its whole list: its size, a line too long or with no line end, a header that does not read or lacks a column, a row
that is not UTF-8, does not parse or has the wrong number of cells; a row with no name whose NPI does not read (no
claim can be held for it); and a file with no named row (a full list always names someone).  A field that does not
read is set aside and its row kept without it.  A row with a readable NPI is a fact; its span is the claim path's: from
the exclusion date (else 0001-01-01) to the day before the reinstatement (else open), and from 0001-01-01 with no end
when the row cannot be trusted (no name, no exclusion type, a date after the as-of, a reinstatement on or before its
start).  Every other row is an entry in the set-aside list, for the claim path's hold by name.  A repeat of a fact's
statement identity is an entry too, and the fact takes the most restrictive reading of all its rows: the earliest
start, the latest end (open when any is) and waiver 0 when any row has 0.  A repeat with another NPI refuses the
file: an identity rule that merges providers would leave one of them excluded nowhere.  The sinks' output is the file's only when
the receipt is returned.
"""
from __future__ import annotations

import csv
import hashlib
import re
import sqlite3
from typing import Callable

from app import right_rail_fact_codec as codec
from app.right_rail_fact_registry import OPEN, entry_ok, ident, valid_date
from app.right_rail_reader_fixed import Seen, day_before, part, sid
from app.right_rail_reader_leie import _WANTED, _Bad, _day, _npi, _text, _type
from app.right_rail_reader_lines import BOM, MAX_FILE_BYTES, MAX_LINE_BYTES, ReaderError, ReadResult, csv_header

EXCL = 3
FEDERAL_LIST = 1
# Why a row is set aside: no NPI; an NPI that does not read; no NPI and no exclusion type; no name and no NPI; a
# statement identity already met.  The claim path holds claims by name for 2 and 3.
NO_NPI, NPI_UNREAD, NO_NPI_NO_TYPE, NO_NAME_NO_NPI, REPEATED = 1, 2, 3, 4, 5
_PARSE = {"NPI": _npi, "EXCLTYPE": _type, "EXCLDATE": _day, "REINDATE": _day, "WAIVERDATE": _day}
_WAIVER_READS = {"EXCLTYPE", "EXCLDATE", "REINDATE", "WAIVERDATE", "WVRSTATE"}  # a waiver needs all of them read
_WORD = re.compile(r"[!-~]{1,20}")
_STATE = re.compile(r"[A-Z]{2}")


def _lines(stream, digest):
    """(line number, line without its line end) for each line; the bytes read also go into ``digest``."""
    total, n = 0, -1
    while b := stream.readline(MAX_LINE_BYTES + 2):
        total += len(b)
        if total > MAX_FILE_BYTES:
            raise ReaderError("file_too_large")
        digest.update(b)
        n += 1
        ended = b.endswith(b"\n")
        line = b[:-1] if ended else b
        if line.endswith(b"\r"):
            line = line[:-1]
        if len(line) > MAX_LINE_BYTES:
            raise ReaderError("line_too_long", f"line {n}")
        if not ended:
            raise ReaderError("unterminated_record", f"line {n}")
        yield n, line


def _ymd(iso):
    return int(iso.replace("-", "")) if iso else None


def _aside(n: int, why: int, v: dict) -> bytes:
    """A set-aside entry: line u40, why u8, exclusion type (identifier block of 9), then the last, first, middle and
    business names, each a u16 length and UTF-8 (length 0 when blank or set aside)."""
    out = n.to_bytes(5, "little") + bytes([why]) + ident(9, v["EXCLTYPE"] or "")
    for k in ("LASTNAME", "FIRSTNAME", "MIDNAME", "BUSNAME"):
        b = (v[k] or "").encode()
        out += len(b).to_bytes(2, "little") + b
    return out


def read_federal_exclusion(stream, entry: dict, sink: Callable[[bytes], None], aside: Callable[[bytes], None], *,
                           asof: int, cover: int, fseq: int, sender: str, scope: str, state: str, scratch: str,
                           channel: int, key: int, reader: int) -> bytes:
    """Read one federal exclusion list from the binary ``stream`` and return its receipt.  The file states none of its
    coverage, so the caller does: ``asof`` (yyyymmdd), ``cover`` (1 the full list, 2 a supplement), ``fseq``,
    ``sender`` and ``scope``; ``state`` is the program's two-letter state, whose waivers count.  Fact rows go to
    ``sink`` and set-aside entries to ``aside``, in file order.  Raises ReaderError on any fault, and then nothing
    either sink got belongs to an accepted file."""
    if not (type(asof) is int and valid_date(asof) and cover in (1, 2) and type(fseq) is int and 0 <= fseq < 1 << 64
            and all(isinstance(w, str) and _WORD.fullmatch(w) for w in (sender, scope))
            and isinstance(state, str) and _STATE.fullmatch(state)):
        raise ReaderError("bad_coverage")
    if not entry_ok(entry):  # e.g. one kind named twice, whose identity rule would then be ambiguous
        raise ReaderError("bad_entry")
    ids = dict(entry["ids"]).get(EXCL)
    if ids is None:
        raise ReaderError("kind_not_registered")
    if any(c not in (1, 2, 3, 4) for c in ids):
        raise ReaderError("unknown_identity_field")
    digest = hashlib.sha3_512()
    lines = _lines(stream, digest)
    _, first = next(lines, (0, None))
    if first is None:
        raise ReaderError("no_header")
    header = csv_header(first[len(BOM):] if first.startswith(BOM) else first, ReadResult(""), str.upper)
    if len(set(header)) != len(header) or not set(header) >= set(_WANTED):
        raise ReaderError("bad_header")
    rows = quar = frows = named = 0
    mixed = None  # the first line whose statement identity an earlier row with another NPI has
    with Seen(scratch) as seen:
        db = seen.db
        db.execute("CREATE TABLE f(roff INTEGER PRIMARY KEY, sid BLOB UNIQUE, npi TEXT, type TEXT, vstart INT,"
                   " vstop INT, waiver INT)")
        for n, line in lines:
            if not line.strip():
                continue
            frows += 1
            try:
                cells = next(csv.reader([line.decode("utf-8")], strict=True))
            except UnicodeDecodeError:
                raise ReaderError("not_utf8", f"line {n}") from None
            except (csv.Error, StopIteration):
                raise ReaderError("unparseable", f"line {n}") from None
            if len(cells) != len(header):
                raise ReaderError("column_count", f"line {n}")
            raw, v, unread = dict(zip(header, cells)), {}, set()
            for col in _WANTED:
                try:
                    v[col] = _PARSE.get(col, _text)(raw[col].strip())
                except _Bad:
                    v[col] = None
                    unread.add(col)
            who, npi, blank = v["LASTNAME"] or v["BUSNAME"], v["NPI"], not raw["EXCLTYPE"].strip()
            named += bool(who)
            if not npi:
                if not who and "NPI" in unread:
                    raise ReaderError("unholdable_row", f"line {n}")
                aside(_aside(n, NO_NAME_NO_NPI if not who else NPI_UNREAD if "NPI" in unread
                             else NO_NPI_NO_TYPE if blank else NO_NPI, v))
                quar += 1
                continue
            excl, back, waived = _ymd(v["EXCLDATE"]), _ymd(v["REINDATE"]), _ymd(v["WAIVERDATE"])
            trusted = (who and not blank and not (excl and excl > asof) and not (back and back > asof)
                       and not (back and back <= (excl or 10101)))
            vstart, vstop = (excl or 10101, day_before(back) if back else OPEN) if trusted else (10101, OPEN)
            waiver = int(bool(trusted and not unread & _WAIVER_READS and v["WVRSTATE"] == state and waived and excl
                              and waived <= excl))
            idv = {1: npi.encode(), 2: (v["EXCLTYPE"] or "").encode(), 3: vstart, 4: vstop}
            s = sid(entry["src"], EXCL, [part(idv[c]) for c in ids])
            if db.execute("UPDATE f SET vstart = min(vstart, ?), vstop = max(vstop, ?), waiver = min(waiver, ?)"
                          " WHERE sid = ? AND npi = ?", (vstart, vstop, waiver, s, npi)).rowcount:
                aside(_aside(n, REPEATED, v))
                quar += 1
                continue
            try:
                db.execute("INSERT INTO f VALUES (?, ?, ?, ?, ?, ?, ?)", (n, s, npi, v["EXCLTYPE"] or "", vstart,
                                                                         vstop, waiver))
            except sqlite3.IntegrityError:  # the statement identity is another NPI's
                if mixed is None:
                    mixed = n
        if not named and (cover == 1 or frows):
            raise ReaderError("no_rows")
        if mixed is not None:
            raise ReaderError("identity_merges_npis", f"line {mixed}")
        for n, s, npi, kind, vstart, vstop, waiver in db.execute("SELECT * FROM f ORDER BY roff"):
            sink(codec.encode_fact({"kind": EXCL, "op": 0, "subject": ident(21, npi) + bytes(11), "sid": s,
                                    "vstart": vstart, "vstop": vstop, "until": OPEN, "receipt": 0, "roff": n,
                                    "value": {"list": FEDERAL_LIST, "type": ident(9, kind), "waiver": waiver}}))
            rows += 1
    return codec.encode_receipt({
        "src": entry["src"], "cover": cover, "kb": 0, "asof": asof,
        "cfrom": (0 if entry["cfrom_rule"] == 1 else asof) if cover == 1 else 0, "fseq": fseq,
        "file": digest.digest(), "sender": ident(21, sender), "channel": channel, "key": key, "reader": reader,
        "reread": 0, "rows": rows, "admitted": 0, "same": 0, "quar": quar, "scope": ident(21, scope), "frows": frows})
