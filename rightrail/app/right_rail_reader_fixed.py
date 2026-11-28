"""Fixed-width state files to fact rows: the part every state layout shares (conformance/ELIG_EXTRACT_V1.md §1, §3-§5).

A layout is a table of record positions and code lists; a kind adds a row function that makes one detail row's subject,
span and value and refuses what the kind does not allow.  Framing, field types, the header, the trailer count, the
statement identity, the repeated-identity check, streaming and the receipt are here once.  Every fault refuses the
whole file with a named cause (ReaderError.cause) and nothing is guessed.  The registry entry decides which fields
make a row's statement identity; the layout says what each identity code names.

The file streams: one record is held at a time, fact rows go to the caller's sink as they are made, and the statement
identities met so far live in an SQLite file under the caller's scratch directory with a fixed page cache, so memory
does not grow with the file.  The sink's rows are the file's only when the receipt is returned; on a refusal the caller
drops them.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from datetime import date, timedelta
from typing import Callable, NamedTuple

from app import right_rail_fact_codec as codec
from app.right_rail_fact_registry import OPEN, entry_ok, ident, valid_date
from app.right_rail_reader_lines import MAX_FILE_BYTES, ReaderError

_SID = b"RR/GATE/SID/v1\x00"
_CACHE_KIB = 4096  # the SQLite page cache of the identity set

# The synthetic state's header and trailer, shared by its layouts; a layout may add header fields from byte 70.
HEADER = (("layout", 1, 9, "text"), ("sender", 9, 29, "text"), ("fseq", 29, 41, "number"), ("asof", 41, 49, "date"),
          ("cover", 49, 50, "code"), ("scope", 50, 70, "text"))
TRAILER = (("count", 1, 10, "number"),)
COVER = {b"F": 1, b"C": 2}


class Layout(NamedTuple):
    name: bytes  # the header's layout field
    kind: int  # the fact kind its detail rows state
    record_len: int
    header: tuple  # (name, start, end, type); must hold layout, sender, fseq, asof, cover and scope
    detail: tuple
    trailer: tuple  # must hold count
    codes: dict  # code field -> {raw byte: value}
    identity: dict  # registry identity code -> detail field, or the row's "subject", "vstart" or "vstop"


def day_before(v: int) -> int:
    """The calendar day before the yyyymmdd day ``v``."""
    d = date(v // 10000, v // 100 % 100, v % 100) - timedelta(1)
    return d.year * 10000 + d.month * 100 + d.day


def part(v) -> bytes:
    """An identity field's bytes: text as it is, a date as its eight digits."""
    return v if isinstance(v, bytes) else b"%08d" % v


def sid(src: int, kind: int, fields) -> bytes:
    """The statement identity of design fact-record §2.4: SHA3-256 over the domain, src, kind and length-prefixed fields."""
    return hashlib.sha3_256(_SID + src.to_bytes(2, "little") + bytes([kind])
                            + b"".join(len(f).to_bytes(2, "little") + f for f in fields)).digest()


def _records(stream, n: int, digest):
    """Each record of ``n`` bytes without its line feed, in order; every byte read also goes into ``digest``."""
    total = 0
    while True:
        c = stream.read(n + 1)
        while c and len(c) < n + 1:  # a short read is not the end until a read returns nothing
            more = stream.read(n + 1 - len(c))
            if not more:
                break
            c += more
        if not c:
            return
        total += len(c)
        if total > MAX_FILE_BYTES:
            raise ReaderError("file_too_large")
        digest.update(c)
        i = c.find(b"\n")
        if i == n:
            yield c[:n]
        elif i < 0 and len(c) <= n:
            raise ReaderError("unterminated_record")
        else:
            raise ReaderError("bad_record_length")


def _fields(rec: bytes, spec: tuple, codes: dict, line: int) -> dict:
    out = {}
    for name, a, b, typ in spec:
        raw, where = rec[a:b], f"{name} on line {line}"
        if typ == "text":
            v = raw.rstrip(b" ")
            if not v or any(c < 0x21 or c > 0x7E for c in v):
                raise ReaderError("bad_text", where)
        elif typ == "code":
            v = codes[name].get(raw)
            if v is None:
                raise ReaderError("unknown_code", where)
        elif not raw.isdigit():  # bytes.isdigit is ASCII digits only
            raise ReaderError("bad_date" if typ == "date" else "bad_number", where)
        else:
            v = int(raw)
            if typ == "date" and not valid_date(v):
                raise ReaderError("bad_date", where)
        out[name] = v
    if rec[spec[-1][2]:].strip(b" "):
        raise ReaderError("bad_filler", f"line {line}")
    return out


class Seen:
    """The statement identities met so far, in an SQLite file under ``scratch`` that is removed on exit."""

    def __init__(self, scratch: str):
        fd, self.path = tempfile.mkstemp(prefix="fixed-seen-", suffix=".db", dir=scratch)
        os.close(fd)
        try:
            self.db = sqlite3.connect(self.path, isolation_level=None)
            self.db.executescript(f"PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-{_CACHE_KIB};"
                                  " CREATE TABLE s(k BLOB PRIMARY KEY) WITHOUT ROWID; BEGIN;")
        except BaseException:
            os.remove(self.path)
            raise

    def add(self, k: bytes) -> bool:
        """False when ``k`` was already met."""
        try:
            self.db.execute("INSERT INTO s VALUES (?)", (k,))
        except sqlite3.IntegrityError:
            return False
        return True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            self.db.close()
        finally:
            os.remove(self.path)


Row = Callable[[dict, dict, bytes], tuple]  # (header, detail fields, raw record) -> (subject, vstart, vstop, value)


def read_fixed(stream, entry: dict, layout: Layout, row: Row, sink: Callable[[bytes], None], *, scratch: str,
               channel: int, key: int, reader: int) -> bytes:
    """Read one file from the binary ``stream`` under the source's registry entry and return its receipt.  Each fact
    row goes to ``sink`` in file order; ``row`` makes its subject, span and value or raises ReaderError.  ``scratch`` is
    a directory for the identity set; ``channel``, ``key`` and ``reader`` are the receipt fields the file cannot state.
    Raises ReaderError on any fault, and then nothing the sink got belongs to an accepted file."""
    if not entry_ok(entry):  # e.g. one kind named twice, whose identity rule would then be ambiguous
        raise ReaderError("bad_entry")
    ids = dict(entry["ids"]).get(layout.kind)
    if ids is None:
        raise ReaderError("kind_not_registered")
    if any(c not in layout.identity for c in ids):
        raise ReaderError("unknown_identity_field")
    digest = hashlib.sha3_512()
    recs = _records(stream, layout.record_len, digest)
    first = next(recs, None)
    if first is None:
        raise ReaderError("unterminated_record")  # an empty file
    if first[:1] != b"H":
        raise ReaderError("no_header")
    h = _fields(first, layout.header, layout.codes, 0)
    if h["layout"] != layout.name:
        raise ReaderError("unknown_layout")
    rows, count = 0, None
    with Seen(scratch) as seen:
        for n, rec in enumerate(recs, 1):
            if count is not None or rec[:1] not in (b"D", b"T"):
                raise ReaderError("unknown_record_type", f"line {n}")
            if rec[:1] == b"T":
                count = _fields(rec, layout.trailer, layout.codes, n)["count"]
                continue
            d = _fields(rec, layout.detail, layout.codes, n)
            try:
                d["subject"], d["vstart"], d["vstop"], value = row(h, d, rec)
            except ReaderError as e:
                raise ReaderError(e.cause, f"line {n}") from None
            s = sid(entry["src"], layout.kind, [part(d[layout.identity[c]]) for c in ids])
            if not seen.add(s):
                raise ReaderError("duplicate_key", f"line {n}")
            sink(codec.encode_fact({"kind": layout.kind, "op": 0, "subject": d["subject"], "sid": s,
                                    "vstart": d["vstart"], "vstop": d["vstop"], "until": OPEN, "receipt": 0, "roff": n,
                                    "value": value}))
            rows += 1
    if count is None:
        raise ReaderError("no_trailer")
    if count != rows:
        raise ReaderError("count_mismatch")
    full = h["cover"] == 1
    return codec.encode_receipt({
        "src": entry["src"], "cover": h["cover"], "kb": 0, "asof": h["asof"],
        "cfrom": (0 if entry["cfrom_rule"] == 1 else h["asof"]) if full else 0, "fseq": h["fseq"],
        "file": digest.digest(), "sender": ident(21, h["sender"].decode()), "channel": channel, "key": key,
        "reader": reader, "reread": 0, "rows": rows, "admitted": 0, "same": 0, "quar": 0,
        "scope": ident(21, h["scope"].decode()), "frows": rows})
