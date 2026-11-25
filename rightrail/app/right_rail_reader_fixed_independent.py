"""Independent verifier for the fixed-width state files, written from conformance/ELIG_EXTRACT_V1.md §1, §3-§5 alone.

It shares only the fact codec with app/right_rail_reader_fixed.py.  Its framing reads one line at a time (at most 122
bytes), each record type is a regular expression, dates are checked with the standard calendar, and it makes the
statement identity and identifier blocks itself.  A repeated statement identity is found with an external merge sort
under the caller's scratch directory, so memory does not grow with the file.  A kind's verifier gives the pattern of the
rest of its header and a function from one detail record to its fact row; verify_fixed does the rest, or raises Refused
with the spec's cause.
"""
from __future__ import annotations

import functools
import hashlib
import heapq
import os
import re
import tempfile
from datetime import date

from app import right_rail_fact_codec as codec

_HEAD = re.compile(rb"H(.{8})(.{20})(.{12})(.{8})(.)(.{20})(.*)", re.S)
_TAIL = re.compile(rb"T(.{9})(.*)", re.S)
_TEXT = re.compile(rb"([\x21-\x7e]+) *")
_DIGITS = re.compile(rb"[0-9]+")
_COVER = {b"F": 1, b"C": 2}
_MAX_BYTES = 1 << 30
_RUN, _FAN = 1 << 16, 16  # identities sorted in memory at a time; sorted runs merged at a time


class Refused(Exception):
    def __init__(self, cause: str):
        super().__init__(cause)
        self.cause = cause


def text(b: bytes) -> bytes:
    m = _TEXT.fullmatch(b)
    if not m:
        raise Refused("bad_text")
    return m.group(1)


def num(b: bytes) -> int:
    if not _DIGITS.fullmatch(b):
        raise Refused("bad_number")
    return int(b)


def day(b: bytes) -> int:
    if not _DIGITS.fullmatch(b):
        raise Refused("bad_date")
    try:
        date(int(b[:4]), int(b[4:6]), int(b[6:]))
    except ValueError:
        raise Refused("bad_date") from None
    return int(b)


def code(table: dict, b: bytes) -> int:
    if b not in table:
        raise Refused("unknown_code")
    return table[b]


def filler(b: bytes) -> None:
    if b != b" " * len(b):
        raise Refused("bad_filler")


def mkey(secret: bytes, member: bytes) -> bytes:
    """The keyed member key of a claim line."""
    return hashlib.sha3_256(len(secret).to_bytes(2, "big") + secret + b"RR/GATE/MEMBER-KEY/v1\x00" + member).digest()


def block(t: bytes, w: int = 21) -> bytes:
    """An identifier block of ``w`` bytes: the length, the text, zeros."""
    return bytes([len(t)]) + t + bytes(w - 1 - len(t))


def entry_sound(e: dict) -> bool:
    """The registry's rule for one source entry: a source number, identifier blocks for scope and name, class 1-5,
    flags of 0 or 1, at most 50 dropped, sequence rule 1 or 2 (2 when gapless), and each kind 1-63 named once, in
    rising order, with at least one identity code and the kind mask to match."""
    def is_block(b):
        return len(b) > b[0] and b[1 + b[0]:] == bytes(len(b) - 1 - b[0])

    kinds = [k for k, _ in e["ids"]]
    if any(not 1 <= k <= 63 for k in kinds) or kinds != sorted(set(kinds)) or not all(c for _, c in e["ids"]):
        return False
    return (e["src"] > 0 and is_block(e["scope"]) and is_block(e["name"]) and e["cls"] in range(1, 6)
            and max(e["gapless"], e["oneper"], e["full"], e["cfrom_rule"]) <= 1 and e["drop"] <= 50
            and e["fseq_rule"] in (1, 2) and (not e["gapless"] or e["fseq_rule"] == 2)
            and e["kinds"] == sum(1 << k for k in kinds))


def records(path: str, w: int):
    """The ``w``-byte records of the file at ``path``, in order."""
    with open(path, "rb") as f:
        yield from iter(functools.partial(f.read, w), b"")


def sort_file(path: str, w: int, tmp: str) -> str:
    """A new file under ``tmp`` with the ``w``-byte records of the file at ``path`` in byte order.  An external merge
    sort: runs of _RUN records sorted in memory, then merged _FAN at a time until one is left, so memory is fixed
    whatever the record count."""
    name = os.path.join(tmp, os.path.basename(path) + ".")
    runs = []
    with open(path, "rb") as f:
        while chunk := f.read(w * _RUN):
            runs.append(f"{name}{len(runs)}")
            with open(runs[-1], "wb") as o:
                o.write(b"".join(sorted(chunk[i:i + w] for i in range(0, len(chunk), w))))
    made = len(runs)
    while len(runs) > 1:
        merged = []
        for i in range(0, len(runs), _FAN):
            merged.append(f"{name}{made}")
            made += 1
            files = [open(p, "rb") for p in runs[i:i + _FAN]]
            try:
                with open(merged[-1], "wb") as o:
                    o.writelines(heapq.merge(*(iter(functools.partial(g.read, w), b"") for g in files)))
            finally:
                for g in files:
                    g.close()
            for p in runs[i:i + _FAN]:
                os.remove(p)
        runs = merged
    if not runs:
        runs.append(f"{name}0")
        open(runs[0], "wb").close()
    return runs[0]


def has_duplicate(path: str, tmp: str) -> bool:
    """Is any 32-byte identity in the file at ``path`` there twice?"""
    last = None
    for k in records(sort_file(path, 32, tmp), 32):
        if k == last:
            return True
        last = k
    return False


class Lines:
    """The file's records, one line at a time, with the framing refusals and the file's SHA3-512."""

    def __init__(self, stream):
        self.stream, self.whole, self.size = stream, hashlib.sha3_512(), 0

    def __call__(self):
        b = self.stream.readline(122)
        self.size += len(b)
        if self.size > _MAX_BYTES:
            raise Refused("file_too_large")
        self.whole.update(b)
        if not b:
            return None
        if b.endswith(b"\n"):
            if len(b) != 121:
                raise Refused("bad_record_length")
            return b[:-1]
        raise Refused("bad_record_length" if len(b) > 120 else "unterminated_record")


def verify_fixed(stream, entry: dict, kind: int, lay: bytes, codes: set, head_rest, row, sink, *, scratch: str,
                 channel: int, key: int, reader: int) -> bytes:
    """Re-read the binary ``stream``: each fact row to ``sink``, then the receipt; or Refused, and then the sink's rows
    belong to no accepted file.  ``codes`` are the identity codes the layout defines; ``head_rest(bytes)`` reads the
    header after its scope field into a dict; ``row(record, header)`` gives (subject, vstart, vstop, value, {identity
    code: bytes}) for one detail record."""
    if not entry_sound(entry):
        raise Refused("bad_entry")
    wanted = [c for k, c in entry["ids"] if k == kind]
    if not wanted:
        raise Refused("kind_not_registered")
    if not set(wanted[0]) <= codes:
        raise Refused("unknown_identity_field")
    line = Lines(stream)
    first = line()
    if first is None:
        raise Refused("unterminated_record")
    if not first.startswith(b"H"):
        raise Refused("no_header")
    got, sender, fseq, asof, cover, scope, rest = _HEAD.fullmatch(first).groups()
    head = {"layout": text(got), "sender": text(sender), "fseq": num(fseq), "asof": day(asof),
            "cover": code(_COVER, cover), "scope": text(scope)}
    head.update(head_rest(rest))
    if head["layout"] != lay:
        raise Refused("unknown_layout")

    rows, count, roff = 0, None, 0
    with tempfile.TemporaryDirectory(prefix="fixed-verify-", dir=scratch) as tmp:
        ids_path = os.path.join(tmp, "ids")
        with open(ids_path, "wb") as ids:
            while (x := line()) is not None:
                roff += 1
                if count is not None:
                    raise Refused("unknown_record_type")
                if x.startswith(b"T"):
                    count, rest = _TAIL.fullmatch(x).groups()
                    count = num(count)
                    filler(rest)
                    continue
                if not x.startswith(b"D"):
                    raise Refused("unknown_record_type")
                subject, start, stop, value, parts = row(x, head)
                h = hashlib.sha3_256()
                h.update(b"RR/GATE/SID/v1\x00" + entry["src"].to_bytes(2, "little") + bytes([kind]))
                for c in wanted[0]:
                    h.update(len(parts[c]).to_bytes(2, "little") + parts[c])
                s = h.digest()
                ids.write(s)
                sink(codec.encode_fact({"kind": kind, "op": 0, "subject": subject, "sid": s, "vstart": start,
                                        "vstop": stop, "until": 99991231, "receipt": 0, "roff": roff, "value": value}))
                rows += 1
        if count is None:
            raise Refused("no_trailer")
        if count != rows:
            raise Refused("count_mismatch")
        if has_duplicate(ids_path, tmp):
            raise Refused("duplicate_key")
    cfrom = head["asof"] if head["cover"] == 1 and entry["cfrom_rule"] != 1 else 0
    return codec.encode_receipt({
        "src": entry["src"], "cover": head["cover"], "kb": 0, "asof": head["asof"], "cfrom": cfrom,
        "fseq": head["fseq"], "file": line.whole.digest(), "sender": block(head["sender"]), "channel": channel,
        "key": key, "reader": reader, "reread": 0, "rows": rows, "admitted": 0, "same": 0, "quar": 0,
        "scope": block(head["scope"]), "frows": rows})
