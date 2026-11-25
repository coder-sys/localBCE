"""Byte codecs for the fee-for-service fact records and the source receipt, and the statement order `rank`.

This is the twin of `lean/BlindLedger/Gate/FactCodec.lean`, which is the specification; it exists for tests.
Nothing in the gate, owner or engine uses it.  A record is 245 bytes of body (the rows-file codec adds its own
link bytes to make the 256-byte record).  Numbers are little-endian; a block is a fixed number of bytes; padding
is zero and any other padding is refused.  A record is a dict of field name to int or bytes.  Only the canonical form
of a record is accepted, so each record has one encoding: an operation of 0 to 2, a span that does not run backwards (an end row, operation 2, may),
identifier blocks ("i") with a length byte inside the block and zeros after the text, and a provider subject (kinds 3
and 4) that is an identifier of 21 bytes then 11 zeros.
"""
from __future__ import annotations

BODY = 245
VALUE = 157
RECEIPT_TAG = 0x40

# ("n", width) is a little-endian number; ("b", width) is a block of bytes; ("i", width) an identifier block.
FACT_HEAD = [("op", "n", 1), ("subject", "b", 32), ("sid", "b", 32), ("vstart", "n", 4), ("vstop", "n", 4),
             ("until", "n", 4), ("receipt", "n", 5), ("roff", "n", 5)]
KINDS = {
    1: ("ELIG", [("status", "n", 1), ("basis", "n", 1), ("program", "i", 21), ("aid", "i", 21),
                 ("determined", "n", 4), ("notice", "n", 4)]),
    2: ("DEATH", [("proof", "n", 1), ("record", "b", 64)]),
    3: ("EXCL", [("list", "n", 1), ("type", "i", 9), ("waiver", "n", 1)]),
    4: ("PDEATH", [("proof", "n", 1)]),
    5: ("ACK", [("pay", "b", 72), ("status", "n", 1), ("amount", "n", 8), ("trace", "i", 51)]),
    6: ("DISC", [("event", "n", 1), ("pay", "b", 72), ("amount", "n", 8), ("case", "i", 31)]),
    7: ("RECOV", [("pay", "b", 72), ("amount", "n", 8), ("source", "n", 1), ("ref", "i", 51)]),
}
RECEIPT = [("src", "n", 2), ("cover", "n", 1), ("kb", "n", 5), ("asof", "n", 4), ("cfrom", "n", 4),
           ("fseq", "n", 8), ("file", "b", 64), ("sender", "i", 21), ("channel", "n", 1), ("key", "n", 2),
           ("reader", "n", 2), ("reread", "n", 5), ("rows", "n", 4), ("admitted", "n", 4), ("same", "n", 4),
           ("quar", "n", 4), ("scope", "i", 21), ("frows", "n", 8)]


def _ident(name: str, v: bytes, w: int) -> None:
    """A canonical identifier block: a length byte below the width, then that much text, then zeros."""
    if v[0] >= w or any(v[1 + v[0]:]):
        raise ValueError(f"{name}: not a canonical identifier")


def _check(f: dict) -> None:
    """The canonical form of a fact row beyond its widths (the Lean `Fact.WF` and the decoder's checks)."""
    if f["op"] > 2:
        raise ValueError("op: not 0 to 2")
    if f["op"] != 2 and f["vstart"] > f["vstop"]:  # an end row stops the day before the file that ended it
        raise ValueError("vstart after vstop")
    if f["kind"] in (3, 4):
        _ident("subject", f["subject"][:21], 21)
        if any(f["subject"][21:]):
            raise ValueError("subject: bytes after the identifier")


def _put(fields, rec) -> bytes:
    out = b""
    for name, typ, w in fields:
        v = rec[name]
        if typ == "n":
            if type(v) is not int or not 0 <= v < 256 ** w:
                raise ValueError(f"{name}: not a {w}-byte number")
            out += v.to_bytes(w, "little")
        else:
            if type(v) is not bytes or len(v) != w:
                raise ValueError(f"{name}: not a {w}-byte block")
            if typ == "i":
                _ident(name, v, w)
            out += v
    return out


def _get(fields, b: bytes, at: int):
    rec = {}
    for name, typ, w in fields:
        part = b[at:at + w]
        rec[name] = int.from_bytes(part, "little") if typ == "n" else bytes(part)
        if typ == "i":
            _ident(name, rec[name], w)
        at += w
    return rec, at


def encode_fact(f: dict) -> bytes:
    """`f` holds `kind` (1 to 7), the head fields and `value` (a dict of that kind's fields)."""
    if f["kind"] not in KINDS:
        raise ValueError("unknown kind")
    fields = KINDS[f["kind"]][1]
    value = _put(fields, f["value"])
    head = _put(FACT_HEAD, f)
    _check(f)
    return bytes([f["kind"]]) + head + value + bytes(VALUE - len(value))


def decode_fact(b: bytes) -> dict:
    """Exactly 245 bytes, a kind from 1 to 7, a canonical row and zero padding; otherwise ValueError."""
    if len(b) != BODY:
        raise ValueError("wrong length")
    kind = b[0]
    if kind not in KINDS:
        raise ValueError("unknown kind")
    f, at = _get(FACT_HEAD, b, 1)
    f["kind"] = kind
    f["value"], at = _get(KINDS[kind][1], b, at)
    _check(f)
    if any(b[at:]):
        raise ValueError("nonzero padding")
    return f


def encode_receipt(r: dict) -> bytes:
    """The fields, then `rd` (64 bytes: the hash of the frame's reference rows; zero, or absent from `r`, when it had
    none), then 16 zero bytes."""
    body = bytes([RECEIPT_TAG]) + _put(RECEIPT, r) + _put([("rd", "b", 64)], {"rd": r.get("rd", bytes(64))})
    return body + bytes(BODY - len(body))


def decode_receipt(b: bytes) -> dict:
    """Exactly 245 bytes, tag 0x40, canonical identifiers and zero padding; otherwise ValueError.  `rd` is in the dict
    only when it is not zero."""
    if len(b) != BODY:
        raise ValueError("wrong length")
    if b[0] != RECEIPT_TAG:
        raise ValueError("not a receipt")
    r, at = _get(RECEIPT, b, 1)
    if any(b[at:at + 64]):
        r["rd"] = bytes(b[at:at + 64])
    if any(b[at + 64:]):
        raise ValueError("nonzero padding")
    return r


def rank(fseq: int, reader: int, roff: int) -> tuple:
    """The statement order of §3.2: a larger tuple is the newer statement."""
    return (fseq, reader, roff)
