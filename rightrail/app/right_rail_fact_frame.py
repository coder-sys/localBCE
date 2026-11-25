"""The fact frame `RRDF`, its answer and its retry rule (design fact-record §2.10).

This is the twin of `lean/BlindLedger/Gate/FactFrame.lean`, which is the specification; it exists for tests.  Nothing in
the gate, owner or engine uses it.  Numbers are little-endian.

Request: `RRDF ‖ version u16 = 1 ‖ shard u32 ‖ batch u64 ‖ digest 64` (82 bytes), then the body
`prev 64 ‖ pin 64 ‖ 37 zero bytes ‖ receipt 165 ‖ count u32 ‖ count × row 236 ‖ u32 0`.  The digest is
`rq = SHA3-512(dom FACTS ‖ body)` and is checked before any body byte is read.  The wire receipt is the stored receipt's
165 field bytes with `kb`, `admitted` and `same` zero; a wire row is a fact row without `until` and `receipt`, and is
never an end row (`op = 2`).  Rows are strictly increasing in (`subject`, kind, `sid`, `roff`).  A refusal carries
FRAME_V1's word: `LENGTH`, `MAGIC`, `DIGEST` or `RECORD`, the first one met in byte order.

Answer: `RRDA ‖ version u16 = 3 ‖ status u8 = 0 ‖ shard u32 ‖ batch u64 ‖ lines u32 ‖ digest 64` (87 bytes), then
`lines × (disposition u8 ‖ cause u8 ‖ seq u40)`, then `head 64 ‖ root 64 ‖ rs 64 ‖ items u32 ‖ money u32`.
"""
from __future__ import annotations

import hashlib

from app import right_rail_fact_codec as c

MAGIC = b"RRDF"
VERSION = 1
HEADER = 82
RECEIPT = 165
ROW = 236
AUTH_ZERO = 37
FACTS_DOM = b"RR/GATE/FACTS/v1\x00"
ENGINE_SET = ("kb", "admitted", "same")
ANSWER_MAGIC = b"RRDA"
ANSWER_VERSION = 3
ANSWER_HEADER = 87
ENTRY = 7


class Refused(Exception):
    """A request refused with FRAME_V1's word."""

    def __init__(self, word: str):
        super().__init__(word)
        self.word = word


def _le(v: int, w: int) -> bytes:
    if type(v) is not int or not 0 <= v < 256 ** w:
        raise ValueError(f"not a {w}-byte number")
    return v.to_bytes(w, "little")


def encode_receipt(r: dict) -> bytes:
    """The receipt's 165 field bytes; its engine-set fields must be zero."""
    if any(r[k] for k in ENGINE_SET) or any(r.get("rd", b"")):
        raise ValueError("engine-set receipt field not zero")
    return c.encode_receipt(r)[:RECEIPT]


def decode_receipt(b: bytes) -> dict:
    r = c.decode_receipt(b + bytes(80))
    if any(r[k] for k in ENGINE_SET):
        raise ValueError("engine-set receipt field not zero")
    return r


def encode_row(w: dict) -> bytes:
    """`w` is a fact row (as `right_rail_fact_codec`) without `until` and `receipt`."""
    if w["op"] == 2:
        raise ValueError("end row on the wire")
    b = c.encode_fact({**w, "until": 0, "receipt": 0})
    return b[:74] + b[83:]


def decode_row(b: bytes) -> dict:
    f = c.decode_fact(b[:74] + bytes(9) + b[74:])
    if f["op"] == 2:
        raise ValueError("end row on the wire")
    del f["until"], f["receipt"]
    return f


def key(w: dict) -> bytes:
    """The row's place in the frame: subject, kind, sid, roff (big-endian), compared as bytes."""
    return w["subject"] + bytes([w["kind"]]) + w["sid"] + w["roff"].to_bytes(5, "big")


REF_KINDS = (3, 4)


def _h(name: str, *parts: bytes) -> bytes:
    return hashlib.sha3_512(b"RR/GATE/" + name.encode() + b"/v1\x00" + b"".join(parts)).digest()


def ref_entry(receipt: dict, rows: list) -> bytes | None:
    """The reference set entry of a written receipt (§2.9, `RefSet.ent`): `src u16 ‖ fseq u64 ‖ reader u16` big-endian,
    `file`, `rd = H(dom REFROWS ‖ its rows of kinds 3 and 4, wire encoded)`; none without such a row."""
    rr = [w for w in rows if w["kind"] in REF_KINDS]
    if not rr:
        return None
    return (receipt["src"].to_bytes(2, "big") + receipt["fseq"].to_bytes(8, "big") +
            receipt["reader"].to_bytes(2, "big") + receipt["file"] + _h("REFROWS", *(encode_row(w) for w in rr)))


def ref_set(entries: list) -> bytes:
    """`rs` of the entries in any order (`RefSet.rs`): per source ascending, `src u16 ‖` its chain's last value."""
    out, chains = b"", {}
    for e in sorted(entries):
        src = e[:2][::-1]
        h = chains.get(src, _h("REFSRC", src))
        chains[src] = _h("REFSRC", h, e[2:10][::-1], e[12:])
    for src in sorted(chains, key=lambda s: s[::-1]):
        out += src + chains[src]
    return _h("REFSET", out)


def encode_body(prev: bytes, pin: bytes, receipt: dict, rows: list) -> bytes:
    """The body as given, with no check of order or count (tests build refused frames with it)."""
    return (prev + pin + bytes(AUTH_ZERO) + encode_receipt(receipt) + _le(len(rows), 4) +
            b"".join(encode_row(w) for w in rows) + bytes(4))


def frame(shard: int, batch: int, body: bytes) -> bytes:
    """The header in front of a body, its digest `rq` computed."""
    return MAGIC + _le(VERSION, 2) + _le(shard, 4) + _le(batch, 8) + hashlib.sha3_512(FACTS_DOM + body).digest() + body


def encode_request(q: dict) -> bytes:
    """`q` holds shard, batch, prev, pin, receipt and rows; only a canonical request is encoded."""
    if len(q["prev"]) != 64 or len(q["pin"]) != 64:
        raise ValueError("prev and pin are 64 bytes")
    if len(q["rows"]) != q["receipt"]["rows"]:
        raise ValueError("row count is not the receipt's rows")
    keys = [key(w) for w in q["rows"]]
    if any(a >= b for a, b in zip(keys, keys[1:])):
        raise ValueError("rows not strictly increasing")
    return frame(q["shard"], q["batch"], encode_body(q["prev"], q["pin"], q["receipt"], q["rows"]))


def decode_request(b: bytes) -> tuple[dict, bytes]:
    """The request and its digest `rq`; otherwise Refused with the first word met in byte order."""
    if len(b) < HEADER:
        raise Refused("LENGTH")
    if b[:4] != MAGIC or int.from_bytes(b[4:6], "little") != VERSION:
        raise Refused("MAGIC")
    shard, batch, rq, body = int.from_bytes(b[6:10], "little"), int.from_bytes(b[10:18], "little"), b[18:82], b[82:]
    if hashlib.sha3_512(FACTS_DOM + body).digest() != rq:
        raise Refused("DIGEST")
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if len(body) - at < n:
            raise Refused("LENGTH")
        at += n
        return body[at - n:at]

    prev, pin = take(64), take(64)
    if any(take(AUTH_ZERO)):
        raise Refused("RECORD")
    part = take(RECEIPT)
    try:
        receipt = decode_receipt(part)
    except ValueError:
        raise Refused("RECORD") from None
    n = int.from_bytes(take(4), "little")
    if n != receipt["rows"]:
        raise Refused("RECORD")
    rows = []
    for _ in range(n):
        part = take(ROW)
        try:
            rows.append(decode_row(part))
        except ValueError:
            raise Refused("RECORD") from None
    keys = [key(w) for w in rows]
    if any(x >= y for x, y in zip(keys, keys[1:])):
        raise Refused("RECORD")
    if int.from_bytes(take(4), "little") != 0:
        raise Refused("RECORD")
    if at != len(body):
        raise Refused("LENGTH")
    return {"shard": shard, "batch": batch, "prev": prev, "pin": pin, "receipt": receipt, "rows": rows}, rq


def _entry_ok(d: int, cause: int) -> bool:
    return 1 <= d <= 4 and (d == 3 or cause == 0)


def encode_answer(a: dict) -> bytes:
    """`a` holds shard, batch, digest, entries (disp, cause, seq), head, root, rs, items, money."""
    for name in ("digest", "head", "root", "rs"):
        if len(a[name]) != 64:
            raise ValueError(f"{name} is 64 bytes")
    out = ANSWER_MAGIC + _le(ANSWER_VERSION, 2) + _le(0, 1) + _le(a["shard"], 4) + _le(a["batch"], 8)
    out += _le(len(a["entries"]), 4) + a["digest"]
    for d, cause, seq in a["entries"]:
        if not _entry_ok(d, cause):
            raise ValueError("bad entry")
        out += _le(d, 1) + _le(cause, 1) + _le(seq, 5)
    return out + a["head"] + a["root"] + a["rs"] + _le(a["items"], 4) + _le(a["money"], 4)


def decode_answer(b: bytes) -> dict:
    """Exactly the canonical bytes of a fact answer; otherwise ValueError."""
    if len(b) < ANSWER_HEADER or b[:4] != ANSWER_MAGIC:
        raise ValueError("not a fact answer")
    if int.from_bytes(b[4:6], "little") != ANSWER_VERSION or b[6] != 0:
        raise ValueError("not a fact answer")
    n = int.from_bytes(b[19:23], "little")
    if len(b) != ANSWER_HEADER + ENTRY * n + 3 * 64 + 8:
        raise ValueError("wrong length")
    entries, at = [], ANSWER_HEADER
    for _ in range(n):
        d, cause, seq = b[at], b[at + 1], int.from_bytes(b[at + 2:at + 7], "little")
        if not _entry_ok(d, cause):
            raise ValueError("bad entry")
        entries.append((d, cause, seq))
        at += ENTRY
    return {"shard": int.from_bytes(b[7:11], "little"), "batch": int.from_bytes(b[11:19], "little"),
            "digest": b[23:87], "entries": entries, "head": b[at:at + 64], "root": b[at + 64:at + 128],
            "rs": b[at + 128:at + 192], "items": int.from_bytes(b[at + 192:at + 196], "little"),
            "money": int.from_bytes(b[at + 196:at + 200], "little")}


def retry(engine: dict, q: dict, rq: bytes) -> tuple:
    """ENGINE_V3 §9 for a fact frame.  `engine` holds shard, head (bytes, or None before any batch) and log (per logged
    batch its identity and answer bytes).  ("decide",), ("replay", answer) or ("refuse", word)."""
    n = len(engine["log"])
    if q["shard"] != engine["shard"]:
        return ("refuse", "SHARD")
    if q["batch"] == 1:
        return ("refuse", "NOT_NEXT")
    if q["batch"] == n + 1:
        return ("decide",) if engine["head"] == q["prev"] else ("refuse", "HEAD")
    if q["batch"] == n and n > 0:
        d, a = engine["log"][-1]
        return ("replay", a) if d == rq else ("refuse", "CONFLICT")
    return ("refuse", "NOT_NEXT")
