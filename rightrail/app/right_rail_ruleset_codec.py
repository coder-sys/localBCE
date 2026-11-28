"""Byte codec for the signed rule sets RR/GATE/RULESET/v1 and v2 (conformance/RULESET_V1.md, RULESET_V2.md).

This is the twin of `lean/BlindLedger/Gate/RuleSet/Spec.lean` (`decode`, `encode`), which decides; it carries bytes
and decides nothing.  `tests/test_ruleset_v1_codec.py` and `tests/test_ruleset_v2.py` check it against that model's
golden digests.  A record is a dict (section 7 of RULESET_V1.md; a version 2 record adds `"format": 2` and `"aids"`);
`decode` accepts only the canonical form, so `encode(decode(x)) == x`.  `RuleSetRefused.detail` names the first failing
part, in the order the Lean decoder reads them.
"""
from __future__ import annotations

import datetime
import hashlib
import re

TAG = b"RR/GATE/RULESET/v1\x00"
SIGTAG = b"RR/GATE/RULESET/v1/SIG\x00"
TAG2 = b"RR/GATE/RULESET/v2\x00"
SIGTAG2 = b"RR/GATE/RULESET/v2/SIG\x00"
ELIG = 7
MAX_AIDS = 1024
MAX_AID_LEN = 20
MAX_RECORD = 131072
MAX_COST = 1024
MAX_DEPTH = 8
MAX_ARITY = 8
KEY_LEN = 64
SIG_LEN = 4627
MAX_LIFE_DAYS = 31
OPEN_END = 99991231
IDENT = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
# The thirteen fact reasons a rule may name, by their fixed mask bit (Reason.idx).
FACT_BITS = frozenset((1, 7, 8, 9, 10, 12, 13, 14, 15, 18, 19, 20, 21))
# The eligibility reasons only a version 2 rule may name.
ELIG_BITS = frozenset((24, 25, 26, 27, 28))
# The benefit level reasons: well formed, but no fact field carries a benefit level yet, so admission refuses a record
# that names one (NOSOURCE, `Spec.lean` `unbacked`).
NO_SOURCE_BITS = frozenset((24, 25))
# Source byte (SNAPSHOT/v2 kind, 7 the eligibility facts): its ceiling on the maximum age, in days (`Src.ceil`,
# RuleSet/Spec.lean).  Only a version 2 record may declare source 7.
CEILING = {1: 90, 2: 90, 3: 31, 4: 10, ELIG: 10}
# (source, subject, test) triples a HIT may name.
HIT_OK = frozenset(((1, 1, 1), (2, 2, 1), (3, 2, 2), (4, 1, 2), (4, 1, 3)))
LEAF_OPS = {0x20: "present", 0x21: "fresh", 0x31: "overlap"}


class RuleSetRefused(ValueError):
    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def _date(d: int) -> datetime.date | None:
    try:
        return datetime.date(d // 10000, d // 100 % 100, d % 100)
    except ValueError:
        return None


def _span_ok(nb: int, na: int) -> bool:
    b, a = _date(nb), _date(na)
    return b is not None and a is not None and 0 <= (a - b).days <= MAX_LIFE_DAYS


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def take(self, n: int, part: str) -> bytes:
        if self.at + n > len(self.data):
            raise RuleSetRefused(part)
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def num(self, w: int, part: str, lo: int = 0, hi: int | None = None) -> int:
        v = int.from_bytes(self.take(w, part), "big")
        if v < lo or (hi is not None and v > hi):
            raise RuleSetRefused(part)
        return v

    def ident(self, part: str) -> bytes:
        s = self.take(self.num(2, part), part)
        if not IDENT.fullmatch(s):
            raise RuleSetRefused(part)
        return s


def cost(e: tuple) -> int:
    op = e[0]
    if op in ("and", "or"):
        return 1 + sum(cost(x) for x in e[1])
    if op == "not":
        return 1 + cost(e[1])
    if op == "hit":
        return 2 if e[2] == 1 else 3
    return 2 if op in ("overlap", "elig") else 1


def _expr(r: _Reader, ok: list, depth: int) -> tuple:
    if depth == 0:
        raise RuleSetRefused("expr")
    op = r.num(1, "expr")
    if op in (1, 2):
        n = r.num(1, "expr", 2, MAX_ARITY)
        return ("and" if op == 1 else "or", [_expr(r, ok, depth - 1) for _ in range(n)])
    if op == 3:
        return ("not", _expr(r, ok, depth - 1))
    if op == 0x10:
        return ("flow", r.num(1, "expr", 1, 7))
    if op == 0x11:
        return ("date_ok",)
    if op == 0x22:  # the eligibility read: 1 answer mask, 2 status mask, 3 aid class
        if ELIG not in ok:
            raise RuleSetRefused("expr")
        q = r.num(1, "expr", 1, 3)
        return ("elig", q, r.num(1, "expr", 1, 3 if q == 3 else 15))
    if op in (0x20, 0x21, 0x30, 0x31):
        src = r.num(1, "expr", 1, ELIG)
        if src not in ok:
            raise RuleSetRefused("expr")
        if op == 0x30:
            hit = (src, r.num(1, "expr", 1, 2), r.num(1, "expr", 1, 3))
            if hit not in HIT_OK:
                raise RuleSetRefused("expr")
            return ("hit",) + hit
        if op == 0x31 and src != 4:
            raise RuleSetRefused("expr")
        return (LEAF_OPS[op], src)
    raise RuleSetRefused("expr")


def _ascending(keys: list) -> bool:
    return all(a < b for a, b in zip(keys, keys[1:]))


def _parse(data: bytes) -> tuple[dict, int]:
    """The record and the length of its body (what the digest covers)."""
    data = bytes(data)
    if len(data) > MAX_RECORD:
        raise RuleSetRefused("length")
    r = _Reader(data)
    tag = r.take(len(TAG), "tag")
    if tag not in (TAG, TAG2):
        raise RuleSetRefused("tag")
    v2 = tag == TAG2
    d = {"format": 2} if v2 else {}
    d["state"] = r.take(64, "state")
    d["tenant"] = r.ident("tenant").decode("ascii")
    d["version"] = r.num(4, "version", 1)
    d["prev"] = r.take(64, "prev")
    if (d["version"] == 1) != (d["prev"] == bytes(64)):
        raise RuleSetRefused("prev")
    d["not_before"], d["not_after"] = r.num(4, "window"), r.num(4, "window")
    if not _span_ok(d["not_before"], d["not_after"]):
        raise RuleSetRefused("window")
    d["eff_from"], d["eff_to"] = r.num(4, "effective"), r.num(4, "effective")
    if not (_date(d["eff_from"]) and _date(d["eff_to"]) and d["eff_from"] <= d["eff_to"]):
        raise RuleSetRefused("effective")
    d["ends"] = [(r.num(4, "ends", 1), r.num(4, "ends")) for _ in range(r.num(1, "ends", 0, 8))]
    if not (_ascending([v for v, _ in d["ends"]]) and all(v < d["version"] and (t == 0 or _date(t))
                                                          for v, t in d["ends"])):
        raise RuleSetRefused("ends")
    d["cites"] = []
    for _ in range(r.num(1, "cites", 1, 32)):
        kind, ref = r.num(1, "cites", 1, 7), r.ident("cites").decode("ascii")
        when, doc = r.num(4, "cites"), r.take(64, "cites")
        if not _date(when) or doc == bytes(64):
            raise RuleSetRefused("cites")
        d["cites"].append((kind, ref, when, doc))
    d["ages"] = []
    for _ in range(r.num(1, "ages", 1, 5 if v2 else 4)):
        src = r.num(1, "ages", 1, ELIG)
        if src not in CEILING or (src == ELIG and not v2):
            raise RuleSetRefused("ages")
        d["ages"].append((src, r.num(2, "ages", 1, CEILING[src])))
    if not _ascending([s for s, _ in d["ages"]]):
        raise RuleSetRefused("ages")
    ok = [s for s, _ in d["ages"]]
    if v2:
        d["aids"] = []
        for _ in range(r.num(2, "aids", 0, MAX_AIDS)):
            code = r.ident("aids")
            if len(code) > MAX_AID_LEN:
                raise RuleSetRefused("aids")
            d["aids"].append((code.decode("ascii"), r.num(1, "aids", 1, 2)))
        if not _ascending([c.encode() for c, _ in d["aids"]]):
            raise RuleSetRefused("aids")
    bits = FACT_BITS | ELIG_BITS if v2 else FACT_BITS
    d["rules"] = []
    for _ in range(r.num(1, "rules", 1, 64)):
        bit = r.num(1, "rules")
        cite = r.num(1, "rules")
        if bit not in bits or cite >= len(d["cites"]):
            raise RuleSetRefused("rules")
        d["rules"].append((bit, cite, _expr(r, ok, MAX_DEPTH)))
    if not _ascending([b for b, _, _ in d["rules"]]):
        raise RuleSetRefused("rules")
    if sum(cost(e) for _, _, e in d["rules"]) > MAX_COST:
        raise RuleSetRefused("cost")
    body = r.at
    m = r.num(1, "sigs", 1, 16)
    d["sigs"] = [(r.take(KEY_LEN, "sigs"), r.take(SIG_LEN, "sigs")) for _ in range(m)]
    if r.at != len(data) or not _ascending([k for k, _ in d["sigs"]]):
        raise RuleSetRefused("sigs")
    return d, body


def decode(data: bytes) -> dict:
    return _parse(data)[0]


def unbacked(d: dict) -> list[int]:
    """The reason bits of `d`'s rules that no data source backs yet; admission refuses the record when there is one."""
    return [b for b, _, _ in d["rules"] if b in NO_SOURCE_BITS]


def _u(n: int, w: int, part: str) -> bytes:
    if not isinstance(n, int) or not 0 <= n < 256 ** w:
        raise RuleSetRefused(part)
    return n.to_bytes(w, "big")


def _blob(b: bytes, w: int, part: str) -> bytes:
    if not isinstance(b, bytes) or len(b) != w:
        raise RuleSetRefused(part)
    return b


def _ident(s: str, part: str) -> bytes:
    b = s.encode("utf-8") if isinstance(s, str) else b""
    return _u(len(b), 2, part) + b


def _enc_expr(e: tuple) -> bytes:
    op = e[0]
    if op in ("and", "or"):
        return bytes((1 if op == "and" else 2, len(e[1]))) + b"".join(_enc_expr(x) for x in e[1])
    if op == "not":
        return b"\x03" + _enc_expr(e[1])
    if op == "flow":
        return bytes((0x10, e[1]))
    if op == "date_ok":
        return b"\x11"
    if op == "hit":
        return bytes((0x30, e[1], e[2], e[3]))
    if op == "elig":
        return bytes((0x22, e[1], e[2]))
    return bytes(({v: k for k, v in LEAF_OPS.items()}[op], e[1]))


def encode(d: dict) -> bytes:
    """The record's bytes, refusing what `decode` would refuse (the bytes are decoded again before they are returned).
    A dict without `"format"` is a version 1 record, which has no aid table."""
    fmt = d.get("format", 1)
    if fmt not in (1, 2):
        raise RuleSetRefused("tag")
    if fmt == 1 and "aids" in d:
        raise RuleSetRefused("aids")
    try:
        out = [TAG2 if fmt == 2 else TAG, _blob(d["state"], 64, "state"), _ident(d["tenant"], "tenant"),
               _u(d["version"], 4, "version"), _blob(d["prev"], 64, "prev"), _u(d["not_before"], 4, "window"), _u(d["not_after"], 4, "window"),
               _u(d["eff_from"], 4, "effective"), _u(d["eff_to"], 4, "effective"), _u(len(d["ends"]), 1, "ends")]
        out += [_u(v, 4, "ends") + _u(t, 4, "ends") for v, t in d["ends"]]
        out.append(_u(len(d["cites"]), 1, "cites"))
        out += [_u(k, 1, "cites") + _ident(r, "cites") + _u(t, 4, "cites") + _blob(doc, 64, "cites")
                for k, r, t, doc in d["cites"]]
        out.append(_u(len(d["ages"]), 1, "ages"))
        out += [_u(s, 1, "ages") + _u(a, 2, "ages") for s, a in d["ages"]]
        if fmt == 2:
            out.append(_u(len(d["aids"]), 2, "aids"))
            out += [_ident(c, "aids") + _u(k, 1, "aids") for c, k in d["aids"]]
        out.append(_u(len(d["rules"]), 1, "rules"))
        out += [_u(b, 1, "rules") + _u(c, 1, "rules") + _enc_expr(e) for b, c, e in d["rules"]]
        out.append(_u(len(d["sigs"]), 1, "sigs"))
        out += [_blob(k, KEY_LEN, "sigs") + _blob(s, SIG_LEN, "sigs") for k, s in d["sigs"]]
    except RuleSetRefused:
        raise
    except (KeyError, IndexError, TypeError, ValueError):
        raise RuleSetRefused("expr") from None
    data = b"".join(out)
    decode(data)
    return data


def digest(data: bytes) -> bytes:
    """The rule set's identity: SHA3-512 of the body, signatures excluded."""
    return hashlib.sha3_512(bytes(data)[:_parse(data)[1]]).digest()


def message(data: bytes) -> bytes:
    """What the signers sign: the body under its version's signature tag."""
    d, n = _parse(data)
    return hashlib.sha3_512((SIGTAG2 if "format" in d else SIGTAG) + bytes(data)[:n]).digest()
