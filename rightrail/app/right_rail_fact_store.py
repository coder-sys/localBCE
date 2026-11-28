"""The `facts` file and the two links files of a shard, as projections of the log.

This is the twin of `lean/BlindLedger/Gate/FactStore.lean`, which is the specification; it exists for tests.  Nothing
in the gate, owner or engine uses it.  A `facts` record is a 245-byte body (a fact row, a receipt, a lift record, a
quarantine marker, a member summary part or a money row) and its 11-byte link: the previous record of its chain plus one (5 bytes), the
chain's count up to it (2 bytes, at most 65535) and four zero bytes.  A links record is 32 bytes: the previous row of
the set with the same member, payee and rendering provider (each plus one, 5 bytes), then the row's batch, its record's
index in that batch's answer, its reason bits, its rule and the batch's authority day.  Numbers are little-endian.

A lift record (0x41) holds, for one receipt, up to 23 lifts of 10 bytes: the restated row's record number and the
`roff` of the full file row that stated it again (5 bytes each).

A file is derived from its records in log order (`writer_of`), a batch is appended with `put`, and `load_facts` /
`load_links` recompute the file from the records it holds and accept it only if the bytes are equal: a stored link is
compared, never trusted.  A writer is `(file, count, table)`; the table maps each chain key to the newest record of
the chain and its count.
"""
from __future__ import annotations

from app import right_rail_fact_codec as codec

BODY = codec.BODY
RECORD = 256
LINK_RECORD = 32
COUNT_CAP = 65535
ENTRY_MAX = 8
LIFT_MAX = 23

SUM_HEAD = [("tag", "n", 1), ("member", "b", 32), ("kb", "n", 5), ("cut", "n", 4), ("old", "n", 5), ("more", "n", 5),
            ("n", "n", 1)]
ENTRY = [("seq", "n", 5), ("receipt", "n", 5), ("fkind", "n", 1), ("vstart", "n", 4), ("vstop", "n", 4),
         ("until", "n", 4), ("dec", "n", 1)]
MARKER = [("src", "n", 2), ("fkind", "n", 1), ("subject", "b", 32), ("receipt", "n", 5), ("roff", "n", 5),
          ("cause", "n", 1), ("sidk", "n", 1), ("sid", "b", 32)]
MONEY = [("form", "n", 1), ("mkind", "n", 1), ("okey", "b", 72), ("line", "n", 5), ("cents", "n", 8),
         ("entitled", "n", 8), ("verdict", "n", 1), ("wbatch", "n", 8), ("windex", "n", 3), ("cause", "n", 5),
         ("link", "n", 5), ("identified", "n", 4), ("discovered", "n", 4), ("deadline", "n", 4), ("reg", "n", 1),
         ("due", "n", 8), ("refunded", "n", 8), ("questioned", "n", 8), ("allocated", "n", 8), ("available", "n", 8),
         ("noticed", "n", 8), ("under", "n", 8)]
TAIL = [("batch", "n", 5), ("windex", "n", 3), ("reasons", "n", 4), ("rule", "n", 1), ("day", "n", 4)]
# The money row kinds of each form (1 a payment, 2 a provider-level balance, 4 an advance).
MONEY_KINDS = {1: {1, 2, 3, 4, 5, 7}, 2: {8, 10, 11, 12}, 4: {9, 10, 11, 12}}
TAIL_RULES = {1, 2, 5}


def _body(tag: int, fields, rec: dict) -> bytes:
    out = bytes([tag]) + codec._put(fields, rec)
    return out + bytes(BODY - len(out))


def _read(tag: int, fields, b: bytes) -> dict:
    if len(b) != BODY:
        raise ValueError("wrong length")
    if b[0] != tag:
        raise ValueError("wrong tag")
    rec, at = codec._get(fields, b, 1)
    if any(b[at:]):
        raise ValueError("nonzero padding")
    return rec


# Member summary (tags 0x51 recent, 0x52 old): up to eight 24-byte entries, then zeros.

def encode_summary(s: dict) -> bytes:
    es = s["entries"]
    if s["tag"] not in (0x51, 0x52) or len(es) > ENTRY_MAX:
        raise ValueError("not a summary")
    block = b"".join(codec._put(ENTRY, e) for e in es)
    head = codec._put(SUM_HEAD, dict(s, n=len(es)))
    return head + block + bytes(BODY - len(head) - len(block))


def decode_summary(b: bytes) -> dict:
    if len(b) != BODY:
        raise ValueError("wrong length")
    s, at = codec._get(SUM_HEAD, b, 0)
    if s["tag"] not in (0x51, 0x52) or s["n"] > ENTRY_MAX:
        raise ValueError("not a summary")
    s["entries"] = [codec._get(ENTRY, b, at + 24 * i)[0] for i in range(s.pop("n"))]
    if any(b[at + 24 * len(s["entries"]):]):
        raise ValueError("nonzero entry padding")
    return s


# Quarantine marker (0x50), money row (0x60, format only) and the links record's tail.

def _marker_ok(m: dict) -> None:
    if m["cause"] == 0 or m["sidk"] > 1:
        raise ValueError("not a marker")


def encode_marker(m: dict) -> bytes:
    _marker_ok(m)
    return _body(0x50, MARKER, m)


def decode_marker(b: bytes) -> dict:
    m = _read(0x50, MARKER, b)
    _marker_ok(m)
    return m


def _money_ok(m: dict) -> None:
    if m["mkind"] not in MONEY_KINDS.get(m["form"], ()) or m["verdict"] > 2 or (m["form"] != 1 and m["line"] != 0):
        raise ValueError("not a money row")
    k = m["okey"]
    if m["form"] != 1:  # payee 21, reference 31, period u32, zeros
        codec._ident("okey payee", k[:21], 21)
        codec._ident("okey reference", k[21:52], 31)
        if any(k[56:]):
            raise ValueError("okey: bytes after the period")


def encode_money(m: dict) -> bytes:
    body = _body(0x60, MONEY, m)
    _money_ok(m)
    return body


def decode_money(b: bytes) -> dict:
    m = _read(0x60, MONEY, b)
    _money_ok(m)
    return m


def encode_tail(t: dict) -> bytes:
    if t["rule"] not in TAIL_RULES:
        raise ValueError("rule: not released, unresolved or bypassed")
    return codec._put(TAIL, t)


def decode_tail(b: bytes) -> dict:
    if len(b) != 17:
        raise ValueError("wrong length")
    t = codec._get(TAIL, b, 0)[0]
    if t["rule"] not in TAIL_RULES:
        raise ValueError("rule: not released, unresolved or bypassed")
    return t


def encode_lift(receipt: int, lifts: list[tuple[int, int]]) -> bytes:
    """A lift record of receipt record `receipt` holding `lifts`, each (restated row, roff)."""
    if not 1 <= len(lifts) <= LIFT_MAX:
        raise ValueError("lifts: 1 to 23")
    out = bytes([0x41]) + _le(5, receipt) + bytes([len(lifts)]) + b"".join(_le(5, j) + _le(5, roff) for j, roff in lifts)
    return out + bytes(BODY - len(out))


def decode_lift(b: bytes) -> dict:
    """A lift record: its receipt record and its lifts, each (restated row, roff)."""
    if len(b) != BODY or b[0] != 0x41:
        raise ValueError("not a lift record")
    n = b[6]
    if not 1 <= n <= LIFT_MAX or any(b[7 + 10 * n:]):
        raise ValueError("lifts: count or padding")
    num = lambda at: int.from_bytes(b[at:at + 5], "little")
    return {"receipt": num(1), "lifts": [(num(7 + 10 * i), num(12 + 10 * i)) for i in range(n)]}


def decode_body(b: bytes) -> tuple[str, dict]:
    """A `facts` body of any kind, by its tag; ValueError for an unknown tag or a body its kind refuses."""
    t = b[0] if b else 0
    if 1 <= t <= 0x3F:
        return "fact", codec.decode_fact(b)
    if t == 0x40:
        return "receipt", codec.decode_receipt(b)
    if t == 0x41:
        return "lift", decode_lift(b)
    if t == 0x50:
        return "marker", decode_marker(b)
    if t in (0x51, 0x52):
        return "summary", decode_summary(b)
    if t == 0x60:
        return "money", decode_money(b)
    raise ValueError("unknown tag")


# Chains and the projection.

def _le(w: int, v: int) -> bytes:
    """The low `w` bytes of `v`, as the specification's `leBytes`."""
    return (v % 256 ** w).to_bytes(w, "little")


def chain_keys(b: bytes) -> list[bytes]:
    """A receipt's source and file hash (the first 8 bytes); a fact row's or marker's subject; a summary's member; a
    money row's form and key; none for a lift record.  The first key is the chain the record's link follows."""
    t = b[0]
    if 1 <= t <= 0x3F:
        return [b"\x02" + b[2:34]]
    if t == 0x40:
        return [b"\x01" + b[1:3], b"\x05" + b[25:33]]
    if t == 0x50:
        return [b"\x02" + b[4:36]]
    if t in (0x51, 0x52):
        return [b"\x03" + b[1:33]]
    if t == 0x60:
        return [b"\x04" + b[1:2] + b[3:75]]
    return []


def run(tab: dict, n: int, kss: list[list[bytes]]) -> tuple[list[list[tuple[int, int]]], dict]:
    """Records n, n + 1, ... with keys `kss`: each record's links (prev, count), and the table after them."""
    tab = dict(tab)
    links = []
    for i, ks in enumerate(kss, n):
        mine = []
        for k in ks:
            j, c = tab[k] if k in tab else (None, 0)
            link = (0 if j is None else j + 1, min(c + 1, COUNT_CAP))
            tab[k] = (i, link[1])
            mine.append(link)
        links.append(mine)
    return links, tab


def _facts_out(b: bytes, links) -> bytes:
    prev, count = links[0] if links else (0, 0)
    return b + _le(5, prev) + _le(2, count) + bytes(4)


def _links_out(x: tuple[bytes, dict], links) -> bytes:
    prevs = [links[i][0] if i < len(links) else 0 for i in range(3)]
    return b"".join(_le(5, p) for p in prevs) + encode_tail(x[1])


def _link_keys(x: tuple[bytes, dict]) -> list[bytes]:
    r = x[0]
    return [b"\x01" + r[124:156], b"\x02" + r[156:177], b"\x03" + r[177:198]]


def _put(keys, out, w: tuple, xs: list) -> tuple:
    file, n, tab = w
    links, tab = run(tab, n, [keys(x) for x in xs])
    return file + b"".join(out(x, l) for x, l in zip(xs, links)), n + len(xs), tab


EMPTY = (b"", 0, {})


def put_facts(w: tuple, bodies: list[bytes]) -> tuple:
    return _put(chain_keys, _facts_out, w, bodies)


def facts_writer(bodies: list[bytes]) -> tuple:
    return put_facts(EMPTY, bodies)


def load_facts(f: bytes) -> tuple | None:
    """The writer of a `facts` file, or None unless every body decodes and the file is the one its bodies derive."""
    bodies = [f[i * RECORD:i * RECORD + BODY] for i in range(len(f) // RECORD)]
    try:
        for b in bodies:
            decode_body(b)
    except ValueError:
        return None
    w = facts_writer(bodies)
    return w if w[0] == f else None


def put_links(w: tuple, xs: list[tuple[bytes, dict]]) -> tuple:
    return _put(_link_keys, _links_out, w, xs)


def links_writer(xs: list[tuple[bytes, dict]]) -> tuple:
    return put_links(EMPTY, xs)


def load_links(rows: list[bytes], f: bytes) -> tuple | None:
    """The writer of a set's links file read beside its rows, or None unless there is one record per row, each
    decodes, and the file is the one the rows and stored answer fields derive."""
    try:
        tails = [decode_tail(f[i * LINK_RECORD + 15:(i + 1) * LINK_RECORD]) for i in range(len(f) // LINK_RECORD)]
    except ValueError:
        return None
    if len(tails) != len(rows):
        return None
    w = links_writer(list(zip(rows, tails)))
    return w if w[0] == f else None
