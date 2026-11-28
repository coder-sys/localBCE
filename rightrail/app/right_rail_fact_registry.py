"""Source registry and source state (design fact-record §2.3, §3.1-§3.3): the Python twin of
lean/BlindLedger/Gate/FactRegistry.lean.  Lean decides; this module is checked against the Lean file's golden
vectors and scenario (tests/test_fact_registry.py).  Receipts are the dicts of right_rail_fact_codec."""

OPEN = 99991231
MAX_DROP = 50
_RULES = (1, 2)


def _le(n: int, w: int) -> bytes:
    if not 0 <= n < 256**w:
        raise ValueError("number out of range")
    return n.to_bytes(w, "little")


def ident(w: int, s: str) -> bytes:
    b = s.encode()
    if len(b) > w - 1:
        raise ValueError("text too long")
    return bytes([len(b)]) + b + bytes(w - 1 - len(b))


def mask_of(ids) -> int:
    return sum(2**k for k, _ in ids)


def _canon(b: bytes) -> bool:
    """An identifier block: a length byte inside the block, then that text, then zeros."""
    return b[0] < len(b) and not any(b[1 + b[0]:])


def entry_ok(e: dict) -> bool:
    ks = [k for k, _ in e["ids"]]
    return (0 < e["src"] and _canon(e["scope"]) and _canon(e["name"]) and 1 <= e["cls"] <= 5 and e["gapless"] <= 1 and e["oneper"] <= 1
            and e["drop"] <= MAX_DROP and e["fseq_rule"] in _RULES and (e["gapless"] == 0 or e["fseq_rule"] == 2)
            and e["full"] <= 1 and e["cfrom_rule"] <= 1 and all(1 <= k <= 63 for k in ks) and all(c for _, c in e["ids"])
            and all(a < b for a, b in zip(ks, ks[1:])) and e["kinds"] == mask_of(e["ids"]))


def encode_entry(e: dict) -> bytes:
    if len(e["scope"]) != 21 or len(e["name"]) != 31 or len(e["ids"]) > 255:
        raise ValueError("bad entry")
    out = (_le(e["src"], 2) + _le(e["cls"], 1) + _le(e["origin"], 2) + _le(e["kinds"], 8) + _le(e["gapless"], 1)
           + _le(e["maxage"], 2) + _le(e["drop"], 1) + _le(e["oneper"], 1) + e["scope"] + e["name"]
           + _le(e["fseq_rule"], 1) + _le(e["full"], 1) + _le(e["cfrom_rule"], 1) + _le(len(e["ids"]), 1))
    for k, codes in e["ids"]:
        out += _le(k, 1) + _le(len(codes), 1) + b"".join(_le(c, 2) for c in codes)
    if not entry_ok(e):
        raise ValueError("entry not ok")
    return out


def decode_entry(b: bytes):
    """One entry and the rest of the bytes; ValueError when too short or not ok."""
    at = 0

    def num(w):
        nonlocal at
        if at + w > len(b):
            raise ValueError("short")
        v = int.from_bytes(b[at:at + w], "little")
        at += w
        return v

    def blk(w):
        nonlocal at
        if at + w > len(b):
            raise ValueError("short")
        v = b[at:at + w]
        at += w
        return v

    e = {"src": num(2), "cls": num(1), "origin": num(2), "kinds": num(8), "gapless": num(1), "maxage": num(2),
         "drop": num(1), "oneper": num(1), "scope": blk(21), "name": blk(31), "fseq_rule": num(1), "full": num(1),
         "cfrom_rule": num(1)}
    ids = []
    for _ in range(num(1)):
        k = num(1)
        ids.append((k, [num(2) for _ in range(num(1))]))
    e["ids"] = ids
    if not entry_ok(e):
        raise ValueError("entry not ok")
    return e, b[at:]


def lookup(reg, src):
    return next((e for e in reg if e["src"] == src), None)


def registry_ok(reg) -> bool:
    """Every entry ok and no `src` listed twice (so the look-up shadows nothing)."""
    srcs = [e["src"] for e in reg]
    return all(entry_ok(e) for e in reg) and len(set(srcs)) == len(srcs)


def fseq_date_isa(date: int, isa: int) -> int:
    return date * 1_000_000_000 + isa


# ---- dates (the same arithmetic as Rules.Spec) -------------------------------------------------------------

def _leap(y):
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def _month_days(y, m):
    return (29 if _leap(y) else 28) if m == 2 else 30 if m in (4, 6, 9, 11) else 31


def valid_date(d: int) -> bool:
    y, m, dd = d // 10000, d // 100 % 100, d % 100
    return 0 < y <= 9999 and 0 < m <= 12 and 0 < dd <= _month_days(y, m)


def day_num(d: int) -> int:
    m = d // 100 % 100
    y = d // 10000 - (1 if m <= 2 else 0)
    mp = m - 3 if m > 2 else m + 9
    return y * 365 + y // 4 - y // 100 + y // 400 + (153 * mp + 2) // 5 + d % 100 - 1


# ---- receipts of a source ----------------------------------------------------------------------------------

def rcpts_of(recs, src):
    return [r for _, r in recs if r["src"] == src]


def pick_max(rs):
    """The receipt of greatest fseq (the earliest of equals)."""
    best = None
    for r in rs:
        if best is None or best["fseq"] < r["fseq"]:
            best = r
    return best


def pick_min(rs):
    best = None
    for r in rs:
        if best is None or r["fseq"] < best["fseq"]:
            best = r
    return best


# ---- admission ---------------------------------------------------------------------------------------------

class State:
    def __init__(self, recs=None, reused=None, dropped=None):
        self.recs = list(recs or [])
        self.reused = list(reused or [])
        self.dropped = list(dropped or [])

    def copy(self):
        return State(self.recs, self.reused, self.dropped)

    def confirm_reuse(self, src):
        return State(self.recs, [s for s in self.reused if s != src], self.dropped)

    def confirm_drop(self, seq):
        return State(self.recs, self.reused, [s for s in self.dropped if s != seq])


def cfrom_ok(e, r) -> bool:
    if r["cover"] == 1:
        return (e["full"] == 1 and r["scope"] == e["scope"]
                and r["cfrom"] == (0 if e["cfrom_rule"] == 1 else r["asof"]))
    return r["cfrom"] == 0


def fseq_date_ok(e, r) -> bool:
    return e["fseq_rule"] != 1 or valid_date(r["fseq"] // 1000000000)


def shape_ok(e, r) -> bool:
    return (1 <= r["cover"] <= 4 and cfrom_ok(e, r) and valid_date(r["asof"]) and 1 <= r["channel"] <= 3
            and (r["cover"] == 4 or r["reread"] == 0) and fseq_date_ok(e, r))


def _already_of(recs, r):
    if r["cover"] == 4:
        return None
    return next((s for s in recs if s[1]["file"] == r["file"]), None)


def _reused_by(recs, r):
    return any(s[1]["src"] == r["src"] and s[1]["fseq"] == r["fseq"] and s[1]["file"] != r["file"] for s in recs)


def _same_reading(recs, r):
    if r["cover"] != 4:
        return None
    return next((s for s in recs if s[1]["src"] == r["src"] and s[1]["fseq"] == r["fseq"]
                 and s[1]["reader"] == r["reader"]), None)


def _reread_ok(recs, r):
    return r["cover"] != 4 or any(
        s[0] == r["reread"] and s[1]["src"] == r["src"] and s[1]["fseq"] == r["fseq"] and s[1]["file"] == r["file"]
        and s[1]["asof"] == r["asof"] and s[1]["scope"] == r["scope"] and s[1]["sender"] == r["sender"]
        and s[1]["reader"] < r["reader"] for s in recs)


def drop_fails(drop, new, old) -> bool:
    return new * 100 < (100 - drop) * old


def prev_full(rs, f):
    return pick_max([a for a in rs if a["cover"] == 1 and a["fseq"] < f])


def drop_check(e, recs, r, in_force) -> bool:
    if r["cover"] != 1:
        return False
    p = prev_full(rcpts_of(recs, r["src"]), r["fseq"])
    return (p is not None and drop_fails(e["drop"], r["frows"], p["frows"])) or drop_fails(e["drop"], r["rows"], in_force)


def admit(reg, st, n, r, in_force):
    """One receipt as record n: (answer text, new state).  Answers: 'already N', 'refused WHY', 'admitted N D'."""
    s = _already_of(st.recs, r)
    if s is not None:
        return f"already {s[0]}", st
    e = lookup(reg, r["src"])
    if e is None:
        return "refused unregistered", st
    if not shape_ok(e, r):
        return "refused record", st
    if not _reread_ok(st.recs, r):
        return "refused reread", st
    if _reused_by(st.recs, r):
        reused = st.reused if r["src"] in st.reused else [r["src"]] + st.reused
        return "refused reused", State(st.recs, reused, st.dropped)
    s = _same_reading(st.recs, r)
    if s is not None:
        return f"already {s[0]}", st
    d = drop_check(e, st.recs, r, in_force)
    return f"admitted {n} {1 if d else 0}", State(st.recs + [(n, r)], st.reused, ([n] + st.dropped) if d else st.dropped)


def day_ok(prev, today) -> bool:
    return valid_date(today) and prev <= today


def admit_frame(reg, st, prev, today, n, r, in_force):
    """The one entry for runtime code: a registry that is not ok refuses every frame."""
    if not registry_ok(reg):
        return "refused registry", st
    if not day_ok(prev, today):
        return "refused day", st
    e = lookup(reg, r["src"])
    if today < r["asof"] or (e is not None and e["fseq_rule"] == 1 and today < r["fseq"] // 1000000000):
        return "refused record", st
    return admit(reg, st, n, r, in_force)


# ---- source state at a day ---------------------------------------------------------------------------------

def gap_at(rs, b, h) -> bool:
    """Is a number missing strictly between b and h?"""
    have = {a["fseq"] for a in rs}
    return any(f not in have for f in range(b + 1, h))


def gap_open(e, rs) -> bool:
    if e["gapless"] != 1:
        return False
    hi = pick_max(rs)
    if hi is None:
        return False
    f = pick_max([a for a in rs if a["cover"] == 1])
    if f is not None:
        return gap_at(rs, f["fseq"], hi["fseq"])
    lo = pick_min(rs)
    return gap_at(rs, lo["fseq"], hi["fseq"])


def stale_cause(e, st, today):
    """None when the source is fresh at `today`; else the first cause, in the order the design tries them."""
    n = pick_max(rcpts_of(st.recs, e["src"]))
    if n is None:
        return "noReceipt"
    if today < n["asof"]:
        return "future"
    if day_num(n["asof"]) + e["maxage"] < day_num(today):
        return "age"
    if gap_open(e, rcpts_of(st.recs, e["src"])):
        return "gap"
    if any(s[1]["src"] == e["src"] and s[0] in st.dropped for s in st.recs):
        return "drop"
    if e["src"] in st.reused:
        return "reused"
    return None


def day_before(d: int) -> int:
    """The calendar day before a date; 0 for 0, which stands for the start of history."""
    if d % 100 > 1:
        return d - 1
    y, m = d // 10000, d // 100 % 100
    if m > 1:
        return y * 10000 + (m - 1) * 100 + _month_days(y, m - 1)
    return (y - 1) * 10000 + 1231 if y > 1 else 0


def late_until(rs, f) -> int:
    """The `until` of a row of fseq f: the day before the least cfrom of the full receipts above f."""
    cfroms = [a["cfrom"] for a in rs if a["cover"] == 1 and f < a["fseq"]]
    return day_before(min(cfroms)) if cfroms else OPEN


def ends_allowed(st, n, r, subjectless) -> bool:
    return r["cover"] == 1 and not subjectless and n not in st.dropped and r["src"] not in st.reused
