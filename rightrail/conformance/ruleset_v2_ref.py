"""Reference evaluator for a signed rule set's conditions (conformance/RULESET_V2.md section 5), written from the
spec alone.  Synthetic, non-PHI.

`fired(record, read, date, flow, today)` is the mask of the reasons the gate's rules fire for one line (`dataFires`), in
the empty context `ruleset_admit` answers EVAL questions in: no reference snapshot is present, so PRESENT, FRESH, HIT
and OVERLAP of sources 1 to 4 are false; the line's service date and flow tag and the batch's date `today` (the
service date when not given) are given; the eligibility read is `read`.  A record is a dict as
`app/right_rail_ruleset_codec.py` decodes it (version 1 or 2).

`read` is the eligibility read for the line: `ans` (0 present, 1 absent, 2 unknown, 3 conflict), `status` (the
status of the newest statement when present: 1 eligible, 2 not eligible, 3 pending, 4 presumptive), `asof` (the
oldest as-of of the facts the answer cites, or None) and `aids` (the 21-byte identifier blocks of the aid codes the
cited facts carry).

The gate's fixed guards apply.  Enrollment: with no enrollment snapshot STALE_ENROLLMENT (19) fires and no hold rule
that reads source 4 does.  Eligibility: every PROGRAM_NOT_ELIGIBLE (26) rule, and a rule for another hold reason that
reads source 7 and is not true in three values with every node that reads source 7 unknown (Kleene AND, OR and NOT),
so whose value depends on the read, fires only on a fresh read (FRESH 7: a present answer within the maximum age); on
any other read, under version 2, such a rule fires PROGRAM_NOT_ELIGIBLE_UNVERIFIED (27) unless its condition is false
in three values, so false whatever the read.  A rule for another hold reason that is true in three values holds the
line on any read.

`admissible(record)` is admission's data source check: no rule may name a benefit level reason (24, 25).

`el_read(sources)` is the eligibility read from facts, for the shape of the conformance corpus only: each source a
clean full file of its own origin, fresh at its registry age, each of its rows for the member holding on the date.
"""
from __future__ import annotations

import datetime
import re

SPAN, ELIG = 4, 7
STALE_ENROLLMENT, PNE, PNE_UNV = 19, 26, 27
NO_SOURCE = (24, 25)
# The review reasons (`Rules.review`); every other reason is a hold.
REVIEW = frozenset((2, 5, 6, 8, 10, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 28))
MIN_CLASS = 1  # the class the corpus read asks for: a source of a higher class number is weaker and does not count
IDENT = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _date(d: int) -> datetime.date | None:
    try:
        return datetime.date(d // 10000, d // 100 % 100, d % 100)
    except ValueError:
        return None


def aid_class(table: dict, block: bytes) -> int:
    """1 listed eligible, 2 listed not eligible, 3 not on the list or not a well-formed aid code."""
    if len(block) != 21 or block[0] > 20 or any(block[1 + block[0]:]):
        return 3
    code = block[1:1 + block[0]]
    return table.get(code, 3) if IDENT.fullmatch(code) else 3


def reads(e: tuple, src: int) -> bool:
    op = e[0]
    if op in ("and", "or"):
        return any(reads(x, src) for x in e[1])
    if op == "not":
        return reads(e[1], src)
    if op in ("present", "fresh", "hit", "overlap"):
        return e[1] == src
    return op == "elig" and src == ELIG


def fired(record: dict, read: dict, date: int, flow: int, today: int | None = None) -> int:
    ages = dict(record["ages"])
    table = {c.encode(): k for c, k in record.get("aids", [])}
    day, now = _date(date), _date(date if today is None else today)

    def fresh() -> bool:
        asof = None if read["asof"] is None else _date(read["asof"])
        return (read["ans"] == 0 and asof is not None and day is not None and now is not None and asof <= now
                and (day - asof).days <= ages.get(ELIG, 0))

    def elig(q: int, a: int) -> bool:
        ans = read["ans"]
        if q == 1:
            return bool(a >> ans & 1)
        if ans != 0:
            return False
        if q == 2:
            return read["status"] >= 1 and bool(a >> (read["status"] - 1) & 1)
        return any(aid_class(table, b) == a for b in read["aids"])

    def ev(e: tuple) -> bool:
        op = e[0]
        if op == "and":
            return all(ev(x) for x in e[1])
        if op == "or":
            return any(ev(x) for x in e[1])
        if op == "not":
            return not ev(e[1])
        if op == "flow":
            return bool(e[1] >> (flow - 1) & 1)
        if op == "date_ok":
            return day is not None
        if op == "present":
            return e[1] == ELIG and read["asof"] is not None
        if op == "fresh":
            return e[1] == ELIG and fresh()
        if op == "elig":
            return elig(e[1], e[2])
        return False  # HIT and OVERLAP read only the snapshots, none of which is present

    def ev3(e: tuple) -> bool | None:
        """`ev` with every node that reads source 7 unknown (None)."""
        op = e[0]
        if op in ("and", "or"):
            vs = [ev3(x) for x in e[1]]
            stop = op == "or"  # the value that decides: false for AND, true for OR
            return stop if stop in vs else None if None in vs else not stop
        if op == "not":
            v = ev3(e[1])
            return None if v is None else not v
        return None if reads(e, ELIG) else ev(e)

    mask, stopped = 1 << STALE_ENROLLMENT, False
    for bit, _, cond in record["rules"]:
        # the guard covers every PNE rule and a hold rule whose value depends on the read; on a read that is not fresh it
        # fires none of them, and sends the line to review unless the rule is false whatever the read
        hold = bit not in REVIEW
        guarded = hold and (bit == PNE or reads(cond, ELIG) and ev3(cond) is not True) and not fresh()
        stopped |= guarded and ev3(cond) is not False
        if ev(cond) and not (guarded or hold and reads(cond, SPAN)):
            mask |= 1 << bit
    if stopped and record.get("format") == 2:
        mask |= 1 << PNE_UNV
    return mask


def admissible(record: dict) -> bool:
    return not any(bit in NO_SOURCE for bit, _, _ in record["rules"])


def el_read(sources: list) -> dict:
    """`sources` is a list of (source, class, as-of, [(status, aid code)]); a source of a class above `MIN_CLASS` does not
    count.  Rows of the counted sources whose statuses differ, in one source or across sources, are a conflict;
    otherwise any row makes the answer present, citing every row, with that status and every row's aid code, sources in
    order; no row at all is absent.  The as-of is the oldest of the sources whose rows the present answer cites, None
    for any other answer (it cites none)."""
    counted = [(asof, rs) for _, cls, asof, rs in sources if cls <= MIN_CLASS]
    rows = [(st, code) for _, rs in counted for st, code in rs]
    ans = 3 if len({st for st, _ in rows}) > 1 else 0 if rows else 1
    return {"ans": ans, "status": rows[0][0] if ans == 0 else 0,
            "asof": min(asof for asof, rs in counted if rs) if ans == 0 else None,
            "aids": [bytes([len(c)]) + c + bytes(20 - len(c)) for _, c in rows] if ans == 0 else []}
