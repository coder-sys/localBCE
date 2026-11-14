"""820 premium-payment reader: one capitation line per member remittance, in integer cents, citing file hash and offsets.

A payment set carries one BPR/TRN pair (the payment: total, direction, date, trace number) and a payee (N1*PE, the
plan). Each remittance line (RMR, with the member from the ENT and the NM1*IL above it, and the report period from
DTM*582) becomes one `CapLine`. The member is ENT04 when ENT02 is 2J or IL and ENT03 is ZZ or 34; when the ENT and the
NM1*IL both name one and they differ, the line is quarantined. A line that cannot be read in full, whether the amount,
member, plan or report month, is quarantined whole with a cause; an amount is never inferred, rounded or taken from
another field. The payment's own total is reported next to the sum of the lines that were read, and a difference is a
finding only (never a change to an amount): adjustments legitimately make them differ, and whoever owns the record
decides what a difference means. The trace number is only read when TRN01 is 3; a set with no BPR, no TRN02 or another TRN01 keeps its lines with an
empty trace, and a finding counts them. A report period of one day is that day.
"""

from typing import NamedTuple

from app import right_rail_x12 as x12

_HELD = 2000  # lines that may wait for a late payment header before the rest of the set is dropped
KNOWN = frozenset("BPR TRN CUR REF DTM N1 N2 N3 N4 PER ENT NM1 RMR ADX IT1 SLN LS LE".split())


class CapLine(NamedTuple):
    plan: str
    member_id: str
    coverage_month: str  # YYYY-MM of the report period (DTM*582)
    period_begin: str  # the report period as sent, ISO; a single day is that day twice
    period_end: str
    amount_cents: int  # as sent: a negative amount stays negative
    trace: str  # TRN02 of the payment this line belongs to
    payment_date: str  # BPR16 as ISO, "" when not sent
    direction: str  # BPR03: C (plan is paid) or D
    file_at: str
    file_sha3_512: str
    set_control: str
    offsets: tuple  # byte offsets of the segments that gave a value, RMR first


class Payment(NamedTuple):
    trace: str
    total_cents: object  # int cents, or None when BPR02 would not parse
    lines_cents: int  # sum of the lines read from this set
    lines: int
    plan: str
    set_control: str
    offset: int  # of the BPR


class Read820(NamedTuple):
    lines: tuple
    payments: tuple
    findings: tuple  # Quarantine-shaped, nothing dropped: total_mismatch, total_unchecked
    quarantines: tuple
    repairs: tuple
    refused: str


def stream_820(data, sink):
    """Read bytes or a seekable file into `sink` (see right_rail_x12.Sink), one payment set at a time; returns the refusal cause or ""."""
    return x12.read(data, sink, "820", _read_set)


def read_820(data):
    sink = x12.Collector()
    refused = stream_820(data, sink)
    return Read820(sink.get("line"), sink.get("payment"), sink.get("finding"), tuple(sink.envelope) + sink.get("quarantine"),
                   tuple(sink.counts.items()), refused)


def _read_set(sha, ts, emit):
    def bad(unit, cause, at, detail=""):
        emit("quarantine", x12.Quarantine(unit, cause, at, detail))

    bpr = trn = None
    plan = ""
    payment_date = ""
    direction = ""
    member = ""
    ent_bad = False  # the open ENT names its member in a way this reader does not read
    names = None  # (member id, offset) of the NM1*IL waiting for its RMR
    lost = 0
    line = None  # open remittance line: dict
    held, full = [], False  # lines read before the trace is known, and whether the hold overflowed (the rest of the set is dropped)
    lines = given = paid = 0

    def trace():
        return x12.element(trn, 2) if trn is not None and x12.element(trn, 1) == "3" else ""

    def give(draft):
        nonlocal given, paid
        given += 1
        paid += draft[2]
        emit("line", CapLine(plan, draft[0], draft[1][0][:7], draft[1][0], draft[1][1], draft[2], trace(), payment_date, direction, ts.file_at, sha, ts.control, draft[3]))

    def put(draft):
        """Lines go out as soon as the payment header is seen; before that, a fixed number wait for it."""
        nonlocal lines, lost, full
        lines += 1
        if bpr is not None and trace():
            while held:
                give(held.pop(0))
            give(draft)
        elif len(held) < _HELD:
            held.append(draft)
        else:
            if not full:
                full = True
                bad("set", "header_late", ts.offset)
            lost += 1

    def stray():
        nonlocal names
        if names:
            bad("segment", "misplaced_segment", names[1], "NM1*IL not followed by RMR")
        names = None

    def close():
        nonlocal line, lost
        if line is None:
            return
        done, line = line, None
        for cause, ok in (("no_plan", plan), ("bad_member_qualifier", not done["ent_bad"]), ("no_member", done["member"] or member),
                          ("bad_amount", done["amount"] is not None), ("bad_report_period", done["period"])):
            if not ok:
                lost += 1
                bad("segment", cause, done["offsets"][0], "RMR")
                return
        if member and done["member"] and member != done["member"]:
            lost += 1
            bad("segment", "member_conflict", done["offsets"][0], "ENT and NM1*IL disagree")
            return
        put((done["member"] or member, done["period"], done["amount"], tuple(done["offsets"])))

    for seg in ts.segments:
        sid = seg.id
        if sid not in KNOWN:
            bad("segment", "unknown_segment", seg.offset, sid)
        elif sid == "BPR":
            if bpr is not None:
                bad("segment", "repeated_segment", seg.offset, "BPR")
                continue
            bpr = seg
            direction = x12.element(seg, 3)
            if x12.element(seg, 16):
                payment_date = x12.x12_date(x12.element(seg, 16)) or ""
                if not payment_date:
                    bad("segment", "bad_date", seg.offset, "BPR16")
        elif sid == "TRN":
            if trn is not None:
                bad("segment", "repeated_segment", seg.offset, "TRN")
            else:
                trn = seg
        elif sid == "N1" and x12.element(seg, 1) == "PE" and line is None and not plan:
            plan = x12.element(seg, 4)
        elif sid == "ENT":
            close()
            stray()
            ent_bad = x12.element(seg, 2) not in ("2J", "IL") or x12.element(seg, 3) not in ("ZZ", "34")
            member = "" if ent_bad else x12.element(seg, 4)
        elif sid == "RMR":
            close()
            line = {"amount": x12.cents(x12.element(seg, 4)), "member": names[0] if names else "", "period": None, "dtm": False,
                    "offsets": [seg.offset] + ([names[1]] if names else []), "ent_bad": ent_bad}
            names = None
        elif sid == "NM1" and x12.element(seg, 1) == "IL":
            close()
            stray()
            names = (x12.element(seg, 9), seg.offset)
        elif line is not None and sid == "DTM" and x12.element(seg, 1) == "582":
            if line["dtm"]:
                bad("segment", "repeated_segment", seg.offset, "DTM*582")
                continue
            line["dtm"] = True
            line["period"] = _period(seg)
            line["offsets"].append(seg.offset)
    close()
    stray()
    if bpr is None or not trace():  # the lines are still source facts: kept without a trace, and the count says how many
        cause = "bad_trace_type" if trn is not None and x12.element(trn, 2) and not trace() else "no_payment_header"
        emit("finding", x12.Quarantine("set", cause, ts.offset, f"{lines} lines kept without a trace or payment header"))
    total = x12.cents(x12.element(bpr, 2)) if bpr is not None else None
    if bpr is not None and total is None:
        bad("segment", "bad_amount", bpr.offset, "BPR02")
    while held:
        give(held.pop(0))
    if bpr is None:
        return
    if total is not None and lost:
        emit("finding", x12.Quarantine("set", "total_unchecked", bpr.offset, "a line was quarantined"))
    elif total is not None and total != paid:
        emit("finding", x12.Quarantine("set", "total_mismatch", bpr.offset, f"BPR02={total} lines={paid}"))
    emit("payment", Payment(trace(), total, paid, given, plan, ts.control, bpr.offset))


def _period(seg):
    """(begin, end) ISO of DTM*582: one day (a single date) or a range (RD8) inside one report month, else None."""
    if x12.element(seg, 5) == "RD8":
        first, _, last = x12.element(seg, 6).partition("-")
        first, last = x12.x12_date(first), x12.x12_date(last)
    else:
        first = last = x12.x12_date(x12.element(seg, 2))
    return (first, last) if first and last and first <= last and first[:7] == last[:7] else None
