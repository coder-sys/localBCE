"""835 remittance reader: claim payments, service lines, adjustments and provider-level adjustments, in integer cents.

A payment set carries the payment (BPR total and direction, TRN trace, payer N1*PR, payee N1*PE with its NPI), then per
claim a CLP (claim id, status, charge, paid, patient responsibility, payer claim control number) with CAS adjustments
(group, then repeated reason/amount/quantity triples) and SVC service lines with their own CAS; PLB carries
provider-level adjustments. A segment whose amount will not parse is quarantined whole, a claim whose CLP will not
parse with everything under it; nothing is inferred. The payment total is checked against the sum of the claim paid
amounts minus the PLB amounts (PLB amounts are positive when they reduce the payment). A difference is a finding
reported with the numbers, not a refusal and not a quarantine: the claims are still source facts. In the same way a
claim's paid amount (CLP04) is compared with the sum of its service line paid amounts when it has any, and a claim id
used by more than one claim is reported in `duplicates` with every row kept. A payment date (BPR16) that is not a real
date is quarantined and left empty. A set with no BPR or no TRN02 keeps its claims with an empty trace and a finding counts
them; a CLP05 left out stays out of that claim's row and the claim is still read.
"""

from typing import NamedTuple

from app import right_rail_x12 as x12

_HELD = 2000  # records that may wait for a late payment header before the rest of the set is dropped
KNOWN = frozenset("BPR TRN CUR REF DTM N1 N2 N3 N4 PER LX TS3 TS2 NM1 CLP CAS MIA MOA RDM AMT QTY LQ SVC PLB ADX".split())


class ClaimPayment(NamedTuple):
    trace: str
    payer_id: str  # N1*PR N104
    payer_name: str
    payee_npi: str  # N1*PE N104 when N103 is XX
    claim_id: str  # CLP01
    status: str  # CLP02
    charge_cents: int
    paid_cents: int
    patient_responsibility_cents: object  # CLP05, None when the sender left it out
    payer_claim_control: str  # CLP07
    adjustments: tuple  # (group, reason, cents, quantity text) at claim level
    file_at: str
    file_sha3_512: str
    set_control: str
    offsets: tuple  # CLP first, then its CAS segments


class ServicePayment(NamedTuple):
    claim_id: str
    procedure_qualifier: str
    procedure: str
    modifiers: tuple
    revenue_code: str
    charge_cents: int
    paid_cents: int
    units_milli: object  # paid units in thousandths, None if not sent
    service_date: str  # DTM*472, ISO, "" if not sent
    adjustments: tuple
    file_sha3_512: str
    set_control: str
    offsets: tuple
    line_control: str = ""  # REF*6R under the service line: the line control number the claim was sent with, "" when not sent or repeated


class ProviderAdjustment(NamedTuple):
    trace: str
    provider_id: str  # PLB01
    fiscal_period: str  # PLB02, ISO
    reason_code: str  # PLB03-1
    reference: str  # PLB03-2
    amount_cents: int  # positive reduces the payment
    file_sha3_512: str
    set_control: str
    offset: int


class Payment(NamedTuple):
    trace: str
    total_cents: object  # BPR02, None when it would not parse
    direction: str  # BPR03
    payment_date: str
    paid_cents: int  # sum of CLP paid amounts read
    provider_adjustment_cents: int
    set_control: str
    offset: int


class Read835(NamedTuple):
    claims: tuple
    services: tuple
    provider_adjustments: tuple
    payments: tuple
    duplicates: tuple  # (claim_id, CLP offsets) for ids that open more than one claim
    findings: tuple  # Quarantine-shaped, but nothing is dropped: total_mismatch, total_unchecked
    quarantines: tuple
    repairs: tuple
    refused: str


def stream_835(data, sink):
    """Read bytes or a seekable file into `sink` (see right_rail_x12.Sink), one payment set at a time; returns the refusal cause or ""."""
    return x12.read(data, sink, "835", _read_set)


def read_835(data):
    sink = x12.Collector()
    refused = stream_835(data, sink)
    return Read835(sink.get("claim"), sink.get("service"), sink.get("plb"), sink.get("payment"), sink.duplicates(), sink.get("finding"),
                   tuple(sink.envelope) + sink.get("quarantine"), tuple(sink.counts.items()), refused)


def _adjustments(seg):
    """((group, reason, cents, quantity), ...) from one CAS, or None when any amount will not parse."""
    found = []
    for i in range(2, len(seg.elements) + 1, 3):
        if not x12.element(seg, i) and not x12.element(seg, i + 1):
            continue
        amount = x12.cents(x12.element(seg, i + 1))
        if not x12.element(seg, i) or amount is None:
            return None
        found.append((x12.element(seg, 1), x12.element(seg, i), amount, x12.element(seg, i + 2)))
    return tuple(found) if found and x12.element(seg, 1) else None


def _read_set(sha, ts, emit):
    bpr = trn = None
    payer = ("", "")
    payee = ""
    claim = service = None  # open CLP / SVC: dicts
    target = None  # where a CAS goes: the open claim's or service's adjustment list
    skip = False  # inside a quarantined CLP
    held, full = [], False  # records read before the trace is known, and whether the hold overflowed (the rest of the set is dropped)
    claims = total_paid = adjusted = 0
    unchecked = False

    def bad(unit, cause, at, detail=""):
        emit("quarantine", x12.Quarantine(unit, cause, at, detail))

    def trace():
        return x12.element(trn, 2) if trn is not None else ""

    def give(kind, item):
        nonlocal total_paid, adjusted
        if kind == "c":
            total_paid += item["amounts"][1]
            emit("seen", (item["id"], item["offsets"][0]))
            if item["svc_lost"]:
                emit("finding", x12.Quarantine("loop", "total_unchecked", item["offsets"][0], "a service line was quarantined"))
            elif item["svcs"] and item["svc_paid"] != item["amounts"][1]:
                emit("finding", x12.Quarantine("loop", "total_mismatch", item["offsets"][0], f"CLP04={item['amounts'][1]} svc={item['svc_paid']}"))
            emit("claim", ClaimPayment(trace(), payer[0], payer[1], payee, item["id"], item["status"], item["amounts"][0], item["amounts"][1],
                                       item["amounts"][2], item["control"], tuple(item["adj"]), ts.file_at, sha, ts.control, tuple(item["offsets"])))
        elif kind == "s":
            emit("service", ServicePayment(item["claim"], item["pq"], item["proc"], item["mods"], item["rev"], item["amounts"][0], item["amounts"][1],
                                           item["units"], item["date"], tuple(item["adj"]), sha, ts.control, tuple(item["offsets"]), item.get("ctl", "")))
        else:
            adjusted += item[3]
            emit("plb", ProviderAdjustment(trace(), item[0], item[1], item[2], item[5], item[3], sha, ts.control, item[4]))

    def put(kind, item):
        """Records go out as soon as the payment header is seen; before that, a fixed number wait for it."""
        nonlocal claims, unchecked, full
        claims += kind == "c"
        if bpr is not None and trace():
            while held:
                give(*held.pop(0))
            give(kind, item)
        elif len(held) < _HELD:
            held.append((kind, item))
        else:
            if not full:
                full = True
                bad("set", "header_late", ts.offset)
            unchecked = True

    def close_service():
        nonlocal service
        if service is not None:
            claim["svcs"] += 1
            claim["svc_paid"] += service["amounts"][1]
            put("s", service)
            service = None

    def close_claim():
        nonlocal claim, target
        close_service()
        if claim is not None:
            put("c", claim)
        claim = target = None

    for seg in ts.segments:
        sid = seg.id
        if sid not in KNOWN:
            bad("segment", "unknown_segment", seg.offset, "835 " + sid)
        elif sid == "BPR":
            if bpr is not None:
                bad("segment", "repeated_segment", seg.offset, "BPR")
            else:
                bpr = seg
        elif sid == "TRN":
            if trn is not None:
                bad("segment", "repeated_segment", seg.offset, "TRN")
            else:
                trn = seg
        elif sid == "N1" and claim is None and x12.element(seg, 1) == "PR":
            payer = (x12.element(seg, 4), x12.element(seg, 2))
        elif sid == "N1" and claim is None and x12.element(seg, 1) == "PE":
            payee = x12.element(seg, 4) if x12.element(seg, 3) == "XX" else ""
        elif sid == "CLP":
            close_claim()
            skip = False
            amounts = [x12.cents(x12.element(seg, n)) for n in (3, 4, 5)]
            if not x12.element(seg, 1) or None in amounts[:2] or (x12.element(seg, 5) and amounts[2] is None):  # CLP05 may be left out
                skip = True
                bad("loop", "bad_clp", seg.offset)
                unchecked = True
                continue
            claim = {"id": x12.element(seg, 1), "status": x12.element(seg, 2), "amounts": amounts, "control": x12.element(seg, 7),
                     "adj": [], "offsets": [seg.offset], "svcs": 0, "svc_paid": 0, "svc_lost": False}
            target = claim
        elif sid == "PLB":
            pairs = _plb(seg, bad)
            unchecked = unchecked or pairs is None
            for pair in pairs or ():
                put("p", pair)
        elif skip:
            continue
        elif sid == "CAS":
            adj = _adjustments(seg)
            if target is None:
                bad("segment", "cas_without_target", seg.offset)
            elif adj is None:
                bad("segment", "bad_cas", seg.offset)
            else:
                target["adj"].extend(adj)
                target["offsets"].append(seg.offset)
        elif sid == "SVC" and claim is not None:
            close_service()
            target = None
            first = seg.elements[0] if seg.elements else ("",)
            charge, paid = x12.cents(x12.element(seg, 2)), x12.cents(x12.element(seg, 3))
            units_text = x12.element(seg, 5)
            units = x12.scaled(units_text, 3) if units_text else None
            if charge is None or paid is None or (units_text and units is None):
                bad("loop", "bad_svc", seg.offset)
                claim["svc_lost"] = True
                unchecked = True
                continue
            service = {"claim": claim["id"], "pq": first[0], "proc": first[1] if len(first) > 1 else "", "mods": tuple(m for m in first[2:6] if m),
                       "rev": x12.element(seg, 4), "amounts": (charge, paid), "units": units, "date": "", "adj": [], "offsets": [seg.offset]}
            target = service
        elif sid == "REF" and service is not None and x12.element(seg, 1) == "6R":
            if "ctl" in service:  # a repeated control number says nothing: it is quarantined and the line has none
                bad("segment", "repeated_segment", seg.offset, "REF*6R")
                service["ctl"] = ""
            else:
                service["ctl"] = x12.element(seg, 2)
                service["offsets"].append(seg.offset)
        elif sid == "DTM" and service is not None and x12.element(seg, 1) == "472":
            day = x12.x12_date(x12.element(seg, 2))
            if day is None or service["date"]:
                bad("segment", "bad_date" if day is None else "repeated_segment", seg.offset, "DTM*472")
            else:
                service["date"] = day
                service["offsets"].append(seg.offset)
    close_claim()
    if bpr is None or not trace():  # the claims are still source facts: kept without a trace, and the count says how many
        emit("finding", x12.Quarantine("set", "no_payment_header", ts.offset, f"{claims} claims kept without BPR or TRN02"))
    while held:
        give(*held.pop(0))
    if bpr is None:
        return
    total = x12.cents(x12.element(bpr, 2))
    date = x12.x12_date(x12.element(bpr, 16)) or ""
    if x12.element(bpr, 16) and not date:
        bad("segment", "bad_date", bpr.offset, "BPR16")
    if total is None:
        bad("segment", "bad_amount", bpr.offset, "BPR02")
    unchecked = unchecked or total is None
    if unchecked:
        emit("finding", x12.Quarantine("set", "total_unchecked", bpr.offset, "a claim or provider adjustment was quarantined"))
    elif total != total_paid - adjusted:
        emit("finding", x12.Quarantine("set", "total_mismatch", bpr.offset, f"BPR02={total} claims={total_paid} plb={adjusted}"))
    emit("payment", Payment(trace(), total, x12.element(bpr, 3), date, total_paid, adjusted, ts.control, bpr.offset))


def _plb(seg, bad):
    """PLB records (provider, period, reason, amount, offset, reference), one per pair, or None. Any bad amount quarantines the segment."""
    period = x12.x12_date(x12.element(seg, 2))
    pairs = []
    for i in range(3, len(seg.elements) + 1, 2):
        amount = x12.cents(x12.element(seg, i + 1))
        if not x12.element(seg, i) or amount is None:
            pairs = None
            break
        pairs.append((x12.element(seg, i, 1), x12.element(seg, i, 2), amount))
    if not x12.element(seg, 1) or period is None or not pairs:
        bad("segment", "bad_plb", seg.offset)
        return None
    return [(x12.element(seg, 1), period, reason, amount, seg.offset, ref) for reason, ref, amount in pairs]
