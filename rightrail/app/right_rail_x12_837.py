"""837 claim reader (professional 837P and institutional 837I): one plain row per service line, citing file hash and offsets.

Per claim it reads the billing provider (2010AA NM1*85, NPI), the subscriber (2010BA NM1*IL) and patient (a patient
level, HL 23, or an NM1*QC marks a dependent, with or without the identifier 5010 no longer sends), the rendering provider (NM1*82 NPI, the line's over the claim's; X12 omits it when it is the billing provider), the claim (CLM:
id, total charge in cents, facility code, frequency code), the diagnoses (HI), and per service line LX with SV1
(professional) or SV2 (institutional): procedure, modifiers, revenue code, units, charge and DTP*472 service date. A
replacement (frequency 7) or void (frequency 8) keeps the original claim reference (REF*F8) and is never applied here: it is
a fact for the claim record's owner. A claim or line that cannot be read in full (no billing NPI, a rendering provider
without one, a charge that will not parse, replacement or void without its reference, no service line) is quarantined at its
unit with a cause; nothing is inferred and the rest of the file is read. An HL whose number is not the previous plus one, whose
parent is unseen, or whose code is not 20, 22 or 23 is quarantined and clears the billing provider, subscriber and patient, so the
next claim is set aside, never attached to the previous member. So is a subscriber, patient or billing provider segment (NM1*IL, NM1*QC,
SBR, NM1*85, PAT) met while a claim is open: no HL came before it, so it closes the claim and is a fault in the gap between the claims.
An unknown segment never extends a claim: one after a claim's last read segment is a fault in the gap, holding the claims above and below. A claim id that opens more than one claim is reported in
`duplicates` with every row kept. A CLM02 that differs from the sum of its kept line charges is a finding; no amount changes.
A claim with a line or a segment of it quarantined (a second NM1*82, DTP*472, SV1, SV2 or REF*F8, an unknown segment) has
its total unchecked, a finding, so it is never taken as whole.
"""

from typing import NamedTuple

from app import right_rail_x12 as x12
from app.right_rail_reader_lines import name_tokens

KNOWN = frozenset("BHT HL PRV CUR NM1 N3 N4 REF DMG SBR PAT CLM DTP CL1 PWK CN1 AMT HI HCP LX SV1 SV2 SV5 CR1 CR2 CR3 CR5 CRC QTY OI MOA "
                  "LIN CTP SVD CAS PS1 NTE K3 DN1 DN2 PER OTI SV3 SV4 SV6 SV7 TOO LQ FRM MEA".split())

_HEADER = frozenset(("HL", "CLM", "N3", "N4", "DMG"))  # the segments that may head a claim (a subscriber or patient segment after a line, or any billing provider or PAT, is a fault)


class ClaimLine(NamedTuple):
    claim_id: str  # CLM01
    line_number: str  # LX01
    form: str  # "P" professional (SV1) or "I" institutional (SV2)
    billing_npi: str
    rendering_npi: str
    subscriber_id: str
    patient_id: str  # NM1*QC's identifier, "" when not sent (5010 sends none) or the patient is the subscriber
    total_charge_cents: int  # CLM02, the whole claim's charge
    facility_code: str  # CLM05-1
    frequency_code: str  # CLM05-3: 1 original, 7 replacement, 8 void
    original_claim_ref: str  # REF*F8; required with 7 and 8
    diagnoses: tuple  # (qualifier, code) from every HI element
    procedure_qualifier: str
    procedure: str
    modifiers: tuple
    revenue_code: str  # institutional only
    units_milli: object  # units in thousandths, None if not sent
    line_charge_cents: int
    service_begin: str  # DTP*472, ISO; "" if not sent
    service_end: str
    file_at: str
    file_sha3_512: str
    set_control: str
    offsets: tuple  # byte offsets of the segments that gave a value
    dependent: bool = False  # the patient is not the subscriber: a patient level (HL 23) or an NM1*QC above the claim
    names: tuple = ()  # the billing and the rendering provider's names, as right_rail_reader_lines.name_tokens reads them (sets of words)
    line_control: str = ""  # REF*6R on the line: the line control number the payer's 835 repeats; "" when not sent or sent twice


class ClaimAt(NamedTuple):
    """Every claim the file opens, read whole or not: where it lies, so a fault can be held to the claims it may belong to, and what a
    replacement or void says of the claim it names, as read before any fault, so a void that did not read still holds its claim."""
    id: str  # CLM01, "" when not sent
    offset: int  # its CLM segment
    end: int  # its last segment that was read; the segments after it, up to the next CLM, head the next claim
    cents: int  # CLM02, 0 when it does not read
    frequency: str  # CLM05-3, "" when not sent
    refs: tuple  # each REF*F8 value in order, a repeat the reader set aside too, so a void naming two claims holds both; () when none was sent
    npi: str  # the billing NPI above it, "" when none was read
    subscriber: str  # the subscriber id above it, "" when none was read
    first: str  # its earliest and latest service day on any line, read whole or not, ISO; both "" (any day) when a line has none that read
    last: str
    set: int  # offsets of the ST, GS and ISA above it
    group: int
    interchange: int
    void: bool  # its set, group or interchange was taken back, so it has no rows


class Read837(NamedTuple):
    rows: tuple
    duplicates: tuple  # (claim_id, CLM offsets) for ids that open more than one claim
    findings: tuple  # Quarantine-shaped, nothing dropped: total_mismatch, total_unchecked
    quarantines: tuple
    repairs: tuple
    refused: str
    claims: tuple = ()  # ClaimAt of every claim, in file order


def stream_837(data, sink):
    """Read bytes or a seekable file into `sink` (see right_rail_x12.Sink), one claim at a time; returns the refusal cause or ""."""
    return x12.read(data, sink, "837", _read_set)


def read_837(data):
    sink = x12.Collector()
    refused = stream_837(data, sink)
    return Read837(sink.get("row"), sink.duplicates(), sink.get("finding"), tuple(sink.envelope) + sink.get("quarantine"),
                   tuple(sink.counts.items()), refused,
                   tuple(ClaimAt(*c, *w) for c, *w in sink.where("claim")))


def _service_dates(seg):
    """(begin, end) ISO for DTP*472 in D8 or RD8, or None."""
    fmt, text = x12.element(seg, 2), x12.element(seg, 3)
    if fmt == "D8":
        day = x12.x12_date(text)
        return (day, day) if day else None
    if fmt == "RD8":
        first, _, last = text.partition("-")
        first, last = x12.x12_date(first), x12.x12_date(last)
        return (first, last) if first and last and first <= last else None
    return None


def _read_set(sha, ts, emit):
    billing = sub = patient = None  # (value, offset) from the hierarchy above the claim; the billing provider's also its name
    claim = None
    line = None
    hl_seen, hl_last = set(), 0
    tops, top = {}, None  # the billing provider of each billing level (HL 20) by its number; the one whose NM1*85 is next

    def bad(unit, cause, at, detail=""):
        if claim is not None and unit == "segment":  # a claim with a segment of it set aside is never sent as if whole
            claim["lost"] = True
        emit("quarantine", x12.Quarantine(unit, cause, at, detail))

    def close_line():
        nonlocal line
        if line is None:
            return
        done, line = line, None
        claim["days"] += [done.get("begin", ""), done.get("end", "")]  # "" when its date did not read or none was sent
        if "sv" not in done:
            claim["lost"] = True
            bad("loop", "no_sv_segment", done["offsets"][0])
        elif done["fault"]:
            claim["lost"] = True
            bad(done["fault"][0], done["fault"][1], done["fault"][2])
        else:
            claim["lines"].append(done)

    def close_claim():
        nonlocal claim
        if claim is None:
            return
        close_line()
        done, claim = claim, None
        first = min(done["days"], default="")  # "" when a line has no day that read: then the claim may be any day
        emit("claim", (done["id"], done["offsets"][0], done["end"] if done["lx"] else done["offsets"][0], done["total"] or 0,  # with no line, what follows it may head the next claim
                       done["frequency"], tuple(done["refs"]), billing[0] if billing else "", sub[0] if sub else "", first, max(done["days"]) if first else ""))
        if done["id"]:
            emit("seen", (done["id"], done["offsets"][0]))
        fault = done["fault"]
        if fault is None and not done["lines"]:
            fault = ("loop", "no_service_lines", done["offsets"][0])
        if fault is None and not billing:
            fault = ("loop", "no_billing_npi", done["offsets"][0])
        if fault is None and not sub:
            fault = ("loop", "no_subscriber", done["offsets"][0])
        if fault is None and done["frequency"] in ("7", "8") and not done["ref"]:
            fault = ("loop", "missing_original_ref", done["offsets"][0])
        if fault:
            bad(fault[0], fault[1], fault[2])
            return
        paid = sum(ln["charge"] for ln in done["lines"])
        if done["lost"]:
            emit("finding", x12.Quarantine("loop", "total_unchecked", done["offsets"][0]))
        elif done["total"] != paid:
            emit("finding", x12.Quarantine("loop", "total_mismatch", done["offsets"][0], f"CLM02={done['total']} lines={paid}"))
        base = (done["offsets"][0],) + ((billing[1],) if billing else ()) + ((sub[1],) if sub else ()) + ((patient[1],) if patient else ())
        for ln in done["lines"]:
            emit("row", ClaimLine(
                done["id"], ln["number"], ln["form"], billing[0], ln["rend"] or done["rend"] or billing[0], sub[0], patient[0] if patient else "",
                done["total"], done["facility"], done["frequency"], done["ref"], tuple(done["dx"]), ln["pq"], ln["proc"], ln["mods"], ln["rev"],
                ln["units"], ln["charge"], ln["begin"], ln["end"], ts.file_at, sha, ts.control, base + tuple(done["offsets"][1:]) + tuple(ln["offsets"]),
                patient is not None, (billing[2], ln.get("rname") or done.get("rname") or billing[2]), ln.get("ctl", "")))

    for seg in ts.segments:
        sid = seg.id
        who = x12.element(seg, 1) if sid == "NM1" else ""
        other = claim is not None and claim["sbr"] and not claim["lx"]  # in an other-payer loop (2320, after its SBR): its NM1 loops (2330) are not the claim's
        if claim is not None and ((sid == "PAT" or who == "85") and not other or who == "QC" or (claim["lx"] and (sid == "SBR" or who == "IL"))):  # a header segment with no HL since the CLM: whose is it?
            close_claim()
            bad("segment", "header_without_hl", seg.offset, sid)
            billing = sub = patient = None
            continue
        if claim is not None and sid in KNOWN and sid not in _HEADER and who != "PR":
            claim["end"] = seg.offset  # a segment that is not the next claim's header; an unknown one may be, so it never extends the claim
        if sid not in KNOWN:
            bad("segment", "unknown_segment", seg.offset, sid)
        elif sid == "HL":
            close_claim()
            code, number, parent = x12.element(seg, 3), x12.element(seg, 1), x12.element(seg, 2)
            if code not in ("20", "22", "23") or not number.isascii() or not number.isdigit() or len(number) > 12 or int(number) != hl_last + 1 or (parent and parent not in hl_seen):
                bad("segment", "bad_hl", seg.offset, "HL01, HL02 or HL03")
                billing = sub = patient = top = None
                if not (number.isascii() and number.isdigit() and len(number) <= 12 and int(number) <= hl_last):
                    hl_last += 1  # the number it should have had: a later HL is judged on its own, not held for this one; its children fail on the unseen parent (a repeat or too-low number leaves it alone)
                continue
            hl_seen.add(number)
            hl_last = int(number)
            if code == "20":
                billing = sub = patient = None
                top = number
            elif code == "22":
                billing, sub, patient = tops.get(parent), None, None  # its own billing provider, whatever level above it was lost
            else:
                patient = ("", seg.offset)  # a dependent, named or not by the NM1*QC that may follow
        elif sid == "NM1" and claim is None:
            who = x12.element(seg, 1)
            if who == "85":
                billing = (x12.element(seg, 9), seg.offset, name_tokens(x12.element(seg, 3), x12.element(seg, 4), x12.element(seg, 5))) if x12.element(seg, 8) == "XX" and x12.element(seg, 9) else None
                if top:
                    tops[top] = billing
            elif who == "IL":
                sub = (x12.element(seg, 9), seg.offset) if x12.element(seg, 9) else None
            elif who == "QC":
                patient = (x12.element(seg, 9), seg.offset)
        elif sid == "CLM":
            close_claim()
            total = x12.cents(x12.element(seg, 2))
            claim = {"id": x12.element(seg, 1), "total": total, "facility": x12.element(seg, 5, 1), "frequency": x12.element(seg, 5, 3),
                     "ref": "", "refs": [], "dx": [], "lines": [], "days": [], "offsets": [seg.offset], "end": seg.offset, "fault": None, "lost": False, "rend": None, "lx": False, "sbr": False}
            if not claim["id"]:
                claim["fault"] = ("loop", "no_claim_id", seg.offset)
            elif total is None:
                claim["fault"] = ("loop", "bad_total_charge", seg.offset)
            elif not claim["frequency"]:
                claim["fault"] = ("loop", "no_frequency_code", seg.offset)
        elif claim is None:
            continue
        elif sid == "SBR":
            claim["sbr"] = True
        elif sid == "NM1" and who == "82" and not other:
            unit = claim if line is None else line
            if unit["rend"] is not None:
                bad("segment", "repeated_segment", seg.offset, "NM1*82")
                continue
            unit["rend"] = x12.element(seg, 9) if x12.element(seg, 8) == "XX" else ""
            unit["rname"] = name_tokens(x12.element(seg, 3), x12.element(seg, 4), x12.element(seg, 5))
            unit["offsets"].append(seg.offset)
            unit["fault"] = unit["fault"] or (None if unit["rend"] else ("loop", "no_rendering_npi", seg.offset))
        elif sid == "REF" and x12.element(seg, 1) == "F8" and line is None:
            claim["refs"].append(x12.element(seg, 2))
            if claim["ref"]:
                bad("segment", "repeated_segment", seg.offset, "REF*F8")
            else:
                claim["ref"] = x12.element(seg, 2)
                claim["offsets"].append(seg.offset)
        elif sid == "REF" and x12.element(seg, 1) == "6R" and line is not None:
            line["ctl"] = "" if "ctl" in line else x12.element(seg, 2)  # sent twice: no number; nothing else is quarantined for it
        elif sid == "HI" and line is None:
            claim["offsets"].append(seg.offset)
            for part in seg.elements:
                if part[0] or len(part) > 1:
                    claim["dx"].append((part[0], part[1] if len(part) > 1 else ""))
        elif sid == "LX":
            close_line()
            claim["lx"] = True
            line = {"number": x12.element(seg, 1), "offsets": [seg.offset], "fault": None, "rend": None}
        elif line is not None and sid in ("SV1", "SV2"):
            if "sv" in line:
                bad("segment", "repeated_segment", seg.offset, sid)
                continue
            line["sv"] = True
            line["offsets"].append(seg.offset)
            prof = sid == "SV1"
            comp = seg.elements[0 if prof else 1] if len(seg.elements) > (0 if prof else 1) else ("",)
            line.update(form="P" if prof else "I", pq=comp[0], proc=comp[1] if len(comp) > 1 else "", mods=tuple(m for m in comp[2:6] if m),
                        rev="" if prof else x12.element(seg, 1), begin="", end="")
            charge = x12.cents(x12.element(seg, 2 if prof else 3))
            units_text = x12.element(seg, 4 if prof else 5)
            units = x12.scaled(units_text, 3) if units_text else None
            if charge is None:
                line["fault"] = ("loop", "bad_line_charge", seg.offset)
            elif units_text and units is None:
                line["fault"] = ("loop", "bad_units", seg.offset)
            elif not prof and not line["rev"]:
                line["fault"] = ("loop", "no_revenue_code", seg.offset)
            line["charge"], line["units"] = charge, units
        elif line is not None and sid == "DTP" and x12.element(seg, 1) == "472" and "sv" in line:
            if line["begin"]:
                bad("segment", "repeated_segment", seg.offset, "DTP*472")
                continue
            dates = _service_dates(seg)
            if dates is None:
                bad("segment", "bad_date", seg.offset, "DTP*472")
                line["fault"] = line["fault"] or ("loop", "bad_service_date", seg.offset)
            else:
                line["begin"], line["end"] = dates
                line["offsets"].append(seg.offset)
    close_claim()
