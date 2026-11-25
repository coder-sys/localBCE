"""834 benefit-enrollment reader: one plain row per member coverage, every fact citing its file hash and byte offsets.

A member loop (2000) is read for its identity, maintenance type and reason, eligibility dates and death date; the
member's name loop (2100A) for name, address and demographics; each coverage loop (2300) for plan and benefit dates.
Valid time (the effective dates) and the time the state knew it (the group's own date and time, `file_at`) are both
kept. A segment or loop that cannot be read is quarantined with a cause and the rest of the member is still read (an
INS whose INS01 or INS03 does not read too: its row carries them as sent, so its identifier is never lost; a member loop with
no identifier gives no row, and its quarantine names its member as sent, "last*first*birth date", or "" when it has no last name or it is not UTF-8). A
second copy of a segment or loop is never merged with the first; the first is read, the second quarantined. A member
who appears twice in one file is reported in `duplicates`, with every row kept, for whoever owns the record to decide.
Nothing here decides whether a date is plausible: a death date before or after coverage is reported as sent. A segment
in the name loop that this reader does not read is quarantined, not dropped. When the name loop's identifier and a
REF*0F name different members, the REF*0F stands and the disagreement is reported in `findings`.
"""

from typing import NamedTuple

from app import right_rail_x12 as x12

KNOWN = frozenset("BGN REF DTP N1 N2 N3 N4 ACT INS NM1 PER DMG HD LUI AMT COB ICM IDC LS LE LX QTY PLA HLH EC DSB PRV".split())
_ELIGIBILITY_DATES = {"356": "eligibility_begin", "357": "eligibility_end", "303": "maintenance_effective"}
_BENEFIT_DATES = {"348": "coverage_begin", "349": "coverage_end"}


class Enrollment(NamedTuple):
    member_id: str
    maintenance_type: str  # INS03, such as 021 addition, 024 cancellation
    maintenance_reason: str  # INS04
    subscriber: str  # INS01, Y or N
    benefit_status: str  # INS05
    plan: str  # HD04, "" when the member has no coverage loop
    coverage_line: str  # HD03
    coverage_begin: str  # ISO dates, "" when not sent
    coverage_end: str
    eligibility_begin: str
    eligibility_end: str
    maintenance_effective: str
    death_date: str
    birth_date: str
    gender: str
    last_name: str
    first_name: str
    street: str
    city: str
    state: str
    zip: str
    file_at: str  # when the sender says the file was made
    file_sha3_512: str
    set_control: str
    offsets: tuple  # byte offsets of every segment that gave a value, INS first
    name_raw_hex: str = ""  # the name segment's raw bytes when they are not valid UTF-8 (the names above then hold replacement marks)
    coverage_type: str = ""  # HD01, the coverage's own maintenance type (024 cancels it)
    interchange: int = 0  # the byte offset of the ISA above the row; with file_sha3_512 it names the interchange in any number of reads


class Roster(NamedTuple):
    """One transaction set as its own header says, whether or not it holds a member loop."""
    file_at: str  # its group's date and time
    file_sha3_512: str
    interchange: int  # the byte offset of the ISA above it
    action: str  # the whole BGN08, trimmed and in capitals ("2" change, "RX" replace, "4" verify); "" when absent or when two BGN in its header differ
    start: int  # the byte offset of its ST


class Read834(NamedTuple):
    rows: tuple
    duplicates: tuple  # (member_id, INS offsets) for ids that open more than one member loop
    findings: tuple  # Quarantine-shaped, nothing dropped: member_id_conflict
    quarantines: tuple
    repairs: tuple
    refused: str
    rosters: tuple = ()  # a Roster for each transaction set read, so a fault is placed in its own set and an empty set still counts
    reads: tuple = ()  # (file hash, number of quarantines, number of findings) per read, in order, so reads joined field by field still place each fault in its own file


def stream_834(data, sink):
    """Read bytes or a seekable file into `sink` (see right_rail_x12.Sink), one member at a time; returns the refusal cause or ""."""
    return x12.read(data, sink, "834", _read_set)


def read_834(data):
    sink = x12.Collector()
    refused = stream_834(data, sink)
    findings, quarantines, rosters = sink.get("finding"), tuple(sink.envelope) + sink.get("quarantine"), sink.get("roster")
    return Read834(sink.get("row"), sink.duplicates(), findings, quarantines, tuple(sink.counts.items()), refused, rosters,
                   ((rosters[0].file_sha3_512 if rosters else "", len(quarantines), len(findings)),))  # no set read: no fault in it is in a member loop


def _read_set(sha, ts, emit):
    member = None
    loop = ""
    action = None

    def bad(unit, cause, at, detail=""):
        emit("quarantine", x12.Quarantine(unit, cause, at, detail))

    def date_of(segment, number, fmt_number):
        """ISO date of segment element `number`, "" if absent; quarantines and returns "" if not a real D8 date."""
        text = x12.element(segment, number)
        if not text:
            return ""
        iso = x12.x12_date(text) if x12.element(segment, fmt_number) == "D8" else None
        if iso is None:
            bad("segment", "bad_date", segment.offset, segment.id)
            return ""
        return iso

    def once(store, key, segment):
        if key in store:
            bad("segment", "repeated_segment", segment.offset, f"{segment.id} {key}")
            return False
        store[key] = None
        return True

    def close():
        if member is None:
            return
        if not member["id"]:
            # the member as sent, "last*first*birth date" (a value with a "*" in it splits wrong and names no one), so the members it may be are held, not every one
            bad("loop", "no_member_id", member["start"], f"{member['last']}*{member['first']}*{member['dob']}" if member["last"] and not member["name_raw"] else "")
            return
        emit("seen", (member["id"], member["start"]))
        covers = member["covers"] or [{"offsets": []}]
        for cover in covers:
            emit("row", Enrollment(
                member["id"], member["type"], member["reason"], member["subscriber"], member["status"],
                cover.get("plan", ""), cover.get("line", ""), cover.get("coverage_begin", ""), cover.get("coverage_end", ""),
                member["dates"].get("eligibility_begin", ""), member["dates"].get("eligibility_end", ""),
                member["dates"].get("maintenance_effective", ""), member["death"], member["dob"], member["gender"],
                member["last"], member["first"], member["street"], member["city"], member["state"], member["zip"],
                ts.file_at, sha, ts.control, tuple(member["offsets"] + cover["offsets"]), member["name_raw"], cover.get("type", ""), ts.interchange))

    for seg in ts.segments:
        sid = seg.id
        if sid not in KNOWN:
            bad("segment", "unknown_segment", seg.offset, sid)
            continue
        if sid == "INS":
            close()
            member = None
            loop = "member"
            if x12.element(seg, 1) not in ("Y", "N") or not x12.element(seg, 3):  # the loop is still read: its REF*0F names whose record it hurts
                bad("segment", "bad_ins", seg.offset, "INS01 or INS03 missing or invalid")
            member = {"id": "", "type": x12.element(seg, 3), "reason": x12.element(seg, 4), "subscriber": x12.element(seg, 1), "status": x12.element(seg, 5), "dates": {}, "death": "",
                      "dob": "", "gender": "", "last": "", "first": "", "street": "", "city": "", "state": "", "zip": "",
                      "offsets": [seg.offset], "covers": [], "keys": {}, "start": seg.offset, "name_id": "", "name_raw": ""}
            if x12.element(seg, 12):
                death = x12.x12_date(x12.element(seg, 12)) if x12.element(seg, 11) == "D8" else None
                if death is None:
                    bad("segment", "bad_death_date", seg.offset, "INS11/INS12")
                else:
                    member["death"] = death
            continue
        if member is None:
            if sid == "BGN":  # the set's header: a second BGN that disagrees leaves no action, so the set reads as a full roster
                code = ":".join(seg.elements[7]).strip().upper() if len(seg.elements) > 7 else ""  # every part: 2:RX is not 2
                action = code if action in (None, code) else ""
            continue
        keys = member["keys"]
        if sid == "NM1":
            if x12.element(seg, 1) != "IL":
                loop = "other"
            elif "NM1" in keys:
                bad("loop", "repeated_loop", seg.offset, "second member name loop")
                loop = "other"
            else:
                keys["NM1"] = None
                loop = "name"
                member["last"], member["first"], member["name_raw"] = x12.element(seg, 3), x12.element(seg, 4), seg.raw
                member["offsets"].append(seg.offset)
                if x12.element(seg, 8) == "MI" and x12.element(seg, 9):
                    member["name_id"] = x12.element(seg, 9)
                    if not member["id"]:
                        member["id"] = member["name_id"]  # stands unless a REF*0F follows
                    elif member["id"] != member["name_id"]:
                        emit("finding", x12.Quarantine("segment", "member_id_conflict", seg.offset, "NM1 and REF*0F name different members"))
        elif sid in ("COB", "LS"):
            loop = "other"
        elif sid == "HD":
            loop = "cover"
            member["covers"].append({"type": x12.element(seg, 1), "plan": x12.element(seg, 4), "line": x12.element(seg, 3), "offsets": [seg.offset], "keys": {}})
        elif loop in ("member", "name") and sid == "REF" and x12.element(seg, 1) == "0F":
            if once(keys, "REF0F", seg):
                if not x12.element(seg, 2):
                    bad("segment", "empty_member_id", seg.offset)
                else:
                    if member["name_id"] and member["name_id"] != x12.element(seg, 2):
                        emit("finding", x12.Quarantine("segment", "member_id_conflict", seg.offset, "NM1 and REF*0F name different members"))
                    member["id"] = x12.element(seg, 2)
                    member["offsets"].append(seg.offset)
        elif loop == "member" and sid == "DTP" and x12.element(seg, 1) in _ELIGIBILITY_DATES:
            if once(keys, "DTP" + x12.element(seg, 1), seg):
                member["dates"][_ELIGIBILITY_DATES[x12.element(seg, 1)]] = date_of(seg, 3, 2)
                member["offsets"].append(seg.offset)
        elif loop == "name" and sid in ("N3", "N4", "DMG"):
            if not once(keys, sid, seg):
                continue
            member["offsets"].append(seg.offset)
            if sid == "N3":
                member["street"] = " ".join(p for p in (x12.element(seg, 1), x12.element(seg, 2)) if p)
            elif sid == "N4":
                member["city"], member["state"], member["zip"] = x12.element(seg, 1), x12.element(seg, 2), x12.element(seg, 3)
            else:
                member["dob"] = date_of(seg, 2, 1)
                member["gender"] = x12.element(seg, 3)
        elif loop == "name":
            bad("segment", "unread_segment", seg.offset, f"{sid} in the member name loop")
        elif loop == "cover" and sid == "DTP" and x12.element(seg, 1) in _BENEFIT_DATES:
            cover = member["covers"][-1]
            if once(cover["keys"], "DTP" + x12.element(seg, 1), seg):
                cover[_BENEFIT_DATES[x12.element(seg, 1)]] = date_of(seg, 3, 2)
                cover["offsets"].append(seg.offset)
        elif sid == "DTP" and x12.element(seg, 1) in _ELIGIBILITY_DATES | _BENEFIT_DATES:  # a date read in the wrong loop would be dropped
            bad("segment", "unread_segment", seg.offset, f"DTP*{x12.element(seg, 1)} outside its loop")
    close()
    emit("roster", Roster(ts.file_at, sha, ts.interchange, action or "", ts.offset))

