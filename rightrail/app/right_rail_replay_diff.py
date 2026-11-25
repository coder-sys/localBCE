"""Replay difference report: the same claim lines decided by several systems, every line whose outcome differs, grouped by cause and system.

Read-only and pure: it reads nothing from disk but the staff cause table, writes nothing and decides nothing. Each side is a
system name and its claims; a claim is its lines, and a line is its line control number (REF*6R, the number the 837 sent and the
835 repeats), the cents the system paid, the cents billed and its cause codes (why it did not pay). Two adapters build a side:
``from_835`` from payment files already read (what a claims system paid; any number of them) and ``from_decision`` from the real gate path: the 837 files
read, the requests ``requests_of`` built from them and the rows ``decide_claims`` returned (payment id, line position, outcome,
reasons). ALLOW pays the line's billed cents; any other outcome pays nothing and carries the engine's reason names, each of which
must be in the staff cause table or the claim is set aside. ``from_gate`` takes rows already keyed by claim and control number.

A line is compared by ``<claim id>#<line control number>``. When any system lacks the number for any line of a claim (or
uses the word ``claim`` as one), the claim is compared as one key ``<claim id>#claim``, its lines summed, and the report counts
it under ``claim_level`` for each system that lacked the numbers. Nothing is dropped silently: a claim that cannot be compared
(an id repeated, a service line lost, a repeated line control number, a reversal, an unmappable gate row) is set aside whole on
every side and its items counted per system in ``set_aside``.

Any number of sides are compared (two or more, each under its own system name; the gate is one side among the others, so the
report can name it as the system at fault). The gate decides pay or hold and does not price: its paid cents are the billed charge. A
side from an 835 prices (``Side.prices``). A key differs when some side pays and another does not (the system that did not pay is at
fault, its single cause the first reason name, in sorted order, of the systems that did not pay, or ``NOT_PAID_NO_REASON``), when a
side has the line and another lacks it (``MISSING_ON_ONE_SIDE``, the side that lacks it at fault), or when every side that has it pays
and the sides that price it paid different cents (``PRICE_DIFFERS``; the sides off the most common amount are at fault, all of them
when no amount is most common, named joined by ``+``). A line that two non-pricing sides, or a pricing and a non-pricing side, both
pay agrees, whatever each paid. Cents at stake (so cents are never counted twice): the most any side paid, else billed, for a pay or
missing difference; the spread of the priced amounts for a price difference. Sides that all decline a line, for whatever reasons,
agree on the money and are not listed (a line one system lacks while every system that has it declines it is still counted as missing, at its
billed cents). The cents are a comparison figure, never a payable amount (``cents_meaning``). A ``system_map`` (``load_map``: data the state
supplies, pinned by its hash) names for every line the system at fault (``fault``) and its owner (``owner``), from each stopping side's own
cause: the map's step for that cause (a step ``@side`` says the side itself), else ``UNMAPPED:<cause>``, never a guess; sides that differ
all appear, sorted, joined by ``+``. A side the map does not name is refused, and a side that prices must not be a ``gate`` system, nor a side that does not. A system that could not be read whole (a refused file, a quarantined file, interchange,
group or set, or a claim that would not parse) is incomplete: a claim only another system has is counted in ``set_aside`` for the
incomplete system, never reported as missing. When the systems have line control numbers but not the same ones for a claim, the
claim is compared as one key, but only when each side is all paid or all unpaid and all have the same number of lines; otherwise
it is set aside on every side that has it (``claim:partly_paid_at_claim_level``). A claim whose 835 total does not add up
(``loop:total_mismatch``), that holds a quarantined segment (``loop:segment_quarantined``), or whose 835 payee NPI differs from
the 837 billing NPI, or any two sides name different NPIs (``claim:payee_differs``; an empty payee is keyed by claim id alone) is set aside the same way. The report is canonical JSON (sorted keys, compact, ASCII, one final newline), so the same
input gives the same bytes.
"""

import bisect
import functools
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import NamedTuple

from app import right_rail_gate_ffs as ffs

CONTRACT = "RR/REPLAY/DIFFERENCE-REPORT/v4"
CLAIM_KEY = "claim"
MAX_CENTS = 10 ** 10  # a line above this many cents (a hundred million dollars) is not a payment
CENTS_MEANING = "A comparison figure: the most any side paid (else billed), or the spread of priced amounts; not a payable amount."
_OUTCOMES = frozenset(("ALLOW", "HOLD", "HUMAN_REVIEW", "ANSWERED"))
_OWN = {  # causes this report names itself; every gate cause comes from app/cause_actions.json
    "MISSING_ON_ONE_SIDE": ("Only one system has this line.", "Find out why the other system never received or recorded the line."),
    "PRICE_DIFFERS": ("Systems that both paid the line paid different amounts.", "Ask the owner of each system named which price is right."),
    "NOT_PAID_NO_REASON": ("One system did not pay the line and gave no reason.", "Ask the owner of that system why the line was not paid."),
}


class Line(NamedTuple):
    control: str  # REF*6R, "" when the system did not have one
    paid: int
    billed: int
    causes: tuple


class Side(NamedTuple):
    system: str
    claims: dict  # claim id -> tuple of Line
    excluded: frozenset  # claim ids set aside whole: compared on neither side
    aside: dict  # "<unit>:<cause>" -> count
    incomplete: bool = False  # the system's input could not be read whole: a claim it lacks is not known to be missing
    npi: dict = {}  # claim id -> the provider NPI that system names for it (837 billing, 835 payee), "" when none; read only
    prices: bool = False  # its paid cents are its own price (an 835); the gate pays the billed charge and does not price


@functools.lru_cache(maxsize=1)
def _table():
    path = Path(__file__).with_name("cause_actions.json")
    return {row["code"]: (row["meaning"], row["action"]) for row in json.loads(path.read_text("utf-8"))}


def _words(code, table):
    if code in table:
        return table[code]
    if code in _OWN:
        return _OWN[code]
    if code.startswith("CARC_"):
        return (f"The remittance adjusted the line with reason code {code[5:]}.", "Look the code up in the payer's remittance guide and ask that system's owner.")
    return ("No staff wording is on file for this cause.", "Ask the owner of that system what the code means.")


def _cents(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_CENTS


def _key(claim, control):
    """``<claim>#<control>``, with "%" and "#" in either part written %25 and %23 so that no two keys read alike."""
    return "#".join(part.replace("%", "%25").replace("#", "%23") for part in (claim, control))


class _Build:
    """Claims, exclusions and set-aside counts of one side, filled by an adapter."""

    def __init__(self):
        self.claims, self.excluded, self.aside, self.npi = {}, set(), Counter(), {}

    def drop(self, claim_id, cause, count=1):
        if isinstance(claim_id, str) and claim_id:
            self.excluded.add(claim_id)
        self.aside[cause] += count

    def add(self, claim_id, lines):
        controls = [line.control for line in lines if line.control]
        if len(set(controls)) < len(controls):  # a repeated number cannot name a line
            self.drop(claim_id, "loop:duplicate_line_control", len(lines))
        elif claim_id not in self.excluded:
            self.claims[claim_id] = tuple(lines)

    def side(self, system, incomplete=False, prices=False):
        return Side(system, {c: v for c, v in self.claims.items() if c not in self.excluded}, frozenset(self.excluded), dict(self.aside), incomplete, dict(self.npi), prices)


def from_gate(system, rows, prices=False):
    """A side from rows ``{"claim": id, "control": 6R or "", "outcome": ..., "reasons": [...], "cents": n}``. A bad row, a reason the
    staff table does not name, or an ALLOW of zero cents (a paid line of nothing cannot be told from an unpaid one) is counted aside
    and sets its claim aside whole."""
    build, found, table = _Build(), {}, _table()
    for row in rows:
        reasons = row.get("reasons") if isinstance(row, dict) else None
        claim = row.get("claim") if isinstance(row, dict) else None
        if not (isinstance(claim, str) and claim and isinstance(row.get("control"), str) and row.get("outcome") in _OUTCOMES and _cents(row.get("cents"))
                and isinstance(reasons, (list, tuple)) and all(isinstance(r, str) and r for r in reasons)):
            build.drop(claim, "row:bad_row")
        elif any(r not in table for r in reasons):
            build.drop(claim, "row:unknown_reason")
        elif row["outcome"] == "ALLOW" and not row["cents"]:
            build.drop(claim, "row:allow_zero_cents")
        else:
            paid = row["cents"] if row["outcome"] == "ALLOW" else 0
            found.setdefault(claim, []).append(Line(row["control"], paid, row["cents"], () if paid else tuple(sorted(set(reasons)))))
    for claim, lines in found.items():
        build.add(claim, lines)
    return build.side(system, prices=prices)


def from_decision(system, reads, sent, rows, left, feed_left=(), ruleset_left=()):
    """A side from the real decide path: ``reads`` (Read837), ``sent`` and ``left`` (what ``requests_of`` returned for them) and
    ``rows`` (what ``decide_claims`` returned). A request's line i is line i of the first copy of its claim in the files, and its
    cents and line control number are that 837 line's. A claim the gate never decided (``left``), a payment id no 837 claim
    gives, a claim id under more than one payment id, a line count that differs from its request's, a line with no row or two rows is
    set aside, never guessed.  ``feed_left`` is what ``feeds`` set aside (members and providers, not claims): each is counted in
    ``aside`` as ``feed:<cause>`` and sets no claim aside.  ``ruleset_left`` is (file name, why) of each rule-set file the host
    set aside, counted as ``ruleset:<file name>:<why>``; it sets no claim aside either."""
    first = {}
    for n, read in enumerate(reads):
        for r in read.rows:
            pid = ffs.canonical_id("C", r.billing_npi, r.claim_id)
            if pid not in first:
                first[pid] = (r.claim_id, (n, r.offsets[0]), [])
            if first[pid][1] == (n, r.offsets[0]):  # the first copy's rows are read together
                first[pid][2].append(r)
    asked = {req.payment_id: len(req.lines) for req in sent}
    build, got = _Build(), {}
    for claim, n in Counter(claim for claim, _, _ in first.values()).items():
        if n > 1:  # the same claim id billed under several NPIs: which payment is the claim cannot be told
            build.drop(claim, "claim:id_under_several_payments", n)
    for a in left:
        if a.cause != "retry":  # a retry is an exact copy of a claim that was sent, and is decided with it
            build.drop(a.id, "claim:set_aside_before_decide")
    for a in feed_left:
        build.aside["feed:" + a.cause] += 1
    for name, why in ruleset_left:
        build.aside[f"ruleset:{name}:{why}"] += 1
    for p, i, outcome, reasons in rows:
        if p not in first or p not in asked:
            build.drop(None, "row:unknown_payment")
        else:
            got.setdefault(p, {}).setdefault(i, []).append((outcome, reasons))
    for p, (claim, _, lines) in first.items():
        if p not in asked or claim in build.excluded:
            continue
        mine = got.get(p, {})
        if len(lines) != asked[p]:
            build.drop(claim, "claim:line_count_mismatch", asked[p])
        elif set(mine) != set(range(len(lines))) or any(len(v) != 1 for v in mine.values()):
            build.drop(claim, "claim:line_without_one_outcome", len(lines))
    ok = [{"claim": first[p][0], "control": line.line_control, "outcome": mine[i][0][0], "reasons": mine[i][0][1], "cents": line.line_charge_cents}
          for p, mine in sorted(got.items()) if first[p][0] not in build.excluded for i, line in enumerate(first[p][2])]
    side = from_gate(system, ok)
    unreadable = any(read.refused or any(q.unit in ("file", "interchange", "group", "set") for q in read.quarantines)
                     or any(not c.id for c in read.claims) or any(not r.claim_id for r in read.rows) for read in reads)
    return Side(system, {c: v for c, v in side.claims.items() if c not in build.excluded}, side.excluded | build.excluded,
                dict(Counter(side.aside) + build.aside), unreadable, {claim: lines[0].billing_npi for claim, _, lines in first.values()})


def _carcs(adjustments):
    return tuple(sorted({"CARC_" + reason for group, reason, _, _ in adjustments if group != "PR"}))  # PR is the patient's share, not a denial


def from_835(system, reads):
    """A side from ``read_835`` results (what the incumbent paid). A refused file and every quarantined unit is counted aside."""
    build, first, counted, incomplete = _Build(), {}, set(), False
    for read in reads:
        incomplete = incomplete or bool(read.refused) or any(q.unit in ("file", "interchange", "group", "set") or q.cause == "bad_clp" for q in read.quarantines)
        if read.refused and not any(q.cause == read.refused for q in read.quarantines):  # the reader usually lists a refusal among its quarantines
            build.aside["file:" + read.refused] += 1
        for q in read.quarantines:
            build.aside[f"{q.unit}:{q.cause}"] += 1
        services = {}
        for s in read.services:
            services.setdefault(s.claim_id, []).append(s)
        repeated = {claim_id for claim_id, _ in read.duplicates}
        lost = {q.offset for q in read.findings if q.cause == "total_unchecked" and q.detail == "a service line was quarantined"}
        mismatched = {q.offset for q in read.findings if q.cause == "total_mismatch"}
        starts = sorted(c.offsets[0] for c in read.claims)
        faults = sorted(q.offset for q in read.quarantines) if read.claims else []
        for claim in read.claims:
            mine, cid, at = services.get(claim.claim_id, ()), claim.claim_id, claim.offsets[0]
            if cid in repeated or cid in first:  # whose service lines belong to which claim cannot be told
                build.drop(cid, "loop:duplicate_claim_id", 1 + (first.get(cid, 0) + len(mine)) * (cid not in counted))
                counted.add(cid)
                continue
            first[cid] = 1 + len(mine)
            after = bisect.bisect_right(starts, at)
            end = starts[after] if after < len(starts) else None  # the claim's bytes run up to the next claim in this read
            hit = bisect.bisect_left(faults, at)  # the first fault at or after the claim; it is inside when it comes before the next claim
            cause = ("loop:service_line_lost" if at in lost else "loop:total_mismatch" if at in mismatched else
                     "loop:segment_quarantined" if hit < len(faults) and (end is None or faults[hit] < end) else "")
            if cause:  # a lost service line, a total that does not add up, or a quarantined segment: the claim cannot be trusted line by line
                build.drop(cid, cause, 1 + len(mine))
                counted.add(cid)
                continue
            build.npi[cid] = claim.payee_npi
            rows = [(s.line_control, s.paid_cents, s.charge_cents, _carcs(s.adjustments) or _carcs(claim.adjustments)) for s in mine]
            rows = rows or [("", claim.paid_cents, claim.charge_cents, _carcs(claim.adjustments))]
            if any(paid < 0 or billed < 0 for _, paid, billed, _ in rows):  # a reversal: the gate side has no such line
                build.drop(claim.claim_id, "line:negative_cents", sum(paid < 0 or billed < 0 for _, paid, billed, _ in rows))
                counted.add(cid)
            elif any(paid > billed or billed > MAX_CENTS for _, paid, billed, _ in rows):  # paid above billed, or an absurd amount: not a payment to compare
                build.drop(claim.claim_id, "line:cents_implausible", sum(paid > billed or billed > MAX_CENTS for _, paid, billed, _ in rows))
                counted.add(cid)
            else:
                build.add(claim.claim_id, [Line(ctl, paid, billed, () if paid else causes) for ctl, paid, billed, causes in rows])
    return build.side(system, incomplete, True)


def _keyed(lines):
    return lines is None or all(line.control and line.control != CLAIM_KEY for line in lines)


def _whole(lines):
    return Line(CLAIM_KEY, sum(x.paid for x in lines), sum(x.billed for x in lines), tuple(sorted({c for x in lines for c in x.causes})))


def _own(line):
    return line.causes[0] if line.causes else "NOT_PAID_NO_REASON"


def _difference(parts):
    """(cause, causes, [(system at fault, its own cause)], cents) for one key, or None when the money agrees. ``parts`` is (side, line or None) per side."""
    have = [(side, line) for side, line in parts if line is not None]
    lack = [side.system for side, line in parts if line is None]
    stopped = [(side, line) for side, line in have if not line.paid]
    paid = [line.paid for _, line in have]
    if lack:
        return ("MISSING_ON_ONE_SIDE", (), [(name, "MISSING_ON_ONE_SIDE") for name in lack] + [(side.system, _own(line)) for side, line in stopped if any(paid)],
                max(paid) or max(line.billed for _, line in have))
    if not any(paid):
        return None
    if stopped:
        causes = tuple(sorted({c for _, line in stopped for c in line.causes}))
        return (causes[0] if causes else "NOT_PAID_NO_REASON"), causes, [(side.system, _own(line)) for side, line in stopped], max(paid)
    priced = [(side.system, line.paid) for side, line in have if side.prices]
    amounts = Counter(cents for _, cents in priced)
    if len(amounts) < 2:
        return None
    top = amounts.most_common(2)
    usual = top[0][0] if top[0][1] > top[1][1] else None  # no amount is the usual one when the two commonest are tied
    return "PRICE_DIFFERS", (), [(name, "PRICE_DIFFERS") for name, cents in priced if cents != usual], max(amounts) - min(amounts)


def _fault(system_map, name, own):
    """The system at fault for a side that stopped on its own cause: the map's step, ``@side`` meaning the side, else UNMAPPED."""
    step = system_map["steps"].get(own) if system_map else "@side"
    return name if step == "@side" else step or f"UNMAPPED:{own}"


def _no_repeats(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) < len(keys):
        raise ValueError("the system map repeats a key")
    return dict(pairs)


def load_map(data, pin):
    """The system map from its bytes (JSON the state supplies): ``{"systems": {name: {"kind": "vendor" | "state_office" | "gate", "owner":
    text}}, "steps": {cause: name}}``; a step names the system whose work a cause is, wherever the cause shows (a stale member file is the
    state's office, whichever system held the line). The bytes must hash to ``pin`` (SHA3-512 hex, from the state and not from the file).
    Returns the map and its digest; any other shape is refused. It is pinned, not signed: no signature format is defined for it."""
    digest = hashlib.sha3_512(data).hexdigest()
    if digest != pin:
        raise ValueError("the system map does not match its pin")
    try:
        got = json.loads(data, object_pairs_hook=_no_repeats)
    except (ValueError, RecursionError) as error:  # too deep to read is refused like any other bad shape
        raise ValueError(f"the system map is not JSON, repeats a key or is nested too deep: {error}") from None
    systems, steps = (got.get("systems"), got.get("steps")) if isinstance(got, dict) and set(got) == {"systems", "steps"} else (None, None)
    if not (isinstance(systems, dict) and isinstance(steps, dict) and systems and all(
            isinstance(n, str) and n and "+" not in n and n != "@side" and isinstance(v, dict) and set(v) == {"kind", "owner"}
            and v["kind"] in ("vendor", "state_office", "gate") and isinstance(v["owner"], str) and v["owner"] for n, v in systems.items())
            and all(isinstance(c, str) and c and (w in systems or w == "@side") for c, w in steps.items())):
        raise ValueError("the system map must be exactly systems (name: kind and owner) and steps (cause: a name in systems, or @side for the side itself)")
    return {"digest": digest, "systems": systems, "steps": steps}


def diff_report(*sides, system_map=None):
    """The report (a dict of plain values) for two or more sides, whose system names must differ and be named by ``system_map`` when one is given."""
    names = [side.system for side in sides]
    if len(names) < 2 or len(set(names)) < len(names) or not all(names) or any("+" in n for n in names):
        raise ValueError("the sides need two or more different, non-empty system names without a plus sign")
    if system_map and any(n not in system_map["systems"] for n in names):
        raise ValueError("the system map does not name every side: " + ", ".join(n for n in names if n not in system_map["systems"]))
    if system_map and any((system_map["systems"][side.system]["kind"] == "gate") == side.prices for side in sides):
        raise ValueError("the system map's gate systems must be exactly the sides that do not price: " + ", ".join(
            side.system for side in sides if (system_map["systems"][side.system]["kind"] == "gate") == side.prices))
    table, skip = _table(), frozenset().union(*(side.excluded for side in sides))
    found, compared, coarse, unknown, payee, partly = [], 0, Counter(), Counter(), Counter(), Counter()
    for claim in sorted(set().union(*(side.claims for side in sides)) - skip):
        lines = [side.claims.get(claim) for side in sides]
        gone = [side.system for side, x in zip(sides, lines) if x is None and side.incomplete]
        if gone:  # a side that could not be read whole may hold the claim: not missing, not known
            unknown.update(gone)
            continue
        have = [(side, x) for side, x in zip(sides, lines) if x is not None]
        if len({side.npi[claim] for side, _ in have if side.npi.get(claim)}) > 1:
            payee.update(side.system for side, _ in have if side.npi.get(claim))  # the same claim id under two providers is not one claim
            continue
        controls = {frozenset(x.control for x in kept) for _, kept in have}
        if all(_keyed(x) for x in lines) and len(controls) <= 1:
            pairs = {line.control: [None] * len(sides) for kept in lines for line in kept or ()}
            for slot, kept in enumerate(lines):
                for line in kept or ():
                    pairs[line.control][slot] = line
        else:
            if len(have) > 1 and (len({len(x) for _, x in have}) > 1 or any(len({bool(y.paid) for y in x}) > 1 for _, x in have)):
                partly.update(side.system for side, _ in have)  # a claim summed over lines that were not all paid or all declined hides the held ones
                continue
            coarse.update(side.system for side, x in have if not _keyed(x) or (len(controls) > 1 and
                          {y.control for other, z in have if other is not side for y in z if y.control} - {y.control for y in x}))
            pairs = {CLAIM_KEY: [x and _whole(x) for x in lines]}
        for control, slots in pairs.items():
            compared += 1
            got = _difference(list(zip(sides, slots)))
            if got:
                cause, causes, culprits, cents = got
                faults = {_fault(system_map, name, own) for name, own in culprits}
                found.append({"key": _key(claim, control), "cause": cause, "causes": list(causes), "system": "+".join(sorted(name for name, _ in culprits)),
                              "fault": "+".join(sorted(faults)), "owner": "+".join(system_map["systems"][n]["owner"] for n in sorted(faults) if n in system_map["systems"]) if system_map else "",
                              "cents": cents,
                              "paid": {side.system: x and x.paid for side, x in zip(sides, slots)}})
    found.sort(key=lambda d: d["key"])
    groups, systems, faults = {}, {}, {}
    for d in found:
        for bucket, name in ((groups, (d["cause"], d["system"])), (systems, d["system"]), (faults, d["fault"])):
            count, cents = bucket.get(name, (0, 0))
            bucket[name] = (count + 1, cents + d["cents"])
    by_cause = [{"cause": c, "system": s, "count": n, "cents": m, "meaning": _words(c, table)[0], "action": _words(c, table)[1]}
                for (c, s), (n, m) in sorted(groups.items())]
    aside = [{"system": side.system, "cause": cause, "count": n} for side in sides for cause, n in sorted(side.aside.items())]
    for cause, counts in (("claim:not_known_missing_from_incomplete_input", unknown), ("claim:payee_differs", payee), ("claim:partly_paid_at_claim_level", partly)):
        aside += [{"system": system, "cause": cause, "count": n} for system, n in sorted(counts.items())]
    return {"contract": CONTRACT, "systems": sorted(names), "map": system_map["digest"] if system_map else "", "compared": compared, "differing": len(found),
            "cents_at_stake": sum(d["cents"] for d in found), "cents_meaning": CENTS_MEANING, "by_cause": by_cause,
            "by_system": [{"system": s, "count": n, "cents": m} for s, (n, m) in sorted(systems.items())],
            "by_fault": [{"fault": s, "count": n, "cents": m} for s, (n, m) in sorted(faults.items())],
            "claim_level": [{"system": s, "claims": n} for s, n in sorted(coarse.items())],
            "set_aside": sorted(aside, key=lambda r: (r["system"], r["cause"])), "differences": found}


def render(report):
    """The report as canonical bytes: the same report always gives the same bytes."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
