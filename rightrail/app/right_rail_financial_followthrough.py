"""Read-only follow-through pack: who found each obligation, who owns it and which clocks run on it.

Documentation only. Deadlines are Control Pack data: a
canonical rules file whose SHA-256 exactly one approved Control Pack lists. The pack is built from a
verified store (right_rail_financial_derived) and writes nothing. Standing claims: synthetic,
non-PHI, nonpayment, proofSuiteId=null, production_usable=false, activation=false.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import calendar
import hashlib
import json
import re

from app.right_rail_financial_derived import (
    NOT_HELD, DerivedError, bound_control_pack, hex_upper, need, quarter_of, quarter_window, signed_pack, verified_rows,
)
from app.right_rail_financial_owner_independent import IndependentFinancialError, MAX_PACKAGE_BYTES
from app.right_rail_financial_switch import FinancialSwitchError, _decode_canonical_json, _id, _text

RULES_CONTRACT = "RR/FOLLOWTHROUGH/RULES/v1"
PACK_CONTRACT = "RR/FOLLOWTHROUGH/PACK/v3"  # v3: "share_parts" by CMS-64 quarter replace "collected_share"; v2: signed with the custody key
RULES_SOURCE_REF = "followthrough-rules:sha256:"  # the approved Control Pack lists this ref plus the rules' SHA-256
MAX_RULES_BYTES = 64 * 1024
MAX_FOLLOWTHROUGH_PACK_BYTES = 2 * MAX_PACKAGE_BYTES
_DAY = 86_400_000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ANCHOR_EVENTS = {"EVENT:OFFSET_REJECTED_CORRECTION_AUTHORIZED", "EVENT:ACTION_ACKNOWLEDGED"}
_NAME, _FORM, _LINE, _SUMMARY = (re.compile(pattern) for pattern in (r"[A-Z][A-Z0-9_]{0,63}\Z", r"64\.9[A-Z][0-9]?\Z", r"[0-9]{1,2}\Z", r"[0-9]{1,2}[A-Z]{1,2}\Z"))


def _fail(code: str) -> None:
    raise DerivedError(code)


def _keys(value: object, keys: set[str], code: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        _fail(code)
    return value


def _names(values: object, code: str, allowed: object = None) -> list:
    """A sorted, unique list of strings, all in ``allowed`` when given."""
    if type(values) is not list or any(type(value) is not str for value in values) or values != sorted(set(values)) or (allowed is not None and not set(values) <= set(allowed)):
        _fail(code)
    return values


def _match(pattern: re.Pattern, value: object) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _listed(values: object, code: str, allowed: set[str], purposes: set[str]) -> None:
    """A non-empty sorted list of ``EVIDENCE:<declared purpose>`` or one of ``allowed``."""
    if not _names(values, code):
        _fail(code)
    for value in values:
        if value.startswith("EVIDENCE:"):
            if value[9:] not in purposes:
                _fail("rules-purpose-undeclared")
        elif value not in allowed:
            _fail(code)


def _rules(raw: bytes, state_id: str) -> dict:
    rules = _decode_canonical_json(raw, maximum=MAX_RULES_BYTES, label="followthrough-rules")
    if set(rules) != {"contract", "state_id", "pack_version", "parties", "default_owner_id", "clocks", "closure_reasons", "fmap_basis_points"}:
        _fail("rules-fields")
    if rules["contract"] != RULES_CONTRACT:
        _fail("rules-contract")
    if rules["state_id"] != state_id:
        _fail("rules-state")
    if type(rules["pack_version"]) is not int or rules["pack_version"] < 1:
        _fail("rules-pack-version")
    parties, purposes = rules["parties"], set()
    if type(parties) is not list or not parties:
        _fail("rules-party")
    for party in parties:
        _keys(party, {"party_id", "party", "kind", "purposes"}, "rules-party")
        _id(party["party_id"], "rules-party")
        if party["party"] not in ("STATE", "CONTRACTOR", "HEALTH_PLAN") or party["kind"] not in ("SYSTEM", "PERSON", "MODEL") or not all(_match(_NAME, name) for name in _names(party["purposes"], "rules-party")):
            _fail("rules-party")
        purposes.update(party["purposes"])
    _names([party["party_id"] for party in parties], "rules-party")
    if rules["default_owner_id"] not in [party["party_id"] for party in parties if party["kind"] != "MODEL"]:
        _fail("rules-owner")
    clocks = rules["clocks"]
    if type(clocks) is not list or not clocks:
        _fail("rules-clock")
    for clock in clocks:
        _keys(clock, {"clock_id", "anchors", "add", "report", "satisfied_by", "citation"}, "rules-clock")
        _id(clock["clock_id"], "rules-clock")
        _listed(clock["anchors"], "rules-anchor", _ANCHOR_EVENTS, purposes)
        _listed(clock["satisfied_by"], "rules-clock", {"SATISFIED"}, purposes)
        starts, ends = ({name[9:] for name in clock[key] if name.startswith("EVIDENCE:")} for key in ("anchors", "satisfied_by"))
        if any(starts & set(party["purposes"]) and ends & set(party["purposes"]) for party in parties):
            _fail("rules-party-both-ends")  # one party's document could start the clock and satisfy it
        _text(clock["citation"], "rules-citation", maximum=256)
        add = _keys(clock["add"], {"unit", "count"}, "rules-clock")
        report = clock["report"]
        if add["unit"] not in ("DAY", "YEAR") or type(add["count"]) is not int or not 1 <= add["count"] <= 3650:
            _fail("rules-clock")
        if report != {"kind": "AT_END"}:
            _keys(report, {"kind", "due_days", "collected", "uncollected"}, "rules-clock")
            if report["kind"] != "CMS64_QUARTER" or type(report["due_days"]) is not int or not 1 <= report["due_days"] <= 366:
                _fail("rules-clock")
            for ref in (report["collected"], report["uncollected"]):
                _keys(ref, {"form", "line", "summary_line"}, "rules-clock")
                if not (_match(_FORM, ref["form"]) and (ref["line"] is None or _match(_LINE, ref["line"])) and _match(_SUMMARY, ref["summary_line"])):
                    _fail("rules-clock")
    clock_ids = [clock["clock_id"] for clock in clocks]
    _names(clock_ids, "rules-clock")
    reasons = rules["closure_reasons"]
    if type(reasons) is not list:
        _fail("rules-reason")
    for reason in reasons:
        _keys(reason, {"reason_code", "stops", "requires", "citation"}, "rules-reason")
        if not _match(_NAME, reason["reason_code"]):
            _fail("rules-reason")
        _text(reason["citation"], "rules-reason", maximum=256)
        _names(reason["stops"], "rules-stops", clock_ids)
        _names(reason["requires"], "rules-purpose-undeclared", purposes)
    _names([reason["reason_code"] for reason in reasons], "rules-reason")
    fmap = rules["fmap_basis_points"]
    if fmap is not None:
        if type(fmap) is not list or not fmap:
            _fail("rules-fmap")
        for entry in fmap:
            _keys(entry, {"period_id", "basis_points"}, "rules-fmap")
            _id(entry["period_id"], "rules-fmap")
            if type(entry["basis_points"]) is not int or not 1 <= entry["basis_points"] <= 10_000:
                _fail("rules-fmap")
        _names([entry["period_id"] for entry in fmap], "rules-fmap")
    return rules


def _add(at_ms: int, add: dict) -> int:
    """``at_ms`` plus the clock's period; a 29 February anniversary in a common year is 28 February."""
    try:
        moment = _EPOCH + timedelta(milliseconds=at_ms)
        year = moment.year + add["count"]
        later = moment + timedelta(days=add["count"]) if add["unit"] == "DAY" else moment.replace(year=year, day=28 if (moment.month, moment.day) == (2, 29) and not calendar.isleap(year) else moment.day)
    except (OverflowError, ValueError):
        _fail("clock-date-range")  # past year 9999
    return (later - _EPOCH) // timedelta(milliseconds=1)


def _cms64_due(ends_ms: int, recovered_at_ms: int | None, due_days: int) -> tuple[str, int, bool]:
    """The CMS-64 quarter carrying the credit (the recovery's, if before the year end; else the year end's), its due time, and which."""
    collected = recovered_at_ms is not None and recovered_at_ms < ends_ms
    quarter = quarter_of(recovered_at_ms if collected else ends_ms - 1)
    return quarter, quarter_window(quarter)[1] + due_days * _DAY, collected


def _share_parts(clock: dict, ends_ms: int, rest: tuple[str, int, bool], payments: list, owed: int, stopped: bool, basis: int, generated_at_ms: int, filed: list) -> list:
    """The federal share of the debt by the CMS-64 quarter that carries each part (42 CFR 433.320(a)(2)).

    Each collection (payment or authorized offset) owes on its own quarter. Before a stop, collections at or after the
    year end add nothing (433.320(b)(2)) and the rest of the debt owes on ``rest``, the clock's own quarter (433.316(h): a
    part payment does not move the year). Once a covered close stops the clock, only collected money owes, whenever it
    is collected. In quarter order, then the order they were on record, each collection owes the rounded share of the
    running total (at most ``owed``) less the rounded share before it, so the shares add up to the rounded share of what
    they cover. Each credit ``filed`` (in filing order) meets the earliest collection not yet met that owes cents and was
    on record by its filing after its quarter ended, with every other collection of that quarter and line on record by
    then; collections recorded later are a separate part of the quarter for a later credit. Neighbouring collections of
    one quarter, line and credit make one part; a part that owes no cents is left out, and the debt it covers is not listed.
    """
    listed = [row for row in payments if stopped or row["event_at_ms"] < ends_ms]
    cells = [] if stopped else [[rest, max(owed - sum(row["amount_cents"] for row in listed), 0), quarter_window(rest[0])[1]]]  # [key, cents, ready]
    for row in listed:
        key = _cms64_due(row["event_at_ms"] + 1, row["event_at_ms"], clock["report"]["due_days"])  # its own quarter
        cells.append([key, row["amount_cents"], max(quarter_window(key[0])[1], row["received_at_ms"])])
    cells.sort(key=lambda cell: (quarter_window(cell[0][0])[1], cell[2]))
    before = 0
    for cell in cells:  # now [key, principal, ready, share, the filing that met it]
        total = min(owed, before + cell[1])
        cell[1:] = total - before, cell[2], (total * basis + 5000) // 10_000 - (before * basis + 5000) // 10_000, None
        before = total
    for at in filed:
        first = next((cell for cell in cells if cell[4] is None and cell[3] and cell[2] <= at), None)
        for cell in cells if first is not None else ():
            if cell[4] is None and cell[0] == first[0] and cell[2] <= at:
                cell[4] = at
    runs: list = []  # [key, filing, principal, share]
    for key, principal, _, cents, met in cells:
        if runs and runs[-1][:2] == [key, met]:
            runs[-1][2:] = runs[-1][2] + principal, runs[-1][3] + cents
        else:
            runs.append([key, met, principal, cents])
    return [{"clock_id": clock["clock_id"], "principal_cents": principal, "cents": cents, "due_ms": due,
             "report": {"quarter": quarter, **clock["report"]["collected" if collected else "uncollected"]},
             "status": ("MISSED" if generated_at_ms >= due else "DUE") if met is None else "MET" if met < due else "MET_LATE"}
            for (quarter, due, collected), met, principal, cents in runs if cents]


def _by(rows: list, key: str, keep: object = lambda row: True) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for row in rows:
        if keep(row):
            grouped.setdefault(row[key], []).append(row)
    return grouped


_NOT_ACTIVITY = ("FOLLOWTHROUGH_DECIDED", "ACTION_ACKNOWLEDGED", "EVALUATION_RECORDED")


def _covered(requires: list[str], sources: list[str], holders: dict[str, set[str]]) -> bool:
    """Each required purpose gets its own evidence row, from a source that holds that purpose: one document never meets two."""
    taken: dict[int, str] = {}  # evidence row -> the purpose it meets

    def place(purpose: str, tried: set[int]) -> bool:
        for n, source in enumerate(sources):
            if source in holders.get(purpose, ()) and n not in tried:
                tried.add(n)
                if n not in taken or place(taken[n], tried):
                    taken[n] = purpose
                    return True
        return False
    return all(place(purpose, set()) for purpose in requires)


def _documents(rows: list) -> list:
    """One row per document: a repeat under the same origin or content digest is the same document, so it meets one purpose at most."""
    seen: set = set()
    kept = []
    for row in rows:
        marks = {("origin", row["common_origin_id"]), ("digest", bytes(row["content_digest"]))}
        if not marks & seen:
            kept.append(row)
        seen |= marks
    return kept


def _fact(source: str, at_ms: int, evidence: dict | None, **more: object) -> dict:
    return {"source": source, "at_ms": at_ms, "evidence_id": None if evidence is None else evidence["evidence_id"],
            "evidence_record_digest": None if evidence is None else hex_upper(evidence["record_digest"]), **more}


def build_followthrough_pack(database: object, package_bytes: bytes, *, trusted_authority: object, expected_scope: object, rules_bytes: bytes, generated_at_ms: int, custody: object) -> bytes:
    """Canonical follow-through pack bytes for every obligation in the verified store.

    The same inputs always give the same bytes but the hedged ``signature`` (``generated_at_ms`` is an input, never read from a clock).
    """
    try:
        return _build(database, package_bytes, trusted_authority=trusted_authority, expected_scope=expected_scope, rules_bytes=rules_bytes, generated_at_ms=generated_at_ms, custody=custody)
    except (DerivedError, FinancialSwitchError, IndependentFinancialError) as error:
        raise DerivedError(f"followthrough:{error}") from None


def _build(database: object, package_bytes: bytes, *, trusted_authority: object, expected_scope: object, rules_bytes: bytes, generated_at_ms: int, custody: object) -> bytes:
    store, rows, source = verified_rows(database, package_bytes, trusted_authority=trusted_authority, expected_scope=expected_scope, generated_at_ms=generated_at_ms)
    rules = _rules(rules_bytes, store["scope"]["state_id"])
    rules_sha256 = hashlib.sha256(rules_bytes).hexdigest().upper()
    pack = bound_control_pack(rows, RULES_SOURCE_REF, rules_sha256, version=rules["pack_version"], before_ms=generated_at_ms + 1, label="followthrough-rules")
    parties = {party["party_id"]: party for party in rules["parties"]}
    holders = {name: {party_id for party_id, party in parties.items() if name in party["purposes"]} for party in parties.values() for name in party["purposes"]}
    fmap = None if rules["fmap_basis_points"] is None else {entry["period_id"]: entry["basis_points"] for entry in rules["fmap_basis_points"]}
    manifests = {row["manifest_id"]: row for row in rows["population_manifests"]}
    finders = {row["population_id"]: need(manifests, row["manifest_id"], "manifest") for row in rows["population_manifest_bindings"]}
    reasons = {reason["reason_code"]: reason for reason in rules["closure_reasons"]}
    support = _by(rows["evidence"], "item_id", lambda row: row["kind"] == "SUPPORT")
    events = _by(rows["financial_events"], "aggregate_id", lambda row: row["aggregate_type"] == "OBLIGATION")
    evaluations = _by(sorted(rows["evaluations"], key=lambda row: row["revision"]), "obligation_id")
    received = {row["evidence_id"]: row["received_at_ms"] for row in rows["evidence"]}
    acted = {row["determination_id"]: row["created_at_ms"] for row in rows["actions"]}
    # money recovered: payments in force, and authorized offsets, each a recovery at its decision time and on record from
    # the later of that and its action's record
    payments = _by([*({"obligation_id": row["obligation_id"], "event_at_ms": row["event_at_ms"], "received_at_ms": need(received, row["evidence_id"], "payment-evidence"),
                       "amount_cents": row["amount_cents"]} for row in rows["payments"] if row["active"] == 1),
                    *({"obligation_id": row["obligation_id"], "event_at_ms": row["decided_at_ms"], "amount_cents": row["amount_cents"],
                       "received_at_ms": max(row["decided_at_ms"], need(acted, row["determination_id"], "offset-action"))} for row in rows["determinations"] if row["decision"] == "OFFSET_AUTHORIZED")], "obligation_id")
    recorded = {json.loads(row["payload_json"])["evidence_id"]: row["event_sequence"] for row in rows["financial_events"] if row["kind"] == "SUPPORT_EVIDENCE_RECORDED"}  # event order, not time
    gaps, items = set(), []
    for obligation in sorted(rows["obligations"], key=lambda row: row["item_id"]):
        manifest = need(finders, obligation["population_id"], "population-manifest")
        finder = parties.get(manifest["source_owner_id"])
        if finder is None:
            gaps.add(f"gap:finder-not-typed:{manifest['source_owner_id']}")
        history = evaluations.get(obligation["obligation_id"], [])
        satisfied_row = None
        if obligation["amount_satisfied"] == 1:  # the first evaluation after the last unsatisfied one
            satisfied_row = history[1 + max((n for n, row in enumerate(history) if row["amount_satisfied"] == 0), default=-1)]
        recovered_at = None  # the collection date (433.320(a)(2)(i)), never the recording time; a satisfaction with no payment has only its recording time
        if satisfied_row is not None:
            recovered_at = max((row["event_at_ms"] for row in payments.get(obligation["obligation_id"], []) if row["received_at_ms"] <= satisfied_row["evaluated_at_ms"]), default=satisfied_row["evaluated_at_ms"])
        share = None
        if fmap is not None:
            if obligation["period_id"] in fmap:
                basis = fmap[obligation["period_id"]]
                share = {"period_id": obligation["period_id"], "basis_points": basis, "cents": (obligation["owed_cents"] * basis + 5000) // 10_000}
            else:
                gaps.add(f"gap:fmap-period-missing:{obligation['period_id']}")
        decisions = [{"decision_id": p["decision_id"], "act": p["act"], "reason_code": p["reason_code"], "owner_id": p["owner_id"], "suggestion": p["suggestion"],
                      "agrees_with_suggestion": None if p["suggestion"] is None else all(p[key] == p["suggestion"][key] for key in ("act", "reason_code", "owner_id")),
                      "actor_id": p["actor_id"], "actor_role": p["actor_role"], "decided_at_ms": row["committed_at_ms"], "event_sequence": row["event_sequence"]}
                     for row in sorted(events.get(obligation["obligation_id"], []), key=lambda row: row["event_sequence"]) if row["kind"] == "FOLLOWTHROUGH_DECIDED" for p in [json.loads(row["payload_json"])]]
        covered = set()  # closes in the rules whose every required purpose (433.318) has its own document recorded before the decision (event order)
        for d in decisions:
            listed = d["reason_code"] in reasons if d["act"] == "CLOSE" else parties.get(d["owner_id"], {"kind": "MODEL"})["kind"] != "MODEL"
            if not listed:
                gaps.add(f"gap:decision-not-in-rules:{d['decision_id']}")
            elif d["act"] == "CLOSE" and _covered(reasons[d["reason_code"]]["requires"], [row["source_id"] for row in _documents([row for row in support.get(obligation["item_id"], []) if need(recorded, row["evidence_id"], "support-evidence-event") < d["event_sequence"]])], holders):
                covered.add(d["decision_id"])
            elif d["act"] == "CLOSE":
                gaps.add(f"gap:closure-evidence-missing:{d['decision_id']}")
            if d["suggestion"] is not None and d["suggestion"]["source_id"] not in parties:
                gaps.add(f"gap:suggestion-source-not-typed:{d['decision_id']}")
        close = decisions[-1] if decisions and decisions[-1]["act"] == "CLOSE" else None  # an ASSIGN after a close reopens the item
        assigned = next((d for d in reversed(decisions) if d["act"] == "ASSIGN"), None)
        if close is not None and any(row["event_sequence"] > close["event_sequence"] and row["kind"] not in _NOT_ACTIVITY for row in events.get(obligation["obligation_id"], [])):
            gaps.add(f"gap:activity-after-close:{obligation['item_id']}")  # evidence, payment or offset recorded after the close
        share_parts = []
        clocks = []
        for clock in rules["clocks"]:
            facts = []
            for name in clock["anchors"]:
                if name.startswith("EVIDENCE:"):
                    facts += [((row["event_at_ms"], 0, row["evidence_id"], 0), _fact(name, row["event_at_ms"], row, recorded_at_ms=row["received_at_ms"], event_sequence=None))
                              for row in support.get(obligation["item_id"], []) if row["source_id"] in holders[name[9:]]]
                else:
                    facts += [((row["committed_at_ms"], 1, "", row["event_sequence"]), _fact(name, row["committed_at_ms"], None, recorded_at_ms=row["committed_at_ms"], event_sequence=row["event_sequence"]))
                              for row in events.get(obligation["obligation_id"], []) if row["kind"] == name[6:]]
            anchor = min(facts, key=lambda fact: fact[0])[1] if facts else None
            done = [((row["received_at_ms"], name, row["evidence_id"]), _fact(name, row["received_at_ms"], row, evaluation_id=None))
                    for name in clock["satisfied_by"] if name.startswith("EVIDENCE:") for row in support.get(obligation["item_id"], []) if row["source_id"] in holders[name[9:]]]
            # credits filed: one per document, in filing order; a recovery meets a clock but is not a filing
            filed = [row["received_at_ms"] for row in _documents(sorted((row for row in support.get(obligation["item_id"], []) if any(
                row["source_id"] in holders[name[9:]] for name in clock["satisfied_by"] if name.startswith("EVIDENCE:"))), key=lambda row: (row["received_at_ms"], row["evidence_id"])))]
            if satisfied_row is not None and "SATISFIED" in clock["satisfied_by"]:
                done.append(((recovered_at, "SATISFIED", ""), _fact("SATISFIED", recovered_at, None, evaluation_id=satisfied_row["evaluation_id"])))
            satisfied = min(done, key=lambda fact: fact[0])[1] if done else None
            ends = due = report = owes = None
            if anchor is not None:
                ends = due = _add(anchor["at_ms"], clock["add"])
                if clock["report"]["kind"] == "CMS64_QUARTER":
                    owes = _cms64_due(ends, recovered_at, clock["report"]["due_days"])
                    quarter, due, collected = owes
                    report = {"quarter": quarter, **clock["report"]["collected" if collected else "uncollected"]}
            # 433.320(d): a covered close stops only the uncollected part, whether or not a credit was filed
            stops = anchor is not None and close is not None and close["decision_id"] in covered and clock["clock_id"] in reasons[close["reason_code"]]["stops"] and close["decided_at_ms"] < ends
            stopped_by = None
            if anchor is None:
                status = "NOT_ANCHORED"
            elif satisfied is not None:
                status = "MET" if satisfied["at_ms"] < due else "MET_LATE"
            elif stops:
                status, stopped_by = "STOPPED", close["decision_id"]
                report = None
                gaps.add(f"gap:write-off-line-unknown:{obligation['item_id']}")  # the 64.9 write-off line is not in the rules (design risk 2)
            else:
                status = "MISSED" if generated_at_ms >= due else "RUNNING"
            if owes is not None and share is not None:  # after a stop the share of money collected stays due (433.320(a)(2)-(3))
                share_parts += _share_parts(clock, ends, owes, payments.get(obligation["obligation_id"], []), obligation["owed_cents"], stops, share["basis_points"], generated_at_ms, filed)
            clocks.append({"clock_id": clock["clock_id"], "citation": clock["citation"], "anchor": anchor, "ends_ms": ends, "due_ms": due, "report": report,
                           "satisfied": satisfied, "stopped_by": stopped_by, "status": status})
        items.append({
            "item_id": obligation["item_id"],
            "obligation_id": obligation["obligation_id"],
            "found": {"source_owner_id": manifest["source_owner_id"], "source_id": manifest["source_id"], "party": None if finder is None else finder["party"],
                      "kind": None if finder is None else finder["kind"], "manifest_id": manifest["manifest_id"], "registered_at_ms": manifest["registered_at_ms"],
                      "approved_by": manifest["approved_by"], "approval_ref": manifest["approval_ref"]},
            "owner": {"owner_id": rules["default_owner_id"], "basis": "RULES_DEFAULT", "decision_id": None} if assigned is None
                     else {"owner_id": assigned["owner_id"], "basis": "DECISION", "decision_id": assigned["decision_id"]},
            "status": "SATISFIED" if satisfied_row is not None else "OPEN" if close is None else "CLOSED",
            "principal_cents": obligation["owed_cents"],
            "open_cents": obligation["shortfall_cents"],
            "clocks": clocks,
            "federal_share": share,
            "share_parts": share_parts,
            "decisions": decisions,
        })
    return signed_pack({
        "contract": PACK_CONTRACT,
        "documentation_only": True,
        "claims": {"proofSuiteId": None, "production_usable": False, "activation": False},
        "generated_at_ms": generated_at_ms,
        "items": items,
        "comparison": None,
        "unavailable": sorted({*NOT_HELD, *gaps}),
        "versions": {"rules_sha256": rules_sha256, "control_pack": {"pack_id": pack["pack_id"], "version": pack["version"], "digest": hex_upper(pack["pack_digest"])}},
        "source": source,
    }, custody, database, MAX_FOLLOWTHROUGH_PACK_BYTES)
