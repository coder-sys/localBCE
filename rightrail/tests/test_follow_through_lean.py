"""The Lean follow-through and correction follow-up status (lean/BlindLedger/Financial/FollowThrough.lean) give the
same outputs as the Python they will replace: `_build` in app/right_rail_financial_followthrough.py and the owner's
`_correction_followup_status`, on the same records.

The module imports only `Init`, so it is compiled here from source with the pinned toolchain into a scratch
directory; no Lake target names it and no pinned build input moves. tests/follow_through_lean.lean runs it.
Cases: hospital H's correction at each point of its life, generated records that cover every clock, every
closure reason, a 29 February anchor and a half-cent federal share, hand-built records on each comparison boundary
and across leap years, and every day from 1971 to 2200 through the calendar helpers.

The Lean functions answer on every input; Python refuses some (a satisfied obligation with no satisfying evaluation,
years outside 1971 to 9998). The two are compared only on inputs Python accepts."""

from __future__ import annotations

import dataclasses
from datetime import date
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import random
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

from app import right_rail_financial_followthrough as followthrough
from app import right_rail_financial_owner as owner_module
from app.right_rail_financial_derived import NOT_HELD, quarter_of, quarter_window
from app.right_rail_financial_switch import _canonical_json
from tests.rightrail_financial_expected_cases import H_ITEM_ID, PERIOD_ONE_SCOPE

ROOT = Path(__file__).resolve().parents[1]
LEAN = ROOT / "lean"
MODULE = LEAN / "BlindLedger" / "Financial" / "FollowThrough.lean"
RUNNER = ROOT / "tests" / "follow_through_lean.lean"
VERSION = (LEAN / "lean-toolchain").read_text("utf-8").strip().split(":v")[1]
TOOLCHAIN = Path.home() / ".elan" / "toolchains" / f"leanprover--lean4---v{VERSION}"
RULES = json.loads((ROOT / "tests" / "fixtures" / "followthrough_rules_recovery_v1.json").read_bytes())
DAY = 86_400_000
CORRECTION_CLOCK = {"add": {"count": 30, "unit": "DAY"}, "anchors": ["EVENT:ACTION_ACKNOWLEDGED", "EVENT:OFFSET_REJECTED_CORRECTION_AUTHORIZED"],
                    "citation": "synthetic state policy: the correction is paid within 30 days of its acknowledgment", "clock_id": "correction-paid",
                    "report": {"kind": "AT_END"}, "satisfied_by": ["SATISFIED"]}
STANDARD_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


def _ms(year: int, month: int, day: int) -> int:
    from datetime import datetime, timezone
    return int(datetime(year, month, day, tzinfo=timezone.utc).timestamp()) * 1000


def _encode(value: object) -> bytes:
    return _canonical_json(value, maximum=followthrough.MAX_RULES_BYTES)


def _rules(state_id: str, fmap: object) -> dict:
    return {**RULES, "state_id": state_id, "clocks": sorted([*RULES["clocks"], CORRECTION_CLOCK], key=lambda c: c["clock_id"]), "fmap_basis_points": fmap}


def _lean_run(args: list[str], lean_path: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, LEAN_PATH=str(lean_path), LEAN_SYSROOT=str(TOOLCHAIN))
    return subprocess.run([str(TOOLCHAIN / "bin" / "lean.exe"), *args], env=env, capture_output=True, text=True, encoding="utf-8", timeout=1800)


# --- Python records -> the Lean functions' inputs (field names as in the Lean structures) ---

def _decision(payload: dict) -> dict:
    s = payload["suggestion"]
    return {"decisionId": payload["decision_id"], "act": payload["act"], "reasonCode": payload["reason_code"], "ownerId": payload["owner_id"],
            "actorId": payload["actor_id"], "actorRole": payload["actor_role"],
            "suggestion": None if s is None else {"sourceId": s["source_id"], "sourceRef": s["source_ref"], "sourceSha256": s["source_sha256"],
                                                  "suggestedAt": s["suggested_at_ms"], "act": s["act"], "reasonCode": s["reason_code"], "ownerId": s["owner_id"]}}


def lean_obligations(rows: dict) -> list[dict]:
    """Each obligation's records as the Lean function reads them, in the order the rows hold them."""
    manifests = {m["manifest_id"]: m for m in rows["population_manifests"]}
    finders = {b["population_id"]: manifests[b["manifest_id"]] for b in rows["population_manifest_bindings"]}
    recorded = {json.loads(e["payload_json"])["evidence_id"]: e["event_sequence"] for e in rows["financial_events"] if e["kind"] == "SUPPORT_EVIDENCE_RECORDED"}
    received = {e["evidence_id"]: e["received_at_ms"] for e in rows["evidence"]}
    acted = {a["determination_id"]: a["created_at_ms"] for a in rows["actions"]}
    out = []
    for o in sorted(rows["obligations"], key=lambda row: row["item_id"]):
        m, oid = finders[o["population_id"]], o["obligation_id"]
        out.append({
            "itemId": o["item_id"], "obligationId": oid, "periodId": o["period_id"], "owedCents": o["owed_cents"],
            "shortfallCents": o["shortfall_cents"], "amountSatisfied": o["amount_satisfied"] == 1,
            "finder": {"sourceOwnerId": m["source_owner_id"], "sourceId": m["source_id"], "manifestId": m["manifest_id"],
                       "registeredAt": m["registered_at_ms"], "approvedBy": m["approved_by"], "approvalRef": m["approval_ref"]},
            "evaluations": [{"evaluationId": e["evaluation_id"], "revision": e["revision"], "satisfied": e["amount_satisfied"] == 1, "evaluatedAt": e["evaluated_at_ms"]}
                            for e in rows["evaluations"] if e["obligation_id"] == oid],
            "payments": [{"eventAt": p["event_at_ms"], "receivedAt": received[p["evidence_id"]], "amount": p["amount_cents"]} for p in rows["payments"] if p["obligation_id"] == oid and p["active"] == 1]
                        + [{"eventAt": d["decided_at_ms"], "receivedAt": max(d["decided_at_ms"], acted[d["determination_id"]]), "amount": d["amount_cents"]}
                           for d in rows["determinations"] if d["obligation_id"] == oid and d["decision"] == "OFFSET_AUTHORIZED"],
            "support": [{"evidenceId": e["evidence_id"], "sourceId": e["source_id"], "origin": e["common_origin_id"], "contentDigest": bytes(e["content_digest"]).hex(),
                         "recordDigest": bytes(e["record_digest"]).hex().upper(), "eventAt": e["event_at_ms"], "receivedAt": e["received_at_ms"], "recorded": recorded[e["evidence_id"]]}
                        for e in rows["evidence"] if e["kind"] == "SUPPORT" and e["item_id"] == o["item_id"]],
            "events": [{"kind": e["kind"], "seq": e["event_sequence"], "committedAt": e["committed_at_ms"],
                        "decision": _decision(json.loads(e["payload_json"])) if e["kind"] == "FOLLOWTHROUGH_DECIDED" else None}
                       for e in rows["financial_events"] if e["aggregate_type"] == "OBLIGATION" and e["aggregate_id"] == oid],
        })
    return out


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def lean_correction(connection: sqlite3.Connection, package: dict, item_id: str, sequence: int, followup: object, artifact: object) -> dict:
    """The correction follow-up status inputs, read from the same store the owner reads."""
    obligation_id = package["obligation"]["obligation_id"]
    try:
        basis = None
        if artifact is not None and followup["contract"] == owner_module._CORRECTION_FOLLOWUP_CONTRACT and followup["dependency_families"] == list(owner_module._CORRECTION_FOLLOWUP_DEPENDENCIES):
            pack, authority = followup["control_pack"], followup["authority"]
            basis = {"workId": followup["work_id"], "packId": f"{pack['pack_id']}", "pack": [[k, _canonical(v)] for k, v in pack.items()],
                     "authorityId": f"{authority['authority_id']}", "authority": _canonical(authority), "determinationId": followup["determination_id"],
                     "determinationDigest": followup["determination_digest"], "boundEvidence": [v["evidence_id"] for v in followup["supporting_evidence"]]}
    except (KeyError, TypeError, AttributeError):
        basis = None
    work = basis["workId"] if basis else None
    determination = package["current_determination"]
    try:
        determination = None if determination is None else [determination["determination_id"], determination["determination_digest"]]
    except (KeyError, TypeError):
        determination = None
    delivery = connection.execute("SELECT a.status,o.status FROM actions a JOIN action_outbox o USING(action_id) WHERE a.action_id=?", (work,)).fetchone()
    evidence = []
    for evidence_id, kind in connection.execute("SELECT evidence_id,kind FROM evidence WHERE item_id=?", (item_id,)).fetchall():
        pays = [w for (w,) in connection.execute(
            "SELECT json_extract(f.payload_json,'$.pays_action_id') FROM payments p JOIN financial_events f ON json_extract(f.payload_json,'$.payment_id')=p.payment_id "
            "WHERE p.evidence_id=? AND f.aggregate_type='OBLIGATION' AND f.aggregate_id=? AND f.kind='PAYMENT_RECEIVED'", (evidence_id, obligation_id)) if w is not None]
        repeats = connection.execute(
            "SELECT NOT EXISTS (SELECT 1 FROM payments WHERE evidence_id=:e) AND NOT EXISTS (SELECT 1 FROM financial_conflicts WHERE candidate_evidence_id=:e) "
            "AND EXISTS (SELECT 1 FROM financial_events f WHERE f.aggregate_type='OBLIGATION' AND f.aggregate_id=:o AND f.kind='PAYMENT_DUPLICATE_EVIDENCE' "
            "AND json_extract(f.payload_json,'$.candidate_evidence_id')=:e)", {"e": evidence_id, "o": obligation_id}).fetchone()[0]
        evidence.append({"evidenceId": evidence_id, "kind": kind, "paysWork": pays, "repeatsConfirmation": bool(repeats)})
    later = [{"kind": kind, "otherObligation": bool(other)} for kind, other in connection.execute(
        "SELECT DISTINCT kind,aggregate_type='OBLIGATION' AND aggregate_id<>? FROM financial_events WHERE event_sequence>?", (obligation_id, sequence))]
    return {"itemId": item_id, "obligationId": obligation_id, "basis": basis, "evidence": evidence, "later": later,
            "current": {"pack": [[k, _canonical(v)] for k, v in package["control_pack"].items()], "authority": _canonical(package["evaluation_receipt"]["authority"]),
                        "determination": determination, "delivery": None if delivery is None else list(delivery)}}


def python_followthrough(rows: dict, rules: dict, now: int) -> tuple[list, set]:
    """The Python module's items and gaps for these rows; only the store check, pack lookup and signature are stubbed."""
    with mock.patch.object(followthrough, "verified_rows", return_value=({"scope": {"state_id": rules["state_id"]}}, rows, {})), \
            mock.patch.object(followthrough, "bound_control_pack", return_value={"pack_id": "pack:test", "version": 1, "pack_digest": b"\x00"}), \
            mock.patch.object(followthrough, "signed_pack", side_effect=lambda record, *rest: record):
        record = followthrough._build(None, b"", trusted_authority=None, expected_scope=None, rules_bytes=_encode(rules), generated_at_ms=now, custody=None)
    return record["items"], set(record["unavailable"]) - set(NOT_HELD)


# --- Generated records ---

LEGAL, DEMAND, CMS64 = "state-legal-office", "state-demand-letters", "state-cms64"
DATES = (_ms(2028, 2, 29), _ms(2027, 3, 1), _ms(2027, 10, 1) - 1, _ms(2027, 10, 1), _ms(2027, 1, 15), _ms(2027, 6, 30) + 12 * 3_600_000 + 7)


def _empty_rows() -> dict:
    """Rows with the two finders (one typed in the rules, one not) and nothing else."""
    rows: dict[str, list] = {k: [] for k in ("population_manifests", "population_manifest_bindings", "evidence", "financial_events", "evaluations", "payments", "determinations", "actions", "obligations")}
    for population, finder in (("population:typed", "rac-contractor-1"), ("population:untyped", "unlisted-finder")):
        manifest = f"manifest:{finder}"
        rows["population_manifests"].append({"manifest_id": manifest, "source_owner_id": finder, "source_id": f"source:{finder}", "registered_at_ms": 1_000,
                                             "approved_by": "synthetic-official", "approval_ref": f"ref:{finder}"})
        rows["population_manifest_bindings"].append({"population_id": population, "manifest_id": manifest})
    return rows


def generated_rows(seed: int, count: int) -> dict:
    rng = random.Random(seed)
    rows = _empty_rows()
    seq = iter(range(1, 1_000_000))
    for n in range(count):
        item, oid, base = f"item-{n:04d}", f"obligation:{n:04d}", rng.choice(DATES)

        def event(kind: str, payload: dict, at: int) -> int:
            number = next(seq)
            rows["financial_events"].append({"aggregate_type": "OBLIGATION", "aggregate_id": oid, "kind": kind, "payload_json": json.dumps(payload),
                                             "event_sequence": number, "committed_at_ms": at})
            return number

        origins, digests = [], []

        def document(d: object, source: str) -> None:
            evidence_id = f"evidence:{n}:{d}"
            origin = rng.choice(origins) if origins and rng.random() < 0.12 else f"origin:{n}:{d}"
            digest = rng.choice(digests) if digests and rng.random() < 0.08 else hashlib.sha3_512(evidence_id.encode()).digest()
            origins.append(origin), digests.append(digest)
            at = base + rng.choice((0, 0, -DAY, 3 * DAY, 200 * DAY, 400 * DAY))
            received = at + rng.choice((0, DAY, 90 * DAY, 380 * DAY))
            rows["evidence"].append({"kind": "SUPPORT", "item_id": item, "evidence_id": evidence_id, "source_id": source, "common_origin_id": origin, "content_digest": digest,
                                     "record_digest": hashlib.sha3_512(b"record:" + evidence_id.encode()).digest(), "event_at_ms": at, "received_at_ms": received})
            event("SUPPORT_EVIDENCE_RECORDED", {"evidence_id": evidence_id}, received)

        for d in range(rng.randrange(0, 9)):
            document(d, rng.choice(("state-demand-letters", "state-mailroom", "state-cms64", LEGAL, LEGAL, LEGAL, "outside-source")))
        for kind in ("OFFSET_REJECTED_CORRECTION_AUTHORIZED", "ACTION_ACKNOWLEDGED"):
            if rng.random() < 0.4:
                event(kind, {}, base + rng.choice((0, 5 * DAY, 40 * DAY)))
        owed = rng.choice((1, 3, 101, 10_001, 1_000_000, 500_001))
        for p in range(rng.choice((0, 0, 1, 2))):
            evidence_id, at = f"evidence:{n}:payment:{p}", base + rng.choice((10 * DAY, 100 * DAY, 380 * DAY))
            received = at + rng.choice((0, 2 * DAY))
            rows["evidence"].append({"kind": "PAYMENT_CONFIRMATION", "item_id": item, "evidence_id": evidence_id, "source_id": "state-collections", "common_origin_id": evidence_id,
                                     "content_digest": hashlib.sha3_512(evidence_id.encode()).digest(), "record_digest": hashlib.sha3_512(evidence_id.encode()).digest(),
                                     "event_at_ms": at, "received_at_ms": received})
            rows["payments"].append({"obligation_id": oid, "active": int(rng.random() < 0.85), "event_at_ms": at, "evidence_id": evidence_id,
                                     "amount_cents": rng.choice((1, owed // 2 + 1, owed, 2 * owed))})
            event("PAYMENT_RECEIVED", {"payment_id": f"payment:{n}:{p}"}, received)
        for d, decision in enumerate(rng.sample(("OFFSET_AUTHORIZED", "OFFSET_AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED"), rng.choice((0, 0, 1, 2)))):
            decided = base + rng.choice((15 * DAY, 200 * DAY, 365 * DAY, 400 * DAY))
            rows["determinations"].append({"obligation_id": oid, "determination_id": f"determination:{n}:{d}", "decision": decision, "decided_at_ms": decided,
                                           "amount_cents": rng.choice((1, owed // 2 + 1, owed))})
            rows["actions"].append({"determination_id": f"determination:{n}:{d}", "created_at_ms": decided + rng.choice((0, DAY, 100 * DAY))})
        flags =[rng.random() < 0.6 for _ in range(rng.randrange(0, 4))]
        for revision in rng.sample(range(1, len(flags) + 1), len(flags)):  # rows out of revision order
            rows["evaluations"].append({"obligation_id": oid, "revision": revision, "amount_satisfied": int(flags[revision - 1]),
                                        "evaluated_at_ms": base + revision * rng.choice((20 * DAY, 120 * DAY)), "evaluation_id": f"evaluation:{n}:{revision}"})
        for d in range(rng.choice((0, 0, 1, 1, 2, 3))):
            act = rng.choice(("ASSIGN", "CLOSE", "CLOSE"))
            reason = rng.choice(("BANKRUPTCY", "OUT_OF_BUSINESS", "UNCOLLECTIBLE_OTHER", "UNCOLLECTIBLE_OTHER", "NOT_IN_RULES")) if act == "CLOSE" else None
            owner = rng.choice(("state-recovery-unit", "triage-model-1", "unlisted-person", "plan-a")) if act == "ASSIGN" else None
            suggestion = None if rng.random() < 0.5 else {
                "source_id": rng.choice(("triage-model-1", "unlisted-model")), "source_ref": "ref:suggestion", "source_sha256": "AB" * 32, "suggested_at_ms": base,
                "act": act if rng.random() < 0.6 else "ASSIGN", "reason_code": reason if rng.random() < 0.7 else None, "owner_id": owner if rng.random() < 0.7 else "plan-a"}
            event("FOLLOWTHROUGH_DECIDED", {"decision_id": f"decision:{n}:{d}", "item_id": item, "act": act, "reason_code": reason, "owner_id": owner, "suggestion": suggestion,
                                            "actor_id": "synthetic-official", "actor_role": "CASE_OWNER"}, base + rng.choice((30 * DAY, 300 * DAY, 500 * DAY)))
        if rng.random() < 0.15:
            document("late", LEGAL)  # recorded after the decisions: never covers a close, and is activity after it
        if rng.random() < 0.1:
            event("PAYMENT_REVERSED", {}, base + 600 * DAY)
        rows["obligations"].append({"item_id": item, "obligation_id": oid, "population_id": "population:typed" if rng.random() < 0.9 else "population:untyped",
                                    "period_id": rng.choice(("period:ffy2027q2", "period:ffy2028q1", "period:ffy2029q3")), "owed_cents": owed,
                                    "shortfall_cents": rng.choice((0, owed, owed // 2, owed - 1)), "amount_satisfied": int(bool(flags) and flags[-1])})
    return rows


def hand_rows(*specs: dict) -> dict:
    """One typed-finder obligation per spec: support [(source, time)], payments [(event, received, cents)], authorized
    offsets [(decision time, recorded, cents)], satisfied_at, decisions [(act, reason, time)], owed and shortfall cents. Events are
    numbered in that order."""
    rows, seq = _empty_rows(), iter(range(1, 1_000_000))
    for n, spec in enumerate(specs):
        item, oid = f"item-{n}", f"obligation:{n}"

        def event(kind: str, payload: dict, at: int) -> None:
            rows["financial_events"].append({"aggregate_type": "OBLIGATION", "aggregate_id": oid, "kind": kind, "payload_json": json.dumps(payload),
                                             "event_sequence": next(seq), "committed_at_ms": at})

        def evidence(kind: str, evidence_id: str, source: str, at: int, received: int) -> None:
            digest = hashlib.sha3_512(evidence_id.encode()).digest()
            rows["evidence"].append({"kind": kind, "item_id": item, "evidence_id": evidence_id, "source_id": source, "common_origin_id": evidence_id,
                                     "content_digest": digest, "record_digest": digest, "event_at_ms": at, "received_at_ms": received})

        for d, (source, at) in enumerate(spec.get("support", ())):
            evidence("SUPPORT", f"evidence:{n}:{d}", source, at, at)
            event("SUPPORT_EVIDENCE_RECORDED", {"evidence_id": f"evidence:{n}:{d}"}, at)
        for p, (at, received, cents) in enumerate(spec.get("payments", ())):
            evidence("PAYMENT_CONFIRMATION", f"evidence:{n}:payment:{p}", "state-collections", at, received)
            rows["payments"].append({"obligation_id": oid, "active": 1, "event_at_ms": at, "evidence_id": f"evidence:{n}:payment:{p}", "amount_cents": cents})
            event("PAYMENT_RECEIVED", {"payment_id": f"payment:{n}:{p}"}, received)
        for d, (at, recorded, cents) in enumerate(spec.get("offsets", ())):
            rows["determinations"].append({"obligation_id": oid, "determination_id": f"determination:{n}:{d}", "decision": "OFFSET_AUTHORIZED", "decided_at_ms": at, "amount_cents": cents})
            rows["actions"].append({"determination_id": f"determination:{n}:{d}", "created_at_ms": recorded})
        satisfied_at = spec.get("satisfied_at")
        if satisfied_at is not None:
            rows["evaluations"].append({"obligation_id": oid, "revision": 1, "amount_satisfied": 1, "evaluated_at_ms": satisfied_at, "evaluation_id": f"evaluation:{n}"})
        for d, (act, reason, at) in enumerate(spec.get("decisions", ())):
            event("FOLLOWTHROUGH_DECIDED", {"decision_id": f"decision:{n}:{d}", "item_id": item, "act": act, "reason_code": reason, "owner_id": None, "suggestion": None,
                                            "actor_id": "synthetic-official", "actor_role": "CASE_OWNER"}, at)
        owed = spec.get("owed", 1000)
        rows["obligations"].append({"item_id": item, "obligation_id": oid, "population_id": "population:typed", "period_id": "period:ffy2027q2", "owed_cents": owed,
                                    "shortfall_cents": spec.get("shortfall", owed), "amount_satisfied": int(satisfied_at is not None)})
    return rows


CORRECTION_KINDS = ("SUPPORT", "PAYMENT_CONFIRMATION", "PAYMENT_CONFIRMATION", "PAYMENT_REVERSAL", "OFFSET_CLAIM", "REPORT", "REPORT_CORRECTION", "UNLISTED_EVIDENCE")
LATER_KINDS = (*owner_module._FOLLOWUP_TOUCHES, "UNLISTED_EVENT")


def generated_correction(rng: random.Random) -> tuple[sqlite3.Connection, dict, str, int, object, object]:
    """One correction's store: the tables and columns the owner's status query reads."""
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        "CREATE TABLE actions(action_id TEXT PRIMARY KEY, status TEXT); CREATE TABLE action_outbox(action_id TEXT PRIMARY KEY, status TEXT);"
        "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY, item_id TEXT, kind TEXT); CREATE TABLE payments(payment_id TEXT PRIMARY KEY, evidence_id TEXT);"
        "CREATE TABLE financial_events(event_sequence INTEGER PRIMARY KEY, aggregate_type TEXT, aggregate_id TEXT, kind TEXT, payload_json TEXT);"
        "CREATE TABLE financial_conflicts(candidate_evidence_id TEXT);")
    work, item, obligation, sequence = "action:correction:g", "item-g", "obligation:g", 500
    numbers = iter(rng.sample([*range(1, sequence), *range(sequence + 1, 2 * sequence)], 60))

    def event(aggregate: tuple[str, str], kind: str, payload: dict) -> None:
        connection.execute("INSERT INTO financial_events VALUES (?,?,?,?,?)", (next(numbers), *aggregate, kind, json.dumps(payload)))

    pack, authority = {"pack_id": "pack:v1", "version": 1, "digest": "AA"}, {"authority_id": "authority:1", "epoch": 1}
    bound = []
    for e in range(rng.randrange(0, 6)):
        evidence_id, kind = f"evidence:{e}", rng.choice(CORRECTION_KINDS)
        connection.execute("INSERT INTO evidence VALUES (?,?,?)", (evidence_id, item if rng.random() < 0.9 else "item-other", kind))
        if rng.random() < 0.35:
            bound.append(evidence_id)
        if kind == "PAYMENT_CONFIRMATION":
            if rng.random() < 0.6:
                connection.execute("INSERT INTO payments VALUES (?,?)", (f"payment:{e}", evidence_id))
                event(("OBLIGATION", rng.choice((obligation, obligation, "obligation:other"))), "PAYMENT_RECEIVED",
                      {"payment_id": f"payment:{e}", "pays_action_id": rng.choice((work, "action:other", None))})
            elif rng.random() < 0.7:
                event(("OBLIGATION", obligation), "PAYMENT_DUPLICATE_EVIDENCE", {"candidate_evidence_id": evidence_id})
                if rng.random() < 0.3:
                    connection.execute("INSERT INTO financial_conflicts VALUES (?)", (evidence_id,))
    for _ in range(rng.randrange(0, 10)):
        event(rng.choice((("OBLIGATION", obligation), ("OBLIGATION", obligation), ("OBLIGATION", "obligation:other"), ("CONTROL_PACK", "pack:v2"))), rng.choice(LATER_KINDS), {})
    statuses = rng.choice((("READY", "READY"), ("ACKNOWLEDGED", "ACKNOWLEDGED")) * 3 + (("CANCELLED", "CANCELLED"), ("READY", "CANCELLED"), None))
    if statuses is not None:
        connection.execute("INSERT INTO actions VALUES (?,?)", (work, statuses[0]))
        connection.execute("INSERT INTO action_outbox VALUES (?,?)", (work, statuses[1]))
    followup = {"contract": owner_module._CORRECTION_FOLLOWUP_CONTRACT, "dependency_families": list(owner_module._CORRECTION_FOLLOWUP_DEPENDENCIES), "work_id": work,
                "control_pack": dict(pack), "authority": dict(authority), "determination_id": "determination:1", "determination_digest": "D1",
                "supporting_evidence": [{"evidence_id": e} for e in bound]}
    damage = rng.random()
    if damage < 0.04:
        followup["contract"] = "RR/FINANCIAL/CORRECTION-FOLLOWUP/v0"
    elif damage < 0.08:
        followup["dependency_families"] = followup["dependency_families"][:-1]
    elif damage < 0.12:
        del followup[rng.choice(("work_id", "control_pack", "authority", "determination_id", "supporting_evidence"))]
    current_pack = rng.choice((dict(pack), dict(pack), {**pack, "version": 2}, {"pack_id": "pack:v1", "version": 1}, {**pack, "extra": True}))
    current_authority = rng.choice((authority, authority, {**authority, "epoch": 2}))
    determination = rng.choice(({"determination_id": "determination:1", "determination_digest": "D1"},) * 3 + ({"determination_id": "determination:2", "determination_digest": "D2"}, None))
    package = {"obligation": {"obligation_id": obligation}, "control_pack": current_pack, "evaluation_receipt": {"authority": current_authority}, "current_determination": determination}
    artifact = None if rng.random() < 0.05 else {"contract": "x", "version": 1, "sha256": "00"}
    return connection, package, item, sequence, followup, artifact


class FollowThroughLeanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        scratch = os.environ.get("E3_SCRATCH")
        if not scratch:
            raise RuntimeError("set E3_SCRATCH to a scratch folder for this run; the test stores never go to the Temp folder")
        cls.tmp = tempfile.TemporaryDirectory(prefix="rr-follow-lean-", dir=scratch)
        cls.dir = Path(cls.tmp.name)
        out = cls.dir / "olean" / "BlindLedger" / "Financial"
        out.mkdir(parents=True)
        done = _lean_run([f"--root={LEAN}", "-o", str(out / "FollowThrough.olean"), str(MODULE)], cls.dir / "olean")
        assert done.returncode == 0 and not done.stdout.strip(), done.stdout[-4000:] + done.stderr[-2000:]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def _lean(self, follow: list[dict], corrections: list[dict], calendar: tuple[int, ...] = ()) -> dict:
        path = self.dir / "input.json"
        path.write_text(json.dumps({"follow": follow, "corrections": corrections, "calendar": list(calendar)}), encoding="utf-8")
        done = _lean_run(["--run", str(RUNNER), str(path)], self.dir / "olean")
        self.assertEqual(done.returncode, 0, done.stdout[-2000:] + done.stderr[-2000:])
        return json.loads(done.stdout)

    def _same_followthrough(self, cases: list[tuple[dict, dict, int]]) -> list[dict]:
        """Lean equals Python on every (rows, rules, now); returns the Python items."""
        lean = self._lean([{"rules": rules, "now": now, "obligations": lean_obligations(rows)} for rows, rules, now in cases], [])["follow"]
        seen = []
        for (rows, rules, now), got in zip(cases, lean, strict=True):
            items, gaps = python_followthrough(rows, rules, now)
            self.assertEqual([g["item"] for g in got], items)
            self.assertEqual({gap for g in got for gap in g["gaps"]}, gaps)
            seen += items
        return seen

    def test_the_laws_theorem_uses_only_the_standard_axioms(self) -> None:
        check = self.dir / "axioms.lean"
        check.write_text("import BlindLedger.Financial.FollowThrough\n#print axioms BlindLedger.Financial.FollowThrough.follow_through_laws\n", encoding="utf-8")
        done = _lean_run([str(check)], self.dir / "olean")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("depends on axioms: [", done.stdout)
        axioms = set(done.stdout.split("depends on axioms: [", 1)[1].split("]", 1)[0].replace("\n", " ").replace(" ", "").split(","))
        self.assertLessEqual(axioms, STANDARD_AXIOMS)

    def test_hospital_h_correction_at_each_point(self) -> None:
        from tests.test_right_rail_financial_mirror import FinancialMirrorTests

        scope = dataclasses.asdict(PERIOD_ONE_SCOPE)
        rules = _rules(scope["state_id"], [{"basis_points": 5000, "period_id": scope["period_id"]}])
        case = FinancialMirrorTests("test_correction_followup_outputs_resume_and_reopen_through_mirror")
        case.setUp()
        self.addCleanup(case.doCleanups)
        store, mirror, statuses, follow = case.store, case.mirror, [], []
        real_rows, real_status = followthrough.verified_rows, owner_module.FinancialOwner._correction_followup_status

        def point(now_offsets: tuple[int, ...] = (DAY, 90 * DAY)) -> None:
            captured = []

            def rows_spy(*args: object, **kwargs: object) -> tuple:
                captured.append(real_rows(*args, **kwargs))
                return captured[-1]

            for offset in now_offsets:
                with mock.patch.object(followthrough, "verified_rows", rows_spy), \
                        mock.patch.object(followthrough, "bound_control_pack", return_value={"pack_id": "pack:test", "version": 1, "pack_digest": b"\x00"}), \
                        mock.patch.object(followthrough, "signed_pack", side_effect=lambda record, *rest: record):
                    record = followthrough._build(store.path, store.export_continuity(), trusted_authority=store.trusted_authority, expected_scope=scope,
                                                  rules_bytes=_encode(rules), generated_at_ms=case.clock.value + offset, custody=None)
                follow.append((captured[-1][1], rules, case.clock.value + offset, record["items"]))
            self._correction_point(statuses, real_status, mirror)

        case._prepare_action()  # the correction is READY
        point()
        case.clock.value += DAY
        mirror.acknowledge_action("action:correction:h", "ack:correction:h:followup")
        point()
        case.clock.value += DAY
        with closing(sqlite3.connect(f"file:{store.path}?mode=ro", uri=True)) as connection:
            (shortfall,) = connection.execute("SELECT shortfall_cents FROM obligations WHERE item_id=?", (H_ITEM_ID,)).fetchone()
        store.record_payment_evidence(item_id=H_ITEM_ID, payment_id="payment:correction", common_origin_id="origin:payment:correction", amount_cents=shortfall,
                                      evidence_id="evidence:payment:correction", event_at_ms=case.clock.value - 1, pays_action_id="action:correction:h")
        store.evaluate_obligation(H_ITEM_ID)
        point()
        case.clock.value += DAY
        store.record_support_evidence(item_id=H_ITEM_ID, evidence_id="evidence:notice:h", common_origin_id="origin:notice:h",
                                      source_id="state-demand-letters", applicable_at_ms=case.clock.value, event_at_ms=case.clock.value)
        point((DAY, 400 * DAY))
        case._cancel_correction()  # a raw store edit: the store no longer verifies, so only the status is compared
        self._correction_point(statuses, real_status, mirror)

        items = self._same_followthrough([(rows, rules, now) for rows, rules, now, _ in follow])
        self.assertEqual([i for _, _, _, i in follow for i in i], items)
        h = [i for i in items if i["item_id"] == H_ITEM_ID]
        self.assertEqual({c["status"] for i in h for c in i["clocks"] if c["clock_id"] == "correction-paid"}, {"RUNNING", "MISSED", "MET"})
        self.assertIn("SATISFIED", {i["status"] for i in h})
        self.assertEqual(statuses[0], ("CURRENT", []))
        self.assertEqual({s for s, _ in statuses}, {"CURRENT", "REOPENED", "REVIEW_REQUIRED"})

    def _correction_point(self, statuses: list, real_status: object, mirror: object) -> None:
        seen = []

        def spy(self_: object, connection: sqlite3.Connection, *args: object) -> tuple:
            result = real_status(self_, connection, *args)
            seen.append((lean_correction(connection, *args), result))
            return result

        with mock.patch.object(owner_module.FinancialOwner, "_correction_followup_status", spy):
            mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")
        ((inputs, (status, changed)),) = seen
        (got,) = self._lean([], [inputs])["corrections"]
        self.assertEqual((got["status"], got["changed"]), (status, changed))
        statuses.append((status, changed))

    def test_generated_follow_through(self) -> None:
        nows = (_ms(2027, 6, 1), _ms(2028, 6, 1), _ms(2030, 1, 1))
        fmap = [{"basis_points": 5000, "period_id": "period:ffy2027q2"}, {"basis_points": 7311, "period_id": "period:ffy2028q1"}]
        cases = [(generated_rows(seed, 100), _rules(RULES["state_id"], None if seed % 8 == 7 else fmap), nows[seed % 3]) for seed in range(16)]
        items = self._same_followthrough(cases)
        clocks = [(c["clock_id"], c["status"]) for i in items for c in i["clocks"]]
        for clock in ("correction-paid", "federal-share-credit", "recovery-action"):
            for status in ("NOT_ANCHORED", "RUNNING", "MISSED", "MET", "MET_LATE"):
                self.assertIn((clock, status), clocks)
        for clock in ("federal-share-credit", "recovery-action"):
            self.assertIn((clock, "STOPPED"), clocks)
        stopped_by = {d["reason_code"] for i in items for c in i["clocks"] for d in i["decisions"] if c["stopped_by"] == d["decision_id"]}
        self.assertEqual(stopped_by, {r["reason_code"] for r in RULES["closure_reasons"]})
        gaps = {":".join(gap.split(":")[:2]) for rows, rules, now in cases for gap in python_followthrough(rows, rules, now)[1]}
        self.assertLessEqual({"gap:closure-evidence-missing", "gap:decision-not-in-rules", "gap:activity-after-close", "gap:suggestion-source-not-typed",
                              "gap:finder-not-typed", "gap:fmap-period-missing", "gap:write-off-line-unknown"}, gaps)
        leap = [c for i in items for c in i["clocks"] if c["anchor"] and c["anchor"]["at_ms"] == _ms(2028, 2, 29) and c["clock_id"] == "federal-share-credit"]
        self.assertTrue(leap)
        self.assertTrue(all(c["ends_ms"] == _ms(2029, 2, 28) for c in leap))
        self.assertTrue(any(i["federal_share"] and i["federal_share"]["cents"] * 2 == i["principal_cents"] + 1 for i in items))
        parts = [(i, p) for i in items for p in i["share_parts"]]
        self.assertTrue(any(p["principal_cents"] * i["federal_share"]["basis_points"] % 10_000 == 5_000 for i, p in parts))
        self.assertEqual({i["status"] for i in items}, {"OPEN", "SATISFIED", "CLOSED"})
        self.assertEqual({p["status"] for _, p in parts}, {"DUE", "MISSED", "MET", "MET_LATE"})
        self.assertEqual({p["report"]["form"] for _, p in parts}, {"64.9C1", "64.9O"})
        self.assertTrue(any(len({p["report"]["quarter"] for p in i["share_parts"]}) > 1 for i in items))
        stopped_and_met = 0
        for rows, rules, now in cases:  # every part owes cents; the parts cover the whole debt, or the money collected once a covered close stops the clock
            stops = {reason["reason_code"]: reason["stops"] for reason in rules["closure_reasons"]}
            kinds = {clock["clock_id"]: clock["report"]["kind"] for clock in rules["clocks"]}
            python, gaps = python_followthrough(rows, rules, now)
            for i in python:
                collected = sum(row["amount_cents"] for row in rows["payments"] if row["obligation_id"] == i["obligation_id"] and row["active"] == 1) + sum(
                    row["amount_cents"] for row in rows["determinations"] if row["obligation_id"] == i["obligation_id"] and row["decision"] == "OFFSET_AUTHORIZED")
                close = i["decisions"][-1] if i["decisions"] and i["decisions"][-1]["act"] == "CLOSE" else None
                for clock in i["clocks"]:
                    mine = [p for p in i["share_parts"] if p["clock_id"] == clock["clock_id"]]
                    self.assertTrue(all(p["principal_cents"] > 0 and p["cents"] > 0 for p in mine))
                    self.assertLessEqual(sum(p["principal_cents"] for p in mine), i["principal_cents"])
                    if clock["anchor"] and kinds[clock["clock_id"]] == "CMS64_QUARTER" and i["federal_share"]:
                        stopped = (close is not None and f"gap:closure-evidence-missing:{close['decision_id']}" not in gaps and clock["clock_id"] in stops.get(close["reason_code"], ())
                                   and close["decided_at_ms"] < clock["ends_ms"])
                        covered = min(i["principal_cents"], collected) if stopped else i["principal_cents"]
                        self.assertEqual(sum(p["cents"] for p in mine), (covered * i["federal_share"]["basis_points"] + 5000) // 10_000)
                        stopped_and_met += stopped and clock["status"] in ("MET", "MET_LATE")
        self.assertTrue(stopped_and_met)

    def test_hand_boundaries_and_leap_years(self) -> None:
        notice, ends = _ms(2027, 3, 1), _ms(2027, 3, 1) + 60 * DAY  # the recovery-action clock's end
        credit_due, share_due, fed_ends = _ms(2028, 4, 1) + 30 * DAY, _ms(2027, 4, 1) + 30 * DAY, _ms(2028, 3, 1)
        demand = (DEMAND, notice)
        four_year = {**CORRECTION_CLOCK, "add": {"count": 4, "unit": "YEAR"}, "anchors": ["EVIDENCE:DISCOVERY_NOTICE"], "clock_id": "four-year", "satisfied_by": ["SATISFIED"]}
        rules = _rules(RULES["state_id"], RULES["fmap_basis_points"])
        four = {**rules, "clocks": sorted([*rules["clocks"], four_year], key=lambda c: c["clock_id"])}
        plain = hand_rows({"support": [demand]})
        closed = hand_rows({"support": [demand, *[(LEGAL, notice + DAY)] * 3], "payments": [(notice + 10 * DAY, notice + 11 * DAY, 600)], "owed": 1000, "shortfall": 400,
                            "decisions": [("CLOSE", "BANKRUPTCY", notice + 30 * DAY)]})
        deciding = hand_rows(*({"support": [demand], "decisions": [("CLOSE", "UNCOLLECTIBLE_OTHER", at)]} for at in (ends, ends - 1)))
        recovering = hand_rows(*({"support": [demand], "satisfied_at": at} for at in (fed_ends, fed_ends - 1)))
        leap = hand_rows(*({"support": [(DEMAND, _ms(year, 2, 29))]} for year in (2024, 2096, 2092)))
        cases = [(plain, rules, now) for now in (ends - 1, ends, credit_due - 1, credit_due)] + [(closed, rules, share_due - 1), (closed, rules, share_due),
                 (deciding, rules, ends + DAY), (recovering, rules, ends + DAY), (leap, four, _ms(2100, 6, 1))]
        items = iter(self._same_followthrough(cases))
        got = [[next(items) for _ in rows["obligations"]] for rows, _, _ in cases]

        def field(case: int, clock: str, key: str) -> list:
            return [{c["clock_id"]: c for c in item["clocks"]}[clock][key] for item in got[case]]

        # now equal to the due time is late, at the clock's own comparison and at the collected share's
        self.assertEqual([field(n, "recovery-action", "status")[0] for n in range(4)], ["RUNNING", "MISSED", "MISSED", "MISSED"])
        self.assertEqual([field(n, "federal-share-credit", "status")[0] for n in range(4)], ["RUNNING", "RUNNING", "RUNNING", "MISSED"])
        self.assertEqual([got[n][0]["share_parts"][0]["status"] for n in (4, 5)], ["DUE", "MISSED"])
        # a close decided at the clock's end does not stop it; one millisecond earlier does
        self.assertEqual(field(6, "recovery-action", "status"), ["MISSED", "STOPPED"])
        # a recovery at the year end is not before it: the uncollected line; one millisecond earlier, the collected line
        self.assertEqual([r["form"] for r in field(7, "federal-share-credit", "report")], ["64.9O", "64.9C1"])
        # four years from 29 February: a leap year keeps it, 2100 is not one
        self.assertEqual(field(8, "four-year", "ends_ms"), [_ms(2028, 2, 29), _ms(2100, 2, 28), _ms(2096, 2, 29)])

    def test_federal_share_is_due_on_each_collection_quarter(self) -> None:
        # 42 CFR 433.320(a)(2): each collection before the year end owes its share on that quarter's CMS-64; the rest on the
        # year-end quarter (433.316(h): a part payment does not move the year); nothing after the year end (433.320(b)(2)).
        found, ends = _ms(2026, 1, 15), _ms(2027, 1, 15)
        first, second = (_ms(2026, 3, 10), _ms(2026, 3, 10), 600_000), (_ms(2026, 11, 20), _ms(2026, 11, 20), 400_000)
        demand, legal = (DEMAND, found), [(LEGAL, found + DAY)] * 3
        rules = _rules(RULES["state_id"], RULES["fmap_basis_points"])
        specs = [  # (spec, now)
            ({"support": [demand], "payments": [first], "owed": 1_000_000, "shortfall": 400_000}, _ms(2026, 8, 1)),
            ({"support": [demand], "payments": [first, second], "owed": 1_000_000, "shortfall": 0, "satisfied_at": second[1]}, _ms(2026, 12, 1)),
            ({"support": [demand], "payments": [(_ms(2026, 2, 1), _ms(2026, 2, 1), 300_000), (_ms(2026, 3, 20), _ms(2026, 3, 20), 300_000)],
              "owed": 1_000_000, "shortfall": 400_000}, _ms(2026, 4, 15)),
            ({"support": [demand], "payments": [(ends, ends, 1000)], "owed": 1000, "shortfall": 0, "satisfied_at": ends}, _ms(2027, 2, 1)),
            ({"support": [demand], "payments": [(ends - 1, ends - 1, 1000)], "owed": 1000, "shortfall": 0, "satisfied_at": ends - 1}, _ms(2027, 2, 1)),
            ({"support": [demand], "payments": [(_ms(2026, m, 1), _ms(2026, m, 1), 1) for m in (2, 5, 8)], "owed": 3, "shortfall": 0, "satisfied_at": _ms(2026, 8, 1)}, _ms(2026, 9, 1)),
            ({"support": [demand, *legal], "payments": [first], "owed": 1_000_000, "shortfall": 400_000, "decisions": [("CLOSE", "BANKRUPTCY", _ms(2026, 6, 1))]}, _ms(2026, 7, 1)),
            # an authorized offset is a recovery at its decision time, like a payment
            ({"support": [demand], "payments": [first], "offsets": [second], "owed": 1_000_000, "shortfall": 0, "satisfied_at": second[1]}, _ms(2026, 12, 1)),
            ({"support": [demand], "offsets": [(ends, ends, 1000)], "owed": 1000, "shortfall": 0, "satisfied_at": ends}, _ms(2027, 2, 1)),
            # a filed credit covers only quarters ended by its filing: one before the first quarter's end covers nothing
            ({"support": [demand, (CMS64, _ms(2026, 4, 20))], "payments": [first, second], "owed": 1_000_000, "shortfall": 0, "satisfied_at": second[1]}, _ms(2026, 12, 1)),
            ({"support": [demand, (CMS64, _ms(2026, 4, 1) - 1), (CMS64, _ms(2026, 5, 1))], "payments": [first, second], "owed": 1_000_000, "shortfall": 0,
              "satisfied_at": second[1]}, _ms(2026, 12, 1)),
            # a credit filed before a collection was on record cannot have reported it (payment evidence, then an offset's record)
            ({"support": [demand, (CMS64, _ms(2027, 2, 1))], "payments": [(_ms(2026, 12, 15), _ms(2027, 3, 1), 1_000_000)], "owed": 1_000_000, "shortfall": 0,
              "satisfied_at": _ms(2027, 3, 1)}, _ms(2027, 3, 15)),
            ({"support": [demand, (CMS64, _ms(2027, 2, 1))], "offsets": [(_ms(2026, 12, 15), _ms(2027, 3, 1), 1_000_000)], "owed": 1_000_000, "shortfall": 0,
              "satisfied_at": _ms(2027, 3, 1)}, _ms(2027, 3, 15)),
            # one credit meets one part, the earliest it can; a second credit meets the next
            *(({"support": [(DEMAND, _ms(2026, 6, 1)), *credits], "payments": [(_ms(2026, 11, 1), _ms(2026, 11, 1), 500_000), (_ms(2027, 2, 1), _ms(2027, 2, 1), 500_000)],
                "owed": 1_000_000, "shortfall": 0, "satisfied_at": _ms(2027, 2, 1)}, _ms(2027, 4, 25))
              for credits in ([(CMS64, _ms(2027, 4, 15))], [(CMS64, _ms(2027, 4, 20)), (CMS64, _ms(2027, 4, 15))])),
            # a covered close stops the uncollected part even when a credit was filed
            ({"support": [demand, *legal, (CMS64, _ms(2026, 4, 20))], "payments": [first], "owed": 1_000_000, "shortfall": 400_000,
              "decisions": [("CLOSE", "BANKRUPTCY", _ms(2026, 6, 1))]}, _ms(2027, 6, 1)),
            # after a stop, money collected after the year end owes on its own quarter, and a credit filed before it cannot report it
            *(({"support": [(DEMAND, _ms(2026, 6, 15)), *[(LEGAL, _ms(2026, 6, 16))] * 3, *credits], "payments": [(_ms(2027, 9, 5), _ms(2027, 9, 5), 50_000)],
                "owed": 1_000_000, "shortfall": 950_000, "decisions": [("CLOSE", "BANKRUPTCY", _ms(2027, 1, 15))]}, _ms(2027, 10, 15))
              for credits in ([(CMS64, _ms(2027, 7, 10))], [])),
            # a credit meets the collections on record when it was filed; a cent of the same quarter recorded later is a part of its own
            *(({"support": [demand, *credits], "payments": [(_ms(2026, 12, 15), _ms(2026, 12, 16), 100_000), (_ms(2026, 12, 20), _ms(2027, 3, 1), 1)],
                "owed": 1_000_000, "shortfall": 899_999}, _ms(2027, 3, 15))
              for credits in ([(CMS64, _ms(2027, 1, 20))], [(CMS64, _ms(2027, 1, 20)), (CMS64, _ms(2027, 3, 5))])),
            # cents past the owed amount add no principal, so their late record does not hold back the credit
            ({"support": [demand, (CMS64, _ms(2027, 1, 20))], "payments": [(_ms(2026, 12, 15), _ms(2026, 12, 16), 100), (_ms(2026, 12, 20), _ms(2027, 6, 1), 40)],
              "owed": 100, "shortfall": 0, "satisfied_at": _ms(2026, 12, 16)}, _ms(2027, 7, 1)),
            # satisfied before a later payment: parts in quarter order, and the credit meets the earliest quarter
            ({"support": [demand, (CMS64, _ms(2027, 1, 10))], "payments": [(_ms(2026, 11, 20), _ms(2026, 11, 20), 400_000)], "owed": 1_000_000, "shortfall": 0,
              "satisfied_at": _ms(2026, 3, 1)}, _ms(2027, 1, 20)),
        ]
        met_by_recovery = {**rules, "clocks": [{**c, "satisfied_by": [*c["satisfied_by"], "SATISFIED"]} if c["clock_id"] == "federal-share-credit" else c
                                                for c in rules["clocks"]]}
        items = self._same_followthrough([(hand_rows(spec), rules, now) for spec, now in specs] + [(hand_rows(specs[1][0]), met_by_recovery, specs[1][1])])
        got = [[(p["principal_cents"], p["cents"], p["report"]["quarter"], p["report"]["form"], p["status"]) for p in i["share_parts"]] for i in items]
        self.assertEqual(got, [
            # the example: on 1 August 2026 the first collection's 300,000 is overdue; the 200,000 balance waits for the year end
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MISSED"), (400_000, 200_000, "FFY2027Q2", "64.9O", "DUE")],
            # paid in full in two quarters: each owes on its own quarter
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MISSED"), (400_000, 200_000, "FFY2027Q1", "64.9C1", "DUE")],
            # two collections in one quarter make one part
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "DUE"), (400_000, 200_000, "FFY2027Q2", "64.9O", "DUE")],
            # paid at the year-end instant: not before it, so the uncollected line; one millisecond earlier, the collected line
            [(1000, 500, "FFY2027Q2", "64.9O", "DUE")],
            [(1000, 500, "FFY2027Q2", "64.9C1", "DUE")],
            # half cents: each part rounds the running total, so 1 + 0 + 1 = round(1.5); rounding each part alone gives 3. The
            # middle collection owes 0 cents, so it makes no part (nothing to file)
            [(1, 1, "FFY2026Q2", "64.9C1", "MISSED"), (1, 1, "FFY2026Q4", "64.9C1", "DUE")],
            # a covered close stops the uncollected 400,000; the collected part's share stays due on its own quarter
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MISSED")],
            # the offset owes on its decision quarter; at the year end it adds nothing
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MISSED"), (400_000, 200_000, "FFY2027Q1", "64.9C1", "DUE")],
            [(1000, 500, "FFY2027Q2", "64.9O", "DUE")],
            # filed before the first part's due time: met; filed at it: late; the second quarter has not ended, so still due
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MET"), (400_000, 200_000, "FFY2027Q1", "64.9C1", "DUE")],
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MET_LATE"), (400_000, 200_000, "FFY2027Q1", "64.9C1", "DUE")],
            [(1_000_000, 500_000, "FFY2027Q1", "64.9C1", "MISSED")],
            [(1_000_000, 500_000, "FFY2027Q1", "64.9C1", "MISSED")],
            [(500_000, 250_000, "FFY2027Q1", "64.9C1", "MET_LATE"), (500_000, 250_000, "FFY2027Q2", "64.9C1", "DUE")],
            [(500_000, 250_000, "FFY2027Q1", "64.9C1", "MET_LATE"), (500_000, 250_000, "FFY2027Q2", "64.9C1", "MET")],
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MET")],
            [(50_000, 25_000, "FFY2027Q4", "64.9C1", "DUE")],
            [(50_000, 25_000, "FFY2027Q4", "64.9C1", "DUE")],
            [(100_000, 50_000, "FFY2027Q1", "64.9C1", "MET"), (1, 1, "FFY2027Q1", "64.9C1", "MISSED"), (899_999, 449_999, "FFY2027Q2", "64.9O", "DUE")],
            [(100_000, 50_000, "FFY2027Q1", "64.9C1", "MET"), (1, 1, "FFY2027Q1", "64.9C1", "MET_LATE"), (899_999, 449_999, "FFY2027Q2", "64.9O", "DUE")],
            [(100, 50, "FFY2027Q1", "64.9C1", "MET")],
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MET_LATE"), (400_000, 200_000, "FFY2027Q1", "64.9C1", "DUE")],
            # a recovery meets a clock that lists it, but it is not a filing: its parts stay missed or due
            [(600_000, 300_000, "FFY2026Q2", "64.9C1", "MISSED"), (400_000, 200_000, "FFY2027Q1", "64.9C1", "DUE")],
        ])
        self.assertEqual([p["due_ms"] for p in items[1]["share_parts"]], [_ms(2026, 5, 1), _ms(2027, 1, 31)])
        full = [i for n, i in enumerate(items) if n not in (6, 15, 16, 17)]  # the others cover the whole debt
        self.assertEqual([sum(p["cents"] for p in i["share_parts"]) for i in full], [i["federal_share"]["cents"] for i in full])
        federal = [{c["clock_id"]: c for c in i["clocks"]}["federal-share-credit"] for i in items]
        self.assertEqual([c["status"] for c in federal], [*["RUNNING"] * 6, "STOPPED", "RUNNING", "RUNNING", "MET", "MET", "MET_LATE", "MET_LATE", "MET", "MET",
                                                          "MET", "MET", "STOPPED", "MET", "MET", "MET", "MET_LATE", "MET"])
        self.assertEqual(federal[6]["due_ms"], _ms(2027, 5, 1))  # a stopped clock keeps its own due time, not a part's
        self.assertEqual(federal[7]["report"]["quarter"], "FFY2027Q1")  # the offset is the last recovery

    def test_calendar_matches_datetime_every_day(self) -> None:
        first, last = ((date(*day) - date(1970, 1, 1)).days for day in ((1971, 1, 1), (2200, 12, 31)))
        want = []
        for day in range(first, last + 1):
            t = day * DAY + 12345
            q = quarter_of(t)
            want.append([int(q[3:7]) * 10 + int(q[8]), quarter_window(q)[1], followthrough._add(t, {"count": 1, "unit": "YEAR"}), followthrough._add(t, {"count": 4, "unit": "YEAR"})])
        got = self._lean([], [], (first, last))["calendar"]
        self.assertEqual([first + i for i, (g, w) in enumerate(zip(got, want, strict=True)) if g != w][:3], [])

    def test_generated_correction_statuses(self) -> None:
        rng = random.Random(20261111)
        cases = [generated_correction(rng) for _ in range(2000)]
        inputs = [lean_correction(*case) for case in cases]
        python = [owner_module.FinancialOwner._correction_followup_status(None, *case) for case in cases]
        for case in cases:
            case[0].close()
        lean = self._lean([], inputs)["corrections"]
        self.assertEqual([(g["status"], g["changed"]) for g in lean], [(s, c) for s, c in python])
        self.assertEqual({s for s, _ in python}, {"CURRENT", "REOPENED", "REVIEW_REQUIRED"})
        families = {key.split("(", 1)[1].split(",", 1)[0] if key.startswith("COLLECTION") else key.split("(", 1)[0] for s, c in python for key in c}
        self.assertEqual(families, {"RULE", "AUTHORITY", "DETERMINATION", "SUPPORT_EVIDENCE", "PAYMENT_EVIDENCE", "OFFSET_EVIDENCE", "REPORT_EVIDENCE"})


if __name__ == "__main__":
    unittest.main()
