"""Read-only CMS-64.9 line pack: one line and one quarter, documented from a verified store.

The pack is documentation only (docs/CORE_REDESIGN.md "Line pack"). It reconciles cents to the
Ledger, names each row's evidence digest and the Control Pack and rule version it was decided
under, splits service period from payment date and lists what the Ledger does not hold. It makes
no determination about any payment. It is built only from a Continuity package that the
independent checker binds, row for row, to a fully verified store opened read-only; it writes
nothing. Standing claims: synthetic, non-PHI, nonpayment, proofSuiteId=null,
production_usable=false, activation=false.
"""

from __future__ import annotations

import hashlib
import json
import re

from app.right_rail_financial_derived import (  # NOT_HELD and quarter_window stay importable from here
    NOT_HELD, DerivedError, bound_control_pack, cents as _cents, hex_upper as _hex, quarter_of as _quarter_of, quarter_window, signed_pack, verified_rows,
)
from app.right_rail_financial_owner_independent import IndependentFinancialError, MAX_PACKAGE_BYTES
from app.right_rail_financial_switch import FinancialSwitchError, _canonical_json, _decode_canonical_json, _id


LINE_PACK_CONTRACT = "RR/LINE-PACK/CMS-64.9/v2"  # v2 (H2): signed with the custody key; v1 had "signer": null
LINE_MAP_CONTRACT = "RR/LINE-PACK/LINE-MAP/v1"
PROVENANCE_CONTRACT = "RR/LINE-PACK/PROVENANCE/v1"
PAYMENT_DATE_BASIS = "PAYMENT_EVENT_AT"  # CMS-64 reports by payment date; the only basis the Ledger holds
MAX_LINE_PACK_BYTES = 2 * MAX_PACKAGE_BYTES
MAX_LINE_MAP_BYTES = 64 * 1024
LINE_MAP_SOURCE_REF = "line-map:sha256:"  # the approved Control Pack lists this ref plus the map's SHA-256
_SOURCE_STATE = {"sequence", "history_head", "package_digest", "package_sha256"}  # the rest names the store
_LINE_RE = re.compile(r"[0-9]{1,2}[A-Z]{1,2}\Z")


class LinePackError(ValueError):
    """Raised when inputs cannot yield an exact line pack; nothing partial is returned."""


def _fail(code: str) -> None:
    raise LinePackError(f"line-pack:{code}")


def _line_entry(line_map_bytes: bytes, line: str, state_id: str) -> dict:
    """The one map entry for ``line``; the whole file is bound by SHA-256, so any edit is a new map."""
    value = _decode_canonical_json(line_map_bytes, maximum=MAX_LINE_MAP_BYTES, label="line-map")
    if set(value) != {"contract", "state_id", "lines"} or value["contract"] != LINE_MAP_CONTRACT:
        _fail("line-map-fields")
    if value["state_id"] != state_id:
        _fail("line-map-state")
    lines = value["lines"]
    if type(lines) is not list or not lines:
        _fail("line-map-lines")
    seen = []
    for entry in lines:
        if type(entry) is not dict or set(entry) != {"line_id", "payment_class", "payment_date_basis", "pack_version"}:
            _fail("line-map-entry")
        if type(entry["line_id"]) is not str or _LINE_RE.fullmatch(entry["line_id"]) is None:
            _fail("line-map-line-id")
        predicate = entry["payment_class"]
        if type(predicate) is not dict or set(predicate) != {"program_id", "payment_source_ids"}:
            _fail("line-map-predicate")
        _id(predicate["program_id"], "line-map-program")
        sources = predicate["payment_source_ids"]
        if type(sources) is not list or not sources or [_id(source, "line-map-source") for source in sources] != sorted(set(sources)):
            _fail("line-map-sources")
        if entry["payment_date_basis"] != PAYMENT_DATE_BASIS:
            _fail("line-map-date-basis")
        if type(entry["pack_version"]) is not int or entry["pack_version"] < 1:
            _fail("line-map-pack-version")
        seen.append(entry["line_id"])
    if seen != sorted(set(seen)):
        _fail("line-map-order")
    if line not in seen:
        _fail("line-map-unknown-line")
    return lines[seen.index(line)]


def _prior(prior_pack: bytes | None, line: str, quarter: str, source: dict, generated_at_ms: int, heads: dict) -> str | None:
    """A superseding pack is strictly later: same line, quarter and store; newer time; a head in this history."""
    if prior_pack is None:
        return None
    prior = _decode_canonical_json(prior_pack, maximum=MAX_LINE_PACK_BYTES, label="prior-pack")
    try:
        old = prior["source"]
        same = (
            prior["contract"] == LINE_PACK_CONTRACT
            and prior["line"] == line
            and prior["quarter"] == quarter
            and {k: v for k, v in old.items() if k not in _SOURCE_STATE} == {k: v for k, v in source.items() if k not in _SOURCE_STATE}
        )
        later = type(prior["generated_at_ms"]) is int and prior["generated_at_ms"] < generated_at_ms
        forward = type(old["history_head"]) is str and heads.get(old["sequence"]) == old["history_head"]
    except (AttributeError, KeyError, TypeError):
        _fail("prior-pack-fields")
    if not same:
        _fail("prior-pack-identity")
    if not later or not forward:
        _fail("chronology-not-strict")
    return hashlib.sha256(prior_pack).hexdigest().upper()


def build_line_pack(database: object, package_bytes: bytes, **inputs: object) -> bytes:
    """Canonical line-pack bytes for one CMS-64.9 ``line`` and ``quarter``.

    ``database`` is verified in full, read-only, against caller-supplied authority and scope, and
    ``package_bytes`` must be its current snapshot row for row; nothing else is trusted. The same
    inputs always give the same bytes but the hedged ``signature`` (``generated_at_ms`` is an input, never read from a clock).
    ``reported_line_cents`` is the state's reported line amount: the coverage denominator. Every field reads only what
    the owner clock recorded before quarter end; a payment, reversal or amount conflict recorded later is listed once,
    in the adjustments of the quarter that recorded it, so a closed quarter's pack never changes.
    """
    try:
        return _build(database, package_bytes, **inputs)
    except (DerivedError, FinancialSwitchError, IndependentFinancialError) as error:
        raise LinePackError(f"line-pack:{error}") from None


def _build(
    database: object,
    package_bytes: bytes,
    *,
    trusted_authority: object,
    expected_scope: object,
    line_map_bytes: bytes,
    line: str,
    quarter: str,
    reported_line_cents: int,
    generated_at_ms: int,
    prior_pack: bytes | None = None,
    custody: object,
) -> bytes:
    start_ms, end_ms = quarter_window(quarter)
    denominator = _cents(reported_line_cents, "reported-line-cents", minimum=1)
    store, rows, source = verified_rows(database, package_bytes, trusted_authority=trusted_authority, expected_scope=expected_scope, generated_at_ms=generated_at_ms)
    scope = store["scope"]
    entry = _line_entry(line_map_bytes, line, scope["state_id"])
    line_map_sha256 = hashlib.sha256(line_map_bytes).hexdigest().upper()

    # The map is Control Pack data by reference: exactly one approved pack of the map's version, published by quarter end, lists it.
    pack = bound_control_pack(rows, LINE_MAP_SOURCE_REF, line_map_sha256, version=entry["pack_version"], before_ms=end_ms, label="line-map")
    pack_digest = _hex(pack["pack_digest"])
    # Publish commit times give what held at quarter end (a published import never changes after).
    published = {e["aggregate_id"]: e["committed_at_ms"] for e in rows["financial_events"] if e["kind"] == "POPULATION_PUBLISHED"}

    unavailable = set(NOT_HELD)
    if not (pack["effective_start_ms"] <= start_ms and end_ms <= pack["effective_end_ms"]):
        unavailable.add("gap:line-map-window-does-not-cover-quarter")
    complete = [p for p in rows["population_imports"] if p["status"] == "PUBLISHED" and p["source_complete"] == 1 and published[p["population_id"]] < end_ms]
    superseded = {row["supersedes_manifest_id"] for row in rows["population_manifests"] if row["registered_at_ms"] < end_ms}
    bindings = {row["population_id"]: row["manifest_id"] for row in rows["population_manifest_bindings"]}
    manifests = {row["manifest_id"]: row for row in rows["population_manifests"]}
    member_manifest_digest = None
    if len(complete) == 1 and bindings[complete[0]["population_id"]] not in superseded:  # the head at quarter end
        member_manifest_digest = _hex(manifests[bindings[complete[0]["population_id"]]]["member_digest"])
    else:
        unavailable.add("gap:member-manifest-not-complete-at-quarter-end")

    evidence = {row["evidence_id"]: row for row in rows["evidence"]}
    obligations = {row["obligation_id"]: row for row in rows["obligations"]}
    decided = {row["obligation_id"]: row for row in sorted(rows["evaluations"], key=lambda row: row["revision"])
               if row["evaluated_at_ms"] < end_ms}
    predicate = entry["payment_class"]
    conflicts: dict[str, list[int]] = {}  # a differing amount for a payment's origin, by payment
    for conflict in rows["financial_conflicts"]:
        conflicts.setdefault(conflict["existing_payment_id"], []).append(conflict["visible_at_ms"])
    pack_rows, split, rule_versions, adjustments = [], {}, set(), []
    for payment in sorted(rows["payments"], key=lambda row: row["payment_id"]):
        proof = evidence[payment["evidence_id"]]
        if scope["program_id"] != predicate["program_id"] or proof["source_id"] not in predicate["payment_source_ids"]:
            continue
        # Quarters go by the owner-clock received_at_ms (checker-bound, never before event_at_ms), not a caller's date.
        learned = proof["received_at_ms"]
        undone = None if payment["active"] == 1 else max(evidence[payment["reversed_by_evidence_id"]]["received_at_ms"], learned)
        if payment["event_at_ms"] < start_ms:  # an earlier quarter's payment: facts learned now are listed, never netted
            for kind, at_ms in (("PAYMENT", learned), ("REVERSAL", undone), *(("CONFLICT", seen) for seen in sorted(conflicts.get(payment["payment_id"], ())))):
                if at_ms is not None and start_ms <= at_ms < end_ms:
                    adjustments.append({"kind": kind, "payment_id": payment["payment_id"], "amount_cents": payment["amount_cents"],
                                        "paid_quarter": _quarter_of(payment["event_at_ms"])})
            continue
        if learned >= end_ms:  # paid later, or learned only after this quarter closed: a later quarter's adjustment
            continue
        if undone is not None and undone < end_ms:  # not cash at quarter end; named so a reviewer sees it
            unavailable.add(f"excluded:reversed-payment:{payment['payment_id']}")
            continue
        if any(seen < end_ms for seen in conflicts.get(payment["payment_id"], ())):
            unavailable.add(f"gap:amount-conflict-visible:{payment['payment_id']}")
        obligation = obligations[payment["obligation_id"]]
        evaluation = decided.get(payment["obligation_id"])
        if (
            evaluation is None
            or payment["evidence_id"] not in json.loads(evaluation["evidence_ids_json"])["evidence_ids"]
            or _hex(evaluation["control_pack_digest"]) != pack_digest
        ):
            evaluation = None  # counted in the total, but not bound to the map's rules: a declared gap
            unavailable.add(f"gap:row-not-decided-under-bound-pack:{payment['payment_id']}")
        else:
            rule_versions.add(evaluation["rule_version"])
        pack_rows.append({
            "payment_id": payment["payment_id"],
            "item_id": payment["item_id"],
            "obligation_id": payment["obligation_id"],
            "amount_cents": payment["amount_cents"],
            "paid_at_ms": payment["event_at_ms"],
            "service_period_id": obligation["period_id"],
            "evidence_id": payment["evidence_id"],
            "evidence_record_digest": _hex(proof["record_digest"]),
            "evaluation_id": None if evaluation is None else evaluation["evaluation_id"],
            "evaluation_receipt_digest": None if evaluation is None else _hex(evaluation["receipt_digest"]),
            "rule_version": None if evaluation is None else evaluation["rule_version"],
        })
        cents, count = split.get(obligation["period_id"], (0, 0))
        split[obligation["period_id"]] = (cents + payment["amount_cents"], count + 1)

    total = _cents(sum(row["amount_cents"] for row in pack_rows), "total-cents")
    if total < denominator:
        unavailable.add(f"gap:reported-cents-not-in-this-package:{denominator - total}")
    elif total > denominator:
        unavailable.add(f"gap:ledger-cents-above-reported:{total - denominator}")
    status = "EXCEEDS_REPORTED" if total > denominator else ("PARTIAL" if any(item.startswith("gap:") for item in unavailable) else "FULL")
    record = {
        "contract": LINE_PACK_CONTRACT,
        "documentation_only": True,
        "claims": {"proofSuiteId": None, "production_usable": False, "activation": False},
        "line": line,
        "quarter": quarter,
        "window_ms": {"start": start_ms, "end": end_ms},
        "payment_date_basis": PAYMENT_DATE_BASIS,
        "total_cents": total,
        "row_count": len(pack_rows),
        "rows": pack_rows,
        "prior_quarter_adjustments": adjustments,
        "service_period_split": [
            {"service_period_id": period, "cents": cents, "row_count": count}
            for period, (cents, count) in sorted(split.items())
        ],
        "member_manifest_digest": member_manifest_digest,
        "provenance_root": hashlib.sha256(_canonical_json({
            "contract": PROVENANCE_CONTRACT,
            "evidence_record_digests": [row["evidence_record_digest"] for row in pack_rows],
        }, maximum=MAX_LINE_PACK_BYTES)).hexdigest().upper(),
        "unavailable": sorted(unavailable),
        "coverage": {"numerator_cents": total, "denominator_cents": denominator, "status": status},
        "versions": {
            "line_map_sha256": line_map_sha256,
            "control_pack": {"pack_id": pack["pack_id"], "version": pack["version"], "digest": pack_digest},
            "rule_versions": sorted(rule_versions),
        },
        "source": source,
        "generated_at_ms": generated_at_ms,
        "supersedes": _prior(prior_pack, line, quarter, source, generated_at_ms, {e["event_sequence"]: _hex(e["head"]) for e in rows["financial_events"]}),
    }
    return signed_pack(record, custody, database, MAX_LINE_PACK_BYTES)
