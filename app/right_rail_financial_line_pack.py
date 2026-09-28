"""Read-only CMS-64.9 line pack: one line and one quarter, documented from verified Continuity bytes.

The pack is documentation only (docs/CORE_REDESIGN.md "Line pack"). It reconciles cents to the
Ledger, names each row's evidence digest and the Control Pack and rule version it was decided
under, splits service period from payment date and lists what the Ledger does not hold. It makes
no determination about any payment. It reads caller-supplied package bytes and a line-map file,
opens no store, has no tables and writes nothing. Standing claims: synthetic, non-PHI,
nonpayment, proofSuiteId=null, production_usable=false, activation=false.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import re

from app.right_rail_financial_owner_independent import (
    IndependentFinancialError,
    MAX_CENTS,
    MAX_PACKAGE_BYTES,
    MAX_ROWS,
    SCHEMA_VERSION,
    verify_continuity_package,
)


LINE_PACK_CONTRACT = "RR/LINE-PACK/CMS-64.9/v1"
LINE_MAP_CONTRACT = "RR/LINE-PACK/LINE-MAP/v1"
PROVENANCE_CONTRACT = "RR/LINE-PACK/PROVENANCE/v1"
PAYMENT_DATE_BASIS = "PAYMENT_EVENT_AT"  # CMS-64 reports by payment date; the only basis the Ledger holds
MAX_LINE_PACK_BYTES = 2 * MAX_PACKAGE_BYTES
MAX_LINE_MAP_BYTES = 64 * 1024
LINE_MAP_SOURCE_REF = "line-map:sha256:"  # the approved Control Pack lists this ref plus the map's SHA-256
NOT_HELD = (  # never in the Ledger; stated on every pack
    "not-held:clinical-and-medical-necessity-records",
    "not-held:eligibility-and-immigration-status",
    "not-held:mco-encounter-detail",
    "not-held:per-claim-service-date",
    "not-held:waiver-and-spa-coverage-determination",
)
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_LINE_RE = re.compile(r"[0-9]{1,2}[A-Z]{1,2}\Z")
_QUARTER_RE = re.compile(r"FFY([0-9]{4})Q([1-4])\Z")


class LinePackError(ValueError):
    """Raised when inputs cannot yield an exact line pack; nothing partial is returned."""


def _fail(code: str) -> None:
    raise LinePackError(f"line-pack:{code}")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("ascii")
    except (TypeError, ValueError):
        _fail("canonical-json")


def _decode(raw: object, maximum: int, label: str) -> dict:
    """Canonical JSON only: re-encoding must give the same bytes (so no duplicate keys or constants)."""
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _fail(f"{label}-byte-cap")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, ValueError, RecursionError):
        _fail(f"{label}-json")
    if type(value) is not dict or _canonical(value) != raw:
        _fail(f"{label}-canonical")
    return value


def _id(value: object, label: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        _fail(label)
    return value


def _cents(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_CENTS:
        _fail(label)
    return value


def _hex(value: object) -> str:
    return bytes(value).hex().upper()


def quarter_window(quarter: str) -> tuple[int, int]:
    """[start, end) in UTC milliseconds for a federal fiscal quarter "FFYyyyyQn" (Q1 starts 1 October)."""
    match = _QUARTER_RE.fullmatch(quarter) if type(quarter) is str else None
    if match is None:
        _fail("quarter")
    year, number = int(match.group(1)), int(match.group(2))
    if not 1971 <= year <= 9998:
        _fail("quarter")
    months = [(year - 1, 10), (year, 1), (year, 4), (year, 7), (year, 10)]
    start, end = (datetime(y, m, 1, tzinfo=timezone.utc) for y, m in months[number - 1:number + 1])
    return int(start.timestamp()) * 1000, int(end.timestamp()) * 1000


def _line_entry(line_map_bytes: bytes, line: str, state_id: str) -> dict:
    """The one map entry for ``line``; the whole file is bound by SHA-256, so any edit is a new map."""
    value = _decode(line_map_bytes, MAX_LINE_MAP_BYTES, "line-map")
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
        if type(sources) is not list or not sources or sources != sorted(set(sources)):
            _fail("line-map-sources")
        for source in sources:
            _id(source, "line-map-source")
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


def _prior(prior_pack: bytes | None, line: str, quarter: str, source: dict, generated_at_ms: int) -> str | None:
    """A superseding pack must be strictly later: same line, quarter and owner; newer time; no older state."""
    if prior_pack is None:
        return None
    prior = _decode(prior_pack, MAX_LINE_PACK_BYTES, "prior-pack")
    try:
        same = (
            prior["contract"] == LINE_PACK_CONTRACT
            and prior["line"] == line
            and prior["quarter"] == quarter
            and prior["source"]["owner_id"] == source["owner_id"]
            and prior["source"]["state_id"] == source["state_id"]
        )
        later = type(prior["generated_at_ms"]) is int and prior["generated_at_ms"] < generated_at_ms
        forward = type(prior["source"]["sequence"]) is int and prior["source"]["sequence"] <= source["sequence"]
    except (KeyError, TypeError):
        _fail("prior-pack-fields")
    if not same:
        _fail("prior-pack-identity")
    if not later or not forward:
        _fail("chronology-not-strict")
    return hashlib.sha256(prior_pack).hexdigest().upper()


def build_line_pack(
    package_bytes: bytes,
    *,
    trusted_authority: object,
    expected_scope: Mapping[str, object],
    line_map_bytes: bytes,
    line: str,
    quarter: str,
    reported_line_cents: int,
    generated_at_ms: int,
    prior_pack: bytes | None = None,
) -> bytes:
    """Canonical line-pack bytes for one CMS-64.9 ``line`` and ``quarter``.

    The package is verified independently against caller-supplied authority and scope. The same
    inputs always give the same bytes (``generated_at_ms`` is an input, never read from a clock).
    ``reported_line_cents`` is the state's reported line amount: the coverage denominator.
    """
    if type(package_bytes) is not bytes or not package_bytes or len(package_bytes) > MAX_PACKAGE_BYTES:
        _fail("package-byte-cap")
    if trusted_authority is None or not isinstance(expected_scope, Mapping):
        _fail("trust-required")
    start_ms, end_ms = quarter_window(quarter)
    denominator = _cents(reported_line_cents, "reported-line-cents", minimum=1)
    generated_at_ms = _cents(generated_at_ms, "generated-at")
    try:
        verified = verify_continuity_package(
            package_bytes,
            expected_scope=expected_scope,
            expected_authority=trusted_authority,
            expected_schema_version=SCHEMA_VERSION,
            _include_rows=True,
        )
    except IndependentFinancialError as error:
        raise LinePackError(f"line-pack:package-integrity:{error}") from None
    rows, scope = verified["_decoded_rows"], verified["scope"]
    (meta,) = rows["financial_meta"]
    entry = _line_entry(line_map_bytes, line, scope["state_id"])
    line_map_sha256 = hashlib.sha256(line_map_bytes).hexdigest().upper()

    # The map is Control Pack data by reference: exactly one approved pack of the map's version lists it.
    bound_packs = [
        pack for pack in rows["control_packs"]
        if pack["status"] == "APPROVED"
        and pack["version"] == entry["pack_version"]
        and LINE_MAP_SOURCE_REF + line_map_sha256 in json.loads(pack["source_refs_json"])["values"]
    ]
    if len(bound_packs) != 1:
        _fail("line-map-not-in-approved-control-pack")
    pack = bound_packs[0]
    pack_digest = _hex(pack["pack_digest"])

    unavailable = list(NOT_HELD)
    complete = [p for p in rows["population_imports"] if p["status"] == "PUBLISHED" and p["source_complete"] == 1]
    heads = {row["manifest_id"] for row in rows["population_manifest_heads"]}
    bindings = {row["population_id"]: row["manifest_id"] for row in rows["population_manifest_bindings"]}
    manifests = {row["manifest_id"]: row for row in rows["population_manifests"]}
    member_manifest_digest = None
    if len(complete) == 1 and bindings.get(complete[0]["population_id"]) in heads:
        member_manifest_digest = _hex(manifests[bindings[complete[0]["population_id"]]]["member_digest"])
    else:
        unavailable.append("gap:member-manifest-not-current-and-complete")

    evidence = {row["evidence_id"]: row for row in rows["evidence"]}
    obligations = {row["obligation_id"]: row for row in rows["obligations"]}
    evaluations = {row["evaluation_id"]: row for row in rows["evaluations"]}
    predicate = entry["payment_class"]
    pack_rows, split, rule_versions = [], {}, set()
    for payment in sorted(rows["payments"], key=lambda row: row["payment_id"]):
        proof = evidence[payment["evidence_id"]]
        if (
            not start_ms <= payment["event_at_ms"] < end_ms
            or scope["program_id"] != predicate["program_id"]
            or proof["source_id"] not in predicate["payment_source_ids"]
        ):
            continue
        if payment["active"] != 1:  # the Ledger's cash excludes it too; named so a reviewer sees it
            unavailable.append(f"excluded:reversed-payment:{payment['payment_id']}")
            continue
        obligation = obligations[payment["obligation_id"]]
        evaluation = evaluations.get(obligation["current_evaluation_id"])
        if (
            evaluation is None
            or payment["evidence_id"] not in json.loads(evaluation["evidence_ids_json"])["evidence_ids"]
            or _hex(evaluation["control_pack_digest"]) != pack_digest
        ):
            evaluation = None  # counted in the total, but not bound to the map's rules: a declared gap
            unavailable.append(f"gap:row-not-decided-under-bound-pack:{payment['payment_id']}")
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
    if len(pack_rows) > MAX_ROWS:
        _fail("row-cap")

    total = _cents(sum(row["amount_cents"] for row in pack_rows), "total-cents")
    status = "FULL" if total == denominator else ("PARTIAL" if total < denominator else "EXCEEDS_REPORTED")
    if total < denominator:
        unavailable.append(f"gap:reported-cents-not-in-ledger:{denominator - total}")
    elif total > denominator:
        unavailable.append(f"gap:ledger-cents-above-reported:{total - denominator}")
    source = {
        "owner_id": meta["owner_id"],
        "mode": meta["mode"],
        "sequence": verified["sequence"],
        "history_head": verified["history_head"],
        "package_digest": verified["package_digest"],
        "package_sha256": hashlib.sha256(package_bytes).hexdigest().upper(),
        **{key: scope[key] for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")},
    }
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
        "service_period_split": [
            {"service_period_id": period, "cents": cents, "row_count": count}
            for period, (cents, count) in sorted(split.items())
        ],
        "member_manifest_digest": member_manifest_digest,
        "provenance_root": hashlib.sha256(_canonical({
            "contract": PROVENANCE_CONTRACT,
            "evidence_record_digests": [row["evidence_record_digest"] for row in pack_rows],
        })).hexdigest().upper(),
        "unavailable": sorted(unavailable),
        "coverage": {"numerator_cents": total, "denominator_cents": denominator, "status": status},
        "versions": {
            "line_map_sha256": line_map_sha256,
            "control_pack": {"pack_id": pack["pack_id"], "version": pack["version"], "digest": pack_digest},
            "rule_versions": sorted(rule_versions),
        },
        "source": source,
        "generated_at_ms": generated_at_ms,
        "supersedes": _prior(prior_pack, line, quarter, source, generated_at_ms),
        "signer": None,  # no post-quantum signing path exists yet; never RSA/ECDSA
    }
    encoded = _canonical(record)
    if len(encoded) > MAX_LINE_PACK_BYTES:
        _fail("pack-byte-cap")
    return encoded
