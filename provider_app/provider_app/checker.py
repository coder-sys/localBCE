"""Independent reconstruction checker for canonical synthetic preflight inputs.

This module deliberately has no imports from provider_app. It owns a separate
small interpretation of the published fixture contract and returns only
stable paths/codes, never input values.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from typing import Any

_MAX_BYTES = 16_384
_MAX_DEPTH = 8
_LIMITATION = (
    "Synthetic pre-submission result only; it is not claim acceptance, "
    "coverage, authorization, clinical judgment, or payment."
)
_REQUEST = "RR/PROVIDER-APP/CHECK-REQUEST/v1"
_BUNDLE = "RR/PROVIDER-APP/RULE-BUNDLE/v1"
_RESULT = "RR/PROVIDER-APP/CHECK-RESULT/v1"
_BUNDLE_ID = "RR-SYNTHETIC-PREFLIGHT"
_SCOPE_A = "RR-SYNTHETIC-PROVIDER-A"
_SCOPE_B = "RR-SYNTHETIC-PROVIDER-B"
_RULES = (
    ("SYN-PRE-001", "SERVICE_DATE_IN_EFFECTIVE_WINDOW"),
    ("SYN-PRE-002", "SERVICE_CATEGORY_EQUALS"),
    ("SYN-PRE-003", "SUPPORT_REFERENCE_PRESENT"),
    ("SYN-PRE-004", "CHARGE_CENTS_BETWEEN"),
    ("SYN-PRE-005", "SOURCE_COMPLETE_AND_FRESH"),
)
_FACT_ORDER = tuple(
    "service_date service_category support_reference charge_cents source_binding source_effective_at "
    "source_received_at".split()
)
_REQUEST_KEYS = {"contract", "mode", "scope", "evaluatedAt", "facts"}
_FACT_KEYS = {
    "serviceDate", "serviceCategory", "supportReference", "chargeCents", "sourceBinding"
}
_SOURCE_KEYS = {"source", "version", "status", "effectiveAt", "receivedAt"}
_BUNDLE_KEYS = {
    "contract", "bundleId", "version", "scope", "provenance", "issuerReference",
    "publishedAt", "effectiveFrom", "effectiveUntil", "expiresAt", "withdrawnAt",
    "rules", "contentDigest"
}
_RULE_KEYS = {
    "ruleId", "version", "semantic", "effectiveFrom", "effectiveUntil",
    "expectedCategory", "minimumCents", "maximumCents", "maxSourceAgeDays"
}
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class _Invalid(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _Invalid("duplicate")
        out[key] = value
    return out


def _no_float(_: str) -> None:
    raise _Invalid("float")


def _no_constant(_: str) -> None:
    raise _Invalid("constant")


def _depth(raw: bytes) -> None:
    level = 0
    quoted = False
    escape = False
    for byte in raw:
        if quoted:
            if escape:
                escape = False
            elif byte == 0x5C:
                escape = True
            elif byte == 0x22:
                quoted = False
        elif byte == 0x22:
            quoted = True
        elif byte in (0x7B, 0x5B):
            level += 1
            if level > _MAX_DEPTH:
                raise _Invalid("depth")
        elif byte in (0x7D, 0x5D):
            level = max(0, level - 1)


def _load(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > _MAX_BYTES:
        raise _Invalid("size")
    _depth(raw)
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
            parse_float=_no_float, parse_constant=_no_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _Invalid("json") from exc
    if not isinstance(value, dict):
        raise _Invalid("object")
    return value


def _keys(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _is_date(value: Any) -> bool:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.utcoffset() == timezone.utc.utcoffset(parsed) else None


def _valid_request(req: dict[str, Any]) -> bool:
    if not _keys(req, _REQUEST_KEYS) or req["contract"] != _REQUEST:
        return False
    if req["mode"] not in ("SYNTHETIC_TEST", "REAL_USE") or req["scope"] not in (_SCOPE_A, _SCOPE_B):
        return False
    if _time(req["evaluatedAt"]) is None or not _keys(req["facts"], _FACT_KEYS):
        return False
    facts = req["facts"]
    if facts["serviceDate"] is not None and not _is_date(facts["serviceDate"]):
        return False
    if facts["serviceCategory"] not in (None, "SYNTH-CATEGORY-A", "SYNTH-CATEGORY-B"):
        return False
    if facts["supportReference"] not in (None, "PRESENT", "ABSENT"):
        return False
    cents = facts["chargeCents"]
    if cents is not None and (type(cents) is not int or not 0 <= cents <= 100_000_000):
        return False
    source = facts["sourceBinding"]
    if source is None:
        return True
    if not _keys(source, _SOURCE_KEYS):
        return False
    if source["source"] not in ("SYNTHETIC-SOURCE-ALPHA", "SYNTHETIC-SOURCE-BETA"):
        return False
    if source["version"] != "SYNTHETIC-SOURCE/v1":
        return False
    if source["status"] not in ("COMPLETE_FIXTURE", "PARTIAL", "STALE", "CONFLICT", "REPLAYED", "UNKNOWN"):
        return False
    if source["effectiveAt"] is not None and not _is_date(source["effectiveAt"]):
        return False
    return source["receivedAt"] is None or _time(source["receivedAt"]) is not None


def _valid_bundle(bundle: dict[str, Any]) -> bool:
    if not _keys(bundle, _BUNDLE_KEYS) or bundle["contract"] != _BUNDLE:
        return False
    if bundle["bundleId"] != _BUNDLE_ID or type(bundle["version"]) is not int or not 1 <= bundle["version"] <= 65_535:
        return False
    if bundle["scope"] not in (_SCOPE_A, _SCOPE_B):
        return False
    provenance = bundle["provenance"]
    if not _keys(provenance, {"status", "issuerReference"}):
        return False
    if provenance["status"] != "UNAPPROVED_SYNTHETIC_FIXTURE":
        return False
    if bundle["issuerReference"] != "LOCAL-SYNTHETIC-FIXTURE" or provenance["issuerReference"] != bundle["issuerReference"]:
        return False
    published = _time(bundle["publishedAt"])
    expires = _time(bundle["expiresAt"])
    start, end = bundle["effectiveFrom"], bundle["effectiveUntil"]
    if published is None or expires is None or not _is_date(start) or not _is_date(end) or start >= end or expires <= published:
        return False
    withdrawn = bundle["withdrawnAt"]
    if withdrawn is not None and (_time(withdrawn) is None or _time(withdrawn) <= published):
        return False
    rules = bundle["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= 8:
        return False
    known_ids = {item[0] for item in _RULES}
    known_semantics = {item[1] for item in _RULES}
    seen_rule_ids: set[str] = set()
    for rule in rules:
        if not _keys(rule, _RULE_KEYS) or rule["ruleId"] not in known_ids or rule["semantic"] not in known_semantics:
            return False
        if rule["ruleId"] in seen_rule_ids:
            return False
        seen_rule_ids.add(rule["ruleId"])
        if type(rule["version"]) is not int or not 1 <= rule["version"] <= 65_535:
            return False
        if not _is_date(rule["effectiveFrom"]) or not _is_date(rule["effectiveUntil"]):
            return False
        if rule["effectiveFrom"] >= rule["effectiveUntil"] or rule["effectiveFrom"] < start or rule["effectiveUntil"] > end:
            return False
        if rule["expectedCategory"] not in (None, "SYNTH-CATEGORY-A", "SYNTH-CATEGORY-B"):
            return False
        for key in ("minimumCents", "maximumCents"):
            value = rule[key]
            if value is not None and (type(value) is not int or not 0 <= value <= 100_000_000):
                return False
        age = rule["maxSourceAgeDays"]
        if age is not None and (type(age) is not int or not 0 <= age <= 365):
            return False
        semantic = rule["semantic"]
        cat, low, high, max_age = (rule[k] for k in ("expectedCategory", "minimumCents", "maximumCents", "maxSourceAgeDays"))
        if semantic == "SERVICE_CATEGORY_EQUALS":
            ok = cat is not None and low is None and high is None and max_age is None
        elif semantic == "CHARGE_CENTS_BETWEEN":
            ok = cat is None and low is not None and high is not None and low <= high and max_age is None
        elif semantic == "SOURCE_COMPLETE_AND_FRESH":
            ok = cat is None and low is None and high is None and max_age is not None
        else:
            ok = cat is None and low is None and high is None and max_age is None
        if not ok:
            return False
    declared = bundle["contentDigest"]
    if not isinstance(declared, str) or not _DIGEST.fullmatch(declared):
        return False
    content = {key: value for key, value in bundle.items() if key != "contentDigest"}
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return declared == "sha256:" + hashlib.sha256(canonical).hexdigest()


def _supported_rules(bundle: dict[str, Any]) -> bool:
    rules = bundle["rules"]
    if len(rules) != len(_RULES) or len({rule["ruleId"] for rule in rules}) != len(_RULES):
        return False
    expected_params = {
        "SYN-PRE-001": ("SERVICE_DATE_IN_EFFECTIVE_WINDOW", None, None, None, None),
        "SYN-PRE-002": ("SERVICE_CATEGORY_EQUALS", "SYNTH-CATEGORY-A", None, None, None),
        "SYN-PRE-003": ("SUPPORT_REFERENCE_PRESENT", None, None, None, None),
        "SYN-PRE-004": ("CHARGE_CENTS_BETWEEN", None, 100, 100_000, None),
        "SYN-PRE-005": ("SOURCE_COMPLETE_AND_FRESH", None, None, None, 30),
    }
    by_id = {rule["ruleId"]: rule for rule in rules}
    for rule_id, semantic in _RULES:
        rule = by_id.get(rule_id)
        if rule is None:
            return False
        expected = expected_params[rule_id]
        actual = (
            rule["semantic"], rule["expectedCategory"], rule["minimumCents"],
            rule["maximumCents"], rule["maxSourceAgeDays"],
        )
        if rule["version"] != 1 or actual != expected:
            return False
        if rule["effectiveFrom"] != bundle["effectiveFrom"] or rule["effectiveUntil"] != bundle["effectiveUntil"]:
            return False
    return True


def _bundle_issues(req: dict[str, Any], bundle: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    evaluated = _time(req["evaluatedAt"])
    published = _time(bundle["publishedAt"])
    expires = _time(bundle["expiresAt"])
    withdrawn = None if bundle["withdrawnAt"] is None else _time(bundle["withdrawnAt"])
    if req["mode"] == "REAL_USE":
        issues.append("REAL_USE_REQUIRES_APPROVED_ISSUER_BUNDLE")
    if bundle["bundleId"] != _BUNDLE_ID:
        issues.append("BUNDLE_ID_UNSUPPORTED")
    if bundle["version"] != 1:
        issues.append("BUNDLE_SEMANTIC_VERSION_UNSUPPORTED")
    if bundle["provenance"]["status"] != "UNAPPROVED_SYNTHETIC_FIXTURE":
        issues.append("BUNDLE_PROVENANCE_UNSUPPORTED")
    if bundle["issuerReference"] != "LOCAL-SYNTHETIC-FIXTURE":
        issues.append("BUNDLE_ISSUER_UNSUPPORTED")
    if bundle["scope"] != _SCOPE_A or req["scope"] != bundle["scope"]:
        issues.append("BUNDLE_SCOPE_MISMATCH")
    if bundle["effectiveFrom"] >= bundle["effectiveUntil"]:
        issues.append("BUNDLE_EFFECTIVE_INTERVAL_INVALID")
    if published > evaluated:
        issues.append("BUNDLE_NOT_YET_PUBLISHED")
    if evaluated >= expires:
        issues.append("BUNDLE_EXPIRED")
    if withdrawn is not None and evaluated >= withdrawn:
        issues.append("BUNDLE_WITHDRAWN")
    if not _supported_rules(bundle):
        issues.append("BUNDLE_RULESET_UNSUPPORTED")
    return issues


def _rule_result(rule_id: str, version: int, outcome: str, missing: tuple[str, ...] = (), reasons: tuple[str, ...] = (), used: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "citation": f"{_BUNDLE_ID}/v1#{rule_id}/v{version}",
        "outcome": outcome,
        "missingFacts": list(missing),
        "reasonCodes": list(reasons),
        "factsUsed": list(used),
    }


def _expected(req: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    issues = _bundle_issues(req, bundle)
    rule_map = {rule["ruleId"]: rule for rule in bundle["rules"]}
    results: list[dict[str, Any]] = []
    for rule_id, semantic in _RULES:
        if issues:
            results.append(_rule_result(rule_id, 1, "HUMAN_CHECK", reasons=("BUNDLE_BLOCKED",)))
            continue
        rule = rule_map[rule_id]
        facts = req["facts"]
        if semantic == "SERVICE_DATE_IN_EFFECTIVE_WINDOW":
            value = facts["serviceDate"]
            if value is None:
                result = _rule_result(rule_id, 1, "MISSING", ("service_date",), ("REQUIRED_FACT_MISSING",))
            elif not rule["effectiveFrom"] <= value < rule["effectiveUntil"]:
                result = _rule_result(rule_id, 1, "HUMAN_CHECK", reasons=("SERVICE_DATE_OUTSIDE_RULE_INTERVAL",), used=("service_date",))
            else:
                result = _rule_result(rule_id, 1, "PASS", used=("service_date",))
        elif semantic == "SERVICE_CATEGORY_EQUALS":
            value = facts["serviceCategory"]
            if value is None:
                result = _rule_result(rule_id, 1, "MISSING", ("service_category",), ("REQUIRED_FACT_MISSING",))
            elif value != rule["expectedCategory"]:
                result = _rule_result(rule_id, 1, "HUMAN_CHECK", reasons=("SERVICE_CATEGORY_REQUIRES_REVIEW",), used=("service_category",))
            else:
                result = _rule_result(rule_id, 1, "PASS", used=("service_category",))
        elif semantic == "SUPPORT_REFERENCE_PRESENT":
            value = facts["supportReference"]
            if value is None:
                result = _rule_result(rule_id, 1, "MISSING", ("support_reference",), ("REQUIRED_FACT_MISSING",))
            elif value == "ABSENT":
                result = _rule_result(rule_id, 1, "MISSING", ("support_reference",), ("SUPPORT_REFERENCE_MISSING",), ("support_reference",))
            else:
                result = _rule_result(rule_id, 1, "PASS", used=("support_reference",))
        elif semantic == "CHARGE_CENTS_BETWEEN":
            value = facts["chargeCents"]
            if value is None:
                result = _rule_result(rule_id, 1, "MISSING", ("charge_cents",), ("REQUIRED_FACT_MISSING",))
            elif value < rule["minimumCents"] or value > rule["maximumCents"]:
                result = _rule_result(rule_id, 1, "HUMAN_CHECK", reasons=("CHARGE_OUTSIDE_SYNTHETIC_RANGE",), used=("charge_cents",))
            else:
                result = _rule_result(rule_id, 1, "PASS", used=("charge_cents",))
        else:
            source = facts["sourceBinding"]
            if source is None:
                result = _rule_result(rule_id, 1, "MISSING", ("source_binding",), ("REQUIRED_FACT_MISSING",))
            else:
                missing: list[str] = []
                reasons: list[str] = []
                if source["effectiveAt"] is None:
                    missing.append("source_effective_at")
                    reasons.append("SOURCE_EFFECTIVE_TIME_MISSING")
                if source["receivedAt"] is None:
                    missing.append("source_received_at")
                    reasons.append("SOURCE_RECEIVED_TIME_MISSING")
                if missing:
                    result = _rule_result(rule_id, 1, "MISSING", tuple(missing), tuple(reasons), ("source_binding",))
                elif source["status"] != "COMPLETE_FIXTURE":
                    result = _rule_result(rule_id, 1, "HUMAN_CHECK", reasons=("SOURCE_STATUS_REQUIRES_REVIEW",), used=("source_binding",))
                else:
                    effective_day = date.fromisoformat(source["effectiveAt"])
                    received = _time(source["receivedAt"])
                    evaluated = _time(req["evaluatedAt"])
                    if received.date() < effective_day:
                        result = _rule_result(rule_id, 1, "HUMAN_CHECK", reasons=("SOURCE_RECEIVED_BEFORE_EFFECTIVE_DATE",), used=("source_binding", "source_effective_at", "source_received_at"))
                    elif received > evaluated:
                        result = _rule_result(rule_id, 1, "HUMAN_CHECK", reasons=("SOURCE_RECEIVED_AFTER_EVALUATION_TIME",), used=("source_binding", "source_received_at"))
                    elif (evaluated.date() - received.date()).days > rule["maxSourceAgeDays"]:
                        result = _rule_result(rule_id, 1, "HUMAN_CHECK", reasons=("SOURCE_STALE_FOR_SYNTHETIC_WINDOW",), used=("source_binding", "source_received_at"))
                    else:
                        result = _rule_result(rule_id, 1, "PASS", used=("source_binding", "source_effective_at", "source_received_at"))
        results.append(result)
    if bundle["version"] != 1:
        for item in results:
            item["citation"] = f"{bundle['bundleId']}/v{bundle['version']}#{item['ruleId']}/v1"
    if issues or any(item["outcome"] == "HUMAN_CHECK" for item in results):
        outcome = "HUMAN_CHECK"
    elif any(item["outcome"] == "MISSING" for item in results):
        outcome = "MISSING"
    else:
        outcome = "PASS"
    missing_seen = {fact for item in results for fact in item["missingFacts"]}
    missing = [fact for fact in _FACT_ORDER if fact in missing_seen]
    source = req["facts"]["sourceBinding"]
    binding = {
        "bundleId": bundle["bundleId"], "version": bundle["version"],
        "scope": bundle["scope"], "provenance": bundle["provenance"]["status"],
        "issuerReference": bundle["issuerReference"], "contentDigest": bundle["contentDigest"],
        "effectiveFrom": bundle["effectiveFrom"], "effectiveUntil": bundle["effectiveUntil"],
        "expiresAt": bundle["expiresAt"], "withdrawnAt": bundle["withdrawnAt"],
    }
    return {
        "contract": _RESULT, "outcome": outcome, "runMode": req["mode"],
        "scope": req["scope"], "evaluatedAt": req["evaluatedAt"],
        "bundle": binding, "sourceBinding": source, "bundleIssues": issues,
        "rules": results, "missingFacts": missing, "limitation": _LIMITATION,
    }


def _diff(expected: Any, actual: Any, path: str, output: list[str]) -> None:
    if len(output) >= 32:
        return
    if isinstance(expected, dict) and isinstance(actual, dict):
        if set(expected) != set(actual):
            output.append("RESULT_KEYS:" + (path or "/"))
        for key in sorted(set(expected) & set(actual)):
            _diff(expected[key], actual[key], path + "/" + key, output)
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            output.append("RESULT_LENGTH:" + (path or "/"))
        for index, (left, right) in enumerate(zip(expected, actual)):
            _diff(left, right, path + "/" + str(index), output)
    elif type(expected) is not type(actual) or expected != actual:
        output.append("RESULT_VALUE:" + (path or "/"))


def check_result(request_bytes: bytes, bundle_bytes: bytes, result_bytes: bytes) -> tuple[str, ...]:
    """Return an empty tuple on exact reconstruction, otherwise stable codes."""
    try:
        request = _load(request_bytes)
        bundle = _load(bundle_bytes)
        result = _load(result_bytes)
        if not _valid_request(request) or not _valid_bundle(bundle):
            return ("CHECK_INPUT_INVALID",)
        expected = _expected(request, bundle)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return ("CHECK_INPUT_INVALID",)
    differences: list[str] = []
    _diff(expected, result, "", differences)
    return tuple(differences)
