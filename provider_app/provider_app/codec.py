"""Strict, size-bounded JSON adapter for CHECK-REQUEST/v1 and RULE-BUNDLE/v1."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Mapping

from .contracts import (
    BUNDLE_CONTRACT,
    BUNDLE_ID,
    MAX_AMOUNT_CENTS,
    MAX_JSON_BYTES,
    MAX_JSON_DEPTH,
    MAX_RULES,
    MAX_VERSION,
    REQUEST_CONTRACT,
    RESULT_CONTRACT,
    BundleProvenance,
    CheckRequest,
    CheckResult,
    ClaimFacts,
    InputError,
    ReferenceState,
    RuleBundle,
    RuleId,
    RuleSemantic,
    RuleSpec,
    RunMode,
    Scope,
    ServiceCategory,
    SourceBinding,
    SourceStatus,
    SyntheticSource,
    is_utc_timestamp,
)

_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUEST_KEYS = {"contract", "mode", "scope", "evaluatedAt", "facts"}
_FACT_KEYS = {
    "serviceDate",
    "serviceCategory",
    "supportReference",
    "chargeCents",
    "sourceBinding",
}
_SOURCE_KEYS = {"source", "version", "status", "effectiveAt", "receivedAt"}
_BUNDLE_KEYS = {
    "contract",
    "bundleId",
    "version",
    "scope",
    "provenance",
    "issuerReference",
    "publishedAt",
    "effectiveFrom",
    "effectiveUntil",
    "expiresAt",
    "withdrawnAt",
    "rules",
    "contentDigest",
}
_PROVENANCE_KEYS = {"status", "issuerReference"}
_RULE_KEYS = {
    "ruleId",
    "version",
    "semantic",
    "effectiveFrom",
    "effectiveUntil",
    "expectedCategory",
    "minimumCents",
    "maximumCents",
    "maxSourceAgeDays",
}
_HEX_DIGEST_PREFIX = "sha256:"


def _object(value: object, code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise InputError(code)
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise InputError(code)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_float(_: str) -> None:
    raise InputError("JSON_FLOAT_UNSUPPORTED")


def _reject_constant(_: str) -> None:
    raise InputError("JSON_CONSTANT_UNSUPPORTED")


def _check_json_depth(raw: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise InputError("JSON_DEPTH_EXCEEDED")
        elif byte in (0x7D, 0x5D):
            depth = max(0, depth - 1)


def _load(raw: bytes, size_code: str) -> Mapping[str, Any]:
    if type(raw) is not bytes:
        raise InputError("JSON_BYTES_REQUIRED")
    if len(raw) > MAX_JSON_BYTES:
        raise InputError(size_code)
    _check_json_depth(raw)
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except InputError:
        raise
    except (ValueError, RecursionError):
        raise InputError("JSON_INVALID") from None
    return _object(value, "JSON_OBJECT_REQUIRED")


def _string(value: object, code: str, max_length: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise InputError(code)
    return value


def _integer(value: object, code: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise InputError(code)
    return value


def _date(value: object, code: str, allow_none: bool = False) -> date | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise InputError(code)
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise InputError(code) from None
    if parsed.isoformat() != value:
        raise InputError(code)
    return parsed


def _utc(value: object, code: str, allow_none: bool = False) -> datetime | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        raise InputError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise InputError(code) from None
    return parsed.astimezone(timezone.utc)


def _enum(enum_type: type, value: object, code: str):
    if not isinstance(value, str):
        raise InputError(code)
    try:
        return enum_type(value)
    except ValueError:
        raise InputError(code) from None


def parse_request_bytes(raw: bytes) -> CheckRequest:
    return request_from_mapping(_load(raw, "REQUEST_TOO_LARGE"))


def request_from_mapping(value: object) -> CheckRequest:
    request = _object(value, "REQUEST_OBJECT_REQUIRED")
    _exact_keys(request, _REQUEST_KEYS, "REQUEST_SCHEMA")
    if request["contract"] != REQUEST_CONTRACT:
        raise InputError("REQUEST_CONTRACT_UNSUPPORTED")
    mode = _enum(RunMode, request["mode"], "REQUEST_MODE_UNSUPPORTED")
    scope = _enum(Scope, request["scope"], "REQUEST_SCOPE_UNSUPPORTED")
    evaluated_at = _utc(request["evaluatedAt"], "REQUEST_TIME_INVALID")
    facts_value = _object(request["facts"], "FACTS_OBJECT_REQUIRED")
    _exact_keys(facts_value, _FACT_KEYS, "FACTS_SCHEMA")

    service_date = _date(
        facts_value["serviceDate"], "SERVICE_DATE_INVALID", allow_none=True
    )
    category_value = facts_value["serviceCategory"]
    category = (
        None
        if category_value is None
        else _enum(
            ServiceCategory, category_value, "SERVICE_CATEGORY_UNSUPPORTED"
        )
    )
    reference_value = facts_value["supportReference"]
    reference = (
        None
        if reference_value is None
        else _enum(ReferenceState, reference_value, "SUPPORT_REFERENCE_INVALID")
    )
    amount_value = facts_value["chargeCents"]
    amount = (
        None
        if amount_value is None
        else _integer(amount_value, "CHARGE_CENTS_INVALID", 0, MAX_AMOUNT_CENTS)
    )

    source_value = facts_value["sourceBinding"]
    source = None
    if source_value is not None:
        source_object = _object(source_value, "SOURCE_BINDING_OBJECT_REQUIRED")
        _exact_keys(source_object, _SOURCE_KEYS, "SOURCE_BINDING_SCHEMA")
        source_version = _string(
            source_object["version"], "SOURCE_VERSION_INVALID", max_length=64
        )
        if source_version != "SYNTHETIC-SOURCE/v1":
            raise InputError("SOURCE_VERSION_UNSUPPORTED")
        source = SourceBinding(
            source=_enum(
                SyntheticSource, source_object["source"], "SOURCE_UNSUPPORTED"
            ),
            version=source_version,
            status=_enum(
                SourceStatus, source_object["status"], "SOURCE_STATUS_UNSUPPORTED"
            ),
            effective_at=_date(
                source_object["effectiveAt"],
                "SOURCE_EFFECTIVE_TIME_INVALID",
                allow_none=True,
            ),
            received_at=_utc(
                source_object["receivedAt"],
                "SOURCE_RECEIVED_TIME_INVALID",
                allow_none=True,
            ),
        )

    if evaluated_at is None:
        raise InputError("REQUEST_TIME_INVALID")
    return CheckRequest(
        mode=mode,
        scope=scope,
        evaluated_at=evaluated_at,
        facts=ClaimFacts(
            service_date=service_date,
            service_category=category,
            support_reference=reference,
            charge_cents=amount,
            source_binding=source,
        ),
    )


def bundle_content_digest(value: Mapping[str, Any]) -> str:
    """Hash rule-bundle content only; claim inputs never enter this function."""
    content = {key: item for key, item in value.items() if key != "contentDigest"}
    canonical = json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return _HEX_DIGEST_PREFIX + hashlib.sha256(canonical).hexdigest()


def parse_bundle_bytes(raw: bytes) -> RuleBundle:
    return bundle_from_mapping(_load(raw, "BUNDLE_TOO_LARGE"))


def bundle_from_mapping(value: object) -> RuleBundle:
    bundle = _object(value, "BUNDLE_OBJECT_REQUIRED")
    _exact_keys(bundle, _BUNDLE_KEYS, "BUNDLE_SCHEMA")
    if bundle["contract"] != BUNDLE_CONTRACT:
        raise InputError("BUNDLE_CONTRACT_UNSUPPORTED")
    if bundle["bundleId"] != BUNDLE_ID:
        raise InputError("BUNDLE_ID_UNSUPPORTED")
    version = _integer(bundle["version"], "BUNDLE_VERSION_INVALID", 1, MAX_VERSION)
    scope = _enum(Scope, bundle["scope"], "BUNDLE_SCOPE_UNSUPPORTED")

    provenance_value = _object(bundle["provenance"], "BUNDLE_PROVENANCE_REQUIRED")
    _exact_keys(provenance_value, _PROVENANCE_KEYS, "BUNDLE_PROVENANCE_SCHEMA")
    provenance = _enum(
        BundleProvenance,
        provenance_value["status"],
        "BUNDLE_PROVENANCE_UNSUPPORTED",
    )
    issuer_reference = _string(
        bundle["issuerReference"], "BUNDLE_ISSUER_REFERENCE_INVALID", 64
    )
    provenance_issuer = _string(
        provenance_value["issuerReference"],
        "BUNDLE_PROVENANCE_ISSUER_INVALID",
        64,
    )
    if (
        issuer_reference != "LOCAL-SYNTHETIC-FIXTURE"
        or provenance_issuer != issuer_reference
    ):
        raise InputError("BUNDLE_ISSUER_UNSUPPORTED")

    published_at = _utc(bundle["publishedAt"], "BUNDLE_PUBLICATION_TIME_INVALID")
    effective_from = _date(bundle["effectiveFrom"], "BUNDLE_EFFECTIVE_START_INVALID")
    effective_until = _date(bundle["effectiveUntil"], "BUNDLE_EFFECTIVE_END_INVALID")
    expires_at = _utc(bundle["expiresAt"], "BUNDLE_EXPIRY_INVALID")
    withdrawn_at = _utc(
        bundle["withdrawnAt"], "BUNDLE_WITHDRAWAL_INVALID", allow_none=True
    )
    if (
        published_at is None
        or effective_from is None
        or effective_until is None
        or expires_at is None
        or effective_from >= effective_until
    ):
        raise InputError("BUNDLE_INTERVAL_INVALID")
    if expires_at <= published_at:
        raise InputError("BUNDLE_LIFETIME_INVALID")
    if withdrawn_at is not None and withdrawn_at <= published_at:
        raise InputError("BUNDLE_WITHDRAWAL_INVALID")

    rules_value = bundle["rules"]
    if not isinstance(rules_value, list) or not 1 <= len(rules_value) <= MAX_RULES:
        raise InputError("BUNDLE_RULE_COUNT_INVALID")
    rules: list[RuleSpec] = []
    seen: set[RuleId] = set()
    for raw_rule in rules_value:
        rule_object = _object(raw_rule, "BUNDLE_RULE_OBJECT_REQUIRED")
        _exact_keys(rule_object, _RULE_KEYS, "BUNDLE_RULE_SCHEMA")
        rule_id = _enum(RuleId, rule_object["ruleId"], "BUNDLE_RULE_UNSUPPORTED")
        if rule_id in seen:
            raise InputError("BUNDLE_RULE_DUPLICATE")
        seen.add(rule_id)
        rule_version = _integer(
            rule_object["version"], "BUNDLE_RULE_VERSION_INVALID", 1, MAX_VERSION
        )
        semantic = _enum(
            RuleSemantic, rule_object["semantic"], "BUNDLE_RULE_SEMANTIC_UNSUPPORTED"
        )
        rule_start = _date(
            rule_object["effectiveFrom"], "BUNDLE_RULE_START_INVALID"
        )
        rule_end = _date(rule_object["effectiveUntil"], "BUNDLE_RULE_END_INVALID")
        if rule_start is None or rule_end is None or rule_start >= rule_end:
            raise InputError("BUNDLE_RULE_INTERVAL_INVALID")
        if rule_start < effective_from or rule_end > effective_until:
            raise InputError("BUNDLE_RULE_OUTSIDE_BUNDLE_INTERVAL")

        expected_value = rule_object["expectedCategory"]
        expected_category = (
            None
            if expected_value is None
            else _enum(
                ServiceCategory,
                expected_value,
                "BUNDLE_RULE_CATEGORY_INVALID",
            )
        )
        minimum_value = rule_object["minimumCents"]
        maximum_value = rule_object["maximumCents"]
        max_age_value = rule_object["maxSourceAgeDays"]
        minimum_cents = (
            None
            if minimum_value is None
            else _integer(
                minimum_value, "BUNDLE_RULE_MINIMUM_INVALID", 0, MAX_AMOUNT_CENTS
            )
        )
        maximum_cents = (
            None
            if maximum_value is None
            else _integer(
                maximum_value, "BUNDLE_RULE_MAXIMUM_INVALID", 0, MAX_AMOUNT_CENTS
            )
        )
        max_source_age_days = (
            None
            if max_age_value is None
            else _integer(max_age_value, "BUNDLE_RULE_MAX_AGE_INVALID", 0, 365)
        )
        _validate_rule_parameters(
            semantic,
            expected_category,
            minimum_cents,
            maximum_cents,
            max_source_age_days,
        )
        rules.append(
            RuleSpec(
                rule_id=rule_id,
                version=rule_version,
                semantic=semantic,
                effective_from=rule_start,
                effective_until=rule_end,
                expected_category=expected_category,
                minimum_cents=minimum_cents,
                maximum_cents=maximum_cents,
                max_source_age_days=max_source_age_days,
            )
        )

    declared_digest = _string(
        bundle["contentDigest"], "BUNDLE_DIGEST_INVALID", max_length=71
    )
    if not _DIGEST.fullmatch(declared_digest):
        raise InputError("BUNDLE_DIGEST_INVALID")
    if declared_digest != bundle_content_digest(bundle):
        raise InputError("BUNDLE_DIGEST_MISMATCH")

    return RuleBundle(
        bundle_id=BUNDLE_ID,
        version=version,
        scope=scope,
        provenance=provenance,
        issuer_reference=issuer_reference,
        published_at=published_at,
        effective_from=effective_from,
        effective_until=effective_until,
        expires_at=expires_at,
        withdrawn_at=withdrawn_at,
        rules=tuple(rules),
        content_digest=declared_digest,
    )


def _validate_rule_parameters(
    semantic: RuleSemantic,
    expected_category: ServiceCategory | None,
    minimum_cents: int | None,
    maximum_cents: int | None,
    max_source_age_days: int | None,
) -> None:
    params = (expected_category, minimum_cents, maximum_cents, max_source_age_days)
    if semantic is RuleSemantic.SERVICE_CATEGORY_EQUALS:
        valid = expected_category is not None and params == (
            expected_category,
            None,
            None,
            None,
        )
    elif semantic is RuleSemantic.CHARGE_CENTS_BETWEEN:
        valid = (
            expected_category is None
            and minimum_cents is not None
            and maximum_cents is not None
            and minimum_cents <= maximum_cents
            and max_source_age_days is None
        )
    elif semantic is RuleSemantic.SOURCE_COMPLETE_AND_FRESH:
        valid = (
            expected_category is None
            and minimum_cents is None
            and maximum_cents is None
            and max_source_age_days is not None
        )
    else:
        valid = all(parameter is None for parameter in params)
    if not valid:
        raise InputError("BUNDLE_RULE_PARAMETERS_INVALID")


def bundle_to_mapping(bundle: RuleBundle) -> dict[str, Any]:
    value: dict[str, Any] = {
        "contract": BUNDLE_CONTRACT,
        "bundleId": bundle.bundle_id,
        "version": bundle.version,
        "scope": bundle.scope.value,
        "provenance": {
            "status": bundle.provenance.value,
            "issuerReference": bundle.issuer_reference,
        },
        "issuerReference": bundle.issuer_reference,
        "publishedAt": _format_utc(bundle.published_at),
        "effectiveFrom": bundle.effective_from.isoformat(),
        "effectiveUntil": bundle.effective_until.isoformat(),
        "expiresAt": _format_utc(bundle.expires_at),
        "withdrawnAt": (
            None if bundle.withdrawn_at is None else _format_utc(bundle.withdrawn_at)
        ),
        "rules": [
            {
                "ruleId": rule.rule_id.value,
                "version": rule.version,
                "semantic": rule.semantic.value,
                "effectiveFrom": rule.effective_from.isoformat(),
                "effectiveUntil": rule.effective_until.isoformat(),
                "expectedCategory": (
                    None
                    if rule.expected_category is None
                    else rule.expected_category.value
                ),
                "minimumCents": rule.minimum_cents,
                "maximumCents": rule.maximum_cents,
                "maxSourceAgeDays": rule.max_source_age_days,
            }
            for rule in bundle.rules
        ],
    }
    value["contentDigest"] = bundle_content_digest(value)
    return value


def result_to_mapping(result: CheckResult) -> dict[str, Any]:
    return {
        "contract": RESULT_CONTRACT,
        "outcome": result.outcome.value,
        "runMode": result.mode.value,
        "scope": result.scope.value,
        "evaluatedAt": _format_utc(result.evaluated_at),
        "bundle": {
            "bundleId": result.bundle.bundle_id,
            "version": result.bundle.version,
            "scope": result.bundle.scope.value,
            "provenance": result.bundle.provenance.value,
            "issuerReference": result.bundle.issuer_reference,
            "contentDigest": result.bundle.content_digest,
            "effectiveFrom": result.bundle.effective_from.isoformat(),
            "effectiveUntil": result.bundle.effective_until.isoformat(),
            "expiresAt": _format_utc(result.bundle.expires_at),
            "withdrawnAt": (
                None
                if result.bundle.withdrawn_at is None
                else _format_utc(result.bundle.withdrawn_at)
            ),
        },
        "sourceBinding": (
            None
            if result.source_binding is None
            else {
                "source": result.source_binding.source.value,
                "version": result.source_binding.version,
                "status": result.source_binding.status.value,
                "effectiveAt": (
                    None
                    if result.source_binding.effective_at is None
                    else result.source_binding.effective_at.isoformat()
                ),
                "receivedAt": (
                    None
                    if result.source_binding.received_at is None
                    else _format_utc(result.source_binding.received_at)
                ),
            }
        ),
        "bundleIssues": list(result.bundle_issues),
        "rules": [
            {
                "ruleId": item.rule_id.value,
                "citation": item.citation,
                "outcome": item.outcome.value,
                "missingFacts": [fact.value for fact in item.missing_facts],
                "reasonCodes": list(item.reason_codes),
                "factsUsed": [fact.value for fact in item.facts_used],
            }
            for item in result.rules
        ],
        "missingFacts": [fact.value for fact in result.missing_facts],
        "limitation": result.limitation,
    }


def _format_utc(value: datetime) -> str:
    if not is_utc_timestamp(value):
        raise InputError("UTC_TIME_REQUIRED")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
