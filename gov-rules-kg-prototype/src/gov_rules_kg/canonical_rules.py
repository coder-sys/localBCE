from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


RULE_SCHEMA_VERSION = "localbce-government-rule-v1"
BUNDLE_SCHEMA_VERSION = "localbce-government-rule-bundle-v1"
QUEUE_SCHEMA_VERSION = "localbce-rule-promotion-queue-v1"

CONDITION_OPERATORS = {
    "eq",
    "neq",
    "lt",
    "lte",
    "gt",
    "gte",
    "in",
    "not_in",
    "contains",
    "before",
    "on_or_before",
    "after",
    "on_or_after",
}
BOOLEAN_OPERATORS = {"all", "any", "not"}
FACT_TYPES = {"boolean", "integer", "decimal", "string", "date", "list"}
RULE_TYPES = {
    "administration_rule",
    "appeal_rule",
    "deadline_rule",
    "documentation_rule",
    "eligibility_rule",
    "enforcement_rule",
    "enrollment_rule",
    "exception_rule",
    "payment_rule",
    "provider_rule",
    "reporting_rule",
    "verification_rule",
}
OUTCOME_KINDS = {
    "administrative",
    "appeal",
    "deadline",
    "decision",
    "enforcement",
    "obligation",
    "payment",
}
JURISDICTION_LEVELS = {"federal", "state", "local", "tribal", "territory"}
REVIEW_STATUSES = {"unreviewed", "machine_reviewed", "human_reviewed", "approved", "rejected"}
LEGAL_STATUSES = {"not_verified", "pending", "verified", "rejected"}
RUNTIME_STATUSES = {"blocked", "shadow_only", "eligible", "active"}
COARSE_OPERATORS = {
    "administration",
    "appeal_right",
    "deadline",
    "determine_eligibility",
    "enforcement",
    "payment",
    "prohibit_or_deny",
    "reporting",
    "require",
    "verify_or_determine",
}

BLOCKER_CODES = {
    "ambiguous_free_text_condition",
    "conflicting_duplicate",
    "exact_duplicate",
    "human_review_not_approved",
    "invalid_effective_date",
    "invalid_source_url",
    "legal_not_verified",
    "missing_effective_date",
    "missing_lineage",
    "missing_provenance",
    "missing_source_artifact",
    "missing_typed_fact",
    "semantic_duplicate",
    "source_hash_mismatch",
    "unsupported_operator",
}

INPUT_FACT_TYPES = {
    "age": "integer",
    "application_status": "string",
    "benefit_or_package_status": "string",
    "citizenship_or_immigration_status": "string",
    "compliance_status": "string",
    "coverage_status": "string",
    "deadline": "date",
    "disability_status": "string",
    "documentation": "list",
    "education_or_training": "string",
    "employment_status": "string",
    "filing_status": "string",
    "grant_or_award_status": "string",
    "household_status": "string",
    "income": "decimal",
    "jurisdiction_or_authority": "string",
    "lawful_status": "string",
    "payment": "decimal",
    "property_status": "string",
    "provider_status": "string",
    "residency": "string",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _is_sha256(value: Any) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", _text(value)))


def _parse_iso_date(value: Any, field: str, errors: list[str]) -> date | None:
    text = _text(value)
    if not text:
        errors.append(f"{field} is required")
        return None
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DD")
        return None
    if parsed.isoformat() != text:
        errors.append(f"{field} must use canonical YYYY-MM-DD")
        return None
    return parsed


def _validate_typed_value(value: Any, path: str, errors: list[str]) -> str | None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be a typed value object")
        return None
    value_type = _text(value.get("type"))
    if value_type not in FACT_TYPES:
        errors.append(f"{path}.type is unsupported")
        return None
    raw = value.get("value")
    if value_type == "boolean" and not isinstance(raw, bool):
        errors.append(f"{path}.value must be boolean")
    elif value_type == "integer" and (not isinstance(raw, int) or isinstance(raw, bool)):
        errors.append(f"{path}.value must be an integer")
    elif value_type == "decimal" and (
        not isinstance(raw, str) or not re.fullmatch(r"-?(?:0|[1-9]\d*)(?:\.\d+)?", raw)
    ):
        errors.append(f"{path}.value must be a canonical decimal string")
    elif value_type == "string" and (not isinstance(raw, str) or not raw.strip()):
        errors.append(f"{path}.value must be a non-empty string")
    elif value_type == "date":
        _parse_iso_date(raw, f"{path}.value", errors)
    elif value_type == "list":
        if not isinstance(raw, list) or not raw:
            errors.append(f"{path}.value must be a non-empty typed-value list")
        else:
            member_types = {
                member_type
                for index, item in enumerate(raw)
                if (member_type := _validate_typed_value(item, f"{path}.value[{index}]", errors))
            }
            if "list" in member_types:
                errors.append(f"{path}.value cannot contain nested lists")
            if len(member_types) > 1:
                errors.append(f"{path}.value members must use one type")
    return value_type


def _validate_condition(condition: Any, path: str, errors: list[str]) -> None:
    if not isinstance(condition, dict):
        errors.append(f"{path} must be an object")
        return
    allowed_keys = {"op", "conditions", "condition", "fact", "fact_type", "operator", "value"}
    unexpected = sorted(set(condition) - allowed_keys)
    if unexpected:
        errors.append(f"{path} contains unsupported fields: {', '.join(unexpected)}")
    op = _text(condition.get("op"))
    if op in {"all", "any"}:
        children = condition.get("conditions")
        if not isinstance(children, list) or not children:
            errors.append(f"{path}.conditions must be a non-empty list")
            return
        for index, child in enumerate(children):
            _validate_condition(child, f"{path}.conditions[{index}]", errors)
        return
    if op == "not":
        if "condition" not in condition:
            errors.append(f"{path}.condition is required")
            return
        _validate_condition(condition.get("condition"), f"{path}.condition", errors)
        return
    if op != "compare":
        errors.append(f"{path}.op is unsupported")
        return

    fact = _text(condition.get("fact"))
    if not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", fact):
        errors.append(f"{path}.fact must be a canonical fact identifier")
    fact_type = _text(condition.get("fact_type"))
    if fact_type not in FACT_TYPES:
        errors.append(f"{path}.fact_type is unsupported")
    operator = _text(condition.get("operator"))
    if operator not in CONDITION_OPERATORS:
        errors.append(f"{path}.operator is unsupported")
    value_type = _validate_typed_value(condition.get("value"), f"{path}.value", errors)
    if operator in {"in", "not_in"} and value_type != "list":
        errors.append(f"{path}.operator {operator} requires a list value")
    if operator in {"in", "not_in"} and value_type == "list":
        values = condition.get("value", {}).get("value", [])
        member_types = {
            _text(item.get("type")) for item in values if isinstance(item, dict)
        }
        if member_types != {fact_type}:
            errors.append(f"{path}.value member type must match fact_type")
    if operator in {"before", "on_or_before", "after", "on_or_after"} and (
        fact_type != "date" or value_type != "date"
    ):
        errors.append(f"{path}.operator {operator} requires date operands")
    if operator in {"lt", "lte", "gt", "gte"} and fact_type not in {"integer", "decimal"}:
        errors.append(f"{path}.operator {operator} requires numeric operands")
    if operator == "contains" and fact_type != "list":
        errors.append(f"{path}.operator contains requires a list fact")
    if value_type and operator not in {"in", "not_in", "contains"} and value_type != fact_type:
        errors.append(f"{path}.value type must match fact_type")


def _validate_outcome(outcome: Any, path: str, errors: list[str]) -> None:
    if not isinstance(outcome, dict):
        errors.append(f"{path} must be an object")
        return
    if set(outcome) - {"kind", "code", "parameters"}:
        errors.append(f"{path} contains unsupported fields")
    if _text(outcome.get("kind")) not in OUTCOME_KINDS:
        errors.append(f"{path}.kind is unsupported")
    if not re.fullmatch(r"[a-z][a-z0-9_.:-]*", _text(outcome.get("code"))):
        errors.append(f"{path}.code must be a canonical outcome code")
    parameters = outcome.get("parameters", {})
    if not isinstance(parameters, dict):
        errors.append(f"{path}.parameters must be an object")
        return
    for name, value in parameters.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", str(name)):
            errors.append(f"{path}.parameters contains an invalid name")
        _validate_typed_value(value, f"{path}.parameters.{name}", errors)


def _resolve_evidence_path(evidence_root: Path, artifact_path: Any, errors: list[str]) -> Path | None:
    text = _text(artifact_path)
    if not text:
        errors.append("source.artifact_path is required")
        return None
    relative = Path(text)
    if relative.is_absolute() or ".." in relative.parts:
        errors.append("source.artifact_path must be a safe relative evidence path")
        return None
    root = evidence_root.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        errors.append("source.artifact_path escapes the evidence directory")
        return None
    if not resolved.is_file():
        errors.append("source.artifact_path does not exist")
        return None
    return resolved


def validate_canonical_rule(
    rule: Any,
    evidence_root: Path,
    *,
    allow_runtime_eligible: bool = False,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(rule, dict):
        return ["rule must be an object"]
    required = {
        "schema_version",
        "rule_id",
        "version",
        "program",
        "jurisdiction",
        "authority",
        "rule_type",
        "conditions",
        "outcome",
        "effective_from",
        "effective_through",
        "source",
        "review_status",
        "legal_verification_status",
        "runtime_eligibility_status",
    }
    missing = sorted(required - set(rule))
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")
    if rule.get("schema_version") != RULE_SCHEMA_VERSION:
        errors.append(f"schema_version must be {RULE_SCHEMA_VERSION}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]*", _text(rule.get("rule_id"))):
        errors.append("rule_id must be canonical")
    if not re.fullmatch(r"[1-9]\d*\.\d+\.\d+", _text(rule.get("version"))):
        errors.append("version must use semantic MAJOR.MINOR.PATCH form")
    if not re.fullmatch(r"[a-z][a-z0-9_]*", _text(rule.get("program"))):
        errors.append("program must be a canonical identifier")

    jurisdiction = rule.get("jurisdiction")
    if not isinstance(jurisdiction, dict):
        errors.append("jurisdiction must be an object")
    else:
        if jurisdiction.get("country") != "US":
            errors.append("jurisdiction.country must be US")
        level = _text(jurisdiction.get("level"))
        if level not in JURISDICTION_LEVELS:
            errors.append("jurisdiction.level is unsupported")
        if level in {"state", "local"} and not re.fullmatch(
            r"[A-Z]{2}", _text(jurisdiction.get("state"))
        ):
            errors.append("jurisdiction.state is required for state/local rules")

    authority = rule.get("authority")
    if not isinstance(authority, dict):
        errors.append("authority must be an object")
    else:
        if not _text(authority.get("issuer")):
            errors.append("authority.issuer is required")
        if _text(authority.get("level")) not in JURISDICTION_LEVELS:
            errors.append("authority.level is unsupported")
        if not _text(authority.get("citation")):
            errors.append("authority.citation is required")

    if _text(rule.get("rule_type")) not in RULE_TYPES:
        errors.append("rule_type is unsupported")
    _validate_condition(rule.get("conditions"), "conditions", errors)
    _validate_outcome(rule.get("outcome"), "outcome", errors)

    effective_from = _parse_iso_date(rule.get("effective_from"), "effective_from", errors)
    effective_through_text = _text(rule.get("effective_through"))
    effective_through = None
    if effective_through_text:
        effective_through = _parse_iso_date(effective_through_text, "effective_through", errors)
    if effective_from and effective_through and effective_through < effective_from:
        errors.append("effective_through cannot precede effective_from")

    source = rule.get("source")
    if not isinstance(source, dict):
        errors.append("source must be an object")
    else:
        url = _text(source.get("url"))
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            errors.append("source.url must be an absolute HTTPS URL")
        if not _text(source.get("citation_text")):
            errors.append("source.citation_text is required")
        expected_hash = _text(source.get("sha256"))
        if not _is_sha256(expected_hash):
            errors.append("source.sha256 must be a lowercase SHA-256 digest")
        evidence_path = _resolve_evidence_path(evidence_root, source.get("artifact_path"), errors)
        if evidence_path and _is_sha256(expected_hash) and file_sha256(evidence_path) != expected_hash:
            errors.append("source.sha256 does not match exact evidence bytes")

    review_status = _text(rule.get("review_status"))
    legal_status = _text(rule.get("legal_verification_status"))
    runtime_status = _text(rule.get("runtime_eligibility_status"))
    if review_status not in REVIEW_STATUSES:
        errors.append("review_status is unsupported")
    if legal_status not in LEGAL_STATUSES:
        errors.append("legal_verification_status is unsupported")
    if runtime_status not in RUNTIME_STATUSES:
        errors.append("runtime_eligibility_status is unsupported")
    if runtime_status in {"eligible", "active"}:
        if not allow_runtime_eligible:
            errors.append("runtime eligibility is forbidden before Phase R5")
        if review_status != "approved" or legal_status != "verified":
            errors.append("runtime promotion requires approved review and legal verification")
    return errors


def validate_canonical_bundle(bundle: Any, evidence_root: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return ["bundle must be an object"]
    if bundle.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        errors.append(f"schema_version must be {BUNDLE_SCHEMA_VERSION}")
    if bundle.get("runtime_activation") is not False:
        errors.append("runtime_activation must remain false")
    if bundle.get("proof_binding") is not False:
        errors.append("proof_binding must remain false")
    rules = bundle.get("rules")
    if not isinstance(rules, list):
        errors.append("rules must be a list")
        rules = []
    ids: set[str] = set()
    for index, rule in enumerate(rules):
        rule_errors = validate_canonical_rule(rule, evidence_root)
        errors.extend(f"rules[{index}]: {error}" for error in rule_errors)
        rule_id = _text(rule.get("rule_id")) if isinstance(rule, dict) else ""
        if rule_id in ids:
            errors.append(f"rules[{index}]: duplicate rule_id {rule_id}")
        ids.add(rule_id)
    expected_hash = canonical_sha256(rules)
    if bundle.get("rules_sha256") != expected_hash:
        errors.append(f"rules_sha256 mismatch: expected {expected_hash}")
    for conflict in detect_canonical_conflicts(rules):
        errors.append(
            "conflicting duplicate rules: " + ", ".join(conflict["rule_ids"])
        )
    return errors


def _jurisdiction_key(rule: dict[str, Any]) -> str:
    return canonical_json(rule.get("jurisdiction", {}))


def _effective_window(rule: dict[str, Any]) -> tuple[date, date]:
    start = datetime.strptime(rule["effective_from"], "%Y-%m-%d").date()
    end_text = rule.get("effective_through")
    end = datetime.strptime(end_text, "%Y-%m-%d").date() if end_text else date.max
    return start, end


def detect_canonical_conflicts(rules: list[Any]) -> list[dict[str, Any]]:
    valid_rules = [rule for rule in rules if isinstance(rule, dict)]
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for rule in valid_rules:
        if not _text(rule.get("effective_from")):
            continue
        key = (
            _text(rule.get("program")),
            _jurisdiction_key(rule),
            canonical_json(rule.get("conditions")),
        )
        groups[key].append(rule)
    conflicts: list[dict[str, Any]] = []
    for grouped in groups.values():
        for left_index, left in enumerate(grouped):
            for right in grouped[left_index + 1 :]:
                try:
                    left_start, left_end = _effective_window(left)
                    right_start, right_end = _effective_window(right)
                except (KeyError, ValueError):
                    continue
                if max(left_start, right_start) <= min(left_end, right_end) and canonical_json(
                    left.get("outcome")
                ) != canonical_json(right.get("outcome")):
                    conflicts.append(
                        {
                            "conflict_type": "overlapping_condition_outcome_conflict",
                            "rule_ids": sorted([_text(left.get("rule_id")), _text(right.get("rule_id"))]),
                        }
                    )
    return sorted(conflicts, key=lambda item: item["rule_ids"])


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _records(payload: Any, field: str | None = None) -> list[dict[str, Any]]:
    if field and isinstance(payload, dict):
        payload = payload.get(field)
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def _normalized_text(value: Any) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", _text(value).lower()))


def _jurisdiction_from_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    raw = _text(candidate.get("jurisdiction_level")) or "federal"
    state = None
    level = raw
    if raw.startswith("state_"):
        level = "state"
        state = raw.removeprefix("state_").upper()
    elif raw == "state":
        state = _text(candidate.get("jurisdiction_state")).upper() or None
    return {"country": "US", "level": level, "state": state}


def _outcome_kind(operator: str) -> str:
    return {
        "administration": "administrative",
        "appeal_right": "appeal",
        "deadline": "deadline",
        "determine_eligibility": "decision",
        "enforcement": "enforcement",
        "payment": "payment",
        "prohibit_or_deny": "decision",
        "reporting": "obligation",
        "require": "obligation",
        "verify_or_determine": "obligation",
    }.get(operator, "administrative")


def _evidence_blockers(candidate: dict[str, Any], workdir: Path) -> list[str]:
    artifact = _text(candidate.get("source_artifact_path"))
    digest = _text(candidate.get("source_hash") or candidate.get("source_sha256"))
    if not artifact or not digest:
        return ["missing_source_artifact", "missing_provenance"]
    errors: list[str] = []
    path = _resolve_evidence_path(workdir / "evidence", artifact, errors)
    if path is None:
        return ["missing_source_artifact"]
    if not _is_sha256(digest):
        return ["missing_provenance"]
    if path and file_sha256(path) != digest:
        return ["source_hash_mismatch"]
    return []


def _draft_for(candidate: dict[str, Any], mapping: dict[str, Any] | None) -> dict[str, Any]:
    inputs = sorted(set(mapping.get("inputs_required", []))) if mapping else []
    return {
        "operator_category": _text(mapping.get("operator")) if mapping else None,
        "required_facts": [
            {"fact_id": input_name, "suggested_type": INPUT_FACT_TYPES.get(input_name)}
            for input_name in inputs
        ],
        "threshold_candidate": mapping.get("threshold") if mapping else None,
        "effective_date_candidate": mapping.get("effective_date") if mapping else None,
        "outcome_kind_candidate": _outcome_kind(_text(mapping.get("operator"))) if mapping else None,
        "condition_source_text": _text(mapping.get("condition_text"))
        if mapping
        else _text(candidate.get("statement")),
        "mapping_status": _text(mapping.get("mapping_status")) if mapping else "missing_lineage",
    }


def _candidate_blockers(
    candidate: dict[str, Any],
    mapping: dict[str, Any] | None,
    promotion: dict[str, Any] | None,
    workdir: Path,
) -> list[str]:
    blockers = set(_evidence_blockers(candidate, workdir))
    source_url = _text(candidate.get("source_url"))
    parsed = urlparse(source_url)
    if parsed.scheme != "https" or not parsed.netloc:
        blockers.add("invalid_source_url")
        blockers.add("missing_provenance")
    if not _text(candidate.get("citation_text")):
        blockers.add("missing_provenance")
    if mapping is None or promotion is None:
        blockers.add("missing_lineage")
    operator = _text(mapping.get("operator")) if mapping else ""
    if operator and operator not in COARSE_OPERATORS:
        blockers.add("unsupported_operator")
    inputs = mapping.get("inputs_required") if mapping else None
    if not isinstance(inputs, list) or not inputs or any(item not in INPUT_FACT_TYPES for item in inputs):
        blockers.add("missing_typed_fact")
    if mapping is None or mapping.get("qa_status") != "qa_pass" or mapping.get("mapping_status") != "strong_mapping_candidate":
        blockers.add("ambiguous_free_text_condition")
    else:
        # Current mappings retain a normalized prose condition and do not contain a typed AST.
        blockers.add("ambiguous_free_text_condition")
    effective = _text(mapping.get("effective_date")) if mapping else ""
    if not effective:
        blockers.add("missing_effective_date")
        blockers.add("missing_provenance")
    else:
        date_errors: list[str] = []
        _parse_iso_date(effective, "effective_date", date_errors)
        if date_errors:
            blockers.add("invalid_effective_date")
            blockers.add("missing_provenance")
    blockers.add("human_review_not_approved")
    blockers.add("legal_not_verified")
    return sorted(blockers)


def build_promotion_queue(workdir: Path) -> dict[str, Any]:
    workdir = workdir.resolve()
    reports = workdir / "reports"
    raw = _records(_read_json(reports / "claude_web_candidate_corpus.json"), "candidate_rules")
    promotion = _records(_read_json(reports / "claude_web_promotion_ready.json"))
    mapping_payload = _read_json(reports / "claude_web_mapping_qa.json")
    mappings = _records(mapping_payload, "candidates")

    promotions_by_id = {_text(item.get("candidate_id")): item for item in promotion}
    mappings_by_id = {_text(item.get("source_candidate_id")): item for item in mappings}
    items: list[dict[str, Any]] = []
    for candidate in raw:
        candidate_id = _text(candidate.get("candidate_id"))
        mapping = mappings_by_id.get(candidate_id)
        promotion_item = promotions_by_id.get(candidate_id)
        blockers = _candidate_blockers(candidate, mapping, promotion_item, workdir)
        items.append(
            {
                "candidate_id": candidate_id,
                "program": _text(candidate.get("program")),
                "jurisdiction": _jurisdiction_from_candidate(candidate),
                "rule_type": _text(candidate.get("rule_unit_type")),
                "source": {
                    "url": _text(candidate.get("source_url")),
                    "citation_text": _text(candidate.get("citation_text")),
                    "artifact_path": candidate.get("source_artifact_path"),
                    "sha256": candidate.get("source_hash") or candidate.get("source_sha256"),
                },
                "draft": _draft_for(candidate, mapping),
                "canonical_rule": None,
                "blockers": blockers,
                "review_status": "machine_reviewed" if promotion_item else "unreviewed",
                "legal_verification_status": "not_verified",
                "runtime_eligibility_status": "blocked",
            }
        )

    items.sort(key=lambda item: item["candidate_id"])
    _mark_draft_duplicates(items)
    programs = sorted({_text(item.get("program")) for item in items if _text(item.get("program"))})
    blocker_counts = Counter(blocker for item in items for blocker in item["blockers"])
    items_sha256 = canonical_sha256(items)
    summary = {
        "source_candidates": len(raw),
        "promotion_review_records": len(promotion),
        "mapping_records": len(mappings),
        "qa_pass_records": sum(1 for item in mappings if item.get("qa_status") == "qa_pass"),
        "program_count": len(programs),
        "programs": programs,
        "queue_items": len(items),
        "runtime_eligible": 0,
        "by_blocker": dict(sorted(blocker_counts.items())),
    }
    return {
        "schema_version": QUEUE_SCHEMA_VERSION,
        "queue_id": f"government-rule-promotion:{items_sha256[:24]}",
        "items_sha256": items_sha256,
        "runtime_activation": False,
        "proof_binding": False,
        "warning": (
            "Machine-generated all-program promotion queue. No record is legally verified, "
            "runtime eligible, proof bound, or permitted to affect adjudication."
        ),
        "summary": summary,
        "items": items,
    }


def _mark_draft_duplicates(items: list[dict[str, Any]]) -> None:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        key = (
            item["program"],
            canonical_json(item["jurisdiction"]),
            _normalized_text(item["draft"].get("condition_source_text")),
        )
        groups[key].append(item)
    for group in groups.values():
        if len(group) < 2:
            continue
        outcomes = {item["draft"].get("outcome_kind_candidate") for item in group}
        signatures = {
            canonical_json(
                {
                    "program": item["program"],
                    "jurisdiction": item["jurisdiction"],
                    "rule_type": item["rule_type"],
                    "source": item["source"],
                    "draft": item["draft"],
                }
            )
            for item in group
        }
        if len(outcomes) > 1:
            blocker = "conflicting_duplicate"
        elif len(signatures) == 1:
            blocker = "exact_duplicate"
        else:
            blocker = "semantic_duplicate"
        for item in group:
            item["blockers"] = sorted(set(item["blockers"]) | {blocker})


def validate_promotion_queue(queue: Any, evidence_root: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(queue, dict):
        return ["queue must be an object"]
    if queue.get("schema_version") != QUEUE_SCHEMA_VERSION:
        errors.append(f"schema_version must be {QUEUE_SCHEMA_VERSION}")
    if queue.get("runtime_activation") is not False:
        errors.append("runtime_activation must remain false")
    if queue.get("proof_binding") is not False:
        errors.append("proof_binding must remain false")
    items = queue.get("items")
    if not isinstance(items, list):
        errors.append("items must be a list")
        items = []
    if queue.get("items_sha256") != canonical_sha256(items):
        errors.append("items_sha256 does not match canonical queue items")
    ids: set[str] = set()
    for index, item in enumerate(items):
        prefix = f"items[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        candidate_id = _text(item.get("candidate_id"))
        if not candidate_id or candidate_id in ids:
            errors.append(f"{prefix}.candidate_id is missing or duplicate")
        ids.add(candidate_id)
        blockers = item.get("blockers")
        if not isinstance(blockers, list) or blockers != sorted(set(blockers)):
            errors.append(f"{prefix}.blockers must be a sorted unique list")
            blockers = []
        unsupported = sorted(set(blockers) - BLOCKER_CODES)
        if unsupported:
            errors.append(f"{prefix}.blockers contains unsupported codes")
        if item.get("runtime_eligibility_status") != "blocked":
            errors.append(f"{prefix}.runtime_eligibility_status must remain blocked")
        if item.get("legal_verification_status") != "not_verified":
            errors.append(f"{prefix}.legal_verification_status must remain not_verified")
        canonical_rule = item.get("canonical_rule")
        if canonical_rule is not None:
            rule_errors = validate_canonical_rule(canonical_rule, evidence_root)
            errors.extend(f"{prefix}.canonical_rule: {error}" for error in rule_errors)
        if not blockers and canonical_rule is None:
            errors.append(f"{prefix} has no blockers but no canonical_rule")
    summary = queue.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be an object")
    else:
        if summary.get("queue_items") != len(items):
            errors.append("summary.queue_items mismatch")
        if summary.get("runtime_eligible") != 0:
            errors.append("summary.runtime_eligible must remain zero")
    return errors


def write_promotion_queue(workdir: Path) -> dict[str, Any]:
    workdir = workdir.resolve()
    queue = build_promotion_queue(workdir)
    errors = validate_promotion_queue(queue, workdir / "evidence")
    if errors:
        raise ValueError("; ".join(errors))
    summary = queue["summary"]
    if summary["source_candidates"] != 226:
        raise ValueError(f"expected 226 source candidates, got {summary['source_candidates']}")
    if summary["promotion_review_records"] != 221 or summary["mapping_records"] != 221:
        raise ValueError("expected 221 reviewed and mapped candidates")
    if summary["qa_pass_records"] != 191:
        raise ValueError(f"expected 191 QA-passing mappings, got {summary['qa_pass_records']}")
    if summary["program_count"] != 51:
        raise ValueError(f"expected 51 programs, got {summary['program_count']}")

    reports = workdir / "reports"
    queue_path = reports / "rules_promotion_queue_v1.json"
    summary_path = reports / "rules_promotion_queue_v1_summary.json"
    markdown_path = reports / "rules_promotion_queue_v1.md"
    queue_path.write_text(json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_queue_markdown(queue), encoding="utf-8")
    return {
        "queue": str(queue_path),
        "summary": str(summary_path),
        "markdown": str(markdown_path),
        "queue_id": queue["queue_id"],
        "items_sha256": queue["items_sha256"],
        "queue_items": summary["queue_items"],
        "program_count": summary["program_count"],
        "runtime_eligible": 0,
        "runtime_activation": False,
        "proof_binding": False,
        "verdict": "R2_R3_PROMOTION_QUEUE_VALIDATED_NON_RUNTIME",
    }


def validate_promotion_queue_file(workdir: Path, path: Path) -> dict[str, Any]:
    resolved = path if path.is_absolute() else workdir / path
    queue = _read_json(resolved)
    errors = validate_promotion_queue(queue, workdir / "evidence")
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "path": str(resolved),
        "queue_id": queue["queue_id"],
        "items_sha256": queue["items_sha256"],
        "queue_items": len(queue["items"]),
        "program_count": queue["summary"]["program_count"],
        "runtime_eligible": 0,
        "runtime_activation": False,
        "proof_binding": False,
        "verdict": "R2_R3_PROMOTION_QUEUE_VALID",
    }


def _queue_markdown(queue: dict[str, Any]) -> str:
    summary = queue["summary"]
    lines = [
        "# Rules Promotion Queue V1",
        "",
        f"- queue_id: {queue['queue_id']}",
        f"- items_sha256: {queue['items_sha256']}",
        f"- source_candidates: {summary['source_candidates']}",
        f"- promotion_review_records: {summary['promotion_review_records']}",
        f"- mapping_records: {summary['mapping_records']}",
        f"- qa_pass_records: {summary['qa_pass_records']}",
        f"- queue_items: {summary['queue_items']}",
        f"- programs: {summary['program_count']}",
        "- runtime_eligible: 0",
        "- runtime_activation: false",
        "- proof_binding: false",
        "",
        queue["warning"],
        "",
        "## Blockers",
        "",
    ]
    lines.extend(f"- {code}: {count}" for code, count in summary["by_blocker"].items())
    return "\n".join(lines) + "\n"
