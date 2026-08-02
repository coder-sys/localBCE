from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "claude-web-rust-shadow-bundle-v1"
EXECUTION_STATUS = "shadow_only_non_runtime"
LEGAL_STATUS = "candidate_not_legally_verified"
ALLOWED_OPERATORS = {
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


def write_claude_web_rust_shadow_bundle(workdir: Path) -> dict:
    source_path = workdir / "reports" / "claude_web_mapping_qa.json"
    if not source_path.exists():
        raise FileNotFoundError(f"Claude web mapping QA not found: {source_path}")
    raw = json.loads(source_path.read_text(encoding="utf-8"))
    candidates = raw.get("candidates") if isinstance(raw, dict) else None
    if not isinstance(candidates, list):
        raise ValueError("claude_web_mapping_qa.json must contain a candidates list")

    bundle = build_rust_shadow_bundle(candidates)
    validate_rust_shadow_bundle(bundle)
    summary = build_rust_shadow_summary(bundle, len(candidates))

    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "claude_web_rust_shadow_rules.json"
    summary_path = reports_dir / "claude_web_rust_shadow_summary.json"
    markdown_path = reports_dir / "claude_web_rust_shadow_rules.md"
    json_path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_rust_shadow_markdown(summary), encoding="utf-8")

    return {
        "input_candidates": summary["input_candidates"],
        "exported_shadow_rules": summary["exported_shadow_rules"],
        "excluded_candidates": summary["excluded_candidates"],
        "programs_covered": summary["programs_covered"],
        "bundle_sha256": bundle["rules_sha256"],
        "runtime_activation": False,
        "rust_shadow_rules": str(json_path),
        "summary": str(summary_path),
        "markdown": str(markdown_path),
        "verdict": "CLAUDE_WEB_RUST_SHADOW_READY",
    }


def build_rust_shadow_bundle(raw_candidates: list[Any]) -> dict:
    eligible = [
        candidate
        for candidate in raw_candidates
        if isinstance(candidate, dict)
        and candidate.get("qa_status") == "qa_pass"
        and candidate.get("mapping_status") == "strong_mapping_candidate"
        and not candidate.get("qa_issues")
    ]
    rules = [normalize_rust_shadow_rule(candidate) for candidate in eligible]
    rules.sort(
        key=lambda item: (
            item["vertical"],
            item["program"],
            item["jurisdiction_level"],
            item.get("jurisdiction_state") or "",
            item["rule_type"],
            item["rule_id"],
        )
    )
    rules_sha256 = canonical_sha256(rules)
    return {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": f"claude-web-shadow:{rules_sha256[:24]}",
        "rules_sha256": rules_sha256,
        "ruleset_kind": "source_grounded_candidate_shadow",
        "execution_status": EXECUTION_STATUS,
        "legal_verification_status": LEGAL_STATUS,
        "runtime_activation": False,
        "proof_binding": False,
        "selection_gate": {
            "qa_status": "qa_pass",
            "mapping_status": "strong_mapping_candidate",
            "qa_issues": [],
        },
        "warning": (
            "These rules are deterministic-shape, source-grounded candidates only. "
            "They are not legal verification and cannot be activated by rust-engine."
        ),
        "rules": rules,
    }


def normalize_rust_shadow_rule(candidate: dict) -> dict:
    source_mapping_id = required_text(candidate, "mapping_candidate_id")
    identity = {
        "source_mapping_id": source_mapping_id,
        "source_candidate_id": required_text(candidate, "source_candidate_id"),
        "condition": required_text(candidate, "normalized_condition"),
        "program": required_text(candidate, "program"),
    }
    rule_id = f"claude-shadow:{canonical_sha256(identity)[:24]}"
    return {
        "rule_id": rule_id,
        "source_mapping_id": source_mapping_id,
        "source_executable_rule_id": required_text(candidate, "source_executable_rule_id"),
        "source_candidate_id": required_text(candidate, "source_candidate_id"),
        "vertical": required_text(candidate, "vertical"),
        "program": required_text(candidate, "program"),
        "rule_type": required_text(candidate, "rule_type"),
        "jurisdiction_level": required_text(candidate, "jurisdiction_level"),
        "jurisdiction_state": candidate.get("jurisdiction_state"),
        "authority_level": required_text(candidate, "authority_level"),
        "condition_text": required_text(candidate, "condition_text"),
        "normalized_condition": required_text(candidate, "normalized_condition"),
        "operator": required_text(candidate, "operator"),
        "inputs_required": sorted(set(required_text_list(candidate, "inputs_required"))),
        "threshold": candidate.get("threshold"),
        "effective_date": candidate.get("effective_date"),
        "exception_text": candidate.get("exception_text"),
        "outcome_text": required_text(candidate, "outcome_text"),
        "source_url": required_text(candidate, "source_url"),
        "citation_text": required_text(candidate, "citation_text"),
        "confidence_score": float(candidate.get("confidence_score")),
        "mapping_confidence": float(candidate.get("mapping_confidence")),
        "qa_status": "qa_pass",
        "mapping_status": "strong_mapping_candidate",
        "legal_verification_status": LEGAL_STATUS,
        "execution_status": EXECUTION_STATUS,
        "runtime_compatible": False,
        "proof_bound": False,
    }


def validate_rust_shadow_bundle(bundle: dict) -> None:
    errors: list[str] = []
    if bundle.get("schema_version") != SCHEMA_VERSION:
        errors.append("invalid schema_version")
    if bundle.get("execution_status") != EXECUTION_STATUS:
        errors.append("bundle execution_status must remain shadow-only")
    if bundle.get("legal_verification_status") != LEGAL_STATUS:
        errors.append("bundle legal verification status is invalid")
    if bundle.get("runtime_activation") is not False:
        errors.append("runtime_activation must be false")
    if bundle.get("proof_binding") is not False:
        errors.append("proof_binding must be false")
    rules = bundle.get("rules")
    if not isinstance(rules, list):
        errors.append("rules must be a list")
        rules = []
    if bundle.get("rules_sha256") != canonical_sha256(rules):
        errors.append("rules_sha256 does not match canonical rules")

    ids: set[str] = set()
    for index, rule in enumerate(rules):
        prefix = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix} must be an object")
            continue
        rule_id = str(rule.get("rule_id") or "")
        if not rule_id or rule_id in ids:
            errors.append(f"{prefix}.rule_id is missing or duplicate")
        ids.add(rule_id)
        if rule.get("operator") not in ALLOWED_OPERATORS:
            errors.append(f"{prefix}.operator is unsupported")
        if not rule.get("inputs_required"):
            errors.append(f"{prefix}.inputs_required must not be empty")
        if rule.get("qa_status") != "qa_pass":
            errors.append(f"{prefix}.qa_status must be qa_pass")
        if rule.get("mapping_status") != "strong_mapping_candidate":
            errors.append(f"{prefix}.mapping_status must be strong_mapping_candidate")
        if rule.get("execution_status") != EXECUTION_STATUS:
            errors.append(f"{prefix}.execution_status must remain shadow-only")
        if rule.get("runtime_compatible") is not False or rule.get("proof_bound") is not False:
            errors.append(f"{prefix} cannot claim runtime or proof compatibility")
        if rule.get("legal_verification_status") != LEGAL_STATUS:
            errors.append(f"{prefix}.legal_verification_status is invalid")
        if not str(rule.get("source_url") or "").startswith("https://"):
            errors.append(f"{prefix}.source_url must use https")
        if not str(rule.get("citation_text") or "").strip():
            errors.append(f"{prefix}.citation_text is required")

    if errors:
        raise ValueError("; ".join(errors))


def build_rust_shadow_summary(bundle: dict, input_count: int) -> dict:
    rules = bundle["rules"]
    by_program = Counter(rule["program"] for rule in rules)
    by_vertical = Counter(rule["vertical"] for rule in rules)
    by_operator = Counter(rule["operator"] for rule in rules)
    by_rule_type = Counter(rule["rule_type"] for rule in rules)
    return {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": bundle["bundle_id"],
        "rules_sha256": bundle["rules_sha256"],
        "input_candidates": input_count,
        "exported_shadow_rules": len(rules),
        "excluded_candidates": input_count - len(rules),
        "programs_covered": len(by_program),
        "verticals_covered": len(by_vertical),
        "by_program": dict(sorted(by_program.items())),
        "by_vertical": dict(sorted(by_vertical.items())),
        "by_operator": dict(sorted(by_operator.items())),
        "by_rule_type": dict(sorted(by_rule_type.items())),
        "runtime_activation": False,
        "proof_binding": False,
        "legal_verification_status": LEGAL_STATUS,
        "warning": bundle["warning"],
    }


def write_rust_shadow_markdown(summary: dict) -> str:
    lines = [
        "# Claude Web Rust Shadow Rules",
        "",
        f"- schema_version: {summary['schema_version']}",
        f"- bundle_id: {summary['bundle_id']}",
        f"- rules_sha256: {summary['rules_sha256']}",
        f"- input_candidates: {summary['input_candidates']}",
        f"- exported_shadow_rules: {summary['exported_shadow_rules']}",
        f"- excluded_candidates: {summary['excluded_candidates']}",
        f"- programs_covered: {summary['programs_covered']}",
        f"- verticals_covered: {summary['verticals_covered']}",
        "- runtime_activation: false",
        "- proof_binding: false",
        "",
        summary["warning"],
        "",
        "## By Operator",
        "",
    ]
    lines.extend(f"- {name}: {count}" for name, count in summary["by_operator"].items())
    lines.extend(["", "## By Program", ""])
    lines.extend(f"- {name}: {count}" for name, count in summary["by_program"].items())
    return "\n".join(lines) + "\n"


def required_text(candidate: dict, field: str) -> str:
    value = str(candidate.get(field) or "").strip()
    if not value:
        raise ValueError(f"candidate is missing required {field}")
    return value


def required_text_list(candidate: dict, field: str) -> list[str]:
    value = candidate.get(field)
    if not isinstance(value, list) or not value:
        raise ValueError(f"candidate is missing required {field}")
    result = [str(item).strip() for item in value if str(item).strip()]
    if not result:
        raise ValueError(f"candidate is missing required {field}")
    return result


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
