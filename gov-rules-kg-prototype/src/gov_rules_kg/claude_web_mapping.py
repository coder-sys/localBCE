from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .claude_web_executable import normalize_condition, read_json_list


INPUT_KEYWORDS = {
    "age": ["age", "older", "younger"],
    "income": ["income", "fpl", "poverty", "magi", "taxable"],
    "residency": ["resident", "residency", "live in", "service area"],
    "citizenship_or_immigration_status": ["citizen", "national", "lawfully present", "qualified non-citizen", "immigration"],
    "disability_status": ["disability", "disabled", "blindness", "blind"],
    "application_status": ["application", "apply", "enroll", "enrollment"],
    "documentation": ["documentation", "record", "form", "submit"],
    "deadline": ["within", "days", "months", "deadline", "period"],
    "payment": ["payment", "premium", "reimburse", "reimbursement", "refund", "credit"],
    "provider_status": ["provider", "vendor", "license", "contractor"],
}


def write_claude_web_deterministic_mapping(workdir: Path) -> dict:
    source_path = workdir / "reports" / "claude_web_executable_rule_candidates.json"
    if not source_path.exists():
        raise FileNotFoundError(f"Claude web executable candidates not found: {source_path}")
    candidates = read_json_list(source_path)
    mapped = [map_deterministic_candidate(candidate) for candidate in candidates if isinstance(candidate, dict)]
    summary = build_mapping_summary(candidates, mapped)

    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_path = reports_dir / "claude_web_deterministic_mapping_candidates.json"
    summary_path = reports_dir / "claude_web_deterministic_mapping_summary.json"
    markdown_path = reports_dir / "claude_web_deterministic_mapping.md"
    output_path.write_text(json.dumps(mapped, indent=2, sort_keys=True), encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_mapping_markdown(summary, mapped), encoding="utf-8")

    return {
        "input_candidates": summary["input_candidates"],
        "mapped_candidates": summary["mapped_candidates"],
        "strong_mapping_candidates": summary["strong_mapping_candidates"],
        "partial_mapping_candidates": summary["partial_mapping_candidates"],
        "needs_manual_mapping_candidates": summary["needs_manual_mapping_candidates"],
        "by_operator": summary["by_operator"],
        "by_program": summary["by_program"],
        "deterministic_mapping_candidates": str(output_path),
        "summary": str(summary_path),
        "markdown": str(markdown_path),
        "verdict": "CLAUDE_WEB_DETERMINISTIC_MAPPING_READY",
    }


def map_deterministic_candidate(candidate: dict) -> dict:
    condition = str(candidate.get("condition_text") or "").strip()
    normalized = normalize_condition(condition)
    exception_text = extract_exception_text(condition)
    operator = infer_operator(condition, candidate)
    threshold = extract_threshold(condition)
    effective_date = extract_effective_date(condition)
    inputs_required = infer_inputs_required(condition)
    outcome_text = infer_outcome_text(condition, operator)
    mapping_confidence = mapping_confidence_score(operator, threshold, effective_date, inputs_required, exception_text)
    mapping_status = mapping_status_for_confidence(mapping_confidence)
    return {
        "mapping_candidate_id": f"map:{str(candidate.get('executable_rule_id') or candidate.get('source_candidate_id') or '')}",
        "source_executable_rule_id": candidate.get("executable_rule_id"),
        "source_candidate_id": candidate.get("source_candidate_id"),
        "vertical": candidate.get("vertical"),
        "program": candidate.get("program"),
        "rule_type": candidate.get("rule_type"),
        "jurisdiction_level": candidate.get("jurisdiction_level"),
        "jurisdiction_state": candidate.get("jurisdiction_state"),
        "authority_level": candidate.get("authority_level"),
        "condition_text": condition,
        "normalized_condition": normalized,
        "outcome_text": outcome_text,
        "inputs_required": inputs_required,
        "operator": operator,
        "threshold": threshold,
        "effective_date": effective_date,
        "exception_text": exception_text,
        "source_url": candidate.get("source_url"),
        "citation_text": candidate.get("citation_text"),
        "confidence_score": candidate.get("confidence_score"),
        "mapping_confidence": mapping_confidence,
        "mapping_status": mapping_status,
        "validation_status": "deterministic_mapping_candidate_not_legal_verified",
        "notes": mapping_notes(operator, threshold, effective_date, inputs_required, exception_text),
    }


def infer_operator(text: str, candidate: dict) -> str:
    lowered = text.lower()
    rule_type = str(candidate.get("rule_type") or "")
    if any(term in lowered for term in ["prohibited", "may not", "must not", "ineligible", "deny", "denied"]):
        return "prohibit_or_deny"
    if any(term in lowered for term in ["must", "shall", "required", "requires"]):
        return "require"
    if any(term in lowered for term in ["eligible", "qualify", "qualifies"]):
        return "determine_eligibility"
    if any(term in lowered for term in ["within", "no later than", "before", "after"]) or rule_type == "deadline_rule":
        return "deadline"
    if any(term in lowered for term in ["pay", "payment", "premium", "reimburse", "refund", "credit"]):
        return "payment"
    if any(term in lowered for term in ["report", "submit", "notify"]):
        return "reporting"
    if any(term in lowered for term in ["appeal", "hearing"]):
        return "appeal_right"
    return "unknown"


def extract_threshold(text: str) -> dict | None:
    patterns = [
        (r"(\d+(?:\.\d+)?)\s*%(\s*(?:of)?\s*(?:the)?\s*(?:federal poverty level|fpl))?", "percent"),
        (r"\$(\d+(?:,\d{3})*(?:\.\d+)?)", "currency"),
        (r"\b(\d+)\s+(days|months|years)\b", "duration"),
        (r"\bage\s+(\d+)\b|\b(\d+)\s+or\s+older\b", "age"),
    ]
    lowered = text.lower()
    for pattern, kind in patterns:
        match = re.search(pattern, lowered)
        if not match:
            continue
        value = next(group for group in match.groups() if group and re.match(r"^\d", group.replace(",", "")))
        unit = kind
        if kind == "duration" and len(match.groups()) >= 2:
            unit = match.group(2)
        return {"kind": kind, "value": value.replace(",", ""), "unit": unit, "text": match.group(0)}
    return None


def extract_effective_date(text: str) -> str | None:
    patterns = [
        r"\b(?:effective|beginning|starting)\s+([A-Z][a-z]+\s+\d{1,2},\s+\d{4})",
        r"\b([A-Z][a-z]+\s+\d{1,2},\s+\d{4})\b",
        r"\b(\d{1,2}/\d{1,2}/\d{4})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def extract_exception_text(text: str) -> str | None:
    match = re.search(r"\b(unless|except|except for|other than)\b(.+)$", text, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(0).strip().rstrip(".")


def infer_inputs_required(text: str) -> list[str]:
    lowered = text.lower()
    inputs = [
        input_name
        for input_name, keywords in INPUT_KEYWORDS.items()
        if any(keyword in lowered for keyword in keywords)
    ]
    return sorted(set(inputs))


def infer_outcome_text(text: str, operator: str) -> str:
    if operator == "prohibit_or_deny":
        return f"Deny or prohibit when condition applies: {text}"
    if operator == "determine_eligibility":
        return f"Determine eligibility based on condition: {text}"
    if operator == "deadline":
        return f"Enforce deadline described by condition: {text}"
    if operator == "payment":
        return f"Apply payment outcome described by condition: {text}"
    if operator == "reporting":
        return f"Require reporting action described by condition: {text}"
    if operator == "appeal_right":
        return f"Provide appeal or hearing right described by condition: {text}"
    if operator == "require":
        return f"Require action described by condition: {text}"
    return f"Manual mapping required for outcome: {text}"


def mapping_confidence_score(
    operator: str,
    threshold: dict | None,
    effective_date: str | None,
    inputs_required: list[str],
    exception_text: str | None,
) -> float:
    score = 0.35
    if operator != "unknown":
        score += 0.25
    if inputs_required:
        score += 0.15
    if threshold:
        score += 0.15
    if effective_date:
        score += 0.05
    if exception_text:
        score += 0.05
    return round(min(score, 0.95), 2)


def mapping_status_for_confidence(confidence: float) -> str:
    if confidence >= 0.75:
        return "strong_mapping_candidate"
    if confidence >= 0.55:
        return "partial_mapping_candidate"
    return "needs_manual_mapping"


def mapping_notes(
    operator: str,
    threshold: dict | None,
    effective_date: str | None,
    inputs_required: list[str],
    exception_text: str | None,
) -> list[str]:
    notes = ["Deterministic heuristic mapping only; not legal verification."]
    if operator == "unknown":
        notes.append("Operator could not be inferred deterministically.")
    if not inputs_required:
        notes.append("No explicit input fields inferred.")
    if not threshold:
        notes.append("No numeric/date threshold inferred.")
    if effective_date:
        notes.append("Effective date candidate extracted.")
    if exception_text:
        notes.append("Exception clause candidate extracted.")
    return notes


def build_mapping_summary(input_candidates: list[Any], mapped: list[dict]) -> dict:
    by_status = Counter(str(item.get("mapping_status") or "unknown") for item in mapped)
    by_operator = Counter(str(item.get("operator") or "unknown") for item in mapped)
    by_program = Counter(str(item.get("program") or "unknown") for item in mapped)
    by_rule_type = Counter(str(item.get("rule_type") or "unknown") for item in mapped)
    return {
        "input_candidates": len(input_candidates),
        "mapped_candidates": len(mapped),
        "strong_mapping_candidates": by_status.get("strong_mapping_candidate", 0),
        "partial_mapping_candidates": by_status.get("partial_mapping_candidate", 0),
        "needs_manual_mapping_candidates": by_status.get("needs_manual_mapping", 0),
        "by_mapping_status": dict(sorted(by_status.items())),
        "by_operator": dict(sorted(by_operator.items())),
        "by_program": dict(sorted(by_program.items())),
        "by_rule_type": dict(sorted(by_rule_type.items())),
        "warning": "Deterministic mappings are candidates only and require legal review before production execution.",
    }


def write_mapping_markdown(summary: dict, mapped: list[dict]) -> str:
    lines = [
        "# Claude Web Deterministic Mapping Candidates",
        "",
        f"- input_candidates: {summary['input_candidates']}",
        f"- mapped_candidates: {summary['mapped_candidates']}",
        f"- strong_mapping_candidates: {summary['strong_mapping_candidates']}",
        f"- partial_mapping_candidates: {summary['partial_mapping_candidates']}",
        f"- needs_manual_mapping_candidates: {summary['needs_manual_mapping_candidates']}",
        "",
        summary["warning"],
        "",
        "## By Operator",
        "",
    ]
    for operator, count in summary["by_operator"].items():
        lines.append(f"- {operator}: {count}")
    lines.extend(["", "## By Program", ""])
    for program, count in summary["by_program"].items():
        lines.append(f"- {program}: {count}")
    lines.extend(["", "## Strong Mapping Sample", ""])
    strong = [item for item in mapped if item["mapping_status"] == "strong_mapping_candidate"]
    partial = [item for item in mapped if item["mapping_status"] == "partial_mapping_candidate"]
    manual = [item for item in mapped if item["mapping_status"] == "needs_manual_mapping"]
    for item in strong[:50]:
        lines.extend(mapping_item_lines(item))
    lines.extend(["", "## Partial Mapping Sample", ""])
    for item in partial[:50]:
        lines.extend(mapping_item_lines(item))
    lines.extend(["", "## Needs Manual Mapping Sample", ""])
    for item in manual[:50]:
        lines.extend(mapping_item_lines(item))
    return "\n".join(lines)


def mapping_item_lines(item: dict) -> list[str]:
    threshold = item.get("threshold")
    threshold_text = json.dumps(threshold, sort_keys=True) if threshold else "none"
    return [
        f"### {item.get('program')} / {item.get('rule_type')}",
        "",
        f"- id: {item.get('mapping_candidate_id')}",
        f"- status: {item.get('mapping_status')}",
        f"- operator: {item.get('operator')}",
        f"- inputs_required: {', '.join(item.get('inputs_required', [])) or 'none'}",
        f"- threshold: {threshold_text}",
        f"- effective_date: {item.get('effective_date') or 'none'}",
        f"- exception_text: {item.get('exception_text') or 'none'}",
        f"- condition: {item.get('condition_text')}",
        f"- outcome: {item.get('outcome_text')}",
        "",
    ]
