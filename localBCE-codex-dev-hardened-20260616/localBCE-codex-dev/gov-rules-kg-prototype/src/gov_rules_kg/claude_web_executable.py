from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .claude_web_coverage import taxonomy_programs
from .ratification import require_ratified_candidates


EXECUTABLE_RULE_TYPES = {
    "eligibility_rule",
    "enrollment_rule",
    "documentation_rule",
    "appeal_rule",
    "deadline_rule",
    "payment_rule",
    "reporting_rule",
    "enforcement_rule",
    "exception_rule",
    "provider_rule",
    "administration_rule",
    "verification_rule",
    "fraud_abuse_rule",
    "other",
}

RULE_TYPE_ALIASES = {
    "claim_rule": "administration_rule",
    "definition_rule": "administration_rule",
}


def write_claude_web_executable_candidates(workdir: Path) -> dict:
    source_path = workdir / "reports" / "claude_web_promotion_ready.json"
    if not source_path.exists():
        raise FileNotFoundError(f"Claude web promotion-ready report not found: {source_path}")
    candidates = read_json_list(source_path)
    executable_candidates = [normalize_executable_candidate(candidate) for candidate in candidates if isinstance(candidate, dict)]
    executable = require_ratified_candidates(workdir, executable_candidates)
    summary = build_executable_summary(candidates, executable)

    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_path = reports_dir / "claude_web_executable_rule_candidates.json"
    markdown_path = reports_dir / "claude_web_executable_rule_candidates.md"
    summary_path = reports_dir / "claude_web_executable_summary.json"
    output_path.write_text(json.dumps(executable, indent=2, sort_keys=True), encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_executable_markdown(summary, executable), encoding="utf-8")

    return {
        "input_candidates": summary["input_candidates"],
        "exported_candidates": summary["exported_candidates"],
        "programs_covered": summary["programs_covered"],
        "verticals_covered": summary["verticals_covered"],
        "by_rule_type": summary["by_rule_type"],
        "by_program": summary["by_program"],
        "executable_rule_candidates": str(output_path),
        "markdown": str(markdown_path),
        "summary": str(summary_path),
        "verdict": "CLAUDE_WEB_EXECUTABLE_EXPORT_READY",
    }


def normalize_executable_candidate(candidate: dict) -> dict:
    statement = str(candidate.get("statement") or "").strip()
    source_candidate_id = str(candidate.get("candidate_id") or "").strip() or candidate_fallback_id(candidate)
    rule_type = classify_executable_rule_type(candidate)
    jurisdiction_level = str(candidate.get("jurisdiction_level") or "unknown").strip() or "unknown"
    jurisdiction_state = candidate.get("jurisdiction_state") or candidate.get("state_code")
    if jurisdiction_level != "state":
        jurisdiction_state = None
    item = {
        "executable_rule_id": executable_rule_id(source_candidate_id, statement),
        "source_candidate_id": source_candidate_id,
        "vertical": str(candidate.get("vertical") or "unknown").strip(),
        "program": str(candidate.get("program") or "unknown").strip(),
        "rule_type": rule_type,
        "jurisdiction_level": jurisdiction_level,
        "jurisdiction_state": jurisdiction_state,
        "authority_level": authority_level_for_candidate(candidate),
        "condition_text": statement,
        "normalized_condition": normalize_condition(statement),
        "outcome_text": statement,
        "source_url": str(candidate.get("source_url") or "").strip(),
        "citation_text": str(candidate.get("citation_text") or "").strip(),
        "confidence_score": parse_float(candidate.get("confidence_score")),
        "executable_status": "needs_deterministic_mapping",
        "validation_status": "promotion_ready_requires_signed_ratification",
        "notes": [
            "Derived from Claude web promotion-ready candidate corpus only.",
            "Requires deterministic condition/outcome mapping before execution.",
            "Requires signed human ratification before executable export.",
        ],
    }
    return item


def classify_executable_rule_type(candidate: dict) -> str:
    raw = str(candidate.get("rule_unit_type") or candidate.get("rule_type") or "").strip()
    mapped = RULE_TYPE_ALIASES.get(raw, raw)
    statement = str(candidate.get("statement") or "").lower()
    program = str(candidate.get("program") or "").lower()
    if mapped in EXECUTABLE_RULE_TYPES:
        return mapped
    if "fraud" in statement or "abuse" in statement or program == "fraud_abuse":
        return "fraud_abuse_rule"
    if "appeal" in statement or "hearing" in statement:
        return "appeal_rule"
    if "deadline" in statement or re.search(r"\bwithin\s+\d+\s+(days|months|years)\b", statement):
        return "deadline_rule"
    if "verify" in statement or "verification" in statement:
        return "verification_rule"
    if "document" in statement or "record" in statement:
        return "documentation_rule"
    if "payment" in statement or "reimburse" in statement:
        return "payment_rule"
    if "provider" in statement:
        return "provider_rule"
    if "report" in statement or "submit" in statement:
        return "reporting_rule"
    if "eligible" in statement or "eligibility" in statement:
        return "eligibility_rule"
    return "other"


def authority_level_for_candidate(candidate: dict) -> str:
    jurisdiction = str(candidate.get("jurisdiction_level") or "").strip()
    source_type = str(candidate.get("source_type") or "").strip()
    if jurisdiction in {"federal", "state", "county", "city"}:
        return jurisdiction
    if source_type in {"statute", "regulation"}:
        return "legal_authority"
    if source_type:
        return "agency_authority"
    return "unknown"


def build_executable_summary(input_candidates: list[Any], executable: list[dict]) -> dict:
    by_rule_type = Counter(item["rule_type"] for item in executable)
    by_program = Counter(item["program"] for item in executable)
    verticals = {item["vertical"] for item in executable if item.get("vertical")}
    programs = {item["program"] for item in executable if item.get("program")}
    return {
        "input_candidates": len(input_candidates),
        "exported_candidates": len(executable),
        "programs_covered": len(programs),
        "verticals_covered": len(verticals),
        "by_rule_type": dict(sorted(by_rule_type.items())),
        "by_program": dict(sorted(by_program.items())),
        "warning": "Exported candidates required signed human ratification; deterministic condition/outcome mapping is still required before execution.",
    }


def write_executable_markdown(summary: dict, executable: list[dict]) -> str:
    lines = [
        "# Claude Web Executable Rule Candidates",
        "",
        f"- input_candidates: {summary['input_candidates']}",
        f"- exported_candidates: {summary['exported_candidates']}",
        f"- programs_covered: {summary['programs_covered']}",
        f"- verticals_covered: {summary['verticals_covered']}",
        "",
        summary["warning"],
        "",
        "## By Rule Type",
        "",
    ]
    for rule_type, count in summary["by_rule_type"].items():
        lines.append(f"- {rule_type}: {count}")
    lines.extend(["", "## By Program", ""])
    for program, count in summary["by_program"].items():
        lines.append(f"- {program}: {count}")
    lines.extend(["", "## Candidates", ""])
    for vertical, program_items in group_by_vertical_program(executable).items():
        lines.extend([f"### {vertical}", ""])
        for program, items in program_items.items():
            lines.extend([f"#### {program}", ""])
            for item in items:
                lines.extend(
                    [
                        f"- `{item['executable_rule_id']}` [{item['rule_type']}]",
                        f"  - condition: {item['condition_text']}",
                        f"  - source: {item['source_url']}",
                    ]
                )
    return "\n".join(lines)


def write_claude_web_proof_report(workdir: Path, confidence_threshold: float = 0.85) -> dict:
    source_path = workdir / "reports" / "claude_web_executable_rule_candidates.json"
    if not source_path.exists():
        raise FileNotFoundError(f"Claude web executable candidates not found: {source_path}")
    executable = read_json_list(source_path)
    report = build_claude_web_proof_report(executable, confidence_threshold)

    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "claude_web_programmatic_proof_report.json"
    markdown_path = reports_dir / "claude_web_programmatic_proof_report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_proof_markdown(report), encoding="utf-8")

    return {
        "programmatic_proof_report": str(json_path),
        "markdown": str(markdown_path),
        "summary": report["summary"],
        "verdict": "CLAUDE_WEB_PROOF_REPORT_READY",
    }


def build_claude_web_proof_report(executable: list[Any], confidence_threshold: float) -> dict:
    items = [item for item in executable if isinstance(item, dict)]
    programs = {str(item.get("program") or "") for item in items if item.get("program")}
    source_url_count = sum(1 for item in items if str(item.get("source_url") or "").strip())
    citation_count = sum(1 for item in items if str(item.get("citation_text") or "").strip())
    confident_count = sum(1 for item in items if parse_float(item.get("confidence_score")) >= confidence_threshold)
    all_programs = taxonomy_programs()
    missing_programs = [program for program in all_programs if program not in programs]
    return {
        "summary": {
            "total_claude_web_candidates": len(items),
            "executable_candidates_exported": len(items),
            "programs_covered": len(programs),
            "missing_programs": len(missing_programs),
            "citation_coverage_rate": safe_rate(citation_count, len(items)),
            "source_url_coverage_rate": safe_rate(source_url_count, len(items)),
            "confidence_threshold": confidence_threshold,
            "candidates_at_or_above_confidence_threshold": confident_count,
            "warning": "These candidates passed signed export ratification; deterministic condition/outcome mapping is still required before execution.",
        },
        "by_program": dict(sorted(Counter(str(item.get("program") or "unknown") for item in items).items())),
        "by_rule_type": dict(sorted(Counter(str(item.get("rule_type") or "unknown") for item in items).items())),
        "missing_programs": missing_programs,
    }


def write_proof_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Claude Web Programmatic Proof Report",
        "",
        f"- total_claude_web_candidates: {summary['total_claude_web_candidates']}",
        f"- executable_candidates_exported: {summary['executable_candidates_exported']}",
        f"- programs_covered: {summary['programs_covered']}",
        f"- missing_programs: {summary['missing_programs']}",
        f"- citation_coverage_rate: {summary['citation_coverage_rate']}",
        f"- source_url_coverage_rate: {summary['source_url_coverage_rate']}",
        f"- confidence_threshold: {summary['confidence_threshold']}",
        f"- candidates_at_or_above_confidence_threshold: {summary['candidates_at_or_above_confidence_threshold']}",
        "",
        summary["warning"],
        "",
        "## By Program",
        "",
    ]
    for program, count in report["by_program"].items():
        lines.append(f"- {program}: {count}")
    lines.extend(["", "## Missing Programs", ""])
    for program in report["missing_programs"]:
        lines.append(f"- {program}")
    return "\n".join(lines)


def group_by_vertical_program(items: list[dict]) -> dict[str, dict[str, list[dict]]]:
    grouped: dict[str, dict[str, list[dict]]] = {}
    for item in items:
        vertical = str(item.get("vertical") or "unknown")
        program = str(item.get("program") or "unknown")
        grouped.setdefault(vertical, {}).setdefault(program, []).append(item)
    return grouped


def executable_rule_id(source_candidate_id: str, statement: str) -> str:
    digest = hashlib.sha256(f"{source_candidate_id}|{normalize_condition(statement)}".encode("utf-8")).hexdigest()[:24]
    return f"exec:{digest}"


def candidate_fallback_id(candidate: dict) -> str:
    parts = [
        str(candidate.get("program") or ""),
        str(candidate.get("rule_unit_type") or candidate.get("rule_type") or ""),
        str(candidate.get("source_url") or ""),
        normalize_condition(str(candidate.get("statement") or "")),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"claude-web:{digest}"


def normalize_condition(text: str) -> str:
    lowered = text.lower()
    lowered = re.sub(r"[^a-z0-9]+", " ", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def safe_rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def parse_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def read_json_list(path: Path) -> list[Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    return []
