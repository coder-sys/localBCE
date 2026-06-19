from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .agent_discovery import PROGRAM_OFFICIAL_ENTRYPOINTS, source_allowed
from .claude_web_executable import EXECUTABLE_RULE_TYPES, normalize_condition, parse_float, read_json_list
from .domain import vertical_for_program


VAGUE_TERMS = [
    "generally",
    "typically",
    "may",
    "approximately",
    "varies",
    "can",
    "should",
    "as applicable",
]

DETERMINISTIC_SIGNALS = [
    "must",
    "shall",
    "required",
    "prohibited",
    "eligible",
    "ineligible",
    "within",
    "before",
    "after",
    "not",
    "no later than",
]


def write_claude_web_audit(workdir: Path) -> dict:
    source_path = workdir / "reports" / "claude_web_executable_rule_candidates.json"
    if not source_path.exists():
        raise FileNotFoundError(f"Claude web executable candidates not found: {source_path}")
    candidates = read_json_list(source_path)
    report = build_claude_web_audit(candidates)

    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    audit_path = reports_dir / "claude_web_audit.json"
    summary_path = reports_dir / "claude_web_audit_summary.json"
    markdown_path = reports_dir / "claude_web_audit.md"
    audit_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    summary_path.write_text(json.dumps(report["summary"], indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_audit_markdown(report), encoding="utf-8")

    return {
        "audit": str(audit_path),
        "summary": str(summary_path),
        "markdown": str(markdown_path),
        "input_candidates": report["summary"]["input_candidates"],
        "clean_candidates": report["summary"]["clean_candidates"],
        "needs_mapping_candidates": report["summary"]["needs_mapping_candidates"],
        "audit_attention_candidates": report["summary"]["audit_attention_candidates"],
        "by_issue": report["summary"]["by_issue"],
        "verdict": "CLAUDE_WEB_AUDIT_READY",
    }


def build_claude_web_audit(raw_candidates: list[Any]) -> dict:
    candidates = [candidate for candidate in raw_candidates if isinstance(candidate, dict)]
    exact_duplicate_groups = duplicate_groups(candidates)
    near_duplicate_ids = near_duplicate_candidate_ids(candidates)
    source_counts = Counter(normalize_source_url(candidate.get("source_url")) for candidate in candidates)
    concentrated_sources = {
        source
        for source, count in source_counts.items()
        if source and count >= max(10, int(len(candidates) * 0.10))
    }

    audited = [
        audit_candidate(candidate, exact_duplicate_groups, near_duplicate_ids, concentrated_sources)
        for candidate in candidates
    ]
    summary = build_audit_summary(audited, len(candidates), concentrated_sources)
    return {
        "summary": summary,
        "candidates": audited,
        "concentrated_sources": sorted(concentrated_sources),
        "warning": "Audit results are deterministic quality checks over promotion-ready candidates; they are not legal verification.",
    }


def audit_candidate(
    candidate: dict,
    exact_duplicate_groups: dict[str, list[str]],
    near_duplicate_ids: set[str],
    concentrated_sources: set[str],
) -> dict:
    item = dict(candidate)
    issues: list[str] = []
    warnings: list[str] = []
    candidate_id = str(item.get("executable_rule_id") or item.get("source_candidate_id") or "")
    condition = str(item.get("condition_text") or "").strip()
    outcome = str(item.get("outcome_text") or "").strip()
    normalized = str(item.get("normalized_condition") or normalize_condition(condition))
    citation = str(item.get("citation_text") or "").strip()
    source_url = str(item.get("source_url") or "").strip()
    program = str(item.get("program") or "").strip()
    vertical = str(item.get("vertical") or "").strip()
    rule_type = str(item.get("rule_type") or "").strip()
    source = normalize_source_url(source_url)

    if not condition or len(condition) < 40:
        issues.append("condition_missing_or_too_short")
    if not outcome or outcome == condition:
        warnings.append("needs_deterministic_condition_outcome_split")
    if rule_type not in EXECUTABLE_RULE_TYPES:
        issues.append("rule_type_not_allowed")
    if vertical_for_program(program) and vertical != vertical_for_program(program):
        issues.append("program_vertical_mismatch")
    if not source_url:
        issues.append("source_url_missing")
    elif not source_allowed(source_url, official_only=True)[0]:
        issues.append("source_url_not_official_allowed")
    elif source_domain_unexpected_for_program(source_url, program):
        warnings.append("unexpected_program_source_domain")
    if not citation or len(citation) < 40:
        issues.append("citation_text_weak_or_missing")
    if parse_float(item.get("confidence_score")) < 0.85:
        issues.append("confidence_below_threshold")
    if normalized in exact_duplicate_groups and len(exact_duplicate_groups[normalized]) > 1:
        warnings.append("exact_duplicate_statement")
    if candidate_id in near_duplicate_ids:
        warnings.append("near_duplicate_statement")
    if source in concentrated_sources:
        warnings.append("source_overconcentration")
    if vague_wording(condition):
        warnings.append("vague_or_qualified_wording")
    if not deterministic_wording(condition):
        warnings.append("weak_deterministic_signal")

    if issues:
        audit_status = "audit_attention_required"
    elif warnings:
        audit_status = "needs_mapping_review"
    else:
        audit_status = "clean_candidate"

    item["audit_status"] = audit_status
    item["audit_issues"] = issues
    item["audit_warnings"] = sorted(set(warnings))
    item["audit_note"] = "Deterministic audit only; not legal verification."
    return item


def build_audit_summary(audited: list[dict], input_count: int, concentrated_sources: set[str]) -> dict:
    by_issue: Counter[str] = Counter()
    by_warning: Counter[str] = Counter()
    by_status = Counter(item["audit_status"] for item in audited)
    by_program = Counter(str(item.get("program") or "unknown") for item in audited)
    for item in audited:
        by_issue.update(item.get("audit_issues", []))
        by_warning.update(item.get("audit_warnings", []))
    return {
        "input_candidates": input_count,
        "audited_candidates": len(audited),
        "clean_candidates": by_status.get("clean_candidate", 0),
        "needs_mapping_candidates": by_status.get("needs_mapping_review", 0),
        "audit_attention_candidates": by_status.get("audit_attention_required", 0),
        "by_audit_status": dict(sorted(by_status.items())),
        "by_issue": dict(sorted(by_issue.items())),
        "by_warning": dict(sorted(by_warning.items())),
        "by_program": dict(sorted(by_program.items())),
        "concentrated_source_count": len(concentrated_sources),
        "warning": "Promotion-ready candidates still require deterministic mapping and legal review before production execution.",
    }


def duplicate_groups(candidates: list[dict]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for candidate in candidates:
        normalized = str(candidate.get("normalized_condition") or normalize_condition(str(candidate.get("condition_text") or "")))
        candidate_id = str(candidate.get("executable_rule_id") or candidate.get("source_candidate_id") or "")
        if normalized:
            groups.setdefault(normalized, []).append(candidate_id)
    return groups


def near_duplicate_candidate_ids(candidates: list[dict]) -> set[str]:
    ids: set[str] = set()
    tokenized = [
        (
            str(candidate.get("executable_rule_id") or candidate.get("source_candidate_id") or ""),
            set(str(candidate.get("normalized_condition") or "").split()),
        )
        for candidate in candidates
    ]
    for index, (left_id, left_tokens) in enumerate(tokenized):
        if len(left_tokens) < 6:
            continue
        for right_id, right_tokens in tokenized[index + 1 :]:
            if len(right_tokens) < 6:
                continue
            score = jaccard(left_tokens, right_tokens)
            if score >= 0.9:
                ids.add(left_id)
                ids.add(right_id)
    return ids


def source_domain_unexpected_for_program(source_url: str, program: str) -> bool:
    expected = expected_domains_for_program(program)
    if not expected:
        return False
    host = urlparse(source_url).netloc.lower().removeprefix("www.")
    return not any(host == domain or host.endswith(f".{domain}") for domain in expected)


def expected_domains_for_program(program: str) -> set[str]:
    urls = PROGRAM_OFFICIAL_ENTRYPOINTS.get(program, [])
    domains: set[str] = set()
    for url in urls:
        host = urlparse(url).netloc.lower().removeprefix("www.")
        if host:
            domains.add(host)
    return domains


def vague_wording(text: str) -> bool:
    lowered = text.lower()
    return any(re.search(rf"\b{re.escape(term)}\b", lowered) for term in VAGUE_TERMS)


def deterministic_wording(text: str) -> bool:
    lowered = text.lower()
    return any(signal in lowered for signal in DETERMINISTIC_SIGNALS)


def normalize_source_url(value: object) -> str:
    return str(value or "").strip().lower()


def jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def write_audit_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Claude Web Audit",
        "",
        f"- input_candidates: {summary['input_candidates']}",
        f"- audited_candidates: {summary['audited_candidates']}",
        f"- clean_candidates: {summary['clean_candidates']}",
        f"- needs_mapping_candidates: {summary['needs_mapping_candidates']}",
        f"- audit_attention_candidates: {summary['audit_attention_candidates']}",
        f"- concentrated_source_count: {summary['concentrated_source_count']}",
        "",
        summary["warning"],
        "",
        "## Issues",
        "",
    ]
    if summary["by_issue"]:
        for issue, count in summary["by_issue"].items():
            lines.append(f"- {issue}: {count}")
    else:
        lines.append("- none")
    lines.extend(["", "## Warnings", ""])
    if summary["by_warning"]:
        for warning, count in summary["by_warning"].items():
            lines.append(f"- {warning}: {count}")
    else:
        lines.append("- none")
    lines.extend(["", "## By Program", ""])
    for program, count in summary["by_program"].items():
        lines.append(f"- {program}: {count}")
    attention = [item for item in report["candidates"] if item["audit_status"] == "audit_attention_required"]
    mapping = [item for item in report["candidates"] if item["audit_status"] == "needs_mapping_review"]
    lines.extend(["", "## Audit Attention Sample", ""])
    if attention:
        for item in attention[:50]:
            lines.extend(candidate_lines(item, include_issues=True))
    else:
        lines.append("- none")
    lines.extend(["", "## Mapping Review Sample", ""])
    for item in mapping[:50]:
        lines.extend(candidate_lines(item, include_issues=False))
    return "\n".join(lines)


def candidate_lines(item: dict, include_issues: bool) -> list[str]:
    details = [
        f"### {item.get('program')} / {item.get('rule_type')}",
        "",
        f"- id: {item.get('executable_rule_id')}",
        f"- status: {item.get('audit_status')}",
        f"- warnings: {', '.join(item.get('audit_warnings', [])) or 'none'}",
        f"- condition: {item.get('condition_text')}",
        f"- source: {item.get('source_url')}",
        "",
    ]
    if include_issues:
        details.insert(4, f"- issues: {', '.join(item.get('audit_issues', [])) or 'none'}")
    return details
