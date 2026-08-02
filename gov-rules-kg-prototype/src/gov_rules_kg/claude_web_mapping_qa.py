from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .claude_web_executable import read_json_list


THRESHOLD_EXPECTED_RULE_TYPES = {
    "deadline_rule",
    "payment_rule",
}


def write_claude_web_mapping_qa(workdir: Path) -> dict:
    source_path = workdir / "reports" / "claude_web_deterministic_mapping_candidates.json"
    if not source_path.exists():
        raise FileNotFoundError(f"Claude web deterministic mapping candidates not found: {source_path}")
    candidates = read_json_list(source_path)
    report = build_mapping_qa(candidates)

    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "claude_web_mapping_qa.json"
    markdown_path = reports_dir / "claude_web_mapping_qa.md"
    summary_path = reports_dir / "claude_web_mapping_qa_summary.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    summary_path.write_text(json.dumps(report["summary"], indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_mapping_qa_markdown(report), encoding="utf-8")

    return {
        "mapping_qa": str(json_path),
        "summary": str(summary_path),
        "markdown": str(markdown_path),
        "input_candidates": report["summary"]["input_candidates"],
        "qa_attention_candidates": report["summary"]["qa_attention_candidates"],
        "by_issue": report["summary"]["by_issue"],
        "next_fix_buckets": report["summary"]["next_fix_buckets"],
        "verdict": "CLAUDE_WEB_MAPPING_QA_READY",
    }


def build_mapping_qa(raw_candidates: list[Any]) -> dict:
    candidates = [candidate for candidate in raw_candidates if isinstance(candidate, dict)]
    reviewed = [qa_mapping_candidate(candidate) for candidate in candidates]
    summary = build_mapping_qa_summary(reviewed, len(candidates))
    return {
        "summary": summary,
        "candidates": reviewed,
        "warning": "Mapping QA identifies deterministic mapping weaknesses; it is not legal verification.",
    }


def qa_mapping_candidate(candidate: dict) -> dict:
    item = dict(candidate)
    issues: list[str] = []
    operator = str(item.get("operator") or "")
    mapping_status = str(item.get("mapping_status") or "")
    rule_type = str(item.get("rule_type") or "")
    threshold = item.get("threshold")
    inputs_required = item.get("inputs_required") if isinstance(item.get("inputs_required"), list) else []
    exception_text = str(item.get("exception_text") or "").strip()

    if operator == "unknown":
        issues.append("operator_unknown")
    if mapping_status == "needs_manual_mapping":
        issues.append("needs_manual_mapping")
    if mapping_status == "partial_mapping_candidate":
        issues.append("partial_mapping_candidate")
    if not inputs_required:
        issues.append("missing_inputs_required")
    expects_threshold = threshold_expected(rule_type, str(item.get("condition_text") or ""))
    if expects_threshold and not threshold:
        issues.append("expected_threshold_missing")
    if exception_text and malformed_exception_text(exception_text):
        issues.append("malformed_exception_text")
    if operator == "deadline" and expects_threshold and not threshold:
        issues.append("deadline_operator_without_threshold")
    if operator == "payment" and expects_threshold and not threshold:
        issues.append("payment_operator_without_threshold")

    item["qa_status"] = "qa_attention_required" if issues else "qa_pass"
    item["qa_issues"] = sorted(set(issues))
    item["qa_recommended_fix"] = recommended_fix(item["qa_issues"])
    return item


def threshold_expected(rule_type: str, condition_text: str) -> bool:
    if rule_type == "deadline_rule":
        return True
    if rule_type != "payment_rule":
        return False
    lowered = condition_text.lower()
    if any(term in lowered for term in ["%", "$", "equal amount", "mid-"]):
        return True
    numeric_amount = re.search(
        r"\b\d+(?:\.\d+)?\s*(?:cents?|dollars?|days?|months?|years?)\b",
        lowered,
    )
    word_amount = re.search(
        r"\b(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s+(?:cents?|dollars?)\b",
        lowered,
    )
    return numeric_amount is not None or word_amount is not None


def build_mapping_qa_summary(reviewed: list[dict], input_count: int) -> dict:
    by_issue: Counter[str] = Counter()
    by_status = Counter(str(item.get("qa_status") or "unknown") for item in reviewed)
    by_program = Counter(str(item.get("program") or "unknown") for item in reviewed)
    by_operator = Counter(str(item.get("operator") or "unknown") for item in reviewed)
    for item in reviewed:
        by_issue.update(item.get("qa_issues", []))
    return {
        "input_candidates": input_count,
        "qa_pass_candidates": by_status.get("qa_pass", 0),
        "qa_attention_candidates": by_status.get("qa_attention_required", 0),
        "by_qa_status": dict(sorted(by_status.items())),
        "by_issue": dict(sorted(by_issue.items())),
        "by_program": dict(sorted(by_program.items())),
        "by_operator": dict(sorted(by_operator.items())),
        "next_fix_buckets": next_fix_buckets(by_issue),
        "warning": "QA pass does not mean legal verification; it means no deterministic mapping weakness was detected by this gate.",
    }


def next_fix_buckets(by_issue: Counter[str]) -> list[dict]:
    priorities = [
        ("operator_unknown", "Add operator inference patterns for unknown statements."),
        ("malformed_exception_text", "Tighten exception clause boundary extraction."),
        ("expected_threshold_missing", "Improve numeric/date threshold extraction for deadline and payment rules."),
        ("deadline_operator_without_threshold", "Add deadline phrase parsing for date windows."),
        ("payment_operator_without_threshold", "Add payment amount, percentage, premium, and refund parsers."),
        ("missing_inputs_required", "Expand input keyword taxonomy."),
        ("needs_manual_mapping", "Review low-confidence mappings manually or add new rule-specific parsers."),
        ("partial_mapping_candidate", "Improve parser coverage enough to promote partial mappings."),
    ]
    buckets: list[dict] = []
    for issue, recommendation in priorities:
        count = by_issue.get(issue, 0)
        if count:
            buckets.append({"issue": issue, "count": count, "recommended_fix": recommendation})
    return buckets


def recommended_fix(issues: list[str]) -> str:
    if "operator_unknown" in issues:
        return "Add or refine operator inference for this statement family."
    if "malformed_exception_text" in issues:
        return "Tighten exception extraction so only the exception clause is captured."
    if "expected_threshold_missing" in issues or "deadline_operator_without_threshold" in issues or "payment_operator_without_threshold" in issues:
        return "Improve threshold extraction for this deadline/payment rule."
    if "missing_inputs_required" in issues:
        return "Add input keyword coverage for the fields this rule depends on."
    if "needs_manual_mapping" in issues:
        return "Manual review required before deterministic execution."
    if "partial_mapping_candidate" in issues:
        return "Add parser coverage to promote this partial mapping."
    return "No deterministic mapping QA issue detected."


def malformed_exception_text(exception_text: str) -> bool:
    text = exception_text.strip()
    if not text:
        return False
    if ")" in text and "(" not in text:
        return True
    word_count = len(re.findall(r"\b\w+\b", text))
    if word_count > 25:
        return True
    trailing_verbs = [
        " are automatically ",
        " is automatically ",
        " must ",
        " may ",
        " shall ",
        " will ",
    ]
    return any(token in f" {text.lower()} " for token in trailing_verbs)


def write_mapping_qa_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Claude Web Mapping QA",
        "",
        f"- input_candidates: {summary['input_candidates']}",
        f"- qa_pass_candidates: {summary['qa_pass_candidates']}",
        f"- qa_attention_candidates: {summary['qa_attention_candidates']}",
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
    lines.extend(["", "## Next Fix Buckets", ""])
    for bucket in summary["next_fix_buckets"]:
        lines.append(f"- {bucket['issue']} ({bucket['count']}): {bucket['recommended_fix']}")
    lines.extend(["", "## Attention Sample", ""])
    attention = [item for item in report["candidates"] if item["qa_status"] == "qa_attention_required"]
    for item in attention[:80]:
        lines.extend(mapping_qa_item_lines(item))
    return "\n".join(lines)


def mapping_qa_item_lines(item: dict) -> list[str]:
    return [
        f"### {item.get('program')} / {item.get('rule_type')}",
        "",
        f"- id: {item.get('mapping_candidate_id')}",
        f"- issues: {', '.join(item.get('qa_issues', [])) or 'none'}",
        f"- recommended_fix: {item.get('qa_recommended_fix')}",
        f"- operator: {item.get('operator')}",
        f"- status: {item.get('mapping_status')}",
        f"- exception_text: {item.get('exception_text') or 'none'}",
        f"- threshold: {json.dumps(item.get('threshold'), sort_keys=True) if item.get('threshold') else 'none'}",
        f"- inputs_required: {', '.join(item.get('inputs_required', [])) or 'none'}",
        f"- condition: {item.get('condition_text')}",
        "",
    ]
