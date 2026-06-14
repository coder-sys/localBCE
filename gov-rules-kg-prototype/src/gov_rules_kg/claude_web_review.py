from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from .agent_discovery import source_allowed
from .domain import RULE_UNIT_TYPES, SOURCE_TYPES, valid_program, valid_vertical, vertical_for_program


def review_claude_web_candidates(workdir: Path, min_confidence: float = 0.85) -> dict:
    source_path = preferred_candidate_source_path(workdir)
    if not source_path.exists():
        raise FileNotFoundError(f"Claude web research report not found: {source_path}")
    report = json.loads(source_path.read_text(encoding="utf-8"))
    candidates = report.get("candidate_rules", [])
    if not isinstance(candidates, list):
        candidates = []

    reviewed = [review_candidate(candidate, min_confidence) for candidate in candidates if isinstance(candidate, dict)]
    promotion_ready = [item for item in reviewed if item["review_status"] == "promotion_ready"]
    human_review = [item for item in reviewed if item["review_status"] != "promotion_ready"]
    hierarchy = group_reviewed_by_hierarchy(reviewed)
    summary = build_review_summary(reviewed, promotion_ready, human_review, min_confidence)
    summary["source_report"] = str(source_path)

    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    review_path = reports_dir / "claude_web_candidate_review.json"
    ready_path = reports_dir / "claude_web_promotion_ready.json"
    queue_path = reports_dir / "claude_web_human_review_queue.json"
    hierarchy_path = reports_dir / "claude_web_hierarchy_report.json"
    markdown_path = reports_dir / "claude_web_candidate_review.md"

    write_json(review_path, {"summary": summary, "candidates": reviewed})
    write_json(ready_path, promotion_ready)
    write_json(queue_path, human_review)
    write_json(hierarchy_path, hierarchy)
    markdown_path.write_text(write_review_markdown(summary, promotion_ready, human_review, hierarchy), encoding="utf-8")

    return {
        "candidate_review": str(review_path),
        "promotion_ready": str(ready_path),
        "human_review_queue": str(queue_path),
        "hierarchy_report": str(hierarchy_path),
        "markdown": str(markdown_path),
        "summary": summary,
        "verdict": "CLAUDE_WEB_REVIEW_READY",
    }


def preferred_candidate_source_path(workdir: Path) -> Path:
    corpus_path = workdir / "reports" / "claude_web_candidate_corpus.json"
    if corpus_path.exists():
        return corpus_path
    return workdir / "reports" / "claude_web_research.json"


def review_candidate(candidate: dict, min_confidence: float) -> dict:
    item = dict(candidate)
    issues: list[str] = []
    source_url = str(item.get("source_url") or "").strip()
    citation_text = str(item.get("citation_text") or "").strip()
    statement = str(item.get("statement") or "").strip()
    confidence = parse_float(item.get("confidence_score"))
    vertical = valid_vertical(item.get("vertical"))
    program = valid_program(item.get("program"))
    rule_unit_type = str(item.get("rule_unit_type") or "").strip()
    source_type = str(item.get("source_type") or "").strip()

    if not statement or len(statement) < 40:
        issues.append("statement_missing_or_too_short")
    if not source_url:
        issues.append("source_url_missing")
    elif not source_allowed(source_url, official_only=True)[0]:
        issues.append("source_url_not_official_allowed")
    elif urlparse(source_url).scheme not in {"https", "http"}:
        issues.append("source_url_invalid_scheme")
    if not citation_text or len(citation_text) < 25:
        issues.append("citation_text_missing_or_too_short")
    if confidence < min_confidence:
        issues.append("confidence_below_threshold")
    if not vertical:
        issues.append("vertical_invalid")
    if not program:
        issues.append("program_invalid")
    elif vertical and vertical_for_program(program) != vertical:
        issues.append("program_vertical_mismatch")
    if rule_unit_type not in RULE_UNIT_TYPES:
        issues.append("rule_unit_type_invalid")
    if source_type not in SOURCE_TYPES:
        issues.append("source_type_invalid")

    item["confidence_score"] = confidence
    item["review_issues"] = issues
    item["review_status"] = "promotion_ready" if not issues else "human_review_required"
    item["promotion_status"] = "candidate_only_not_verified"
    return item


def group_reviewed_by_hierarchy(candidates: list[dict]) -> dict:
    hierarchy: dict = {}
    for item in candidates:
        domain = str(item.get("domain") or "government_transaction_rules")
        vertical = str(item.get("vertical") or "unknown")
        program = str(item.get("program") or "unknown")
        jurisdiction = str(item.get("jurisdiction_level") or "unknown")
        source_type = str(item.get("source_type") or "unknown")
        rule_unit_type = str(item.get("rule_unit_type") or "unknown")
        hierarchy.setdefault(domain, {}).setdefault(vertical, {}).setdefault(program, {}).setdefault(jurisdiction, {}).setdefault(source_type, {}).setdefault(rule_unit_type, []).append(item)
    return hierarchy


def build_review_summary(reviewed: list[dict], promotion_ready: list[dict], human_review: list[dict], min_confidence: float) -> dict:
    by_program = Counter(str(item.get("program") or "unknown") for item in reviewed)
    by_status = Counter(str(item.get("review_status") or "unknown") for item in reviewed)
    by_issue: Counter[str] = Counter()
    for item in reviewed:
        by_issue.update(item.get("review_issues", []))
    return {
        "total_candidates": len(reviewed),
        "promotion_ready_candidates": len(promotion_ready),
        "human_review_required": len(human_review),
        "minimum_confidence_score": min_confidence,
        "by_program": dict(sorted(by_program.items())),
        "by_review_status": dict(sorted(by_status.items())),
        "by_issue": dict(sorted(by_issue.items())),
        "verification_note": "Promotion-ready candidates are not verified rules; they passed source/citation/evidence sanity checks only.",
    }


def write_review_markdown(summary: dict, promotion_ready: list[dict], human_review: list[dict], _hierarchy: dict) -> str:
    lines = [
        "# Claude Web Candidate Review",
        "",
        f"- total_candidates: {summary['total_candidates']}",
        f"- promotion_ready_candidates: {summary['promotion_ready_candidates']}",
        f"- human_review_required: {summary['human_review_required']}",
        f"- minimum_confidence_score: {summary['minimum_confidence_score']}",
        "",
        "Promotion-ready candidates are not verified rules. They passed source/citation/evidence sanity checks only.",
        "",
        "## By Program",
    ]
    for program, count in summary["by_program"].items():
        lines.append(f"- {program}: {count}")
    if summary["by_issue"]:
        lines.extend(["", "## Issues", ""])
        for issue, count in summary["by_issue"].items():
            lines.append(f"- {issue}: {count}")
    lines.extend(["", "## Promotion Ready Sample", ""])
    for item in promotion_ready[:50]:
        lines.extend(
            [
                f"### {item.get('program')} / {item.get('rule_unit_type')}",
                "",
                f"- statement: {item.get('statement')}",
                f"- source: {item.get('source_url')}",
                f"- citation_text: {item.get('citation_text')}",
                "",
            ]
        )
    if human_review:
        lines.extend(["", "## Human Review Sample", ""])
        for item in human_review[:50]:
            lines.extend(
                [
                    f"### {item.get('program')} / {item.get('rule_unit_type')}",
                    "",
                    f"- issues: {', '.join(item.get('review_issues', []))}",
                    f"- statement: {item.get('statement')}",
                    f"- source: {item.get('source_url')}",
                    "",
                ]
            )
    return "\n".join(lines)


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def parse_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
