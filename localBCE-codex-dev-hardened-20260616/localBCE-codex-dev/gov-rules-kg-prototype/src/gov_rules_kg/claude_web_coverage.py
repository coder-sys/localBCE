from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .claude_web_review import preferred_candidate_source_path, review_candidate
from .domain import GOVERNMENT_RULE_TAXONOMY, vertical_for_program


def write_claude_web_coverage(workdir: Path, batch_size: int = 5, min_confidence: float = 0.85) -> dict:
    report = build_claude_web_coverage(workdir, batch_size, min_confidence)
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "claude_web_coverage.json"
    markdown_path = reports_dir / "claude_web_coverage.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_coverage_markdown(report), encoding="utf-8")
    return {
        "claude_web_coverage": str(json_path),
        "markdown": str(markdown_path),
        "summary": report["summary"],
        "verdict": "CLAUDE_WEB_COVERAGE_READY",
    }


def build_claude_web_coverage(workdir: Path, batch_size: int = 5, min_confidence: float = 0.85) -> dict:
    source_path = preferred_candidate_source_path(workdir)
    payload = read_json_if_exists(source_path, {})
    candidates = payload.get("candidate_rules", []) if isinstance(payload, dict) else []
    if not isinstance(candidates, list):
        candidates = []

    reviewed = [review_candidate(candidate, min_confidence) for candidate in candidates if isinstance(candidate, dict)]
    promotion_ready = [item for item in reviewed if item["review_status"] == "promotion_ready"]
    programs = taxonomy_programs()
    candidates_per_program = count_by_program(reviewed)
    promotion_ready_per_program = count_by_program(promotion_ready)
    missing_programs = [program for program in programs if candidates_per_program.get(program, 0) == 0]
    missing_promotion_ready_programs = [program for program in programs if promotion_ready_per_program.get(program, 0) == 0]
    program_rows = [
        {
            "vertical": vertical_for_program(program),
            "program": program,
            "candidates": candidates_per_program.get(program, 0),
            "promotion_ready": promotion_ready_per_program.get(program, 0),
        }
        for program in programs
    ]

    return {
        "source_report": str(source_path),
        "summary": {
            "taxonomy_programs_total": len(programs),
            "total_candidates": len(reviewed),
            "promotion_ready_candidates": len(promotion_ready),
            "programs_with_candidates": sum(1 for program in programs if candidates_per_program.get(program, 0) > 0),
            "programs_with_promotion_ready": sum(1 for program in programs if promotion_ready_per_program.get(program, 0) > 0),
            "missing_programs": len(missing_programs),
            "missing_promotion_ready_programs": len(missing_promotion_ready_programs),
            "minimum_confidence_score": min_confidence,
            "verification_note": "Promotion-ready candidates are not verified rules; they passed source/citation/evidence sanity checks only.",
        },
        "programs": program_rows,
        "candidates_per_program": {program: candidates_per_program.get(program, 0) for program in programs},
        "promotion_ready_per_program": {program: promotion_ready_per_program.get(program, 0) for program in programs},
        "missing_programs": missing_programs,
        "missing_promotion_ready_programs": missing_promotion_ready_programs,
        "next_recommended_claude_web_batches": recommended_batches(missing_promotion_ready_programs, batch_size),
    }


def taxonomy_programs() -> list[str]:
    programs: list[str] = []
    for vertical_programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].values():
        programs.extend(vertical_programs)
    return programs


def count_by_program(candidates: list[dict]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for candidate in candidates:
        program = str(candidate.get("program") or "").strip()
        if program:
            counts[program] += 1
    return counts


def recommended_batches(missing_programs: list[str], batch_size: int) -> list[dict]:
    size = max(1, batch_size)
    batches: list[dict] = []
    for index in range(0, len(missing_programs), size):
        programs = missing_programs[index : index + size]
        batches.append(
            {
                "batch_index": len(batches) + 1,
                "programs": programs,
                "command": (
                    "python -m gov_rules_kg.main claude-web-research "
                    "--ai-provider claude "
                    "--claude-model claude-sonnet-4-6 "
                    f"--programs {','.join(programs)} "
                    f"--batch-size {size} "
                    "--max-uses 10 "
                    "--max-candidates-per-branch 2 "
                    "--timeout-seconds 300 "
                    "--retries 1"
                ),
            }
        )
    return batches


def write_coverage_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Claude Web Coverage",
        "",
        f"- taxonomy_programs_total: {summary['taxonomy_programs_total']}",
        f"- total_candidates: {summary['total_candidates']}",
        f"- promotion_ready_candidates: {summary['promotion_ready_candidates']}",
        f"- programs_with_candidates: {summary['programs_with_candidates']}",
        f"- programs_with_promotion_ready: {summary['programs_with_promotion_ready']}",
        f"- missing_programs: {summary['missing_programs']}",
        f"- missing_promotion_ready_programs: {summary['missing_promotion_ready_programs']}",
        "",
        summary["verification_note"],
        "",
        "## Program Coverage",
        "",
        "| vertical | program | candidates | promotion_ready |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in report["programs"]:
        lines.append(f"| {row['vertical']} | {row['program']} | {row['candidates']} | {row['promotion_ready']} |")
    lines.extend(["", "## Missing Programs", ""])
    for program in report["missing_programs"]:
        lines.append(f"- {program}")
    lines.extend(["", "## Missing Promotion-Ready Programs", ""])
    for program in report["missing_promotion_ready_programs"]:
        lines.append(f"- {program}")
    lines.extend(["", "## Next Recommended Claude Web Batches", ""])
    for batch in report["next_recommended_claude_web_batches"]:
        lines.extend(
            [
                f"### Batch {batch['batch_index']}",
                "",
                f"- programs: {', '.join(batch['programs'])}",
                "",
                "```bash",
                batch["command"],
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def read_json_if_exists(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))
