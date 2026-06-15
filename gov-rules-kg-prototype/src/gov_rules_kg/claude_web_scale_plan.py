from __future__ import annotations

import json
from pathlib import Path

from .claude_web_coverage import taxonomy_programs
from .domain import SOURCE_TYPES, vertical_for_program


DEFAULT_JURISDICTIONS = ["federal", "state_ca", "state_tx", "state_ny", "state_fl"]
DEFAULT_SOURCE_TYPES = [
    "statute",
    "regulation",
    "agency_guidance",
    "manual",
    "bulletin_letter",
    "form_instruction",
    "court_administrative_decision",
    "faq_public_guidance",
]


def write_claude_web_scale_plan(
    workdir: Path,
    target_candidates_per_branch: int = 10,
    batch_size: int = 5,
    jurisdictions: list[str] | None = None,
    source_types: list[str] | None = None,
    max_batches: int = 0,
) -> dict:
    plan = build_claude_web_scale_plan(
        target_candidates_per_branch=target_candidates_per_branch,
        batch_size=batch_size,
        jurisdictions=jurisdictions,
        source_types=source_types,
        max_batches=max_batches,
    )
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "claude_web_scale_plan.json"
    markdown_path = reports_dir / "claude_web_scale_plan.md"
    commands_path = reports_dir / "claude_web_scale_commands.sh"
    json_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_scale_plan_markdown(plan), encoding="utf-8")
    commands_path.write_text(write_scale_commands(plan), encoding="utf-8")
    return {
        "scale_plan": str(json_path),
        "markdown": str(markdown_path),
        "commands": str(commands_path),
        "summary": plan["summary"],
        "verdict": "CLAUDE_WEB_SCALE_PLAN_READY",
    }


def build_claude_web_scale_plan(
    target_candidates_per_branch: int = 10,
    batch_size: int = 5,
    jurisdictions: list[str] | None = None,
    source_types: list[str] | None = None,
    max_batches: int = 0,
) -> dict:
    jurisdiction_targets = jurisdictions or DEFAULT_JURISDICTIONS
    source_type_targets = source_types or DEFAULT_SOURCE_TYPES
    programs = taxonomy_programs()
    branches = [
        {
            "branch_id": f"{program}:{jurisdiction}:{source_type}",
            "vertical": vertical_for_program(program),
            "program": program,
            "jurisdiction": jurisdiction,
            "source_type": source_type,
            "target_candidates": target_candidates_per_branch,
            "priority": branch_priority(jurisdiction, source_type),
        }
        for program in programs
        for jurisdiction in jurisdiction_targets
        for source_type in source_type_targets
    ]
    branches.sort(key=lambda item: (item["priority"], item["vertical"], item["program"], item["jurisdiction"], item["source_type"]))
    batches = build_batches(branches, batch_size, target_candidates_per_branch)
    if max_batches > 0:
        batches = batches[:max_batches]
    planned_branches = sum(len(batch["branches"]) for batch in batches)
    planned_candidate_slots = sum(branch["target_candidates"] for batch in batches for branch in batch["branches"])
    return {
        "mode": "claude_web_scale_plan_no_fetch_no_ai_call",
        "summary": {
            "taxonomy_programs": len(programs),
            "jurisdictions": len(jurisdiction_targets),
            "source_types": len(source_type_targets),
            "total_possible_branches": len(branches),
            "planned_batches": len(batches),
            "planned_branches": planned_branches,
            "target_candidates_per_branch": target_candidates_per_branch,
            "planned_candidate_slots": planned_candidate_slots,
            "estimated_claude_calls": len(batches),
            "warning": "This is an expansion plan only. It does not create verified rules or call Claude.",
        },
        "jurisdictions": jurisdiction_targets,
        "source_types": source_type_targets,
        "batches": batches,
    }


def build_batches(branches: list[dict], batch_size: int, target_candidates_per_branch: int) -> list[dict]:
    size = max(1, batch_size)
    batches: list[dict] = []
    grouped: dict[tuple[str, str], list[dict]] = {}
    for branch in branches:
        grouped.setdefault((branch["jurisdiction"], branch["source_type"]), []).append(branch)
    for _group_key, group_branches in grouped.items():
        for index in range(0, len(group_branches), size):
            batch_branches = group_branches[index : index + size]
            programs = [branch["program"] for branch in batch_branches]
            jurisdictions = sorted({branch["jurisdiction"] for branch in batch_branches})
            source_types = sorted({branch["source_type"] for branch in batch_branches})
            batches.append(
                {
                    "batch_index": len(batches) + 1,
                    "branches": batch_branches,
                    "target_candidates": len(batch_branches) * target_candidates_per_branch,
                    "command": scale_batch_command(programs, jurisdictions, source_types, size, target_candidates_per_branch),
                }
            )
    return batches


def scale_batch_command(
    programs: list[str],
    jurisdictions: list[str],
    source_types: list[str],
    batch_size: int,
    target_candidates_per_branch: int,
) -> str:
    max_uses = max(10, len(programs) * len(jurisdictions) * len(source_types) * 2)
    return (
        "python -m gov_rules_kg.main claude-web-research "
        "--ai-provider claude "
        "--claude-model claude-sonnet-4-6 "
        f"--programs {','.join(programs)} "
        f"--jurisdictions {','.join(jurisdictions)} "
        f"--source-types {','.join(source_types)} "
        f"--batch-size {batch_size} "
        f"--max-candidates-per-branch {target_candidates_per_branch} "
        f"--max-uses {max_uses} "
        "--timeout-seconds 300 "
        "--retries 1"
    )


def branch_priority(jurisdiction: str, source_type: str) -> int:
    jurisdiction_score = {
        "federal": 0,
        "state_ca": 1,
        "state_tx": 2,
        "state_ny": 3,
        "state_fl": 4,
    }.get(jurisdiction, 9)
    source_score = {
        "regulation": 0,
        "statute": 1,
        "agency_guidance": 2,
        "manual": 3,
        "bulletin_letter": 4,
        "form_instruction": 5,
        "court_administrative_decision": 6,
        "faq_public_guidance": 7,
    }.get(source_type, 9)
    return jurisdiction_score * 100 + source_score


def write_scale_plan_markdown(plan: dict) -> str:
    summary = plan["summary"]
    lines = [
        "# Claude Web Scale Plan",
        "",
        f"- taxonomy_programs: {summary['taxonomy_programs']}",
        f"- jurisdictions: {summary['jurisdictions']}",
        f"- source_types: {summary['source_types']}",
        f"- total_possible_branches: {summary['total_possible_branches']}",
        f"- planned_batches: {summary['planned_batches']}",
        f"- planned_branches: {summary['planned_branches']}",
        f"- planned_candidate_slots: {summary['planned_candidate_slots']}",
        f"- estimated_claude_calls: {summary['estimated_claude_calls']}",
        "",
        summary["warning"],
        "",
        "## First Batches",
        "",
    ]
    for batch in plan["batches"][:25]:
        lines.extend(
            [
                f"### Batch {batch['batch_index']}",
                "",
                f"- branches: {len(batch['branches'])}",
                f"- target_candidates: {batch['target_candidates']}",
                "",
                "```bash",
                batch["command"],
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def write_scale_commands(plan: dict) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Generated Claude web expansion batches.",
        "# Run from gov-rules-kg-prototype with .venv activated.",
        "",
    ]
    for batch in plan["batches"]:
        lines.extend([f"# Batch {batch['batch_index']}: {batch['target_candidates']} candidate slots", batch["command"], ""])
    return "\n".join(lines)


def parse_csv_or_default(value: str, default: list[str], allowed: set[str] | None = None) -> list[str]:
    if not value.strip():
        return default
    items = [part.strip().lower() for part in value.split(",") if part.strip()]
    if allowed:
        invalid = [item for item in items if item not in allowed]
        if invalid:
            raise ValueError(f"unknown value(s): {', '.join(invalid)}")
    return items


def allowed_source_types() -> set[str]:
    return set(DEFAULT_SOURCE_TYPES) | set(SOURCE_TYPES)
