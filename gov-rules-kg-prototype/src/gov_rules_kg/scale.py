from __future__ import annotations

import json
from pathlib import Path

from .config import ecfr_all_title_sources


def write_ecfr_manifest(path: Path, date: str = "2026-06-10") -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    sources = [
        {
            "name": source.name,
            "url": source.url,
            "required": source.required,
            "discovery_seed": source.discovery_seed,
            "jurisdiction_level": source.jurisdiction_level,
            "state_code": source.state_code,
            "source_type": source.source_type,
        }
        for source in ecfr_all_title_sources(date)
    ]
    payload = {
        "manifest_type": "source_manifest",
        "name": "ecfr_all_titles",
        "date": date,
        "source_count": len(sources),
        "sources": sources,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def build_scale_playbook(workdir: Path, target_atomic_rules: int = 600_000) -> dict:
    proof_path = workdir / "reports" / "programmatic_proof_report.json"
    inventory_path = workdir / "reports" / "rule_inventory.json"
    proof = read_json(proof_path, {})
    inventory = read_json(inventory_path, {})
    current_rules = int(
        inventory.get("total_graph_atomic_rules")
        or proof.get("summary", {}).get("total_graph_atomic_rules")
        or 0
    )
    current_run_rules = int(
        inventory.get("current_run_atomic_rules")
        or proof.get("summary", {}).get("current_run_atomic_rules")
        or 0
    )
    remaining = max(0, target_atomic_rules - current_rules)
    observed_per_run = max(1, current_run_rules or int(proof.get("summary", {}).get("new_atomic_rules_added") or 993))
    estimated_runs = (remaining + observed_per_run - 1) // observed_per_run

    manifest_path = workdir / "data" / "source_manifests" / "ecfr_all_titles.json"
    return {
        "target_atomic_rules": target_atomic_rules,
        "current_total_graph_atomic_rules": current_rules,
        "current_run_atomic_rules_observed": current_run_rules,
        "remaining_atomic_rules": remaining,
        "estimated_runs_at_observed_rate": estimated_runs,
        "source_manifest": str(manifest_path),
        "strategy": [
            "Generate broad source manifests instead of one-off hardcoded crawls.",
            "Run all eCFR titles first for high-yield federal baseline coverage.",
            "Add state Medicaid source manifests next, one state at a time.",
            "Keep extracted rules as candidates until citation/source/gold-set validation passes.",
            "Use proof-report after every batch to show source-grounded and citation-grounded growth.",
        ],
        "commands": {
            "generate_ecfr_manifest": f"python -m gov_rules_kg.main generate-ecfr-manifest --output {manifest_path} --summary-only",
            "federal_bulk_run": (
                "python -m gov_rules_kg.main run "
                "--bulk-ingest "
                "--domain government_transaction_rules "
                "--vertical healthcare_benefits "
                "--program medicaid "
                "--jurisdiction federal "
                "--include-federal true "
                "--include-states none "
                f"--source-manifest {manifest_path} "
                "--manifest-only "
                "--max-depth 0 "
                "--global-doc-cap 50 "
                "--per-host-cap 50 "
                "--max-rule-sections-per-document 10000 "
                "--phase0-mode required"
            ),
            "ai_refinement_sample": (
                "python -m gov_rules_kg.main run "
                "--fast "
                "--domain government_transaction_rules "
                "--vertical healthcare_benefits "
                "--program medicaid "
                "--jurisdiction federal "
                "--include-federal true "
                "--include-states none "
                f"--source-manifest {manifest_path} "
                "--manifest-only "
                "--max-depth 0 "
                "--global-doc-cap 5 "
                "--per-host-cap 5 "
                "--max-rule-sections-per-document 2000 "
                "--ai-provider claude "
                "--claude-model claude-sonnet-4-6 "
                "--claude-max-sections 25 "
                "--fail-on-ai-fallback true "
                "--allow-local-stub false"
            ),
            "refresh_proof_report": "python -m gov_rules_kg.main proof-report",
        },
        "power_advantage_over_manual_collection": [
            "Every candidate rule has source URL and extraction timestamp.",
            "Rules carry verification status rather than pretending all extracted rules are verified.",
            "Reports separate current-run, total-graph, legacy, and review-required rules.",
            "The same source manifest can be rerun to refresh rules programmatically.",
            "Scale is achieved by repeatable manifests and batches, not copy-paste collection.",
        ],
    }


def write_scale_playbook(workdir: Path, target_atomic_rules: int = 600_000) -> dict:
    payload = build_scale_playbook(workdir, target_atomic_rules)
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "scale_playbook.json"
    md_path = reports_dir / "scale_playbook.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(scale_playbook_markdown(payload), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path), "summary": payload}


def scale_playbook_markdown(payload: dict) -> str:
    lines = [
        "# Scale Playbook",
        "",
        f"Target atomic rules: {payload['target_atomic_rules']}",
        f"Current total graph atomic rules: {payload['current_total_graph_atomic_rules']}",
        f"Remaining atomic rules: {payload['remaining_atomic_rules']}",
        f"Estimated runs at observed rate: {payload['estimated_runs_at_observed_rate']}",
        "",
        "## Strategy",
        "",
    ]
    lines.extend(f"- {item}" for item in payload["strategy"])
    lines.extend(["", "## Commands", ""])
    for name, command in payload["commands"].items():
        lines.extend([f"### {name}", "", "```bash", command, "```", ""])
    lines.extend(["## Power Advantage", ""])
    lines.extend(f"- {item}" for item in payload["power_advantage_over_manual_collection"])
    return "\n".join(lines)


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))
