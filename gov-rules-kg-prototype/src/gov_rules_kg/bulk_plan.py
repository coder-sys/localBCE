from __future__ import annotations

import json
from pathlib import Path


def build_bulk_plan(workdir: Path, target_atomic_rules: int) -> dict:
    report_path = workdir / "reports" / "run_report.json"
    if not report_path.exists():
        return {
            "target_atomic_rules": target_atomic_rules,
            "status": "NO_RUN_REPORT",
            "message": "Run discovery first so the planner can estimate from observed extraction rates.",
        }

    report = json.loads(report_path.read_text(encoding="utf-8"))
    stats = report.get("recursion_stats", {})
    processed_documents = max(1, int(stats.get("processed_documents", 0) or 1))
    atomic_rule_units = int(stats.get("atomic_rule_units", 0) or 0)
    relevant_rule_sections = int(stats.get("relevant_rule_sections", 0) or 0)
    rule_sections_extracted = int(stats.get("rule_sections_extracted", 0) or 0)

    atomic_per_doc = atomic_rule_units / processed_documents
    relevant_sections_per_doc = relevant_rule_sections / processed_documents
    extracted_sections_per_doc = rule_sections_extracted / processed_documents
    estimated_docs_for_target = None
    if atomic_per_doc > 0:
        estimated_docs_for_target = int((target_atomic_rules + atomic_per_doc - 1) // atomic_per_doc)

    return {
        "target_atomic_rules": target_atomic_rules,
        "status": "READY",
        "observed": {
            "processed_documents": processed_documents,
            "atomic_rule_units": atomic_rule_units,
            "relevant_rule_sections": relevant_rule_sections,
            "rule_sections_extracted": rule_sections_extracted,
            "atomic_rule_units_per_document": atomic_per_doc,
            "relevant_rule_sections_per_document": relevant_sections_per_doc,
            "rule_sections_extracted_per_document": extracted_sections_per_doc,
        },
        "estimate": {
            "estimated_documents_for_target": estimated_docs_for_target,
            "recommended_next_run": {
                "max_depth": 1,
                "global_doc_cap": min(500, max(50, estimated_docs_for_target or 50)),
                "per_host_cap": 100,
                "ecfr_all_titles": True,
                "max_rule_sections_per_document": 5000,
                "ai_provider": "auto",
                "claude_max_sections": 100,
            },
        },
        "notes": [
            "Million-scale extraction requires broad source coverage and repeated checkpointed runs.",
            "Do not use bot-protection evasion; blocked sources should remain NEEDS_MANUAL.",
            "Use atomic_rule_units for volume; use relevant_rule_sections for legal-section count.",
            "Claude extraction is opt-in. Start with a small claude_max_sections value and review quality/cost before scaling.",
        ],
    }
