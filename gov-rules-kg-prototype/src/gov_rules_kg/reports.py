from __future__ import annotations

import json
import hashlib
from collections import defaultdict
from pathlib import Path

from .domain import GOVERNMENT_RULE_TAXONOMY, RULE_UNIT_TYPES, SOURCE_TYPES, infer_source_type, rule_unit_type_for_rule_type
from .store import Store


EXPECTED_REPORTS = [
    "rules_by_family.json",
    "rules_by_citation.json",
    "rules_by_program.json",
    "rules_by_hierarchy.json",
    "rules_by_state.json",
    "federal_medicaid_rules.json",
    "state_medicaid_rules.json",
    "federal_state_mapping.json",
    "state_to_federal_mapping.json",
    "federal_state_conflicts.json",
    "state_exceptions.json",
    "executable_rule_candidates.json",
    "human_review_queue.json",
    "human_review_queue.md",
    "source_quality_report.json",
    "citation_index.json",
    "graph_nodes.json",
    "graph_edges.json",
    "audit_report.json",
    "audit_report.md",
    "evaluation_report.json",
    "final_scorecard.json",
    "rule_inventory.json",
    "programmatic_proof_report.json",
    "programmatic_proof_report.md",
]


def write_production_reports(
    store: Store,
    reports_dir: Path,
    ai_report: dict,
    hierarchy: dict,
    merge_candidates: list[dict],
    rule_inventory: dict | None = None,
) -> dict:
    reports_dir.mkdir(parents=True, exist_ok=True)
    atomic_rules = load_atomic_rules(store)
    documents = load_documents(store)
    edges = load_edges(store)

    by_family = group_by(atomic_rules, "rule_family")
    by_program = group_by(atomic_rules, "program")
    by_hierarchy = group_by_hierarchy(atomic_rules)
    by_state = group_by(atomic_rules, "state_code", none_key="federal_or_unknown")
    by_citation = group_by(atomic_rules, "normalized_citation", none_key="missing_citation")
    federal_rules = [rule for rule in atomic_rules if rule.get("jurisdiction_level") == "federal"]
    state_rules = [rule for rule in atomic_rules if rule.get("jurisdiction_level") == "state"]
    citation_index = build_citation_index(atomic_rules)
    source_quality = build_source_quality_report(documents)
    review_queue = build_human_review_queue(atomic_rules, source_quality, ai_report, merge_candidates)
    executable_candidates = build_executable_candidates(atomic_rules)
    audit_report = build_audit_report(atomic_rules, documents, source_quality, ai_report, merge_candidates, review_queue)
    evaluation_report = placeholder_evaluation_report()
    inventory = rule_inventory or build_rule_inventory_from_rules(atomic_rules)
    programmatic_proof = build_programmatic_proof_report(atomic_rules, documents, inventory)
    scorecard = build_final_scorecard(atomic_rules, source_quality, ai_report, merge_candidates, evaluation_report, inventory)

    write_json(reports_dir / "rules_by_family.json", by_family)
    write_json(reports_dir / "rules_by_citation.json", by_citation)
    write_json(reports_dir / "rules_by_program.json", by_program)
    write_json(reports_dir / "rules_by_hierarchy.json", by_hierarchy)
    write_json(reports_dir / "rules_by_state.json", by_state)
    write_json(reports_dir / "federal_medicaid_rules.json", federal_rules)
    write_json(reports_dir / "state_medicaid_rules.json", state_rules)
    write_json(reports_dir / "federal_state_mapping.json", [])
    write_json(reports_dir / "state_to_federal_mapping.json", [])
    write_json(reports_dir / "federal_state_conflicts.json", [])
    write_json(reports_dir / "state_exceptions.json", [])
    write_json(reports_dir / "executable_rule_candidates.json", executable_candidates)
    write_json(reports_dir / "human_review_queue.json", review_queue)
    write_markdown_queue(reports_dir / "human_review_queue.md", review_queue)
    write_json(reports_dir / "source_quality_report.json", source_quality)
    write_json(reports_dir / "citation_index.json", citation_index)
    write_json(reports_dir / "graph_nodes.json", load_graph_nodes(store, hierarchy))
    write_json(reports_dir / "graph_edges.json", edges)
    write_json(reports_dir / "audit_report.json", audit_report)
    write_markdown_audit(reports_dir / "audit_report.md", audit_report)
    write_json(reports_dir / "evaluation_report.json", evaluation_report)
    write_json(reports_dir / "final_scorecard.json", scorecard)
    write_json(reports_dir / "rule_inventory.json", inventory)
    write_json(reports_dir / "programmatic_proof_report.json", programmatic_proof)
    write_markdown_programmatic_proof(reports_dir / "programmatic_proof_report.md", programmatic_proof)
    return {
        "generated": [str(reports_dir / report) for report in EXPECTED_REPORTS],
        "final_scorecard": str(reports_dir / "final_scorecard.json"),
        "human_review_queue": str(reports_dir / "human_review_queue.json"),
        "rule_inventory": str(reports_dir / "rule_inventory.json"),
        "programmatic_proof_report": str(reports_dir / "programmatic_proof_report.json"),
    }


def load_atomic_rules(store: Store) -> list[dict]:
    rules: list[dict] = []
    for row in store.rows("entities"):
        if row["entity_type"] != "atomic_rule":
            continue
        metadata = json.loads(row["metadata_json"])
        rules.append(normalize_rule_record({**metadata, "canonical_key": row["canonical_key"], "row_text": row["text"], "row_source_url": row["source_url"]}))
    return rules


def normalize_rule_record(rule: dict) -> dict:
    source_url = rule.get("source_url") or rule.get("row_source_url") or "unknown"
    normalized_rule = rule.get("normalized_rule") or rule.get("statement") or rule.get("row_text") or ""
    exact_source_text = rule.get("exact_source_text") or rule.get("attribution", {}).get("evidence") or normalized_rule
    rule_id = rule.get("rule_id")
    if not rule_id:
        digest = hashlib.sha256(f"{source_url}|{rule.get('canonical_key')}|{normalized_rule}".encode("utf-8")).hexdigest()[:24]
        rule_id = f"rule:legacy:{digest}"
    confidence = rule.get("confidence_score", rule.get("confidence", 0.35))
    try:
        confidence_score = float(confidence)
    except (TypeError, ValueError):
        confidence_score = 0.35
    human_review_required = bool(rule.get("human_review_required")) or confidence_score < 0.75 or not rule.get("normalized_citation")
    human_review_reason = rule.get("human_review_reason") or ("legacy/partial rule metadata requires review" if rule_id.startswith("rule:legacy:") else "")
    raw_rule_types = rule.get("rule_types") or ["cross_reference_only"]
    if isinstance(raw_rule_types, str):
        raw_rule_types = [raw_rule_types]
    verification_status = rule.get("verification_status") or infer_verification_status(rule, confidence_score, human_review_required)
    source_type = rule.get("source_type") or "unknown"
    if source_type == "unknown":
        source_type = infer_source_type(source_url, normalized_rule)
    rule_type = rule.get("rule_type") or raw_rule_types[0]
    rule_unit_type = rule.get("rule_unit_type") or "administration_rule"
    if rule_unit_type == "administration_rule":
        rule_unit_type = rule_unit_type_for_rule_type(str(rule_type), normalized_rule)
    return {
        **rule,
        "rule_id": rule_id,
        "source_url": source_url,
        "source_document_id": rule.get("source_document_id") or source_url,
        "normalized_rule": normalized_rule,
        "statement": rule.get("statement") or normalized_rule,
        "exact_source_text": exact_source_text,
        "normalized_citation": rule.get("normalized_citation") or rule.get("citation"),
        "parsed_citations": rule.get("parsed_citations") or [],
        "domain": rule.get("domain") or "government_transaction_rules",
        "vertical": rule.get("vertical") or "healthcare_benefits",
        "program": rule.get("program") or "medicaid",
        "source_type": source_type,
        "rule_unit_type": rule_unit_type,
        "hierarchy_path": rule.get("hierarchy_path")
        or [
            rule.get("domain") or "government_transaction_rules",
            rule.get("vertical") or "healthcare_benefits",
            rule.get("program") or "medicaid",
            rule.get("jurisdiction_level") or "unknown",
            source_type,
            rule_unit_type,
        ],
        "jurisdiction_level": rule.get("jurisdiction_level") or "unknown",
        "state_code": rule.get("state_code"),
        "rule_family": rule.get("rule_family") or "administration",
        "rule_type": rule_type,
        "confidence_score": confidence_score,
        "human_review_required": human_review_required,
        "human_review_reason": human_review_reason,
        "verification_status": verification_status,
    }


def infer_verification_status(rule: dict, confidence_score: float, human_review_required: bool) -> str:
    if rule.get("verification_status"):
        return str(rule["verification_status"])
    if human_review_required:
        return "human_review_required"
    if confidence_score >= 0.85 and rule.get("normalized_citation") and rule.get("exact_source_text"):
        return "machine_validated_candidate"
    return "candidate_extracted"


def load_documents(store: Store) -> list[dict]:
    return [
        {
            "canonical_url": row["canonical_url"],
            "source_url": row["source_url"],
            "status": row["status"],
            "metadata": json.loads(row["metadata_json"]),
        }
        for row in store.rows("documents")
    ]


def load_edges(store: Store) -> list[dict]:
    return [
        {
            "edge_id": f"edge:{row['id']}",
            "edge_type": row["edge_type"],
            "source_node": row["from_key"],
            "target_node": row["to_key"],
            "evidence_text": row["evidence"],
            "source_url": row["source_url"],
            "confidence_score": 0.75,
            "human_review_required": False,
        }
        for row in store.rows("edges")
    ]


def load_graph_nodes(store: Store, hierarchy: dict) -> list[dict]:
    nodes = taxonomy_nodes()
    nodes.append({"id": "federal_space:medicaid", "node_type": "federal_space", "title": "Medicaid Federal Baseline Space"})
    for state_space in hierarchy.get("state_spaces", []):
        nodes.append({"id": state_space["state_space_id"], "node_type": "state_space", **state_space})
    for row in store.rows("entities"):
        nodes.append(
            {
                "id": row["canonical_key"],
                "node_type": row["entity_type"],
                "title": row["title"],
                "source_url": row["source_url"],
            }
        )
    return nodes


def taxonomy_nodes() -> list[dict]:
    nodes: list[dict] = [
        {
            "id": "domain:government_transaction_rules",
            "node_type": "domain",
            "title": "Government Transaction Rules",
            "taxonomy": GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"],
            "source_types": SOURCE_TYPES,
            "rule_unit_types": RULE_UNIT_TYPES,
        }
    ]
    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        nodes.append({"id": f"vertical:{vertical}", "node_type": "vertical", "title": titleize(vertical)})
        for program in programs:
            nodes.append(
                {
                    "id": f"program:{program}",
                    "node_type": "program",
                    "title": titleize(program),
                    "vertical": vertical,
                }
            )
    for source_type in SOURCE_TYPES:
        nodes.append({"id": f"source_type:{source_type}", "node_type": "source_type", "title": titleize(source_type)})
    for rule_unit_type in RULE_UNIT_TYPES:
        nodes.append({"id": f"rule_unit_type:{rule_unit_type}", "node_type": "rule_unit_type", "title": titleize(rule_unit_type)})
    return nodes


def group_by(rules: list[dict], key: str, none_key: str = "unknown") -> dict:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for rule in rules:
        grouped[str(rule.get(key) or none_key)].append(rule)
    return dict(sorted(grouped.items()))


def group_by_hierarchy(rules: list[dict]) -> dict:
    grouped: dict[str, dict] = {}
    for rule in rules:
        domain = str(rule.get("domain") or "government_transaction_rules")
        vertical = str(rule.get("vertical") or "unknown")
        program = str(rule.get("program") or "unknown")
        jurisdiction = str(rule.get("jurisdiction_level") or "unknown")
        source_type = str(rule.get("source_type") or "unknown")
        rule_unit_type = str(rule.get("rule_unit_type") or "administration_rule")
        cursor = grouped.setdefault(domain, {})
        cursor = cursor.setdefault(vertical, {})
        cursor = cursor.setdefault(program, {})
        cursor = cursor.setdefault(jurisdiction, {})
        cursor = cursor.setdefault(source_type, {})
        cursor.setdefault(rule_unit_type, []).append(rule)
    return grouped


def verified_rules(rules: list[dict]) -> list[dict]:
    return [
        rule
        for rule in rules
        if rule.get("verification_status") == "machine_validated_candidate"
        and not rule.get("human_review_required")
        and float(rule.get("confidence_score", 0) or 0) >= 0.85
        and bool(rule.get("source_url"))
        and bool(rule.get("exact_source_text"))
        and bool(rule.get("normalized_citation"))
    ]


def build_verified_rules_by_hierarchy(rules: list[dict]) -> dict:
    return group_by_hierarchy(verified_rules(rules))


def clean_verified_rule(rule: dict) -> dict:
    statement = rule.get("normalized_rule") or rule.get("statement") or ""
    source_type = rule.get("source_type") if rule.get("source_type") != "unknown" else infer_source_type(rule.get("source_url") or "", statement)
    rule_unit_type = rule.get("rule_unit_type")
    if not rule_unit_type or rule_unit_type == "administration_rule":
        rule_unit_type = rule_unit_type_for_rule_type(str(rule.get("rule_type") or ""), statement)
    return {
        "rule_id": rule.get("rule_id"),
        "path": {
            "domain": rule.get("domain"),
            "vertical": rule.get("vertical"),
            "program": rule.get("program"),
            "jurisdiction": rule.get("jurisdiction_level"),
            "source_type": source_type,
            "rule_unit_type": rule_unit_type,
        },
        "statement": statement,
        "citation": rule.get("normalized_citation"),
        "source_url": rule.get("source_url"),
        "evidence": rule.get("exact_source_text"),
        "confidence_score": rule.get("confidence_score"),
        "verification_status": rule.get("verification_status"),
    }


def build_full_verified_hierarchy(rules: list[dict], clean: bool = True) -> dict:
    grouped = group_by_hierarchy(reclassify_verified_rules_for_export(verified_rules(rules)))
    full: dict = {"government_transaction_rules": {}}
    domain_cursor = full["government_transaction_rules"]
    grouped_domain = grouped.get("government_transaction_rules", {})
    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        vertical_cursor = domain_cursor.setdefault(vertical, {})
        grouped_vertical = grouped_domain.get(vertical, {})
        for program in programs:
            program_cursor = vertical_cursor.setdefault(program, {})
            grouped_program = grouped_vertical.get(program, {})
            for jurisdiction in ["federal", "state", "county", "city_municipality", "agency_specific", "unknown"]:
                jurisdiction_cursor = program_cursor.setdefault(jurisdiction, {})
                grouped_jurisdiction = grouped_program.get(jurisdiction, {})
                for source_type in SOURCE_TYPES:
                    source_cursor = jurisdiction_cursor.setdefault(source_type, {})
                    grouped_source = grouped_jurisdiction.get(source_type, {})
                    for rule_unit_type in RULE_UNIT_TYPES:
                        leaf_rules = grouped_source.get(rule_unit_type, [])
                        source_cursor[rule_unit_type] = [clean_verified_rule(rule) for rule in leaf_rules] if clean else leaf_rules
    return full


def build_verified_rules_summary(rules: list[dict]) -> dict:
    verified = reclassify_verified_rules_for_export(verified_rules(rules))
    by_program: dict[str, int] = defaultdict(int)
    by_vertical: dict[str, int] = defaultdict(int)
    by_source_type: dict[str, int] = defaultdict(int)
    by_rule_unit_type: dict[str, int] = defaultdict(int)
    for rule in verified:
        by_program[str(rule.get("program") or "unknown")] += 1
        by_vertical[str(rule.get("vertical") or "unknown")] += 1
        by_source_type[str(rule.get("source_type") or "unknown")] += 1
        by_rule_unit_type[str(rule.get("rule_unit_type") or "unknown")] += 1
    all_programs = [
        program
        for programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].values()
        for program in programs
    ]
    programs_with_verified_rules = sorted(program for program, count in by_program.items() if count)
    return {
        "total_rules_in_graph": len(rules),
        "verified_rules": len(verified),
        "excluded_rules": len(rules) - len(verified),
        "coverage": {
            "taxonomy_verticals_total": len(GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"]),
            "taxonomy_programs_total": len(all_programs),
            "programs_with_verified_rules": programs_with_verified_rules,
            "programs_with_verified_rules_count": len(programs_with_verified_rules),
            "programs_without_verified_rules": [program for program in all_programs if program not in programs_with_verified_rules],
        },
        "criteria": {
            "verification_status": "machine_validated_candidate",
            "human_review_required": False,
            "minimum_confidence_score": 0.85,
            "requires_source_url": True,
            "requires_exact_source_text": True,
            "requires_normalized_citation": True,
        },
        "by_vertical": dict(sorted(by_vertical.items())),
        "by_program": dict(sorted(by_program.items())),
        "by_source_type": dict(sorted(by_source_type.items())),
        "by_rule_unit_type": dict(sorted(by_rule_unit_type.items())),
    }


def write_verified_rules_by_hierarchy(reports_dir: Path, rules: list[dict]) -> dict:
    reports_dir.mkdir(parents=True, exist_ok=True)
    hierarchy = build_verified_rules_by_hierarchy(rules)
    full_clean_hierarchy = build_full_verified_hierarchy(rules, clean=True)
    summary = build_verified_rules_summary(rules)
    hierarchy_path = reports_dir / "verified_rules_by_hierarchy.json"
    clean_hierarchy_path = reports_dir / "verified_rules_clean_full_hierarchy.json"
    summary_path = reports_dir / "verified_rules_summary.json"
    markdown_path = reports_dir / "verified_rules_summary.md"
    readable_path = reports_dir / "verified_rules_readable.md"
    write_json(hierarchy_path, hierarchy)
    write_json(clean_hierarchy_path, full_clean_hierarchy)
    write_json(summary_path, summary)
    write_markdown_verified_summary(markdown_path, summary)
    write_markdown_verified_rules(readable_path, reclassify_verified_rules_for_export(verified_rules(rules)))
    return {
        "verified_rules_by_hierarchy": str(hierarchy_path),
        "verified_rules_clean_full_hierarchy": str(clean_hierarchy_path),
        "verified_rules_summary": str(summary_path),
        "markdown": str(markdown_path),
        "readable_markdown": str(readable_path),
        "summary": summary,
    }


def write_markdown_verified_summary(path: Path, summary: dict) -> None:
    lines = [
        "# Verified Rules Summary",
        "",
        f"- total_rules_in_graph: {summary.get('total_rules_in_graph')}",
        f"- verified_rules: {summary.get('verified_rules')}",
        f"- excluded_rules: {summary.get('excluded_rules')}",
        "",
        "## Criteria",
        "",
    ]
    for key, value in summary.get("criteria", {}).items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## coverage", ""])
    coverage = summary.get("coverage", {})
    lines.append(f"- taxonomy_verticals_total: {coverage.get('taxonomy_verticals_total')}")
    lines.append(f"- taxonomy_programs_total: {coverage.get('taxonomy_programs_total')}")
    lines.append(f"- programs_with_verified_rules_count: {coverage.get('programs_with_verified_rules_count')}")
    lines.append(f"- programs_with_verified_rules: {', '.join(coverage.get('programs_with_verified_rules', [])) or 'none'}")
    for section in ["by_vertical", "by_program", "by_source_type", "by_rule_unit_type"]:
        lines.extend(["", f"## {section}", ""])
        for key, value in summary.get(section, {}).items():
            lines.append(f"- {key}: {value}")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_markdown_verified_rules(path: Path, rules: list[dict]) -> None:
    lines = ["# Verified Rules", ""]
    if not rules:
        lines.append("No verified rules matched the current criteria.")
    for rule in rules:
        clean = clean_verified_rule(rule)
        path_bits = clean["path"]
        lines.append(f"## {clean['rule_id']}")
        lines.append(
            "Path: "
            + " > ".join(
                str(path_bits.get(key) or "unknown")
                for key in ["domain", "vertical", "program", "jurisdiction", "source_type", "rule_unit_type"]
            )
        )
        lines.append(f"Statement: {clean['statement']}")
        lines.append(f"Citation: {clean['citation']}")
        lines.append(f"Source: {clean['source_url']}")
        lines.append(f"Confidence: {clean['confidence_score']}")
        lines.append(f"Evidence: {clean['evidence']}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def reclassify_verified_rules_for_export(rules: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    for rule in rules:
        statement = rule.get("normalized_rule") or rule.get("statement") or ""
        source_type = rule.get("source_type")
        if not source_type or source_type == "unknown":
            source_type = infer_source_type(rule.get("source_url") or "", statement)
        rule_unit_type = rule.get("rule_unit_type")
        if not rule_unit_type or rule_unit_type == "administration_rule":
            rule_unit_type = rule_unit_type_for_rule_type(str(rule.get("rule_type") or ""), statement)
        enriched.append({**rule, "source_type": source_type, "rule_unit_type": rule_unit_type})
    return enriched


def titleize(value: str) -> str:
    return value.replace("_", " ").title()


def build_rule_inventory_from_rules(rules: list[dict]) -> dict:
    run_ids = sorted({rule.get("run_id") for rule in rules if rule.get("run_id")})
    legacy_rules = [rule for rule in rules if not rule.get("run_id") or str(rule.get("rule_id", "")).startswith("rule:legacy:")]
    return {
        "run_id": run_ids[-1] if run_ids else "unknown",
        "current_run_atomic_rules": 0,
        "current_run_rule_units_attempted": 0,
        "new_atomic_rules_added": 0,
        "updated_or_reseen_atomic_rules": 0,
        "total_graph_atomic_rules": len(rules),
        "rules_excluded_from_current_scope": len(rules),
        "legacy_or_unversioned_atomic_rules": len(legacy_rules),
        "note": "Inventory was rebuilt from stored rules without current-run key tracking.",
    }


def build_programmatic_proof_report(rules: list[dict], documents: list[dict], inventory: dict) -> dict:
    total = len(rules)
    source_grounded = [rule for rule in rules if rule.get("source_url") and rule.get("exact_source_text")]
    citation_grounded = [rule for rule in rules if rule.get("normalized_citation")]
    machine_validated = [rule for rule in rules if rule.get("verification_status") == "machine_validated_candidate"]
    review_required = [rule for rule in rules if rule.get("human_review_required")]
    executable_ready = [
        rule
        for rule in rules
        if not rule.get("human_review_required")
        and float(rule.get("confidence_score", 0)) >= 0.85
        and rule.get("exact_source_text")
    ]
    by_status: dict[str, int] = defaultdict(int)
    by_method: dict[str, int] = defaultdict(int)
    by_jurisdiction: dict[str, int] = defaultdict(int)
    for rule in rules:
        by_status[str(rule.get("verification_status") or "unknown")] += 1
        by_method[str(rule.get("extraction_method") or "unknown")] += 1
        by_jurisdiction[str(rule.get("jurisdiction_level") or "unknown")] += 1
    sample_rules = prioritize_sample_rules(rules, str(inventory.get("run_id") or ""))

    return {
        "summary": {
            "total_graph_atomic_rules": total,
            "current_run_atomic_rules": inventory.get("current_run_atomic_rules", 0),
            "new_atomic_rules_added": inventory.get("new_atomic_rules_added", 0),
            "source_grounded_rules": len(source_grounded),
            "citation_grounded_rules": len(citation_grounded),
            "machine_validated_candidate_rules": len(machine_validated),
            "human_review_required_rules": len(review_required),
            "executable_candidate_ready_rules": len(executable_ready),
            "source_grounding_rate": len(source_grounded) / max(1, total),
            "citation_grounding_rate": len(citation_grounded) / max(1, total),
            "documents_in_graph": len(documents),
            "verification_status_distribution": dict(sorted(by_status.items())),
            "extraction_method_distribution": dict(sorted(by_method.items())),
            "jurisdiction_distribution": dict(sorted(by_jurisdiction.items())),
        },
        "programmatic_claim": (
            "Rules are generated through a reproducible pipeline that preserves source URL, exact source text, "
            "citation fields when available, extraction method, confidence score, and human-review status."
        ),
        "sample_rules": [
            {
                "rule_id": rule.get("rule_id"),
                "verification_status": rule.get("verification_status"),
                "source_url": rule.get("source_url"),
                "normalized_citation": rule.get("normalized_citation"),
                "rule_family": rule.get("rule_family"),
                "rule_type": rule.get("rule_type"),
                "confidence_score": rule.get("confidence_score"),
                "human_review_required": rule.get("human_review_required"),
                "exact_source_text": rule.get("exact_source_text"),
                "normalized_rule": rule.get("normalized_rule"),
            }
            for rule in sample_rules[:100]
        ],
    }


def prioritize_sample_rules(rules: list[dict], current_run_id: str) -> list[dict]:
    def score(rule: dict) -> tuple[int, int, float]:
        current_run = 1 if current_run_id and rule.get("run_id") == current_run_id else 0
        not_legacy = 1 if not str(rule.get("rule_id", "")).startswith("rule:legacy:") else 0
        confidence = float(rule.get("confidence_score", 0) or 0)
        return (current_run, not_legacy, confidence)

    return sorted(rules, key=score, reverse=True)


def build_citation_index(rules: list[dict]) -> list[dict]:
    index: dict[str, dict] = {}
    for rule in rules:
        for citation in rule.get("parsed_citations", []):
            citation_id = citation["citation_id"]
            entry = index.setdefault(citation_id, {**citation, "rule_ids": []})
            entry["rule_ids"].append(rule["rule_id"])
    return list(index.values())


def build_source_quality_report(documents: list[dict]) -> list[dict]:
    report = []
    for document in documents:
        quality = document["metadata"].get("source_quality")
        if quality:
            report.append(quality)
        else:
            report.append(
                {
                    "url": document["canonical_url"],
                    "source_type": "unknown",
                    "jurisdiction_level": "unknown",
                    "state_code": None,
                    "program": "medicaid",
                    "fetch_status": document["status"],
                    "text_quality_score": 0.0,
                    "parser_used": "unknown",
                    "sections_detected": 0,
                    "tables_detected": 0,
                    "citations_detected": 0,
                    "rules_detected": 0,
                    "problems": ["source_quality_missing"],
                }
            )
    return report


def build_human_review_queue(rules: list[dict], source_quality: list[dict], ai_report: dict, merge_candidates: list[dict]) -> list[dict]:
    queue: list[dict] = []
    for rule in rules:
        if rule.get("human_review_required") or not rule.get("normalized_citation") or float(rule.get("confidence_score", 0)) < 0.75:
            queue.append(
                {
                    "review_id": f"review:{rule['rule_id']}",
                    "priority": "high" if not rule.get("normalized_citation") else "medium",
                    "reason": rule.get("human_review_reason") or "Rule requires validation",
                    "rule_id": rule["rule_id"],
                    "source_url": rule["source_url"],
                    "citation": rule.get("normalized_citation"),
                    "exact_source_text": rule.get("exact_source_text"),
                    "suggested_fix": "Validate citation, actor/action split, and source text.",
                    "review_status": "pending",
                }
            )
    for quality in source_quality:
        if quality.get("text_quality_score", 1.0) < 0.75:
            queue.append(
                {
                    "review_id": f"review:source:{abs(hash(quality['url']))}",
                    "priority": "medium",
                    "reason": "; ".join(quality.get("problems") or ["source quality below threshold"]),
                    "rule_id": None,
                    "source_url": quality["url"],
                    "citation": None,
                    "exact_source_text": None,
                    "suggested_fix": "Manually inspect source parser or retrieval path.",
                    "review_status": "pending",
                }
            )
    if ai_report.get("ai_fallback_used") or ai_report.get("ai_error_count"):
        queue.append(
            {
                "review_id": "review:ai-provider",
                "priority": "high",
                "reason": "AI provider fallback/error present",
                "rule_id": None,
                "source_url": None,
                "citation": None,
                "exact_source_text": None,
                "suggested_fix": "Fix Claude configuration before production extraction.",
                "review_status": "pending",
            }
        )
    for candidate in merge_candidates:
        queue.append(
            {
                "review_id": f"review:merge:{abs(hash(candidate['left_key'] + candidate['right_key']))}",
                "priority": "medium",
                "reason": "Near duplicate requires human review; no legal fuzzy merge allowed.",
                "rule_id": None,
                "source_url": None,
                "citation": None,
                "exact_source_text": json.dumps(candidate.get("evidence", {}), sort_keys=True),
                "suggested_fix": "Approve only exact source/citation/path/text duplicate merges.",
                "review_status": "pending",
            }
        )
    return queue


def build_executable_candidates(rules: list[dict]) -> list[dict]:
    candidates = []
    for rule in rules:
        if float(rule.get("confidence_score", 0)) < 0.60:
            continue
        if rule.get("human_review_required") and rule.get("human_review_reason") == "Ambiguous condition/action boundary":
            continue
        candidates.append(
            {
                "rule_id": rule["rule_id"],
                "exact_source_text": rule.get("exact_source_text"),
                "candidate_only": True,
                "if": [{"text": rule.get("condition")}] if rule.get("condition") else [],
                "then": [{"actor": rule.get("actor"), "must": rule.get("action"), "within": rule.get("time_limit")}],
                "unless": [{"text": item} for item in rule.get("exception", [])],
                "human_review_required": rule.get("human_review_required", True),
            }
        )
    return candidates


def build_audit_report(
    rules: list[dict],
    documents: list[dict],
    source_quality: list[dict],
    ai_report: dict,
    merge_candidates: list[dict],
    review_queue: list[dict],
) -> dict:
    return {
        "low_confidence_rules": [rule for rule in rules if float(rule.get("confidence_score", 0)) < 0.75],
        "missing_citations": [rule for rule in rules if not rule.get("normalized_citation")],
        "skipped_documents": [doc for doc in documents if doc["status"].startswith("SKIPPED")],
        "source_quality_issues": [item for item in source_quality if item.get("problems")],
        "ai_failures": ai_report.get("ai_errors", []),
        "proposed_merges": merge_candidates,
        "blocked_unsafe_merges": [],
        "state_federal_mapping_issues": [],
        "possible_conflicts": [],
        "rules_requiring_human_review": review_queue,
    }


def placeholder_evaluation_report() -> dict:
    return {
        "overall_score": 0,
        "precision": 0.0,
        "recall": 0.0,
        "citation_accuracy": 0.0,
        "state_classification_accuracy": 0.0,
        "federal_state_separation_accuracy": 0.0,
        "rule_family_accuracy": 0.0,
        "rule_type_accuracy": 0.0,
        "condition_action_accuracy": 0.0,
        "hallucination_rate": 0.0,
        "missing_citation_rate": 0.0,
        "production_ready": False,
        "blocking_issues": ["No gold-set evaluation has been run."],
    }


def build_final_scorecard(
    rules: list[dict],
    source_quality: list[dict],
    ai_report: dict,
    merge_candidates: list[dict],
    evaluation_report: dict,
    rule_inventory: dict | None = None,
) -> dict:
    blocking = []
    if ai_report.get("ai_fallback_used"):
        blocking.append("AI fallback was used.")
    if evaluation_report.get("blocking_issues"):
        blocking.extend(evaluation_report["blocking_issues"])
    if any(not rule.get("exact_source_text") for rule in rules):
        blocking.append("At least one rule is missing exact_source_text.")
    if any(rule.get("jurisdiction_level") == "federal" and rule.get("state_code") for rule in rules):
        blocking.append("Federal rule has state_code populated.")
    if merge_candidates:
        blocking.append("Merge candidates require human review before any merge.")
    missing_citation_rate = sum(1 for rule in rules if not rule.get("normalized_citation")) / max(1, len(rules))
    if missing_citation_rate > 0.02:
        blocking.append("Missing citation rate exceeds 2%.")
    if rule_inventory and rule_inventory.get("legacy_or_unversioned_atomic_rules", 0):
        blocking.append("Legacy or unversioned atomic rules are present in the graph.")

    base_score = 8 if rules else 4
    if blocking:
        base_score = min(base_score, 7)
    return {
        "source_ingestion_score": 8 if source_quality else 4,
        "rule_extraction_score": 8 if rules else 3,
        "citation_accuracy_score": 6 if missing_citation_rate > 0.02 else 8,
        "state_space_score": 8,
        "federal_state_mapping_score": 5,
        "classification_score": 8 if rules else 3,
        "condition_action_score": 6,
        "graph_quality_score": 7,
        "deduplication_score": 7 if not merge_candidates else 5,
        "auditability_score": 8,
        "validation_score": 0,
        "production_readiness_score": base_score,
        "overall_score": base_score,
        "blocking_issues": blocking,
        "rule_inventory": rule_inventory or {},
    }


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_markdown_queue(path: Path, queue: list[dict]) -> None:
    lines = ["# Human Review Queue", ""]
    for item in queue[:200]:
        lines.append(f"## {item['priority'].title()} - {item['reason']}")
        lines.append(f"- Rule: {item.get('rule_id')}")
        lines.append(f"- Source: {item.get('source_url')}")
        lines.append(f"- Citation: {item.get('citation')}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_markdown_audit(path: Path, audit: dict) -> None:
    lines = ["# Audit Report", ""]
    for key, values in audit.items():
        lines.append(f"## {key}")
        lines.append(f"Count: {len(values)}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_markdown_programmatic_proof(path: Path, proof: dict) -> None:
    summary = proof.get("summary", {})
    lines = [
        "# Programmatic Proof Report",
        "",
        proof.get("programmatic_claim", ""),
        "",
        "## Summary",
        "",
    ]
    for key in [
        "total_graph_atomic_rules",
        "current_run_atomic_rules",
        "new_atomic_rules_added",
        "source_grounded_rules",
        "citation_grounded_rules",
        "machine_validated_candidate_rules",
        "human_review_required_rules",
        "executable_candidate_ready_rules",
        "source_grounding_rate",
        "citation_grounding_rate",
        "documents_in_graph",
    ]:
        lines.append(f"- {key}: {summary.get(key)}")

    lines.extend(["", "## Verification Status", ""])
    for key, value in summary.get("verification_status_distribution", {}).items():
        lines.append(f"- {key}: {value}")

    lines.extend(["", "## Extraction Method", ""])
    for key, value in summary.get("extraction_method_distribution", {}).items():
        lines.append(f"- {key}: {value}")

    lines.extend(["", "## Sample Rules", ""])
    for rule in proof.get("sample_rules", [])[:20]:
        lines.append(f"### {rule.get('rule_id')}")
        lines.append(f"- Status: {rule.get('verification_status')}")
        lines.append(f"- Citation: {rule.get('normalized_citation')}")
        lines.append(f"- Source: {rule.get('source_url')}")
        lines.append(f"- Confidence: {rule.get('confidence_score')}")
        lines.append(f"- Review required: {rule.get('human_review_required')}")
        lines.append(f"- Rule: {rule.get('normalized_rule')}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
