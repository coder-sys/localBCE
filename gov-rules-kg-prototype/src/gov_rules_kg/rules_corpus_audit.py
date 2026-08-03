from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable


SCHEMA_VERSION = "localbce-rules-corpus-inventory-v1"
REPORTED_COFUNDER_RULE_COUNT = 457_000


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _records(payload: Any, preferred_key: str | None = None) -> list[dict[str, Any]]:
    if preferred_key and isinstance(payload, dict):
        value = payload.get(preferred_key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    found: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, list):
            found.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            for child in value.values():
                visit(child)

    visit(payload)
    return found


def _present(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _first(record: dict[str, Any], fields: Iterable[str]) -> Any:
    for field in fields:
        value = record.get(field)
        if _present(value):
            return value
    return None


def _program(record: dict[str, Any]) -> str | None:
    value = record.get("program")
    if _present(value):
        return str(value)
    path = record.get("path")
    if isinstance(path, dict) and _present(path.get("program")):
        return str(path["program"])
    return None


def _identifier(record: dict[str, Any]) -> str | None:
    value = _first(
        record,
        (
            "rule_id",
            "candidate_id",
            "executable_rule_id",
            "mapping_candidate_id",
            "source_candidate_id",
            "canonical_key",
        ),
    )
    return str(value) if value is not None else None


def _content_key(record: dict[str, Any]) -> str | None:
    direct = _first(record, ("statement", "exact_source_text", "evidence"))
    if direct is not None:
        return " ".join(str(direct).lower().split())
    condition = _first(record, ("normalized_condition", "condition_text", "condition"))
    outcome = _first(record, ("outcome_text", "action"))
    if condition is not None or outcome is not None:
        return json.dumps([condition, outcome], sort_keys=True, separators=(",", ":"), default=str)
    if "if" in record or "then" in record:
        return json.dumps(
            [record.get("if"), record.get("then"), record.get("unless")],
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    return None


def _duplicate_metrics(records: list[dict[str, Any]], key: Callable[[dict[str, Any]], str | None]) -> dict[str, int]:
    counts = Counter(value for record in records if (value := key(record)))
    duplicate_sizes = [count for count in counts.values() if count > 1]
    return {
        "duplicate_groups": len(duplicate_sizes),
        "records_in_duplicate_groups": sum(duplicate_sizes),
        "duplicate_excess_records": sum(count - 1 for count in duplicate_sizes),
    }


def _coverage(count: int, total: int) -> dict[str, int | float]:
    return {
        "present": count,
        "missing": total - count,
        "rate": round(count / total, 6) if total else 0.0,
    }


def _is_legally_verified(record: dict[str, Any]) -> bool:
    if record.get("legally_verified") is True or record.get("legal_verification") is True:
        return True
    status = str(
        _first(record, ("legal_verification_status", "legal_review_status")) or ""
    ).lower()
    return status in {"legally_verified", "legal_verified", "verified_by_counsel"}


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(records)
    programs = Counter(program for record in records if (program := _program(record)))
    source_urls = sum(_present(_first(record, ("source_url", "url"))) for record in records)
    citations = sum(_present(_first(record, ("citation_text", "citation"))) for record in records)
    source_hashes = sum(
        _present(_first(record, ("source_hash", "source_sha256", "evidence_sha256")))
        for record in records
    )
    effective_dates = sum(
        _present(_first(record, ("effective_date", "effective_from", "effective_to")))
        for record in records
    )
    evidence = sum(
        _present(_first(record, ("evidence", "exact_source_text", "statement", "citation_text")))
        for record in records
    )
    return {
        "record_count": total,
        "program_coverage": {
            "program_count": len(programs),
            "by_program": dict(sorted(programs.items())),
        },
        "provenance_coverage": {
            "source_url": _coverage(source_urls, total),
            "citation": _coverage(citations, total),
            "source_hash": _coverage(source_hashes, total),
            "effective_date": _coverage(effective_dates, total),
            "evidence_text": _coverage(evidence, total),
        },
        "duplicate_counts": {
            "identifier": _duplicate_metrics(records, _identifier),
            "normalized_content": _duplicate_metrics(records, _content_key),
        },
        "legal_verification": {
            "legally_verified": sum(_is_legally_verified(record) for record in records),
            "not_legally_verified_or_unspecified": total
            - sum(_is_legally_verified(record) for record in records),
        },
    }


def _entry(
    corpus_id: str,
    classification: str,
    path: str,
    records: list[dict[str, Any]] | None,
    *,
    count_semantics: str = "records",
    status: str = "present",
    notes: list[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "corpus_id": corpus_id,
        "classification": classification,
        "path": path,
        "inventory_status": status,
        "count_semantics": count_semantics,
        "notes": notes or [],
    }
    if records is None:
        result["record_count"] = None
        result["program_coverage"] = None
        result["provenance_coverage"] = None
        result["duplicate_counts"] = None
        result["legal_verification"] = None
    else:
        result.update(summarize_records(records))
    return result


def _policy_entry_count(payload: dict[str, Any] | None) -> int:
    if not isinstance(payload, dict):
        return 0
    sections = (
        ("L2_ELIGIBILITY_PROOF", "gates"),
        ("L3_PROVIDER_ENROLLMENT", "gates"),
        ("L4_CLAIMS_TAR_ADJUDICATION", "adjudication_edits"),
        ("L5_APPEAL_EXCEPTION", "tracks"),
    )
    count = 0
    for section_name, field in sections:
        section = payload.get(section_name, {})
        value = section.get(field, {}) if isinstance(section, dict) else {}
        count += len(value) if isinstance(value, (dict, list)) else 0
    return count


def _reference_policy_entry(corpus_id: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    count = _policy_entry_count(payload)
    records = [{} for _ in range(count)]
    entry = _entry(
        corpus_id,
        "reference_only",
        path,
        records,
        count_semantics="top-level policy gates, edits, and tracks; not atomic extracted rules",
        status="present" if payload is not None else "missing",
        notes=["Target/reference AST only; runtime loading is forbidden in Phase R1."],
    )
    version = payload.get("_meta", {}).get("version") if isinstance(payload, dict) else None
    entry["declared_version"] = version
    return entry


def _parse_rust_expected_rules(source: str) -> list[tuple[str, int, str]]:
    marker = "const EXPECTED_RULES"
    if marker not in source:
        return []
    segment = source.split(marker, 1)[1].split("#[cfg(test)]", 1)[0]
    matches = re.findall(r'\(\s*"([^"]+)"\s*,\s*(\d+)\s*,\s*"([^"]+)"\s*,?\s*\)', segment)
    return [(rule_id, int(priority), reason) for rule_id, priority, reason in matches]


def _active_parity(repo_root: Path, active_bundle: dict[str, Any]) -> dict[str, Any]:
    rules = active_bundle.get("rules", [])
    canonical = json.dumps(rules, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    computed_hash = hashlib.sha256(canonical).hexdigest()
    rust_path = repo_root / "rust-engine" / "src" / "rules_engine.rs"
    rust_source = rust_path.read_text(encoding="utf-8")
    hash_match = re.search(r'CURRENT_RULESET_SHA256:\s*&str\s*=\s*\n?\s*"([0-9a-f]{64})"', rust_source)
    rust_hash = hash_match.group(1) if hash_match else None
    expected = _parse_rust_expected_rules(rust_source)
    actual = [
        (str(rule.get("id", "")), int(rule.get("priority", -1)), str(rule.get("denial_reason", "")))
        for rule in rules
    ]
    config = _read_json(repo_root / "rust-engine" / "config.json", {})
    configured_backend = config.get("rules_backend") if isinstance(config, dict) else None
    default_backend = configured_backend or "hardcoded_g1_g10"
    bundle_hash = active_bundle.get("rules_sha256")
    exact_parity = (
        len(actual) == 13
        and actual == expected
        and computed_hash == bundle_hash
        and computed_hash == rust_hash
    )
    return {
        "bundle_rule_count": len(actual),
        "computed_rules_sha256": computed_hash,
        "bundle_rules_sha256": bundle_hash,
        "rust_pinned_rules_sha256": rust_hash,
        "ordered_rule_metadata_matches_rust": actual == expected,
        "hash_matches_bundle_and_rust": computed_hash == bundle_hash == rust_hash,
        "exact_g1_g10_parity": exact_parity,
        "configured_rules_backend": configured_backend,
        "resolved_default_rules_backend": default_backend,
        "hardcoded_default_preserved": default_backend == "hardcoded_g1_g10",
    }


def _imported_gate_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    source = path.read_text(encoding="utf-8")
    names = re.findall(r'gate\("(G\d+[A-Z]?_[A-Z0-9_]+)"', source)
    return [{"rule_id": name} for name in dict.fromkeys(names)]


def _reported_corpus_matches(repo_root: Path) -> list[str]:
    patterns = ("457k", "457000", "457_000")
    matches: list[str] = []
    skipped = {".git", ".venv", "node_modules", "target", "out", "cache"}
    for current, directories, files in os.walk(repo_root, followlinks=False):
        directories[:] = [directory for directory in directories if directory not in skipped]
        current_path = Path(current)
        for filename in files:
            if any(pattern in filename.lower() for pattern in patterns):
                matches.append((current_path / filename).relative_to(repo_root).as_posix())
    return sorted(matches)


def build_rules_corpus_audit(workdir: Path) -> dict[str, Any]:
    workdir = workdir.resolve()
    repo_root = workdir.parent
    reports = workdir / "reports"
    active_bundle = _read_json(repo_root / "rust-engine" / "rules_active_v1.json")
    if not isinstance(active_bundle, dict):
        raise FileNotFoundError("rust-engine/rules_active_v1.json is required for the corpus audit")

    active_rules = _records(active_bundle, "rules")
    legacy_program_rules = _records(_read_json(reports / "rules_by_program.json", {}))
    legacy_federal_medicaid = _records(_read_json(reports / "federal_medicaid_rules.json", []))
    legacy_inventory = _read_json(reports / "rule_inventory.json", {}) or {}
    legacy_verified_summary = _read_json(reports / "verified_rules_summary.json", {}) or {}
    verified_rules = _records(_read_json(reports / "verified_rules_clean_full_hierarchy.json", {}))
    claude_raw = _records(_read_json(reports / "claude_web_candidate_corpus.json", {}), "candidate_rules")
    claude_promotion = _records(_read_json(reports / "claude_web_promotion_ready.json", []))
    claude_executable = _records(_read_json(reports / "claude_web_executable_rule_candidates.json", []))
    claude_mapping = _records(_read_json(reports / "claude_web_deterministic_mapping_candidates.json", []))
    claude_shadow_payload = _read_json(reports / "claude_web_rust_shadow_rules.json", {}) or {}
    claude_shadow = _records(claude_shadow_payload, "rules")
    legacy_executable = _records(_read_json(reports / "executable_rule_candidates.json", []))
    legacy_rules_by_type = _records(_read_json(reports / "rules_by_type.json", {}))
    legacy_human_review = _records(_read_json(reports / "human_review_queue.json", []))
    verified_hierarchy = _records(_read_json(reports / "verified_rules_by_hierarchy.json", {}))
    claude_candidate_review = _records(_read_json(reports / "claude_web_candidate_review.json", {}), "candidates")
    claude_human_review = _records(_read_json(reports / "claude_web_human_review_queue.json", []))
    claude_hierarchy = _records(_read_json(reports / "claude_web_hierarchy_report.json", {}))
    claude_mapping_qa_payload = _read_json(reports / "claude_web_mapping_qa.json", {}) or {}
    claude_mapping_qa = _records(claude_mapping_qa_payload, "candidates")
    rules_json = _read_json(repo_root / "rust-engine" / "rules.json")
    rules_v9 = _read_json(repo_root / "rust-engine" / "rules_v9.json")
    imported_gates = _imported_gate_records(
        repo_root / "blind-ledger-app-layer" / "rules-engine-rust" / "src" / "lib.rs"
    )
    reported_matches = _reported_corpus_matches(repo_root)

    corpora = [
        _entry(
            "active_g1_g10_v1",
            "active_runtime",
            "rust-engine/rules_active_v1.json",
            active_rules,
            count_semantics="ordered deterministic denial branches",
            notes=[
                "Opt-in versioned_g1_g10 implementation; hardcoded_g1_g10 remains the default.",
                "Runtime eligibility depends on exact pinned-hash and G1-G10 parity.",
            ],
        ),
        _reference_policy_entry("rules_v7_reference_ast", "rust-engine/rules.json", rules_json),
        _reference_policy_entry("rules_v9_target_ast", "rust-engine/rules_v9.json", rules_v9),
        _entry(
            "legacy_graph_rule_export",
            "invalid_or_stale",
            "gov-rules-kg-prototype/reports/rules_by_program.json",
            legacy_program_rules,
            notes=["Legacy report derivative; not a runtime source and not additive with its hierarchy indexes."],
        ),
        _entry(
            "legacy_executable_candidates",
            "invalid_or_stale",
            "gov-rules-kg-prototype/reports/executable_rule_candidates.json",
            legacy_executable,
            notes=["Legacy candidate-only export lacks source URL and citation fields."],
        ),
        _entry(
            "legacy_federal_medicaid_subset",
            "invalid_or_stale",
            "gov-rules-kg-prototype/reports/federal_medicaid_rules.json",
            legacy_federal_medicaid,
            notes=[
                "Filtered legacy graph derivative; overlaps the legacy graph export and is not additive.",
                "Most records still require human review.",
            ],
        ),
        _entry(
            "machine_validated_hierarchy_candidates",
            "promotion_ready",
            "gov-rules-kg-prototype/reports/verified_rules_clean_full_hierarchy.json",
            verified_rules,
            notes=["Machine-validated candidates are not legally verified or runtime eligible."],
        ),
        _entry(
            "claude_web_candidate_corpus",
            "shadow_only",
            "gov-rules-kg-prototype/reports/claude_web_candidate_corpus.json",
            claude_raw,
            notes=["Source-grounded research candidates only; no automatic promotion."],
        ),
        _entry(
            "claude_web_promotion_ready",
            "promotion_ready",
            "gov-rules-kg-prototype/reports/claude_web_promotion_ready.json",
            claude_promotion,
            notes=["Promotion-ready means pipeline-reviewed, not legally verified."],
        ),
        _entry(
            "claude_web_executable_candidates",
            "promotion_ready",
            "gov-rules-kg-prototype/reports/claude_web_executable_rule_candidates.json",
            claude_executable,
            notes=["Needs deterministic mapping; not a runtime ruleset."],
        ),
        _entry(
            "claude_web_deterministic_mapping_candidates",
            "deterministic_candidate",
            "gov-rules-kg-prototype/reports/claude_web_deterministic_mapping_candidates.json",
            claude_mapping,
            notes=["Heuristic deterministic shape only; runtime promotion is forbidden."],
        ),
        _entry(
            "claude_web_rust_shadow_bundle",
            "shadow_only",
            "gov-rules-kg-prototype/reports/claude_web_rust_shadow_rules.json",
            claude_shadow,
            notes=["Rust-validated non-runtime bundle with proof_binding=false."],
        ),
        _entry(
            "cofounder_app_rules_engine",
            "reference_only",
            "blind-ledger-app-layer/rules-engine-rust/src/lib.rs",
            imported_gates,
            count_semantics="hardcoded imported gate definitions",
            notes=["Standalone imported semantics; not wired into the active Rust adjudicator."],
        ),
        _entry(
            "reported_cofounder_457k_rules",
            "invalid_or_stale",
            "not located in repository",
            None,
            count_semantics="reported external count; unavailable for verification",
            status="not_present",
            notes=[
                f"Reported count is {REPORTED_COFUNDER_RULE_COUNT}; no matching corpus artifact was located.",
                "Count, duplicates, coverage, provenance, and legal status cannot be verified.",
            ],
        ),
    ]
    corpora[-1]["reported_record_count"] = REPORTED_COFUNDER_RULE_COUNT
    corpora[-1]["matching_paths"] = reported_matches

    raw_ids = {_identifier(record) for record in claude_raw if _identifier(record)}
    promotion_ids = {_identifier(record) for record in claude_promotion if _identifier(record)}
    missing_from_review = sorted(raw_ids - promotion_ids)
    legacy_inventory_count = legacy_inventory.get("total_graph_atomic_rules")
    legacy_summary_count = legacy_verified_summary.get("total_rules_in_graph")
    parity = _active_parity(repo_root, active_bundle)

    serious_findings = []
    if missing_from_review:
        serious_findings.append(
            {
                "finding_id": "claude_lineage_incomplete",
                "severity": "high",
                "detail": f"{len(missing_from_review)} Claude corpus candidates are absent from the current promotion-ready export.",
                "candidate_ids": missing_from_review,
            }
        )
    if legacy_inventory_count != legacy_summary_count:
        serious_findings.append(
            {
                "finding_id": "legacy_report_count_mismatch",
                "severity": "high",
                "detail": "Legacy report totals disagree; derivatives are stale and must not be added together.",
                "rule_inventory_total": legacy_inventory_count,
                "verified_summary_total": legacy_summary_count,
                "rules_by_program_records": len(legacy_program_rules),
            }
        )
    if not reported_matches:
        serious_findings.append(
            {
                "finding_id": "reported_457k_corpus_missing",
                "severity": "high",
                "detail": "The reported approximately 457k-rule corpus is not present and cannot be audited.",
            }
        )
    if not parity["exact_g1_g10_parity"] or not parity["hardcoded_default_preserved"]:
        serious_findings.append(
            {
                "finding_id": "active_runtime_parity_failure",
                "severity": "critical",
                "detail": "Active versioned rules do not preserve the required hash/parity/default boundary.",
            }
        )
    candidate_entries = [entry for entry in corpora if entry["classification"] in {"deterministic_candidate", "promotion_ready", "shadow_only"}]
    if any(
        entry.get("provenance_coverage", {}).get("source_hash", {}).get("missing", 0) > 0
        for entry in candidate_entries
        if entry.get("provenance_coverage")
    ):
        serious_findings.append(
            {
                "finding_id": "candidate_source_hashes_missing",
                "severity": "high",
                "detail": "Candidate corpora lack complete source hashes, preventing immutable provenance verification.",
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "audit_mode": "read_only_json_and_source_inventory_no_sqlite",
        "sqlite_pipeline_used": False,
        "runtime_boundaries": {
            "default_rules_backend": "hardcoded_g1_g10",
            "opt_in_rules_backend": "versioned_g1_g10",
            "forbidden_runtime_inputs": [
                "rust-engine/rules.json",
                "rust-engine/rules_v9.json",
                "Claude web candidate and shadow corpora",
                "reported cofounder 457k corpus",
                "legacy SQLite graph exports",
            ],
            "proof_backends_preserved": ["groth16", "stark_attested"],
            "automatic_candidate_promotion": False,
        },
        "active_rules_parity": parity,
        "corpora": corpora,
        "lineage": {
            "claude_web": {
                "candidate_corpus": len(claude_raw),
                "promotion_ready": len(claude_promotion),
                "executable_candidates": len(claude_executable),
                "deterministic_mapping_candidates": len(claude_mapping),
                "rust_shadow_rules": len(claude_shadow),
                "missing_from_current_promotion_export": len(missing_from_review),
                "missing_candidate_ids": missing_from_review,
            },
            "legacy_graph": {
                "rules_by_program_records": len(legacy_program_rules),
                "rule_inventory_total": legacy_inventory_count,
                "verified_summary_total": legacy_summary_count,
                "machine_validated_candidates": len(verified_rules),
                "legacy_executable_candidates": len(legacy_executable),
                "federal_medicaid_subset": len(legacy_federal_medicaid),
            },
        },
        "non_additive_derivative_artifacts": [
            {
                "path": "gov-rules-kg-prototype/reports/rules_by_type.json",
                "record_references": len(legacy_rules_by_type),
                "role": "legacy multi-index view; records may appear under multiple types",
            },
            {
                "path": "gov-rules-kg-prototype/reports/human_review_queue.json",
                "record_references": len(legacy_human_review),
                "role": "legacy review queue",
            },
            {
                "path": "gov-rules-kg-prototype/reports/verified_rules_by_hierarchy.json",
                "record_references": len(verified_hierarchy),
                "role": "hierarchy view of the machine-validated candidate subset",
            },
            {
                "path": "gov-rules-kg-prototype/reports/claude_web_candidate_review.json",
                "record_references": len(claude_candidate_review),
                "role": "review annotations over the Claude candidate corpus",
            },
            {
                "path": "gov-rules-kg-prototype/reports/claude_web_human_review_queue.json",
                "record_references": len(claude_human_review),
                "role": "Claude lineage review queue",
            },
            {
                "path": "gov-rules-kg-prototype/reports/claude_web_hierarchy_report.json",
                "record_references": len(claude_hierarchy),
                "role": "hierarchy view of reviewed Claude candidates",
            },
            {
                "path": "gov-rules-kg-prototype/reports/claude_web_mapping_qa.json",
                "record_references": len(claude_mapping_qa),
                "role": "QA annotations over deterministic mapping candidates",
            },
            {
                "path": "gov-rules-kg-prototype/data/rules_kg.sqlite",
                "record_references": None,
                "role": "legacy SQLite source intentionally not opened by this audit",
            },
        ],
        "serious_findings": serious_findings,
        "phase_r2_blockers": [
            "Canonical deterministic rule schema and operator allowlist do not yet cover promoted government rules.",
            "Candidate source hashes and effective dates are incomplete.",
            "The five-candidate Claude lineage gap must be reviewed or explicitly excluded.",
            "The reported 457k corpus must be supplied with immutable provenance and a reproducible manifest.",
            "No candidate is legally verified or eligible for runtime activation.",
        ],
    }


def _markdown(audit: dict[str, Any]) -> str:
    lines = [
        "# Rules Corpus Inventory",
        "",
        "> Phase R1 read-only baseline. Promotion-ready and machine-validated candidates are not legally verified rules.",
        "",
        "## Runtime Boundary",
        "",
        "- Default evaluator: `hardcoded_g1_g10`",
        "- Opt-in parity evaluator: `versioned_g1_g10`",
        "- Automatic candidate promotion: disabled",
        "- SQLite graph pipeline used: no",
        "- Proof paths preserved: Groth16 and `stark_attested`",
        "",
        "## Active Parity",
        "",
        f"- Exact G1-G10 parity: `{str(audit['active_rules_parity']['exact_g1_g10_parity']).lower()}`",
        f"- Pinned hash: `{audit['active_rules_parity']['computed_rules_sha256']}`",
        f"- Hardcoded default preserved: `{str(audit['active_rules_parity']['hardcoded_default_preserved']).lower()}`",
        "",
        "## Corpora",
        "",
        "| Corpus | Classification | Records | Programs | URL | Citation | Source hash | Content duplicate excess |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in audit["corpora"]:
        provenance = entry.get("provenance_coverage") or {}
        duplicates = entry.get("duplicate_counts") or {}
        lines.append(
            "| {corpus} | {classification} | {records} | {programs} | {urls} | {citations} | {hashes} | {duplicates} |".format(
                corpus=entry["corpus_id"],
                classification=entry["classification"],
                records=entry.get("record_count") if entry.get("record_count") is not None else "unavailable",
                programs=(entry.get("program_coverage") or {}).get("program_count", "unavailable"),
                urls=provenance.get("source_url", {}).get("present", "unavailable"),
                citations=provenance.get("citation", {}).get("present", "unavailable"),
                hashes=provenance.get("source_hash", {}).get("present", "unavailable"),
                duplicates=duplicates.get("normalized_content", {}).get("duplicate_excess_records", "unavailable"),
            )
        )
    lines.extend(["", "## Serious Findings", ""])
    for finding in audit["serious_findings"]:
        lines.append(f"- **{finding['severity'].upper()} `{finding['finding_id']}`:** {finding['detail']}")
    lines.extend(["", "## Phase R2 Blockers", ""])
    lines.extend(f"- {blocker}" for blocker in audit["phase_r2_blockers"])
    lines.append("")
    return "\n".join(lines)


def write_rules_corpus_audit(workdir: Path) -> dict[str, Any]:
    audit = build_rules_corpus_audit(workdir)
    reports = workdir.resolve() / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    json_path = reports / "rules_corpus_inventory.json"
    markdown_path = reports / "rules_corpus_inventory.md"
    json_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_markdown(audit), encoding="utf-8")
    return {
        "schema_version": audit["schema_version"],
        "corpus_count": len(audit["corpora"]),
        "serious_finding_count": len(audit["serious_findings"]),
        "exact_g1_g10_parity": audit["active_rules_parity"]["exact_g1_g10_parity"],
        "hardcoded_default_preserved": audit["active_rules_parity"]["hardcoded_default_preserved"],
        "reported_457k_corpus_status": next(
            entry["inventory_status"]
            for entry in audit["corpora"]
            if entry["corpus_id"] == "reported_cofounder_457k_rules"
        ),
        "json": str(json_path),
        "markdown": str(markdown_path),
    }
