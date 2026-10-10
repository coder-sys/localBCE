#!/usr/bin/env python3
"""Build the inactive RightRail handoff crosswalk and review queue."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "localbce-rightrail-handoff-crosswalk-v1"
QUEUE_SCHEMA_VERSION = "localbce-rightrail-handoff-port-queue-v1"
CONTROL_SCHEMA_VERSION = "localbce-rightrail-hardening-controls-v1"
PQ_SCHEMA_VERSION = "localbce-rightrail-pq-compatibility-v1"

CATALOG_NAME = "handoff_20261003_catalog_v1.jsonl"
CATALOG_SUMMARY_NAME = "handoff_20261003_catalog_summary_v1.json"
QUEUE_NAME = "handoff_20261003_port_queue_v1.jsonl"
SUMMARY_NAME = "handoff_20261003_crosswalk_summary_v1.json"
CONTROLS_NAME = "handoff_20261003_hardening_controls_v1.json"
PQ_NAME = "handoff_20261003_pq_compatibility_v1.json"
CHECKPOINT_NAME = "handoff_20261003_integration_checkpoint_v1.json"

EXPECTED_RECORDS = 1108
EXPECTED_PACKAGE_FILES = 323
EXPECTED_TRUNK_FILES = 637
EXPECTED_GIT_REFS = 148

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "right-rail-integration" / "reports"


class CrosswalkError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def queue_id(record_id: str) -> str:
    digest = hashlib.sha256(f"port-queue\0{record_id}".encode("ascii")).hexdigest()[:24]
    return f"rrport-{digest}"


def load_catalog(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        for line_number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), start=1):
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise CrosswalkError(f"catalog line {line_number} is not an object")
            records.append(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CrosswalkError(f"could not read catalog {path}: {exc}") from exc
    if len(records) != EXPECTED_RECORDS:
        raise CrosswalkError(f"expected {EXPECTED_RECORDS} catalog records, got {len(records)}")
    ids = [record.get("record_id") for record in records]
    if len(ids) != len(set(ids)):
        raise CrosswalkError("catalog record IDs are not unique")
    return records


def target_for(domain: str) -> tuple[str, str, list[str]]:
    mapping = {
        "authorization_and_governance": (
            "governance_and_ops",
            "ops/, STARK_RUNTIME.md, and existing governed contract tests",
            ["architecture_reviewer", "security_reviewer"],
        ),
        "adjudication_and_rules": (
            "rules_engine",
            "RULES_ENGINE.md and gov-rules-kg-prototype/",
            ["rules_reviewer", "legal_reviewer"],
        ),
        "settlement_and_recovery": (
            "stark_settlement",
            "rust-engine settlement journal and STARK reconciliation tests",
            ["settlement_reviewer", "security_reviewer"],
        ),
        "state_and_audit_history": (
            "state_and_audit",
            "Rust/STARK state ownership and append-only audit controls",
            ["architecture_reviewer", "operations_reviewer"],
        ),
        "privacy_and_source_evidence": (
            "privacy_and_provenance",
            "rules source evidence and operational privacy controls",
            ["privacy_reviewer", "security_reviewer"],
        ),
        "formal_verification": (
            "formal_lane",
            "right-rail-integration/formal/",
            ["formal_methods_reviewer", "architecture_reviewer"],
        ),
        "post_quantum_research": (
            "post_quantum_research",
            "right-rail-integration/pq/",
            ["cryptography_reviewer", "security_reviewer"],
        ),
        "ui_and_operations": (
            "ui_and_operations_reference",
            "inactive app-layer and operations review material",
            ["operations_reviewer", "privacy_reviewer"],
        ),
    }
    try:
        return mapping[domain]
    except KeyError as exc:
        raise CrosswalkError(f"unsupported catalog domain: {domain}") from exc


def action_for(disposition: str) -> str:
    actions = {
        "adopt_control": "review_control_for_localbce_test_or_validator",
        "adapt_specification": "rewrite_selected_invariant_without_copying_runtime",
        "shadow_candidate": "evaluate_only_in_isolated_non_runtime_lane",
        "reference_only": "retain_hash_and_location_as_reference_evidence",
        "superseded_duplicate": "retain_lineage_to_canonical_content_record",
        "quarantine": "do_not_execute_extract_import_or_activate",
    }
    try:
        return actions[disposition]
    except KeyError as exc:
        raise CrosswalkError(f"unsupported disposition: {disposition}") from exc


def blockers_for(record: dict[str, Any]) -> list[str]:
    blockers = ["human_review_not_recorded", "runtime_activation_forbidden"]
    disposition = record["disposition"]
    if disposition == "quarantine":
        blockers.extend(["security_quarantine", "execution_forbidden"])
    if record["source_surface"] == "git_ref":
        blockers.append("historical_ref_not_reviewed")
    if record["domain"] == "formal_verification":
        blockers.extend(["formal_toolchain_reproduction_required", "runtime_equivalence_not_established"])
    if record["domain"] == "post_quantum_research":
        blockers.extend(["cryptographic_review_required", "production_dependency_forbidden"])
    if disposition in {"adapt_specification", "shadow_candidate"}:
        blockers.append("local_reimplementation_and_tests_required")
    return sorted(set(blockers))


def make_queue(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    queue = []
    for record in records:
        target_subsystem, target_location, reviewer_roles = target_for(record["domain"])
        value = {
            "schema_version": QUEUE_SCHEMA_VERSION,
            "queue_id": queue_id(record["record_id"]),
            "catalog_record_id": record["record_id"],
            "source_surface": record["source_surface"],
            "source_locator": record["locator"],
            "source_sha256": record.get("sha256"),
            "source_git_object_id": record.get("git_object_id"),
            "domain": record["domain"],
            "disposition": record["disposition"],
            "proposed_action": action_for(record["disposition"]),
            "target_subsystem": target_subsystem,
            "target_location": target_location,
            "blockers": blockers_for(record),
            "required_reviewer_roles": reviewer_roles,
            "human_decision": None,
            "human_decision_by": None,
            "human_decision_at": None,
            "human_decision_rationale": None,
            "execution_allowed": False,
            "runtime_eligible": False,
            "proof_binding": False,
            "production_evidence": False,
        }
        queue.append(value)
    return sorted(queue, key=lambda item: item["queue_id"])


CONTROLS = [
    {
        "control_id": "RRH-AUTHORITY-SEPARATION",
        "title": "Explicit authority for consequential actions",
        "source_path": "CONSTITUTION.md",
        "line_start": 24,
        "line_end": 25,
        "evidence_text": "Any power to approve, hold, release or redirect an external action needs separate, explicit state authority.",
        "local_target": "governance roles, timelock controls, and treasury separation",
        "local_evidence": [
            {
                "path": "blind-ledger/test/StarkGovernedV2.t.sol",
                "required_markers": [
                    "test_EmergencyPauseIsImmediateButUnpauseIsTimelocked",
                    "test_AttestorPolicyVerifierAndAllowlistChangesAreTimelocked",
                    "test_TreasuryTransferIsTimelockedAndTwoStep",
                ],
                "status": "implemented_and_tested",
            }
        ],
    },
    {
        "control_id": "RRH-SINGLE-WRITER",
        "title": "One authoritative writer per state domain",
        "source_path": "CONSTITUTION.md",
        "line_start": 44,
        "line_end": 45,
        "evidence_text": "Each responsibility has exactly one authoritative writer.",
        "local_target": "PostgreSQL rules ownership, Rust proof state, and settlement journal boundaries",
        "local_evidence": [
            {
                "path": "right-rail-integration/DATABASE_CROSSWALK.md",
                "required_markers": ["No second active writer", "PostgreSQL remains the sole bulk rules/source/review database"],
                "status": "documented_boundary",
            },
            {
                "path": "stark-engine/tests/phase8_production_nullifier_state.rs",
                "required_markers": ["file_provider_is_atomic_and_exclusive"],
                "status": "implemented_and_tested",
            },
        ],
    },
    {
        "control_id": "RRH-ATOMIC-COMMIT",
        "title": "Atomic history, projection, and outbox identity",
        "source_path": "CONSTITUTION.md",
        "line_start": 46,
        "line_end": 47,
        "evidence_text": "History, current projection and the action/outbox identity commit together, atomically.",
        "local_target": "settlement journal and state compare-and-swap tests",
        "local_evidence": [
            {
                "path": "stark-engine/src/production_stark_settlement.rs",
                "required_markers": ["write_json_atomic", "local_state_committed"],
                "status": "implemented_and_tested",
            },
            {
                "path": "stark-engine/tests/phase8_production_nullifier_state.rs",
                "required_markers": ["approved_transition_persists_and_advances_generation", "file_provider_is_atomic_and_exclusive"],
                "status": "implemented_and_tested",
            },
        ],
    },
    {
        "control_id": "RRH-IDEMPOTENT-RETRY",
        "title": "Exact retry is duplicate; changed retry conflicts",
        "source_path": "CONSTITUTION.md",
        "line_start": 48,
        "line_end": 50,
        "evidence_text": "An exact retry is a duplicate; changed meaning is a conflict.",
        "local_target": "settlement request idempotency and reconciliation conflict tests",
        "local_evidence": [
            {
                "path": "stark-engine/tests/phase8_production_nullifier_state.rs",
                "required_markers": ["duplicate_and_deterministic_index_collision_are_rejected", "stale_transition_fails_compare_and_swap"],
                "status": "implemented_and_tested",
            },
            {
                "path": "stark-engine/src/production_stark_settlement.rs",
                "required_markers": ["possible reorg or wrong RPC chain", "conflicts with both sides of the finalized transition"],
                "status": "implemented_and_tested",
            },
        ],
    },
    {
        "control_id": "RRH-APPEND-ONLY-HISTORY",
        "title": "History is append-only",
        "source_path": "CONSTITUTION.md",
        "line_start": 51,
        "line_end": 52,
        "evidence_text": "History is never rewound; corrections are new, linked facts.",
        "local_target": "append-only audit records and hash-linked reconciliation evidence",
        "local_evidence": [
            {
                "path": "ops/monitoring_events.json",
                "required_markers": ["previousHash", "newHash", "transactionHash", "blockNumber"],
                "status": "monitoring_contract_only",
            },
            {
                "path": "right-rail-integration/HARDENING_CONTROLS.md",
                "required_markers": ["append-only, linked corrections"],
                "status": "documented_boundary",
            },
        ],
    },
    {
        "control_id": "RRH-INDEPENDENT-REPLAY",
        "title": "Independent read-only verification and replay",
        "source_path": "ARCHITECTURE.md",
        "line_start": 16,
        "line_end": 21,
        "evidence_text": "independent checker, read-only; Switch: read-only replay and comparison",
        "local_target": "read-only reconciliation and deterministic replay validation",
        "local_evidence": [
            {
                "path": "scripts/generate_stark_pilot_reconciliation_report.py",
                "required_markers": ["reconciliation", "chain"],
                "status": "implemented_read_only_report",
            },
            {
                "path": "stark-engine/src/bin/reconcile_production_stark_settlement.rs",
                "required_markers": ["reconcile_production_stark_settlement"],
                "status": "implemented_and_tested",
            },
        ],
    },
    {
        "control_id": "RRH-FINALITY-BOUND-SETTLEMENT",
        "title": "Settlement changes state only after finality",
        "source_path": "docs/RIGHTRAIL_FULL_STACK_TARGET.md",
        "line_start": 173,
        "line_end": 177,
        "evidence_text": "States move to released or denied only by a new determination revision.",
        "local_target": "existing finalized settlement journal; approved advances and denied preserves roots",
        "local_evidence": [
            {
                "path": "stark-engine/src/production_stark_settlement.rs",
                "required_markers": ["wait_for_finality", "local_state_committed"],
                "status": "implemented_and_tested",
            },
            {
                "path": "stark-engine/tests/phase8_production_nullifier_state.rs",
                "required_markers": ["denied_transition_is_a_valid_no_op"],
                "status": "implemented_and_tested",
            },
        ],
    },
    {
        "control_id": "RRH-NO-SILENT-FALLBACK",
        "title": "Recovery never silently selects another implementation",
        "source_path": "CONSTITUTION.md",
        "line_start": 71,
        "line_end": 72,
        "evidence_text": "When Lean fails, nothing silently falls back to another implementation.",
        "local_target": "no automatic STARK-to-Groth16 fallback",
        "local_evidence": [
            {
                "path": "rust-engine/src/main.rs",
                "required_markers": ["config_missing_proof_backend_preserves_groth16_default", "run_stark_attested_app"],
                "status": "implemented_and_tested",
            },
            {
                "path": "scripts/validate_stark_runtime_settlement.sh",
                "required_markers": ["proof_backend", "stark_attested", "replay unexpectedly succeeded"],
                "status": "implemented_and_tested",
            },
        ],
    },
    {
        "control_id": "RRH-PRIVACY-ALLOWLIST",
        "title": "Support and outputs receive approved material only",
        "source_path": "CONSTITUTION.md",
        "line_start": 60,
        "line_end": 63,
        "evidence_text": "Outputs are built from approved fields; support works from approved packages and fictional reproductions.",
        "local_target": "rules evidence and operations reporting privacy controls",
        "local_evidence": [
            {
                "path": "right-rail-integration/HARDENING_CONTROLS.md",
                "required_markers": ["allowlisted, non-sensitive support and analytics material"],
                "status": "documented_boundary",
            },
            {
                "path": "right-rail-integration/reports/operating_plan_safety_review_packet_v1.json",
                "required_markers": ["privacy-owner review", "approved non-sensitive material"],
                "status": "risk_tracked",
            },
        ],
    },
    {
        "control_id": "RRH-HONEST-EVIDENCE",
        "title": "Prototype evidence is not production qualification",
        "source_path": "CONSTITUTION.md",
        "line_start": 80,
        "line_end": 85,
        "evidence_text": "Verified locally is not qualified; production_usable=false and activation=false remain explicit.",
        "local_target": "STARK, rules, formal, and PQ status reporting",
        "local_evidence": [
            {
                "path": "ops/stark_v2_release_profile.example.json",
                "required_markers": ["production_usable", "legal_approval_recorded", "independent_audits_complete"],
                "status": "release_gate_enforced",
            },
            {
                "path": "right-rail-integration/reports/handoff_20261003_integration_checkpoint_v1.json",
                "required_markers": ["formal_runtime_dependency", "ml_dsa_runtime_activation"],
                "status": "integration_status_enforced",
            },
        ],
    },
]


def build_controls(catalog_by_locator: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
    controls = []
    for control in CONTROLS:
        source = catalog_by_locator.get(("trunk_member", control["source_path"]))
        if source is None:
            raise CrosswalkError(f"missing control source in catalog: {control['source_path']}")
        controls.append(
            {
                **control,
                "source_sha256": source["sha256"],
                "adoption_status": "selected_for_localbce_hardening",
                "runtime_behavior_changed": False,
                "human_approved": False,
                "proof_binding": False,
            }
        )
    body = {
        "schema_version": CONTROL_SCHEMA_VERSION,
        "control_count": len(controls),
        "controls": controls,
        "runtime_behavior_changed": False,
        "human_approval_count": 0,
        "proof_binding": False,
    }
    return {**body, "checkpoint_sha256": sha256_bytes(canonical_json(body))}


def build_pq(records: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = []
    for record in records:
        if record["domain"] != "post_quantum_research":
            continue
        candidates.append(
            {
                "catalog_record_id": record["record_id"],
                "source_surface": record["source_surface"],
                "source_locator": record["locator"],
                "source_sha256": record.get("sha256"),
                "format_family": "ML-DSA-87" if "mldsa" in record["locator"].lower() else "post_quantum_unspecified",
                "disposition": "research_only",
                "bytes_copied": False,
                "execution_allowed": False,
                "production_dependency": False,
                "runtime_eligible": False,
                "proof_binding": False,
            }
        )
    candidates.sort(key=lambda item: item["catalog_record_id"])
    body = {
        "schema_version": PQ_SCHEMA_VERSION,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "production_signature_scheme": "secp256k1_controlled_attestation_unchanged",
        "stark_envelope_bytes": 129,
        "ml_dsa_runtime_activation": False,
        "production_dependency_added": False,
        "preserved_binary_execution_allowed": False,
        "proof_binding": False,
    }
    return {**body, "checkpoint_sha256": sha256_bytes(canonical_json(body))}


def build() -> dict[str, bytes]:
    records = load_catalog(REPORTS / CATALOG_NAME)
    summary = json.loads((REPORTS / CATALOG_SUMMARY_NAME).read_text(encoding="ascii"))
    if summary.get("catalog_record_count") != len(records):
        raise CrosswalkError("catalog summary count does not match catalog")
    by_locator = {(record["source_surface"], record["locator"]): record for record in records}
    queue = make_queue(records)
    if len(queue) != len(records):
        raise CrosswalkError("crosswalk does not cover every catalog record")
    if any(item["human_decision"] is not None for item in queue):
        raise CrosswalkError("review queue contains a human decision")
    if any(item[field] for item in queue for field in ("execution_allowed", "runtime_eligible", "proof_binding")):
        raise CrosswalkError("review queue activates handoff material")
    queue_bytes = b"".join(canonical_json(item) for item in queue)
    controls = build_controls(by_locator)
    pq = build_pq(records)
    domain_counts = Counter(item["domain"] for item in queue)
    disposition_counts = Counter(item["disposition"] for item in queue)
    surface_counts = Counter(item["source_surface"] for item in queue)
    summary_body = {
        "schema_version": SCHEMA_VERSION,
        "catalog_checkpoint_sha256": summary["checkpoint_sha256"],
        "queue_record_count": len(queue),
        "queue_sha256": sha256_bytes(queue_bytes),
        "source_surface_counts": dict(sorted(surface_counts.items())),
        "domain_counts": dict(sorted(domain_counts.items())),
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "package_file_count": surface_counts["package_file"],
        "trunk_file_count": surface_counts["trunk_member"],
        "git_ref_count": surface_counts["git_ref"],
        "complete_catalog_coverage": len(queue) == EXPECTED_RECORDS,
        "human_decision_count": 0,
        "execution_allowed_count": 0,
        "runtime_eligible_count": 0,
        "proof_binding_count": 0,
        "hardening_control_count": controls["control_count"],
        "hardening_controls_checkpoint_sha256": controls["checkpoint_sha256"],
        "pq_candidate_count": pq["candidate_count"],
        "pq_checkpoint_sha256": pq["checkpoint_sha256"],
    }
    if (
        summary_body["package_file_count"] != EXPECTED_PACKAGE_FILES
        or summary_body["trunk_file_count"] != EXPECTED_TRUNK_FILES
        or summary_body["git_ref_count"] != EXPECTED_GIT_REFS
    ):
        raise CrosswalkError("crosswalk surface counts do not match required handoff counts")
    crosswalk_summary = {
        **summary_body,
        "checkpoint_sha256": sha256_bytes(canonical_json(summary_body)),
    }
    integration_files = [
        "right-rail-integration/DATABASE_CROSSWALK.md",
        "right-rail-integration/HARDENING_CONTROLS.md",
        "right-rail-integration/formal/README.md",
        "right-rail-integration/formal/lean-toolchain",
        "right-rail-integration/formal/lakefile.toml",
        "right-rail-integration/formal/LocalBCE/Settlement.lean",
        "right-rail-integration/formal/Settlement.tla",
        "right-rail-integration/formal/Settlement.cfg",
        "right-rail-integration/formal/settlement_model_v1.json",
        "right-rail-integration/pq/README.md",
    ]
    selected_files = []
    for relative in integration_files:
        path = ROOT / relative
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise CrosswalkError(f"missing integration file {relative}: {exc}") from exc
        selected_files.append({"path": relative, "sha256": sha256_bytes(content)})
    checkpoint_body = {
        "schema_version": "localbce-rightrail-integration-checkpoint-v1",
        "catalog_checkpoint_sha256": summary["checkpoint_sha256"],
        "crosswalk_checkpoint_sha256": crosswalk_summary["checkpoint_sha256"],
        "complete_catalog_record_count": len(records),
        "complete_disposition_count": len(queue),
        "selected_integration_files": selected_files,
        "external_handoff_committed": False,
        "sqlite_runtime_imported": False,
        "groth16_default_preserved": True,
        "stark_attested_explicitly_gated": True,
        "hardcoded_g1_g10_default_preserved": True,
        "stark_envelope_bytes": 129,
        "controlled_attestation_scheme": "secp256k1",
        "formal_runtime_dependency": False,
        "ml_dsa_runtime_activation": False,
        "execution_allowed_count": 0,
        "runtime_eligible_count": 0,
        "proof_binding_count": 0,
        "human_decision_count": 0,
    }
    integration_checkpoint = {
        **checkpoint_body,
        "checkpoint_sha256": sha256_bytes(canonical_json(checkpoint_body)),
    }
    return {
        QUEUE_NAME: queue_bytes,
        SUMMARY_NAME: json.dumps(crosswalk_summary, indent=2, sort_keys=True).encode("ascii") + b"\n",
        CONTROLS_NAME: json.dumps(controls, indent=2, sort_keys=True).encode("ascii") + b"\n",
        PQ_NAME: json.dumps(pq, indent=2, sort_keys=True).encode("ascii") + b"\n",
        CHECKPOINT_NAME: json.dumps(integration_checkpoint, indent=2, sort_keys=True).encode("ascii") + b"\n",
    }


def write_or_check(outputs: dict[str, bytes], *, check: bool) -> None:
    stale = []
    for name, expected in outputs.items():
        path = REPORTS / name
        if check:
            try:
                current = path.read_bytes()
            except OSError:
                stale.append(str(path))
                continue
            if current != expected:
                stale.append(str(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
    if stale:
        raise CrosswalkError("stale crosswalk outputs: " + ", ".join(stale))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify committed outputs")
    args = parser.parse_args()
    try:
        outputs = build()
        write_or_check(outputs, check=args.check)
        summary = json.loads(outputs[SUMMARY_NAME])
        print(
            json.dumps(
                {
                    "status": "ok",
                    "queue_record_count": summary["queue_record_count"],
                    "checkpoint_sha256": summary["checkpoint_sha256"],
                    "runtime_eligible_count": 0,
                },
                sort_keys=True,
            )
        )
        return 0
    except (CrosswalkError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
