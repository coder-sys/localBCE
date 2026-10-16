from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .canonical_rules import canonical_sha256
from .scaled_corpus import all_programs, load_source_registry, program_quotas
from .state_medicaid_core import (
    load_state_medicaid_preflight,
    load_state_medicaid_registry,
)


CHECKPOINT_SCHEMA = "localbce-rules-corpus-checkpoint-v1"
EXPECTED_CHECKPOINT_SHA256 = (
    "bf2959a6ed10e356601983493a23ad5af5d9cb5542a76b9447b149e87b84f531"
)
EXPECTED_RULES_SHA256 = (
    "95d38b6d8fc9c44b65feace024a07c22b4f11771fe6b23283ce73bbe0a7cb8e3"
)
GROUNDING_STATUSES = {"accepted", "pending", "rejected", "repair"}
INFERENCE_STATUSES = {"completed", "failed", "pending", "rejected"}


class RulesCheckpointError(ValueError):
    """Raised when the committed rules checkpoint fails an integrity check."""


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RulesCheckpointError(f"missing {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RulesCheckpointError(f"invalid JSON in {label}: {exc.msg}") from exc


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RulesCheckpointError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RulesCheckpointError(f"{label} must be a list")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RulesCheckpointError(f"{label} must be a nonnegative integer")
    return value


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise RulesCheckpointError(
            f"{label} mismatch: expected {expected!r}, got {actual!r}"
        )


def _validate_corpus(checkpoint: dict[str, Any]) -> dict[str, int]:
    corpus = _object(checkpoint.get("corpus"), "corpus")
    status_counts = _object(
        corpus.get("grounding_status_counts"), "corpus.grounding_status_counts"
    )
    _require_equal(set(status_counts), GROUNDING_STATUSES, "grounding status set")
    for status, count in status_counts.items():
        _nonnegative_int(count, f"grounding_status_counts.{status}")
    raw_count = _nonnegative_int(
        corpus.get("raw_grounded_candidate_count"),
        "corpus.raw_grounded_candidate_count",
    )
    _require_equal(raw_count, sum(status_counts.values()), "raw candidate total")

    accepted_count = _nonnegative_int(
        corpus.get("active_accepted_candidate_count"),
        "corpus.active_accepted_candidate_count",
    )
    with_date = _nonnegative_int(
        corpus.get("active_accepted_with_effective_date"),
        "corpus.active_accepted_with_effective_date",
    )
    missing_date = _nonnegative_int(
        corpus.get("active_accepted_missing_effective_date"),
        "corpus.active_accepted_missing_effective_date",
    )
    _require_equal(with_date + missing_date, accepted_count, "accepted date coverage")
    if accepted_count > status_counts["accepted"]:
        raise RulesCheckpointError("active accepted candidates exceed accepted records")

    draft_count = _nonnegative_int(
        corpus.get("current_draft_candidate_count"),
        "corpus.current_draft_candidate_count",
    )
    blocked_count = _nonnegative_int(
        corpus.get("blocked_draft_candidate_count"),
        "corpus.blocked_draft_candidate_count",
    )
    deterministic_count = _nonnegative_int(
        corpus.get("deterministic_candidate_count"),
        "corpus.deterministic_candidate_count",
    )
    _require_equal(
        blocked_count + deterministic_count, draft_count, "draft disposition total"
    )

    rows = _list(corpus.get("programs"), "corpus.programs")
    expected_programs = all_programs()
    _require_equal(corpus.get("program_count"), len(expected_programs), "program count")
    _require_equal(len(rows), len(expected_programs), "program row count")
    names: list[str] = []
    accepted_sum = 0
    deterministic_sum = 0
    quotas = program_quotas(600_000)
    for index, raw_row in enumerate(rows):
        row = _object(raw_row, f"corpus.programs[{index}]")
        program = row.get("program")
        if not isinstance(program, str) or not program:
            raise RulesCheckpointError(f"corpus.programs[{index}].program is invalid")
        names.append(program)
        accepted = _nonnegative_int(
            row.get("accepted_grounded_candidates"),
            f"corpus.programs[{index}].accepted_grounded_candidates",
        )
        deterministic = _nonnegative_int(
            row.get("deterministic_candidates"),
            f"corpus.programs[{index}].deterministic_candidates",
        )
        for field in (
            "active_source_count",
            "snapshot_retrieval_count",
            "active_program_section_count",
        ):
            _nonnegative_int(row.get(field), f"corpus.programs[{index}].{field}")
        if program in quotas:
            _require_equal(
                row.get("accepted_deficit"),
                max(quotas[program] - accepted, 0),
                f"{program} accepted deficit",
            )
            _require_equal(
                row.get("deterministic_deficit"),
                max(quotas[program] - deterministic, 0),
                f"{program} deterministic deficit",
            )
        accepted_sum += accepted
        deterministic_sum += deterministic

    if len(names) != len(set(names)):
        raise RulesCheckpointError("corpus program rows contain duplicate programs")
    _require_equal(set(names), set(expected_programs), "program coverage")
    _require_equal(accepted_sum, accepted_count, "accepted program total")
    _require_equal(
        deterministic_sum, deterministic_count, "deterministic program total"
    )
    _require_equal(
        corpus.get("programs_with_accepted_candidates"),
        sum(
            _nonnegative_int(
                _object(row, "program row").get("accepted_grounded_candidates"),
                "accepted_grounded_candidates",
            )
            > 0
            for row in rows
        ),
        "programs with accepted candidates",
    )
    _require_equal(
        corpus.get("programs_with_deterministic_candidates"),
        sum(
            _nonnegative_int(
                _object(row, "program row").get("deterministic_candidates"),
                "deterministic_candidates",
            )
            > 0
            for row in rows
        ),
        "programs with deterministic candidates",
    )
    return {
        "raw_grounded_candidates": raw_count,
        "active_accepted_candidates": accepted_count,
        "deterministic_candidates": deterministic_count,
        "programs": len(rows),
    }


def _validate_jobs(checkpoint: dict[str, Any]) -> dict[str, int]:
    jobs = _object(checkpoint.get("jobs"), "jobs")
    if jobs.get("paid_inference_paused") is not True:
        raise RulesCheckpointError("paid inference must remain paused")
    states = _list(jobs.get("inference_job_states"), "jobs.inference_job_states")
    seen: set[tuple[int, str]] = set()
    state_total = 0
    for index, raw_state in enumerate(states):
        state = _object(raw_state, f"jobs.inference_job_states[{index}]")
        pass_number = state.get("pass")
        status = state.get("status")
        if pass_number not in {1, 2} or status not in INFERENCE_STATUSES:
            raise RulesCheckpointError(
                f"jobs.inference_job_states[{index}] has an invalid pass/status"
            )
        key = (pass_number, status)
        if key in seen:
            raise RulesCheckpointError("duplicate inference job state row")
        seen.add(key)
        state_total += _nonnegative_int(
            state.get("count"), f"jobs.inference_job_states[{index}].count"
        )
        _require_equal(
            state.get("expired_leases"),
            0,
            f"jobs.inference_job_states[{index}].expired_leases",
        )

    usage = _object(jobs.get("inference_usage"), "jobs.inference_usage")
    for field in (
        "job_count",
        "attempts",
        "input_tokens",
        "output_tokens",
        "retry_rounds",
        "lease_renewals",
    ):
        _nonnegative_int(usage.get(field), f"jobs.inference_usage.{field}")
    _require_equal(state_total, usage["job_count"], "inference job-state total")

    durable = _object(jobs.get("durable_queue_states"), "jobs.durable_queue_states")
    for queue_name, raw_counts in durable.items():
        counts = _object(raw_counts, f"jobs.durable_queue_states.{queue_name}")
        for status, count in counts.items():
            _nonnegative_int(count, f"jobs.durable_queue_states.{queue_name}.{status}")
    return {"inference_jobs": state_total, "expired_leases": 0}


def _validate_provenance_and_quality(checkpoint: dict[str, Any]) -> None:
    corpus = _object(checkpoint.get("corpus"), "corpus")
    accepted = corpus["active_accepted_candidate_count"]
    provenance = _object(
        checkpoint.get("provenance_and_citations"), "provenance_and_citations"
    )
    for field in (
        "accepted_candidates",
        "citation_covered",
        "evidence_span_present",
        "source_snapshot_covered",
    ):
        _require_equal(provenance.get(field), accepted, f"provenance {field}")

    duplicate_state = _object(
        checkpoint.get("duplicates_and_conflicts"), "duplicates_and_conflicts"
    )
    _require_equal(
        duplicate_state.get("silently_merged_conflicts"),
        0,
        "silently merged conflicts",
    )
    _nonnegative_int(
        duplicate_state.get("active_open_conflicts"), "active open conflicts"
    )
    clusters = _list(duplicate_state.get("stored_clusters"), "stored clusters")
    seen_clusters: set[tuple[str, str]] = set()
    for index, raw_cluster in enumerate(clusters):
        cluster = _object(raw_cluster, f"stored_clusters[{index}]")
        key = (str(cluster.get("kind", "")), str(cluster.get("status", "")))
        if not all(key) or key in seen_clusters:
            raise RulesCheckpointError("duplicate or invalid conflict cluster summary")
        seen_clusters.add(key)
        cluster_count = _nonnegative_int(
            cluster.get("count"), f"stored_clusters[{index}].count"
        )
        if cluster_count == 0:
            raise RulesCheckpointError("stored conflict cluster count must be positive")

    blockers = _object(checkpoint.get("blockers"), "blockers")
    blocker_counts = _object(
        blockers.get("draft_blocker_counts"), "blockers.draft_blocker_counts"
    )
    _require_equal(
        set(blocker_counts),
        {"missing_effective_date", "conflicting_duplicate", "semantic_duplicate"},
        "draft blocker set",
    )
    for blocker, count in blocker_counts.items():
        _nonnegative_int(count, f"blockers.draft_blocker_counts.{blocker}")
    if blocker_counts["missing_effective_date"] > corpus["blocked_draft_candidate_count"]:
        raise RulesCheckpointError("missing-effective-date blockers exceed blocked drafts")
    for field in (
        "minimum_additional_physical_sections_lower_bound",
        "minimum_additional_program_contexts_lower_bound",
    ):
        _nonnegative_int(blockers.get(field), f"blockers.{field}")
    remaining_medicaid = _list(
        blockers.get("remaining_medicaid_capture_blockers"),
        "blockers.remaining_medicaid_capture_blockers",
    )
    if (
        any(not isinstance(source_id, str) or not source_id for source_id in remaining_medicaid)
        or len(remaining_medicaid) != len(set(remaining_medicaid))
        or remaining_medicaid != sorted(remaining_medicaid)
    ):
        raise RulesCheckpointError("Medicaid capture blockers must be unique sorted IDs")

    review = _object(
        checkpoint.get("review_legal_and_quality"), "review_legal_and_quality"
    )
    _require_equal(review.get("quality_gate_passed"), False, "quality gate")
    _require_equal(review.get("release_count"), 0, "corpus release count")
    _require_equal(review.get("passed_release_count"), 0, "passed release count")
    _require_equal(review.get("reviewer_decision_count"), 0, "reviewer decision count")
    _require_equal(review.get("reviewer_decisions"), [], "reviewer decisions")
    sample_count = _nonnegative_int(
        review.get("quality_sample_count"), "quality sample count"
    )
    two_role_count = _nonnegative_int(
        review.get("two_role_sample_count"), "two-role sample count"
    )
    if two_role_count > sample_count:
        raise RulesCheckpointError("two-role sample count exceeds quality sample count")
    gates = _object(review.get("quality_gates"), "review_legal_and_quality.quality_gates")
    if any(not isinstance(value, bool) for value in gates.values()):
        raise RulesCheckpointError("quality gates must be boolean")
    _require_equal(
        review.get("quality_gate_passed"), all(gates.values()), "aggregate quality gate"
    )
    measurements = _object(
        review.get("quality_measurements"),
        "review_legal_and_quality.quality_measurements",
    )
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0.0 <= value <= 1.0
        for value in measurements.values()
    ):
        raise RulesCheckpointError("quality measurements must be between zero and one")
    _require_equal(
        review.get("human_approved_medicaid_sources"),
        0,
        "human-approved Medicaid sources",
    )
    _require_equal(
        review.get("legally_verified_medicaid_sources"),
        0,
        "legally verified Medicaid sources",
    )


def _validate_source_registries(
    repo_root: Path, checkpoint: dict[str, Any]
) -> dict[str, int]:
    workdir = repo_root / "gov-rules-kg-prototype"
    registry_path = workdir / "data" / "source_manifests" / "state_medicaid_core_v1.json"
    preflight_path = workdir / "reports" / "state_medicaid_core_preflight_v1.json"
    try:
        federal = load_source_registry(workdir)
        medicaid_registry, registry_summary = load_state_medicaid_registry(registry_path)
        _, preflight_summary = load_state_medicaid_preflight(
            preflight_path, medicaid_registry
        )
    except ValueError as exc:
        raise RulesCheckpointError(str(exc)) from exc

    source_registries = _object(
        checkpoint.get("source_registries"), "source_registries"
    )
    expected_source_fields = {
        "federal_registry_id": federal["registry_id"],
        "federal_registry_manifest_sha256": federal["registry_manifest_sha256"],
        "medicaid_registry_id": medicaid_registry["registry_id"],
        "medicaid_registry_canonical_sha256": registry_summary["canonical_sha256"],
        "medicaid_preflight_canonical_sha256": preflight_summary["canonical_sha256"],
    }
    for field, expected in expected_source_fields.items():
        _require_equal(source_registries.get(field), expected, field)

    medicaid = _object(checkpoint.get("medicaid_core_v1"), "medicaid_core_v1")
    expected_medicaid_fields = {
        "registry_id": medicaid_registry["registry_id"],
        "source_count": registry_summary["source_count"],
        "registry_source_count": registry_summary["source_count"],
        "active_source_count": registry_summary["source_count"],
        "state_counts": registry_summary["state_counts"],
        "rule_family_coverage": registry_summary["rule_family_coverage"],
        "preflight_status_counts": preflight_summary["status_counts"],
        "adapter_required_source_ids": preflight_summary[
            "adapter_required_source_ids"
        ],
        "source_records_only": True,
        "candidates_created": 0,
        "california_shells_are_legal_evidence": False,
        "snapshot_count": 0,
        "fetch_job_count": 0,
        "captured_legal_evidence_source_count": 0,
        "human_approved_source_count": 0,
        "legally_verified_source_count": 0,
        "runtime_activation": False,
        "proof_binding": False,
    }
    for field, expected in expected_medicaid_fields.items():
        _require_equal(medicaid.get(field), expected, f"medicaid_core_v1.{field}")
    blockers = _object(checkpoint.get("blockers"), "blockers")
    _require_equal(
        blockers.get("remaining_medicaid_capture_blockers"),
        preflight_summary["adapter_required_source_ids"],
        "remaining Medicaid capture blockers",
    )
    return {
        "federal_source_entrypoints": len(federal["sources"]),
        "medicaid_source_records": registry_summary["source_count"],
        "medicaid_adapter_blockers": len(
            preflight_summary["adapter_required_source_ids"]
        ),
    }


def _validate_safety_boundaries(repo_root: Path, checkpoint: dict[str, Any]) -> None:
    safety = _object(checkpoint.get("safety_boundaries"), "safety_boundaries")
    expected = {
        "hardcoded_g1_g10_default": True,
        "rules_active_v1_unchanged_required": True,
        "candidate_rule_activation": False,
        "production_release_created": False,
        "human_or_legal_approval_implied": False,
        "legacy_sqlite_graph_used": False,
        "runtime_activation": False,
        "proof_binding": False,
        "runtime_activated_candidate_count": 0,
        "proof_bound_candidate_count": 0,
        "runtime_release_count": 0,
        "proof_bound_release_count": 0,
    }
    for field, expected_value in expected.items():
        _require_equal(safety.get(field), expected_value, f"safety_boundaries.{field}")

    rules_path = repo_root / "rust-engine" / "rules_active_v1.json"
    rules = _object(_load_json(rules_path, "active rules bundle"), "active rules bundle")
    _require_equal(rules.get("rules_sha256"), EXPECTED_RULES_SHA256, "active rules pin")
    rust_canonical_rules = json.dumps(
        rules.get("rules"), separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    _require_equal(
        hashlib.sha256(rust_canonical_rules).hexdigest(),
        EXPECTED_RULES_SHA256,
        "active rules canonical hash",
    )
    config = _object(
        _load_json(repo_root / "rust-engine" / "config.json", "Rust config"),
        "Rust config",
    )
    _require_equal(
        config.get("rules_backend", "hardcoded_g1_g10"),
        "hardcoded_g1_g10",
        "default rules backend",
    )
    _require_equal(config.get("proof_backend"), "none", "default proof backend")
    _require_equal(
        config.get("proof_execution_enabled"),
        False,
        "default proof execution gate",
    )
    rust_source = (repo_root / "rust-engine" / "src" / "rules_engine.rs").read_text(
        encoding="utf-8"
    )
    if EXPECTED_RULES_SHA256 not in rust_source:
        raise RulesCheckpointError("Rust active rules pin does not match the checkpoint")


def validate_rules_corpus_checkpoint(
    repo_root: Path,
    checkpoint_path: Path | None = None,
    *,
    expected_checkpoint_sha256: str | None = EXPECTED_CHECKPOINT_SHA256,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    checkpoint_path = (
        checkpoint_path.resolve()
        if checkpoint_path is not None
        else repo_root
        / "gov-rules-kg-prototype"
        / "reports"
        / "rules_corpus_checkpoint_v1.json"
    )
    checkpoint = _object(_load_json(checkpoint_path, "rules corpus checkpoint"), "checkpoint")
    _require_equal(checkpoint.get("schema_version"), CHECKPOINT_SCHEMA, "checkpoint schema")
    _require_equal(
        checkpoint.get("checkpoint_scope"),
        "paused_federal_scale_with_medicaid_core_v1_sources",
        "checkpoint scope",
    )
    stored_hash = checkpoint.get("canonical_checkpoint_sha256")
    calculated_hash = canonical_sha256(
        {
            key: value
            for key, value in checkpoint.items()
            if key != "canonical_checkpoint_sha256"
        }
    )
    _require_equal(stored_hash, calculated_hash, "checkpoint canonical SHA-256")
    if expected_checkpoint_sha256 is not None:
        _require_equal(stored_hash, expected_checkpoint_sha256, "pinned checkpoint SHA-256")

    corpus_summary = _validate_corpus(checkpoint)
    job_summary = _validate_jobs(checkpoint)
    _validate_provenance_and_quality(checkpoint)
    source_summary = _validate_source_registries(repo_root, checkpoint)
    _validate_safety_boundaries(repo_root, checkpoint)
    return {
        "status": "ok",
        "schema_version": CHECKPOINT_SCHEMA,
        "canonical_checkpoint_sha256": stored_hash,
        **corpus_summary,
        **job_summary,
        **source_summary,
        "paid_inference_paused": True,
        "runtime_activation": False,
        "proof_binding": False,
        "rules_backend": "hardcoded_g1_g10",
        "proof_backend": "none",
        "proof_execution_enabled": False,
        "rules_active_v1_sha256": EXPECTED_RULES_SHA256,
        "validation_scope": "committed_snapshot_only",
        "live_postgres_recount_performed": False,
    }
