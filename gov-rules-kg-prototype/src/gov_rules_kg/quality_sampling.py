from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Iterable

from .canonical_rules import canonical_sha256
from .scaled_corpus import all_programs, stable_id


QUALITY_SAMPLE_PLAN_SCHEMA = "localbce-rules-quality-sample-plan-v1"
QUALITY_REVIEW_SCHEMA = "localbce-rules-quality-review-v1"
REQUIRED_MEASUREMENTS = (
    "evidence_span_precise",
    "typed_mapping_correct",
    "program_classification_correct",
    "deterministic_rerun_match",
)


def _is_sha256(value: Any) -> bool:
    return re.fullmatch(r"[0-9a-fA-F]{64}", str(value)) is not None


def build_quality_sample_plan(
    *,
    release_id: str,
    candidates: Iterable[dict[str, Any]],
    target_count: int = 1_020,
) -> dict[str, Any]:
    if not release_id.strip():
        raise ValueError("quality sample release_id is required")
    if target_count < 1_020:
        raise ValueError("quality sample target must be at least 1,020")

    ordered: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    by_program: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in candidates:
        candidate = dict(raw)
        candidate_id = str(candidate.get("candidate_id", ""))
        program = str(candidate.get("primary_program", ""))
        if not candidate_id or candidate_id in seen_ids:
            raise ValueError("quality sample candidates require unique candidate IDs")
        if program not in all_programs():
            raise ValueError("quality sample candidate has an unknown program")
        if not str(candidate.get("draft_id", "")) or not _is_sha256(
            candidate.get("draft_hash", "")
        ):
            raise ValueError("quality sample candidate requires a draft ID and SHA-256 hash")
        reasons = candidate.get("mandatory_reasons") or []
        if not isinstance(reasons, list) or any(not str(reason).strip() for reason in reasons):
            raise ValueError("mandatory_reasons must be a list of nonempty strings")
        candidate["mandatory_reasons"] = sorted(set(str(reason) for reason in reasons))
        candidate["sample_rank"] = canonical_sha256(
            [release_id, "quality-sample", candidate_id]
        )
        seen_ids.add(candidate_id)
        ordered.append(candidate)
        by_program[program].append(candidate)

    for values in by_program.values():
        values.sort(key=lambda item: (item["sample_rank"], item["candidate_id"]))

    selected: dict[str, dict[str, Any]] = {}
    for candidate in ordered:
        if candidate["mandatory_reasons"]:
            selected[candidate["candidate_id"]] = candidate

    for program in all_programs():
        for candidate in by_program.get(program, [])[:20]:
            selected.setdefault(candidate["candidate_id"], candidate)

    for candidate in sorted(ordered, key=lambda item: (item["sample_rank"], item["candidate_id"])):
        if len(selected) >= target_count:
            break
        selected.setdefault(candidate["candidate_id"], candidate)

    samples: list[dict[str, Any]] = []
    for candidate in sorted(selected.values(), key=lambda item: item["candidate_id"]):
        reasons = candidate["mandatory_reasons"]
        mandatory_reason = ",".join(reasons) if reasons else None
        stratum = "mandatory" if mandatory_reason else "program_stratified"
        samples.append(
            {
                "sample_id": stable_id(
                    "sample",
                    release_id,
                    candidate["candidate_id"],
                    candidate["draft_hash"],
                ),
                "release_id": release_id,
                "candidate_id": candidate["candidate_id"],
                "primary_program": candidate["primary_program"],
                "draft_id": candidate["draft_id"],
                "draft_hash": candidate["draft_hash"],
                "stratum": stratum,
                "mandatory_reason": mandatory_reason,
            }
        )

    program_counts = {program: 0 for program in all_programs()}
    for sample in samples:
        program_counts[sample["primary_program"]] += 1
    payload = {
        "schema_version": QUALITY_SAMPLE_PLAN_SCHEMA,
        "release_id": release_id,
        "requested_sample_count": target_count,
        "candidate_count": len(ordered),
        "sample_count": len(samples),
        "mandatory_sample_count": sum(
            sample["mandatory_reason"] is not None for sample in samples
        ),
        "program_sample_counts": program_counts,
        "minimum_20_per_program": all(count >= 20 for count in program_counts.values()),
        "sample_target_met": len(samples) >= target_count,
        "samples": samples,
        "runtime_activation": False,
        "proof_binding": False,
    }
    payload["canonical_plan_hash"] = canonical_sha256(payload)
    return payload


def validate_quality_review_submission(
    submission: dict[str, Any], *, expected_role: str | None = None
) -> list[str]:
    errors: list[str] = []
    if submission.get("schema_version") != QUALITY_REVIEW_SCHEMA:
        errors.append("unsupported quality review schema")
    role = submission.get("reviewer_role")
    if role not in {"policy_reviewer", "legal_verifier"}:
        errors.append("quality review role must be policy_reviewer or legal_verifier")
    if expected_role is not None and role != expected_role:
        errors.append("quality review role does not match the assigned role")
    for field in ("sample_id", "candidate_id", "draft_hash", "reviewer_id"):
        if not str(submission.get(field, "")).strip():
            errors.append(f"quality review {field} is required")
    if not _is_sha256(submission.get("draft_hash", "")):
        errors.append("quality review draft_hash must be a SHA-256 digest")
    if not str(submission.get("rationale", "")).strip():
        errors.append("quality review rationale is required")
    measurements = submission.get("measurements")
    if not isinstance(measurements, dict):
        errors.append("quality review measurements must be an object")
    else:
        unexpected = sorted(set(measurements) - set(REQUIRED_MEASUREMENTS))
        if unexpected:
            errors.append(
                "quality review has unsupported measurements: " + ", ".join(unexpected)
            )
        for name in REQUIRED_MEASUREMENTS:
            if not isinstance(measurements.get(name), bool):
                errors.append(f"quality review measurement {name} must be boolean")
    if submission.get("runtime_activation") is not False:
        errors.append("quality review runtime_activation must be false")
    if submission.get("proof_binding") is not False:
        errors.append("quality review proof_binding must be false")
    return errors


def merge_quality_review_submissions(
    policy: dict[str, Any], legal: dict[str, Any]
) -> dict[str, Any]:
    errors = validate_quality_review_submission(policy, expected_role="policy_reviewer")
    errors.extend(
        validate_quality_review_submission(legal, expected_role="legal_verifier")
    )
    for field in ("sample_id", "candidate_id", "draft_hash"):
        if policy.get(field) != legal.get(field):
            errors.append(f"quality reviews disagree on {field}")
    if policy.get("reviewer_id") == legal.get("reviewer_id"):
        errors.append("policy and legal quality reviewers must be different people")
    if errors:
        raise ValueError("; ".join(errors))

    measurements = {
        name: bool(policy["measurements"][name] and legal["measurements"][name])
        for name in REQUIRED_MEASUREMENTS
    }
    payload = {
        "schema_version": "localbce-rules-quality-consensus-v1",
        "sample_id": policy["sample_id"],
        "candidate_id": policy["candidate_id"],
        "draft_hash": policy["draft_hash"],
        "policy_reviewer_id": policy["reviewer_id"],
        "legal_verifier_id": legal["reviewer_id"],
        "measurements": measurements,
        "runtime_activation": False,
        "proof_binding": False,
    }
    payload["consensus_hash"] = canonical_sha256(payload)
    return payload
