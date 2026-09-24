"""Offline, nonoperative v3 qualification-gate candidate.

This module validates synthetic profile and evidence packets. It never verifies
state authorization, changes the v2 gate, qualifies a release, or activates a
deployment.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha3_512
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping

from tools import ops_authority
from tools import qualification_gate as v2_gate


PROFILE_SCHEMA = "blind_ledger_qualification_profile_v3"
EVIDENCE_SCHEMA = "blind_ledger_qualification_evidence_v3"
RESULT_SCHEMA = "blind_ledger_qualification_candidate_result_v3"
MAX_DOCUMENT_BYTES = 64 * 1024

DIRECT_STATE_OWNED = "DIRECT_STATE_OWNED"
AUTHORITATIVE_ASSERTION = "AUTHORITATIVE_ASSERTION"
PRIVATE_ZK = "PRIVATE_ZK"
EVIDENCE_MODES = frozenset(
    {DIRECT_STATE_OWNED, AUTHORITATIVE_ASSERTION, PRIVATE_ZK}
)

PROVENANCE_MODELS = {
    DIRECT_STATE_OWNED: "STATE_SIGNED_CANONICAL_SNAPSHOT_V1",
    AUTHORITATIVE_ASSERTION: "QUALIFIED_SOURCE_SIGNED_ASSERTION_V1",
    PRIVATE_ZK: "SOURCE_BOUND_PRIVATE_PROOF_V1",
}

PROOF_SOUNDNESS_ID = "BL-PROOF-SOUNDNESS"
PROOF_THROUGHPUT_ID = "BL-PROOF-THROUGHPUT"
COMMON_QUALIFICATION_IDS = (
    "BL-CLEARANCE-STATE-OWNER",
    "BL-FORMAL-KERNEL",
    "BL-CUSTODY-OPERATIONS",
    "BL-INDEPENDENT-AUDIT",
)

_HEX_512 = re.compile(r"[0-9a-f]{128}\Z", re.ASCII)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
_WINDOWS_REPARSE_POINT = 0x400


class QualificationGateV3Error(ValueError):
    """A malformed or incoherent v3 candidate packet."""


def _invalid() -> None:
    raise QualificationGateV3Error("qualification_gate_v3_invalid")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    _invalid()


def _decode_json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_DOCUMENT_BYTES:
        _invalid()
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        QualificationGateV3Error,
        RecursionError,
    ):
        _invalid()
    if type(value) is not dict:
        _invalid()
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str]) -> None:
    if type(value) is not dict or set(value) != expected:
        _invalid()


def _token(value: Any) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _invalid()
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or _HEX_512.fullmatch(value) is None:
        _invalid()
    return value


def _timestamp(value: Any) -> datetime:
    if type(value) is not str or _UTC_SECOND.fullmatch(value) is None:
        _invalid()
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        _invalid()
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _invalid()
    return parsed


def _string_list(value: Any) -> tuple[str, ...]:
    if type(value) is not list or not value:
        _invalid()
    items = tuple(_token(item) for item in value)
    if items != tuple(sorted(set(items))):
        _invalid()
    return items


def _object(value: Any, expected: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict:
        _invalid()
    _exact_keys(value, expected)
    return value


def _parse_scope(value: Any) -> dict[str, Any]:
    scope = _object(
        value,
        frozenset(
            {
                "jurisdiction_id",
                "program_id",
                "period_id",
                "effective_from",
                "effective_until",
                "issuer_ids",
                "source_ids",
                "receiver_ids",
            }
        ),
    )
    for field in ("jurisdiction_id", "program_id", "period_id"):
        _token(scope[field])
    start = _timestamp(scope["effective_from"])
    end = _timestamp(scope["effective_until"])
    if start >= end:
        _invalid()
    for field in ("issuer_ids", "source_ids", "receiver_ids"):
        _string_list(scope[field])
    return dict(scope)


def _parse_release_binding(value: Any) -> dict[str, Any]:
    binding = _object(
        value,
        frozenset(
            {
                "release_id",
                "release_sha3_512",
                "schema_id",
                "schema_sha3_512",
                "control_set_id",
                "control_set_sha3_512",
            }
        ),
    )
    for field in ("release_id", "schema_id", "control_set_id"):
        _token(binding[field])
    for field in (
        "release_sha3_512",
        "schema_sha3_512",
        "control_set_sha3_512",
    ):
        _digest(binding[field])
    return dict(binding)


def _parse_expected_artifacts(mode: str, value: Any) -> dict[str, Any]:
    expected_by_mode = {
        DIRECT_STATE_OWNED: frozenset(
            {
                "state_owner_id",
                "state_instance_id",
                "attestation_key_id",
                "snapshot_schema_id",
                "snapshot_schema_sha3_512",
                "source_manifest_schema_id",
                "source_manifest_schema_sha3_512",
            }
        ),
        AUTHORITATIVE_ASSERTION: frozenset(
            {
                "assertion_profile_id",
                "signature_profile_id",
                "signing_key_id",
                "source_verifier_sha3_512",
            }
        ),
        PRIVATE_ZK: frozenset(
            {
                "proof_suite_artifact_id",
                "proof_suite_artifact_sha3_512",
                "verifier_executable_sha3_512",
                "proof_statement_id",
                "source_binding_profile_id",
                "proof_request_id",
            }
        ),
    }
    artifacts = _object(value, expected_by_mode[mode])
    for field, item in artifacts.items():
        if field.endswith("_sha3_512"):
            _digest(item)
        else:
            _token(item)
    return dict(artifacts)


_THROUGHPUT_KEYS = frozenset(
    {
        "decision",
        "basis",
        "decision_id",
        "state_approver_id",
        "engineering_approver_id",
        "valid_from",
        "valid_until",
        "state_attestation_sha3_512",
        "engineering_attestation_sha3_512",
    }
)


def _parse_throughput_decision(
    mode: str, value: Any, scope: Mapping[str, Any]
) -> dict[str, Any]:
    decision = _object(value, _THROUGHPUT_KEYS)
    allowed = {"REQUIRED", "NOT_APPLICABLE", "DECISION_REQUIRED"}
    if type(decision["decision"]) is not str or decision["decision"] not in allowed:
        _invalid()

    nullable_fields = (
        "decision_id",
        "state_approver_id",
        "engineering_approver_id",
        "valid_from",
        "valid_until",
        "state_attestation_sha3_512",
        "engineering_attestation_sha3_512",
    )
    if mode == PRIVATE_ZK:
        if decision["decision"] != "REQUIRED":
            _invalid()
        if decision["basis"] != "PRIVATE_ZK_COMPLETE_PATH":
            _invalid()
        if any(decision[field] is not None for field in nullable_fields):
            _invalid()
        return dict(decision)

    if decision["basis"] != "STATE_AND_ENGINEERING_APPROVAL_REQUIRED":
        _invalid()
    if decision["decision"] == "DECISION_REQUIRED":
        if any(decision[field] is not None for field in nullable_fields):
            _invalid()
        return dict(decision)

    for field in (
        "decision_id",
        "state_approver_id",
        "engineering_approver_id",
    ):
        _token(decision[field])
    valid_from = _timestamp(decision["valid_from"])
    valid_until = _timestamp(decision["valid_until"])
    state_start = _timestamp(scope["effective_from"])
    state_end = _timestamp(scope["effective_until"])
    if (
        valid_from >= valid_until
        or valid_until <= state_start
        or valid_from >= state_end
    ):
        _invalid()
    _digest(decision["state_attestation_sha3_512"])
    _digest(decision["engineering_attestation_sha3_512"])
    return dict(decision)


_APPROVAL_KEYS = frozenset(
    {
        "authority_id",
        "approver_id",
        "approver_role",
        "key_id",
        "attestation_model",
        "signature_algorithm",
        "approved_at",
        "valid_from",
        "valid_until",
        "scope",
        "profile_binding",
        "signature_artifact_sha3_512",
    }
)


def _profile_binding(profile: Mapping[str, Any]) -> dict[str, Any]:
    release = profile["release_binding"]
    return {
        "profile_id": profile["profile_id"],
        "candidate_capability": profile["candidate_capability"],
        "candidate_mode": profile["candidate_mode"],
        "release_id": release["release_id"],
        "release_sha3_512": release["release_sha3_512"],
        "schema_id": release["schema_id"],
        "schema_sha3_512": release["schema_sha3_512"],
        "control_set_id": release["control_set_id"],
        "control_set_sha3_512": release["control_set_sha3_512"],
        "expected_artifacts": profile["expected_artifacts"],
        "provenance_model": profile["provenance_model"],
        "proof_throughput_applicability": profile[
            "proof_throughput_applicability"
        ],
    }


def _parse_approval_claim(
    value: Any, profile: Mapping[str, Any], scope: Mapping[str, Any]
) -> dict[str, Any]:
    approval = _object(value, _APPROVAL_KEYS)
    for field in (
        "authority_id",
        "approver_id",
        "approver_role",
        "key_id",
        "attestation_model",
        "signature_algorithm",
    ):
        _token(approval[field])
    approved_at = _timestamp(approval["approved_at"])
    valid_from = _timestamp(approval["valid_from"])
    valid_until = _timestamp(approval["valid_until"])
    if (
        valid_from >= valid_until
        or valid_until <= _timestamp(scope["effective_from"])
        or valid_from >= _timestamp(scope["effective_until"])
        or approved_at >= valid_until
    ):
        _invalid()
    if _parse_scope(approval["scope"]) != dict(scope):
        _invalid()
    binding = _object(
        approval["profile_binding"],
        frozenset(
            {
                "profile_id",
                "candidate_capability",
                "candidate_mode",
                "release_id",
                "release_sha3_512",
                "schema_id",
                "schema_sha3_512",
                "control_set_id",
                "control_set_sha3_512",
                "expected_artifacts",
                "provenance_model",
                "proof_throughput_applicability",
            }
        ),
    )
    for field in (
        "profile_id",
        "candidate_capability",
        "candidate_mode",
        "release_id",
        "schema_id",
        "control_set_id",
        "provenance_model",
    ):
        _token(binding[field])
    for field in (
        "release_sha3_512",
        "schema_sha3_512",
        "control_set_sha3_512",
    ):
        _digest(binding[field])
    if dict(binding) != _profile_binding(profile):
        _invalid()
    _digest(approval["signature_artifact_sha3_512"])
    return dict(approval)


def parse_profile(raw: bytes) -> dict[str, Any]:
    """Parse one synthetic, unselected v3 candidate profile."""

    profile = _decode_json(raw)
    _exact_keys(
        profile,
        frozenset(
            {
                "schema_version",
                "synthetic_only",
                "selection_state",
                "profile_id",
                "candidate_capability",
                "candidate_mode",
                "scope",
                "release_binding",
                "expected_artifacts",
                "provenance_model",
                "approval_claim",
                "proof_throughput_applicability",
            }
        ),
    )
    if profile["schema_version"] != PROFILE_SCHEMA:
        _invalid()
    if profile["synthetic_only"] is not True:
        _invalid()
    if profile["selection_state"] != "UNSELECTED":
        _invalid()
    _token(profile["profile_id"])
    _token(profile["candidate_capability"])
    mode = profile["candidate_mode"]
    if type(mode) is not str or mode not in EVIDENCE_MODES:
        _invalid()
    scope = _parse_scope(profile["scope"])
    binding = _parse_release_binding(profile["release_binding"])
    artifacts = _parse_expected_artifacts(mode, profile["expected_artifacts"])
    if profile["provenance_model"] != PROVENANCE_MODELS[mode]:
        _invalid()
    decision = _parse_throughput_decision(
        mode, profile["proof_throughput_applicability"], scope
    )
    normalized = dict(profile)
    normalized["scope"] = scope
    normalized["release_binding"] = binding
    normalized["expected_artifacts"] = artifacts
    normalized["proof_throughput_applicability"] = decision
    _parse_approval_claim(profile["approval_claim"], normalized, scope)
    return normalized


def _parse_mode_evidence(mode: str, value: Any) -> dict[str, Any]:
    fields_by_mode = {
        DIRECT_STATE_OWNED: frozenset(
            {
                "state_owner_id",
                "state_instance_id",
                "snapshot_schema_id",
                "snapshot_schema_sha3_512",
                "snapshot_artifact_sha3_512",
                "source_manifest_schema_id",
                "source_manifest_schema_sha3_512",
                "source_manifest_sha3_512",
                "attestation_model",
                "attestation_key_id",
                "attestation_artifact_sha3_512",
            }
        ),
        AUTHORITATIVE_ASSERTION: frozenset(
            {
                "assertion_profile_id",
                "signature_profile_id",
                "source_verifier_sha3_512",
                "assertion_artifact_sha3_512",
                "signed_payload_sha3_512",
                "signature_artifact_sha3_512",
                "signing_key_id",
                "attestation_model",
                "assertion_valid_from",
                "assertion_valid_until",
            }
        ),
        PRIVATE_ZK: frozenset(
            {
                "proof_suite_artifact_id",
                "proof_suite_artifact_sha3_512",
                "verifier_executable_sha3_512",
                "proof_statement_id",
                "source_binding_profile_id",
                "source_binding_sha3_512",
                "source_commitment_sha3_512",
                "proof_artifact_sha3_512",
                "proof_request_id",
                "proof_nonce_sha3_512",
                "proof_use_state",
            }
        ),
    }
    evidence = _object(value, fields_by_mode[mode])
    for field, item in evidence.items():
        if field.endswith("_sha3_512"):
            _digest(item)
        elif field in {"assertion_valid_from", "assertion_valid_until"}:
            _timestamp(item)
        elif field == "proof_use_state":
            _parse_proof_use_state(item)
        else:
            _token(item)
    if mode == PRIVATE_ZK:
        _digest(evidence["proof_nonce_sha3_512"])
    return dict(evidence)


def _parse_proof_use_state(value: Any) -> dict[str, Any]:
    state = _object(
        value,
        frozenset(
            {
                "ledger_epoch",
                "state_receipt_sha3_512",
                "used_proof_artifact_sha3_512s",
                "used_proof_request_ids",
            }
        ),
    )
    epoch = state["ledger_epoch"]
    if type(epoch) is not int or epoch <= 0:
        _invalid()
    _digest(state["state_receipt_sha3_512"])
    used = state["used_proof_artifact_sha3_512s"]
    if type(used) is not list:
        _invalid()
    used_hashes = tuple(_digest(item) for item in used)
    if used_hashes != tuple(sorted(set(used_hashes))):
        _invalid()
    used_requests = state["used_proof_request_ids"]
    if type(used_requests) is not list:
        _invalid()
    used_request_ids = tuple(_token(item) for item in used_requests)
    if used_request_ids != tuple(sorted(set(used_request_ids))):
        _invalid()
    return dict(state)


def parse_evidence(raw: bytes) -> dict[str, Any]:
    """Parse one synthetic mode-specific v3 evidence packet."""

    evidence = _decode_json(raw)
    _exact_keys(
        evidence,
        frozenset(
            {
                "schema_version",
                "synthetic_only",
                "profile_id",
                "candidate_mode",
                "scope",
                "release_binding",
                "issuer_ids",
                "source_ids",
                "receiver_ids",
                "evidence_issued_at",
                "evidence_valid_from",
                "evidence_valid_until",
                "provenance_model",
                "mode_evidence",
            }
        ),
    )
    if evidence["schema_version"] != EVIDENCE_SCHEMA:
        _invalid()
    if evidence["synthetic_only"] is not True:
        _invalid()
    _token(evidence["profile_id"])
    mode = evidence["candidate_mode"]
    if type(mode) is not str or mode not in EVIDENCE_MODES:
        _invalid()
    scope = _parse_scope(evidence["scope"])
    binding = _parse_release_binding(evidence["release_binding"])
    for field in ("issuer_ids", "source_ids", "receiver_ids"):
        _string_list(evidence[field])
    _timestamp(evidence["evidence_issued_at"])
    _timestamp(evidence["evidence_valid_from"])
    _timestamp(evidence["evidence_valid_until"])
    if evidence["provenance_model"] != PROVENANCE_MODELS[mode]:
        _invalid()
    mode_evidence = _parse_mode_evidence(mode, evidence["mode_evidence"])
    normalized = dict(evidence)
    normalized["scope"] = scope
    normalized["release_binding"] = binding
    normalized["mode_evidence"] = mode_evidence
    return normalized


def _now_value(now: datetime | str | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    if isinstance(now, str):
        return _timestamp(now)
    if not isinstance(now, datetime) or now.tzinfo is None:
        _invalid()
    normalized = now.astimezone(timezone.utc)
    if normalized.microsecond:
        _invalid()
    return normalized


def _contains(start: Any, end: Any, point: datetime) -> bool:
    return _timestamp(start) <= point < _timestamp(end)


def _validate_cross_bindings(
    profile: Mapping[str, Any],
    evidence: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    mode = profile["candidate_mode"]
    scope = profile["scope"]
    if evidence["profile_id"] != profile["profile_id"]:
        _invalid()
    if evidence["candidate_mode"] != mode:
        _invalid()
    if evidence["scope"] != scope:
        _invalid()
    if evidence["release_binding"] != profile["release_binding"]:
        _invalid()
    for field in ("issuer_ids", "source_ids", "receiver_ids"):
        if tuple(evidence[field]) != tuple(scope[field]):
            _invalid()
    if evidence["provenance_model"] != profile["provenance_model"]:
        _invalid()

    scope_start = _timestamp(scope["effective_from"])
    scope_end = _timestamp(scope["effective_until"])
    if not scope_start <= now < scope_end:
        _invalid()

    approval = profile["approval_claim"]
    if not _contains(approval["valid_from"], approval["valid_until"], now):
        _invalid()
    if _timestamp(approval["approved_at"]) > now:
        _invalid()
    throughput_decision = profile["proof_throughput_applicability"]
    if mode != PRIVATE_ZK and throughput_decision["decision"] in {
        "REQUIRED",
        "NOT_APPLICABLE",
    }:
        if not _contains(
            throughput_decision["valid_from"],
            throughput_decision["valid_until"],
            now,
        ):
            _invalid()

    issued_at = _timestamp(evidence["evidence_issued_at"])
    valid_from = _timestamp(evidence["evidence_valid_from"])
    valid_until = _timestamp(evidence["evidence_valid_until"])
    if (
        valid_from >= valid_until
        or valid_from < scope_start
        or valid_until > scope_end
        or not valid_from <= issued_at < valid_until
        or not valid_from <= now < valid_until
        or issued_at > now
    ):
        _invalid()

    expected = profile["expected_artifacts"]
    actual = evidence["mode_evidence"]
    if mode == DIRECT_STATE_OWNED:
        for field in expected:
            if actual[field] != expected[field]:
                _invalid()
        if expected["state_owner_id"] not in scope["issuer_ids"]:
            _invalid()
        if actual["attestation_model"] != profile["provenance_model"]:
            _invalid()
    elif mode == AUTHORITATIVE_ASSERTION:
        for field in expected:
            if actual[field] != expected[field]:
                _invalid()
        assertion_start = _timestamp(actual["assertion_valid_from"])
        assertion_end = _timestamp(actual["assertion_valid_until"])
        if (
            assertion_start >= assertion_end
            or assertion_start < valid_from
            or assertion_end > valid_until
            or not assertion_start <= now < assertion_end
        ):
            _invalid()
        if actual["attestation_model"] != profile["provenance_model"]:
            _invalid()
    else:
        for field in expected:
            if actual[field] != expected[field]:
                _invalid()
        if actual["source_binding_profile_id"] != expected["source_binding_profile_id"]:
            _invalid()
        used_hashes = actual["proof_use_state"]["used_proof_artifact_sha3_512s"]
        if actual["proof_artifact_sha3_512"] in used_hashes:
            _invalid()
        if actual["proof_request_id"] != expected["proof_request_id"]:
            _invalid()
        used_requests = actual["proof_use_state"]["used_proof_request_ids"]
        if actual["proof_request_id"] in used_requests:
            _invalid()

    return {
        "scope_interval_active": True,
        "evidence_interval_active": True,
        "artifact_bindings_match": True,
        "proof_reuse_absent_in_supplied_record": mode != PRIVATE_ZK
        or (
            actual["proof_artifact_sha3_512"]
            not in actual["proof_use_state"]["used_proof_artifact_sha3_512s"]
            and actual["proof_request_id"]
            not in actual["proof_use_state"]["used_proof_request_ids"]
        ),
    }


def _bind_blocker_source(blockers_raw: bytes) -> dict[str, Any]:
    """Bind supplied blocker bytes to the verified tracked checkout copy."""

    if (
        type(blockers_raw) is not bytes
        or not blockers_raw
        or len(blockers_raw) > MAX_DOCUMENT_BYTES
    ):
        _invalid()
    expected_entries = tuple(
        item
        for item in ops_authority.EXPECTED_OPS_FILES
        if item[0] == "launch_blockers.json"
    )
    if len(expected_entries) != 1:
        _invalid()
    source_name, expected_size, expected_digest = expected_entries[0]
    try:
        authority_status = ops_authority.verify_ops_authority()
        canonical_raw = _read_input(
            str(ops_authority.CANONICAL_OPS_ROOT / source_name)
        )
    except Exception:
        _invalid()
    source_digest = sha3_512(canonical_raw).hexdigest()
    if (
        authority_status != ops_authority.OPS_AUTHORITY_STATUS
        or len(canonical_raw) != expected_size
        or source_digest != expected_digest
        or blockers_raw != canonical_raw
    ):
        _invalid()
    return {
        "binding_scope": "TRACKED_CHECKOUT_COPY_ONLY",
        "source": "ops/launch_blockers.json",
        "authority_status": authority_status,
        "source_sha3_512": source_digest,
        "supplied_sha3_512": sha3_512(blockers_raw).hexdigest(),
        "supplied_matches_source": True,
    }


def evaluate(
    blockers_raw: bytes,
    profile_raw: bytes,
    evidence_raw: bytes,
    *,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Inspect a synthetic packet without granting qualification or authority."""

    blocker_source_binding = _bind_blocker_source(blockers_raw)
    blockers = v2_gate.parse_blockers(blockers_raw)
    profile = parse_profile(profile_raw)
    evidence = parse_evidence(evidence_raw)
    point = _now_value(now)
    checks = _validate_cross_bindings(profile, evidence, point)

    blocker_by_id = {item["id"]: item for item in blockers}
    mode = profile["candidate_mode"]
    if mode == PRIVATE_ZK:
        applicable_ids = (
            PROOF_SOUNDNESS_ID,
            PROOF_THROUGHPUT_ID,
            *COMMON_QUALIFICATION_IDS,
        )
        soundness_applicability = "REQUIRED"
        throughput_applicability = "REQUIRED"
        throughput_decision_status = "REQUIRED_BY_PRIVATE_ZK_MODE"
        v3_review_open = (
            "STATE_PROFILE_SELECTION_VERIFICATION",
            "STATE_APPROVAL_CRYPTOGRAPHIC_VERIFICATION",
            "V3_MIGRATION_AND_INTEGRATION_REVIEW",
        )
    else:
        decision = profile["proof_throughput_applicability"]["decision"]
        applicable_ids = (
            PROOF_THROUGHPUT_ID,
            *COMMON_QUALIFICATION_IDS,
        )
        soundness_applicability = "NOT_APPLICABLE_TO_CANDIDATE_MODE"
        throughput_applicability = decision
        throughput_decision_status = (
            "DECISION_REQUIRED"
            if decision == "DECISION_REQUIRED"
            else "DECISION_ASSERTED_BUT_UNVERIFIED"
        )
        v3_review_open = (
            "STATE_PROFILE_SELECTION_VERIFICATION",
            "STATE_APPROVAL_CRYPTOGRAPHIC_VERIFICATION",
            "PROOF_THROUGHPUT_APPLICABILITY_AUTHORIZATION",
            "V3_MIGRATION_AND_INTEGRATION_REVIEW",
        )

    applicable_open = [
        identifier
        for identifier in applicable_ids
        if blocker_by_id[identifier]["status"] == "open"
    ]
    v2_open_qualification = [
        item["id"]
        for item in blockers[:6]
        if item["status"] == "open"
    ]
    v2_open_activation = [
        item["id"]
        for item in blockers
        if item["gate"] == "activation" and item["status"] == "open"
    ]

    return {
        "schema_version": RESULT_SCHEMA,
        "qualification_state": "NOT_QUALIFIED",
        "activation_state": "INACTIVE",
        "selection_state": "UNSELECTED",
        "candidate_mode": mode,
        "synthetic_only": True,
        "nonoperative": True,
        "v2_gate_status": "UNCHANGED_OPERATIVE_NO_SUBSTITUTION",
        "mode_evidence_validation": "STRUCTURE_AND_BINDING_ONLY",
        "profile_approval_validation": "UNVERIFIED_OFFLINE",
        "throughput_applicability_validation": throughput_decision_status,
        "proofSoundnessApplicability": soundness_applicability,
        "proofThroughputApplicability": throughput_applicability,
        "applicable_open_qualification_blockers": applicable_open,
        "v2_open_qualification_blockers": v2_open_qualification,
        "v2_open_activation_blockers": v2_open_activation,
        "blocker_source_binding": blocker_source_binding,
        "v3_review_open": list(v3_review_open),
        "profile_id": profile["profile_id"],
        "proofSuiteId": None,
        "production_usable": False,
        "activation": False,
        "checks": checks,
    }


def _read_input(path_text: str) -> bytes:
    try:
        path = Path(path_text)
        if not path.is_absolute():
            _invalid()
        metadata = path.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or attributes & _WINDOWS_REPARSE_POINT
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_DOCUMENT_BYTES
        ):
            _invalid()
        with path.open("rb") as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    except (OSError, QualificationGateV3Error):
        _invalid()
    if not raw or len(raw) > MAX_DOCUMENT_BYTES:
        _invalid()
    return raw


def main(argv: tuple[str, ...] | list[str] | None = None) -> int:
    """Run explicit read-only inspection; there is no qualify/activate command."""

    args = tuple(sys.argv[1:] if argv is None else argv)
    if (
        len(args) != 7
        or args[0] != "inspect"
        or args[1] != "--blockers"
        or args[3] != "--profile"
        or args[5] != "--evidence"
    ):
        print("qualification_gate_v3=invalid", file=sys.stderr)
        return 2
    try:
        result = evaluate(
            _read_input(args[2]),
            _read_input(args[4]),
            _read_input(args[6]),
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        print("qualification_gate_v3=invalid", file=sys.stderr)
        return 2


__all__ = (
    "AUTHORITATIVE_ASSERTION",
    "DIRECT_STATE_OWNED",
    "EVIDENCE_SCHEMA",
    "MAX_DOCUMENT_BYTES",
    "PRIVATE_ZK",
    "PROFILE_SCHEMA",
    "QualificationGateV3Error",
    "evaluate",
    "main",
    "parse_evidence",
    "parse_profile",
)


if __name__ == "__main__":
    raise SystemExit(main())
