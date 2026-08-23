"""Independent verification for the durable controlled-shadow runtime.

This module is intentionally producer-independent.  It composes only the
already independent source-adapter, governance-observation, and
privacy/support-observation verifiers, then reconstructs the runtime's own
canonical state chain, leases, receipts, exports, and local discrepancies.
The runtime remains a synthetic, read-only observation boundary; this module
never grants authorization or calls a downstream store.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping

from app.mirror import external_governance_approval_independent as governance_independent
from app.mirror import external_privacy_support_approval_independent as privacy_independent
from app.mirror import external_source_adapter_independent as source_independent


SCHEMA = "mirror-controlled-shadow-runtime-v1"
RECEIPT_SCHEMA = "mirror-controlled-shadow-receipt-v1"
SCHEMA_VERSION = 1
EXPORT_SCHEMA = "mirror-controlled-shadow-runtime-export-v1"
EXPORT_VERSION = 1
AUTH_INPUT_SCHEMA = "mirror-controlled-shadow-authorization-input-v1"
EVALUATOR_INPUT_SCHEMA = "mirror-controlled-shadow-evaluator-input-v1"
TRANSITION_PAYLOAD_SCHEMA = "mirror-controlled-shadow-transition-v1"
REQUEST_SCHEMA = "mirror-controlled-shadow-request-v1"

STATE_OPEN = "OPEN"
STATE_RUNNING = "RUNNING"
STATE_PAUSED = "PAUSED"
STATE_COMPLETED = "COMPLETED"
STATE_ABORTED = "ABORTED"
STATES = (STATE_OPEN, STATE_RUNNING, STATE_PAUSED, STATE_COMPLETED, STATE_ABORTED)
TERMINAL_STATES = (STATE_COMPLETED, STATE_ABORTED)
MODE_SYNTHETIC = "SYNTHETIC_REHEARSAL"
MODE_EXTERNAL = "EXTERNAL_CONTROLLED_SHADOW"
MODES = (MODE_SYNTHETIC, MODE_EXTERNAL)
SLOT_DUE = "DUE"
SLOT_LEASED = "LEASED"
SLOT_COMPLETED = "COMPLETED"
SLOT_FAILED = "FAILED"
SLOT_STATES = (SLOT_DUE, SLOT_LEASED, SLOT_COMPLETED, SLOT_FAILED)
OBSERVATION_RESULTS = ("PARITY", "DISCREPANCY", "INDETERMINATE")
PAUSE_REASONS = (
    "AUTHORITY_EXPIRED",
    "EVALUATOR_EXHAUSTED",
    "EVALUATOR_FAILURE",
    "FRESHNESS_FAILURE",
    "MANUAL_PAUSE",
)
ABORT_REASONS = ("INTEGRITY_FAILURE", "MANUAL_ABORT", "AUTHORITY_WITHDRAWN")
FAILURE_CODES = (
    "EVALUATOR_EXCEPTION",
    "EVALUATOR_INVALID",
    "EVALUATOR_TIMEOUT",
    "EVALUATOR_OVERSIZE",
    "AUTHORITY_EXPIRED",
)
FIXED_FLAGS = {
    "zero_phi": True,
    "state_owned": True,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "proofSuiteId": None,
}
SUPPORT_SAFE_FLAGS = {
    "zero_phi": True,
    "state_owned": True,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "proofSuiteId": None,
}
MAX_PROFILE_BYTES = 16_384
MAX_BUNDLE_BYTES = 524_288
MAX_AUTH_BYTES = 16_384
MAX_EVALUATOR_BYTES = 16_384
MAX_EXPORT_BYTES = 1_048_576
MAX_SESSIONS = 16
MAX_OBSERVATIONS = 32
MAX_TRANSITIONS = 256
MAX_OPERATIONS = 256
MAX_FAILURES = 64
MAX_SUPPORT_CODES = 32
BUSY_TIMEOUT_MS = 250
MAX_DEPTH = 16
MAX_NODES = 8_192
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

TABLE_COLUMNS = {
    "runtime_meta": ("key", "value"),
    "runtime_sessions": (
        "session_id", "profile_digest", "manifest_digest", "manifest_material", "authorization_id",
        "authorization_material", "mode", "state", "created_at", "updated_at",
        "session_head_root", "last_sequence", "flags_raw",
    ),
    "runtime_operations": (
        "operation_id", "session_id", "action", "request_raw", "request_hash",
        "transition_sequence", "transition_id", "receipt_raw", "receipt_hash",
        "before_global_root", "after_global_root",
    ),
    "runtime_transitions": (
        "sequence", "session_id", "action", "operation_id", "transition_id",
        "payload_raw", "before_session_root", "after_session_root",
        "before_global_root", "after_global_root",
    ),
    "runtime_slots": (
        "session_id", "slot_number", "attempt", "state", "input_digest",
        "worker_digest", "lease_token_digest", "lease_expires_at", "due_at",
        "result_raw", "result_digest", "observed_at", "completed_at",
        "last_failure_code",
    ),
    "runtime_discrepancies": (
        "session_id", "slot_number", "result_digest", "aggregate_raw", "code",
    ),
}
TABLES = tuple(TABLE_COLUMNS)
META_KEYS = (
    "schema", "schema_version", "profile_digest", "profile_json", "chain_id",
    "global_sequence", "global_head_root", "flags_json",
)
_BUNDLE_KEYS = {
    "source_policy", "quarantine_raw", "quarantine_head", "governance_policy",
    "governance_raw", "governance_evidence_raw", "privacy_policy", "privacy_raw",
    "privacy_evidence_raw",
}
_AUTH_KEYS = {
    "authorization_id", "evidence_sha3_512", "evidence_byte_length", "profile_digest",
    "manifest_digest", "source_policy_digest", "scope", "mode", "terms_digest",
    "retention_policy_digest", "revocation_head_digest", "authority_identity_digest",
    "valid_from", "valid_until", "observed_at", "verifier_id", "verifier_epoch",
    "external_authority_authenticated", "zero_phi", "state_owned",
}
_EVALUATION_KEYS = {
    "session_id", "profile_digest", "slot_number", "attempt", "input_digest",
    "evaluator_id", "evaluator_epoch", "result", "aggregate", "observed_at",
    "completed_at", "zero_phi", "result_digest",
}
_AGGREGATE_KEYS = {"evaluated", "matched", "differing", "unknown"}


class IndependentControlledShadowError(ValueError):
    """A bounded independent runtime-verification failure."""


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentControlledShadowError("runtime:canonical") from exc
    if len(raw) > MAX_EXPORT_BYTES:
        raise IndependentControlledShadowError("runtime:byte-cap")
    return raw


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(label.encode("ascii"))
    digest.update(b"\0")
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise IndependentControlledShadowError("runtime:raw-type")
    return hashlib.sha3_512(raw).hexdigest()


def _parse(raw: bytes, *, maximum: int = MAX_EXPORT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise IndependentControlledShadowError("runtime:bytes")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise IndependentControlledShadowError("runtime:ascii") from exc

    def reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise IndependentControlledShadowError("runtime:duplicate-key")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=reject, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
    except (ValueError, json.JSONDecodeError) as exc:
        raise IndependentControlledShadowError("runtime:json") from exc
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentControlledShadowError("runtime:noncanonical")
    if not isinstance(value, dict):
        raise IndependentControlledShadowError("runtime:top-level")
    return value


def _walk(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    count = nodes if nodes is not None else [0]
    count[0] += 1
    if count[0] > MAX_NODES or depth > MAX_DEPTH:
        raise IndependentControlledShadowError("runtime:shape-cap")
    if isinstance(value, str) and len(value.encode("ascii", "ignore")) > 4096:
        raise IndependentControlledShadowError("runtime:string-cap")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise IndependentControlledShadowError("runtime:key-type")
            _walk(child, depth=depth + 1, nodes=count)
    elif isinstance(value, list):
        for child in value:
            _walk(child, depth=depth + 1, nodes=count)


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentControlledShadowError(f"runtime:{label}-keys")
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentControlledShadowError(f"runtime:{label}-hex")
    return value


def _text(value: object, label: str, *, token: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(char) > 127 for char in value):
        raise IndependentControlledShadowError(f"runtime:{label}-text")
    if token and SAFE_TOKEN.fullmatch(value) is None:
        raise IndependentControlledShadowError(f"runtime:{label}-token")
    if any(fragment in value.lower() for fragment in ("http://", "https://", "password", "token", "credential", "patient", "member", "provider")):
        raise IndependentControlledShadowError(f"runtime:{label}-forbidden")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = 10**12) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentControlledShadowError(f"runtime:{label}-integer")
    return value


def _bool(value: object, label: str, expected: bool | None = None) -> bool:
    if type(value) is not bool or expected is not None and value is not expected:
        raise IndependentControlledShadowError(f"runtime:{label}-boolean")
    return value


def _profile_material(profile: Mapping[str, object]) -> dict[str, object]:
    value = dict(profile)
    if set(value) != PROFILE_KEYS:
        raise IndependentControlledShadowError("runtime:profile-keys")
    return value


PROFILE_KEYS = {
    "profile_id", "version", "runtime_id_domain", "source_policy_digest",
    "quarantine_policy_digest", "quarantine_artifact_id", "quarantine_head_artifact_id",
    "quarantine_head_root", "governance_policy_digest", "governance_artifact_id",
    "governance_evidence_digest", "governance_decision", "privacy_policy_digest",
    "privacy_artifact_id", "privacy_evidence_digest", "privacy_decision",
    "support_decision", "authorization_verifier_id", "authorization_verifier_epoch",
    "evaluator_id", "evaluator_epoch", "scope", "authorization_effective_start",
    "authorization_effective_end", "cadence_seconds", "freshness_grace_seconds",
    "lease_seconds", "max_observations", "minimum_completed_observations",
    "max_evaluator_input_bytes", "max_evaluator_output_bytes", "busy_timeout_ms",
    "max_attempts", "max_sessions", "max_worker_concurrency", "allowed_pause_reasons",
    "allowed_abort_reasons", "allowed_failure_codes", "zero_phi", "state_owned",
    "production_usable", "activation", "payment_authority", "clearance_authority",
    "settlement_authority", "proofSuiteId",
}


def verify_profile(profile: Mapping[str, object]) -> dict[str, object]:
    value = _profile_material(profile)
    _text(value["profile_id"], "profile-id", token=True)
    _integer(value["version"], "profile-version", minimum=1, maximum=1)
    _text(value["runtime_id_domain"], "runtime-domain", token=True)
    for key in (
        "source_policy_digest", "quarantine_policy_digest", "quarantine_artifact_id",
        "quarantine_head_artifact_id", "quarantine_head_root", "governance_policy_digest",
        "governance_artifact_id", "governance_evidence_digest", "privacy_policy_digest",
        "privacy_artifact_id", "privacy_evidence_digest",
    ):
        _hex(value[key], key)
    if value["governance_decision"] not in ("GRANTED", "DENIED", "WITHDRAWN"):
        raise IndependentControlledShadowError("runtime:governance-decision")
    if value["privacy_decision"] not in ("GRANTED", "DENIED", "WITHDRAWN"):
        raise IndependentControlledShadowError("runtime:privacy-decision")
    if value["support_decision"] not in ("GRANTED", "DENIED", "WITHDRAWN"):
        raise IndependentControlledShadowError("runtime:support-decision")
    _text(value["authorization_verifier_id"], "authorization-verifier", token=True)
    _integer(value["authorization_verifier_epoch"], "authorization-epoch", maximum=1_000_000)
    _text(value["evaluator_id"], "evaluator-id", token=True)
    _integer(value["evaluator_epoch"], "evaluator-epoch", maximum=1_000_000)
    if value["scope"] != "MIRROR_CONTROLLED_SHADOW_READ_ONLY":
        raise IndependentControlledShadowError("runtime:scope")
    for key in (
        "authorization_effective_start", "authorization_effective_end", "cadence_seconds",
        "freshness_grace_seconds", "lease_seconds", "max_observations",
        "minimum_completed_observations", "max_evaluator_input_bytes",
        "max_evaluator_output_bytes", "busy_timeout_ms", "max_attempts", "max_sessions",
        "max_worker_concurrency",
    ):
        _integer(value[key], key, minimum=1)
    if value["authorization_effective_end"] <= value["authorization_effective_start"]:
        raise IndependentControlledShadowError("runtime:authorization-window")
    if value["max_observations"] > MAX_OBSERVATIONS or value["max_sessions"] > MAX_SESSIONS or value["max_worker_concurrency"] > 4:
        raise IndependentControlledShadowError("runtime:profile-cap")
    if value["minimum_completed_observations"] > value["max_observations"]:
        raise IndependentControlledShadowError("runtime:completion-cap")
    if value["max_evaluator_input_bytes"] > MAX_EVALUATOR_BYTES or value["max_evaluator_output_bytes"] > MAX_EVALUATOR_BYTES:
        raise IndependentControlledShadowError("runtime:evaluator-cap")
    if value["busy_timeout_ms"] > 5_000 or value["max_attempts"] > 8:
        raise IndependentControlledShadowError("runtime:busy-or-attempt-cap")
    if tuple(value["allowed_pause_reasons"]) != PAUSE_REASONS:
        raise IndependentControlledShadowError("runtime:pause-registry")
    if tuple(value["allowed_abort_reasons"]) != ABORT_REASONS:
        raise IndependentControlledShadowError("runtime:abort-registry")
    if tuple(value["allowed_failure_codes"]) != FAILURE_CODES:
        raise IndependentControlledShadowError("runtime:failure-registry")
    for key in ("zero_phi", "state_owned"):
        _bool(value[key], key, True)
    for key in ("production_usable", "activation", "payment_authority", "clearance_authority", "settlement_authority"):
        _bool(value[key], key, False)
    if value["proofSuiteId"] is not None:
        raise IndependentControlledShadowError("runtime:proof-suite")
    return value


def profile_digest(profile: Mapping[str, object]) -> str:
    return _digest("runtime-profile", verify_profile(profile))


def _safe_raw(value: object, label: str, maximum: int) -> bytes:
    if type(value) is not bytes or not value or len(value) > maximum:
        raise IndependentControlledShadowError(f"runtime:{label}-bytes")
    return bytes(value)


def _policy_digest(module: Any, policy: Mapping[str, object]) -> str:
    material = module._policy_material(policy)
    return module._digest("policy", material)


def verify_upstream_bundle(bundle: Mapping[str, object], profile: Mapping[str, object]) -> dict[str, object]:
    configured = verify_profile(profile)
    value = _expect_keys(bundle, _BUNDLE_KEYS, "bundle")
    source_policy = value["source_policy"]
    governance_policy = value["governance_policy"]
    privacy_policy = value["privacy_policy"]
    if not isinstance(source_policy, Mapping) or not isinstance(governance_policy, Mapping) or not isinstance(privacy_policy, Mapping):
        raise IndependentControlledShadowError("runtime:bundle-policy-type")
    quarantine_raw = _safe_raw(value["quarantine_raw"], "quarantine", MAX_BUNDLE_BYTES)
    governance_raw = _safe_raw(value["governance_raw"], "governance", MAX_BUNDLE_BYTES)
    governance_evidence_raw = _safe_raw(value["governance_evidence_raw"], "governance-evidence", MAX_AUTH_BYTES)
    privacy_raw = _safe_raw(value["privacy_raw"], "privacy", MAX_BUNDLE_BYTES)
    privacy_evidence_raw = _safe_raw(value["privacy_evidence_raw"], "privacy-evidence", MAX_AUTH_BYTES)
    source_policy_digest = _policy_digest(source_independent, source_policy)
    try:
        source_result = source_independent.verify_artifact(quarantine_raw, policy=source_policy)
    except Exception as exc:
        raise IndependentControlledShadowError("runtime:quarantine-artifact") from exc
    head = value["quarantine_head"]
    head = _expect_keys(head, {"policy_digest", "head_artifact_id", "head_root", "state", "sequence"}, "quarantine-head")
    if head["policy_digest"] != source_policy_digest or head["head_artifact_id"] != source_result["artifact_id"] or head["state"] != "QUARANTINED":
        raise IndependentControlledShadowError("runtime:quarantine-head-binding")
    _hex(head["head_root"], "quarantine-head-root")
    _integer(head["sequence"], "quarantine-head-sequence", minimum=1, maximum=MAX_TRANSITIONS)
    governance_policy_digest = _policy_digest(governance_independent, governance_policy)
    try:
        governance_result = governance_independent.verify_artifact(governance_raw, policy=governance_policy, evidence_raw=governance_evidence_raw)
    except Exception as exc:
        raise IndependentControlledShadowError("runtime:governance-artifact") from exc
    if governance_result["quarantine_artifact_id"] != source_result["artifact_id"] or governance_result["quarantine_head_artifact_id"] != head["head_artifact_id"] or governance_result["quarantine_head_root"] != head["head_root"]:
        raise IndependentControlledShadowError("runtime:governance-quarantine-binding")
    privacy_policy_digest = _policy_digest(privacy_independent, privacy_policy)
    try:
        privacy_result = privacy_independent.verify_artifact(privacy_raw, policy=privacy_policy, evidence_raw=privacy_evidence_raw)
    except Exception as exc:
        raise IndependentControlledShadowError("runtime:privacy-artifact") from exc
    if privacy_result["governance_observation_artifact_id"] != governance_result["artifact_id"]:
        raise IndependentControlledShadowError("runtime:privacy-governance-binding")
    manifest = {
        "source_policy_digest": source_policy_digest,
        "quarantine_policy_digest": source_policy_digest,
        "quarantine_artifact_id": source_result["artifact_id"],
        "quarantine_head_artifact_id": head["head_artifact_id"],
        "quarantine_head_root": head["head_root"],
        "quarantine_head_sequence": head["sequence"],
        "source_capture_id": source_result["capture_id"],
        "governance_policy_digest": governance_policy_digest,
        "governance_artifact_id": governance_result["artifact_id"],
        "governance_evidence_digest": _raw_digest(governance_evidence_raw),
        "governance_decision": governance_result["decision"],
        "privacy_policy_digest": privacy_policy_digest,
        "privacy_artifact_id": privacy_result["artifact_id"],
        "privacy_evidence_digest": _raw_digest(privacy_evidence_raw),
        "privacy_decision": privacy_result["privacy_decision"],
        "support_decision": privacy_result["support_decision"],
    }
    if configured["source_policy_digest"] != manifest["source_policy_digest"] or configured["quarantine_policy_digest"] != manifest["quarantine_policy_digest"] or configured["quarantine_artifact_id"] != manifest["quarantine_artifact_id"] or configured["quarantine_head_artifact_id"] != manifest["quarantine_head_artifact_id"] or configured["quarantine_head_root"] != manifest["quarantine_head_root"]:
        raise IndependentControlledShadowError("runtime:profile-quarantine-binding")
    for key in ("governance_policy_digest", "governance_artifact_id", "governance_evidence_digest", "privacy_policy_digest", "privacy_artifact_id", "privacy_evidence_digest"):
        if configured[key] != manifest[key]:
            raise IndependentControlledShadowError(f"runtime:profile-{key}")
    for key in ("governance_decision", "privacy_decision", "support_decision"):
        if configured[key] != manifest[key]:
            raise IndependentControlledShadowError(f"runtime:profile-{key}")
    manifest_digest = _digest("upstream-manifest", manifest)
    return {
        "manifest": manifest,
        "manifest_digest": manifest_digest,
        "source_result": source_result,
        "governance_result": governance_result,
        "privacy_result": privacy_result,
    }


def authorization_input(profile: Mapping[str, object], manifest: Mapping[str, object]) -> bytes:
    configured = verify_profile(profile)
    if set(manifest) != {
        "source_policy_digest", "quarantine_policy_digest", "quarantine_artifact_id", "quarantine_head_artifact_id", "quarantine_head_root", "quarantine_head_sequence", "source_capture_id", "governance_policy_digest", "governance_artifact_id", "governance_evidence_digest", "governance_decision", "privacy_policy_digest", "privacy_artifact_id", "privacy_evidence_digest", "privacy_decision", "support_decision",
    }:
        raise IndependentControlledShadowError("runtime:manifest-keys")
    return _canonical({"schema": AUTH_INPUT_SCHEMA, "profile": configured, "manifest": dict(manifest)})


def verify_authorization_result(
    result: Mapping[str, object],
    *,
    profile: Mapping[str, object],
    manifest: Mapping[str, object],
    verifier_id: str,
    verifier_epoch: int,
    verifier_mode: str,
    fixture_only: bool,
) -> dict[str, object]:
    configured = verify_profile(profile)
    value = _expect_keys(result, _AUTH_KEYS, "authorization")
    input_raw = authorization_input(configured, manifest)
    _hex(value["authorization_id"], "authorization-id")
    _hex(value["evidence_sha3_512"], "authorization-evidence")
    _integer(value["evidence_byte_length"], "authorization-evidence-length", minimum=1, maximum=MAX_AUTH_BYTES)
    if value["evidence_sha3_512"] != _raw_digest(input_raw) or value["evidence_byte_length"] != len(input_raw):
        raise IndependentControlledShadowError("runtime:authorization-evidence-binding")
    expected_profile_digest = profile_digest(configured)
    manifest_digest = _digest("upstream-manifest", dict(manifest))
    if value["profile_digest"] != expected_profile_digest or value["manifest_digest"] != manifest_digest or value["source_policy_digest"] != manifest["source_policy_digest"]:
        raise IndependentControlledShadowError("runtime:authorization-upstream-binding")
    if value["scope"] != configured["scope"] or value["mode"] != verifier_mode or value["mode"] not in MODES:
        raise IndependentControlledShadowError("runtime:authorization-mode")
    if verifier_mode == MODE_SYNTHETIC and not fixture_only:
        raise IndependentControlledShadowError("runtime:synthetic-verifier-required")
    if verifier_mode == MODE_EXTERNAL and fixture_only:
        raise IndependentControlledShadowError("runtime:external-verifier-fixture")
    if value["verifier_id"] != verifier_id or value["verifier_id"] != configured["authorization_verifier_id"] or value["verifier_epoch"] != verifier_epoch or value["verifier_epoch"] != configured["authorization_verifier_epoch"]:
        raise IndependentControlledShadowError("runtime:authorization-verifier")
    for key, configured_key in (("terms_digest", "governance_evidence_digest"), ("retention_policy_digest", "privacy_evidence_digest"), ("revocation_head_digest", "quarantine_head_root"), ("authority_identity_digest", "governance_artifact_id")):
        _hex(value[key], f"authorization-{key}")
        if value[key] != configured[configured_key]:
            raise IndependentControlledShadowError(f"runtime:authorization-{key}")
    for key in ("valid_from", "valid_until", "observed_at"):
        _integer(value[key], f"authorization-{key}", minimum=1)
    if not (configured["authorization_effective_start"] <= value["valid_from"] <= value["observed_at"] <= value["valid_until"] <= configured["authorization_effective_end"]):
        raise IndependentControlledShadowError("runtime:authorization-chronology")
    _bool(value["external_authority_authenticated"], "authorization-authenticated", verifier_mode == MODE_EXTERNAL)
    _bool(value["zero_phi"], "authorization-zero-phi", True)
    _bool(value["state_owned"], "authorization-state-owned", True)
    identity_body = {key: item for key, item in value.items() if key != "authorization_id"}
    if value["authorization_id"] != _digest("authorization-id", identity_body):
        raise IndependentControlledShadowError("runtime:authorization-id")
    return dict(value)


def evaluator_input(profile: Mapping[str, object], manifest: Mapping[str, object], session_id: str, slot_number: int, attempt: int, mode: str) -> bytes:
    configured = verify_profile(profile)
    _text(session_id, "session-id", token=True)
    _integer(slot_number, "slot-number", minimum=0, maximum=MAX_OBSERVATIONS - 1)
    _integer(attempt, "attempt", minimum=1, maximum=8)
    if mode not in MODES:
        raise IndependentControlledShadowError("runtime:evaluator-mode")
    raw = _canonical({
        "schema": EVALUATOR_INPUT_SCHEMA,
        "profile_digest": profile_digest(configured),
        "manifest_digest": _digest("upstream-manifest", dict(manifest)),
        "session_id": session_id,
        "slot_number": slot_number,
        "attempt": attempt,
        "mode": mode,
    })
    if len(raw) > configured["max_evaluator_input_bytes"]:
        raise IndependentControlledShadowError("runtime:evaluator-input-cap")
    return raw


def _aggregate(value: object) -> dict[str, int]:
    aggregate = _expect_keys(value, _AGGREGATE_KEYS, "aggregate")
    result: dict[str, int] = {}
    for key in sorted(_AGGREGATE_KEYS):
        result[key] = _integer(aggregate[key], f"aggregate-{key}", maximum=10**6)
    if result["evaluated"] != result["matched"] + result["differing"] + result["unknown"]:
        raise IndependentControlledShadowError("runtime:aggregate-conservation")
    return result


def _evaluation_body(value: Mapping[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if key != "result_digest"}


def verify_evaluation_result(
    result: Mapping[str, object], *, expected: Mapping[str, object], evaluator_id: str, evaluator_epoch: int,
) -> dict[str, object]:
    value = _expect_keys(result, _EVALUATION_KEYS, "evaluation")
    if value["session_id"] != expected["session_id"] or value["profile_digest"] != expected["profile_digest"] or value["slot_number"] != expected["slot_number"] or value["attempt"] != expected["attempt"] or value["input_digest"] != expected["input_digest"]:
        raise IndependentControlledShadowError("runtime:evaluation-binding")
    _text(value["session_id"], "evaluation-session", token=True)
    _hex(value["profile_digest"], "evaluation-profile")
    _integer(value["slot_number"], "evaluation-slot", minimum=0, maximum=MAX_OBSERVATIONS - 1)
    _integer(value["attempt"], "evaluation-attempt", minimum=1, maximum=8)
    _hex(value["input_digest"], "evaluation-input")
    if value["evaluator_id"] != evaluator_id or value["evaluator_epoch"] != evaluator_epoch:
        raise IndependentControlledShadowError("runtime:evaluator-binding")
    _text(value["evaluator_id"], "evaluator-id", token=True)
    _integer(value["evaluator_epoch"], "evaluator-epoch", maximum=1_000_000)
    if value["result"] not in OBSERVATION_RESULTS:
        raise IndependentControlledShadowError("runtime:evaluation-result")
    aggregate = _aggregate(value["aggregate"])
    _integer(value["observed_at"], "evaluation-observed", minimum=1)
    _integer(value["completed_at"], "evaluation-completed", minimum=1)
    if value["completed_at"] < value["observed_at"]:
        raise IndependentControlledShadowError("runtime:evaluation-chronology")
    _bool(value["zero_phi"], "evaluation-zero-phi", True)
    _hex(value["result_digest"], "evaluation-result-digest")
    body = dict(value)
    body["aggregate"] = aggregate
    if value["result_digest"] != _digest("evaluation-result", _evaluation_body(body)):
        raise IndependentControlledShadowError("runtime:evaluation-digest")
    return {**value, "aggregate": aggregate}


def _genesis_root(profile_digest_value: str) -> str:
    return _digest("runtime-genesis", {"schema": SCHEMA, "profile_digest": profile_digest_value})


def _transition_id(sequence: int, session_id: str, action: str, payload: Mapping[str, object], before_session_root: str, before_global_root: str) -> str:
    return _digest("runtime-transition-id", {"sequence": sequence, "session_id": session_id, "action": action, "payload": dict(payload), "before_session_root": before_session_root, "before_global_root": before_global_root})


def _session_after_root(sequence: int, session_id: str, transition_id: str, before_session_root: str) -> str:
    return _digest("runtime-session-root", {"sequence": sequence, "session_id": session_id, "transition_id": transition_id, "before": before_session_root})


def _global_after_root(sequence: int, transition_id: str, before_global_root: str) -> str:
    return _digest("runtime-global-root", {"sequence": sequence, "transition_id": transition_id, "before": before_global_root})


def _parse_blob(raw: object, label: str, maximum: int = MAX_EXPORT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes:
        raise IndependentControlledShadowError(f"runtime:{label}-blob")
    return _parse(raw, maximum=maximum)


def _table_rows(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    for table in TABLES:
        result[table] = [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")]
    return result


def _check_schema(connection: sqlite3.Connection) -> None:
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != set(TABLES):
        raise IndependentControlledShadowError("runtime:database-tables")
    for table, expected in TABLE_COLUMNS.items():
        actual = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))
        if actual != expected:
            raise IndependentControlledShadowError(f"runtime:database-columns:{table}")


def _verify_meta(rows: Mapping[str, list[dict[str, object]]], profile: Mapping[str, object]) -> tuple[dict[str, str], str, str]:
    meta_rows = rows["runtime_meta"]
    if len(meta_rows) != len(META_KEYS) or {row.get("key") for row in meta_rows} != set(META_KEYS):
        raise IndependentControlledShadowError("runtime:meta-shape")
    meta = {str(row["key"]): str(row["value"]) for row in meta_rows}
    configured = verify_profile(profile)
    p_digest = profile_digest(configured)
    if meta["schema"] != SCHEMA or meta["schema_version"] != str(SCHEMA_VERSION) or meta["profile_digest"] != p_digest or meta["profile_json"] != _canonical(configured).decode("ascii"):
        raise IndependentControlledShadowError("runtime:meta-binding")
    if meta["flags_json"] != _canonical(FIXED_FLAGS).decode("ascii"):
        raise IndependentControlledShadowError("runtime:meta-flags")
    if meta["chain_id"] != _digest("runtime-chain", {"profile_digest": p_digest}):
        raise IndependentControlledShadowError("runtime:meta-chain")
    sequence = int(meta["global_sequence"])
    if sequence < 0 or sequence > MAX_TRANSITIONS:
        raise IndependentControlledShadowError("runtime:meta-sequence")
    _hex(meta["global_head_root"], "global-head")
    return meta, p_digest, meta["global_head_root"]


def _verify_rows(rows: Mapping[str, list[dict[str, object]]], *, profile: Mapping[str, object]) -> dict[str, object]:
    if set(rows) != set(TABLES):
        raise IndependentControlledShadowError("runtime:snapshot-tables")
    for table, values in rows.items():
        if len(values) > (MAX_SESSIONS if table == "runtime_sessions" else MAX_OPERATIONS if table == "runtime_operations" else MAX_TRANSITIONS if table == "runtime_transitions" else MAX_FAILURES if table == "runtime_discrepancies" else MAX_OBSERVATIONS * MAX_SESSIONS if table == "runtime_slots" else len(META_KEYS)):
            raise IndependentControlledShadowError(f"runtime:{table}-count")
    meta, p_digest, global_head = _verify_meta(rows, profile)
    sessions: dict[str, dict[str, object]] = {}
    for row in rows["runtime_sessions"]:
        if set(row) != set(TABLE_COLUMNS["runtime_sessions"]):
            raise IndependentControlledShadowError("runtime:session-columns")
        sid = _text(row["session_id"], "session-id", token=True)
        if sid in sessions:
            raise IndependentControlledShadowError("runtime:session-duplicate")
        if row["profile_digest"] != p_digest or row["mode"] not in MODES or row["state"] not in STATES:
            raise IndependentControlledShadowError("runtime:session-binding")
        _hex(row["manifest_digest"], "manifest-digest")
        manifest = _parse_blob(row["manifest_material"], "manifest-material", MAX_AUTH_BYTES)
        if row["manifest_digest"] != _digest("upstream-manifest", manifest):
            raise IndependentControlledShadowError("runtime:session-manifest")
        _hex(row["authorization_id"], "authorization-id")
        authorization = _parse_blob(row["authorization_material"], "authorization-material", MAX_AUTH_BYTES)
        try:
            checked_authorization = verify_authorization_result(
                authorization,
                profile=profile,
                manifest=manifest,
                verifier_id=str(profile["authorization_verifier_id"]),
                verifier_epoch=int(profile["authorization_verifier_epoch"]),
                verifier_mode=str(row["mode"]),
                fixture_only=str(row["mode"]) == MODE_SYNTHETIC,
            )
        except IndependentControlledShadowError:
            raise
        if checked_authorization["authorization_id"] != row["authorization_id"]:
            raise IndependentControlledShadowError("runtime:session-authorization")
        _integer(row["created_at"], "created-at", minimum=1)
        _integer(row["updated_at"], "updated-at", minimum=1)
        _hex(row["session_head_root"], "session-head")
        _integer(row["last_sequence"], "last-sequence", minimum=1, maximum=MAX_TRANSITIONS)
        if row["flags_raw"] != _canonical(FIXED_FLAGS):
            raise IndependentControlledShadowError("runtime:session-flags")
        sessions[sid] = row
    transitions = sorted(rows["runtime_transitions"], key=lambda item: int(item["sequence"]))
    if len(transitions) != int(meta["global_sequence"]):
        raise IndependentControlledShadowError("runtime:transition-count")
    session_state: dict[str, str] = {}
    session_head: dict[str, str] = {}
    operation_ids: set[str] = set()
    transition_ids: set[str] = set()
    slot_state: dict[tuple[str, int], dict[str, object]] = {}
    discrepancies: dict[tuple[str, int], str] = {}
    previous_global = _genesis_root(p_digest)
    for expected_sequence, row in enumerate(transitions, 1):
        if set(row) != set(TABLE_COLUMNS["runtime_transitions"]):
            raise IndependentControlledShadowError("runtime:transition-columns")
        sequence = _integer(row["sequence"], "transition-sequence", minimum=1, maximum=MAX_TRANSITIONS)
        if sequence != expected_sequence:
            raise IndependentControlledShadowError("runtime:transition-order")
        sid = _text(row["session_id"], "transition-session", token=True)
        action = _text(row["action"], "transition-action", token=True)
        operation_id = _text(row["operation_id"], "operation-id", token=True)
        transition_id = _hex(row["transition_id"], "transition-id")
        payload = _parse_blob(row["payload_raw"], "transition-payload", MAX_AUTH_BYTES)
        _hex(row["before_session_root"], "before-session")
        _hex(row["after_session_root"], "after-session")
        _hex(row["before_global_root"], "before-global")
        _hex(row["after_global_root"], "after-global")
        if row["before_global_root"] != previous_global:
            raise IndependentControlledShadowError("runtime:global-chain")
        if operation_id in operation_ids or transition_id in transition_ids:
            raise IndependentControlledShadowError("runtime:transition-duplicate")
        operation_ids.add(operation_id)
        transition_ids.add(transition_id)
        p = _expect_keys(payload, {"schema", "session_id", "action", "state_before", "state_after", "data"}, "transition-payload")
        if p["schema"] != TRANSITION_PAYLOAD_SCHEMA or p["session_id"] != sid or p["action"] != action or not isinstance(p["data"], dict):
            raise IndependentControlledShadowError("runtime:transition-payload-binding")
        before_state = str(p["state_before"])
        after_state = str(p["state_after"])
        current_state = session_state.get(sid)
        expected_before_root = session_head.get(sid, _genesis_root(p_digest))
        if row["before_session_root"] != expected_before_root or before_state != ("ABSENT" if current_state is None else current_state):
            raise IndependentControlledShadowError("runtime:session-chain")
        if action == "OPEN":
            if current_state is not None or after_state != STATE_OPEN:
                raise IndependentControlledShadowError("runtime:open-transition")
            data = _expect_keys(p["data"], {"manifest_digest", "authorization_id", "mode"}, "open-data")
            _hex(data["manifest_digest"], "open-manifest")
            _hex(data["authorization_id"], "open-authorization")
            if data["mode"] not in MODES:
                raise IndependentControlledShadowError("runtime:open-mode")
            if data["manifest_digest"] != sessions[sid]["manifest_digest"] or data["authorization_id"] != sessions[sid]["authorization_id"] or data["mode"] != sessions[sid]["mode"]:
                raise IndependentControlledShadowError("runtime:open-binding")
        elif action == "START":
            if current_state != STATE_OPEN or after_state != STATE_RUNNING or set(p["data"]) != set():
                raise IndependentControlledShadowError("runtime:start-transition")
        elif action == "CLAIM_SLOT":
            if current_state != STATE_RUNNING or after_state != STATE_RUNNING:
                raise IndependentControlledShadowError("runtime:claim-state")
            data = _expect_keys(p["data"], {"slot_number", "attempt", "input_digest", "worker_digest", "lease_token_digest", "lease_expires_at", "expired_slot_number"}, "claim-data")
            slot = _integer(data["slot_number"], "claim-slot", minimum=0, maximum=MAX_OBSERVATIONS - 1)
            attempt = _integer(data["attempt"], "claim-attempt", minimum=1, maximum=8)
            for key in ("input_digest", "worker_digest", "lease_token_digest"):
                _hex(data[key], f"claim-{key}")
            _integer(data["lease_expires_at"], "lease-expiry", minimum=1)
            if data["expired_slot_number"] is not None:
                _integer(data["expired_slot_number"], "expired-slot", minimum=0, maximum=MAX_OBSERVATIONS - 1)
            slot_state[(sid, slot)] = {"state": SLOT_LEASED, "attempt": attempt, **data}
        elif action == "COMPLETE_OBSERVATION":
            if current_state != STATE_RUNNING or after_state != STATE_RUNNING:
                raise IndependentControlledShadowError("runtime:complete-observation-state")
            data = _expect_keys(p["data"], {"slot_number", "attempt", "result", "result_digest", "aggregate"}, "complete-data")
            slot = _integer(data["slot_number"], "complete-slot", minimum=0, maximum=MAX_OBSERVATIONS - 1)
            existing = slot_state.get((sid, slot))
            if existing is None or existing["state"] != SLOT_LEASED or existing["attempt"] != data["attempt"]:
                raise IndependentControlledShadowError("runtime:complete-slot")
            _hex(data["result_digest"], "complete-result-digest")
            _aggregate(data["aggregate"])
            if data["result"] not in OBSERVATION_RESULTS:
                raise IndependentControlledShadowError("runtime:complete-result")
            slot_state[(sid, slot)] = {**existing, "state": SLOT_COMPLETED, "result_digest": data["result_digest"], "result": data["result"], "aggregate": data["aggregate"]}
            if data["result"] == "DISCREPANCY":
                discrepancies[(sid, slot)] = data["result_digest"]
        elif action == "EVALUATOR_FAILURE":
            if current_state != STATE_RUNNING or after_state not in (STATE_RUNNING, STATE_PAUSED):
                raise IndependentControlledShadowError("runtime:failure-state")
            data = _expect_keys(p["data"], {"slot_number", "attempt", "failure_code", "next_slot_state"}, "failure-data")
            slot = _integer(data["slot_number"], "failure-slot", minimum=0, maximum=MAX_OBSERVATIONS - 1)
            existing = slot_state.get((sid, slot))
            if existing is None or existing["state"] != SLOT_LEASED or existing["attempt"] != data["attempt"]:
                raise IndependentControlledShadowError("runtime:failure-slot")
            if data["failure_code"] not in FAILURE_CODES or data["next_slot_state"] not in (SLOT_DUE, SLOT_FAILED):
                raise IndependentControlledShadowError("runtime:failure-code")
            slot_state[(sid, slot)] = {**existing, "state": data["next_slot_state"], "failure_code": data["failure_code"]}
        elif action == "PAUSE":
            if current_state != STATE_RUNNING or after_state != STATE_PAUSED:
                raise IndependentControlledShadowError("runtime:pause-transition")
            data = _expect_keys(p["data"], {"reason"}, "pause-data")
            if data["reason"] not in PAUSE_REASONS:
                raise IndependentControlledShadowError("runtime:pause-reason")
        elif action == "RESUME":
            if current_state != STATE_PAUSED or after_state != STATE_RUNNING or set(p["data"]) != set():
                raise IndependentControlledShadowError("runtime:resume-transition")
        elif action == "COMPLETE_SESSION":
            if current_state != STATE_RUNNING or after_state != STATE_COMPLETED or set(p["data"]) != {"completed_observations"}:
                raise IndependentControlledShadowError("runtime:complete-session-transition")
            _integer(p["data"]["completed_observations"], "completed-observations", minimum=1, maximum=MAX_OBSERVATIONS)
        elif action == "ABORT":
            if current_state in (None, *TERMINAL_STATES) or after_state != STATE_ABORTED:
                raise IndependentControlledShadowError("runtime:abort-transition")
            data = _expect_keys(p["data"], {"reason"}, "abort-data")
            if data["reason"] not in ABORT_REASONS:
                raise IndependentControlledShadowError("runtime:abort-reason")
        else:
            raise IndependentControlledShadowError("runtime:transition-action")
        expected_transition = _transition_id(sequence, sid, action, payload, row["before_session_root"], row["before_global_root"])
        if transition_id != expected_transition:
            raise IndependentControlledShadowError("runtime:transition-id")
        expected_after_session = _session_after_root(sequence, sid, transition_id, row["before_session_root"])
        expected_after_global = _global_after_root(sequence, transition_id, row["before_global_root"])
        if row["after_session_root"] != expected_after_session or row["after_global_root"] != expected_after_global:
            raise IndependentControlledShadowError("runtime:transition-root")
        session_state[sid] = after_state
        session_head[sid] = row["after_session_root"]
        previous_global = row["after_global_root"]
    if previous_global != global_head:
        raise IndependentControlledShadowError("runtime:global-head")
    if set(sessions) != set(session_state):
        raise IndependentControlledShadowError("runtime:session-transition-set")
    for sid, row in sessions.items():
        if row["state"] != session_state[sid] or row["session_head_root"] != session_head[sid] or int(row["last_sequence"]) != max(int(item["sequence"]) for item in transitions if item["session_id"] == sid):
            raise IndependentControlledShadowError("runtime:session-head")
    operations = rows["runtime_operations"]
    if len(operations) != len(transitions):
        raise IndependentControlledShadowError("runtime:operation-count")
    transition_by_op = {str(row["operation_id"]): row for row in transitions}
    for row in operations:
        if set(row) != set(TABLE_COLUMNS["runtime_operations"]):
            raise IndependentControlledShadowError("runtime:operation-columns")
        op = _text(row["operation_id"], "operation-id", token=True)
        if op not in transition_by_op:
            raise IndependentControlledShadowError("runtime:operation-transition")
        request_raw = _safe_raw(row["request_raw"], "request", MAX_AUTH_BYTES)
        receipt_raw = _safe_raw(row["receipt_raw"], "receipt", MAX_AUTH_BYTES)
        if row["request_hash"] != _raw_digest(request_raw) or row["receipt_hash"] != _raw_digest(receipt_raw):
            raise IndependentControlledShadowError("runtime:operation-digest")
        request = _parse_blob(request_raw, "request", MAX_AUTH_BYTES)
        receipt = _parse_blob(receipt_raw, "receipt", MAX_AUTH_BYTES)
        _expect_keys(request, {"schema", "action", "session_id", "operation_id", "body"}, "request")
        _expect_keys(receipt, {"schema", "operation_id", "action", "session_id", "transition_id", "sequence", "state", "before_session_root", "after_session_root", "before_global_root", "after_global_root", "details", "flags"}, "receipt")
        transition = transition_by_op[op]
        payload = _parse_blob(transition["payload_raw"], "transition-payload", MAX_AUTH_BYTES)
        _integer(row["transition_sequence"], "operation-transition-sequence", minimum=1, maximum=MAX_TRANSITIONS)
        if row["session_id"] != transition["session_id"] or int(row["transition_sequence"]) != int(transition["sequence"]) or row["transition_id"] != transition["transition_id"]:
            raise IndependentControlledShadowError("runtime:operation-transition-binding")
        if request["schema"] != REQUEST_SCHEMA or request["action"] != row["action"] or request["session_id"] != row["session_id"] or request["operation_id"] != op or not isinstance(request["body"], dict):
            raise IndependentControlledShadowError("runtime:operation-request-binding")
        if row["action"] != "OPEN" and request["body"].get("expected_head") != transition["before_session_root"]:
            raise IndependentControlledShadowError("runtime:operation-request-head")
        if receipt["schema"] != RECEIPT_SCHEMA or receipt["operation_id"] != op or receipt["transition_id"] != row["transition_id"] or receipt["action"] != row["action"] or receipt["session_id"] != row["session_id"] or receipt["state"] != payload["state_after"] or receipt["details"] != payload["data"] or receipt["flags"] != FIXED_FLAGS:
            raise IndependentControlledShadowError("runtime:operation-binding")
        if int(receipt["sequence"]) != int(transition["sequence"]) or receipt["before_session_root"] != transition["before_session_root"] or receipt["after_session_root"] != transition["after_session_root"] or receipt["before_global_root"] != transition["before_global_root"] or receipt["after_global_root"] != transition["after_global_root"] or row["before_global_root"] != transition["before_global_root"] or row["after_global_root"] != transition["after_global_root"]:
            raise IndependentControlledShadowError("runtime:receipt-root")
    slots = rows["runtime_slots"]
    slot_rows: dict[tuple[str, int], dict[str, object]] = {}
    for row in slots:
        if set(row) != set(TABLE_COLUMNS["runtime_slots"]):
            raise IndependentControlledShadowError("runtime:slot-columns")
        sid = _text(row["session_id"], "slot-session", token=True)
        slot = _integer(row["slot_number"], "slot-number", minimum=0, maximum=MAX_OBSERVATIONS - 1)
        key = (sid, slot)
        if key in slot_rows or sid not in sessions:
            raise IndependentControlledShadowError("runtime:slot-identity")
        if row["state"] not in SLOT_STATES:
            raise IndependentControlledShadowError("runtime:slot-state")
        _integer(row["attempt"], "slot-attempt", minimum=1, maximum=8)
        for field in ("input_digest", "worker_digest", "lease_token_digest"):
            _hex(row[field], f"slot-{field}")
        for field in ("lease_expires_at", "due_at"):
            _integer(row[field], f"slot-{field}", minimum=1)
        if row["result_raw"] is not None:
            result_raw = _safe_raw(row["result_raw"], "slot-result", MAX_EVALUATOR_BYTES)
            result = _parse_blob(result_raw, "slot-result", MAX_EVALUATOR_BYTES)
            _hex(row["result_digest"], "slot-result-digest")
            if row["result_digest"] != _digest("evaluation-result", _evaluation_body(result)):
                raise IndependentControlledShadowError("runtime:slot-result-digest")
            if row["state"] != SLOT_COMPLETED:
                raise IndependentControlledShadowError("runtime:slot-result-state")
            try:
                checked_result = verify_evaluation_result(
                    result,
                    expected={"session_id": sid, "profile_digest": p_digest, "slot_number": slot, "attempt": int(row["attempt"]), "input_digest": row["input_digest"]},
                    evaluator_id=str(profile["evaluator_id"]),
                    evaluator_epoch=int(profile["evaluator_epoch"]),
                )
            except IndependentControlledShadowError:
                raise
            if row["observed_at"] != checked_result["observed_at"] or row["completed_at"] != checked_result["completed_at"] or row["result_digest"] != checked_result["result_digest"]:
                raise IndependentControlledShadowError("runtime:slot-result-binding")
        elif row["state"] == SLOT_COMPLETED:
            raise IndependentControlledShadowError("runtime:slot-completed-result")
        if row["last_failure_code"] is not None and row["last_failure_code"] not in FAILURE_CODES:
            raise IndependentControlledShadowError("runtime:slot-failure-code")
        slot_rows[key] = row
    for key, replayed in slot_state.items():
        if key not in slot_rows:
            raise IndependentControlledShadowError("runtime:slot-missing")
        row = slot_rows[key]
        if row["state"] != replayed["state"] or int(row["attempt"]) != int(replayed["attempt"]):
            raise IndependentControlledShadowError("runtime:slot-replay")
        if replayed["state"] == SLOT_COMPLETED and (row["result_digest"] != replayed.get("result_digest") or row["result_raw"] is None):
            raise IndependentControlledShadowError("runtime:slot-result-replay")
        if replayed["state"] == SLOT_COMPLETED:
            replayed_result = _parse_blob(row["result_raw"], "slot-result", MAX_EVALUATOR_BYTES)
            if replayed_result["result"] != replayed.get("result") or replayed_result["aggregate"] != replayed.get("aggregate"):
                raise IndependentControlledShadowError("runtime:slot-result-semantic-replay")
        if replayed["state"] in (SLOT_DUE, SLOT_FAILED) and row["last_failure_code"] != replayed.get("failure_code"):
            raise IndependentControlledShadowError("runtime:slot-failure-replay")
    discrepancy_rows = rows["runtime_discrepancies"]
    if len(discrepancy_rows) != len(discrepancies):
        raise IndependentControlledShadowError("runtime:discrepancy-count")
    for row in discrepancy_rows:
        sid = _text(row["session_id"], "discrepancy-session", token=True)
        slot = _integer(row["slot_number"], "discrepancy-slot", minimum=0, maximum=MAX_OBSERVATIONS - 1)
        if (sid, slot) not in discrepancies or row["result_digest"] != discrepancies[(sid, slot)] or row["code"] != "DISCREPANCY":
            raise IndependentControlledShadowError("runtime:discrepancy-binding")
        aggregate = _parse_blob(row["aggregate_raw"], "discrepancy-aggregate", MAX_EVALUATOR_BYTES)
        _aggregate(aggregate)
    return {
        "accepted": True,
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "profile_digest": p_digest,
        "chain_id": meta["chain_id"],
        "global_sequence": int(meta["global_sequence"]),
        "global_head_root": global_head,
        "session_count": len(sessions),
        "operation_count": len(operations),
        "transition_count": len(transitions),
        "slot_count": len(slots),
        "discrepancy_count": len(discrepancy_rows),
        "state_counts": {state: sum(row["state"] == state for row in sessions.values()) for state in STATES},
        "result_counts": {result: sum(value.get("result") == result for value in slot_state.values()) for result in OBSERVATION_RESULTS},
        "failure_count": sum(row["last_failure_code"] is not None for row in slots),
    }


def snapshot_database(path: str | Path, *, profile: Mapping[str, object]) -> dict[str, object]:
    database = Path(path)
    if not database.is_file() or database.stat().st_size > 64 * 1024 * 1024:
        raise IndependentControlledShadowError("runtime:database")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(database, uri=False, timeout=BUSY_TIMEOUT_MS / 1000.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN")
        _check_schema(connection)
        rows = _table_rows(connection)
        result = _verify_rows(rows, profile=profile)
        connection.commit()
        return {**result, "snapshot": rows}
    except IndependentControlledShadowError:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError) as exc:
        raise IndependentControlledShadowError("runtime:database-integrity") from exc
    finally:
        if connection is not None:
            connection.close()


def verify_database(path: str | Path, *, profile: Mapping[str, object]) -> dict[str, object]:
    result = snapshot_database(path, profile=profile)
    return {key: value for key, value in result.items() if key != "snapshot"}


def _export_rows(rows: Mapping[str, list[Mapping[str, object]]]) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    blob_fields = {
        "manifest_material", "authorization_material", "flags_raw", "request_raw", "receipt_raw", "payload_raw", "result_raw", "aggregate_raw",
    }
    for table in TABLES:
        converted: list[dict[str, object]] = []
        for row in rows[table]:
            item: dict[str, object] = {}
            for key in TABLE_COLUMNS[table]:
                value = row[key]
                item[key + "_hex" if key in blob_fields and value is not None else key] = bytes(value).hex() if key in blob_fields and value is not None else value
            converted.append(item)
        result[table] = converted
    return result


def _import_rows(rows: Mapping[str, object]) -> dict[str, list[dict[str, object]]]:
    if set(rows) != set(TABLES):
        raise IndependentControlledShadowError("runtime:export-tables")
    blob_fields = {
        "manifest_material", "authorization_material", "flags_raw", "request_raw", "receipt_raw", "payload_raw", "result_raw", "aggregate_raw",
    }
    result: dict[str, list[dict[str, object]]] = {}
    for table in TABLES:
        values = rows[table]
        if not isinstance(values, list):
            raise IndependentControlledShadowError("runtime:export-row-list")
        result[table] = []
        for item in values:
            if not isinstance(item, dict):
                raise IndependentControlledShadowError("runtime:export-row")
            expected = set(TABLE_COLUMNS[table])
            actual = {key[:-4] if key.endswith("_hex") else key for key in item}
            if actual != expected:
                raise IndependentControlledShadowError("runtime:export-row-keys")
            row: dict[str, object] = {}
            for key in TABLE_COLUMNS[table]:
                if key + "_hex" in item:
                    encoded_key = key + "_hex"
                elif key in item:
                    encoded_key = key
                else:
                    raise IndependentControlledShadowError("runtime:export-column")
                if key in blob_fields:
                    if encoded_key == key:
                        if item[key] is not None:
                            raise IndependentControlledShadowError("runtime:export-blob")
                        row[key] = None
                    else:
                        encoded = item[encoded_key]
                        if not isinstance(encoded, str) or len(encoded) % 2:
                            raise IndependentControlledShadowError("runtime:export-blob-hex")
                        try:
                            row[key] = bytes.fromhex(encoded)
                        except ValueError as exc:
                            raise IndependentControlledShadowError("runtime:export-blob-hex") from exc
                else:
                    row[key] = item[key]
            result[table].append(row)
    return result


def verify_export_bytes(raw: bytes, *, profile: Mapping[str, object]) -> dict[str, object]:
    value = _parse(raw, maximum=MAX_EXPORT_BYTES)
    expected = {"schema", "schema_version", "profile", "profile_digest", "tables", "flags", "export_root"}
    if set(value) != expected or value["schema"] != EXPORT_SCHEMA or value["schema_version"] != EXPORT_VERSION:
        raise IndependentControlledShadowError("runtime:export-schema")
    configured = verify_profile(profile)
    if value["profile"] != configured or value["profile_digest"] != profile_digest(configured) or value["flags"] != FIXED_FLAGS:
        raise IndependentControlledShadowError("runtime:export-profile")
    _hex(value["export_root"], "export-root")
    body = {key: item for key, item in value.items() if key != "export_root"}
    if value["export_root"] != _digest("runtime-export-root", body):
        raise IndependentControlledShadowError("runtime:export-root")
    rows = _import_rows(value["tables"])
    result = _verify_rows(rows, profile=configured)
    return {**result, "export_root": value["export_root"], "snapshot": rows}


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "AUTH_INPUT_SCHEMA", "EVALUATOR_INPUT_SCHEMA",
    "STATE_OPEN", "STATE_RUNNING", "STATE_PAUSED", "STATE_COMPLETED", "STATE_ABORTED", "STATES", "TERMINAL_STATES",
    "MODE_SYNTHETIC", "MODE_EXTERNAL", "MODES", "SLOT_DUE", "SLOT_LEASED", "SLOT_COMPLETED", "SLOT_FAILED", "SLOT_STATES",
    "OBSERVATION_RESULTS", "PAUSE_REASONS", "ABORT_REASONS", "FAILURE_CODES", "FIXED_FLAGS", "TABLE_COLUMNS", "TABLES",
    "IndependentControlledShadowError", "_canonical", "_digest", "_raw_digest", "_parse", "_hex", "_profile_material",
    "verify_profile", "profile_digest", "verify_upstream_bundle", "authorization_input", "verify_authorization_result",
    "evaluator_input", "verify_evaluation_result", "_genesis_root", "_transition_id", "_session_after_root", "_global_after_root",
    "snapshot_database", "verify_database", "verify_export_bytes", "_export_rows", "_import_rows", "_parse_blob", "_evaluation_body",
]
