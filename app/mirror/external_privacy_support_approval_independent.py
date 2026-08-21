"""Independent verifier for privacy/support assertion evidence.

This module has no import from the producer.  It owns bounded parsing,
coverage/control validation, chronology, identity recomputation, and the
nonactivating flag contract.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping


ARTIFACT_KIND = "MIRROR_EXTERNAL_PRIVACY_SUPPORT_APPROVAL_V1"
SCHEMA = "mirror-external-privacy-support-approval-v1"
SCHEMA_VERSION = 1
DOMAIN = "BL/MIRROR/EXTERNAL_PRIVACY_SUPPORT_APPROVAL/"
SCOPE = "MIRROR_CONTROLLED_SHADOW_READ_ONLY"
STATUS = "PRIVACY_SUPPORT_ASSERTIONS_OBSERVED"
DECISIONS = ("GRANTED", "DENIED", "WITHDRAWN")
COVERAGE_KEYS = (
    "employees", "contractors", "logs", "dumps", "monitoring", "analytics",
    "support", "persistent_fingerprints", "ai",
)
SUPPORT_CONTROL_KEYS = (
    "bounded_retention", "redacted_monitoring", "bounded_support_output",
    "incident_escalation", "deletion_withdrawal_handling", "no_raw_capture_disclosure",
)
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024
MAX_TIME = 10**12
MAX_STRING_BYTES = 512
MAX_NODES = 8_192
MAX_DEPTH = 16
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

POLICY_KEYS = {
    "source_policy_digest", "quarantine_policy_digest", "quarantine_artifact_id",
    "quarantine_head_artifact_id", "quarantine_head_root", "governance_observation_artifact_id",
    "governance_evidence_digest", "governance_decision", "terms_digest", "retention_policy_digest",
    "verifier_id", "verifier_epoch", "scope", "effective_start", "effective_end",
    "max_evidence_bytes", "required_zero_phi", "state_owned_control",
    "privacy_authority_evidence_digest", "support_authority_evidence_digest", "revocation_head_digest",
}
ASSERTION_KEYS = {
    "policy_digest", "assertion_id", "evidence_sha3_512", "evidence_byte_length",
    "quarantine_policy_digest", "quarantine_artifact_id", "quarantine_head_artifact_id",
    "quarantine_head_root", "governance_observation_artifact_id", "governance_evidence_digest",
    "governance_decision", "terms_digest", "retention_policy_digest", "privacy_decision",
    "support_decision", "issued_at", "valid_from", "valid_until", "observed_at",
    "verifier_id", "verifier_epoch", "privacy_authority_evidence_digest",
    "support_authority_evidence_digest", "revocation_head_digest", "coverage",
    "support_controls", "zero_phi", "state_owned",
}
TOP_KEYS = {
    "artifact_kind", "schema", "schema_version", "artifact_id", "policy", "policy_digest",
    "assertion", "derived_status", "owners", "nonclaims", "flags",
}
OWNERS = {
    "policy": "STATE_CONFIGURED_PRIVACY_SUPPORT_PROFILE",
    "assertion_verifier": "INJECTED_STATE_PRIVACY_SUPPORT_VERIFIER",
    "artifact": "MIRROR_EXTERNAL_PRIVACY_SUPPORT_APPROVAL",
}
NONCLAIMS = [
    "privacy_and_support_assertions_are_not_authenticated_authority",
    "grant_decisions_are_not_effective_qualification",
    "quarantine_and_governance_snapshots_are_not_source_truth",
    "controlled_shadow_and_production_are_absent",
    "payment_clearance_and_settlement_are_absent",
]
FIXED_FLAGS = {
    "read_only": True,
    "zero_phi": True,
    "state_owned": True,
    "external_authority_authenticated": False,
    "state_privacy_qualified": False,
    "state_support_qualified": False,
    "controlled_shadow_ready": False,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "proofSuiteId": None,
}


class IndependentExternalPrivacySupportError(ValueError):
    """A bounded independent-artifact rejection."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentExternalPrivacySupportError("privacy-support:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentExternalPrivacySupportError(f"privacy-support:{label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or SAFE_IDENTIFIER.fullmatch(value) is None:
        raise IndependentExternalPrivacySupportError(f"privacy-support:{label}")
    lowered = value.lower()
    forbidden = (
        "http://", "https://", "bearer", "cookie", "token=", "password",
        "secret", "credential", "header", "patient", "member", "claim",
        "ssn", "mrn", "npi", "email", "phone", "address", "person",
        "organization", "case", "record",
    )
    if any(marker in lowered for marker in forbidden):
        raise IndependentExternalPrivacySupportError(f"privacy-support:{label}-forbidden")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = MAX_TIME) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentExternalPrivacySupportError(f"privacy-support:{label}")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise IndependentExternalPrivacySupportError("privacy-support:duplicate-key")
        value[key] = item
    return value


def _walk(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_NODES:
        raise IndependentExternalPrivacySupportError("privacy-support:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentExternalPrivacySupportError("privacy-support:depth-cap")
    if isinstance(value, float):
        raise IndependentExternalPrivacySupportError("privacy-support:float")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise IndependentExternalPrivacySupportError("privacy-support:string-cap")
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise IndependentExternalPrivacySupportError("privacy-support:ascii") from exc
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentExternalPrivacySupportError("privacy-support:key-type")
            _walk(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, nodes=nodes)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentExternalPrivacySupportError("privacy-support:artifact-byte-cap")
    try:
        text = raw.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentExternalPrivacySupportError("privacy-support:constant")),
        )
    except IndependentExternalPrivacySupportError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise IndependentExternalPrivacySupportError("privacy-support:parse") from exc
    if not isinstance(value, dict):
        raise IndependentExternalPrivacySupportError("privacy-support:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentExternalPrivacySupportError("privacy-support:not-canonical")
    return value


def _policy_material(policy: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(policy, Mapping) or set(policy) != POLICY_KEYS:
        raise IndependentExternalPrivacySupportError("privacy-support:policy-keys")
    values = dict(policy)
    for label in (
        "source_policy_digest", "quarantine_policy_digest", "quarantine_artifact_id",
        "quarantine_head_artifact_id", "quarantine_head_root", "governance_observation_artifact_id",
        "governance_evidence_digest", "terms_digest", "retention_policy_digest",
        "privacy_authority_evidence_digest", "support_authority_evidence_digest", "revocation_head_digest",
    ):
        _hex(values[label], label.replace("_", "-"))
    if values["governance_decision"] not in DECISIONS:
        raise IndependentExternalPrivacySupportError("privacy-support:governance-decision")
    _text(values["verifier_id"], "verifier-id")
    _integer(values["verifier_epoch"], "verifier-epoch", maximum=1_000_000)
    if values["scope"] != SCOPE:
        raise IndependentExternalPrivacySupportError("privacy-support:scope")
    start = _integer(values["effective_start"], "effective-start")
    end = _integer(values["effective_end"], "effective-end")
    if end <= start:
        raise IndependentExternalPrivacySupportError("privacy-support:effective-interval")
    max_evidence = _integer(values["max_evidence_bytes"], "evidence-cap", minimum=1, maximum=MAX_EVIDENCE_BYTES)
    if values["required_zero_phi"] is not True or type(values["required_zero_phi"]) is not bool:
        raise IndependentExternalPrivacySupportError("privacy-support:zero-phi-policy")
    if values["state_owned_control"] is not True or type(values["state_owned_control"]) is not bool:
        raise IndependentExternalPrivacySupportError("privacy-support:state-owned-policy")
    return {
        "source_policy_digest": values["source_policy_digest"],
        "quarantine_policy_digest": values["quarantine_policy_digest"],
        "quarantine_artifact_id": values["quarantine_artifact_id"],
        "quarantine_head_artifact_id": values["quarantine_head_artifact_id"],
        "quarantine_head_root": values["quarantine_head_root"],
        "governance_observation_artifact_id": values["governance_observation_artifact_id"],
        "governance_evidence_digest": values["governance_evidence_digest"],
        "governance_decision": values["governance_decision"],
        "terms_digest": values["terms_digest"],
        "retention_policy_digest": values["retention_policy_digest"],
        "verifier_id": values["verifier_id"],
        "verifier_epoch": values["verifier_epoch"],
        "scope": values["scope"],
        "effective_start": start,
        "effective_end": end,
        "max_evidence_bytes": max_evidence,
        "required_zero_phi": True,
        "state_owned_control": True,
        "privacy_authority_evidence_digest": values["privacy_authority_evidence_digest"],
        "support_authority_evidence_digest": values["support_authority_evidence_digest"],
        "revocation_head_digest": values["revocation_head_digest"],
    }


def assertion_id_for_evidence(evidence_digest: str, byte_length: int) -> str:
    _hex(evidence_digest, "evidence-digest")
    _integer(byte_length, "evidence-length", minimum=1, maximum=MAX_EVIDENCE_BYTES)
    return _digest(
        "assertion-id",
        {"evidence_sha3_512": evidence_digest, "evidence_byte_length": byte_length},
    )


def _boolean_map(value: object, expected: tuple[str, ...], label: str) -> dict[str, bool]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise IndependentExternalPrivacySupportError(f"privacy-support:{label}-keys")
    result: dict[str, bool] = {}
    for key in expected:
        if type(value[key]) is not bool:
            raise IndependentExternalPrivacySupportError(f"privacy-support:{label}-type")
        result[key] = value[key]
    return result


def _validate_assertion(assertion: object, policy: Mapping[str, object], policy_digest: str) -> dict[str, object]:
    if not isinstance(assertion, dict) or set(assertion) != ASSERTION_KEYS:
        raise IndependentExternalPrivacySupportError("privacy-support:assertion-keys")
    for label in (
        "policy_digest", "evidence_sha3_512", "quarantine_policy_digest", "quarantine_artifact_id",
        "quarantine_head_artifact_id", "quarantine_head_root", "governance_observation_artifact_id",
        "governance_evidence_digest", "terms_digest", "retention_policy_digest",
        "privacy_authority_evidence_digest", "support_authority_evidence_digest", "revocation_head_digest",
    ):
        _hex(assertion[label], label.replace("_", "-"))
    if assertion["policy_digest"] != policy_digest:
        raise IndependentExternalPrivacySupportError("privacy-support:assertion-policy")
    _hex(assertion["assertion_id"], "assertion-id")
    if assertion["assertion_id"] != assertion_id_for_evidence(assertion["evidence_sha3_512"], assertion["evidence_byte_length"]):
        raise IndependentExternalPrivacySupportError("privacy-support:assertion-binding")
    for key in (
        "quarantine_policy_digest", "quarantine_artifact_id", "quarantine_head_artifact_id",
        "quarantine_head_root", "governance_observation_artifact_id", "governance_evidence_digest",
        "governance_decision", "terms_digest", "retention_policy_digest",
    ):
        if assertion[key] != policy[key]:
            raise IndependentExternalPrivacySupportError("privacy-support:upstream-binding")
    for key in ("privacy_authority_evidence_digest", "support_authority_evidence_digest", "revocation_head_digest"):
        if assertion[key] != policy[key]:
            raise IndependentExternalPrivacySupportError("privacy-support:authority-binding")
    _integer(assertion["evidence_byte_length"], "evidence-length", minimum=1, maximum=policy["max_evidence_bytes"])
    for key in ("governance_decision", "privacy_decision", "support_decision"):
        if assertion[key] not in DECISIONS:
            raise IndependentExternalPrivacySupportError(f"privacy-support:{key}")
    _text(assertion["verifier_id"], "verifier-id")
    if assertion["verifier_id"] != policy["verifier_id"] or assertion["verifier_epoch"] != policy["verifier_epoch"]:
        raise IndependentExternalPrivacySupportError("privacy-support:verifier-binding")
    coverage = _boolean_map(assertion["coverage"], COVERAGE_KEYS, "coverage")
    controls = _boolean_map(assertion["support_controls"], SUPPORT_CONTROL_KEYS, "support-controls")
    if assertion["privacy_decision"] == "GRANTED" and not all(coverage.values()):
        raise IndependentExternalPrivacySupportError("privacy-support:coverage-incomplete")
    if assertion["support_decision"] == "GRANTED" and not all(controls.values()):
        raise IndependentExternalPrivacySupportError("privacy-support:controls-incomplete")
    for label in ("issued_at", "valid_from", "valid_until", "observed_at"):
        _integer(assertion[label], label.replace("_", "-"))
    if assertion["valid_until"] <= assertion["valid_from"] or not (
        assertion["issued_at"] <= assertion["valid_from"] <= assertion["observed_at"] <= assertion["valid_until"]
    ):
        raise IndependentExternalPrivacySupportError("privacy-support:chronology")
    if not (
        policy["effective_start"] <= assertion["issued_at"] <= assertion["valid_from"]
        <= assertion["observed_at"] <= assertion["valid_until"] <= policy["effective_end"]
    ):
        raise IndependentExternalPrivacySupportError("privacy-support:policy-chronology")
    if assertion["zero_phi"] is not True or type(assertion["zero_phi"]) is not bool:
        raise IndependentExternalPrivacySupportError("privacy-support:zero-phi")
    if assertion["state_owned"] is not True or type(assertion["state_owned"]) is not bool:
        raise IndependentExternalPrivacySupportError("privacy-support:state-owned")
    return {**assertion, "coverage": coverage, "support_controls": controls}


def _identity_body(value: Mapping[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if key != "artifact_id"}


def verify_artifact(
    raw: bytes,
    *,
    policy: Mapping[str, object],
    evidence_raw: bytes | None = None,
) -> dict[str, object]:
    value = _parse(raw)
    if set(value) != TOP_KEYS:
        raise IndependentExternalPrivacySupportError("privacy-support:artifact-keys")
    if value["artifact_kind"] != ARTIFACT_KIND or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IndependentExternalPrivacySupportError("privacy-support:schema")
    configured_policy = _policy_material(policy)
    policy_digest = _digest("policy", configured_policy)
    if value["policy"] != configured_policy or value["policy_digest"] != policy_digest:
        raise IndependentExternalPrivacySupportError("privacy-support:policy-binding")
    assertion = _validate_assertion(value["assertion"], configured_policy, policy_digest)
    if value["derived_status"] != STATUS:
        raise IndependentExternalPrivacySupportError("privacy-support:status")
    if value["owners"] != OWNERS or value["nonclaims"] != NONCLAIMS or value["flags"] != FIXED_FLAGS:
        raise IndependentExternalPrivacySupportError("privacy-support:authority-flags")
    artifact_id = _hex(value["artifact_id"], "artifact-id")
    if artifact_id != _digest("artifact-id", _identity_body(value)):
        raise IndependentExternalPrivacySupportError("privacy-support:artifact-id")
    if evidence_raw is not None:
        if type(evidence_raw) is not bytes or len(evidence_raw) != assertion["evidence_byte_length"]:
            raise IndependentExternalPrivacySupportError("privacy-support:evidence-recheck")
        if _raw_digest(evidence_raw) != assertion["evidence_sha3_512"]:
            raise IndependentExternalPrivacySupportError("privacy-support:evidence-rebound")
    return {
        "accepted": True,
        "artifact_kind": ARTIFACT_KIND,
        "artifact_id": artifact_id,
        "policy_digest": policy_digest,
        "governance_observation_artifact_id": configured_policy["governance_observation_artifact_id"],
        "privacy_decision": assertion["privacy_decision"],
        "support_decision": assertion["support_decision"],
        "coverage": assertion["coverage"],
        "support_controls": assertion["support_controls"],
        "derived_status": STATUS,
        "external_authority_authenticated": False,
        "state_privacy_qualified": False,
        "state_support_qualified": False,
        "controlled_shadow_ready": False,
        "production_usable": False,
        "activation": False,
    }


def inspect_artifact(raw: bytes, *, policy: Mapping[str, object], evidence_raw: bytes | None = None) -> dict[str, object]:
    return verify_artifact(raw, policy=policy, evidence_raw=evidence_raw)


def verify_bytes(raw: bytes, *, policy: Mapping[str, object], evidence_raw: bytes | None = None) -> dict[str, object]:
    return verify_artifact(raw, policy=policy, evidence_raw=evidence_raw)


__all__ = [
    "ARTIFACT_KIND", "SCHEMA", "SCHEMA_VERSION", "SCOPE", "STATUS", "DECISIONS",
    "COVERAGE_KEYS", "SUPPORT_CONTROL_KEYS", "MAX_EVIDENCE_BYTES", "MAX_ARTIFACT_BYTES",
    "POLICY_KEYS", "ASSERTION_KEYS", "TOP_KEYS", "OWNERS", "NONCLAIMS", "FIXED_FLAGS",
    "IndependentExternalPrivacySupportError", "assertion_id_for_evidence", "verify_artifact",
    "inspect_artifact", "verify_bytes",
]
