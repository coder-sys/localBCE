"""Independent verifier for the governance-assertion evidence contract.

This module deliberately has no import from the producer.  It parses bounded
canonical bytes, reconstructs the configured policy and assertion bindings,
and verifies the fixed non-authorizing flags independently.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from app.mirror.error_boundary import raise_redacted


ARTIFACT_KIND = "MIRROR_EXTERNAL_GOVERNANCE_APPROVAL_V1"
SCHEMA = "mirror-external-governance-approval-v1"
SCHEMA_VERSION = 1
DOMAIN = "BL/MIRROR/EXTERNAL_GOVERNANCE_APPROVAL/"
SCOPE = "MIRROR_CONTROLLED_SHADOW_READ_ONLY"
STATUS = "GOVERNANCE_ASSERTION_OBSERVED"
DECISIONS = ("GRANTED", "DENIED", "WITHDRAWN")
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024
MAX_TIME = 10**12
MAX_STRING_BYTES = 512
MAX_NODES = 4_096
MAX_DEPTH = 16
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

POLICY_KEYS = {
    "source_policy_digest", "quarantine_policy_digest", "quarantine_artifact_id",
    "quarantine_head_artifact_id", "quarantine_head_root", "verifier_id",
    "verifier_epoch", "scope", "effective_start", "effective_end",
    "max_evidence_bytes", "required_zero_phi", "state_owned_control",
    "authority_evidence_digest", "revocation_head_digest", "terms_digest",
    "retention_policy_digest",
}
ASSERTION_KEYS = {
    "policy_digest", "approval_id", "evidence_sha3_512", "evidence_byte_length",
    "quarantine_policy_digest", "quarantine_artifact_id", "quarantine_head_artifact_id",
    "quarantine_head_root", "authority_evidence_digest", "revocation_head_digest",
    "terms_digest", "retention_policy_digest", "decision", "issued_at", "valid_from",
    "valid_until", "observed_at", "verifier_id", "verifier_epoch", "zero_phi", "state_owned",
}
TOP_KEYS = {
    "artifact_kind", "schema", "schema_version", "artifact_id", "policy", "policy_digest",
    "assertion", "derived_status", "owners", "nonclaims", "flags",
}
OWNERS = {
    "policy": "STATE_CONFIGURED_GOVERNANCE_APPROVAL_PROFILE",
    "assertion_verifier": "INJECTED_STATE_GOVERNANCE_ASSERTION_VERIFIER",
    "artifact": "MIRROR_EXTERNAL_GOVERNANCE_APPROVAL",
}
NONCLAIMS = [
    "external_assertion_is_not_authenticated_authority",
    "decision_is_not_effective_approval",
    "quarantine_snapshot_is_not_source_truth",
    "controlled_shadow_and_production_are_absent",
    "payment_clearance_and_settlement_are_absent",
]
FIXED_FLAGS = {
    "read_only": True,
    "zero_phi": True,
    "state_owned": True,
    "external_authority_authenticated": False,
    "state_approval_qualified": False,
    "controlled_shadow_ready": False,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "proofSuiteId": None,
}


class IndependentExternalGovernanceError(ValueError):
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
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(IndependentExternalGovernanceError, "governance:noncanonical")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentExternalGovernanceError(f"governance:{label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or SAFE_IDENTIFIER.fullmatch(value) is None:
        raise IndependentExternalGovernanceError(f"governance:{label}")
    lowered = value.lower()
    forbidden = (
        "http://", "https://", "bearer", "cookie", "token=", "password",
        "secret", "credential", "header", "patient", "member", "claim",
        "ssn", "mrn", "npi", "email", "phone", "address",
    )
    if any(marker in lowered for marker in forbidden):
        raise IndependentExternalGovernanceError(f"governance:{label}-forbidden")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = MAX_TIME) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentExternalGovernanceError(f"governance:{label}")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise IndependentExternalGovernanceError("governance:duplicate-key")
        value[key] = item
    return value


def _walk(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_NODES:
        raise IndependentExternalGovernanceError("governance:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentExternalGovernanceError("governance:depth-cap")
    if isinstance(value, float):
        raise IndependentExternalGovernanceError("governance:float")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise IndependentExternalGovernanceError("governance:string-cap")
        try:
            value.encode("ascii")
        except UnicodeEncodeError:
            raise_redacted(IndependentExternalGovernanceError, "governance:ascii")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentExternalGovernanceError("governance:key-type")
            _walk(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, nodes=nodes)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentExternalGovernanceError("governance:artifact-byte-cap")
    try:
        text = raw.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentExternalGovernanceError("governance:constant")),
        )
    except IndependentExternalGovernanceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise_redacted(IndependentExternalGovernanceError, "governance:parse")
    if not isinstance(value, dict):
        raise IndependentExternalGovernanceError("governance:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentExternalGovernanceError("governance:not-canonical")
    return value


def _policy_material(policy: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(policy, Mapping) or set(policy) != POLICY_KEYS:
        raise IndependentExternalGovernanceError("governance:policy-keys")
    values = dict(policy)
    for label in (
        "source_policy_digest", "quarantine_policy_digest", "quarantine_artifact_id",
        "quarantine_head_artifact_id", "quarantine_head_root", "authority_evidence_digest",
        "revocation_head_digest", "terms_digest", "retention_policy_digest",
    ):
        _hex(values[label], label.replace("_", "-"))
    _text(values["verifier_id"], "verifier-id")
    _integer(values["verifier_epoch"], "verifier-epoch", maximum=1_000_000)
    if values["scope"] != SCOPE:
        raise IndependentExternalGovernanceError("governance:scope")
    start = _integer(values["effective_start"], "effective-start")
    end = _integer(values["effective_end"], "effective-end")
    if end <= start:
        raise IndependentExternalGovernanceError("governance:effective-interval")
    max_evidence = _integer(values["max_evidence_bytes"], "evidence-cap", minimum=1, maximum=MAX_EVIDENCE_BYTES)
    if values["required_zero_phi"] is not True or type(values["required_zero_phi"]) is not bool:
        raise IndependentExternalGovernanceError("governance:zero-phi-policy")
    if values["state_owned_control"] is not True or type(values["state_owned_control"]) is not bool:
        raise IndependentExternalGovernanceError("governance:state-owned-policy")
    return {
        "source_policy_digest": values["source_policy_digest"],
        "quarantine_policy_digest": values["quarantine_policy_digest"],
        "quarantine_artifact_id": values["quarantine_artifact_id"],
        "quarantine_head_artifact_id": values["quarantine_head_artifact_id"],
        "quarantine_head_root": values["quarantine_head_root"],
        "verifier_id": values["verifier_id"],
        "verifier_epoch": values["verifier_epoch"],
        "scope": values["scope"],
        "effective_start": start,
        "effective_end": end,
        "max_evidence_bytes": max_evidence,
        "required_zero_phi": True,
        "state_owned_control": True,
        "authority_evidence_digest": values["authority_evidence_digest"],
        "revocation_head_digest": values["revocation_head_digest"],
        "terms_digest": values["terms_digest"],
        "retention_policy_digest": values["retention_policy_digest"],
    }


def approval_id_for_evidence(evidence_digest: str, byte_length: int) -> str:
    _hex(evidence_digest, "evidence-digest")
    _integer(byte_length, "evidence-length", minimum=1, maximum=MAX_EVIDENCE_BYTES)
    return _digest(
        "approval-id",
        {"evidence_sha3_512": evidence_digest, "evidence_byte_length": byte_length},
    )


def _validate_assertion(assertion: object, policy: Mapping[str, object], policy_digest: str) -> dict[str, object]:
    if not isinstance(assertion, dict) or set(assertion) != ASSERTION_KEYS:
        raise IndependentExternalGovernanceError("governance:assertion-keys")
    for label in (
        "policy_digest", "approval_id", "evidence_sha3_512", "quarantine_policy_digest",
        "quarantine_artifact_id", "quarantine_head_artifact_id", "quarantine_head_root",
        "authority_evidence_digest", "revocation_head_digest", "terms_digest",
        "retention_policy_digest",
    ):
        _hex(assertion[label], label.replace("_", "-"))
    if assertion["policy_digest"] != policy_digest:
        raise IndependentExternalGovernanceError("governance:assertion-policy")
    if assertion["approval_id"] != approval_id_for_evidence(assertion["evidence_sha3_512"], assertion["evidence_byte_length"]):
        raise IndependentExternalGovernanceError("governance:approval-binding")
    if assertion["quarantine_policy_digest"] != policy["quarantine_policy_digest"] or assertion["quarantine_artifact_id"] != policy["quarantine_artifact_id"] or assertion["quarantine_head_artifact_id"] != policy["quarantine_head_artifact_id"] or assertion["quarantine_head_root"] != policy["quarantine_head_root"]:
        raise IndependentExternalGovernanceError("governance:quarantine-binding")
    for key in ("authority_evidence_digest", "revocation_head_digest", "terms_digest", "retention_policy_digest"):
        if assertion[key] != policy[key]:
            raise IndependentExternalGovernanceError("governance:evidence-reference-binding")
    _integer(assertion["evidence_byte_length"], "evidence-length", minimum=1, maximum=policy["max_evidence_bytes"])
    if assertion["decision"] not in DECISIONS:
        raise IndependentExternalGovernanceError("governance:decision")
    _text(assertion["verifier_id"], "verifier-id")
    if assertion["verifier_id"] != policy["verifier_id"] or assertion["verifier_epoch"] != policy["verifier_epoch"]:
        raise IndependentExternalGovernanceError("governance:verifier-binding")
    for label in ("issued_at", "valid_from", "valid_until", "observed_at"):
        _integer(assertion[label], label.replace("_", "-"))
    if assertion["valid_until"] <= assertion["valid_from"] or not (
        assertion["issued_at"] <= assertion["valid_from"] <= assertion["observed_at"] <= assertion["valid_until"]
    ):
        raise IndependentExternalGovernanceError("governance:chronology")
    if not (
        policy["effective_start"] <= assertion["issued_at"] <= assertion["valid_from"]
        <= assertion["observed_at"] <= assertion["valid_until"] <= policy["effective_end"]
    ):
        raise IndependentExternalGovernanceError("governance:policy-chronology")
    if assertion["zero_phi"] is not True or type(assertion["zero_phi"]) is not bool:
        raise IndependentExternalGovernanceError("governance:zero-phi")
    if assertion["state_owned"] is not True or type(assertion["state_owned"]) is not bool:
        raise IndependentExternalGovernanceError("governance:state-owned")
    return dict(assertion)


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
        raise IndependentExternalGovernanceError("governance:artifact-keys")
    if value["artifact_kind"] != ARTIFACT_KIND or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IndependentExternalGovernanceError("governance:schema")
    configured_policy = _policy_material(policy)
    policy_digest = _digest("policy", configured_policy)
    if value["policy"] != configured_policy or value["policy_digest"] != policy_digest:
        raise IndependentExternalGovernanceError("governance:policy-binding")
    assertion = _validate_assertion(value["assertion"], configured_policy, policy_digest)
    if value["derived_status"] != STATUS:
        raise IndependentExternalGovernanceError("governance:status")
    if value["owners"] != OWNERS or value["nonclaims"] != NONCLAIMS or value["flags"] != FIXED_FLAGS:
        raise IndependentExternalGovernanceError("governance:authority-flags")
    artifact_id = _hex(value["artifact_id"], "artifact-id")
    if artifact_id != _digest("artifact-id", _identity_body(value)):
        raise IndependentExternalGovernanceError("governance:artifact-id")
    if evidence_raw is not None:
        if type(evidence_raw) is not bytes or len(evidence_raw) != assertion["evidence_byte_length"]:
            raise IndependentExternalGovernanceError("governance:evidence-recheck")
        if _raw_digest(evidence_raw) != assertion["evidence_sha3_512"]:
            raise IndependentExternalGovernanceError("governance:evidence-rebound")
    return {
        "accepted": True,
        "artifact_kind": ARTIFACT_KIND,
        "artifact_id": artifact_id,
        "policy_digest": policy_digest,
        "quarantine_artifact_id": configured_policy["quarantine_artifact_id"],
        "quarantine_head_artifact_id": configured_policy["quarantine_head_artifact_id"],
        "quarantine_head_root": configured_policy["quarantine_head_root"],
        "approval_id": assertion["approval_id"],
        "decision": assertion["decision"],
        "derived_status": STATUS,
        "external_authority_authenticated": False,
        "state_approval_qualified": False,
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
    "MAX_EVIDENCE_BYTES", "MAX_ARTIFACT_BYTES", "POLICY_KEYS", "ASSERTION_KEYS", "TOP_KEYS",
    "OWNERS", "NONCLAIMS", "FIXED_FLAGS", "IndependentExternalGovernanceError",
    "approval_id_for_evidence", "verify_artifact", "inspect_artifact", "verify_bytes",
]
