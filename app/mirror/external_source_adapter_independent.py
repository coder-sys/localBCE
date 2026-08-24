"""Independent verifier for the transport-neutral external-source contract.

This module intentionally has no import from the producer/composition module.
It validates only canonical artifact bytes and a separately configured policy
view.  It does not authenticate a live source, interpret a URL, or retain raw
capture bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from app.mirror.error_boundary import raise_redacted


ARTIFACT_KIND = "MIRROR_EXTERNAL_SOURCE_EVIDENCE_V1"
SCHEMA = "mirror-external-source-evidence-v1"
SCHEMA_VERSION = 1
DOMAIN = "BL/MIRROR/EXTERNAL_SOURCE_ADAPTER/"
EVIDENCE_MODE = "SOFTWARE_CONTRACT_TEST_ONLY"
CANONICAL_ORDER = "PAGE_DIGEST_ASCENDING"
COMPLETENESS_RULE = "EXPLICIT_COMPLETE_BOOLEAN_NO_ABSENCE"
MAX_ARTIFACT_BYTES = 64 * 1024
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_PAGE_COUNT = 1_024
MAX_STRING_BYTES = 512
MAX_NODES = 4_096
MAX_DEPTH = 16
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

FAILURE_CODES = ("NONE", "AUTHORITY_UNQUALIFIED", "INCOMPLETE", "STALE", "SOURCE_FAILURE")
STATUSES = (
    "OBSERVATION_ADMITTED",
    "HOLD_AUTHORITY_UNQUALIFIED",
    "HOLD_INCOMPLETE",
    "HOLD_STALE",
    "HOLD_SOURCE_FAILURE",
)

POLICY_KEYS = {
    "profile_id", "version", "subject", "scope", "logical_endpoint_id", "source_roles",
    "verifier_id", "verifier_epoch", "authorization_artifact_digest", "terms_artifact_digest",
    "effective_start", "effective_end", "expected_cadence_seconds", "freshness_grace_seconds",
    "max_capture_bytes", "max_page_count", "canonical_order", "completeness_rule", "evidence_mode",
}
CAPTURE_KEYS = {
    "capture_id", "policy_digest", "verifier_id", "verifier_epoch", "payload_sha3_512",
    "byte_length", "observed_at", "fetched_at", "page_digests", "page_count",
    "server_identity_digest", "transport_receipt_digest", "transport_authenticated", "complete",
    "failure_code", "zero_phi",
}
TOP_KEYS = {
    "artifact_kind", "schema", "schema_version", "artifact_id", "policy", "policy_digest",
    "capture", "derived_status", "owners", "nonclaims", "flags",
}
OWNERS = {
    "policy": "STATE_CONFIGURED_SOURCE_PROFILE",
    "capture_verifier": "CONFIGURED_EXTERNAL_CAPTURE_VERIFIER",
    "artifact": "MIRROR_EXTERNAL_SOURCE_ADAPTER",
}
NONCLAIMS = [
    "transport_provenance_is_not_source_truth",
    "external_authorization_and_legal_terms",
    "completeness_or_nonmembership",
    "production_source_authentication",
    "controlled_shadow_or_production_readiness",
    "payment_clearance_settlement_or_activation",
]
FIXED_FLAGS = {
    "read_only": True,
    "zero_phi": True,
    "state_owned": True,
    "external_authorization_qualified": False,
    "controlled_shadow_ready": False,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "proofSuiteId": None,
}


class IndependentExternalSourceError(ValueError):
    """A bounded independent-artifact rejection."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(IndependentExternalSourceError, "external:noncanonical")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def capture_id_for_payload(payload_sha3_512: str) -> str:
    if not isinstance(payload_sha3_512, str) or HEX128.fullmatch(payload_sha3_512) is None:
        raise IndependentExternalSourceError("external:payload-digest")
    return _digest("capture-id", payload_sha3_512)


def _expected_server_identity(policy: Mapping[str, object]) -> str:
    return _digest("server-identity", policy["logical_endpoint_id"])


def _expected_transport_receipt(policy: Mapping[str, object], capture: Mapping[str, object], server_identity_digest: str) -> str:
    return _digest(
        "transport-receipt",
        {
            "policy_digest": capture["policy_digest"],
            "verifier_id": capture["verifier_id"],
            "verifier_epoch": capture["verifier_epoch"],
            "payload_sha3_512": capture["payload_sha3_512"],
            "page_digests": capture["page_digests"],
            "server_identity_digest": server_identity_digest,
            "observed_at": capture["observed_at"],
            "fetched_at": capture["fetched_at"],
            "transport_authenticated": capture["transport_authenticated"],
            "complete": capture["complete"],
            "failure_code": capture["failure_code"],
        },
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise IndependentExternalSourceError("external:duplicate-key")
        value[key] = item
    return value


def _walk(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    nodes = nodes or [0]
    nodes[0] += 1
    if nodes[0] > MAX_NODES:
        raise IndependentExternalSourceError("external:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentExternalSourceError("external:depth-cap")
    if isinstance(value, float):
        raise IndependentExternalSourceError("external:float")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise IndependentExternalSourceError("external:string-cap")
        try:
            value.encode("ascii")
        except UnicodeEncodeError:
            raise_redacted(IndependentExternalSourceError, "external:ascii")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentExternalSourceError("external:key-type")
            _walk(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, nodes=nodes)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentExternalSourceError("external:artifact-byte-cap")
    try:
        raw.decode("ascii")
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentExternalSourceError("external:constant")),
        )
    except IndependentExternalSourceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise_redacted(IndependentExternalSourceError, "external:parse")
    if not isinstance(value, dict):
        raise IndependentExternalSourceError("external:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentExternalSourceError("external:not-canonical")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or not SAFE_IDENTIFIER.fullmatch(value):
        raise IndependentExternalSourceError(f"external:{label}")
    lowered = value.lower()
    forbidden = ("http://", "https://", "bearer", "cookie", "token=", "password", "secret", "credential", "header", "patient_id", "member_id", "claim_id", "ssn", "mrn", "npi", "email", "phone", "address")
    if any(marker in lowered for marker in forbidden):
        raise IndependentExternalSourceError(f"external:{label}-forbidden")
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentExternalSourceError(f"external:{label}")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = 10**12) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentExternalSourceError(f"external:{label}")
    return value


def _policy_material(policy: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(policy, Mapping) or set(policy) != POLICY_KEYS:
        raise IndependentExternalSourceError("external:policy-keys")
    result = {key: policy[key] for key in POLICY_KEYS}
    _text(result["profile_id"], "profile-id")
    _integer(result["version"], "profile-version", minimum=1, maximum=1_000_000)
    _text(result["subject"], "subject")
    _text(result["scope"], "scope")
    _text(result["logical_endpoint_id"], "endpoint")
    roles = result["source_roles"]
    if not isinstance(roles, list) or not 1 <= len(roles) <= 32 or any(not isinstance(item, str) for item in roles) or len(set(roles)) != len(roles):
        raise IndependentExternalSourceError("external:source-roles")
    for role in roles:
        _text(role, "source-role")
    _text(result["verifier_id"], "verifier-id")
    _integer(result["verifier_epoch"], "verifier-epoch", maximum=1_000_000)
    _hex(result["authorization_artifact_digest"], "authorization-digest")
    _hex(result["terms_artifact_digest"], "terms-digest")
    start = _integer(result["effective_start"], "effective-start")
    end = _integer(result["effective_end"], "effective-end")
    if end <= start:
        raise IndependentExternalSourceError("external:effective-interval")
    _integer(result["expected_cadence_seconds"], "cadence", minimum=1, maximum=31_536_000)
    _integer(result["freshness_grace_seconds"], "freshness-grace", maximum=31_536_000)
    max_capture = _integer(result["max_capture_bytes"], "capture-cap", minimum=1, maximum=MAX_CAPTURE_BYTES)
    max_pages = _integer(result["max_page_count"], "page-cap", minimum=1, maximum=MAX_PAGE_COUNT)
    if result["canonical_order"] != CANONICAL_ORDER or result["completeness_rule"] != COMPLETENESS_RULE or result["evidence_mode"] != EVIDENCE_MODE:
        raise IndependentExternalSourceError("external:policy-contract")
    if max_capture > MAX_CAPTURE_BYTES or max_pages > MAX_PAGE_COUNT:
        raise IndependentExternalSourceError("external:policy-cap")
    return {
        "profile_id": result["profile_id"], "version": result["version"], "subject": result["subject"],
        "scope": result["scope"], "logical_endpoint_id": result["logical_endpoint_id"], "source_roles": list(roles),
        "verifier_id": result["verifier_id"], "verifier_epoch": result["verifier_epoch"],
        "authorization_artifact_digest": result["authorization_artifact_digest"], "terms_artifact_digest": result["terms_artifact_digest"],
        "effective_start": start, "effective_end": end, "expected_cadence_seconds": result["expected_cadence_seconds"],
        "freshness_grace_seconds": result["freshness_grace_seconds"], "max_capture_bytes": max_capture,
        "max_page_count": max_pages, "canonical_order": result["canonical_order"],
        "completeness_rule": result["completeness_rule"], "evidence_mode": result["evidence_mode"],
    }


def _stale(policy: Mapping[str, object], capture: Mapping[str, object]) -> bool:
    observed = capture["observed_at"]
    fetched = capture["fetched_at"]
    if type(observed) is not int or type(fetched) is not int:
        raise IndependentExternalSourceError("external:time")
    if fetched < observed:
        raise IndependentExternalSourceError("external:chronology")
    return (
        observed < policy["effective_start"]
        or observed > policy["effective_end"]
        or fetched > observed + policy["expected_cadence_seconds"] + policy["freshness_grace_seconds"]
        or fetched > policy["effective_end"] + policy["freshness_grace_seconds"]
    )


def _derive_status(policy: Mapping[str, object], capture: Mapping[str, object]) -> str:
    failure = capture["failure_code"]
    stale = _stale(policy, capture)
    if failure == "AUTHORITY_UNQUALIFIED":
        if capture["transport_authenticated"] is not False:
            raise IndependentExternalSourceError("external:failure-binding")
        return "HOLD_AUTHORITY_UNQUALIFIED"
    if failure == "INCOMPLETE":
        if capture["complete"] is not False:
            raise IndependentExternalSourceError("external:failure-binding")
        return "HOLD_INCOMPLETE"
    if failure == "STALE":
        if not stale:
            raise IndependentExternalSourceError("external:failure-binding")
        return "HOLD_STALE"
    if failure == "SOURCE_FAILURE":
        return "HOLD_SOURCE_FAILURE"
    if not capture["transport_authenticated"]:
        return "HOLD_AUTHORITY_UNQUALIFIED"
    if not capture["complete"]:
        return "HOLD_INCOMPLETE"
    if stale:
        return "HOLD_STALE"
    return "OBSERVATION_ADMITTED"


def _validate_capture(capture: object, policy: Mapping[str, object], policy_digest: str) -> dict[str, object]:
    if not isinstance(capture, dict) or set(capture) != CAPTURE_KEYS:
        raise IndependentExternalSourceError("external:capture-keys")
    capture_id = _hex(capture["capture_id"], "capture-id")
    if capture["policy_digest"] != policy_digest:
        raise IndependentExternalSourceError("external:capture-policy")
    if capture["verifier_id"] != policy["verifier_id"] or capture["verifier_epoch"] != policy["verifier_epoch"]:
        raise IndependentExternalSourceError("external:capture-verifier")
    payload = _hex(capture["payload_sha3_512"], "payload-digest")
    if capture_id != capture_id_for_payload(payload):
        raise IndependentExternalSourceError("external:capture-id")
    _integer(capture["byte_length"], "byte-length", minimum=1, maximum=policy["max_capture_bytes"])
    _integer(capture["observed_at"], "observed-at")
    _integer(capture["fetched_at"], "fetched-at")
    pages = capture["page_digests"]
    if not isinstance(pages, list) or not 1 <= len(pages) <= policy["max_page_count"] or any(not isinstance(item, str) or HEX128.fullmatch(item) is None for item in pages):
        raise IndependentExternalSourceError("external:pages")
    if len(set(pages)) != len(pages) or pages != sorted(pages) or capture["page_count"] != len(pages):
        raise IndependentExternalSourceError("external:page-order")
    server_digest = _hex(capture["server_identity_digest"], "server-digest")
    if server_digest != _expected_server_identity(policy):
        raise IndependentExternalSourceError("external:server-binding")
    for field in ("transport_authenticated", "complete", "zero_phi"):
        if type(capture[field]) is not bool:
            raise IndependentExternalSourceError(f"external:{field}")
    if capture["zero_phi"] is not True:
        raise IndependentExternalSourceError("external:zero-phi")
    if capture["failure_code"] not in FAILURE_CODES:
        raise IndependentExternalSourceError("external:failure-code")
    transport_digest = _hex(capture["transport_receipt_digest"], "transport-digest")
    if transport_digest != _expected_transport_receipt(policy, capture, server_digest):
        raise IndependentExternalSourceError("external:transport-binding")
    return capture


def _identity_body(value: Mapping[str, object]) -> dict[str, object]:
    return {key: value[key] for key in value if key != "artifact_id"}


def verify_artifact(
    raw: bytes,
    *,
    policy: Mapping[str, object],
    capture_raw: bytes | None = None,
) -> dict[str, object]:
    value = _parse(raw)
    if set(value) != TOP_KEYS:
        raise IndependentExternalSourceError("external:artifact-keys")
    if value["artifact_kind"] != ARTIFACT_KIND or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IndependentExternalSourceError("external:schema")
    configured_policy = _policy_material(policy)
    policy_digest = _digest("policy", configured_policy)
    if value["policy"] != configured_policy or value["policy_digest"] != policy_digest:
        raise IndependentExternalSourceError("external:policy-binding")
    capture = _validate_capture(value["capture"], configured_policy, policy_digest)
    if value["owners"] != OWNERS or value["nonclaims"] != NONCLAIMS or value["flags"] != FIXED_FLAGS:
        raise IndependentExternalSourceError("external:authority-flags")
    expected_status = _derive_status(configured_policy, capture)
    if value["derived_status"] != expected_status or expected_status not in STATUSES:
        raise IndependentExternalSourceError("external:status")
    artifact_id = _hex(value["artifact_id"], "artifact-id")
    if artifact_id != _digest("artifact-id", _identity_body(value)):
        raise IndependentExternalSourceError("external:artifact-id")
    if capture_raw is not None:
        if type(capture_raw) is not bytes or len(capture_raw) != capture["byte_length"]:
            raise IndependentExternalSourceError("external:capture-recheck")
        payload = _raw_digest(capture_raw)
        if payload != capture["payload_sha3_512"] or capture["capture_id"] != capture_id_for_payload(payload):
            raise IndependentExternalSourceError("external:payload-rebound")
    return {
        "accepted": True,
        "artifact_kind": ARTIFACT_KIND,
        "artifact_id": artifact_id,
        "policy_digest": policy_digest,
        "profile_id": configured_policy["profile_id"],
        "profile_version": configured_policy["version"],
        "capture_id": capture["capture_id"],
        "payload_sha3_512": capture["payload_sha3_512"],
        "derived_status": expected_status,
        "external_authorization_qualified": False,
        "production_usable": False,
        "activation": False,
    }


def verify_retry(
    prior_raw: bytes,
    candidate_raw: bytes,
    *,
    policy: Mapping[str, object],
) -> dict[str, object]:
    prior = verify_artifact(prior_raw, policy=policy)
    candidate = verify_artifact(candidate_raw, policy=policy)
    if prior["capture_id"] == candidate["capture_id"] and prior_raw != candidate_raw:
        raise IndependentExternalSourceError("external:capture-id-conflict")
    return candidate


def inspect_artifact(raw: bytes, *, policy: Mapping[str, object]) -> dict[str, object]:
    return verify_artifact(raw, policy=policy)


def verify_bytes(raw: bytes, *, policy: Mapping[str, object], capture_raw: bytes | None = None) -> dict[str, object]:
    return verify_artifact(raw, policy=policy, capture_raw=capture_raw)


__all__ = [
    "ARTIFACT_KIND", "SCHEMA", "SCHEMA_VERSION", "EVIDENCE_MODE", "CANONICAL_ORDER", "COMPLETENESS_RULE",
    "MAX_ARTIFACT_BYTES", "MAX_CAPTURE_BYTES", "MAX_PAGE_COUNT", "FAILURE_CODES", "STATUSES", "POLICY_KEYS",
    "CAPTURE_KEYS", "TOP_KEYS", "OWNERS", "NONCLAIMS", "FIXED_FLAGS", "IndependentExternalSourceError",
    "capture_id_for_payload", "verify_artifact", "verify_retry", "inspect_artifact", "verify_bytes",
]
