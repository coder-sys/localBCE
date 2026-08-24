"""Independent V2 verifier for the raw-free external-source evidence artifact.

This module intentionally has no import from the producer/composition module.
It independently parses the bounded artifact, reconstructs policy and capture
identities, and optionally rebinds the artifact to exact capture bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from app.mirror.error_boundary import raise_redacted


ARTIFACT_KIND = "MIRROR_EXTERNAL_SOURCE_EVIDENCE_V2"
SCHEMA = "mirror-external-source-evidence-v2"
SCHEMA_VERSION = 2
DOMAIN = "BL/MIRROR/EXTERNAL_SOURCE_ADAPTER/"
EVIDENCE_MODE = "SOFTWARE_CONTRACT_TEST_ONLY"
TRANSPORT_EVIDENCE_CLASSIFICATION = "SYNTHETIC_FIXTURE_UNAUTHENTICATED"
CANONICAL_ORDER = "PAGE_INDEX_ORDERED"
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
    "OBSERVATION_ADMITTED", "HOLD_AUTHORITY_UNQUALIFIED", "HOLD_INCOMPLETE",
    "HOLD_STALE", "HOLD_SOURCE_FAILURE",
)
OWNERS = {
    "policy": "STATE_CONFIGURED_SOURCE_CONTRACT",
    "capture_verifier": "CONFIGURED_EXTERNAL_CAPTURE_VERIFIER",
    "artifact": "MIRROR_EXTERNAL_SOURCE_ADAPTER",
}
NONCLAIMS = [
    "transport_provenance_is_not_source_truth", "external_authorization_and_legal_terms",
    "completeness_or_nonmembership", "production_source_authentication",
    "controlled_shadow_or_production_readiness", "payment_clearance_settlement_or_activation",
]
FIXED_FLAGS = {
    "read_only": True, "zero_phi": True, "state_owned": True,
    "external_authorization_qualified": False, "controlled_shadow_ready": False,
    "production_source_authentication": False, "production_usable": False,
    "activation": False, "payment_authority": False, "clearance_authority": False,
    "settlement_authority": False, "adjudication_authority": False, "proofSuiteId": None,
}
POLICY_KEYS = {
    "source_contract_digest", "capture_schema", "capture_schema_version", "logical_endpoint_id",
    "source_roles", "verifier_id", "verifier_epoch", "authorization_artifact_digest",
    "terms_artifact_digest", "effective_start", "effective_end", "expected_cadence_seconds",
    "freshness_grace_seconds", "max_capture_bytes", "max_page_count", "canonical_order",
    "completeness_rule", "evidence_mode",
}
CAPTURE_KEYS = {
    "capture_id", "policy_digest", "verifier_id", "verifier_epoch", "payload_sha3_512",
    "byte_length", "subject_id", "credential_id", "enrollment_id", "subject_locator_digest",
    "observed_at", "fetched_at", "page_bindings", "page_count", "server_identity_digest",
    "transport_receipt_digest", "transport_authenticated", "complete", "failure_code", "zero_phi",
    "transport_evidence_classification",
}
TOP_KEYS = {"artifact_kind", "schema", "schema_version", "policy", "policy_digest", "capture", "derived_status", "artifact_id", "owners", "nonclaims", "flags"}


class IndependentExternalSourceError(ValueError):
    """Fixed-code independent external artifact failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(IndependentExternalSourceError, "external:noncanonical")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def capture_id_for_payload(payload_sha3_512: str) -> str:
    if not isinstance(payload_sha3_512, str) or HEX128.fullmatch(payload_sha3_512) is None:
        raise IndependentExternalSourceError("external:payload-digest")
    return _digest("capture-id", payload_sha3_512)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise IndependentExternalSourceError("external:duplicate-key")
        value[key] = item
    return value


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES:
        raise IndependentExternalSourceError("external:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentExternalSourceError("external:depth-cap")
    if isinstance(value, float):
        raise IndependentExternalSourceError("external:float")
    if isinstance(value, str) and len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise IndependentExternalSourceError("external:string-cap")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentExternalSourceError("external:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentExternalSourceError("external:artifact-byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentExternalSourceError("external:constant")))
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
        raise IndependentExternalSourceError("external:" + label)
    lowered = value.lower()
    forbidden = ("http://", "https://", "bearer", "cookie", "token=", "password", "secret", "credential", "header", "patient_id", "member_id", "claim_id", "ssn", "mrn", "npi", "email", "phone", "address")
    if any(marker in lowered for marker in forbidden):
        raise IndependentExternalSourceError("external:" + label + "-forbidden")
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentExternalSourceError("external:" + label)
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = 10**12) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentExternalSourceError("external:" + label)
    return value


def _policy_material(policy: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(policy, Mapping) or set(policy) != POLICY_KEYS:
        raise IndependentExternalSourceError("external:policy-keys")
    source_roles = policy["source_roles"]
    if not isinstance(source_roles, list) or not 1 <= len(source_roles) <= 32 or any(type(item) is not str for item in source_roles) or len(set(source_roles)) != len(source_roles):
        raise IndependentExternalSourceError("external:source-roles")
    _hex(policy["source_contract_digest"], "source-contract-digest")
    _text(policy["capture_schema"], "capture-schema")
    _integer(policy["capture_schema_version"], "capture-schema-version", minimum=1, maximum=1_000_000)
    _text(policy["logical_endpoint_id"], "endpoint")
    for role in source_roles:
        _text(role, "source-role")
    _text(policy["verifier_id"], "verifier-id")
    _integer(policy["verifier_epoch"], "verifier-epoch", maximum=1_000_000)
    _hex(policy["authorization_artifact_digest"], "authorization-digest")
    _hex(policy["terms_artifact_digest"], "terms-digest")
    start = _integer(policy["effective_start"], "effective-start")
    end = _integer(policy["effective_end"], "effective-end")
    if end <= start:
        raise IndependentExternalSourceError("external:effective-interval")
    _integer(policy["expected_cadence_seconds"], "cadence", minimum=1, maximum=31_536_000)
    _integer(policy["freshness_grace_seconds"], "freshness-grace", maximum=31_536_000)
    max_capture = _integer(policy["max_capture_bytes"], "capture-cap", minimum=1, maximum=MAX_CAPTURE_BYTES)
    max_pages = _integer(policy["max_page_count"], "page-cap", minimum=1, maximum=MAX_PAGE_COUNT)
    if policy["canonical_order"] != CANONICAL_ORDER or policy["completeness_rule"] != COMPLETENESS_RULE or policy["evidence_mode"] != EVIDENCE_MODE:
        raise IndependentExternalSourceError("external:policy-contract")
    return {
        "source_contract_digest": policy["source_contract_digest"], "capture_schema": policy["capture_schema"],
        "capture_schema_version": policy["capture_schema_version"], "logical_endpoint_id": policy["logical_endpoint_id"],
        "source_roles": list(source_roles), "verifier_id": policy["verifier_id"], "verifier_epoch": policy["verifier_epoch"],
        "authorization_artifact_digest": policy["authorization_artifact_digest"], "terms_artifact_digest": policy["terms_artifact_digest"],
        "effective_start": start, "effective_end": end, "expected_cadence_seconds": policy["expected_cadence_seconds"],
        "freshness_grace_seconds": policy["freshness_grace_seconds"], "max_capture_bytes": max_capture,
        "max_page_count": max_pages, "canonical_order": policy["canonical_order"],
        "completeness_rule": policy["completeness_rule"], "evidence_mode": policy["evidence_mode"],
    }


def policy_digest(policy: Mapping[str, object]) -> str:
    return _digest("policy", _policy_material(policy))


def _expected_server_identity(policy: Mapping[str, object]) -> str:
    return _digest("server-identity", policy["logical_endpoint_id"])


def _expected_transport_receipt(policy: Mapping[str, object], capture: Mapping[str, object], server_identity_digest: str) -> str:
    return _digest("transport-receipt", {
        "policy_digest": capture["policy_digest"], "verifier_id": capture["verifier_id"],
        "verifier_epoch": capture["verifier_epoch"], "payload_sha3_512": capture["payload_sha3_512"],
        "page_bindings": capture["page_bindings"], "server_identity_digest": server_identity_digest,
        "observed_at": capture["observed_at"], "fetched_at": capture["fetched_at"],
        "transport_authenticated": capture["transport_authenticated"], "complete": capture["complete"],
        "failure_code": capture["failure_code"],
        "transport_evidence_classification": capture["transport_evidence_classification"],
    })


def _stale(policy: Mapping[str, object], capture: Mapping[str, object]) -> bool:
    observed = _integer(capture["observed_at"], "observed-at")
    fetched = _integer(capture["fetched_at"], "fetched-at")
    if fetched < observed:
        raise IndependentExternalSourceError("external:chronology")
    return observed < policy["effective_start"] or observed > policy["effective_end"] or fetched > observed + policy["expected_cadence_seconds"] + policy["freshness_grace_seconds"] or fetched > policy["effective_end"] + policy["freshness_grace_seconds"]


def _derive_status(policy: Mapping[str, object], capture: Mapping[str, object]) -> str:
    stale = _stale(policy, capture)
    failure = capture["failure_code"]
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
    if capture["transport_authenticated"] is not True and capture["transport_evidence_classification"] != TRANSPORT_EVIDENCE_CLASSIFICATION:
        return "HOLD_AUTHORITY_UNQUALIFIED"
    if capture["complete"] is not True:
        return "HOLD_INCOMPLETE"
    if stale:
        return "HOLD_STALE"
    return "OBSERVATION_ADMITTED"


def _validate_capture(capture: object, policy: Mapping[str, object], expected_policy_digest: str) -> dict[str, object]:
    if not isinstance(capture, dict) or set(capture) != CAPTURE_KEYS:
        raise IndependentExternalSourceError("external:capture-keys")
    capture_id = _hex(capture["capture_id"], "capture-id")
    if capture["policy_digest"] != expected_policy_digest:
        raise IndependentExternalSourceError("external:capture-policy")
    if capture["verifier_id"] != policy["verifier_id"] or capture["verifier_epoch"] != policy["verifier_epoch"]:
        raise IndependentExternalSourceError("external:capture-verifier")
    payload = _hex(capture["payload_sha3_512"], "payload-digest")
    if capture_id != capture_id_for_payload(payload):
        raise IndependentExternalSourceError("external:capture-id")
    _integer(capture["byte_length"], "byte-length", minimum=1, maximum=policy["max_capture_bytes"])
    for label in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest"):
        _hex(capture[label], "capture-" + label)
    observed = _integer(capture["observed_at"], "observed-at")
    fetched = _integer(capture["fetched_at"], "fetched-at")
    if fetched < observed:
        raise IndependentExternalSourceError("external:chronology")
    bindings = capture["page_bindings"]
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= policy["max_page_count"]:
        raise IndependentExternalSourceError("external:pages")
    expected = []
    for index, item in enumerate(bindings):
        if not isinstance(item, list) or len(item) != 2 or item[0] != index:
            raise IndependentExternalSourceError("external:page-order")
        expected.append([index, _hex(item[1], "page-digest")])
    if capture["page_count"] != len(expected):
        raise IndependentExternalSourceError("external:page-count")
    server = _hex(capture["server_identity_digest"], "server-digest")
    if server != _expected_server_identity(policy):
        raise IndependentExternalSourceError("external:server-binding")
    for field in ("transport_authenticated", "complete", "zero_phi"):
        if type(capture[field]) is not bool:
            raise IndependentExternalSourceError("external:" + field)
    if capture["zero_phi"] is not True or capture["failure_code"] not in FAILURE_CODES or capture["transport_evidence_classification"] != TRANSPORT_EVIDENCE_CLASSIFICATION:
        raise IndependentExternalSourceError("external:capture-contract")
    transport = _hex(capture["transport_receipt_digest"], "transport-digest")
    if transport != _expected_transport_receipt(policy, capture, server):
        raise IndependentExternalSourceError("external:transport-binding")
    return capture


def _identity_body(value: Mapping[str, object]) -> dict[str, object]:
    return {key: value[key] for key in value if key != "artifact_id"}


def verify_artifact(raw: bytes, *, policy: Mapping[str, object], capture_raw: bytes | None = None) -> dict[str, object]:
    value = _parse(raw)
    if set(value) != TOP_KEYS or value["artifact_kind"] != ARTIFACT_KIND or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IndependentExternalSourceError("external:schema")
    configured = _policy_material(policy)
    expected_policy_digest = _digest("policy", configured)
    if value["policy"] != configured or value["policy_digest"] != expected_policy_digest:
        raise IndependentExternalSourceError("external:policy-binding")
    capture = _validate_capture(value["capture"], configured, expected_policy_digest)
    if value["owners"] != OWNERS or value["nonclaims"] != NONCLAIMS or value["flags"] != FIXED_FLAGS:
        raise IndependentExternalSourceError("external:authority-flags")
    expected_status = _derive_status(configured, capture)
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
        "accepted": True, "artifact_kind": ARTIFACT_KIND, "artifact_id": artifact_id,
        "policy_digest": expected_policy_digest, "source_contract_digest": configured["source_contract_digest"],
        "capture_id": capture["capture_id"], "payload_sha3_512": capture["payload_sha3_512"],
        "subject_id": capture["subject_id"], "credential_id": capture["credential_id"],
        "enrollment_id": capture["enrollment_id"], "subject_locator_digest": capture["subject_locator_digest"],
        "observed_at": capture["observed_at"], "fetched_at": capture["fetched_at"],
        "page_bindings": tuple((item[0], item[1]) for item in capture["page_bindings"]),
        "page_count": capture["page_count"], "server_identity_digest": capture["server_identity_digest"],
        "transport_receipt_digest": capture["transport_receipt_digest"],
        "transport_authenticated": capture["transport_authenticated"], "complete": capture["complete"],
        "failure_code": capture["failure_code"], "transport_evidence_classification": capture["transport_evidence_classification"], "derived_status": expected_status,
        "external_authorization_qualified": False, "production_usable": False, "activation": False,
    }


def verify_retry(prior_raw: bytes, candidate_raw: bytes, *, policy: Mapping[str, object]) -> dict[str, object]:
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
    "TRANSPORT_EVIDENCE_CLASSIFICATION",
    "CAPTURE_KEYS", "TOP_KEYS", "OWNERS", "NONCLAIMS", "FIXED_FLAGS", "IndependentExternalSourceError",
    "capture_id_for_payload", "policy_digest", "verify_artifact", "verify_retry", "inspect_artifact", "verify_bytes",
]
