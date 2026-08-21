"""Composition boundary for bounded, transport-neutral external evidence.

The configured policy and verifier are the owners of source-contract metadata
and verification identity.  This module snapshots opaque bytes, checks the
typed verifier result against that configuration, and emits one nonproduction
artifact containing no raw capture bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping, Protocol


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


class ExternalSourceAdapterError(ValueError):
    """A bounded composition or verifier-binding rejection."""


class ExternalCaptureVerifier(Protocol):
    """Injected verifier port; no transport or authority implementation."""

    verifier_id: str
    verifier_epoch: int

    def verify(self, capture_raw: bytes) -> "VerifiedExternalCaptureV1": ...


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ExternalSourceAdapterError("external:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _capture_id_for_payload(payload_sha3_512: str) -> str:
    if not isinstance(payload_sha3_512, str) or HEX128.fullmatch(payload_sha3_512) is None:
        raise ExternalSourceAdapterError("external:payload-digest")
    return _digest("capture-id", payload_sha3_512)


def _expected_server_identity(policy: "ExternalSourcePolicyV1") -> str:
    return _digest("server-identity", policy.logical_endpoint_id)


def _expected_transport_receipt(policy: "ExternalSourcePolicyV1", result: "VerifiedExternalCaptureV1", server_identity_digest: str) -> str:
    return _digest(
        "transport-receipt",
        {
            "policy_digest": result.policy_digest,
            "verifier_id": result.verifier_id,
            "verifier_epoch": result.verifier_epoch,
            "payload_sha3_512": result.payload_sha3_512,
            "page_digests": list(result.page_digests),
            "server_identity_digest": server_identity_digest,
            "observed_at": result.observed_at,
            "fetched_at": result.fetched_at,
            "transport_authenticated": result.transport_authenticated,
            "complete": result.complete,
            "failure_code": result.failure_code,
        },
    )


def _safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or not SAFE_IDENTIFIER.fullmatch(value):
        raise ExternalSourceAdapterError(f"external:{label}")
    lowered = value.lower()
    forbidden = ("http://", "https://", "bearer", "cookie", "token=", "password", "secret", "credential", "header", "patient_id", "member_id", "claim_id", "ssn", "mrn", "npi", "email", "phone", "address")
    if any(marker in lowered for marker in forbidden):
        raise ExternalSourceAdapterError(f"external:{label}-forbidden")
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise ExternalSourceAdapterError(f"external:{label}")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = 10**12) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ExternalSourceAdapterError(f"external:{label}")
    return value


def _policy_material(policy: "ExternalSourcePolicyV1") -> dict[str, object]:
    return {
        "profile_id": policy.profile_id,
        "version": policy.version,
        "subject": policy.subject,
        "scope": policy.scope,
        "logical_endpoint_id": policy.logical_endpoint_id,
        "source_roles": list(policy.source_roles),
        "verifier_id": policy.verifier_id,
        "verifier_epoch": policy.verifier_epoch,
        "authorization_artifact_digest": policy.authorization_artifact_digest,
        "terms_artifact_digest": policy.terms_artifact_digest,
        "effective_start": policy.effective_start,
        "effective_end": policy.effective_end,
        "expected_cadence_seconds": policy.expected_cadence_seconds,
        "freshness_grace_seconds": policy.freshness_grace_seconds,
        "max_capture_bytes": policy.max_capture_bytes,
        "max_page_count": policy.max_page_count,
        "canonical_order": policy.canonical_order,
        "completeness_rule": policy.completeness_rule,
        "evidence_mode": policy.evidence_mode,
    }


def _validate_policy(policy: "ExternalSourcePolicyV1") -> None:
    if not isinstance(policy, ExternalSourcePolicyV1) or type(policy.source_roles) is not tuple or not 1 <= len(policy.source_roles) <= 32 or any(not isinstance(role, str) for role in policy.source_roles) or len(set(policy.source_roles)) != len(policy.source_roles):
        raise ExternalSourceAdapterError("external:policy-source-roles")
    for label, value in (("profile-id", policy.profile_id), ("subject", policy.subject), ("scope", policy.scope), ("endpoint", policy.logical_endpoint_id), ("verifier-id", policy.verifier_id)):
        _safe_text(value, label)
    _integer(policy.version, "policy-version", minimum=1, maximum=1_000_000)
    for role in policy.source_roles:
        _safe_text(role, "source-role")
    _integer(policy.verifier_epoch, "verifier-epoch", maximum=1_000_000)
    _hex(policy.authorization_artifact_digest, "authorization-digest")
    _hex(policy.terms_artifact_digest, "terms-digest")
    _integer(policy.effective_start, "effective-start")
    _integer(policy.effective_end, "effective-end")
    if policy.effective_end <= policy.effective_start:
        raise ExternalSourceAdapterError("external:effective-interval")
    _integer(policy.expected_cadence_seconds, "cadence", minimum=1, maximum=31_536_000)
    _integer(policy.freshness_grace_seconds, "freshness-grace", maximum=31_536_000)
    _integer(policy.max_capture_bytes, "capture-cap", minimum=1, maximum=MAX_CAPTURE_BYTES)
    _integer(policy.max_page_count, "page-cap", minimum=1, maximum=MAX_PAGE_COUNT)
    if policy.canonical_order != CANONICAL_ORDER or policy.completeness_rule != COMPLETENESS_RULE or policy.evidence_mode != EVIDENCE_MODE:
        raise ExternalSourceAdapterError("external:policy-contract")


@dataclass(frozen=True)
class ExternalSourcePolicyV1:
    profile_id: str
    version: int
    subject: str
    scope: str
    logical_endpoint_id: str
    source_roles: tuple[str, ...]
    verifier_id: str
    verifier_epoch: int
    authorization_artifact_digest: str
    terms_artifact_digest: str
    effective_start: int
    effective_end: int
    expected_cadence_seconds: int
    freshness_grace_seconds: int
    max_capture_bytes: int
    max_page_count: int
    canonical_order: str = CANONICAL_ORDER
    completeness_rule: str = COMPLETENESS_RULE
    evidence_mode: str = EVIDENCE_MODE

    def __post_init__(self) -> None:
        _validate_policy(self)

    @property
    def digest(self) -> str:
        return _digest("policy", _policy_material(self))

    def material(self) -> dict[str, object]:
        return _policy_material(self)


@dataclass(frozen=True)
class VerifiedExternalCaptureV1:
    policy_digest: str
    verifier_id: str
    verifier_epoch: int
    capture_id: str
    payload_sha3_512: str
    observed_at: int
    fetched_at: int
    page_digests: tuple[str, ...]
    page_count: int
    server_identity_digest: str
    transport_receipt_digest: str
    transport_authenticated: bool
    complete: bool
    failure_code: str
    zero_phi: bool

    def __post_init__(self) -> None:
        _hex(self.policy_digest, "policy-digest")
        _safe_text(self.verifier_id, "verifier-id")
        _integer(self.verifier_epoch, "verifier-epoch", maximum=1_000_000)
        _hex(self.capture_id, "capture-id")
        _hex(self.payload_sha3_512, "payload-digest")
        _integer(self.observed_at, "observed-at")
        _integer(self.fetched_at, "fetched-at")
        if self.fetched_at < self.observed_at:
            raise ExternalSourceAdapterError("external:chronology")
        if type(self.page_digests) is not tuple or not self.page_digests or any(not isinstance(digest, str) for digest in self.page_digests) or self.page_digests != tuple(sorted(self.page_digests)) or len(set(self.page_digests)) != len(self.page_digests):
            raise ExternalSourceAdapterError("external:page-order")
        for digest in self.page_digests:
            _hex(digest, "page-digest")
        _integer(self.page_count, "page-count", minimum=1, maximum=MAX_PAGE_COUNT)
        if self.page_count != len(self.page_digests):
            raise ExternalSourceAdapterError("external:page-count")
        _hex(self.server_identity_digest, "server-digest")
        _hex(self.transport_receipt_digest, "transport-digest")
        for field in (self.transport_authenticated, self.complete, self.zero_phi):
            if type(field) is not bool:
                raise ExternalSourceAdapterError("external:boolean")
        if self.zero_phi is not True:
            raise ExternalSourceAdapterError("external:zero-phi")
        if self.failure_code not in FAILURE_CODES:
            raise ExternalSourceAdapterError("external:failure-code")


@dataclass(frozen=True)
class ExternalSourceArtifactV1:
    raw: bytes
    artifact_id: str
    status: str
    capture_id: str


def _stale(policy: ExternalSourcePolicyV1, result: VerifiedExternalCaptureV1) -> bool:
    return (
        result.observed_at < policy.effective_start
        or result.observed_at > policy.effective_end
        or result.fetched_at > result.observed_at + policy.expected_cadence_seconds + policy.freshness_grace_seconds
        or result.fetched_at > policy.effective_end + policy.freshness_grace_seconds
    )


def _derive_status(policy: ExternalSourcePolicyV1, result: VerifiedExternalCaptureV1) -> str:
    stale = _stale(policy, result)
    if result.failure_code == "AUTHORITY_UNQUALIFIED":
        if result.transport_authenticated is not False:
            raise ExternalSourceAdapterError("external:failure-binding")
        return "HOLD_AUTHORITY_UNQUALIFIED"
    if result.failure_code == "INCOMPLETE":
        if result.complete is not False:
            raise ExternalSourceAdapterError("external:failure-binding")
        return "HOLD_INCOMPLETE"
    if result.failure_code == "STALE":
        if not stale:
            raise ExternalSourceAdapterError("external:failure-binding")
        return "HOLD_STALE"
    if result.failure_code == "SOURCE_FAILURE":
        return "HOLD_SOURCE_FAILURE"
    if not result.transport_authenticated:
        return "HOLD_AUTHORITY_UNQUALIFIED"
    if not result.complete:
        return "HOLD_INCOMPLETE"
    if stale:
        return "HOLD_STALE"
    return "OBSERVATION_ADMITTED"


def _capture_material(result: VerifiedExternalCaptureV1, byte_length: int) -> dict[str, object]:
    return {
        "capture_id": result.capture_id,
        "policy_digest": result.policy_digest,
        "verifier_id": result.verifier_id,
        "verifier_epoch": result.verifier_epoch,
        "payload_sha3_512": result.payload_sha3_512,
        "byte_length": byte_length,
        "observed_at": result.observed_at,
        "fetched_at": result.fetched_at,
        "page_digests": list(result.page_digests),
        "page_count": result.page_count,
        "server_identity_digest": result.server_identity_digest,
        "transport_receipt_digest": result.transport_receipt_digest,
        "transport_authenticated": result.transport_authenticated,
        "complete": result.complete,
        "failure_code": result.failure_code,
        "zero_phi": result.zero_phi,
    }


class ExternalSourceAdapterService:
    """Configured composition root for one immutable source policy."""

    def __init__(self, policy: ExternalSourcePolicyV1, verifier: ExternalCaptureVerifier) -> None:
        _validate_policy(policy)
        if verifier is None:
            raise ExternalSourceAdapterError("external:verifier-required")
        try:
            verifier_id = verifier.verifier_id
            verifier_epoch = verifier.verifier_epoch
        except AttributeError as exc:
            raise ExternalSourceAdapterError("external:verifier-config") from exc
        if verifier_id != policy.verifier_id or verifier_epoch != policy.verifier_epoch:
            raise ExternalSourceAdapterError("external:verifier-config")
        _safe_text(verifier_id, "verifier-id")
        _integer(verifier_epoch, "verifier-epoch", maximum=1_000_000)
        self.policy = policy
        self.verifier = verifier

    def admit(self, capture_raw: bytes) -> ExternalSourceArtifactV1:
        if type(capture_raw) is not bytes or not capture_raw:
            raise ExternalSourceAdapterError("external:capture-bytes")
        snapshot = bytes(capture_raw)
        if len(snapshot) > self.policy.max_capture_bytes:
            raise ExternalSourceAdapterError("external:capture-byte-cap")
        try:
            result = self.verifier.verify(snapshot)
        except Exception as exc:
            raise ExternalSourceAdapterError("external:verifier-failure") from exc
        if type(result) is not VerifiedExternalCaptureV1:
            raise ExternalSourceAdapterError("external:verifier-result-type")
        if result.policy_digest != self.policy.digest or result.verifier_id != self.policy.verifier_id or result.verifier_epoch != self.policy.verifier_epoch:
            raise ExternalSourceAdapterError("external:verifier-binding")
        payload_digest = _raw_digest(snapshot)
        if result.payload_sha3_512 != payload_digest:
            raise ExternalSourceAdapterError("external:payload-binding")
        expected_capture_id = _capture_id_for_payload(payload_digest)
        if result.capture_id != expected_capture_id:
            raise ExternalSourceAdapterError("external:capture-binding")
        if result.server_identity_digest != _expected_server_identity(self.policy):
            raise ExternalSourceAdapterError("external:server-binding")
        if result.transport_receipt_digest != _expected_transport_receipt(self.policy, result, result.server_identity_digest):
            raise ExternalSourceAdapterError("external:transport-binding")
        if result.page_count > self.policy.max_page_count:
            raise ExternalSourceAdapterError("external:page-cap")
        status = _derive_status(self.policy, result)
        body: dict[str, object] = {
            "artifact_kind": ARTIFACT_KIND,
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "policy": self.policy.material(),
            "policy_digest": self.policy.digest,
            "capture": _capture_material(result, len(snapshot)),
            "derived_status": status,
            "owners": dict(OWNERS),
            "nonclaims": list(NONCLAIMS),
            "flags": dict(FIXED_FLAGS),
        }
        artifact_id = _digest("artifact-id", body)
        value = {**body, "artifact_id": artifact_id}
        raw = _canonical(value)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ExternalSourceAdapterError("external:artifact-byte-cap")
        return ExternalSourceArtifactV1(raw=raw, artifact_id=artifact_id, status=status, capture_id=result.capture_id)


def build_artifact(policy: ExternalSourcePolicyV1, verifier: ExternalCaptureVerifier, capture_raw: bytes) -> ExternalSourceArtifactV1:
    return ExternalSourceAdapterService(policy, verifier).admit(capture_raw)


__all__ = [
    "ARTIFACT_KIND", "SCHEMA", "SCHEMA_VERSION", "EVIDENCE_MODE", "CANONICAL_ORDER", "COMPLETENESS_RULE",
    "MAX_ARTIFACT_BYTES", "MAX_CAPTURE_BYTES", "MAX_PAGE_COUNT", "FAILURE_CODES", "STATUSES", "OWNERS",
    "NONCLAIMS", "FIXED_FLAGS", "ExternalSourceAdapterError", "ExternalCaptureVerifier", "ExternalSourcePolicyV1",
    "VerifiedExternalCaptureV1", "ExternalSourceArtifactV1", "ExternalSourceAdapterService", "build_artifact",
]
