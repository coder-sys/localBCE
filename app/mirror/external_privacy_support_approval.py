"""Composition boundary for privacy/support assertion evidence.

The policy and injected verifier own all authority-facing bindings.  This
module snapshots opaque evidence and emits only a bounded observation artifact;
it never approves, promotes, or mutates quarantine or downstream Mirror state.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Protocol

from app.mirror.error_boundary import raise_redacted


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
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

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


class ExternalPrivacySupportApprovalError(ValueError):
    """A bounded policy, verifier, or artifact-binding rejection."""


class ExternalPrivacySupportApprovalVerifier(Protocol):
    """The only future privacy/support authority and authentication seam."""

    verifier_id: str
    verifier_epoch: int
    privacy_authority_evidence_digest: str
    support_authority_evidence_digest: str
    revocation_head_digest: str

    def verify(self, evidence_raw: bytes) -> "VerifiedPrivacySupportAssertionV1": ...


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
        raise_redacted(ExternalPrivacySupportApprovalError, "privacy-support:noncanonical")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise ExternalPrivacySupportApprovalError(f"privacy-support:{label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ExternalPrivacySupportApprovalError(f"privacy-support:{label}")
    lowered = value.lower()
    forbidden = (
        "http://", "https://", "bearer", "cookie", "token=", "password",
        "secret", "credential", "header", "patient", "member", "claim",
        "ssn", "mrn", "npi", "email", "phone", "address", "person",
        "organization", "case", "record",
    )
    if any(marker in lowered for marker in forbidden):
        raise ExternalPrivacySupportApprovalError(f"privacy-support:{label}-forbidden")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = MAX_TIME) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ExternalPrivacySupportApprovalError(f"privacy-support:{label}")
    return value


def _validate_boolean_pairs(value: object, expected: tuple[str, ...], label: str) -> None:
    if type(value) is not tuple or len(value) != len(expected):
        raise ExternalPrivacySupportApprovalError(f"privacy-support:{label}-shape")
    keys: list[str] = []
    for item in value:
        if type(item) is not tuple or len(item) != 2 or not isinstance(item[0], str) or type(item[1]) is not bool:
            raise ExternalPrivacySupportApprovalError(f"privacy-support:{label}-type")
        keys.append(item[0])
    if tuple(keys) != expected:
        raise ExternalPrivacySupportApprovalError(f"privacy-support:{label}-keys")


def _policy_material(policy: "ExternalPrivacySupportPolicyV1") -> dict[str, object]:
    return {
        "source_policy_digest": policy.source_policy_digest,
        "quarantine_policy_digest": policy.quarantine_policy_digest,
        "quarantine_artifact_id": policy.quarantine_artifact_id,
        "quarantine_head_artifact_id": policy.quarantine_head_artifact_id,
        "quarantine_head_root": policy.quarantine_head_root,
        "governance_observation_artifact_id": policy.governance_observation_artifact_id,
        "governance_evidence_digest": policy.governance_evidence_digest,
        "governance_decision": policy.governance_decision,
        "terms_digest": policy.terms_digest,
        "retention_policy_digest": policy.retention_policy_digest,
        "verifier_id": policy.verifier_id,
        "verifier_epoch": policy.verifier_epoch,
        "scope": policy.scope,
        "effective_start": policy.effective_start,
        "effective_end": policy.effective_end,
        "max_evidence_bytes": policy.max_evidence_bytes,
        "required_zero_phi": policy.required_zero_phi,
        "state_owned_control": policy.state_owned_control,
        "privacy_authority_evidence_digest": policy.privacy_authority_evidence_digest,
        "support_authority_evidence_digest": policy.support_authority_evidence_digest,
        "revocation_head_digest": policy.revocation_head_digest,
    }


def _validate_policy(policy: "ExternalPrivacySupportPolicyV1") -> None:
    if not isinstance(policy, ExternalPrivacySupportPolicyV1):
        raise ExternalPrivacySupportApprovalError("privacy-support:policy-type")
    for label, value in (
        ("source-policy-digest", policy.source_policy_digest),
        ("quarantine-policy-digest", policy.quarantine_policy_digest),
        ("quarantine-artifact-id", policy.quarantine_artifact_id),
        ("quarantine-head-artifact-id", policy.quarantine_head_artifact_id),
        ("quarantine-head-root", policy.quarantine_head_root),
        ("governance-observation-artifact-id", policy.governance_observation_artifact_id),
        ("governance-evidence-digest", policy.governance_evidence_digest),
        ("terms-digest", policy.terms_digest),
        ("retention-policy-digest", policy.retention_policy_digest),
        ("privacy-authority-evidence-digest", policy.privacy_authority_evidence_digest),
        ("support-authority-evidence-digest", policy.support_authority_evidence_digest),
        ("revocation-head-digest", policy.revocation_head_digest),
    ):
        _hex(value, label)
    if policy.governance_decision not in DECISIONS:
        raise ExternalPrivacySupportApprovalError("privacy-support:governance-decision")
    _text(policy.verifier_id, "verifier-id")
    _integer(policy.verifier_epoch, "verifier-epoch", maximum=1_000_000)
    if policy.scope != SCOPE:
        raise ExternalPrivacySupportApprovalError("privacy-support:scope")
    _integer(policy.effective_start, "effective-start")
    _integer(policy.effective_end, "effective-end")
    if policy.effective_end <= policy.effective_start:
        raise ExternalPrivacySupportApprovalError("privacy-support:effective-interval")
    _integer(policy.max_evidence_bytes, "evidence-cap", minimum=1, maximum=MAX_EVIDENCE_BYTES)
    if type(policy.required_zero_phi) is not bool or policy.required_zero_phi is not True:
        raise ExternalPrivacySupportApprovalError("privacy-support:zero-phi-policy")
    if type(policy.state_owned_control) is not bool or policy.state_owned_control is not True:
        raise ExternalPrivacySupportApprovalError("privacy-support:state-owned-policy")


@dataclass(frozen=True)
class ExternalPrivacySupportPolicyV1:
    source_policy_digest: str
    quarantine_policy_digest: str
    quarantine_artifact_id: str
    quarantine_head_artifact_id: str
    quarantine_head_root: str
    governance_observation_artifact_id: str
    governance_evidence_digest: str
    governance_decision: str
    terms_digest: str
    retention_policy_digest: str
    verifier_id: str
    verifier_epoch: int
    scope: str
    effective_start: int
    effective_end: int
    max_evidence_bytes: int
    required_zero_phi: bool = True
    state_owned_control: bool = True
    privacy_authority_evidence_digest: str = ""
    support_authority_evidence_digest: str = ""
    revocation_head_digest: str = ""

    def __post_init__(self) -> None:
        _validate_policy(self)

    @property
    def digest(self) -> str:
        return _digest("policy", _policy_material(self))

    def material(self) -> dict[str, object]:
        return _policy_material(self)


def _map_material(value: tuple[tuple[str, bool], ...]) -> dict[str, bool]:
    return {key: state for key, state in value}


def _assertion_material(result: "VerifiedPrivacySupportAssertionV1") -> dict[str, object]:
    return {
        "policy_digest": result.policy_digest,
        "assertion_id": result.assertion_id,
        "evidence_sha3_512": result.evidence_sha3_512,
        "evidence_byte_length": result.evidence_byte_length,
        "quarantine_policy_digest": result.quarantine_policy_digest,
        "quarantine_artifact_id": result.quarantine_artifact_id,
        "quarantine_head_artifact_id": result.quarantine_head_artifact_id,
        "quarantine_head_root": result.quarantine_head_root,
        "governance_observation_artifact_id": result.governance_observation_artifact_id,
        "governance_evidence_digest": result.governance_evidence_digest,
        "governance_decision": result.governance_decision,
        "terms_digest": result.terms_digest,
        "retention_policy_digest": result.retention_policy_digest,
        "privacy_decision": result.privacy_decision,
        "support_decision": result.support_decision,
        "issued_at": result.issued_at,
        "valid_from": result.valid_from,
        "valid_until": result.valid_until,
        "observed_at": result.observed_at,
        "verifier_id": result.verifier_id,
        "verifier_epoch": result.verifier_epoch,
        "privacy_authority_evidence_digest": result.privacy_authority_evidence_digest,
        "support_authority_evidence_digest": result.support_authority_evidence_digest,
        "revocation_head_digest": result.revocation_head_digest,
        "coverage": _map_material(result.coverage),
        "support_controls": _map_material(result.support_controls),
        "zero_phi": result.zero_phi,
        "state_owned": result.state_owned,
    }


@dataclass(frozen=True)
class VerifiedPrivacySupportAssertionV1:
    policy_digest: str
    assertion_id: str
    evidence_sha3_512: str
    evidence_byte_length: int
    quarantine_policy_digest: str
    quarantine_artifact_id: str
    quarantine_head_artifact_id: str
    quarantine_head_root: str
    governance_observation_artifact_id: str
    governance_evidence_digest: str
    governance_decision: str
    terms_digest: str
    retention_policy_digest: str
    privacy_decision: str
    support_decision: str
    issued_at: int
    valid_from: int
    valid_until: int
    observed_at: int
    verifier_id: str
    verifier_epoch: int
    privacy_authority_evidence_digest: str
    support_authority_evidence_digest: str
    revocation_head_digest: str
    coverage: tuple[tuple[str, bool], ...]
    support_controls: tuple[tuple[str, bool], ...]
    zero_phi: bool
    state_owned: bool

    def __post_init__(self) -> None:
        for label, value in (
            ("policy-digest", self.policy_digest),
            ("evidence-digest", self.evidence_sha3_512),
            ("quarantine-policy-digest", self.quarantine_policy_digest),
            ("quarantine-artifact-id", self.quarantine_artifact_id),
            ("quarantine-head-artifact-id", self.quarantine_head_artifact_id),
            ("quarantine-head-root", self.quarantine_head_root),
            ("governance-observation-artifact-id", self.governance_observation_artifact_id),
            ("governance-evidence-digest", self.governance_evidence_digest),
            ("terms-digest", self.terms_digest),
            ("retention-policy-digest", self.retention_policy_digest),
            ("privacy-authority-evidence-digest", self.privacy_authority_evidence_digest),
            ("support-authority-evidence-digest", self.support_authority_evidence_digest),
            ("revocation-head-digest", self.revocation_head_digest),
        ):
            _hex(value, label)
        _integer(self.evidence_byte_length, "evidence-length", minimum=1, maximum=MAX_EVIDENCE_BYTES)
        _hex(self.assertion_id, "assertion-id")
        if self.governance_decision not in DECISIONS or self.privacy_decision not in DECISIONS or self.support_decision not in DECISIONS:
            raise ExternalPrivacySupportApprovalError("privacy-support:decision")
        _text(self.verifier_id, "verifier-id")
        _integer(self.verifier_epoch, "verifier-epoch", maximum=1_000_000)
        _validate_boolean_pairs(self.coverage, COVERAGE_KEYS, "coverage")
        _validate_boolean_pairs(self.support_controls, SUPPORT_CONTROL_KEYS, "support-controls")
        for label, value in (
            ("issued-at", self.issued_at),
            ("valid-from", self.valid_from),
            ("valid-until", self.valid_until),
            ("observed-at", self.observed_at),
        ):
            _integer(value, label)
        if self.valid_until <= self.valid_from or not (
            self.issued_at <= self.valid_from <= self.observed_at <= self.valid_until
        ):
            raise ExternalPrivacySupportApprovalError("privacy-support:chronology")
        if type(self.zero_phi) is not bool or type(self.state_owned) is not bool:
            raise ExternalPrivacySupportApprovalError("privacy-support:control-flags")


@dataclass(frozen=True)
class ExternalPrivacySupportApprovalArtifactV1:
    raw: bytes
    artifact_id: str
    privacy_decision: str
    support_decision: str
    status: str


def assertion_id_for_evidence(evidence_digest: str, byte_length: int) -> str:
    _hex(evidence_digest, "evidence-digest")
    _integer(byte_length, "evidence-length", minimum=1, maximum=MAX_EVIDENCE_BYTES)
    return _digest(
        "assertion-id",
        {"evidence_sha3_512": evidence_digest, "evidence_byte_length": byte_length},
    )


class ExternalPrivacySupportApprovalService:
    """One immutable policy plus one verifier-owned assertion port."""

    def __init__(self, policy: ExternalPrivacySupportPolicyV1, verifier: ExternalPrivacySupportApprovalVerifier) -> None:
        _validate_policy(policy)
        if verifier is None:
            raise ExternalPrivacySupportApprovalError("privacy-support:verifier-required")
        try:
            verifier_id = verifier.verifier_id
            verifier_epoch = verifier.verifier_epoch
            bindings = {
                "privacy_authority_evidence_digest": verifier.privacy_authority_evidence_digest,
                "support_authority_evidence_digest": verifier.support_authority_evidence_digest,
                "revocation_head_digest": verifier.revocation_head_digest,
            }
        except Exception:
            raise_redacted(ExternalPrivacySupportApprovalError, "privacy-support:verifier-config")
        if verifier_id != policy.verifier_id or verifier_epoch != policy.verifier_epoch:
            raise ExternalPrivacySupportApprovalError("privacy-support:verifier-config")
        _text(verifier_id, "verifier-id")
        _integer(verifier_epoch, "verifier-epoch", maximum=1_000_000)
        for label, value in bindings.items():
            if _hex(value, label.replace("_", "-")) != getattr(policy, label):
                raise ExternalPrivacySupportApprovalError("privacy-support:verifier-config")
        self.policy = policy
        self.verifier = verifier

    def observe(self, evidence_raw: bytes) -> ExternalPrivacySupportApprovalArtifactV1:
        if type(evidence_raw) is not bytes or not evidence_raw:
            raise ExternalPrivacySupportApprovalError("privacy-support:evidence-bytes")
        snapshot = bytes(evidence_raw)
        if len(snapshot) > self.policy.max_evidence_bytes:
            raise ExternalPrivacySupportApprovalError("privacy-support:evidence-byte-cap")
        try:
            result = self.verifier.verify(snapshot)
        except Exception:
            raise_redacted(ExternalPrivacySupportApprovalError, "privacy-support:verifier-failure")
        if type(result) is not VerifiedPrivacySupportAssertionV1:
            raise ExternalPrivacySupportApprovalError("privacy-support:verifier-result-type")
        if result.policy_digest != self.policy.digest:
            raise ExternalPrivacySupportApprovalError("privacy-support:policy-binding")
        if (
            result.quarantine_policy_digest != self.policy.quarantine_policy_digest
            or result.quarantine_artifact_id != self.policy.quarantine_artifact_id
            or result.quarantine_head_artifact_id != self.policy.quarantine_head_artifact_id
            or result.quarantine_head_root != self.policy.quarantine_head_root
            or result.governance_observation_artifact_id != self.policy.governance_observation_artifact_id
            or result.governance_evidence_digest != self.policy.governance_evidence_digest
            or result.governance_decision != self.policy.governance_decision
            or result.terms_digest != self.policy.terms_digest
            or result.retention_policy_digest != self.policy.retention_policy_digest
        ):
            raise ExternalPrivacySupportApprovalError("privacy-support:upstream-binding")
        if (
            result.verifier_id != self.policy.verifier_id
            or result.verifier_epoch != self.policy.verifier_epoch
            or result.privacy_authority_evidence_digest != self.policy.privacy_authority_evidence_digest
            or result.support_authority_evidence_digest != self.policy.support_authority_evidence_digest
            or result.revocation_head_digest != self.policy.revocation_head_digest
        ):
            raise ExternalPrivacySupportApprovalError("privacy-support:verifier-binding")
        if result.zero_phi is not True or result.state_owned is not True:
            raise ExternalPrivacySupportApprovalError("privacy-support:control-flags")
        if result.privacy_decision == "GRANTED" and not all(state for _, state in result.coverage):
            raise ExternalPrivacySupportApprovalError("privacy-support:coverage-incomplete")
        if result.support_decision == "GRANTED" and not all(state for _, state in result.support_controls):
            raise ExternalPrivacySupportApprovalError("privacy-support:controls-incomplete")
        digest = _raw_digest(snapshot)
        if result.evidence_sha3_512 != digest or result.evidence_byte_length != len(snapshot):
            raise ExternalPrivacySupportApprovalError("privacy-support:evidence-binding")
        if result.assertion_id != assertion_id_for_evidence(digest, len(snapshot)):
            raise ExternalPrivacySupportApprovalError("privacy-support:assertion-binding")
        if not (
            self.policy.effective_start <= result.issued_at <= result.valid_from
            <= result.observed_at <= result.valid_until <= self.policy.effective_end
        ):
            raise ExternalPrivacySupportApprovalError("privacy-support:policy-chronology")
        body: dict[str, object] = {
            "artifact_kind": ARTIFACT_KIND,
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "policy": self.policy.material(),
            "policy_digest": self.policy.digest,
            "assertion": _assertion_material(result),
            "derived_status": STATUS,
            "owners": dict(OWNERS),
            "nonclaims": list(NONCLAIMS),
            "flags": dict(FIXED_FLAGS),
        }
        value = {**body, "artifact_id": _digest("artifact-id", body)}
        raw = _canonical(value)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ExternalPrivacySupportApprovalError("privacy-support:artifact-byte-cap")
        return ExternalPrivacySupportApprovalArtifactV1(
            raw=raw,
            artifact_id=value["artifact_id"],
            privacy_decision=result.privacy_decision,
            support_decision=result.support_decision,
            status=STATUS,
        )


def observe_privacy_support_assertion(
    policy: ExternalPrivacySupportPolicyV1,
    verifier: ExternalPrivacySupportApprovalVerifier,
    evidence_raw: bytes,
) -> ExternalPrivacySupportApprovalArtifactV1:
    return ExternalPrivacySupportApprovalService(policy, verifier).observe(evidence_raw)


__all__ = [
    "ARTIFACT_KIND", "SCHEMA", "SCHEMA_VERSION", "SCOPE", "STATUS", "DECISIONS",
    "COVERAGE_KEYS", "SUPPORT_CONTROL_KEYS", "MAX_EVIDENCE_BYTES", "MAX_ARTIFACT_BYTES",
    "OWNERS", "NONCLAIMS", "FIXED_FLAGS", "ExternalPrivacySupportApprovalError",
    "ExternalPrivacySupportApprovalVerifier", "ExternalPrivacySupportPolicyV1",
    "VerifiedPrivacySupportAssertionV1", "ExternalPrivacySupportApprovalArtifactV1",
    "ExternalPrivacySupportApprovalService", "assertion_id_for_evidence",
    "observe_privacy_support_assertion",
]
