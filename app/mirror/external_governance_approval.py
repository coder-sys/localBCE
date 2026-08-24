"""Composition boundary for a non-authorizing governance assertion.

The policy and injected verifier own all authority-facing bindings.  This
module snapshots opaque evidence, checks the typed verifier result against
that immutable configuration, and emits a bounded observation artifact.  It
does not mutate quarantine or any downstream Mirror store.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Protocol

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
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

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


class ExternalGovernanceApprovalError(ValueError):
    """A bounded policy, verifier, or artifact-binding rejection."""


class ExternalGovernanceApprovalVerifier(Protocol):
    """The only future authority/authentication seam.

    Implementations are supplied by a state-controlled composition root.  No
    transport, signer, key registry, or fixture issuer is provided here.
    """

    verifier_id: str
    verifier_epoch: int
    authority_evidence_digest: str
    revocation_head_digest: str
    terms_digest: str
    retention_policy_digest: str

    def verify(self, evidence_raw: bytes) -> "VerifiedGovernanceAssertionV1": ...


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
        raise_redacted(ExternalGovernanceApprovalError, "governance:noncanonical")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise ExternalGovernanceApprovalError(f"governance:{label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ExternalGovernanceApprovalError(f"governance:{label}")
    lowered = value.lower()
    forbidden = (
        "http://", "https://", "bearer", "cookie", "token=", "password",
        "secret", "credential", "header", "patient", "member", "claim",
        "ssn", "mrn", "npi", "email", "phone", "address",
    )
    if any(marker in lowered for marker in forbidden):
        raise ExternalGovernanceApprovalError(f"governance:{label}-forbidden")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = MAX_TIME) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ExternalGovernanceApprovalError(f"governance:{label}")
    return value


def _policy_material(policy: "ExternalGovernanceApprovalPolicyV1") -> dict[str, object]:
    return {
        "source_policy_digest": policy.source_policy_digest,
        "quarantine_policy_digest": policy.quarantine_policy_digest,
        "quarantine_artifact_id": policy.quarantine_artifact_id,
        "quarantine_head_artifact_id": policy.quarantine_head_artifact_id,
        "quarantine_head_root": policy.quarantine_head_root,
        "verifier_id": policy.verifier_id,
        "verifier_epoch": policy.verifier_epoch,
        "scope": policy.scope,
        "effective_start": policy.effective_start,
        "effective_end": policy.effective_end,
        "max_evidence_bytes": policy.max_evidence_bytes,
        "required_zero_phi": policy.required_zero_phi,
        "state_owned_control": policy.state_owned_control,
        "authority_evidence_digest": policy.authority_evidence_digest,
        "revocation_head_digest": policy.revocation_head_digest,
        "terms_digest": policy.terms_digest,
        "retention_policy_digest": policy.retention_policy_digest,
    }


def _validate_policy(policy: "ExternalGovernanceApprovalPolicyV1") -> None:
    if not isinstance(policy, ExternalGovernanceApprovalPolicyV1):
        raise ExternalGovernanceApprovalError("governance:policy-type")
    for label, value in (
        ("source-policy-digest", policy.source_policy_digest),
        ("quarantine-policy-digest", policy.quarantine_policy_digest),
        ("quarantine-artifact-id", policy.quarantine_artifact_id),
        ("quarantine-head-artifact-id", policy.quarantine_head_artifact_id),
        ("quarantine-head-root", policy.quarantine_head_root),
        ("authority-evidence-digest", policy.authority_evidence_digest),
        ("revocation-head-digest", policy.revocation_head_digest),
        ("terms-digest", policy.terms_digest),
        ("retention-policy-digest", policy.retention_policy_digest),
    ):
        _hex(value, label)
    _text(policy.verifier_id, "verifier-id")
    _integer(policy.verifier_epoch, "verifier-epoch", maximum=1_000_000)
    if policy.scope != SCOPE:
        raise ExternalGovernanceApprovalError("governance:scope")
    _integer(policy.effective_start, "effective-start")
    _integer(policy.effective_end, "effective-end")
    if policy.effective_end <= policy.effective_start:
        raise ExternalGovernanceApprovalError("governance:effective-interval")
    _integer(policy.max_evidence_bytes, "evidence-cap", minimum=1, maximum=MAX_EVIDENCE_BYTES)
    if type(policy.required_zero_phi) is not bool or policy.required_zero_phi is not True:
        raise ExternalGovernanceApprovalError("governance:zero-phi-policy")
    if type(policy.state_owned_control) is not bool or policy.state_owned_control is not True:
        raise ExternalGovernanceApprovalError("governance:state-owned-policy")


@dataclass(frozen=True)
class ExternalGovernanceApprovalPolicyV1:
    source_policy_digest: str
    quarantine_policy_digest: str
    quarantine_artifact_id: str
    quarantine_head_artifact_id: str
    quarantine_head_root: str
    verifier_id: str
    verifier_epoch: int
    scope: str
    effective_start: int
    effective_end: int
    max_evidence_bytes: int
    required_zero_phi: bool = True
    state_owned_control: bool = True
    authority_evidence_digest: str = ""
    revocation_head_digest: str = ""
    terms_digest: str = ""
    retention_policy_digest: str = ""

    def __post_init__(self) -> None:
        _validate_policy(self)

    @property
    def digest(self) -> str:
        return _digest("policy", _policy_material(self))

    def material(self) -> dict[str, object]:
        return _policy_material(self)


def _assertion_material(result: "VerifiedGovernanceAssertionV1") -> dict[str, object]:
    return {
        "policy_digest": result.policy_digest,
        "approval_id": result.approval_id,
        "evidence_sha3_512": result.evidence_sha3_512,
        "evidence_byte_length": result.evidence_byte_length,
        "quarantine_policy_digest": result.quarantine_policy_digest,
        "quarantine_artifact_id": result.quarantine_artifact_id,
        "quarantine_head_artifact_id": result.quarantine_head_artifact_id,
        "quarantine_head_root": result.quarantine_head_root,
        "authority_evidence_digest": result.authority_evidence_digest,
        "revocation_head_digest": result.revocation_head_digest,
        "terms_digest": result.terms_digest,
        "retention_policy_digest": result.retention_policy_digest,
        "decision": result.decision,
        "issued_at": result.issued_at,
        "valid_from": result.valid_from,
        "valid_until": result.valid_until,
        "observed_at": result.observed_at,
        "verifier_id": result.verifier_id,
        "verifier_epoch": result.verifier_epoch,
        "zero_phi": result.zero_phi,
        "state_owned": result.state_owned,
    }


@dataclass(frozen=True)
class VerifiedGovernanceAssertionV1:
    policy_digest: str
    approval_id: str
    evidence_sha3_512: str
    evidence_byte_length: int
    quarantine_policy_digest: str
    quarantine_artifact_id: str
    quarantine_head_artifact_id: str
    quarantine_head_root: str
    authority_evidence_digest: str
    revocation_head_digest: str
    terms_digest: str
    retention_policy_digest: str
    decision: str
    issued_at: int
    valid_from: int
    valid_until: int
    observed_at: int
    verifier_id: str
    verifier_epoch: int
    zero_phi: bool
    state_owned: bool

    def __post_init__(self) -> None:
        for label, value in (
            ("policy-digest", self.policy_digest),
            ("approval-id", self.approval_id),
            ("evidence-digest", self.evidence_sha3_512),
            ("quarantine-policy-digest", self.quarantine_policy_digest),
            ("quarantine-artifact-id", self.quarantine_artifact_id),
            ("quarantine-head-artifact-id", self.quarantine_head_artifact_id),
            ("quarantine-head-root", self.quarantine_head_root),
            ("authority-evidence-digest", self.authority_evidence_digest),
            ("revocation-head-digest", self.revocation_head_digest),
            ("terms-digest", self.terms_digest),
            ("retention-policy-digest", self.retention_policy_digest),
        ):
            _hex(value, label)
        _integer(self.evidence_byte_length, "evidence-length", minimum=1, maximum=MAX_EVIDENCE_BYTES)
        _text(self.verifier_id, "verifier-id")
        _integer(self.verifier_epoch, "verifier-epoch", maximum=1_000_000)
        if self.decision not in DECISIONS:
            raise ExternalGovernanceApprovalError("governance:decision")
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
            raise ExternalGovernanceApprovalError("governance:chronology")
        if type(self.zero_phi) is not bool:
            raise ExternalGovernanceApprovalError("governance:zero-phi")
        if type(self.state_owned) is not bool:
            raise ExternalGovernanceApprovalError("governance:state-owned")


@dataclass(frozen=True)
class ExternalGovernanceApprovalArtifactV1:
    raw: bytes
    artifact_id: str
    decision: str
    status: str


def _approval_id_for_evidence(evidence_digest: str, byte_length: int) -> str:
    return _digest(
        "approval-id",
        {"evidence_sha3_512": evidence_digest, "evidence_byte_length": byte_length},
    )


class ExternalGovernanceApprovalService:
    """One immutable policy plus one verifier-owned assertion port."""

    def __init__(self, policy: ExternalGovernanceApprovalPolicyV1, verifier: ExternalGovernanceApprovalVerifier) -> None:
        _validate_policy(policy)
        if verifier is None:
            raise ExternalGovernanceApprovalError("governance:verifier-required")
        try:
            verifier_id = verifier.verifier_id
            verifier_epoch = verifier.verifier_epoch
            bindings = {
                "authority_evidence_digest": verifier.authority_evidence_digest,
                "revocation_head_digest": verifier.revocation_head_digest,
                "terms_digest": verifier.terms_digest,
                "retention_policy_digest": verifier.retention_policy_digest,
            }
        except Exception:
            raise_redacted(ExternalGovernanceApprovalError, "governance:verifier-config")
        if verifier_id != policy.verifier_id or verifier_epoch != policy.verifier_epoch:
            raise ExternalGovernanceApprovalError("governance:verifier-config")
        _text(verifier_id, "verifier-id")
        _integer(verifier_epoch, "verifier-epoch", maximum=1_000_000)
        for label, value in bindings.items():
            if _hex(value, label.replace("_", "-")) != getattr(policy, label):
                raise ExternalGovernanceApprovalError("governance:verifier-config")
        self.policy = policy
        self.verifier = verifier

    def observe(self, evidence_raw: bytes) -> ExternalGovernanceApprovalArtifactV1:
        if type(evidence_raw) is not bytes or not evidence_raw:
            raise ExternalGovernanceApprovalError("governance:evidence-bytes")
        snapshot = bytes(evidence_raw)
        if len(snapshot) > self.policy.max_evidence_bytes:
            raise ExternalGovernanceApprovalError("governance:evidence-byte-cap")
        try:
            result = self.verifier.verify(snapshot)
        except Exception:
            raise_redacted(ExternalGovernanceApprovalError, "governance:verifier-failure")
        if type(result) is not VerifiedGovernanceAssertionV1:
            raise ExternalGovernanceApprovalError("governance:verifier-result-type")
        if result.policy_digest != self.policy.digest:
            raise ExternalGovernanceApprovalError("governance:policy-binding")
        if (
            result.quarantine_policy_digest != self.policy.quarantine_policy_digest
            or result.quarantine_artifact_id != self.policy.quarantine_artifact_id
            or result.quarantine_head_artifact_id != self.policy.quarantine_head_artifact_id
            or result.quarantine_head_root != self.policy.quarantine_head_root
        ):
            raise ExternalGovernanceApprovalError("governance:quarantine-binding")
        if (
            result.verifier_id != self.policy.verifier_id
            or result.verifier_epoch != self.policy.verifier_epoch
            or result.authority_evidence_digest != self.policy.authority_evidence_digest
            or result.revocation_head_digest != self.policy.revocation_head_digest
            or result.terms_digest != self.policy.terms_digest
            or result.retention_policy_digest != self.policy.retention_policy_digest
        ):
            raise ExternalGovernanceApprovalError("governance:verifier-binding")
        if result.zero_phi is not True or result.state_owned is not True:
            raise ExternalGovernanceApprovalError("governance:control-flags")
        digest = _raw_digest(snapshot)
        if result.evidence_sha3_512 != digest or result.evidence_byte_length != len(snapshot):
            raise ExternalGovernanceApprovalError("governance:evidence-binding")
        if result.approval_id != _approval_id_for_evidence(digest, len(snapshot)):
            raise ExternalGovernanceApprovalError("governance:approval-binding")
        if not (
            self.policy.effective_start <= result.issued_at <= result.valid_from
            <= result.observed_at <= result.valid_until <= self.policy.effective_end
        ):
            raise ExternalGovernanceApprovalError("governance:policy-chronology")
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
            raise ExternalGovernanceApprovalError("governance:artifact-byte-cap")
        return ExternalGovernanceApprovalArtifactV1(
            raw=raw,
            artifact_id=value["artifact_id"],
            decision=result.decision,
            status=STATUS,
        )


def observe_governance_assertion(
    policy: ExternalGovernanceApprovalPolicyV1,
    verifier: ExternalGovernanceApprovalVerifier,
    evidence_raw: bytes,
) -> ExternalGovernanceApprovalArtifactV1:
    return ExternalGovernanceApprovalService(policy, verifier).observe(evidence_raw)


__all__ = [
    "ARTIFACT_KIND", "SCHEMA", "SCHEMA_VERSION", "SCOPE", "STATUS", "DECISIONS",
    "MAX_EVIDENCE_BYTES", "MAX_ARTIFACT_BYTES", "OWNERS", "NONCLAIMS", "FIXED_FLAGS",
    "ExternalGovernanceApprovalError", "ExternalGovernanceApprovalVerifier",
    "ExternalGovernanceApprovalPolicyV1", "VerifiedGovernanceAssertionV1",
    "ExternalGovernanceApprovalArtifactV1", "ExternalGovernanceApprovalService",
    "observe_governance_assertion",
]
