"""Synthetic, bounded corrective-action evidence boundary.

This module authenticates only a caller-injected evidence verifier result.  It
does not store or dispatch the evidence and grants no corrective authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping, Protocol

from app.mirror.error_boundary import raise_redacted


MAX_EVIDENCE_BYTES = 65_536
MAX_ARTIFACT_BYTES = 32_768
MAX_TIMESTAMP = 2_147_483_647
SCHEMA = "mirror-corrective-action-v1"
SCHEMA_VERSION = 1
FIXED_FLAGS = {
    "synthetic_only": True,
    "production_usable": False,
    "activation": False,
    "state_owned_control": True,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "adjudication_authority": False,
}
_HEX = re.compile(r"^[0-9a-f]{128}$")
_ALLOWED_ACTIONS = ("CORRECTIVE_ACTION_RECORDED",)


class CorrectiveActionError(ValueError):
    """Fixed public corrective-action failure."""


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(CorrectiveActionError, "action:noncanonical")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise CorrectiveActionError("action:byte-cap")
    return raw


def _digest(label: str, value: object) -> str:
    h = hashlib.sha3_512()
    h.update(("BL/MIRROR/CORRECTIVE-ACTION/V1/" + label + "\0").encode("ascii"))
    h.update(_canonical(value))
    return h.hexdigest()


def _raw_digest(raw: bytes) -> str:
    h = hashlib.sha3_512()
    h.update(b"BL/MIRROR/CORRECTIVE-ACTION/V1/evidence\0")
    h.update(raw)
    return h.hexdigest()


def _hex(value: object, code: str) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise CorrectiveActionError(code)
    return value


def _text(value: object, code: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value:
        raise CorrectiveActionError(code)
    try:
        if len(value.encode("ascii")) > maximum or any(not (char.isalnum() or char in "._:-") for char in value):
            raise CorrectiveActionError(code)
    except UnicodeEncodeError:
        raise_redacted(CorrectiveActionError, code)
    return value


@dataclass(frozen=True)
class CorrectiveActionPolicyV1:
    case_id: str
    current_case_artifact_id: str
    source_artifact_id: str
    graph_artifact_id: str
    graph_report_id: str
    target_finding_ids: tuple[str, ...]
    target_finding_kinds: tuple[str, ...]
    verifier_id: str
    verifier_epoch: int
    authority_evidence_digest: str
    revocation_head_digest: str
    terms_digest: str
    retention_policy_digest: str
    valid_from: int
    valid_until: int
    max_evidence_bytes: int = MAX_EVIDENCE_BYTES

    def __post_init__(self) -> None:
        for value in (self.case_id, self.current_case_artifact_id, self.source_artifact_id, self.graph_artifact_id, self.graph_report_id, self.authority_evidence_digest, self.revocation_head_digest, self.terms_digest, self.retention_policy_digest):
            _hex(value, "policy:identity")
        _text(self.verifier_id, "policy:verifier")
        if type(self.verifier_epoch) is not int or self.verifier_epoch < 0 or type(self.valid_from) is not int or type(self.valid_until) is not int or not 0 <= self.valid_from <= self.valid_until <= MAX_TIMESTAMP:
            raise CorrectiveActionError("policy:interval")
        if type(self.max_evidence_bytes) is not int or not 1 <= self.max_evidence_bytes <= MAX_EVIDENCE_BYTES:
            raise CorrectiveActionError("policy:cap")
        if not self.target_finding_ids or len(self.target_finding_ids) != len(self.target_finding_kinds) or len(self.target_finding_ids) > 8:
            raise CorrectiveActionError("policy:findings")
        if tuple(sorted(self.target_finding_ids)) != self.target_finding_ids or len(set(self.target_finding_ids)) != len(self.target_finding_ids):
            raise CorrectiveActionError("policy:findings")
        for value in self.target_finding_ids:
            _hex(value, "policy:finding")
        for value in self.target_finding_kinds:
            _text(value, "policy:finding-kind")

    def material(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "current_case_artifact_id": self.current_case_artifact_id,
            "source_artifact_id": self.source_artifact_id,
            "graph_artifact_id": self.graph_artifact_id,
            "graph_report_id": self.graph_report_id,
            "target_finding_ids": list(self.target_finding_ids),
            "target_finding_kinds": list(self.target_finding_kinds),
            "verifier_id": self.verifier_id,
            "verifier_epoch": self.verifier_epoch,
            "authority_evidence_digest": self.authority_evidence_digest,
            "revocation_head_digest": self.revocation_head_digest,
            "terms_digest": self.terms_digest,
            "retention_policy_digest": self.retention_policy_digest,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "max_evidence_bytes": self.max_evidence_bytes,
            "flags": dict(FIXED_FLAGS),
        }

    @property
    def digest(self) -> str:
        return _digest("policy", self.material())


@dataclass(frozen=True)
class VerifiedCorrectiveActionV1:
    action_id: str
    policy_digest: str
    case_id: str
    current_case_artifact_id: str
    source_artifact_id: str
    graph_artifact_id: str
    graph_report_id: str
    target_finding_ids: tuple[str, ...]
    target_finding_kinds: tuple[str, ...]
    action_code: str
    observed_at: int
    valid_from: int
    valid_until: int
    verifier_id: str
    verifier_epoch: int
    evidence_sha3_512: str
    evidence_byte_length: int


class CorrectiveActionVerifier(Protocol):
    @property
    def identity(self) -> str: ...

    @property
    def epoch(self) -> int: ...

    def verify(self, evidence_raw: bytes, policy: CorrectiveActionPolicyV1) -> VerifiedCorrectiveActionV1: ...


def _assert_verified(result: object, policy: CorrectiveActionPolicyV1, evidence_raw: bytes) -> VerifiedCorrectiveActionV1:
    if not isinstance(result, VerifiedCorrectiveActionV1) or type(evidence_raw) is not bytes or not evidence_raw or len(evidence_raw) > policy.max_evidence_bytes:
        raise CorrectiveActionError("action:verifier-result")
    if result.policy_digest != policy.digest or result.case_id != policy.case_id or result.current_case_artifact_id != policy.current_case_artifact_id or result.source_artifact_id != policy.source_artifact_id or result.graph_artifact_id != policy.graph_artifact_id or result.graph_report_id != policy.graph_report_id:
        raise CorrectiveActionError("action:policy-binding")
    if result.target_finding_ids != policy.target_finding_ids or result.target_finding_kinds != policy.target_finding_kinds or result.verifier_id != policy.verifier_id or result.verifier_epoch != policy.verifier_epoch:
        raise CorrectiveActionError("action:policy-binding")
    if result.action_code not in _ALLOWED_ACTIONS or type(result.observed_at) is not int or result.observed_at < policy.valid_from or result.observed_at > policy.valid_until or result.valid_from != policy.valid_from or result.valid_until != policy.valid_until:
        raise CorrectiveActionError("action:interval-or-code")
    if result.evidence_byte_length != len(evidence_raw) or result.evidence_sha3_512 != _raw_digest(evidence_raw):
        raise CorrectiveActionError("action:evidence-binding")
    expected_action_id = _digest(
        "action-id",
        {
            "policy_digest": policy.digest,
            "evidence_sha3_512": result.evidence_sha3_512,
            "action_code": result.action_code,
            "observed_at": result.observed_at,
        },
    )
    if result.action_id != expected_action_id:
        raise CorrectiveActionError("action:id")
    _hex(result.action_id, "action:id")
    return result


class CorrectiveActionService:
    def __init__(self, policy: CorrectiveActionPolicyV1, verifier: CorrectiveActionVerifier) -> None:
        if not isinstance(policy, CorrectiveActionPolicyV1):
            raise CorrectiveActionError("composition:policy")
        try:
            if verifier.identity != policy.verifier_id or verifier.epoch != policy.verifier_epoch:
                raise CorrectiveActionError("composition:verifier")
        except CorrectiveActionError:
            raise
        except Exception:
            raise_redacted(CorrectiveActionError, "composition:verifier")
        self.policy = policy
        self._verifier = verifier

    def observe(self, evidence_raw: bytes) -> bytes:
        if type(evidence_raw) is not bytes or not evidence_raw or len(evidence_raw) > self.policy.max_evidence_bytes:
            raise CorrectiveActionError("action:evidence-cap")
        try:
            if self._verifier.identity != self.policy.verifier_id or self._verifier.epoch != self.policy.verifier_epoch:
                raise CorrectiveActionError("action:verifier")
            result = self._verifier.verify(evidence_raw, self.policy)
        except CorrectiveActionError:
            raise
        except Exception:
            raise_redacted(CorrectiveActionError, "action:verifier")
        verified = _assert_verified(result, self.policy, evidence_raw)
        assertion = {
            "action_id": verified.action_id,
            "case_id": verified.case_id,
            "current_case_artifact_id": verified.current_case_artifact_id,
            "source_artifact_id": verified.source_artifact_id,
            "graph_artifact_id": verified.graph_artifact_id,
            "graph_report_id": verified.graph_report_id,
            "target_finding_ids": list(verified.target_finding_ids),
            "target_finding_kinds": list(verified.target_finding_kinds),
            "action_code": verified.action_code,
            "observed_at": verified.observed_at,
            "valid_from": verified.valid_from,
            "valid_until": verified.valid_until,
            "verifier_id": verified.verifier_id,
            "verifier_epoch": verified.verifier_epoch,
            "evidence_sha3_512": verified.evidence_sha3_512,
            "evidence_byte_length": verified.evidence_byte_length,
        }
        body = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "kind": "CORRECTIVE_ACTION", "policy": self.policy.material(), "policy_digest": self.policy.digest, "assertion": assertion, "flags": dict(FIXED_FLAGS)}
        body["artifact_id"] = _digest("artifact-id", body)
        raw = _canonical(body)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise CorrectiveActionError("action:byte-cap")
        return raw
