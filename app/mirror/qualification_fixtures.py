"""Fixture-only qualification issuers and rehearsal composition.

Nothing in this module authenticates an external authority.  Its deterministic
hashes and envelope are deliberately scoped to the synthetic rehearsal profile
and are never accepted as ``VERIFIED`` external evidence.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Mapping, Sequence

from app.mirror import qualification
from app.mirror import qualification_independent as independent


def _canonical(value: object) -> bytes:
    return qualification._canonical(value)


def _digest(label: str, value: object) -> str:
    return qualification._digest(label, value)


def _raw_digest(label: str, raw: bytes) -> str:
    return qualification._raw_digest(label, raw)


def _synthetic_key(key_id: str, epoch: int) -> bytes:
    return hashlib.sha3_512(
        (independent.DOMAIN + "synthetic-key/v1\0" + key_id + "|" + str(epoch)).encode("ascii")
    ).digest()


def _crypt(raw: bytes, key: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < len(raw):
        output.extend(hashlib.sha3_512(key + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(left ^ right for left, right in zip(raw, output))


def _tag(key: bytes, header: Mapping[str, object], ciphertext: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(key)
    digest.update(_canonical(header))
    digest.update(ciphertext)
    return digest.hexdigest()


class SyntheticEvidenceAuthority:
    """Fixture-only issuer for rehearsal evidence, never external authority."""

    @staticmethod
    def issue(
        dependency_id: str,
        *,
        state: str = independent.REHEARSAL_VERIFIED_STATE,
        issued_at: int = 1_000,
        valid_until: int = 9_000,
        revoked: bool = False,
    ) -> dict[str, object]:
        allowed = {"PRESENT_UNVERIFIED", independent.REHEARSAL_VERIFIED_STATE, "EXPIRED", "REVOKED"}
        if dependency_id not in independent.DEPENDENCY_IDS:
            raise qualification.QualificationError("qualification:dependency")
        if state not in allowed:
            raise qualification.QualificationError("qualification:evidence-state")
        if type(issued_at) is not int or type(valid_until) is not int or valid_until <= issued_at:
            raise qualification.QualificationError("qualification:evidence-time")
        if type(revoked) is not bool or (revoked and state != "REVOKED") or (state == "REVOKED" and not revoked):
            raise qualification.QualificationError("qualification:evidence-revocation")
        owner = independent.DEPENDENCY_OWNERS[dependency_id]
        material = {
            "dependency_id": dependency_id,
            "owner": owner,
            "state": state,
            "evidence_class": independent.REHEARSAL_EVIDENCE_CLASS,
            "issued_at": issued_at,
            "valid_until": valid_until,
            "revoked": revoked,
            "payload_kind": independent.REHEARSAL_PAYLOAD_KIND,
        }
        return {**material, "proof": _digest("evidence-proof", material), "evidence_id": _digest("evidence-id", material)}


class SyntheticOperationsEvidence:
    """Fixture-only local operational observations for rehearsal."""

    @staticmethod
    def issue(
        operation_id: str,
        *,
        state: str = independent.REHEARSAL_VERIFIED_STATE,
        observed_rpo_seconds: int | None = 0,
        observed_rto_ms: int | None = 1,
        fault_codes: Sequence[str] = (),
    ) -> dict[str, object]:
        allowed = set(independent.OPERATION_STATES) - {"VERIFIED"}
        if operation_id not in independent.OPERATION_IDS:
            raise qualification.QualificationError("qualification:operation")
        if state not in allowed:
            raise qualification.QualificationError("qualification:operation-state")
        codes = sorted(set(fault_codes))
        if any(type(code) is not str for code in codes):
            raise qualification.QualificationError("qualification:fault-code")
        material = {
            "operation_id": operation_id,
            "owner": "STATE_OPERATIONS_AUTHORITY",
            "required": True,
            "state": state,
            "evidence_class": independent.REHEARSAL_EVIDENCE_CLASS,
            "observed_rpo_seconds": observed_rpo_seconds,
            "observed_rto_ms": observed_rto_ms,
            "fault_codes": codes,
        }
        proof = None if state == "PRESENT_UNVERIFIED" else _digest("operation-proof", material)
        return {**material, "proof": proof}


class SyntheticEnvelopeCustody:
    """Fixture custody only; this is not encryption-at-rest qualification."""

    def __init__(self, *, key_id: str = "SYNTHETIC_QUALIFICATION_KEY_V1", epoch: int = 1) -> None:
        if not key_id.startswith("SYNTHETIC_QUALIFICATION_KEY_V") or epoch < 1:
            raise qualification.QualificationError("qualification:custody-key")
        self.key_id = key_id
        self.epoch = epoch
        self.key_state = "ACTIVE"
        self._audit: list[dict[str, object]] = []

    def _audit_entry(self, action: str) -> dict[str, object]:
        return {"action": action, "key_id": self.key_id, "key_epoch": self.epoch, "status": "OBSERVED"}

    def rotate(self) -> dict[str, object]:
        version = int(self.key_id.rsplit("V", 1)[1]) + 1
        self.key_id = f"SYNTHETIC_QUALIFICATION_KEY_V{version}"
        self.epoch += 1
        self.key_state = "ACTIVE"
        self._audit = [self._audit_entry("ROTATE")]
        return {"key_id": self.key_id, "key_epoch": self.epoch, "key_state": self.key_state}

    def revoke(self) -> dict[str, object]:
        self.key_state = "REVOKED"
        self._audit = [self._audit_entry("REVOKE")]
        return {"key_id": self.key_id, "key_epoch": self.epoch, "key_state": self.key_state}

    def seal(self, seed: Mapping[str, object]) -> dict[str, object]:
        if self.key_state != "ACTIVE":
            raise qualification.QualificationError("qualification:custody-key-revoked")
        plaintext = _canonical(dict(seed))
        if len(plaintext) > 32_768:
            raise qualification.QualificationError("qualification:custody-byte-cap")
        key = _synthetic_key(self.key_id, self.epoch)
        header = {"schema": "synthetic-envelope-encryption-v1", "key_id": self.key_id, "key_epoch": self.epoch}
        ciphertext = _crypt(plaintext, key)
        envelope = {
            **header,
            "ciphertext": ciphertext.hex(),
            "tag": _tag(key, header, ciphertext),
            "plaintext_digest": _raw_digest("envelope-plaintext", plaintext),
        }
        prior = [item for item in self._audit if item["action"] != "SEAL"]
        self._audit = [*prior, self._audit_entry("SEAL")]
        return {
            "mode": "SYNTHETIC_DETERMINISTIC_ENVELOPE",
            "key_id": self.key_id,
            "key_epoch": self.epoch,
            "key_state": self.key_state,
            "envelope": envelope,
            "audit": deepcopy(self._audit),
            "audit_root": _digest("custody-audit", self._audit),
            "envelope_digest": _digest("custody-envelope", envelope),
            "encryption_at_rest_qualified": False,
            "production_key_custody": False,
        }

    def open(self, envelope: Mapping[str, object]) -> bytes:
        if not isinstance(envelope, Mapping):
            raise qualification.QualificationError("qualification:custody-envelope")
        key_id = envelope.get("key_id")
        epoch = envelope.get("key_epoch")
        body = envelope.get("envelope")
        if not isinstance(key_id, str) or type(epoch) is not int or not isinstance(body, Mapping):
            raise qualification.QualificationError("qualification:custody-envelope")
        if body.get("key_id") != key_id or body.get("key_epoch") != epoch:
            raise qualification.QualificationError("qualification:custody-binding")
        try:
            ciphertext = bytes.fromhex(str(body["ciphertext"]))
        except (KeyError, ValueError) as exc:
            raise qualification.QualificationError("qualification:custody-ciphertext") from exc
        key = _synthetic_key(key_id, epoch)
        header = {"schema": body["schema"], "key_id": key_id, "key_epoch": epoch}
        if body.get("tag") != _tag(key, header, ciphertext):
            raise qualification.QualificationError("qualification:custody-tag")
        plaintext = _crypt(ciphertext, key)
        if body.get("plaintext_digest") != _raw_digest("envelope-plaintext", plaintext):
            raise qualification.QualificationError("qualification:custody-digest")
        return plaintext


def complete_evidence(*, valid_until: int = 9_000) -> dict[str, dict[str, object]]:
    return {
        dependency_id: SyntheticEvidenceAuthority.issue(dependency_id, valid_until=valid_until)
        for dependency_id in independent.DEPENDENCY_IDS
    }


def complete_operations() -> dict[str, dict[str, object]]:
    return {operation_id: SyntheticOperationsEvidence.issue(operation_id) for operation_id in independent.OPERATION_IDS}


def build_fixture_manifest(
    *,
    evidence: Mapping[str, Mapping[str, object]] | None = None,
    operations: Mapping[str, Mapping[str, object]] | None = None,
    as_of: int = 1_000,
    custody: SyntheticEnvelopeCustody | None = None,
    prior_raw: bytes | None = None,
    rehearsal_state: str = independent.REHEARSAL_NOT_READY,
) -> bytes:
    """Build only a synthetic rehearsal artifact through the production seam."""

    return qualification.build_manifest(
        evidence=evidence,
        operations=operations,
        as_of=as_of,
        custody=custody or SyntheticEnvelopeCustody(),
        prior_raw=prior_raw,
        pilot_state=rehearsal_state,
    )


class QualificationRehearsalService:
    """Fixture composition root; it cannot select controlled-shadow authority."""

    def __init__(self, store_or_path: object) -> None:
        self.service = qualification.QualificationService(store_or_path)
        self.store = self.service.store

    @staticmethod
    def _custody() -> SyntheticEnvelopeCustody:
        return SyntheticEnvelopeCustody()

    def initialize(
        self,
        *,
        evidence: Mapping[str, Mapping[str, object]] | None = None,
        operations: Mapping[str, Mapping[str, object]] | None = None,
        as_of: int = 1_000,
    ):
        return self.service.initialize(evidence=evidence, operations=operations, as_of=as_of, custody=self._custody())

    def advance(
        self,
        target_state: str,
        *,
        evidence: Mapping[str, Mapping[str, object]] | None = None,
        operations: Mapping[str, Mapping[str, object]] | None = None,
        as_of: int | None = None,
    ):
        return self.service.advance(target_state, evidence=evidence, operations=operations, as_of=as_of, custody=self._custody())

    def refresh(
        self,
        *,
        evidence: Mapping[str, Mapping[str, object]],
        as_of: int,
        target_state: str | None = None,
        operations: Mapping[str, Mapping[str, object]] | None = None,
    ):
        return self.service.refresh(evidence=evidence, as_of=as_of, target_state=target_state, operations=operations, custody=self._custody())

    def current_raw(self) -> bytes | None:
        return self.service.current_raw()

    @staticmethod
    def _maps(raw: bytes) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
        return qualification.QualificationService._maps(raw)


__all__ = [
    "SyntheticEvidenceAuthority",
    "SyntheticOperationsEvidence",
    "SyntheticEnvelopeCustody",
    "complete_evidence",
    "complete_operations",
    "build_fixture_manifest",
    "QualificationRehearsalService",
]
