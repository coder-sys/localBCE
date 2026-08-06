"""Exact candidate envelope and ``proofSuiteId`` selection boundary.

The legacy candidate registry remains unqualified and keeps
``proofSuiteId=null``.  This module is the successor path: it can issue a
nonzero suite identity only from an actual selected Rust proof bundle, an
exact 12-field/744-byte envelope, the active GKR hiding certificate, and the
software custody certificate.  The resulting state is
``BUILT_AUDIT_PENDING`` only; activation and production use stay false.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Final

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from experiments.bl_pq512_crypto_foundation.active_gkr_hiding import (
    ActiveGkrHidingCertificate,
    build_active_gkr_hiding_certificate,
    validate_active_gkr_hiding_certificate,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    MAX_SELECTED_TRANSCRIPT_BYTES,
    SelectedChallengeBundle,
)
from experiments.bl_pq512_crypto_foundation.software_custody_candidate import (
    SoftwareCustodyCertificate,
    build_software_custody_certificate,
    validate_software_custody_certificate,
)


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
ENVELOPE_MAGIC: Final[bytes] = b"BLPQENV1"
ENVELOPE_VERSION: Final[int] = 2
PUBLIC_FIELD_COUNT: Final[int] = 12
PUBLIC_FIELD_BYTES: Final[int] = 32
PUBLIC_OUTPUT_BYTES: Final[int] = PUBLIC_FIELD_COUNT * PUBLIC_FIELD_BYTES
SIDECAR_BYTES: Final[int] = 744
MAX_ENVELOPE_BYTES: Final[int] = 512 * 1024 * 1024
STATUS: Final[str] = "BUILT_AUDIT_PENDING"
ACTIVATION_ALLOWED: Final[bool] = False
PRODUCTION_USABLE: Final[bool] = False
STATEMENT_EVIDENCE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/PRODUCTION-CANDIDATE/EVIDENCE/v1\x00"
)
STATEMENT_COMMITMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/PRODUCTION-CANDIDATE/STATEMENT/v1\x00"
)
TRANSCRIPT_COMMITMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/PRODUCTION-CANDIDATE/TRANSCRIPT/v1\x00"
)
PROOF_PACKAGE_COMMITMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/STATE-AIR-PROOF-PACKAGE/v1\x00"
)


class ProductionCandidateError(ValueError):
    """Fail-closed error for candidate proof/statement identity drift."""


def _wide(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64 or not any(value):
        raise ProductionCandidateError(f"candidate_{label}_invalid")
    return value


def _frame(domain: bytes, *parts: bytes) -> bytes:
    output = bytearray(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise ProductionCandidateError("candidate_frame_part_invalid")
        output.extend(len(part).to_bytes(4, "big"))
        output.extend(part)
    return bytes(output)


def _digest(domain: bytes, *parts: bytes) -> bytes:
    return hashlib.sha3_512(_frame(domain, *parts)).digest()


def _public_fields(value: object) -> tuple[bytes, ...]:
    if type(value) is not bytes or len(value) != PUBLIC_OUTPUT_BYTES:
        raise ProductionCandidateError("candidate_public_outputs_shape_invalid")
    fields = tuple(value[index : index + PUBLIC_FIELD_BYTES] for index in range(0, len(value), PUBLIC_FIELD_BYTES))
    if len(fields) != PUBLIC_FIELD_COUNT or any(int.from_bytes(item, "big") >= FIELD_MODULUS for item in fields):
        raise ProductionCandidateError("candidate_public_field_not_canonical")
    return fields


def statement_commitment(public_outputs: bytes, sidecar: bytes) -> bytes:
    fields = _public_fields(public_outputs)
    if type(sidecar) is not bytes or len(sidecar) != SIDECAR_BYTES:
        raise ProductionCandidateError("candidate_sidecar_shape_invalid")
    return _digest(STATEMENT_COMMITMENT_DOMAIN, b"".join(fields), sidecar)


def statement_evidence_commitment(
    public_outputs: bytes,
    sidecar: bytes,
    bundle: SelectedChallengeBundle,
) -> bytes:
    if type(bundle) is not SelectedChallengeBundle:
        raise TypeError("candidate_challenge_bundle_required")
    _public_fields(public_outputs)
    if type(sidecar) is not bytes or len(sidecar) != SIDECAR_BYTES:
        raise ProductionCandidateError("candidate_sidecar_shape_invalid")
    return _digest(
        STATEMENT_EVIDENCE_DOMAIN,
        public_outputs,
        sidecar,
        bundle.final_transcript_root,
        bundle.schedule_commitment,
        bundle.proof_suite_id,
    )


@dataclass(frozen=True, slots=True)
class ProductionProofEnvelope:
    suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    public_outputs: bytes
    sidecar: bytes
    proof_package: bytes
    transcript_evidence: bytes
    evidence_commitment: bytes

    def __post_init__(self) -> None:
        _wide("suite_id", self.suite_id)
        _wide("schema_id", self.schema_id)
        _wide("verifier_artifact_identity", self.verifier_artifact_identity)
        _public_fields(self.public_outputs)
        if type(self.sidecar) is not bytes or len(self.sidecar) != SIDECAR_BYTES:
            raise ProductionCandidateError("candidate_sidecar_shape_invalid")
        if type(self.proof_package) is not bytes or not self.proof_package:
            raise ProductionCandidateError("candidate_proof_package_invalid")
        if type(self.transcript_evidence) is not bytes or not self.transcript_evidence:
            raise ProductionCandidateError("candidate_transcript_evidence_invalid")
        _wide("evidence_commitment", self.evidence_commitment)
        parsed = CandidateSidecarV1.decode(self.sidecar)
        if (
            parsed.proof_suite_id != self.suite_id
            or parsed.schema_id != self.schema_id
            or parsed.verifier_artifact_identity != self.verifier_artifact_identity
        ):
            raise ProductionCandidateError("candidate_sidecar_identity_mismatch")

    def encode(self) -> bytes:
        encoded = b"".join(
            (
                ENVELOPE_MAGIC,
                ENVELOPE_VERSION.to_bytes(2, "big"),
                self.suite_id,
                self.schema_id,
                self.verifier_artifact_identity,
                self.public_outputs,
                SIDECAR_BYTES.to_bytes(4, "big"),
                self.sidecar,
                len(self.proof_package).to_bytes(8, "big"),
                self.proof_package,
                len(self.transcript_evidence).to_bytes(8, "big"),
                self.transcript_evidence,
            )
        )
        if len(encoded) > MAX_ENVELOPE_BYTES:
            raise ProductionCandidateError("candidate_envelope_too_large")
        return encoded

    @classmethod
    def decode(
        cls,
        encoded: bytes,
        *,
        evidence_commitment: bytes,
    ) -> "ProductionProofEnvelope":
        """Decode the canonical envelope after native verification.

        The evidence commitment is deliberately not duplicated in the wire
        envelope.  It is recovered from the native verifier receipt, which
        prevents a caller from supplying an unverified commitment alongside
        the proof bytes.
        """

        if type(encoded) is not bytes or not encoded:
            raise ProductionCandidateError("candidate_envelope_bytes_invalid")
        if len(encoded) > MAX_ENVELOPE_BYTES:
            raise ProductionCandidateError("candidate_envelope_too_large")
        if type(evidence_commitment) is not bytes or len(evidence_commitment) != 64:
            raise ProductionCandidateError("candidate_evidence_commitment_invalid")

        offset = 0

        def take(length: int, label: str) -> bytes:
            nonlocal offset
            if type(length) is not int or length < 0:
                raise ProductionCandidateError(f"candidate_{label}_length_invalid")
            end = offset + length
            if end > len(encoded):
                raise ProductionCandidateError(f"candidate_{label}_truncated")
            value = encoded[offset:end]
            offset = end
            return value

        if take(len(ENVELOPE_MAGIC), "envelope_magic") != ENVELOPE_MAGIC:
            raise ProductionCandidateError("candidate_envelope_magic_invalid")
        if int.from_bytes(take(2, "envelope_version"), "big") != ENVELOPE_VERSION:
            raise ProductionCandidateError("candidate_envelope_version_invalid")
        suite_id = take(64, "suite_id")
        schema_id = take(64, "schema_id")
        verifier_artifact_identity = take(64, "verifier_artifact_identity")
        public_outputs = take(PUBLIC_OUTPUT_BYTES, "public_outputs")
        sidecar_length = int.from_bytes(take(4, "sidecar_length"), "big")
        if sidecar_length != SIDECAR_BYTES:
            raise ProductionCandidateError("candidate_sidecar_length_invalid")
        sidecar = take(sidecar_length, "sidecar")
        proof_length = int.from_bytes(take(8, "proof_length"), "big")
        if proof_length <= 0 or proof_length > MAX_ENVELOPE_BYTES:
            raise ProductionCandidateError("candidate_proof_length_invalid")
        proof_package = take(proof_length, "proof_package")
        transcript_length = int.from_bytes(take(8, "transcript_length"), "big")
        if transcript_length <= 0 or transcript_length > MAX_SELECTED_TRANSCRIPT_BYTES:
            raise ProductionCandidateError("candidate_transcript_length_invalid")
        transcript_evidence = take(transcript_length, "transcript")
        if offset != len(encoded):
            raise ProductionCandidateError("candidate_envelope_trailing_bytes")

        return cls(
            suite_id=suite_id,
            schema_id=schema_id,
            verifier_artifact_identity=verifier_artifact_identity,
            public_outputs=public_outputs,
            sidecar=sidecar,
            proof_package=proof_package,
            transcript_evidence=transcript_evidence,
            evidence_commitment=evidence_commitment,
        )


def build_production_envelope(
    *,
    public_outputs: bytes,
    sidecar: bytes,
    proof_package: bytes,
    transcript_evidence: bytes,
    challenge_bundle: SelectedChallengeBundle,
) -> ProductionProofEnvelope:
    parsed = CandidateSidecarV1.decode(sidecar)
    if parsed.proof_suite_id != challenge_bundle.proof_suite_id:
        raise ProductionCandidateError("candidate_bundle_suite_mismatch")
    expected = statement_evidence_commitment(public_outputs, sidecar, challenge_bundle)
    if challenge_bundle.evidence_commitment != expected:
        raise ProductionCandidateError("candidate_statement_evidence_mismatch")
    return ProductionProofEnvelope(
        suite_id=parsed.proof_suite_id,
        schema_id=parsed.schema_id,
        verifier_artifact_identity=parsed.verifier_artifact_identity,
        public_outputs=public_outputs,
        sidecar=sidecar,
        proof_package=proof_package,
        transcript_evidence=transcript_evidence,
        evidence_commitment=expected,
    )


@dataclass(frozen=True, slots=True)
class NativeVerificationReceipt:
    """Exact fields emitted by the Rust standalone candidate verifier."""

    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    envelope_commitment: bytes
    statement_commitment: bytes
    evidence_commitment: bytes
    proof_package_commitment: bytes
    transcript_commitment: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("proof_suite_id", self.proof_suite_id),
            ("schema_id", self.schema_id),
            ("verifier_artifact_identity", self.verifier_artifact_identity),
            ("envelope_commitment", self.envelope_commitment),
            ("statement_commitment", self.statement_commitment),
            ("evidence_commitment", self.evidence_commitment),
            ("proof_package_commitment", self.proof_package_commitment),
            ("transcript_commitment", self.transcript_commitment),
        ):
            _wide(label, value)

    @classmethod
    def from_native_line(cls, line: str) -> "NativeVerificationReceipt":
        if type(line) is not str or not line.startswith("OK "):
            raise ProductionCandidateError("candidate_native_receipt_header_invalid")
        fields: dict[str, str] = {}
        for item in line.split()[1:]:
            name, separator, value = item.partition("=")
            if separator != "=" or name in fields or not value:
                raise ProductionCandidateError("candidate_native_receipt_field_invalid")
            fields[name] = value
        expected = {
            "proof_suite_id",
            "schema_id",
            "verifier_artifact_identity",
            "envelope_commitment",
            "statement_commitment",
            "evidence_commitment",
            "proof_package_commitment",
            "transcript_commitment",
        }
        if set(fields) != expected:
            raise ProductionCandidateError("candidate_native_receipt_field_set_invalid")
        try:
            values = {name: bytes.fromhex(value) for name, value in fields.items()}
        except ValueError as exc:
            raise ProductionCandidateError("candidate_native_receipt_hex_invalid") from exc
        return cls(**values)


@dataclass(frozen=True, slots=True)
class BuiltAuditPendingSuite:
    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    active_hiding_certificate_sha3_512: str
    software_custody_certificate_sha3_512: str
    proof_package_sha3_512: str
    transcript_evidence_sha3_512: str
    statement_commitment_sha3_512: str
    evidence_commitment_sha3_512: str
    status: str = STATUS
    activation_allowed: bool = False
    production_usable: bool = False

    def __post_init__(self) -> None:
        _wide("proof_suite_id", self.proof_suite_id)
        _wide("schema_id", self.schema_id)
        _wide("verifier_artifact_identity", self.verifier_artifact_identity)
        for label, value in (
            ("active_hiding_certificate", self.active_hiding_certificate_sha3_512),
            ("software_custody_certificate", self.software_custody_certificate_sha3_512),
            ("proof_package", self.proof_package_sha3_512),
            ("transcript_evidence", self.transcript_evidence_sha3_512),
            ("statement_commitment", self.statement_commitment_sha3_512),
            ("evidence_commitment", self.evidence_commitment_sha3_512),
        ):
            if type(value) is not str or len(value) != 128 or value == "0" * 128:
                raise ProductionCandidateError(f"candidate_{label}_digest_invalid")
        if self.status != STATUS or self.activation_allowed or self.production_usable:
            raise ProductionCandidateError("candidate_suite_lifecycle_invalid")

    @property
    def release_identity_sha3_512(self) -> str:
        payload = b"".join(
            (
                self.proof_suite_id,
                self.schema_id,
                self.verifier_artifact_identity,
                bytes.fromhex(self.active_hiding_certificate_sha3_512),
                bytes.fromhex(self.software_custody_certificate_sha3_512),
                bytes.fromhex(self.proof_package_sha3_512),
                bytes.fromhex(self.transcript_evidence_sha3_512),
                bytes.fromhex(self.statement_commitment_sha3_512),
                bytes.fromhex(self.evidence_commitment_sha3_512),
            )
        )
        return hashlib.sha3_512(b"BL/PQ512/BUILT-AUDIT-PENDING-RELEASE/v1\0" + payload).hexdigest()

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "proofSuiteId": self.proof_suite_id.hex(),
            "schemaId": self.schema_id.hex(),
            "verifierArtifactIdentity": self.verifier_artifact_identity.hex(),
            "activeHidingCertificateSha3_512": self.active_hiding_certificate_sha3_512,
            "softwareCustodyCertificateSha3_512": self.software_custody_certificate_sha3_512,
            "proofPackageSha3_512": self.proof_package_sha3_512,
            "transcriptEvidenceSha3_512": self.transcript_evidence_sha3_512,
            "statementCommitmentSha3_512": self.statement_commitment_sha3_512,
            "evidenceCommitmentSha3_512": self.evidence_commitment_sha3_512,
            "releaseIdentitySha3_512": self.release_identity_sha3_512,
            "activationAllowed": self.activation_allowed,
            "productionUsable": self.production_usable,
        }


def select_built_audit_pending_suite(
    envelope: ProductionProofEnvelope,
    *,
    verification: NativeVerificationReceipt,
    hiding: ActiveGkrHidingCertificate | None = None,
    custody: SoftwareCustodyCertificate | None = None,
    root: Path = ROOT,
) -> BuiltAuditPendingSuite:
    if not isinstance(envelope, ProductionProofEnvelope):
        raise TypeError("candidate_envelope_required")
    if not isinstance(verification, NativeVerificationReceipt):
        raise TypeError("candidate_native_verification_receipt_required")
    hiding = build_active_gkr_hiding_certificate(root) if hiding is None else hiding
    custody = build_software_custody_certificate(root) if custody is None else custody
    validate_active_gkr_hiding_certificate(hiding, root)
    validate_software_custody_certificate(custody, root)
    if (
        verification.proof_suite_id != envelope.suite_id
        or verification.schema_id != envelope.schema_id
        or verification.verifier_artifact_identity != envelope.verifier_artifact_identity
        or verification.envelope_commitment != hashlib.sha3_512(envelope.encode()).digest()
        or verification.statement_commitment
        != statement_commitment(envelope.public_outputs, envelope.sidecar)
        or verification.evidence_commitment != envelope.evidence_commitment
        or verification.proof_package_commitment
        != hashlib.sha3_512(PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package).digest()
        or verification.transcript_commitment
        != hashlib.sha3_512(TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence).digest()
    ):
        raise ProductionCandidateError("candidate_native_verification_binding_mismatch")
    return BuiltAuditPendingSuite(
        proof_suite_id=envelope.suite_id,
        schema_id=envelope.schema_id,
        verifier_artifact_identity=envelope.verifier_artifact_identity,
        active_hiding_certificate_sha3_512=hiding.certificate_digest_sha3_512,
        software_custody_certificate_sha3_512=custody.certificate_digest_sha3_512,
        proof_package_sha3_512=verification.proof_package_commitment.hex(),
        transcript_evidence_sha3_512=verification.transcript_commitment.hex(),
        statement_commitment_sha3_512=statement_commitment(
            envelope.public_outputs, envelope.sidecar
        ).hex(),
        evidence_commitment_sha3_512=envelope.evidence_commitment.hex(),
    )


__all__ = (
    "ACTIVATION_ALLOWED",
    "BuiltAuditPendingSuite",
    "ENVELOPE_MAGIC",
    "NativeVerificationReceipt",
    "PROOF_PACKAGE_COMMITMENT_DOMAIN",
    "PRODUCTION_USABLE",
    "ProductionCandidateError",
    "ProductionProofEnvelope",
    "SIDECAR_BYTES",
    "STATUS",
    "TRANSCRIPT_COMMITMENT_DOMAIN",
    "build_production_envelope",
    "select_built_audit_pending_suite",
    "statement_commitment",
    "statement_evidence_commitment",
)
