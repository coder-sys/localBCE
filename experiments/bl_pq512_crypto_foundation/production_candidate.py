"""Exact narrow candidate envelope and native-verification boundary.

The envelope and native receipt bind one selected Rust AIR proof, the exact
12-field/744-byte statement, and the authenticated transcript.  They do not
establish the complete heterogeneous Blind Ledger theorem.  Aggregate
qualification therefore remains unreachable, ``proofSuiteId`` stays null,
and activation and production use remain false.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from typing import Final

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from experiments.bl_pq512_crypto_foundation.active_gkr_hiding import (
    ActiveGkrHidingCertificate,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    MAX_SELECTED_TRANSCRIPT_BYTES,
    SelectedChallengeBundle,
)
from experiments.bl_pq512_crypto_foundation.software_custody_candidate import (
    SoftwareCustodyCertificate,
)


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
ENVELOPE_MAGIC: Final[bytes] = b"BLPQENV1"
ENVELOPE_VERSION: Final[int] = 2
PUBLIC_FIELD_COUNT: Final[int] = 12
PUBLIC_FIELD_BYTES: Final[int] = 32
PUBLIC_OUTPUT_BYTES: Final[int] = PUBLIC_FIELD_COUNT * PUBLIC_FIELD_BYTES
SIDECAR_BYTES: Final[int] = 744
MAX_ENVELOPE_BYTES: Final[int] = 512 * 1024 * 1024
PROOF_PACKAGE_BYTES: Final[int] = 64 * 1024 * 1024
ENVELOPE_PREFIX_BYTES: Final[int] = 8 + 2 + (64 * 3) + PUBLIC_OUTPUT_BYTES + 4 + SIDECAR_BYTES + 8
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
    b"BL/PQ512/STATE-AIR-PROOF-PACKAGE/v2\x00"
)


class ProductionCandidateError(ValueError):
    """Fail-closed error for candidate proof/statement identity drift."""


@dataclass(frozen=True, slots=True)
class ProductionEnvelopeHeader:
    suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    public_outputs: bytes
    sidecar: bytes
    proof_length: int


def _parse_envelope_prefix(encoded: bytes) -> ProductionEnvelopeHeader:
    if type(encoded) is not bytes or len(encoded) != ENVELOPE_PREFIX_BYTES:
        raise ProductionCandidateError("candidate_envelope_prefix_shape_invalid")
    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        end = offset + length
        value = encoded[offset:end]
        if len(value) != length:
            raise ProductionCandidateError("candidate_envelope_prefix_truncated")
        offset = end
        return value

    if take(8) != ENVELOPE_MAGIC:
        raise ProductionCandidateError("candidate_envelope_magic_invalid")
    if int.from_bytes(take(2), "big") != ENVELOPE_VERSION:
        raise ProductionCandidateError("candidate_envelope_version_invalid")
    suite_id = _wide("suite_id", take(64))
    schema_id = _wide("schema_id", take(64))
    verifier_artifact_identity = _wide("verifier_artifact_identity", take(64))
    public_outputs = take(PUBLIC_OUTPUT_BYTES)
    _public_fields(public_outputs)
    if int.from_bytes(take(4), "big") != SIDECAR_BYTES:
        raise ProductionCandidateError("candidate_sidecar_length_invalid")
    sidecar = take(SIDECAR_BYTES)
    parsed_sidecar = CandidateSidecarV1.decode(sidecar)
    if (
        parsed_sidecar.proof_suite_id != suite_id
        or parsed_sidecar.schema_id != schema_id
        or parsed_sidecar.verifier_artifact_identity != verifier_artifact_identity
    ):
        raise ProductionCandidateError("candidate_sidecar_identity_mismatch")
    proof_length = int.from_bytes(take(8), "big")
    if proof_length != PROOF_PACKAGE_BYTES:
        raise ProductionCandidateError("candidate_proof_length_invalid")
    return ProductionEnvelopeHeader(
        suite_id=suite_id,
        schema_id=schema_id,
        verifier_artifact_identity=verifier_artifact_identity,
        public_outputs=public_outputs,
        sidecar=sidecar,
        proof_length=proof_length,
    )


def _validate_envelope_lengths(proof_length: int, transcript_length: int, file_length: int) -> None:
    if type(proof_length) is not int or proof_length != PROOF_PACKAGE_BYTES:
        raise ProductionCandidateError("candidate_proof_length_invalid")
    if type(transcript_length) is not int or not 0 < transcript_length <= MAX_SELECTED_TRANSCRIPT_BYTES:
        raise ProductionCandidateError("candidate_transcript_length_invalid")
    expected = ENVELOPE_PREFIX_BYTES + proof_length + 8 + transcript_length
    if expected > MAX_ENVELOPE_BYTES:
        raise ProductionCandidateError("candidate_envelope_too_large")
    if file_length < expected:
        raise ProductionCandidateError("candidate_envelope_truncated")
    if file_length > expected:
        raise ProductionCandidateError("candidate_envelope_trailing_bytes")


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
        if (
            type(self.transcript_evidence) is not bytes
            or not self.transcript_evidence
            or len(self.transcript_evidence) > MAX_SELECTED_TRANSCRIPT_BYTES
        ):
            raise ProductionCandidateError("candidate_transcript_evidence_invalid")
        if ENVELOPE_PREFIX_BYTES + len(self.proof_package) + 8 + len(self.transcript_evidence) > MAX_ENVELOPE_BYTES:
            raise ProductionCandidateError("candidate_envelope_too_large")
        _wide("evidence_commitment", self.evidence_commitment)
        parsed = CandidateSidecarV1.decode(self.sidecar)
        if (
            parsed.proof_suite_id != self.suite_id
            or parsed.schema_id != self.schema_id
            or parsed.verifier_artifact_identity != self.verifier_artifact_identity
        ):
            raise ProductionCandidateError("candidate_sidecar_identity_mismatch")

    def encode(self) -> bytes:
        encoded_length = (
            ENVELOPE_PREFIX_BYTES
            + len(self.proof_package)
            + 8
            + len(self.transcript_evidence)
        )
        if encoded_length > MAX_ENVELOPE_BYTES:
            raise ProductionCandidateError("candidate_envelope_too_large")
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
    def public_outputs_from_encoded(cls, encoded: bytes) -> bytes:
        """Read only the canonical public projection before native verification."""

        if type(encoded) is not bytes or not encoded:
            raise ProductionCandidateError("candidate_envelope_bytes_invalid")
        prefix_length = len(ENVELOPE_MAGIC) + 2 + (64 * 3)
        if len(encoded) < prefix_length + PUBLIC_OUTPUT_BYTES:
            raise ProductionCandidateError("candidate_envelope_public_outputs_truncated")
        if encoded[: len(ENVELOPE_MAGIC)] != ENVELOPE_MAGIC:
            raise ProductionCandidateError("candidate_envelope_magic_invalid")
        version_start = len(ENVELOPE_MAGIC)
        if int.from_bytes(encoded[version_start : version_start + 2], "big") != ENVELOPE_VERSION:
            raise ProductionCandidateError("candidate_envelope_version_invalid")
        public_start = prefix_length
        public_outputs = encoded[public_start : public_start + PUBLIC_OUTPUT_BYTES]
        _public_fields(public_outputs)
        return public_outputs

    @classmethod
    def read_file(
        cls,
        path: Path,
        *,
        evidence_commitment: bytes,
        expected_suite_id: bytes | None = None,
        expected_schema_id: bytes | None = None,
        expected_verifier_artifact_identity: bytes | None = None,
    ) -> "ProductionProofEnvelope":
        """Parse one v2 file without reading the whole envelope into memory.

        The fixed prefix, identities, sidecar, both section lengths, and exact
        file length are checked before either variable body is allocated.
        """

        if not isinstance(path, Path) or not path.is_absolute():
            raise ProductionCandidateError("candidate_envelope_path_invalid")
        _wide("evidence_commitment", evidence_commitment)
        try:
            with path.open("rb") as handle:
                metadata = os.fstat(handle.fileno())
                if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_ENVELOPE_BYTES:
                    raise ProductionCandidateError("candidate_envelope_file_bounds_invalid")
                prefix = handle.read(ENVELOPE_PREFIX_BYTES)
                header = _parse_envelope_prefix(prefix)
                for label, expected, observed in (
                    ("suite_id", expected_suite_id, header.suite_id),
                    ("schema_id", expected_schema_id, header.schema_id),
                    (
                        "verifier_artifact_identity",
                        expected_verifier_artifact_identity,
                        header.verifier_artifact_identity,
                    ),
                ):
                    if expected is not None and _wide(label, expected) != observed:
                        raise ProductionCandidateError("candidate_envelope_identity_mismatch")
                transcript_length_offset = ENVELOPE_PREFIX_BYTES + header.proof_length
                if transcript_length_offset + 8 > metadata.st_size:
                    raise ProductionCandidateError("candidate_envelope_truncated")
                handle.seek(transcript_length_offset)
                transcript_length_bytes = handle.read(8)
                if len(transcript_length_bytes) != 8:
                    raise ProductionCandidateError("candidate_transcript_length_truncated")
                transcript_length = int.from_bytes(transcript_length_bytes, "big")
                _validate_envelope_lengths(
                    header.proof_length,
                    transcript_length,
                    metadata.st_size,
                )
                handle.seek(ENVELOPE_PREFIX_BYTES)
                proof_package = handle.read(header.proof_length)
                if len(proof_package) != header.proof_length:
                    raise ProductionCandidateError("candidate_proof_package_truncated")
                if handle.read(8) != transcript_length_bytes:
                    raise ProductionCandidateError("candidate_envelope_changed_during_read")
                transcript_evidence = handle.read(transcript_length)
                if len(transcript_evidence) != transcript_length:
                    raise ProductionCandidateError("candidate_transcript_truncated")
                if handle.read(1):
                    raise ProductionCandidateError("candidate_envelope_trailing_bytes")
                observed_hash = hashlib.sha3_512()
                observed_hash.update(prefix)
                observed_hash.update(proof_package)
                observed_hash.update(transcript_length_bytes)
                observed_hash.update(transcript_evidence)
                handle.seek(0)
                stable_hash = hashlib.sha3_512()
                stable_length = 0
                while chunk := handle.read(1024 * 1024):
                    stable_hash.update(chunk)
                    stable_length += len(chunk)
                after = os.fstat(handle.fileno())
                if (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ) or stable_length != metadata.st_size or stable_hash.digest() != observed_hash.digest():
                    raise ProductionCandidateError("candidate_envelope_changed_during_read")
        except (OSError, MemoryError) as exc:
            raise ProductionCandidateError("candidate_envelope_file_read_failed") from exc
        return cls(
            suite_id=header.suite_id,
            schema_id=header.schema_id,
            verifier_artifact_identity=header.verifier_artifact_identity,
            public_outputs=header.public_outputs,
            sidecar=header.sidecar,
            proof_package=proof_package,
            transcript_evidence=transcript_evidence,
            evidence_commitment=evidence_commitment,
        )

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

        prefix = encoded[:ENVELOPE_PREFIX_BYTES]
        header = _parse_envelope_prefix(prefix)
        transcript_length_offset = ENVELOPE_PREFIX_BYTES + header.proof_length
        transcript_length_end = transcript_length_offset + 8
        if transcript_length_end > len(encoded):
            raise ProductionCandidateError("candidate_transcript_length_truncated")
        transcript_length = int.from_bytes(
            encoded[transcript_length_offset:transcript_length_end], "big"
        )
        _validate_envelope_lengths(header.proof_length, transcript_length, len(encoded))
        proof_package = encoded[ENVELOPE_PREFIX_BYTES:transcript_length_offset]
        transcript_evidence = encoded[transcript_length_end:]

        return cls(
            suite_id=header.suite_id,
            schema_id=header.schema_id,
            verifier_artifact_identity=header.verifier_artifact_identity,
            public_outputs=header.public_outputs,
            sidecar=header.sidecar,
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


def select_built_audit_pending_suite(
    envelope: ProductionProofEnvelope,
    *,
    verification: NativeVerificationReceipt,
    hiding: ActiveGkrHidingCertificate | None = None,
    custody: SoftwareCustodyCertificate | None = None,
    aggregate_release: object | None = None,
    root: Path = ROOT,
) -> None:
    if not isinstance(envelope, ProductionProofEnvelope):
        raise TypeError("candidate_envelope_required")
    if not isinstance(verification, NativeVerificationReceipt):
        raise TypeError("candidate_native_verification_receipt_required")
    if aggregate_release is None:
        raise ProductionCandidateError("candidate_aggregate_qualification_required")
    raise ProductionCandidateError(
        "candidate_complete_aggregate_qualification_unimplemented"
    )


__all__ = (
    "ENVELOPE_MAGIC",
    "ENVELOPE_PREFIX_BYTES",
    "NativeVerificationReceipt",
    "PROOF_PACKAGE_COMMITMENT_DOMAIN",
    "PROOF_PACKAGE_BYTES",
    "ProductionCandidateError",
    "ProductionEnvelopeHeader",
    "ProductionProofEnvelope",
    "SIDECAR_BYTES",
    "TRANSCRIPT_COMMITMENT_DOMAIN",
    "build_production_envelope",
    "select_built_audit_pending_suite",
    "statement_commitment",
    "statement_evidence_commitment",
)
