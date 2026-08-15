"""Local native-verifier and Privacy V2 atomic state boundary.

This module is the contained engineering seam between the Rust-authoritative
candidate verifier, the exact ordered twelve-field Privacy V2 statement, and
the local state publication model. It does not open a network, call Ethereum,
handle payment authority, or enable activation. This module is the direct
application-proof-to-state seam; there is no containing chain or rollup proof.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Final, Iterable, Protocol, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.governance_authority_v2 import GovernanceAuthorityV2
from app.native_public_input_projection import PublicInputProjectionV1
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    NativeVerificationReceipt,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    ProductionProofEnvelope,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    statement_commitment,
)


PUBLIC_FIELD_COUNT: Final[int] = 12
PUBLIC_FIELD_BYTES: Final[int] = 32
PUBLIC_OUTPUT_BYTES: Final[int] = PUBLIC_FIELD_COUNT * PUBLIC_FIELD_BYTES
SIDECAR_BYTES: Final[int] = 744
MAX_NATIVE_STDOUT_BYTES: Final[int] = 16 * 1024
MAX_EXECUTABLE_BYTES: Final[int] = 256 * 1024 * 1024
MAX_PROGRAM_BYTES: Final[int] = 64 * 1024 * 1024
NATIVE_VERIFIER_TIMEOUT_SECONDS: Final[float] = float(30 * 60)
V2_PROTOCOL_VERSION: Final[bytes] = (2).to_bytes(PUBLIC_FIELD_BYTES, "big")

_SETTLEMENT_DOMAIN_BINDING = b"BL/PQ512/V2/SETTLEMENT-DOMAIN/v1\x00"
_BATCH_NONCE_BINDING = b"BL/PQ512/V2/BATCH-NONCE/v1\x00"
_VALUE_COMMITMENT_BINDING = b"BL/PQ512/V2/VALUE-COMMITMENT/v1\x00"
_SETTLEMENT_COMMITMENT_BINDING = b"BL/PQ512/V2/SETTLEMENT-COMMITMENT/v1\x00"
_STATE_BINDING = b"BL/PQ512/V2/ATOMIC-STATE/v1\x00"
_DATABASE_STATE_BINDING = b"BL/PQ512/V2/DATABASE-ATOMIC-STATE/v1\x00"
_NATIVE_VERIFIER_ARTIFACT_BINDING = b"BL/PQ512/V2/NATIVE-VERIFIER-ARTIFACT/v1\x00"


class ProductionBoundaryError(ValueError):
    """Stable fail-closed errors at the local production boundary."""


def _wide(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64 or not any(value):
        raise ProductionBoundaryError(f"{label}_must_be_nonzero_512_bits")
    return value


def _field(label: str, value: object, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != PUBLIC_FIELD_BYTES:
        raise ProductionBoundaryError(f"{label}_must_be_bytes32")
    if int.from_bytes(value, "big") >= FIELD_MODULUS:
        raise ProductionBoundaryError(f"{label}_not_canonical_field")
    if nonzero and not any(value):
        raise ProductionBoundaryError(f"{label}_must_be_nonzero")
    return value


def _canonical_fields(values: Sequence[bytes]) -> tuple[bytes, ...]:
    if type(values) not in (tuple, list) or len(values) != PUBLIC_FIELD_COUNT:
        raise ProductionBoundaryError("v2_public_field_count_invalid")
    return tuple(
        _field(f"v2_public_field_{index}", value)
        for index, value in enumerate(values)
    )


def _digest(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 128:
        raise ProductionBoundaryError("binding_domain_invalid")
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 512 * 1024 * 1024:
            raise ProductionBoundaryError("binding_part_invalid")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _field_alias(value: bytes) -> bytes:
    raw = _wide("field_alias_source", value)
    return (int.from_bytes(raw, "big") % (FIELD_MODULUS - 1) + 1).to_bytes(
        PUBLIC_FIELD_BYTES, "big"
    )


def _regular_file(path: Path, *, maximum: int, label: str) -> None:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise ProductionBoundaryError(f"{label}_must_be_an_unlinked_regular_file")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ProductionBoundaryError(f"{label}_stat_failed") from exc
    if size <= 0 or size > maximum:
        raise ProductionBoundaryError(f"{label}_size_invalid")


def _file_sha3_512(path: Path, *, maximum: int, label: str) -> bytes:
    _regular_file(path, maximum=maximum, label=label)
    try:
        before = path.stat()
        digest = hashlib.sha3_512()
        total = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                total += len(chunk)
                if total > maximum:
                    raise ProductionBoundaryError(f"{label}_size_invalid")
                digest.update(chunk)
        after = path.stat()
    except OSError as exc:
        raise ProductionBoundaryError(f"{label}_read_failed") from exc
    if (
        path.is_symlink()
        or total != before.st_size
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise ProductionBoundaryError(f"{label}_changed_during_read")
    return digest.digest()


def native_verifier_artifact_identity(executable: Path, program: Path) -> bytes:
    """Bind the exact native verifier executable and AIR program bytes."""

    return _digest(
        _NATIVE_VERIFIER_ARTIFACT_BINDING,
        _file_sha3_512(
            executable,
            maximum=MAX_EXECUTABLE_BYTES,
            label="verifier_executable",
        ),
        _file_sha3_512(program, maximum=MAX_PROGRAM_BYTES, label="verifier_program"),
    )


@dataclass(frozen=True, slots=True)
class NativeStarkVerifierConfig:
    """Pinned local inputs for the Rust-authoritative verifier process."""

    executable: Path
    program: Path
    suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    public_input_projection: PublicInputProjectionV1
    timeout_seconds: float = NATIVE_VERIFIER_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        _regular_file(self.executable, maximum=MAX_EXECUTABLE_BYTES, label="verifier_executable")
        _regular_file(self.program, maximum=MAX_PROGRAM_BYTES, label="verifier_program")
        _wide("verifier_suite_id", self.suite_id)
        _wide("verifier_schema_id", self.schema_id)
        _wide("verifier_artifact_identity", self.verifier_artifact_identity)
        if (
            native_verifier_artifact_identity(self.executable, self.program)
            != self.verifier_artifact_identity
        ):
            raise ProductionBoundaryError("verifier_artifact_identity_mismatch")
        if type(self.public_input_projection) is not PublicInputProjectionV1:
            raise ProductionBoundaryError("verifier_public_input_projection_invalid")
        if self.public_input_projection.schema_id != self.schema_id:
            raise ProductionBoundaryError("verifier_public_input_projection_schema_mismatch")
        if (
            type(self.timeout_seconds) is not float
            or not 0 < self.timeout_seconds <= NATIVE_VERIFIER_TIMEOUT_SECONDS
        ):
            raise ProductionBoundaryError("verifier_timeout_invalid")


@dataclass(frozen=True, slots=True)
class NativeVerificationResult:
    """Receipt-only result; proof bytes never escape the verifier port."""

    receipt: NativeVerificationReceipt
    envelope_commitment: bytes
    statement_commitment: bytes

    def __post_init__(self) -> None:
        _wide("native_envelope_commitment", self.envelope_commitment)
        _wide("native_statement_commitment", self.statement_commitment)


class NativeVerifierPort(Protocol):
    def verify(self, envelope: ProductionProofEnvelope) -> NativeVerificationResult:
        """Verify one complete envelope and return only bound identities."""


class NativeStarkVerifierPort:
    """Run the pinned Rust verifier with no caller-controlled verification key."""

    def __init__(self, config: NativeStarkVerifierConfig) -> None:
        if type(config) is not NativeStarkVerifierConfig:
            raise TypeError("native_verifier_config_required")
        self.config = config

    def verify(self, envelope: ProductionProofEnvelope) -> NativeVerificationResult:
        if type(envelope) is not ProductionProofEnvelope:
            raise ProductionBoundaryError("native_verifier_envelope_required")
        return self.verify_encoded(envelope.encode())

    def verify_encoded(self, encoded: bytes) -> NativeVerificationResult:
        if type(encoded) is not bytes or not encoded:
            raise ProductionBoundaryError("native_verifier_encoded_envelope_invalid")
        if (
            native_verifier_artifact_identity(self.config.executable, self.config.program)
            != self.config.verifier_artifact_identity
        ):
            raise ProductionBoundaryError("native_verifier_artifact_changed")
        with tempfile.TemporaryDirectory(prefix="blind-ledger-native-verifier-") as directory:
            envelope_path = Path(directory) / "envelope.bin"
            with envelope_path.open("xb") as handle:
                handle.write(encoded)
            projection = self.config.public_input_projection
            try:
                public_outputs = ProductionProofEnvelope.public_outputs_from_encoded(encoded)
                projected = projection.encode_file(public_outputs)
            except ValueError as exc:
                raise ProductionBoundaryError("native_verifier_public_projection_invalid") from exc
            public_inputs_path = Path(directory) / "derived-public-inputs.bin"
            with public_inputs_path.open("xb") as handle:
                handle.write(projected)
            command = [
                str(self.config.executable),
                str(envelope_path),
                str(self.config.program),
                str(public_inputs_path),
                self.config.suite_id.hex(),
                self.config.schema_id.hex(),
                self.config.verifier_artifact_identity.hex(),
            ]
            command.append(projection.schema_id.hex())
            try:
                completed = subprocess.run(
                    command,
                    cwd=self.config.executable.parent,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=False,
                    timeout=self.config.timeout_seconds,
                    check=False,
                    env={
                        "PATH": os.environ.get("PATH", ""),
                        "BL_NETWORK_DISABLED": "1",
                    },
                )
            except subprocess.TimeoutExpired as exc:
                raise ProductionBoundaryError("native_verifier_timeout") from exc
            except OSError as exc:
                raise ProductionBoundaryError("native_verifier_process_unavailable") from exc

        if len(completed.stdout) > MAX_NATIVE_STDOUT_BYTES:
            raise ProductionBoundaryError("native_verifier_stdout_too_large")
        if completed.returncode != 0 or completed.stderr:
            raise ProductionBoundaryError("native_verifier_rejected")
        try:
            output = completed.stdout.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProductionBoundaryError("native_verifier_receipt_not_ascii") from exc
        lines = output.splitlines()
        if len(lines) != 1:
            raise ProductionBoundaryError("native_verifier_receipt_shape_invalid")
        try:
            receipt = NativeVerificationReceipt.from_native_line(lines[0])
        except ValueError as exc:
            raise ProductionBoundaryError("native_verifier_receipt_invalid") from exc
        if (
            receipt.proof_suite_id != self.config.suite_id
            or receipt.schema_id != self.config.schema_id
            or receipt.verifier_artifact_identity != self.config.verifier_artifact_identity
            or receipt.envelope_commitment != hashlib.sha3_512(encoded).digest()
        ):
            raise ProductionBoundaryError("native_verifier_identity_mismatch")
        try:
            verified = ProductionProofEnvelope.decode(
                encoded,
                evidence_commitment=receipt.evidence_commitment,
            )
        except ValueError as exc:
            raise ProductionBoundaryError("native_verifier_envelope_decode_failed") from exc
        expected_statement = statement_commitment(verified.public_outputs, verified.sidecar)
        expected_package = hashlib.sha3_512(
            PROOF_PACKAGE_COMMITMENT_DOMAIN + verified.proof_package
        ).digest()
        expected_transcript = hashlib.sha3_512(
            TRANSCRIPT_COMMITMENT_DOMAIN + verified.transcript_evidence
        ).digest()
        if (
            receipt.statement_commitment != expected_statement
            or receipt.proof_package_commitment != expected_package
            or receipt.transcript_commitment != expected_transcript
        ):
            raise ProductionBoundaryError("native_verifier_receipt_binding_mismatch")
        return NativeVerificationResult(
            receipt=receipt,
            envelope_commitment=receipt.envelope_commitment,
            statement_commitment=expected_statement,
        )


def _sidecar(encoded: bytes) -> CandidateSidecarV1:
    if type(encoded) is not bytes or len(encoded) != SIDECAR_BYTES:
        raise ProductionBoundaryError("v2_sidecar_shape_invalid")
    try:
        return CandidateSidecarV1.decode(encoded)
    except ValueError as exc:
        raise ProductionBoundaryError("v2_sidecar_rejected") from exc


def build_v2_public_fields(
    *,
    settlement_domain: bytes,
    batch_nonce: bytes,
    sidecar: bytes,
    governance_authority: GovernanceAuthorityV2,
    suite_id: bytes,
    schema_id: bytes,
    verifier_artifact_identity: bytes,
) -> tuple[bytes, ...]:
    """Build the exact ordered 12-field compatibility projection."""

    domain = _field("settlement_domain", settlement_domain, nonzero=True)
    nonce = _field("batch_nonce", batch_nonce, nonzero=True)
    suite = _wide("projection_suite_id", suite_id)
    schema = _wide("projection_schema_id", schema_id)
    verifier = _wide("projection_verifier_artifact_identity", verifier_artifact_identity)
    if type(governance_authority) is not GovernanceAuthorityV2:
        raise TypeError("projection_governance_authority_required")
    parsed = _sidecar(sidecar)
    if parsed.proof_suite_id != suite or parsed.schema_id != schema or parsed.verifier_artifact_identity != verifier:
        raise ProductionBoundaryError("v2_sidecar_identity_mismatch")
    if parsed.strong_settlement_domain_id != _digest(_SETTLEMENT_DOMAIN_BINDING, domain):
        raise ProductionBoundaryError("v2_sidecar_settlement_domain_mismatch")
    if parsed.epoch != governance_authority.epoch:
        raise ProductionBoundaryError("v2_sidecar_governance_epoch_mismatch")
    if parsed.strong_governance_commitment != governance_authority.commitment_512:
        raise ProductionBoundaryError("v2_sidecar_governance_authority_mismatch")
    if parsed.strong_batch_commitment != _digest(_BATCH_NONCE_BINDING, nonce):
        raise ProductionBoundaryError("v2_sidecar_batch_nonce_mismatch")
    value_commitment = _digest(
        _VALUE_COMMITMENT_BINDING,
        parsed.strong_payment_state_root_before,
        parsed.strong_payment_state_root_after,
        parsed.sequence_before.to_bytes(8, "big"),
        parsed.sequence_after.to_bytes(8, "big"),
    )
    fields = [
        V2_PROTOCOL_VERSION,
        domain,
        nonce,
        _field_alias(parsed.strong_nullifier_root_before),
        _field_alias(parsed.strong_nullifier_root_after),
        *governance_authority.public_aliases,
        _field_alias(parsed.strong_batch_commitment),
        _field_alias(value_commitment),
        bytes(PUBLIC_FIELD_BYTES),
    ]
    fields[-1] = _field_alias(
        _digest(
            _SETTLEMENT_COMMITMENT_BINDING,
            b"".join(fields[:-1]),
            sidecar,
            suite,
            schema,
            verifier,
        )
    )
    return _canonical_fields(fields)


def validate_v2_public_projection(
    *,
    public_fields: Sequence[bytes],
    sidecar: bytes,
    settlement_domain: bytes,
    batch_nonce: bytes,
    governance_authority: GovernanceAuthorityV2,
    suite_id: bytes,
    schema_id: bytes,
    verifier_artifact_identity: bytes,
) -> tuple[bytes, ...]:
    observed = _canonical_fields(public_fields)
    expected = build_v2_public_fields(
        settlement_domain=settlement_domain,
        batch_nonce=batch_nonce,
        sidecar=sidecar,
        governance_authority=governance_authority,
        suite_id=suite_id,
        schema_id=schema_id,
        verifier_artifact_identity=verifier_artifact_identity,
    )
    if observed != expected:
        raise ProductionBoundaryError("v2_public_projection_mismatch")
    return observed


def public_fields_commitment(public_fields: Sequence[bytes]) -> bytes:
    """Commit to the exact ordered twelve-field V2 projection."""

    return _digest(_SETTLEMENT_COMMITMENT_BINDING, b"".join(_canonical_fields(public_fields)))


@dataclass(frozen=True, slots=True)
class SettlementReceiptV2:
    sequence_before: int
    sequence_after: int
    nullifier_root_before: bytes
    nullifier_root_after: bytes
    public_fields_commitment: bytes
    envelope_commitment: bytes
    native_statement_commitment: bytes
    proof_suite_id: bytes
    state_binding: bytes

    def __post_init__(self) -> None:
        if type(self.sequence_before) is not int or self.sequence_before < 0:
            raise ProductionBoundaryError("settlement_receipt_sequence_before_invalid")
        if self.sequence_after != self.sequence_before + 1:
            raise ProductionBoundaryError("settlement_receipt_sequence_successor_invalid")
        _field("receipt_nullifier_root_before", self.nullifier_root_before, nonzero=True)
        _field("receipt_nullifier_root_after", self.nullifier_root_after, nonzero=True)
        if self.nullifier_root_before == self.nullifier_root_after:
            raise ProductionBoundaryError("settlement_receipt_nullifier_root_unchanged")
        for label, value in (
            ("receipt_public_fields_commitment", self.public_fields_commitment),
            ("receipt_envelope_commitment", self.envelope_commitment),
            ("receipt_native_statement_commitment", self.native_statement_commitment),
            ("receipt_state_binding", self.state_binding),
        ):
            _wide(label, value)
        _wide("receipt_proof_suite_id", self.proof_suite_id)


_VERIFIED_OPERATION_SEAL_DOMAIN = b"BL/PQ512/V2/VERIFIED-OPERATION/v1\x00"


def _verified_operation_seal(
    *,
    authority_key: bytes,
    batch_nonce: bytes,
    submitter: bytes,
    envelope_commitment: bytes,
    statement_commitment: bytes,
    evidence_commitment: bytes,
    proof_package_commitment: bytes,
    transcript_commitment: bytes,
    public_fields_commitment: bytes,
    public_fields: Sequence[bytes],
    sidecar: bytes,
    profile_id: bytes,
    suite_id: bytes,
    schema_id: bytes,
    verifier_artifact_identity: bytes,
    epoch: int,
    sequence_before: int,
    sequence_after: int,
    strong_nullifier_root_before: bytes,
    strong_nullifier_root_after: bytes,
    governance_authority: GovernanceAuthorityV2,
    strong_governance_commitment: bytes,
    strong_payment_state_root_before: bytes,
    strong_payment_state_root_after: bytes,
    strong_batch_commitment: bytes,
) -> bytes:
    key = _wide("verified_operation_authority_key", authority_key)
    payload = _digest(
        _VERIFIED_OPERATION_SEAL_DOMAIN,
        batch_nonce,
        submitter,
        envelope_commitment,
        statement_commitment,
        evidence_commitment,
        proof_package_commitment,
        transcript_commitment,
        public_fields_commitment,
        b"".join(public_fields),
        sidecar,
        profile_id,
        suite_id,
        schema_id,
        verifier_artifact_identity,
        epoch.to_bytes(8, "big"),
        sequence_before.to_bytes(8, "big"),
        sequence_after.to_bytes(8, "big"),
        strong_nullifier_root_before,
        strong_nullifier_root_after,
        governance_authority.canonical_bytes,
        strong_governance_commitment,
        strong_payment_state_root_before,
        strong_payment_state_root_after,
        strong_batch_commitment,
    )
    return hmac.new(key, payload, hashlib.sha3_512).digest()


@dataclass(frozen=True, slots=True)
class VerifiedSettlementOperationV2:
    """Verifier-authorized, sealed input to a transactional state port.

    The transactional application boundary authenticates this value with a
    store-bound, per-instance key after native receipt verification.  Storage
    rechecks that MAC, the sidecar projection, and every persisted identity
    before it can mutate state.  This prevents request code from using a
    deterministic public constructor as a verifier bypass.  Trusted code in
    the same Python process remains inside the application security boundary.
    """

    batch_nonce: bytes
    submitter: bytes
    envelope_commitment: bytes
    statement_commitment: bytes
    evidence_commitment: bytes
    proof_package_commitment: bytes
    transcript_commitment: bytes
    public_fields_commitment: bytes
    public_fields: tuple[bytes, ...]
    sidecar: bytes
    profile_id: bytes
    suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    epoch: int
    sequence_before: int
    sequence_after: int
    strong_nullifier_root_before: bytes
    strong_nullifier_root_after: bytes
    governance_authority: GovernanceAuthorityV2
    strong_governance_commitment: bytes
    strong_payment_state_root_before: bytes
    strong_payment_state_root_after: bytes
    strong_batch_commitment: bytes
    seal: bytes

    def __post_init__(self) -> None:
        _field("operation_batch_nonce", self.batch_nonce, nonzero=True)
        _wide("operation_submitter", self.submitter)
        for label, value in (
            ("operation_envelope_commitment", self.envelope_commitment),
            ("operation_statement_commitment", self.statement_commitment),
            ("operation_evidence_commitment", self.evidence_commitment),
            ("operation_proof_package_commitment", self.proof_package_commitment),
            ("operation_transcript_commitment", self.transcript_commitment),
            ("operation_public_fields_commitment", self.public_fields_commitment),
            ("operation_profile_id", self.profile_id),
            ("operation_suite_id", self.suite_id),
            ("operation_schema_id", self.schema_id),
            ("operation_verifier_artifact_identity", self.verifier_artifact_identity),
            ("operation_strong_nullifier_root_before", self.strong_nullifier_root_before),
            ("operation_strong_nullifier_root_after", self.strong_nullifier_root_after),
            ("operation_strong_governance_commitment", self.strong_governance_commitment),
            ("operation_strong_payment_state_root_before", self.strong_payment_state_root_before),
            ("operation_strong_payment_state_root_after", self.strong_payment_state_root_after),
            ("operation_strong_batch_commitment", self.strong_batch_commitment),
            ("operation_seal", self.seal),
        ):
            _wide(label, value)
        canonical_fields = _canonical_fields(self.public_fields)
        if type(self.public_fields) is not tuple or canonical_fields != self.public_fields:
            raise ProductionBoundaryError("operation_public_fields_not_canonical")
        parsed = _sidecar(self.sidecar)
        if type(self.governance_authority) is not GovernanceAuthorityV2:
            raise TypeError("operation_governance_authority_required")
        if (
            parsed.profile_id != self.profile_id
            or parsed.proof_suite_id != self.suite_id
            or parsed.schema_id != self.schema_id
            or parsed.verifier_artifact_identity != self.verifier_artifact_identity
            or parsed.epoch != self.epoch
            or parsed.sequence_before != self.sequence_before
            or parsed.sequence_after != self.sequence_after
            or parsed.strong_nullifier_root_before != self.strong_nullifier_root_before
            or parsed.strong_nullifier_root_after != self.strong_nullifier_root_after
            or parsed.epoch != self.governance_authority.epoch
            or parsed.strong_governance_commitment
            != self.governance_authority.commitment_512
            or parsed.strong_governance_commitment != self.strong_governance_commitment
            or parsed.strong_payment_state_root_before != self.strong_payment_state_root_before
            or parsed.strong_payment_state_root_after != self.strong_payment_state_root_after
            or parsed.strong_batch_commitment != self.strong_batch_commitment
        ):
            raise ProductionBoundaryError("operation_sidecar_binding_mismatch")
        if type(self.epoch) is not int or self.epoch <= 0:
            raise ProductionBoundaryError("operation_epoch_invalid")
        if type(self.sequence_before) is not int or self.sequence_before < 0:
            raise ProductionBoundaryError("operation_sequence_before_invalid")
        if self.sequence_after != self.sequence_before + 1:
            raise ProductionBoundaryError("operation_sequence_successor_invalid")

    def is_native_authorized(self, authority_key: bytes) -> bool:
        expected = _verified_operation_seal(
            authority_key=authority_key,
            batch_nonce=self.batch_nonce,
            submitter=self.submitter,
            envelope_commitment=self.envelope_commitment,
            statement_commitment=self.statement_commitment,
            evidence_commitment=self.evidence_commitment,
            proof_package_commitment=self.proof_package_commitment,
            transcript_commitment=self.transcript_commitment,
            public_fields_commitment=self.public_fields_commitment,
            public_fields=self.public_fields,
            sidecar=self.sidecar,
            profile_id=self.profile_id,
            suite_id=self.suite_id,
            schema_id=self.schema_id,
            verifier_artifact_identity=self.verifier_artifact_identity,
            epoch=self.epoch,
            sequence_before=self.sequence_before,
            sequence_after=self.sequence_after,
            strong_nullifier_root_before=self.strong_nullifier_root_before,
            strong_nullifier_root_after=self.strong_nullifier_root_after,
            governance_authority=self.governance_authority,
            strong_governance_commitment=self.strong_governance_commitment,
            strong_payment_state_root_before=self.strong_payment_state_root_before,
            strong_payment_state_root_after=self.strong_payment_state_root_after,
            strong_batch_commitment=self.strong_batch_commitment,
        )
        return hmac.compare_digest(self.seal, expected)


@dataclass(frozen=True, slots=True)
class DatabaseSettlementSnapshotV2:
    """Durable reference-state readback, including roots and audit head."""

    epoch: int
    sequence: int
    strong_nullifier_root: bytes
    strong_payment_state_root: bytes
    state_binding: bytes
    audit_head: bytes
    governance_commitment: bytes
    anti_rollback_epoch: int
    settled_batch_count: int

    def __post_init__(self) -> None:
        if type(self.epoch) is not int or self.epoch <= 0:
            raise ProductionBoundaryError("database_snapshot_epoch_invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ProductionBoundaryError("database_snapshot_sequence_invalid")
        if type(self.anti_rollback_epoch) is not int or self.anti_rollback_epoch < 0:
            raise ProductionBoundaryError("database_snapshot_anti_rollback_epoch_invalid")
        if type(self.settled_batch_count) is not int or self.settled_batch_count < 0:
            raise ProductionBoundaryError("database_snapshot_count_invalid")
        for label, value in (
            ("database_snapshot_nullifier_root", self.strong_nullifier_root),
            ("database_snapshot_payment_state_root", self.strong_payment_state_root),
            ("database_snapshot_binding", self.state_binding),
            ("database_snapshot_audit_head", self.audit_head),
            ("database_snapshot_governance_commitment", self.governance_commitment),
        ):
            _wide(label, value)


class TransactionalSettlementStoragePort(Protocol):
    """Internal port used by the application proof boundary for one durable commit."""

    def _bind_native_authority(self, authority_key: bytes) -> None:
        """Bind one per-settlement MAC authority before accepting operations."""

    def _commit_verified(self, operation: VerifiedSettlementOperationV2) -> SettlementReceiptV2:
        """Commit one MAC-authenticated operation through the internal seam."""

    def snapshot(self) -> DatabaseSettlementSnapshotV2:
        """Read the committed state and audit head."""

    def identity_snapshot(self) -> object:
        """Read the active versioned verifier/database identity."""

    def _governance_authority_for_commitment(
        self, commitment: bytes
    ) -> GovernanceAuthorityV2:
        """Resolve an immutable recorded authority for exact retry validation."""

    def verify_integrity(self) -> None:
        """Fail closed if the durable reference is internally inconsistent."""

    def close(self) -> None:
        """Release local resources."""


@dataclass(frozen=True, slots=True)
class SettlementSnapshotV2:
    sequence: int
    nullifier_root: bytes
    state_binding: bytes
    settled_batch_count: int

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ProductionBoundaryError("settlement_snapshot_sequence_invalid")
        _field("settlement_snapshot_nullifier_root", self.nullifier_root, nonzero=True)
        _wide("settlement_snapshot_binding", self.state_binding)
        if type(self.settled_batch_count) is not int or self.settled_batch_count < 0:
            raise ProductionBoundaryError("settlement_snapshot_count_invalid")


class LocalSettlementV2:
    """Atomic, nonactivating Privacy V2 state/settlement model."""

    def __init__(
        self,
        *,
        verifier: NativeVerifierPort,
        settlement_domain: bytes,
        governance_authority: GovernanceAuthorityV2,
        initial_nullifier_root: bytes,
        authorized_submitters: Iterable[bytes],
    ) -> None:
        # Protocol runtime checks are intentionally avoided; the first
        # submit performs the exact method check without accepting a flag.
        if not callable(getattr(verifier, "verify", None)):
            raise TypeError("settlement_native_verifier_required")
        self._verifier = verifier
        self._settlement_domain = _field("settlement_domain", settlement_domain, nonzero=True)
        if type(governance_authority) is not GovernanceAuthorityV2:
            raise TypeError("settlement_governance_authority_required")
        self._governance_authority = governance_authority
        self._current_nullifier_root = _field(
            "initial_nullifier_root", initial_nullifier_root, nonzero=True
        )
        self._sequence = 0
        self._authorized_submitters = frozenset(
            _wide("authorized_submitter", value) for value in authorized_submitters
        )
        if not self._authorized_submitters:
            raise ProductionBoundaryError("settlement_submitters_empty")
        self._settled_nonces: set[bytes] = set()
        self._settled_commitments: set[bytes] = set()
        self._state_binding = _digest(
            _STATE_BINDING,
            self._current_nullifier_root,
            self._sequence.to_bytes(8, "big"),
        )

    def snapshot(self) -> SettlementSnapshotV2:
        return SettlementSnapshotV2(
            sequence=self._sequence,
            nullifier_root=self._current_nullifier_root,
            state_binding=self._state_binding,
            settled_batch_count=len(self._settled_nonces),
        )

    def submit(
        self,
        *,
        envelope: ProductionProofEnvelope,
        batch_nonce: bytes,
        submitter: bytes,
    ) -> SettlementReceiptV2:
        if type(envelope) is not ProductionProofEnvelope:
            raise ProductionBoundaryError("settlement_envelope_required")
        submitter_id = _wide("settlement_submitter", submitter)
        if submitter_id not in self._authorized_submitters:
            raise ProductionBoundaryError("settlement_submitter_not_authorized")
        nonce = _field("settlement_batch_nonce", batch_nonce, nonzero=True)
        if nonce in self._settled_nonces:
            raise ProductionBoundaryError("settlement_batch_nonce_replay")
        parsed_sidecar = _sidecar(envelope.sidecar)
        if parsed_sidecar.sequence_before != self._sequence:
            raise ProductionBoundaryError("settlement_sequence_stale")
        if _field_alias(parsed_sidecar.strong_nullifier_root_before) != self._current_nullifier_root:
            raise ProductionBoundaryError("settlement_nullifier_root_stale")
        fields = validate_v2_public_projection(
            public_fields=tuple(
                envelope.public_outputs[index : index + PUBLIC_FIELD_BYTES]
                for index in range(0, PUBLIC_OUTPUT_BYTES, PUBLIC_FIELD_BYTES)
            ),
            sidecar=envelope.sidecar,
            settlement_domain=self._settlement_domain,
            batch_nonce=nonce,
            governance_authority=self._governance_authority,
            suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
        )
        if fields[2] in self._settled_nonces:
            raise ProductionBoundaryError("settlement_batch_nonce_replay")
        if fields[11] in self._settled_commitments:
            raise ProductionBoundaryError("settlement_commitment_replay")
        result = self._verifier.verify(envelope)
        if type(result) is not NativeVerificationResult:
            raise ProductionBoundaryError("settlement_verifier_result_invalid")
        receipt = result.receipt
        if type(receipt) is not NativeVerificationReceipt:
            raise ProductionBoundaryError("settlement_verifier_receipt_invalid")
        expected_envelope = hashlib.sha3_512(envelope.encode()).digest()
        expected_statement = statement_commitment(envelope.public_outputs, envelope.sidecar)
        expected_package = hashlib.sha3_512(
            PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package
        ).digest()
        expected_transcript = hashlib.sha3_512(
            TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence
        ).digest()
        if (
            result.envelope_commitment != expected_envelope
            or receipt.envelope_commitment != expected_envelope
            or result.statement_commitment != expected_statement
            or receipt.statement_commitment != expected_statement
            or receipt.evidence_commitment != envelope.evidence_commitment
            or receipt.proof_package_commitment != expected_package
            or receipt.transcript_commitment != expected_transcript
            or receipt.proof_suite_id != envelope.suite_id
            or receipt.schema_id != envelope.schema_id
            or receipt.verifier_artifact_identity != envelope.verifier_artifact_identity
        ):
            raise ProductionBoundaryError("settlement_verifier_binding_mismatch")
        next_root = _field_alias(parsed_sidecar.strong_nullifier_root_after)
        next_binding = _digest(
            _STATE_BINDING,
            self._state_binding,
            fields[2],
            next_root,
            result.envelope_commitment,
            result.receipt.evidence_commitment,
        )
        receipt = SettlementReceiptV2(
            sequence_before=self._sequence,
            sequence_after=parsed_sidecar.sequence_after,
            nullifier_root_before=self._current_nullifier_root,
            nullifier_root_after=next_root,
            public_fields_commitment=public_fields_commitment(fields),
            envelope_commitment=result.envelope_commitment,
            native_statement_commitment=result.statement_commitment,
            proof_suite_id=receipt.proof_suite_id,
            state_binding=next_binding,
        )
        # No state mutation occurs before every structural and native check
        # above succeeds.  The three writes below are the atomic publication
        # point for this in-memory local boundary.
        self._settled_nonces.add(fields[2])
        self._settled_commitments.add(fields[11])
        self._current_nullifier_root = next_root
        self._sequence = receipt.sequence_after
        self._state_binding = receipt.state_binding
        return receipt


__all__ = (
    "DatabaseSettlementSnapshotV2",
    "GovernanceAuthorityV2",
    "LocalSettlementV2",
    "NativeStarkVerifierConfig",
    "NativeStarkVerifierPort",
    "NativeVerificationResult",
    "ProductionBoundaryError",
    "SettlementReceiptV2",
    "SettlementSnapshotV2",
    "TransactionalSettlementStoragePort",
    "VerifiedSettlementOperationV2",
    "build_v2_public_fields",
    "native_verifier_artifact_identity",
    "public_fields_commitment",
    "validate_v2_public_projection",
)
