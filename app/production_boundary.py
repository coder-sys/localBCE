"""Local native-verifier and Privacy V2 settlement boundary.

This module is the contained engineering seam between the Rust-authoritative
candidate verifier, the exact ordered twelve-field Privacy V2 statement, and
the local state publication model.  It does not open a network, call
Ethereum, handle payment authority, or enable activation.  The protected
Solidity contracts remain the on-chain interface contract; this module makes
their exact binding executable and fail closed in the local/synthetic stack.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Final, Iterable, Protocol, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
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
MAX_PROGRAM_BYTES: Final[int] = 64 * 1024 * 1024
MAX_PUBLIC_INPUT_BYTES: Final[int] = 16 * 1024 * 1024
NATIVE_VERIFIER_TIMEOUT_SECONDS: Final[float] = float(30 * 60)
V2_PROTOCOL_VERSION: Final[bytes] = (2).to_bytes(PUBLIC_FIELD_BYTES, "big")

_SETTLEMENT_DOMAIN_BINDING = b"BL/PQ512/V2/SETTLEMENT-DOMAIN/v1\x00"
_GOVERNANCE_BINDING = b"BL/PQ512/V2/GOVERNED-ROOTS/v1\x00"
_BATCH_NONCE_BINDING = b"BL/PQ512/V2/BATCH-NONCE/v1\x00"
_VALUE_COMMITMENT_BINDING = b"BL/PQ512/V2/VALUE-COMMITMENT/v1\x00"
_SETTLEMENT_COMMITMENT_BINDING = b"BL/PQ512/V2/SETTLEMENT-COMMITMENT/v1\x00"
_STATE_BINDING = b"BL/PQ512/V2/ATOMIC-STATE/v1\x00"


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


@dataclass(frozen=True, slots=True)
class NativeStarkVerifierConfig:
    """Pinned local inputs for the Rust-authoritative verifier process."""

    executable: Path
    program: Path
    public_inputs: Path
    suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    timeout_seconds: float = NATIVE_VERIFIER_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        _regular_file(self.executable, maximum=256 * 1024 * 1024, label="verifier_executable")
        _regular_file(self.program, maximum=MAX_PROGRAM_BYTES, label="verifier_program")
        _regular_file(
            self.public_inputs,
            maximum=MAX_PUBLIC_INPUT_BYTES,
            label="verifier_public_inputs",
        )
        _wide("verifier_suite_id", self.suite_id)
        _wide("verifier_schema_id", self.schema_id)
        _wide("verifier_artifact_identity", self.verifier_artifact_identity)
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
        with tempfile.TemporaryDirectory(prefix="blind-ledger-native-verifier-") as directory:
            envelope_path = Path(directory) / "envelope.bin"
            with envelope_path.open("xb") as handle:
                handle.write(encoded)
            command = [
                str(self.config.executable),
                str(envelope_path),
                str(self.config.program),
                str(self.config.public_inputs),
                self.config.suite_id.hex(),
                self.config.schema_id.hex(),
                self.config.verifier_artifact_identity.hex(),
            ]
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


@dataclass(frozen=True, slots=True)
class GovernedRootsV2:
    claim_source_root: bytes
    oracle_facts_root: bytes
    policy_root: bytes
    ruleset_root: bytes

    def __post_init__(self) -> None:
        for name, value in (
            ("claim_source_root", self.claim_source_root),
            ("oracle_facts_root", self.oracle_facts_root),
            ("policy_root", self.policy_root),
            ("ruleset_root", self.ruleset_root),
        ):
            _field(name, value, nonzero=True)

    @property
    def commitment_512(self) -> bytes:
        return _digest(
            _GOVERNANCE_BINDING,
            self.claim_source_root,
            self.oracle_facts_root,
            self.policy_root,
            self.ruleset_root,
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
    governed_roots: GovernedRootsV2,
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
    parsed = _sidecar(sidecar)
    if parsed.proof_suite_id != suite or parsed.schema_id != schema or parsed.verifier_artifact_identity != verifier:
        raise ProductionBoundaryError("v2_sidecar_identity_mismatch")
    if parsed.strong_settlement_domain_id != _digest(_SETTLEMENT_DOMAIN_BINDING, domain):
        raise ProductionBoundaryError("v2_sidecar_settlement_domain_mismatch")
    if parsed.strong_governance_commitment != governed_roots.commitment_512:
        raise ProductionBoundaryError("v2_sidecar_governed_roots_mismatch")
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
        governed_roots.claim_source_root,
        governed_roots.oracle_facts_root,
        governed_roots.policy_root,
        governed_roots.ruleset_root,
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
    governed_roots: GovernedRootsV2,
    suite_id: bytes,
    schema_id: bytes,
    verifier_artifact_identity: bytes,
) -> tuple[bytes, ...]:
    observed = _canonical_fields(public_fields)
    expected = build_v2_public_fields(
        settlement_domain=settlement_domain,
        batch_nonce=batch_nonce,
        sidecar=sidecar,
        governed_roots=governed_roots,
        suite_id=suite_id,
        schema_id=schema_id,
        verifier_artifact_identity=verifier_artifact_identity,
    )
    if observed != expected:
        raise ProductionBoundaryError("v2_public_projection_mismatch")
    return observed


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
        governed_roots: GovernedRootsV2,
        initial_nullifier_root: bytes,
        authorized_submitters: Iterable[bytes],
    ) -> None:
        # Protocol runtime checks are intentionally avoided; the first
        # submit performs the exact method check without accepting a flag.
        if not callable(getattr(verifier, "verify", None)):
            raise TypeError("settlement_native_verifier_required")
        self._verifier = verifier
        self._settlement_domain = _field("settlement_domain", settlement_domain, nonzero=True)
        if type(governed_roots) is not GovernedRootsV2:
            raise TypeError("settlement_governed_roots_required")
        self._governed_roots = governed_roots
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
            governed_roots=self._governed_roots,
            suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
        )
        if fields[2] in self._settled_nonces:
            raise ProductionBoundaryError("settlement_batch_nonce_replay")
        if fields[11] in self._settled_commitments:
            raise ProductionBoundaryError("settlement_commitment_replay")
        result = self._verifier.verify(envelope)
        if result.receipt.proof_suite_id != envelope.suite_id:
            raise ProductionBoundaryError("settlement_verifier_suite_mismatch")
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
            public_fields_commitment=_digest(_SETTLEMENT_COMMITMENT_BINDING, b"".join(fields)),
            envelope_commitment=result.envelope_commitment,
            native_statement_commitment=result.statement_commitment,
            proof_suite_id=result.receipt.proof_suite_id,
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
    "GovernedRootsV2",
    "LocalSettlementV2",
    "NativeStarkVerifierConfig",
    "NativeStarkVerifierPort",
    "NativeVerificationResult",
    "ProductionBoundaryError",
    "SettlementReceiptV2",
    "SettlementSnapshotV2",
    "build_v2_public_fields",
    "validate_v2_public_projection",
)
