"""Proof-native authentication for the fixed-shape state AIR component.

The state-plane module deliberately owns the state relation and its canonical
private witness.  This module owns the next boundary: it sends that exact AIR
program/execution through the existing masked AIR/FRI prover, authenticates
the complete dual-PQ transcript, and exposes only a digest-only component
receipt for the outer H4 coordinator.

This is a component proof, not global suite selection or activation.
`build_state_air_binding_bytes` emits the version-3 private H4 envelope; the
native coordinator independently checks its exact state witness and FRI
package before binding the resulting identity into the parent/transcript/
receipt.  Full custom-H4 GKR/PCS composition and the complete
simulator/leakage/security ledger remain open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
from pathlib import Path
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    SelectedProofResult,
    prove_selected_air_streaming,
)
from experiments.bl_pq512_crypto_foundation.state_plane import (
    SHA3_512_LENGTH,
    StateTransitionProof,
    independently_verify_state_transition,
)
from experiments.bl_pq512_crypto_foundation.transparent_hash_code_candidate import (
    TransparentHashCodeCommitment,
    bind_authenticated_public_coin,
)
from experiments.fixed_shape_claim_air.air_binary_ir import (
    air_binary_commitment,
    air_program_commitment,
    encode_air_execution,
    encode_air_program,
)
from experiments.fixed_shape_claim_air.state_relation_executable_air import (
    PROGRAM_ID,
    build_state_relation_air,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


STATUS: Final[str] = "STATE_AIR_PROOF_COMPONENT_VERIFIED_NONACTIVATING"
COMPONENT_ID: Final[str] = "BL-PQ512-STATE-AIR-PROOF-V1"
PUBLIC_OUTPUT_BYTES: Final[int] = 384
SIDECAR_BYTES: Final[int] = 744
STATE_AIR_COMPOSED_BINDING_VERSION: Final[int] = 3
TRANSPARENT_STATE_AIR_COMPOSED_BINDING_VERSION: Final[int] = 6
STATE_AIR_COMPOSED_FRAGMENT_MAGIC: Final[bytes] = b"BLSA02"
PROOF_PACKAGE_MAGIC: Final[bytes] = b"BLPQSPK1"
PROOF_PACKAGE_VERSION: Final[int] = 2
PROOF_PACKAGE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_PROOF_PACKAGE_BYTES: Final[int] = 512 * 1024 * 1024
_DOMAIN: Final[bytes] = b"BL/PQ512/STATE-AIR-PROOF/v1\x00"
_SIDECAR_DOMAIN: Final[bytes] = b"BL/PQ512/STATE-AIR-SIDECAR/v1\x00"
_PROOF_PACKAGE_DOMAIN: Final[bytes] = b"BL/PQ512/STATE-AIR-PROOF-PACKAGE/v2\x00"
_COMPOSED_FRAGMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/STATE-PLANE/AIR-FRAGMENT/v2\x00"
)
_COMPOSED_H4_DOMAIN: Final[bytes] = b"BL/PQ512/STATE-PLANE/H4-COMPOSITION/v2\x00"
_COMPOSED_BINDING_DOMAIN: Final[bytes] = (
    b"BL/PQ512/STATE-PLANE/H4-BINDING-INPUT/v2\x00"
)
_COMPONENT_BINDING_DOMAIN: Final[bytes] = (
    b"BL/PQ512/STATE-AIR-PROOF/COMPONENT-BINDING/v1\x00"
)
_TRANSPARENT_COMPONENT_BINDING_DOMAIN: Final[bytes] = (
    b"BL/PQ512/STATE-AIR-PROOF/COMPONENT-BINDING/v2\x00"
)
_TRANSPARENT_COMPOSED_FRAGMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/STATE-PLANE/AIR-FRAGMENT/v3\x00"
)
_TRANSPARENT_COMPOSED_H4_DOMAIN: Final[bytes] = (
    b"BL/PQ512/STATE-PLANE/H4-COMPOSITION/v3\x00"
)
_TRANSPARENT_COMPOSED_BINDING_DOMAIN: Final[bytes] = (
    b"BL/PQ512/STATE-PLANE/H4-BINDING-INPUT/v3\x00"
)


def _bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise StructuralError(f"state_air_proof_{label}_length_invalid")
    if nonzero and not any(value):
        raise StructuralError(f"state_air_proof_{label}_zero")
    return value


def _hash(*parts: bytes) -> bytes:
    digest = sha3_512(_DOMAIN)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise StructuralError("state_air_proof_hash_part_invalid")
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


def proof_package_commitment(package: bytes) -> bytes:
    if type(package) is not bytes or len(package) != PROOF_PACKAGE_BYTES:
        raise StructuralError("state_air_proof_package_shape_invalid")
    return sha3_512(_PROOF_PACKAGE_DOMAIN + package).digest()


def _validate_proof_package(package: bytes, proof_bytes: int) -> None:
    if (
        type(package) is not bytes
        or len(package) != PROOF_PACKAGE_BYTES
        or package[:8] != PROOF_PACKAGE_MAGIC
        or int.from_bytes(package[8:10], "big") != PROOF_PACKAGE_VERSION
    ):
        raise StructuralError("state_air_proof_package_header_invalid")
    cursor = 10

    def take(length: int) -> bytes:
        nonlocal cursor
        if type(length) is not int or length < 0 or cursor + length > len(package):
            raise StructuralError("state_air_proof_package_truncated")
        value = package[cursor : cursor + length]
        cursor += length
        return value

    def u32() -> int:
        return int.from_bytes(take(4), "big")

    program_length = u32()
    if program_length == 0:
        raise StructuralError("state_air_proof_package_program_empty")
    take(program_length)
    public_count = u32()
    if public_count == 0 or public_count > 1_000_000:
        raise StructuralError("state_air_proof_package_public_input_count_invalid")
    take(public_count * 4)
    bundle_length = u32()
    if bundle_length == 0:
        raise StructuralError("state_air_proof_package_bundle_empty")
    take(bundle_length)
    claim_count = u32()
    if claim_count == 0 or claim_count > 1_000:
        raise StructuralError("state_air_proof_package_claim_count_invalid")
    for _ in range(claim_count):
        take(1)
        value_count = u32()
        if value_count == 0 or value_count > 1_000_000:
            raise StructuralError("state_air_proof_package_claim_width_invalid")
        take(value_count * 64 * 2)
    take(64)
    supplied_proof_bytes = int.from_bytes(take(8), "big")
    if supplied_proof_bytes != proof_bytes or supplied_proof_bytes == 0:
        raise StructuralError("state_air_proof_package_proof_size_mismatch")
    take(supplied_proof_bytes)
    padding = take(len(package) - cursor)
    if not padding or any(padding):
        raise StructuralError("state_air_proof_package_trailing_bytes")


def _state_hash(domain: bytes, *parts: bytes) -> bytes:
    digest = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise StructuralError("state_air_composed_hash_part_invalid")
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


def _component_binding_digest(proof: StateTransitionProof) -> bytes:
    """Bind the sidecar to state identities without rebuilding root AIR."""

    parts = [
        proof.before.root_512,
        proof.after.root_512,
        proof.projection_digest_512,
        proof.statement_digest_512,
        proof.transition_digest_512,
        proof.public_coin_digest_512,
        proof.commitment.commitment_digest_512,
        proof.proof_identity_512,
        proof.attempt_id_512,
        proof.receipt.receipt_digest_512,
    ]
    if type(proof.commitment) is TransparentHashCodeCommitment:
        parts.append(bind_authenticated_public_coin(proof.commitment, proof.public_coin_digest_512))
        domain = _TRANSPARENT_COMPONENT_BINDING_DOMAIN
    else:
        domain = _COMPONENT_BINDING_DOMAIN
    return _state_hash(domain, *parts)


def _component_public_outputs(proof: StateTransitionProof) -> bytes:
    encoded = b"".join(proof.projection_12)
    if len(encoded) != PUBLIC_OUTPUT_BYTES:
        raise StructuralError("state_air_proof_public_output_shape_invalid")
    return encoded


def _component_sidecar(
    proof: StateTransitionProof,
) -> bytes:
    """Return a fixed, public, digest-only sidecar for the state proof.

    The sidecar intentionally carries identities and roots only.  The private
    snapshots, slot values, operations, masks, and AIR trace are never put in
    the authenticated public-coin payload.
    """

    fields = (
        proof.before.root_512,
        proof.after.root_512,
        proof.statement_digest_512,
        proof.transition_digest_512,
        proof.commitment.commitment_digest_512,
        proof.proof_identity_512,
        proof.attempt_id_512,
        proof.receipt.receipt_digest_512,
        _component_binding_digest(proof),
        proof.projection_digest_512,
        proof.public_coin_digest_512,
    )
    for value in fields:
        _bytes("sidecar_field", value, SHA3_512_LENGTH, nonzero=True)
    encoded = _SIDECAR_DOMAIN + bytes((1,)) + b"".join(fields)
    reserved = SIDECAR_BYTES - len(encoded)
    if reserved < 0:
        raise StructuralError("state_air_proof_sidecar_overflow")
    # The reserved tail is part of the versioned grammar, not unconstrained
    # caller input.  It keeps the existing fixed sidecar width without adding
    # another semantic field or exposing private witness material.
    encoded += bytes(reserved)
    if len(encoded) != SIDECAR_BYTES:
        raise StructuralError("state_air_proof_sidecar_shape_invalid")
    return encoded


def _attribution_digest(result: SelectedProofResult) -> bytes:
    attribution = result.proof_attribution
    values = tuple(
        getattr(attribution, name)
        for name in (
            "header_bytes",
            "initial_index_bytes",
            "mask_opening_bytes",
            "main_opening_bytes",
            "interaction_opening_bytes",
            "composition_opening_bytes",
            "next_main_opening_bytes",
            "next_interaction_opening_bytes",
            "fri_layer_count_bytes",
            "fri_opened_value_bytes",
            "fri_log_size_bytes",
            "fri_merkle_metadata_bytes",
            "fri_path_digest_bytes",
            "query_count",
            "fri_layer_count",
            "fri_opened_value_count",
            "fri_path_digest_count",
        )
    )
    return _hash(
        b"attribution",
        *(value.to_bytes(8, "big") for value in values),
    )


@dataclass(frozen=True, slots=True)
class StateAirProofEvidence:
    """Result of one independently verified state AIR proof.

    The canonical evidence is digest-only; the private encoded AIR bytes are
    retained so binding assembly can reuse the exact proof-phase encoding
    without rebuilding the full state trace.
    """

    component_id: str
    program_id: str
    program_commitment_512: bytes
    execution_commitment_512: bytes
    proof_suite_id_512: bytes
    schedule_commitment_512: bytes
    transcript_root_512: bytes
    evidence_commitment_512: bytes
    proof_package_commitment_512: bytes
    proof_identity_512: bytes
    public_input_digest_512: bytes
    attribution_digest_512: bytes
    proof_bytes: int
    worker_report_digest_512: bytes
    proof_package_bytes: bytes = field(default=b"", repr=False, compare=False)
    status: str = STATUS
    state_air_program_bytes: bytes = field(default=b"", repr=False, compare=False)
    state_air_execution_bytes: bytes = field(default=b"", repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.component_id != COMPONENT_ID or self.program_id != PROGRAM_ID:
            raise StructuralError("state_air_proof_component_identity_invalid")
        for label, value in (
            ("program_commitment", self.program_commitment_512),
            ("execution_commitment", self.execution_commitment_512),
            ("proof_suite", self.proof_suite_id_512),
            ("schedule_commitment", self.schedule_commitment_512),
            ("transcript_root", self.transcript_root_512),
            ("evidence_commitment", self.evidence_commitment_512),
            ("proof_package_commitment", self.proof_package_commitment_512),
            ("proof_identity", self.proof_identity_512),
            ("public_input_digest", self.public_input_digest_512),
            ("attribution_digest", self.attribution_digest_512),
            ("worker_report_digest", self.worker_report_digest_512),
        ):
            _bytes(label, value, SHA3_512_LENGTH, nonzero=True)
        if type(self.proof_bytes) is not int or self.proof_bytes <= 0:
            raise StructuralError("state_air_proof_size_invalid")
        _validate_proof_package(self.proof_package_bytes, self.proof_bytes)
        if proof_package_commitment(self.proof_package_bytes) != self.proof_package_commitment_512:
            raise StructuralError("state_air_proof_package_commitment_mismatch")
        if type(self.state_air_program_bytes) is not bytes or not self.state_air_program_bytes:
            raise StructuralError("state_air_proof_program_bytes_missing")
        if type(self.state_air_execution_bytes) is not bytes or not self.state_air_execution_bytes:
            raise StructuralError("state_air_proof_execution_bytes_missing")
        if air_program_commitment(self.state_air_program_bytes) != self.program_commitment_512:
            raise StructuralError("state_air_proof_program_bytes_commitment_mismatch")
        if air_binary_commitment(self.state_air_execution_bytes) != self.execution_commitment_512:
            raise StructuralError("state_air_proof_execution_bytes_commitment_mismatch")
        if self.status != STATUS:
            raise StructuralError("state_air_proof_status_invalid")

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                COMPONENT_ID.encode("ascii"),
                b"\x00",
                self.program_id.encode("ascii"),
                b"\x00",
                self.program_commitment_512,
                self.execution_commitment_512,
                self.proof_package_commitment_512,
                self.proof_suite_id_512,
                self.schedule_commitment_512,
                self.transcript_root_512,
                self.evidence_commitment_512,
                self.proof_identity_512,
                self.public_input_digest_512,
                self.attribution_digest_512,
                self.proof_bytes.to_bytes(8, "big"),
                self.worker_report_digest_512,
            )
        )


def _evidence(
    proof: StateTransitionProof,
    program_commitment: bytes,
    execution_commitment: bytes,
    instance_public_values: tuple[int, ...],
    program_bytes: bytes,
    execution_bytes: bytes,
    result: SelectedProofResult,
    proof_package_bytes: bytes,
) -> StateAirProofEvidence:
    transcript = result.transcript
    bundle = result.challenge_bundle
    evidence = StateAirProofEvidence(
        component_id=COMPONENT_ID,
        program_id=PROGRAM_ID,
        program_commitment_512=program_commitment,
        execution_commitment_512=execution_commitment,
        proof_suite_id_512=bundle.proof_suite_id,
        schedule_commitment_512=bundle.schedule_commitment,
        transcript_root_512=transcript.final_transcript_root,
        evidence_commitment_512=bundle.evidence_commitment,
        proof_package_commitment_512=proof_package_commitment(proof_package_bytes),
        proof_identity_512=_hash(
            b"proof-identity",
            proof_package_commitment(proof_package_bytes),
            bundle.proof_suite_id,
            bundle.schedule_commitment,
            bundle.final_transcript_root,
            bundle.evidence_commitment,
            bundle.main_trace_root,
            bundle.interaction_trace_root,
            bundle.composition_root,
            bundle.oods_claims_commitment,
            bundle.fri_mask_root,
            bundle.fri_batch_derivation_commitment,
            b"".join(bundle.fri_layer_roots),
        ),
        public_input_digest_512=_hash(
            b"public-inputs",
            b"".join(value.to_bytes(4, "big") for value in instance_public_values),
            _component_public_outputs(proof),
        ),
        attribution_digest_512=_attribution_digest(result),
        proof_bytes=result.proof_bytes,
        worker_report_digest_512=_hash(b"worker-report", result.worker_report.encode("ascii")),
        proof_package_bytes=proof_package_bytes,
        state_air_program_bytes=program_bytes,
        state_air_execution_bytes=execution_bytes,
    )
    return StateAirProofEvidence(
        component_id=evidence.component_id,
        program_id=evidence.program_id,
        program_commitment_512=evidence.program_commitment_512,
        execution_commitment_512=evidence.execution_commitment_512,
        proof_suite_id_512=evidence.proof_suite_id_512,
        schedule_commitment_512=evidence.schedule_commitment_512,
        transcript_root_512=evidence.transcript_root_512,
        evidence_commitment_512=evidence.evidence_commitment_512,
        proof_package_commitment_512=evidence.proof_package_commitment_512,
        proof_identity_512=evidence.proof_identity_512,
        public_input_digest_512=evidence.public_input_digest_512,
        attribution_digest_512=evidence.attribution_digest_512,
        proof_bytes=evidence.proof_bytes,
        worker_report_digest_512=evidence.worker_report_digest_512,
        proof_package_bytes=proof_package_bytes,
        state_air_program_bytes=program_bytes,
        state_air_execution_bytes=execution_bytes,
    )


def prove_state_air(
    proof: StateTransitionProof,
    *,
    worker_executable: Path,
    secret_mask_seed: bytes,
    session_id: bytes,
    contributors: tuple[object, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
    scratch_parent: Path,
) -> StateAirProofEvidence:
    """Prove and independently verify the exact state AIR witness once."""

    if type(proof) is not StateTransitionProof:
        raise StructuralError("state_air_proof_state_transition_required")
    if (
        not isinstance(scratch_parent, Path)
        or not scratch_parent.is_absolute()
        or not scratch_parent.is_dir()
        or scratch_parent.is_symlink()
    ):
        raise StructuralError("state_air_proof_scratch_parent_invalid")
    independently_verify_state_transition(proof)
    instance = build_state_relation_air(proof)
    if instance.program.program_id != PROGRAM_ID:
        raise StructuralError("state_air_proof_program_identity_invalid")
    program_bytes = encode_air_program(instance.program)
    execution_bytes = encode_air_execution(
        instance.program,
        instance.traces,
        instance.public_values,
    )
    program_commitment = air_program_commitment(program_bytes)
    execution_commitment = air_binary_commitment(execution_bytes)
    # State AIR is intentionally streamed: the exact K128/K512 state traces
    # are large enough that a monolithic worker would violate the repository's
    # measured laptop resource discipline before it reaches proof generation.
    proof_package_path = scratch_parent / f"bl-state-air-proof-{session_id.hex()}.bin"
    if proof_package_path.exists():
        raise StructuralError("state_air_proof_package_path_exists")
    try:
        result = prove_selected_air_streaming(
            worker_executable=worker_executable,
            program=instance.program,
            traces=instance.traces,
            public_inputs=instance.public_values,
            scratch_parent=scratch_parent,
            secret_mask_seed=secret_mask_seed,
            session_id=session_id,
            public_outputs=_component_public_outputs(proof),
            sidecar=_component_sidecar(proof),
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
            proof_export_path=proof_package_path,
        )
        proof_package_bytes = proof_package_path.read_bytes()
    finally:
        if proof_package_path.exists():
            proof_package_path.unlink()
    return _evidence(
        proof,
        program_commitment,
        execution_commitment,
        instance.public_values,
        program_bytes,
        execution_bytes,
        result,
        proof_package_bytes,
    )


def build_state_air_binding_bytes(
    proof: StateTransitionProof,
    evidence: StateAirProofEvidence,
) -> bytes:
    """Build the v3 private H4 envelope with the proof-native component.

    The package and compact AIR execution remain private.  The native H4
    coordinator independently parses the state operations, checks the compact
    witness columns against them, and verifies the selected FRI package before
    it derives the parent/transcript/receipt identities.
    """

    if type(proof) is not StateTransitionProof or type(evidence) is not StateAirProofEvidence:
        raise StructuralError("state_air_composed_binding_types_invalid")
    independently_verify_state_transition(proof)
    program_bytes = evidence.state_air_program_bytes
    execution_bytes = evidence.state_air_execution_bytes
    if (
        air_program_commitment(program_bytes) != evidence.program_commitment_512
        or air_binary_commitment(execution_bytes) != evidence.execution_commitment_512
    ):
        raise StructuralError("state_air_composed_binding_air_commitment_mismatch")
    program_commitment = evidence.program_commitment_512
    execution_commitment = evidence.execution_commitment_512
    package_commitment = proof_package_commitment(evidence.proof_package_bytes)
    if package_commitment != evidence.proof_package_commitment_512:
        raise StructuralError("state_air_composed_binding_package_commitment_mismatch")
    canonical_evidence = evidence.canonical_bytes
    transparent_coin_binding = (
        bind_authenticated_public_coin(proof.commitment, proof.public_coin_digest_512)
        if type(proof.commitment) is TransparentHashCodeCommitment
        else b""
    )
    fragment = _state_hash(
        (
            _TRANSPARENT_COMPOSED_FRAGMENT_DOMAIN
            if transparent_coin_binding
            else _COMPOSED_FRAGMENT_DOMAIN
        ),
        proof.before.root_512,
        proof.after.root_512,
        proof.projection_digest_512,
        proof.statement_digest_512,
        proof.transition_digest_512,
        proof.commitment.commitment_digest_512,
        proof.proof_identity_512,
        proof.receipt.receipt_digest_512,
        program_commitment,
        execution_commitment,
        package_commitment,
        evidence.proof_identity_512,
        canonical_evidence,
        *(() if not transparent_coin_binding else (transparent_coin_binding,)),
    )
    composition = _state_hash(
        (
            _TRANSPARENT_COMPOSED_H4_DOMAIN
            if transparent_coin_binding
            else _COMPOSED_H4_DOMAIN
        ),
        proof.statement_digest_512,
        proof.transition_digest_512,
        proof.projection_digest_512,
        proof.public_coin_digest_512,
        proof.commitment.commitment_digest_512,
        proof.proof_identity_512,
        proof.receipt.receipt_digest_512,
        program_commitment,
        execution_commitment,
        package_commitment,
        evidence.proof_identity_512,
        canonical_evidence,
        fragment,
        *(() if not transparent_coin_binding else (transparent_coin_binding,)),
    )
    binding_digest = _state_hash(
        (
            _TRANSPARENT_COMPOSED_BINDING_DOMAIN
            if transparent_coin_binding
            else _COMPOSED_BINDING_DOMAIN
        ),
        proof.before.root_512,
        proof.after.root_512,
        proof.statement_digest_512,
        proof.transition_digest_512,
        proof.commitment.commitment_digest_512,
        proof.proof_identity_512,
        proof.receipt.receipt_digest_512,
        composition,
        fragment,
        *(() if not transparent_coin_binding else (transparent_coin_binding,)),
    )
    before = proof.before.encoded
    after = proof.after.encoded
    commitment = proof.commitment.canonical_bytes
    component_id = evidence.component_id.encode("ascii")
    program_id = evidence.program_id.encode("ascii")
    if len(component_id) > 0xFF or len(program_id) > 0xFF:
        raise StructuralError("state_air_composed_binding_component_id_length")
    encoded = b"".join(
        (
            b"BLSB01",
            bytes(
                (
                    TRANSPARENT_STATE_AIR_COMPOSED_BINDING_VERSION
                    if transparent_coin_binding
                    else STATE_AIR_COMPOSED_BINDING_VERSION,
                )
            ),
            len(before).to_bytes(4, "big"),
            before,
            len(after).to_bytes(4, "big"),
            after,
            len(proof.operations).to_bytes(8, "big"),
            b"".join(operation.encoded for operation in proof.operations),
            b"".join(proof.projection_12),
            proof.public_coin_digest_512,
            len(commitment).to_bytes(4, "big"),
            commitment,
            proof.opening.statement_digest_512,
            proof.opening.mask_512,
            STATE_AIR_COMPOSED_FRAGMENT_MAGIC,
            bytes((1,)),
            len(program_bytes).to_bytes(4, "big"),
            program_bytes,
            len(execution_bytes).to_bytes(4, "big"),
            execution_bytes,
            len(evidence.proof_package_bytes).to_bytes(8, "big"),
            evidence.proof_package_bytes,
            bytes((len(component_id),)),
            component_id,
            bytes((len(program_id),)),
            program_id,
            evidence.proof_suite_id_512,
            evidence.schedule_commitment_512,
            evidence.transcript_root_512,
            evidence.evidence_commitment_512,
            evidence.proof_package_commitment_512,
            evidence.proof_identity_512,
            evidence.public_input_digest_512,
            evidence.attribution_digest_512,
            evidence.proof_bytes.to_bytes(8, "big"),
            evidence.worker_report_digest_512,
            len(canonical_evidence).to_bytes(4, "big"),
            canonical_evidence,
        )
    )
    if len(encoded) > MAX_PROOF_PACKAGE_BYTES:
        raise StructuralError("state_air_composed_binding_too_large")
    return encoded


__all__ = (
    "COMPONENT_ID",
    "MAX_PROOF_PACKAGE_BYTES",
    "PUBLIC_OUTPUT_BYTES",
    "PROOF_PACKAGE_MAGIC",
    "PROOF_PACKAGE_BYTES",
    "PROOF_PACKAGE_VERSION",
    "STATE_AIR_COMPOSED_BINDING_VERSION",
    "TRANSPARENT_STATE_AIR_COMPOSED_BINDING_VERSION",
    "STATE_AIR_COMPOSED_FRAGMENT_MAGIC",
    "SIDECAR_BYTES",
    "STATUS",
    "StateAirProofEvidence",
    "proof_package_commitment",
    "build_state_air_binding_bytes",
    "prove_state_air",
)
