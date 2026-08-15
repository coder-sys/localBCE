"""Selected dual-PQ proof and H4 envelope for the typed C0 state AIR."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512, shake_256
from pathlib import Path
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    C0TypedStateWitness,
)
from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    SelectedProofResult,
    prove_selected_air_streaming,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    MAX_SELECTED_TRANSCRIPT_BYTES,
    SELECTED_TRANSCRIPT_MAGIC,
    SELECTED_TRANSCRIPT_VERSION,
    encode_selected_transcript_evidence,
)
from experiments.bl_pq512_crypto_foundation.state_air_proof import (
    MAX_PROOF_PACKAGE_BYTES,
    PROOF_PACKAGE_BYTES,
    PROOF_PACKAGE_MAGIC,
    PROOF_PACKAGE_VERSION,
    _attribution_digest,
    proof_package_commitment,
)
from experiments.bl_pq512_crypto_foundation.transparent_hash_code_candidate import (
    MASK_BYTES as STATE_COMMITMENT_MASK_BYTES,
    TransparentHashCodeCommitment,
    TransparentHashCodeOpening,
    bind_authenticated_public_coin,
    commit as commit_state_statement,
    verify_opening as verify_state_commitment_opening,
)
from experiments.fixed_shape_claim_air.air_binary_ir import (
    air_binary_commitment,
    air_program_commitment,
    encode_air_execution,
    encode_air_program,
)
from experiments.fixed_shape_claim_air.typed_state_relation_executable_air import (
    PROGRAM_ID,
    build_typed_state_relation_air,
    verify_typed_state_relation_air,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


COMPONENT_ID: Final[str] = "BL-PQ512-C0-TYPED-STATE-AIR-V1"
TYPED_BINDING_VERSION: Final[int] = 5
TYPED_FRAGMENT_MAGIC: Final[bytes] = b"BLSA03"
PUBLIC_OUTPUT_BYTES: Final[int] = 384
SIDECAR_BYTES: Final[int] = 744
PORTABLE_PACKAGE_MAGIC: Final[bytes] = b"BLTSPK01"
PORTABLE_PACKAGE_VERSION: Final[int] = 1
PORTABLE_PACKAGE_FLAGS: Final[int] = 0
PORTABLE_PACKAGE_PREFIX_BYTES: Final[int] = (
    8 + 2 + 2 + PUBLIC_OUTPUT_BYTES + SIDECAR_BYTES + 8 + 8
)
PORTABLE_PACKAGE_BYTES: Final[int] = (
    PORTABLE_PACKAGE_PREFIX_BYTES + PROOF_PACKAGE_BYTES + MAX_SELECTED_TRANSCRIPT_BYTES
)
PORTABLE_SIDECAR_MAGIC: Final[bytes] = b"BLTSSC01"
PORTABLE_SIDECAR_VERSION: Final[int] = 1
PORTABLE_SIDECAR_FLAGS: Final[int] = 0
_C0_STATE_ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/C0/STATE-ROOT/v1\x00"
_STATE_ROOT_ENTRY_WIDTH: Final[int] = 137
_STATE_ROOT_CAPACITY_BASE: Final[int] = 512
_PROOF_DOMAIN: Final[bytes] = b"BL/PQ512/STATE-AIR-PROOF/v1\x00"
_PROJECTION_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-PROJECTION/v1\x00"
_PROJECTION_DIGEST_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-PROJECTION-DIGEST/v1\x00"
_STATEMENT_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-STATEMENT/v2\x00"
_TRANSITION_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-TRANSITION/v1\x00"
_PROOF_IDENTITY_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-PROOF/v2\x00"
_ATTEMPT_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-ATTEMPT/v2\x00"
_RECEIPT_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-RECEIPT/v2\x00"
_FRAGMENT_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-FRAGMENT/v2\x00"
_COMPOSITION_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-COMPOSITION/v2\x00"
_BINDING_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-BINDING/v2\x00"
_MASK_DERIVATION_DOMAIN: Final[bytes] = (
    b"BL/PQ512/C0/TYPED-STATE/TRANSPARENT-SHAKE256-1024-MASK/v1\x00"
)
_VERIFIER_IDENTITY: Final[bytes] = (
    b"BL/PQ512/C0/TYPED-STATE/INDEPENDENT-VERIFIER/v1\x00"
)
_SIDECAR_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-SIDECAR/v1\x00"
_PROFILE_IDENTITY_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-PROFILE/v1\x00"
_PROGRAM_IDENTITY_DOMAIN: Final[bytes] = b"BL/PQ512/C0/TYPED-STATE-PROGRAM/v1\x00"


def _hash(domain: bytes, *parts: bytes) -> bytes:
    digest = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise StructuralError("typed_state_air_hash_part_invalid")
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


def _roots(state_witness: C0TypedStateWitness) -> tuple[bytes, bytes, bytes, bytes]:
    payment_before = state_witness.payment_before.root()
    payment_after = state_witness.payment_after.root()
    replay_before = state_witness.replay_batch.root_before
    replay_after = state_witness.replay_batch.root_after
    return (
        sha3_512(_C0_STATE_ROOT_DOMAIN + payment_before + replay_before).digest(),
        sha3_512(_C0_STATE_ROOT_DOMAIN + payment_after + replay_after).digest(),
        payment_before,
        payment_after,
    )


def _projection(public_values: tuple[int, ...]) -> tuple[bytes, ...]:
    public_bytes = b"".join(value.to_bytes(4, "big") for value in public_values)
    return tuple(
        _hash(_PROJECTION_DOMAIN, bytes((index,)), public_bytes)[:32]
        for index in range(12)
    )


def _sidecar(fields: tuple[bytes, ...]) -> bytes:
    if len(fields) != 11 or any(type(value) is not bytes or len(value) != 64 for value in fields):
        raise StructuralError("typed_state_air_sidecar_fields_invalid")
    encoded = b"".join(
        (
            PORTABLE_SIDECAR_MAGIC,
            PORTABLE_SIDECAR_VERSION.to_bytes(2, "big"),
            PORTABLE_SIDECAR_FLAGS.to_bytes(2, "big"),
            SIDECAR_BYTES.to_bytes(4, "big"),
            *fields,
        )
    )
    if len(encoded) > SIDECAR_BYTES:
        raise StructuralError("typed_state_air_sidecar_overflow")
    encoded += bytes(SIDECAR_BYTES - len(encoded))
    return encoded


def _validate_public_sidecar(encoded: bytes) -> None:
    if (
        type(encoded) is not bytes
        or len(encoded) != SIDECAR_BYTES
        or encoded[:8] != PORTABLE_SIDECAR_MAGIC
        or int.from_bytes(encoded[8:10], "big") != PORTABLE_SIDECAR_VERSION
        or int.from_bytes(encoded[10:12], "big") != PORTABLE_SIDECAR_FLAGS
        or int.from_bytes(encoded[12:16], "big") != SIDECAR_BYTES
        or any(encoded[16 + 11 * 64 :])
    ):
        raise StructuralError("typed_state_air_public_sidecar_invalid")
    fields = tuple(encoded[offset : offset + 64] for offset in range(16, 16 + 11 * 64, 64))
    if any(not any(value) for value in fields):
        raise StructuralError("typed_state_air_public_sidecar_field_invalid")


def _validate_transcript_binding(
    encoded: bytes,
    public_outputs: bytes,
    sidecar: bytes,
    proof_suite_id: bytes,
    schedule_commitment: bytes,
    final_transcript_root: bytes,
) -> None:
    """Check the immutable statement fields retained in one BLPQTR01 artifact."""

    minimum = 8 + 2 + 64 + PUBLIC_OUTPUT_BYTES + SIDECAR_BYTES + 64 + 64 + 64
    if (
        type(encoded) is not bytes
        or not minimum <= len(encoded) <= MAX_SELECTED_TRANSCRIPT_BYTES
        or encoded[:8] != SELECTED_TRANSCRIPT_MAGIC
        or int.from_bytes(encoded[8:10], "big") != SELECTED_TRANSCRIPT_VERSION
    ):
        raise StructuralError("typed_state_air_transcript_encoding_invalid")
    public_start = 8 + 2 + 64
    sidecar_start = public_start + PUBLIC_OUTPUT_BYTES
    suite_start = sidecar_start + SIDECAR_BYTES
    schedule_start = suite_start + 64
    if (
        encoded[public_start:sidecar_start] != public_outputs
        or encoded[sidecar_start:suite_start] != sidecar
        or encoded[suite_start:schedule_start] != proof_suite_id
        or encoded[schedule_start : schedule_start + 64] != schedule_commitment
        or encoded[-64:] != final_transcript_root
    ):
        raise StructuralError("typed_state_air_transcript_binding_mismatch")


def _profile_identity(profile_id: bytes) -> bytes:
    return _hash(_PROFILE_IDENTITY_DOMAIN, profile_id)


def _program_identity() -> bytes:
    return _hash(_PROGRAM_IDENTITY_DOMAIN, PROGRAM_ID.encode("ascii"))


@dataclass(frozen=True, slots=True)
class TypedStateAirProofEvidence:
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
    state_commitment: TransparentHashCodeCommitment
    state_commitment_mask: bytes = field(repr=False)
    proof_package_bytes: bytes = field(default=b"", repr=False, compare=False)
    public_outputs: bytes = field(default=b"", repr=False, compare=False)
    public_sidecar: bytes = field(default=b"", repr=False, compare=False)
    transcript_evidence_bytes: bytes = field(default=b"", repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.component_id != COMPONENT_ID or self.program_id != PROGRAM_ID:
            raise StructuralError("typed_state_air_component_identity_invalid")
        for value in (
            self.program_commitment_512,
            self.execution_commitment_512,
            self.proof_suite_id_512,
            self.schedule_commitment_512,
            self.transcript_root_512,
            self.evidence_commitment_512,
            self.proof_package_commitment_512,
            self.proof_identity_512,
            self.public_input_digest_512,
            self.attribution_digest_512,
            self.worker_report_digest_512,
        ):
            if type(value) is not bytes or len(value) != 64 or not any(value):
                raise StructuralError("typed_state_air_evidence_digest_invalid")
        if type(self.proof_bytes) is not int or self.proof_bytes <= 0:
            raise StructuralError("typed_state_air_proof_size_invalid")
        if (
            type(self.state_commitment) is not TransparentHashCodeCommitment
            or type(self.state_commitment_mask) is not bytes
            or len(self.state_commitment_mask) != STATE_COMMITMENT_MASK_BYTES
        ):
            raise StructuralError("typed_state_air_state_commitment_invalid")
        if (
            type(self.proof_package_bytes) is not bytes
            or len(self.proof_package_bytes) != PROOF_PACKAGE_BYTES
            or self.proof_package_bytes[:8] != PROOF_PACKAGE_MAGIC
            or int.from_bytes(self.proof_package_bytes[8:10], "big") != PROOF_PACKAGE_VERSION
            or proof_package_commitment(self.proof_package_bytes)
            != self.proof_package_commitment_512
        ):
            raise StructuralError("typed_state_air_package_invalid")
        if type(self.public_outputs) is not bytes or len(self.public_outputs) != PUBLIC_OUTPUT_BYTES:
            raise StructuralError("typed_state_air_public_outputs_invalid")
        _validate_public_sidecar(self.public_sidecar)
        _validate_transcript_binding(
            self.transcript_evidence_bytes,
            self.public_outputs,
            self.public_sidecar,
            self.proof_suite_id_512,
            self.schedule_commitment_512,
            self.transcript_root_512,
        )

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                self.component_id.encode("ascii"),
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
    instance,
    result: SelectedProofResult,
    program_commitment: bytes,
    execution_commitment: bytes,
    package: bytes,
    projection: tuple[bytes, ...],
    public_sidecar: bytes,
    state_commitment: TransparentHashCodeCommitment,
    state_commitment_mask: bytes,
) -> TypedStateAirProofEvidence:
    bundle = result.challenge_bundle
    package_commitment = proof_package_commitment(package)
    public_bytes = b"".join(value.to_bytes(4, "big") for value in instance.public_values)
    public_outputs = b"".join(projection)
    if result.transcript.public_outputs != public_outputs or result.transcript.sidecar != public_sidecar:
        raise StructuralError("typed_state_air_transcript_statement_mismatch")
    transcript_evidence = encode_selected_transcript_evidence(result.transcript)
    return TypedStateAirProofEvidence(
        COMPONENT_ID,
        PROGRAM_ID,
        program_commitment,
        execution_commitment,
        bundle.proof_suite_id,
        bundle.schedule_commitment,
        result.transcript.final_transcript_root,
        bundle.evidence_commitment,
        package_commitment,
        _hash(
            _PROOF_DOMAIN,
            b"proof-identity",
            package_commitment,
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
        _hash(_PROOF_DOMAIN, b"public-inputs", public_bytes, b"".join(projection)),
        _attribution_digest(result),
        result.proof_bytes,
        _hash(_PROOF_DOMAIN, b"worker-report", result.worker_report.encode("ascii")),
        state_commitment,
        state_commitment_mask,
        package,
        public_outputs,
        public_sidecar,
        transcript_evidence,
    )


def _precommitment_fields(
    state_witness: C0TypedStateWitness,
    program_commitment: bytes,
    execution_commitment: bytes,
    projection: tuple[bytes, ...],
) -> tuple[tuple[bytes, bytes, bytes, bytes], bytes, bytes, bytes, bytes]:
    roots = _roots(state_witness)
    projection_digest = _hash(_PROJECTION_DIGEST_DOMAIN, *projection)
    profile = state_witness.profile.profile_id.encode("ascii")
    capacity = state_witness.profile.claim_slots.to_bytes(8, "big")
    statement = _hash(
        _STATEMENT_DOMAIN,
        profile,
        capacity,
        roots[0],
        roots[1],
        roots[2],
        roots[3],
        projection_digest,
        program_commitment,
        execution_commitment,
    )
    transition = _hash(
        _TRANSITION_DOMAIN,
        profile,
        state_witness.payment_before.epoch.to_bytes(8, "big"),
        state_witness.payment_before.sequence.to_bytes(8, "big"),
        state_witness.payment_after.sequence.to_bytes(8, "big"),
        roots[0],
        roots[1],
        roots[2],
        roots[3],
    )
    attempt = _hash(
        _ATTEMPT_DOMAIN,
        profile,
        capacity,
        roots[0],
        roots[1],
        statement,
        transition,
    )
    return roots, projection_digest, statement, transition, attempt


def _state_commitment_mask(secret_mask_seed: bytes, session_id: bytes) -> bytes:
    if (
        type(secret_mask_seed) is not bytes
        or len(secret_mask_seed) != 64
        or not any(secret_mask_seed)
        or type(session_id) is not bytes
        or len(session_id) != 64
        or not any(session_id)
    ):
        raise StructuralError("typed_state_air_commitment_entropy_invalid")
    return shake_256(_MASK_DERIVATION_DOMAIN + secret_mask_seed + session_id).digest(
        STATE_COMMITMENT_MASK_BYTES
    )


def prove_typed_state_air(
    state_witness: C0TypedStateWitness,
    *,
    worker_executable: Path,
    secret_mask_seed: bytes,
    session_id: bytes,
    contributors: tuple[object, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
    scratch_parent: Path,
) -> TypedStateAirProofEvidence:
    if type(state_witness) is not C0TypedStateWitness:
        raise StructuralError("typed_state_air_witness_required")
    instance = build_typed_state_relation_air(state_witness)
    verify_typed_state_relation_air(instance)
    program_bytes = encode_air_program(instance.program)
    execution_bytes = encode_air_execution(
        instance.program,
        instance.traces,
        instance.public_values,
    )
    projection = _projection(instance.public_values)
    if len(b"".join(projection)) != PUBLIC_OUTPUT_BYTES:
        raise StructuralError("typed_state_air_public_output_shape_invalid")
    program_commitment = air_program_commitment(program_bytes)
    execution_commitment = air_binary_commitment(execution_bytes)
    roots, projection_digest, statement, transition, attempt = _precommitment_fields(
        state_witness,
        program_commitment,
        execution_commitment,
        projection,
    )
    state_commitment_mask = _state_commitment_mask(secret_mask_seed, session_id)
    state_commitment = commit_state_statement(statement, attempt, state_commitment_mask)
    profile = state_witness.profile.profile_id.encode("ascii")
    public_sidecar = _sidecar(
        (
            _profile_identity(profile),
            _program_identity(),
            program_commitment,
            roots[0],
            roots[1],
            roots[2],
            roots[3],
            state_witness.replay_batch.root_before,
            state_witness.replay_batch.root_after,
            transition,
            projection_digest,
        )
    )
    package_path = scratch_parent / f"bl-typed-state-air-proof-{session_id.hex()}.bin"
    if package_path.exists():
        raise StructuralError("typed_state_air_package_path_exists")
    try:
        result = prove_selected_air_streaming(
            worker_executable=worker_executable,
            program=instance.program,
            traces=instance.traces,
            public_inputs=instance.public_values,
            scratch_parent=scratch_parent,
            secret_mask_seed=secret_mask_seed,
            session_id=session_id,
            public_outputs=b"".join(projection),
            sidecar=public_sidecar,
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
            proof_export_path=package_path,
        )
        package = package_path.read_bytes()
    finally:
        if package_path.exists():
            package_path.unlink()
    return _evidence(
        instance,
        result,
        program_commitment,
        execution_commitment,
        package,
        projection,
        public_sidecar,
        state_commitment,
        state_commitment_mask,
    )


def build_typed_state_proof_package_v1(evidence: TypedStateAirProofEvidence) -> bytes:
    """Build the fixed portable verifier input without witness-bearing material.

    The only variable-length section is the authenticated BLPQTR01 transcript;
    it occupies a fixed 16 MiB zero-padded slot.  The legacy transparent-state
    opening mask and AIR execution are deliberately not serialized.
    """

    if type(evidence) is not TypedStateAirProofEvidence:
        raise StructuralError("typed_state_portable_evidence_required")
    _validate_public_sidecar(evidence.public_sidecar)
    _validate_transcript_binding(
        evidence.transcript_evidence_bytes,
        evidence.public_outputs,
        evidence.public_sidecar,
        evidence.proof_suite_id_512,
        evidence.schedule_commitment_512,
        evidence.transcript_root_512,
    )
    transcript_length = len(evidence.transcript_evidence_bytes)
    if not 0 < transcript_length <= MAX_SELECTED_TRANSCRIPT_BYTES:
        raise StructuralError("typed_state_portable_transcript_length_invalid")
    prefix = b"".join(
        (
            PORTABLE_PACKAGE_MAGIC,
            PORTABLE_PACKAGE_VERSION.to_bytes(2, "big"),
            PORTABLE_PACKAGE_FLAGS.to_bytes(2, "big"),
            evidence.public_outputs,
            evidence.public_sidecar,
            PROOF_PACKAGE_BYTES.to_bytes(8, "big"),
            transcript_length.to_bytes(8, "big"),
        )
    )
    if len(prefix) != PORTABLE_PACKAGE_PREFIX_BYTES:
        raise AssertionError("typed_state_portable_prefix_length_mismatch")
    encoded = b"".join(
        (
            prefix,
            evidence.proof_package_bytes,
            evidence.transcript_evidence_bytes,
            bytes(MAX_SELECTED_TRANSCRIPT_BYTES - transcript_length),
        )
    )
    if len(encoded) != PORTABLE_PACKAGE_BYTES:
        raise AssertionError("typed_state_portable_package_length_mismatch")
    return encoded


def _identity_fields(state_witness: C0TypedStateWitness, evidence: TypedStateAirProofEvidence):
    instance = build_typed_state_relation_air(state_witness)
    program_bytes = encode_air_program(instance.program)
    execution_bytes = encode_air_execution(instance.program, instance.traces, instance.public_values)
    program_commitment = air_program_commitment(program_bytes)
    execution_commitment = air_binary_commitment(execution_bytes)
    if (
        evidence.program_commitment_512 != program_commitment
        or evidence.execution_commitment_512 != execution_commitment
    ):
        raise StructuralError("typed_state_air_commitment_mismatch")
    projection = _projection(instance.public_values)
    roots, projection_digest, statement, transition, attempt = _precommitment_fields(
        state_witness,
        program_commitment,
        execution_commitment,
        projection,
    )
    if evidence.state_commitment.attempt_id != attempt:
        raise StructuralError("typed_state_air_commitment_attempt_mismatch")
    try:
        verify_state_commitment_opening(
            evidence.state_commitment,
            TransparentHashCodeOpening(attempt, statement, evidence.state_commitment_mask),
        )
    except (TypeError, ValueError) as exc:
        raise StructuralError("typed_state_air_commitment_opening_rejected") from exc
    public_coin = bind_authenticated_public_coin(
        evidence.state_commitment, evidence.transcript_root_512
    )
    commitment = evidence.state_commitment.identity_512
    proof = _hash(_PROOF_IDENTITY_DOMAIN, statement, evidence.proof_identity_512)
    verifier = sha3_512(_VERIFIER_IDENTITY).digest()
    receipt = _hash(_RECEIPT_DOMAIN, statement, commitment, proof, attempt)
    canonical = evidence.canonical_bytes
    fragment = _hash(
        _FRAGMENT_DOMAIN,
        roots[0],
        roots[1],
        projection_digest,
        statement,
        transition,
        commitment,
        proof,
        receipt,
        program_commitment,
        execution_commitment,
        evidence.proof_package_commitment_512,
        evidence.proof_identity_512,
        canonical,
    )
    composition = _hash(
        _COMPOSITION_DOMAIN,
        statement,
        transition,
        projection_digest,
        public_coin,
        commitment,
        proof,
        receipt,
        program_commitment,
        execution_commitment,
        evidence.proof_package_commitment_512,
        evidence.proof_identity_512,
        canonical,
        fragment,
    )
    binding = _hash(_BINDING_DOMAIN, roots[0], roots[1], statement, commitment, proof, receipt, composition, fragment)
    return instance, program_bytes, execution_bytes, projection, roots, {
        "statement": statement,
        "binding": binding,
        "projection_digest": projection_digest,
        "public_coin": public_coin,
        "transition": transition,
        "commitment": commitment,
        "proof": proof,
        "verifier": verifier,
        "attempt": attempt,
        "receipt": receipt,
        "fragment": fragment,
        "composition": composition,
    }


def build_typed_state_air_binding_bytes(
    state_witness: C0TypedStateWitness,
    evidence: TypedStateAirProofEvidence,
) -> bytes:
    if type(state_witness) is not C0TypedStateWitness or type(evidence) is not TypedStateAirProofEvidence:
        raise StructuralError("typed_state_air_binding_types_invalid")
    instance, program_bytes, execution_bytes, projection, roots, identities = _identity_fields(
        state_witness, evidence
    )
    canonical = evidence.canonical_bytes
    profile = state_witness.profile.profile_id.encode("ascii")
    component = evidence.component_id.encode("ascii")
    program_id = evidence.program_id.encode("ascii")
    for value in (profile, component, program_id):
        if len(value) > 0xFF:
            raise StructuralError("typed_state_air_text_length_invalid")
    encoded = b"".join(
        (
            b"BLSB01",
            bytes((TYPED_BINDING_VERSION,)),
            bytes((len(profile),)),
            profile,
            state_witness.profile.claim_slots.to_bytes(8, "big"),
            roots[0],
            roots[1],
            identities["statement"],
            identities["binding"],
            b"".join(projection),
            identities["projection_digest"],
            identities["public_coin"],
            identities["transition"],
            identities["commitment"],
            len(evidence.state_commitment.canonical_bytes).to_bytes(4, "big"),
            evidence.state_commitment.canonical_bytes,
            evidence.state_commitment_mask,
            identities["proof"],
            identities["verifier"],
            identities["attempt"],
            identities["receipt"],
            evidence.program_commitment_512,
            evidence.execution_commitment_512,
            identities["fragment"],
            identities["composition"],
            TYPED_FRAGMENT_MAGIC,
            bytes((1,)),
            len(program_bytes).to_bytes(4, "big"),
            program_bytes,
            len(execution_bytes).to_bytes(4, "big"),
            execution_bytes,
            len(evidence.proof_package_bytes).to_bytes(8, "big"),
            evidence.proof_package_bytes,
            bytes((len(component),)),
            component,
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
            len(canonical).to_bytes(4, "big"),
            canonical,
        )
    )
    if len(encoded) > MAX_PROOF_PACKAGE_BYTES:
        raise StructuralError("typed_state_air_binding_too_large")
    return encoded


__all__ = (
    "COMPONENT_ID",
    "PORTABLE_PACKAGE_BYTES",
    "PORTABLE_PACKAGE_MAGIC",
    "PORTABLE_PACKAGE_PREFIX_BYTES",
    "PORTABLE_PACKAGE_VERSION",
    "PUBLIC_OUTPUT_BYTES",
    "SIDECAR_BYTES",
    "TYPED_BINDING_VERSION",
    "TypedStateAirProofEvidence",
    "build_typed_state_air_binding_bytes",
    "build_typed_state_proof_package_v1",
    "prove_typed_state_air",
)
