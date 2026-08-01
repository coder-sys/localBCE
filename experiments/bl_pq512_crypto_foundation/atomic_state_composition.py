"""Gate 2E-4/S4 atomic state/proof composition reference.

S4 is the boundary where the scalar relation and a commitment envelope must
stop being independently persuasive.  This module derives one canonical
state statement, verifies the S2 relation independently, verifies the S3
opening and authenticated public-coin transcript, encodes the frozen BLTR
transition, and binds all of it into one reference receipt.

The composition is intentionally synthetic and nonactivating.  The H4
identity in this module is a deferred reference identity, not a proof-suite
selection.  A successful result therefore means only that the reference
binding and mutation gates work; it does not mean that a production proof,
PCS, or settlement transition is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Sequence

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from experiments.bl_pq512_crypto_foundation.pq_commitment_screening import (
    CommitmentArtifact,
    CommitmentOpening,
    CommitmentScreeningError,
    CommitmentStatement,
    verify_opening,
)
from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import (
    ScalarBatchInput,
    ScalarBatchResult,
    independently_verify_candidate,
)
from experiments.bl_pq512_crypto_foundation.state_interface import StateTransitionV1


STATUS: Final[str] = "S4_ATOMIC_STATE_COMPOSITION_V1_SYNTHETIC_REFERENCE_NONPRODUCTION"
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False
PUBLIC_PROJECTION_FIELD_COUNT: Final[int] = 12
PUBLIC_PROJECTION_FIELD_BYTES: Final[int] = 32
H4_PARENT_BINDING_STATUS: Final[str] = "DEFERRED_H4_REFERENCE_IDENTITY_ONLY"
H4_PARENT_REFERENCE_IDENTITY_512: Final[bytes] = sha3_512(
    b"BL/PQ512/S4/H4-PARENT-REFERENCE-IDENTITY/v1\x00"
).digest()
VERIFIER_REFERENCE_IDENTITY_512: Final[bytes] = sha3_512(
    b"BL/PQ512/S4/INDEPENDENT-VERIFIER-REFERENCE-IDENTITY/v1\x00"
).digest()

_LAYOUT_DOMAIN = b"BL/PQ512/S4/LAYOUT/v1\x00"
_ROOT_DOMAIN = b"BL/PQ512/S4/ROOT/v1\x00"
_MANIFEST_DOMAIN = b"BL/PQ512/S4/MANIFEST/v1\x00"
_PROJECTION_DOMAIN = b"BL/PQ512/S4/PUBLIC-PROJECTION/v1\x00"
_RELATION_PAYLOAD_DOMAIN = b"BL/PQ512/S4/RELATION-PAYLOAD/v1\x00"
_TRANSITION_DOMAIN = b"BL/PQ512/S4/TRANSITION/v1\x00"
_ATTEMPT_DOMAIN = b"BL/PQ512/S4/ATTEMPT/v1\x00"
_PROOF_ID_DOMAIN = b"BL/PQ512/S4/PROOF-IDENTITY/v1\x00"
_RECEIPT_DOMAIN = b"BL/PQ512/S4/RECEIPT/v1\x00"
_RECEIPT_DIGEST_DOMAIN = b"BL/PQ512/S4/RECEIPT-DIGEST/v1\x00"


class AtomicCompositionError(ValueError):
    """Stable fail-closed error for the S4 composition boundary."""


def _synthetic() -> None:
    require_synthetic_reference_enabled()


def _text(value: object, label: str, maximum: int = 96) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise AtomicCompositionError(f"s4_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AtomicCompositionError(f"s4_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise AtomicCompositionError(f"s4_{label}_nul")
    return encoded


def _bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise AtomicCompositionError(f"s4_{label}_length_invalid")
    if nonzero and not any(value):
        raise AtomicCompositionError(f"s4_{label}_zero")
    return value


def _u64(label: str, value: object) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise AtomicCompositionError(f"s4_{label}_invalid")
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise AtomicCompositionError("s4_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _int_bytes(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _projection(projection_12: Sequence[bytes]) -> tuple[bytes, ...]:
    if type(projection_12) not in (tuple, list) or len(projection_12) != PUBLIC_PROJECTION_FIELD_COUNT:
        raise AtomicCompositionError("s4_public_projection_count_invalid")
    result = tuple(
        _bytes(f"public_projection_{index}", value, PUBLIC_PROJECTION_FIELD_BYTES, nonzero=True)
        for index, value in enumerate(projection_12)
    )
    return result


def _lane_bytes(result) -> bytes:
    parts = [
        _text(result.lane, "lane"),
        _int_bytes(result.operation_count),
        _int_bytes(result.access_rows),
        _int_bytes(result.position_rows),
        _int_bytes(result.proof_node_rows),
        result.state_root_before_512,
        result.state_root_after_512,
        result.update_root_before_512,
        result.update_root_after_512,
        _int_bytes(result.next_index_before),
        _int_bytes(result.next_index_after),
        _int_bytes(result.update_next_index_before),
        _int_bytes(result.update_next_index_after),
        _hash(_RELATION_PAYLOAD_DOMAIN, b"membership-key", result.membership_key_512),
        _hash(_RELATION_PAYLOAD_DOMAIN, b"membership-value", result.membership_value_512),
        _hash(_RELATION_PAYLOAD_DOMAIN, b"absence-key", result.absence_key_512),
        bytes((int(result.membership_present), int(result.absence_proven))),
        result.operation_digest_512,
        result.relation_digest_512,
        result.candidate_payload_digest_512,
        _int_bytes(len(result.touched_keys)),
        _int_bytes(len(result.dictionary_rows)),
        _int_bytes(len(result.projection_positions)),
        result.shuffle_challenge_512,
        result.shuffle_digest_512,
        _int_bytes(result.candidate_capacity_work_units),
        _int_bytes(result.candidate_online_work_units),
        _int_bytes(result.candidate_initialization_work_units),
        bytes((int(result.candidate_requires_persistent_scan),)),
    ]
    return b"".join(len(part).to_bytes(4, "big") + part for part in parts)


def canonical_relation_payload(result: ScalarBatchResult) -> bytes:
    """Encode only bounded relation identities; never serialize raw private keys."""

    _synthetic()
    if type(result) is not ScalarBatchResult:
        raise AtomicCompositionError("s4_relation_result_type_invalid")
    parts = [
        _text(result.candidate_id, "candidate_id"),
        _text(result.profile_id, "profile_id"),
        _int_bytes(result.claim_slots),
        result.semantic_digest_512,
        result.economic_digest_512,
        _int_bytes(result.total_plan_payable_cents),
        _int_bytes(result.total_debits_cents),
        _int_bytes(result.total_credits_cents),
        _int_bytes(result.candidate_work_units),
    ]
    parts.extend(_lane_bytes(lane) for lane in result.lanes)
    encoded = _RELATION_PAYLOAD_DOMAIN + b"".join(
        len(part).to_bytes(4, "big") + part for part in parts
    )
    if len(encoded) > 1 << 20:
        raise AtomicCompositionError("s4_relation_payload_size_invalid")
    return encoded


def _aggregate_root(result: ScalarBatchResult, stage: str) -> bytes:
    parts = [_text(result.candidate_id, "candidate_id"), _text(stage, "root_stage")]
    for lane in result.lanes:
        parts.append(_text(lane.lane, "lane"))
        parts.append(
            lane.state_root_before_512
            if stage == "before"
            else lane.state_root_after_512
        )
        parts.append(
            lane.update_root_before_512
            if stage == "before"
            else lane.update_root_after_512
        )
    return _hash(_ROOT_DOMAIN, *parts)


def _manifest_digest(batch: ScalarBatchInput, result: ScalarBatchResult) -> bytes:
    return _hash(
        _MANIFEST_DOMAIN,
        _text(batch.profile_id, "profile_id"),
        _int_bytes(batch.claim_slots),
        canonical_relation_payload(result),
    )


def _projection_digest(projection_12: tuple[bytes, ...]) -> bytes:
    return _hash(_PROJECTION_DOMAIN, *projection_12)


def derive_composition_statement(
    batch: ScalarBatchInput,
    result: ScalarBatchResult,
    projection_12: Sequence[bytes],
    *,
    epoch: int,
    sequence_before: int,
) -> CommitmentStatement:
    """Derive the only S3 statement accepted by the S4 composition."""

    _synthetic()
    if type(batch) is not ScalarBatchInput or type(result) is not ScalarBatchResult:
        raise AtomicCompositionError("s4_statement_input_type_invalid")
    independently_verify_candidate(result.candidate_id, batch, result)
    projection = _projection(projection_12)
    _u64("epoch", epoch)
    _u64("sequence_before", sequence_before)
    layout_id = _hash(
        _LAYOUT_DOMAIN,
        _text(result.candidate_id, "candidate_id"),
        result.semantic_digest_512,
    )
    old_root = _aggregate_root(result, "before")
    new_root = _aggregate_root(result, "after")
    return CommitmentStatement(
        profile_id=batch.profile_id,
        layout_id_512=layout_id,
        epoch=epoch,
        sequence_before=sequence_before,
        sequence_after=sequence_before + 1,
        state_root_before_512=old_root,
        state_root_after_512=new_root,
        relation_digest_512=result.semantic_digest_512,
        manifest_digest_512=_manifest_digest(batch, result),
    )


def _transition(statement: CommitmentStatement, candidate_id: str, projection: tuple[bytes, ...]) -> StateTransitionV1:
    parameter_identity = f"BL-S4-{candidate_id}-REFERENCE-v1"
    return StateTransitionV1(
        profile_id=statement.profile_id,
        parameter_identity=parameter_identity,
        epoch=statement.epoch,
        sequence_before=statement.sequence_before,
        sequence_after=statement.sequence_after,
        old_root=statement.state_root_before_512,
        new_root=statement.state_root_after_512,
        manifest_digest=statement.manifest_digest_512,
        public_projection_digest=_projection_digest(projection),
    )


def _transition_digest(transition: StateTransitionV1) -> bytes:
    return _hash(_TRANSITION_DOMAIN, transition.encoded)


def _receipt_digest(
    attempt_id: bytes,
    transition_digest: bytes,
    proof_identity: bytes,
    verifier_identity: bytes,
    commitment: bytes,
) -> bytes:
    return _hash(
        _RECEIPT_DIGEST_DOMAIN,
        attempt_id,
        transition_digest,
        proof_identity,
        verifier_identity,
        commitment,
    )


@dataclass(frozen=True, slots=True)
class AtomicReceipt:
    attempt_id_512: bytes
    transition_digest_512: bytes
    proof_identity_512: bytes
    verifier_identity_512: bytes
    commitment_512: bytes
    receipt_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        for label, value in (
            ("receipt_attempt_id", self.attempt_id_512),
            ("receipt_transition_digest", self.transition_digest_512),
            ("receipt_proof_identity", self.proof_identity_512),
            ("receipt_verifier_identity", self.verifier_identity_512),
            ("receipt_commitment", self.commitment_512),
        ):
            _bytes(label, value, 64, nonzero=True)
        expected = _receipt_digest(
            self.attempt_id_512,
            self.transition_digest_512,
            self.proof_identity_512,
            self.verifier_identity_512,
            self.commitment_512,
        )
        if self.receipt_digest_512 not in (b"", expected):
            raise AtomicCompositionError("s4_receipt_digest_mismatch")
        object.__setattr__(self, "receipt_digest_512", expected)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BLRCP01",
                self.attempt_id_512,
                self.transition_digest_512,
                self.proof_identity_512,
                self.verifier_identity_512,
                self.commitment_512,
                self.receipt_digest_512,
            )
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "attempt_id_sha3_512_hex": self.attempt_id_512.hex(),
            "transition_digest_sha3_512_hex": self.transition_digest_512.hex(),
            "proof_identity_sha3_512_hex": self.proof_identity_512.hex(),
            "verifier_identity_sha3_512_hex": self.verifier_identity_512.hex(),
            "commitment_sha3_512_hex": self.commitment_512.hex(),
            "receipt_digest_sha3_512_hex": self.receipt_digest_512.hex(),
        }


@dataclass(frozen=True, slots=True)
class AtomicComposition:
    candidate_id: str
    commitment_backend_id: str
    profile_id: str
    epoch: int
    sequence_before: int
    projection_12: tuple[bytes, ...]
    transition: StateTransitionV1
    commitment: CommitmentArtifact
    proof_identity_512: bytes
    verifier_identity_512: bytes
    attempt_id_512: bytes
    receipt: AtomicReceipt
    acceptance_status: str = "REFERENCE_VERIFIED_ONLY"

    def __post_init__(self) -> None:
        _synthetic()
        _text(self.candidate_id, "candidate_id")
        _text(self.commitment_backend_id, "commitment_backend_id")
        _text(self.profile_id, "profile_id")
        _u64("composition_epoch", self.epoch)
        _u64("composition_sequence_before", self.sequence_before)
        if type(self.projection_12) is not tuple:
            raise AtomicCompositionError("s4_composition_projection_type_invalid")
        _projection(self.projection_12)
        if type(self.transition) is not StateTransitionV1:
            raise AtomicCompositionError("s4_composition_transition_type_invalid")
        if type(self.commitment) is not CommitmentArtifact:
            raise AtomicCompositionError("s4_composition_commitment_type_invalid")
        if self.commitment.backend_id != self.commitment_backend_id:
            raise AtomicCompositionError("s4_composition_backend_identity_mismatch")
        _bytes("composition_proof_identity", self.proof_identity_512, 64, nonzero=True)
        _bytes("composition_verifier_identity", self.verifier_identity_512, 64, nonzero=True)
        _bytes("composition_attempt_id", self.attempt_id_512, 64, nonzero=True)
        if type(self.receipt) is not AtomicReceipt:
            raise AtomicCompositionError("s4_composition_receipt_type_invalid")
        if self.receipt.attempt_id_512 != self.attempt_id_512:
            raise AtomicCompositionError("s4_composition_receipt_attempt_mismatch")
        if self.receipt.proof_identity_512 != self.proof_identity_512:
            raise AtomicCompositionError("s4_composition_receipt_proof_mismatch")
        if self.receipt.verifier_identity_512 != self.verifier_identity_512:
            raise AtomicCompositionError("s4_composition_receipt_verifier_mismatch")
        if self.acceptance_status != "REFERENCE_VERIFIED_ONLY":
            raise AtomicCompositionError("s4_composition_acceptance_status_invalid")

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "acceptance_status": self.acceptance_status,
            "relation_candidate_id": self.candidate_id,
            "commitment_backend_id": self.commitment_backend_id,
            "profile_id": self.profile_id,
            "epoch": self.epoch,
            "sequence_before": self.sequence_before,
            "projection_field_count": len(self.projection_12),
            "transition_digest_sha3_512_hex": _transition_digest(self.transition).hex(),
            "commitment": self.commitment.as_public_dict(),
            "proof_identity_sha3_512_hex": self.proof_identity_512.hex(),
            "verifier_identity_sha3_512_hex": self.verifier_identity_512.hex(),
            "attempt_id_sha3_512_hex": self.attempt_id_512.hex(),
            "receipt": self.receipt.as_public_dict(),
        }


def build_atomic_composition(
    batch: ScalarBatchInput,
    result: ScalarBatchResult,
    projection_12: Sequence[bytes],
    commitment: CommitmentArtifact,
    opening: CommitmentOpening,
    adapters: dict[str, object],
    *,
    epoch: int,
    sequence_before: int,
) -> AtomicComposition:
    """Build one non-spliceable reference composition and receipt."""

    _synthetic()
    if type(adapters) is not dict:
        raise AtomicCompositionError("s4_adapters_mapping_required")
    independently_verify_candidate(result.candidate_id, batch, result)
    projection = _projection(projection_12)
    statement = derive_composition_statement(
        batch,
        result,
        projection,
        epoch=epoch,
        sequence_before=sequence_before,
    )
    try:
        verify_opening(commitment, statement, opening, adapters)
    except (CommitmentScreeningError, ValueError) as exc:
        raise AtomicCompositionError("s4_commitment_opening_rejected") from exc
    transition = _transition(statement, result.candidate_id, projection)
    transition_digest = _transition_digest(transition)
    proof_identity = _hash(
        _PROOF_ID_DOMAIN,
        _text(result.candidate_id, "candidate_id"),
        _text(commitment.backend_id, "commitment_backend_id"),
        result.semantic_digest_512,
        commitment.commitment_512,
        H4_PARENT_REFERENCE_IDENTITY_512,
        transition_digest,
    )
    attempt_id = _hash(
        _ATTEMPT_DOMAIN,
        _text(batch.profile_id, "profile_id"),
        _text(commitment.backend_id, "commitment_backend_id"),
        _int_bytes(epoch),
        _int_bytes(sequence_before),
        result.semantic_digest_512,
        commitment.commitment_512,
    )
    receipt = AtomicReceipt(
        attempt_id,
        transition_digest,
        proof_identity,
        VERIFIER_REFERENCE_IDENTITY_512,
        commitment.commitment_512,
    )
    return AtomicComposition(
        result.candidate_id,
        commitment.backend_id,
        batch.profile_id,
        epoch,
        sequence_before,
        projection,
        transition,
        commitment,
        proof_identity,
        VERIFIER_REFERENCE_IDENTITY_512,
        attempt_id,
        receipt,
    )


def independently_verify_composition(
    composition: AtomicComposition,
    batch: ScalarBatchInput,
    result: ScalarBatchResult,
    opening: CommitmentOpening,
    adapters: dict[str, object],
) -> None:
    """Replay every relation and binding; never trust the host receipt fields."""

    _synthetic()
    if type(composition) is not AtomicComposition:
        raise AtomicCompositionError("s4_verifier_composition_type_invalid")
    if type(batch) is not ScalarBatchInput or type(result) is not ScalarBatchResult:
        raise AtomicCompositionError("s4_verifier_input_type_invalid")
    independently_verify_candidate(result.candidate_id, batch, result)
    if (
        composition.candidate_id != result.candidate_id
        or composition.commitment_backend_id != composition.commitment.backend_id
        or composition.profile_id != batch.profile_id
    ):
        raise AtomicCompositionError("s4_verifier_identity_mismatch")
    expected_statement = derive_composition_statement(
        batch,
        result,
        composition.projection_12,
        epoch=composition.epoch,
        sequence_before=composition.sequence_before,
    )
    try:
        verify_opening(composition.commitment, expected_statement, opening, adapters)
    except (CommitmentScreeningError, ValueError) as exc:
        raise AtomicCompositionError("s4_verifier_commitment_rejected") from exc
    expected_transition = _transition(
        expected_statement, result.candidate_id, composition.projection_12
    )
    if composition.transition != expected_transition:
        raise AtomicCompositionError("s4_verifier_transition_mismatch")
    transition_digest = _transition_digest(expected_transition)
    expected_proof_identity = _hash(
        _PROOF_ID_DOMAIN,
        _text(result.candidate_id, "candidate_id"),
        _text(composition.commitment_backend_id, "commitment_backend_id"),
        result.semantic_digest_512,
        composition.commitment.commitment_512,
        H4_PARENT_REFERENCE_IDENTITY_512,
        transition_digest,
    )
    expected_attempt_id = _hash(
        _ATTEMPT_DOMAIN,
        _text(batch.profile_id, "profile_id"),
        _text(composition.commitment_backend_id, "commitment_backend_id"),
        _int_bytes(composition.epoch),
        _int_bytes(composition.sequence_before),
        result.semantic_digest_512,
        composition.commitment.commitment_512,
    )
    if composition.proof_identity_512 != expected_proof_identity:
        raise AtomicCompositionError("s4_verifier_proof_identity_mismatch")
    if composition.attempt_id_512 != expected_attempt_id:
        raise AtomicCompositionError("s4_verifier_attempt_identity_mismatch")
    if composition.verifier_identity_512 != VERIFIER_REFERENCE_IDENTITY_512:
        raise AtomicCompositionError("s4_verifier_module_identity_mismatch")
    expected_receipt = AtomicReceipt(
        expected_attempt_id,
        transition_digest,
        expected_proof_identity,
        VERIFIER_REFERENCE_IDENTITY_512,
        composition.commitment.commitment_512,
    )
    if composition.receipt != expected_receipt:
        raise AtomicCompositionError("s4_verifier_receipt_mismatch")


__all__ = (
    "ACTIVATION_ALLOWED",
    "H4_PARENT_BINDING_STATUS",
    "H4_PARENT_REFERENCE_IDENTITY_512",
    "PROOF_SUITE_ID",
    "PUBLIC_PROJECTION_FIELD_COUNT",
    "STATUS",
    "VERIFIER_REFERENCE_IDENTITY_512",
    "AtomicComposition",
    "AtomicCompositionError",
    "AtomicReceipt",
    "build_atomic_composition",
    "canonical_relation_payload",
    "derive_composition_statement",
    "independently_verify_composition",
)
