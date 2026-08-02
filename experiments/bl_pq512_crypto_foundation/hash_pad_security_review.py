"""First-principles security decision for the nonactivating SHA3 hash-pad control.

This is a reviewed rejection record, not an admission record.  The construction
has a useful fixed-width one-time-pad component and a working independent
opening verifier, but the current protocol does not establish the full
256-bit post-quantum binding/composition theorem required by Gate 2E.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from .state_plane import (
    COMMITMENT_PARAMETER_IDENTITY,
    HashPadCommitment,
    HashPadOpening,
    build_hash_pad_commitment,
    verify_hash_pad_opening,
)


REVIEW_ID: Final[str] = "BL-PQ512-SHA3-HASH-PAD-SECURITY-REVIEW-V1"
DECISION: Final[str] = "REJECTED_GATE_2E_ADMISSION"
REQUIRED_QUANTUM_BINDING_BITS: Final[int] = 256
SHA3_OUTPUT_BITS: Final[int] = 512
PAD_BITS: Final[int] = 512
GENERIC_QUANTUM_COLLISION_NUMERATOR: Final[int] = 512
GENERIC_QUANTUM_COLLISION_DENOMINATOR: Final[int] = 3
_REVIEW_DOMAIN = b"BL/PQ512/SHA3-HASH-PAD/SECURITY-REVIEW/v1\x00"


@dataclass(frozen=True, slots=True)
class HashPadSecurityReview:
    review_id: str
    parameter_identity: str
    hash_function: str
    hash_output_bits: int
    pad_bits: int
    required_quantum_binding_bits: int
    generic_quantum_collision_numerator: int
    generic_quantum_collision_denominator: int
    ciphertext_hiding: str
    tag_hiding: str
    public_coin_ordering: str
    independent_reference_verifier: bool
    decision: str
    rejection_reasons: tuple[str, ...]
    review_digest_512: bytes = b""

    def __post_init__(self) -> None:
        if self.review_id != REVIEW_ID:
            raise ValueError("hash_pad_review_id_invalid")
        if self.parameter_identity != COMMITMENT_PARAMETER_IDENTITY:
            raise ValueError("hash_pad_review_parameter_invalid")
        if self.hash_function != "SHA3-512" or self.hash_output_bits != SHA3_OUTPUT_BITS:
            raise ValueError("hash_pad_review_hash_invalid")
        if self.pad_bits != PAD_BITS or self.required_quantum_binding_bits != 256:
            raise ValueError("hash_pad_review_parameter_bits_invalid")
        if self.generic_quantum_collision_numerator != SHA3_OUTPUT_BITS:
            raise ValueError("hash_pad_review_collision_numerator_invalid")
        if self.generic_quantum_collision_denominator != 3:
            raise ValueError("hash_pad_review_collision_denominator_invalid")
        if type(self.independent_reference_verifier) is not bool:
            raise ValueError("hash_pad_review_verifier_flag_invalid")
        if self.decision != DECISION or not self.rejection_reasons:
            raise ValueError("hash_pad_review_decision_invalid")
        if any(type(reason) is not str or not reason for reason in self.rejection_reasons):
            raise ValueError("hash_pad_review_reasons_invalid")
        canonical = self.canonical_bytes
        expected = sha3_512(_REVIEW_DOMAIN + canonical).digest()
        if self.review_digest_512 not in (b"", expected):
            raise ValueError("hash_pad_review_digest_mismatch")
        object.__setattr__(self, "review_digest_512", expected)

    @property
    def canonical_bytes(self) -> bytes:
        fields = (
            self.review_id,
            self.parameter_identity,
            self.hash_function,
            str(self.hash_output_bits),
            str(self.pad_bits),
            str(self.required_quantum_binding_bits),
            str(self.generic_quantum_collision_numerator),
            str(self.generic_quantum_collision_denominator),
            self.ciphertext_hiding,
            self.tag_hiding,
            self.public_coin_ordering,
            str(int(self.independent_reference_verifier)),
            self.decision,
            ",".join(self.rejection_reasons),
        )
        return b"\x00".join(value.encode("ascii") for value in fields)

    @property
    def admitted(self) -> bool:
        return False

    def as_public_dict(self) -> dict[str, object]:
        return {
            "review_id": self.review_id,
            "parameter_identity": self.parameter_identity,
            "hash_function": self.hash_function,
            "hash_output_bits": self.hash_output_bits,
            "pad_bits": self.pad_bits,
            "required_quantum_binding_bits": self.required_quantum_binding_bits,
            "generic_quantum_collision_bound_model": (
                f"2^({self.generic_quantum_collision_numerator}/"
                f"{self.generic_quantum_collision_denominator})"
            ),
            "ciphertext_hiding": self.ciphertext_hiding,
            "tag_hiding": self.tag_hiding,
            "public_coin_ordering": self.public_coin_ordering,
            "independent_reference_verifier": self.independent_reference_verifier,
            "decision": self.decision,
            "admitted": self.admitted,
            "rejection_reasons": self.rejection_reasons,
            "review_digest_sha3_512_hex": self.review_digest_512.hex(),
        }


def hash_pad_security_review() -> HashPadSecurityReview:
    """Return the immutable current review decision for the hash-pad control."""

    return HashPadSecurityReview(
        review_id=REVIEW_ID,
        parameter_identity=COMMITMENT_PARAMETER_IDENTITY,
        hash_function="SHA3-512",
        hash_output_bits=SHA3_OUTPUT_BITS,
        pad_bits=PAD_BITS,
        required_quantum_binding_bits=REQUIRED_QUANTUM_BINDING_BITS,
        generic_quantum_collision_numerator=GENERIC_QUANTUM_COLLISION_NUMERATOR,
        generic_quantum_collision_denominator=GENERIC_QUANTUM_COLLISION_DENOMINATOR,
        ciphertext_hiding="512-bit XOR pad is hiding only when the mask is uniform and never reused",
        tag_hiding="full tag-hiding theorem is not admitted for arbitrary low-entropy statements",
        public_coin_ordering="coin is supplied to the constructor; commit-before-coin ordering is not frozen",
        independent_reference_verifier=True,
        decision=DECISION,
        rejection_reasons=(
            "full_256_bit_quantum_binding_theorem_missing",
            "commit_before_coin_ordering_not_frozen",
            "generic_sha3_512_quantum_collision_model_below_256_bits",
            "h4_state_air_composition_missing",
        ),
    )


def verify_hash_pad_reference_kat() -> tuple[HashPadCommitment, HashPadOpening]:
    """Exercise the exact nonactivating reference opening used by the review."""

    statement = sha3_512(b"BL/PQ512/hash-pad-review/statement").digest()
    mask = sha3_512(b"BL/PQ512/hash-pad-review/one-time-mask").digest()
    coin = sha3_512(b"BL/PQ512/hash-pad-review/public-coin").digest()
    commitment, opening = build_hash_pad_commitment(statement, mask, coin)
    verify_hash_pad_opening(commitment, opening)
    return commitment, opening


__all__ = (
    "DECISION",
    "GENERIC_QUANTUM_COLLISION_DENOMINATOR",
    "GENERIC_QUANTUM_COLLISION_NUMERATOR",
    "HashPadSecurityReview",
    "PAD_BITS",
    "REQUIRED_QUANTUM_BINDING_BITS",
    "REVIEW_ID",
    "SHA3_OUTPUT_BITS",
    "hash_pad_security_review",
    "verify_hash_pad_reference_kat",
)
