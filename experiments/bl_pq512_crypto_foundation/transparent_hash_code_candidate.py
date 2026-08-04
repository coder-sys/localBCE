"""Clean-room transparent hash-code commitment candidate.

This is the smallest candidate that closes the two defects in the retired
512-bit hash-pad control: commitment does not depend on the public coin, and
the binding digest is 1,024 bits.  The candidate is still nonactivating until
its witness-hiding transcript is composed into the actual H4 proof boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import shake_256, sha3_512
from typing import Final


STATUS: Final[str] = "TRANSPARENT_SHAKE256_1024_REFERENCE_CANDIDATE_NONACTIVATING"
BACKEND_ID: Final[str] = "TRANSPARENT_SHAKE256_1024"
PARAMETER_IDENTITY: Final[str] = "BL-PQ512-TRANSPARENT-SHAKE256-1024-V1"
COMMITMENT_MAGIC: Final[bytes] = b"BLTHC02"
COMMITMENT_VERSION: Final[int] = 2
STATEMENT_BYTES: Final[int] = 64
ATTEMPT_BYTES: Final[int] = 64
MASK_BYTES: Final[int] = 128
COMMITMENT_BYTES: Final[int] = 128
PUBLIC_COIN_BYTES: Final[int] = 64
MAX_MULTI_TARGETS: Final[int] = 1 << 32
QUANTUM_COLLISION_BITS: Final[int] = 341
QUANTUM_PREIMAGE_BITS: Final[int] = 512
REQUIRED_SECURITY_BITS: Final[int] = 256

_COMMITMENT_DOMAIN = b"BL/PQ512/TRANSPARENT-SHAKE256-1024/COMMITMENT/v1\x00"
_TRANSCRIPT_DOMAIN = b"BL/PQ512/TRANSPARENT-SHAKE256-1024/COIN-TRANSCRIPT/v1\x00"
_SIMULATOR_DOMAIN = b"BL/PQ512/TRANSPARENT-SHAKE256-1024/SIMULATOR/v1\x00"
_REVIEW_DOMAIN = b"BL/PQ512/TRANSPARENT-SHAKE256-1024/SECURITY-REVIEW/v1\x00"


def _exact_bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ValueError(f"transparent_hash_code_{label}_length_invalid")
    if nonzero and not any(value):
        raise ValueError(f"transparent_hash_code_{label}_zero")
    return value


def _text(label: str, value: object) -> bytes:
    if type(value) is not str or not value or not value.isascii() or "\x00" in value:
        raise ValueError(f"transparent_hash_code_{label}_invalid")
    return value.encode("ascii")


def _part(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ValueError("transparent_hash_code_part_too_large")
    return len(value).to_bytes(4, "big") + value


def _commitment_digest(statement: bytes, attempt_id: bytes, mask: bytes) -> bytes:
    return shake_256(
        _COMMITMENT_DOMAIN
        + _part(_text("parameter", PARAMETER_IDENTITY))
        + _part(attempt_id)
        + _part(statement)
        + _part(mask)
    ).digest(COMMITMENT_BYTES)


@dataclass(frozen=True, slots=True)
class TransparentHashCodeCommitment:
    attempt_id: bytes
    commitment: bytes

    def __post_init__(self) -> None:
        _exact_bytes("attempt_id", self.attempt_id, ATTEMPT_BYTES, nonzero=True)
        _exact_bytes("commitment", self.commitment, COMMITMENT_BYTES, nonzero=True)

    @property
    def canonical_bytes(self) -> bytes:
        parameter = _text("parameter", PARAMETER_IDENTITY)
        return b"".join(
            (
                COMMITMENT_MAGIC,
                bytes((COMMITMENT_VERSION, len(parameter))),
                parameter,
                self.attempt_id,
                self.commitment,
            )
        )

    @property
    def identity_512(self) -> bytes:
        """A SHA3-512 transport identity; binding remains 1,024-bit."""

        return sha3_512(self.canonical_bytes).digest()

    @property
    def commitment_digest_512(self) -> bytes:
        """Common state-plane identity used by the atomic receipt."""

        return self.identity_512

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "parameter_identity": PARAMETER_IDENTITY,
            "attempt_id_sha3_512_hex": self.attempt_id.hex(),
            "commitment_sha3_1024_hex": self.commitment.hex(),
            "commitment_identity_sha3_512_hex": self.identity_512.hex(),
        }


@dataclass(frozen=True, slots=True)
class TransparentHashCodeOpening:
    attempt_id: bytes
    statement: bytes
    mask: bytes

    def __post_init__(self) -> None:
        _exact_bytes("opening_attempt_id", self.attempt_id, ATTEMPT_BYTES, nonzero=True)
        _exact_bytes("statement", self.statement, STATEMENT_BYTES, nonzero=True)
        _exact_bytes("mask", self.mask, MASK_BYTES)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join((_part(self.attempt_id), _part(self.statement), _part(self.mask)))

    @property
    def statement_digest_512(self) -> bytes:
        return self.statement

    @property
    def mask_512(self) -> bytes:
        return self.mask


def commit(
    statement: bytes,
    attempt_id: bytes,
    mask: bytes,
) -> TransparentHashCodeCommitment:
    """Create the commitment before any public coin is available."""

    statement = _exact_bytes("statement", statement, STATEMENT_BYTES, nonzero=True)
    attempt_id = _exact_bytes("attempt_id", attempt_id, ATTEMPT_BYTES, nonzero=True)
    mask = _exact_bytes("mask", mask, MASK_BYTES)
    return TransparentHashCodeCommitment(
        attempt_id=attempt_id,
        commitment=_commitment_digest(statement, attempt_id, mask),
    )


def open_commitment(
    commitment: TransparentHashCodeCommitment,
    statement: bytes,
    mask: bytes,
) -> TransparentHashCodeOpening:
    if type(commitment) is not TransparentHashCodeCommitment:
        raise TypeError("transparent_hash_code_commitment_required")
    opening = TransparentHashCodeOpening(commitment.attempt_id, statement, mask)
    if _commitment_digest(opening.statement, opening.attempt_id, opening.mask) != commitment.commitment:
        raise ValueError("transparent_hash_code_opening_mismatch")
    return opening


def verify_opening(
    commitment: TransparentHashCodeCommitment,
    opening: TransparentHashCodeOpening,
) -> None:
    if type(commitment) is not TransparentHashCodeCommitment:
        raise TypeError("transparent_hash_code_commitment_required")
    if type(opening) is not TransparentHashCodeOpening:
        raise TypeError("transparent_hash_code_opening_required")
    if opening.attempt_id != commitment.attempt_id:
        raise ValueError("transparent_hash_code_attempt_mismatch")
    if _commitment_digest(opening.statement, opening.attempt_id, opening.mask) != commitment.commitment:
        raise ValueError("transparent_hash_code_opening_mismatch")


def bind_authenticated_public_coin(
    commitment: TransparentHashCodeCommitment,
    public_coin: bytes,
) -> bytes:
    """Bind a later authenticated coin without changing the commitment."""

    if type(commitment) is not TransparentHashCodeCommitment:
        raise TypeError("transparent_hash_code_commitment_required")
    public_coin = _exact_bytes("public_coin", public_coin, PUBLIC_COIN_BYTES, nonzero=True)
    return sha3_512(
        _TRANSCRIPT_DOMAIN
        + _part(commitment.canonical_bytes)
        + _part(public_coin)
    ).digest()


def simulate_commitment(simulator_seed: bytes) -> TransparentHashCodeCommitment:
    """Sample the ideal public commitment distribution without a witness.

    This is a distributional simulator reference.  It is not the complete H4
    proof simulator and therefore does not authorize backend admission.
    """

    simulator_seed = _exact_bytes("simulator_seed", simulator_seed, 64, nonzero=True)
    attempt_id = sha3_512(_SIMULATOR_DOMAIN + b"/attempt/" + simulator_seed).digest()
    commitment = shake_256(_SIMULATOR_DOMAIN + b"/commitment/" + simulator_seed).digest(
        COMMITMENT_BYTES
    )
    return TransparentHashCodeCommitment(attempt_id, commitment)


@dataclass(frozen=True, slots=True)
class TransparentHashCodeSecurityLedger:
    parameter_identity: str = PARAMETER_IDENTITY
    output_bits: int = COMMITMENT_BYTES * 8
    quantum_collision_bits: int = QUANTUM_COLLISION_BITS
    quantum_preimage_bits: int = QUANTUM_PREIMAGE_BITS
    multi_target_loss_bits: int = MAX_MULTI_TARGETS.bit_length() - 1
    required_security_bits: int = REQUIRED_SECURITY_BITS

    def __post_init__(self) -> None:
        if (
            self.parameter_identity != PARAMETER_IDENTITY
            or self.output_bits != COMMITMENT_BYTES * 8
            or self.quantum_collision_bits != QUANTUM_COLLISION_BITS
            or self.quantum_preimage_bits != QUANTUM_PREIMAGE_BITS
            or self.multi_target_loss_bits != MAX_MULTI_TARGETS.bit_length() - 1
            or self.required_security_bits != REQUIRED_SECURITY_BITS
        ):
            raise ValueError("transparent_hash_code_security_ledger_mutation")

    @property
    def effective_binding_bits(self) -> int:
        return self.quantum_collision_bits - self.multi_target_loss_bits

    @property
    def effective_hiding_bits(self) -> int:
        return self.quantum_preimage_bits - self.multi_target_loss_bits

    @property
    def meets_floor(self) -> bool:
        return min(self.effective_binding_bits, self.effective_hiding_bits) >= self.required_security_bits

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                _text("parameter", self.parameter_identity),
                self.output_bits.to_bytes(2, "big"),
                self.quantum_collision_bits.to_bytes(2, "big"),
                self.quantum_preimage_bits.to_bytes(2, "big"),
                self.multi_target_loss_bits.to_bytes(2, "big"),
                self.required_security_bits.to_bytes(2, "big"),
                bytes((self.meets_floor,)),
            )
        )

    @property
    def identity_512(self) -> bytes:
        return sha3_512(_COMMITMENT_DOMAIN + self.canonical_bytes).digest()


def security_ledger() -> TransparentHashCodeSecurityLedger:
    return TransparentHashCodeSecurityLedger()


@dataclass(frozen=True, slots=True)
class TransparentHashCodeSecurityReview:
    review_id: str = "BL-PQ512-TRANSPARENT-SHAKE256-1024-REVIEW-V1"
    parameter_identity: str = PARAMETER_IDENTITY
    commitment_before_coin: bool = True
    uniform_mask_required: bool = True
    mask_never_reused: bool = True
    no_fiat_shamir_or_qrom_credit: bool = True
    h4_composition_complete: bool = False
    decision: str = "REVIEWED_CANDIDATE_H4_COMPOSITION_OPEN"
    review_digest_512: bytes = b""

    def __post_init__(self) -> None:
        if (
            self.review_id != "BL-PQ512-TRANSPARENT-SHAKE256-1024-REVIEW-V1"
            or self.parameter_identity != PARAMETER_IDENTITY
            or not self.commitment_before_coin
            or not self.uniform_mask_required
            or not self.mask_never_reused
            or not self.no_fiat_shamir_or_qrom_credit
            or self.h4_composition_complete
            or self.decision != "REVIEWED_CANDIDATE_H4_COMPOSITION_OPEN"
        ):
            raise ValueError("transparent_hash_code_security_review_mutation")
        expected = sha3_512(_REVIEW_DOMAIN + self.canonical_bytes).digest()
        if self.review_digest_512 not in (b"", expected):
            raise ValueError("transparent_hash_code_security_review_digest_mismatch")
        object.__setattr__(self, "review_digest_512", expected)

    @property
    def canonical_bytes(self) -> bytes:
        return b"\x00".join(
            (
                self.review_id.encode("ascii"),
                self.parameter_identity.encode("ascii"),
                b"1" if self.commitment_before_coin else b"0",
                b"1" if self.uniform_mask_required else b"0",
                b"1" if self.mask_never_reused else b"0",
                b"1" if self.no_fiat_shamir_or_qrom_credit else b"0",
                b"1" if self.h4_composition_complete else b"0",
                self.decision.encode("ascii"),
            )
        )


def security_review() -> TransparentHashCodeSecurityReview:
    return TransparentHashCodeSecurityReview()


__all__ = (
    "BACKEND_ID",
    "COMMITMENT_BYTES",
    "COMMITMENT_MAGIC",
    "COMMITMENT_VERSION",
    "MASK_BYTES",
    "PARAMETER_IDENTITY",
    "STATUS",
    "TransparentHashCodeCommitment",
    "TransparentHashCodeOpening",
    "TransparentHashCodeSecurityLedger",
    "TransparentHashCodeSecurityReview",
    "bind_authenticated_public_coin",
    "commit",
    "open_commitment",
    "security_ledger",
    "security_review",
    "simulate_commitment",
    "verify_opening",
)
