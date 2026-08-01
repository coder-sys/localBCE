"""Executable, non-constant-time reference for the BL-PQ512 degree-16 field.

The tower deliberately extends S-two's existing M31 -> CM31 -> QM31 tower:

    i^2 = -1
    u^2 = 2 + i
    v^2 = u
    w^2 = v

Elements use the flat basis

    1, i, u, iu, v, iv, uv, iuv,
    w, iw, uw, iuw, vw, ivw, uvw, iuvw.

This module is an algebra/KAT reference.  It is not constant time and cannot
be registered as a production proof module.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Iterable


M31_MODULUS: Final[int] = (1 << 31) - 1
EXTENSION_DEGREE: Final[int] = 16
ENCODED_LENGTH: Final[int] = 64
FIELD_ORDER: Final[int] = M31_MODULUS**EXTENSION_DEGREE
HASH_SPACE: Final[int] = 1 << 512
ACCEPTANCE_MULTIPLIER: Final[int] = HASH_SPACE // FIELD_ORDER
ACCEPTANCE_LIMIT: Final[int] = ACCEPTANCE_MULTIPLIER * FIELD_ORDER
REJECTION_COUNT: Final[int] = HASH_SPACE - ACCEPTANCE_LIMIT
DEFAULT_MAX_ATTEMPTS: Final[int] = 16

SAMPLE_MAGIC: Final[bytes] = b"BLPQF16S"
SAMPLE_VERSION: Final[int] = 1
SAMPLE_DOMAIN_CODE: Final[int] = 776

BASIS: Final[tuple[str, ...]] = (
    "1",
    "i",
    "u",
    "iu",
    "v",
    "iv",
    "uv",
    "iuv",
    "w",
    "iw",
    "uw",
    "iuw",
    "vw",
    "ivw",
    "uvw",
    "iuvw",
)

# Each value is represented in the flat basis of the immediately lower field.
_NONRESIDUES: Final[dict[int, tuple[int, ...]]] = {
    1: (M31_MODULUS - 1,),                 # i^2 = -1
    2: (2, 1),                             # u^2 = 2 + i
    3: (0, 0, 1, 0),                       # v^2 = u
    4: (0, 0, 0, 0, 1, 0, 0, 0),          # w^2 = v
}


def _add(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    return tuple((a + b) % M31_MODULUS for a, b in zip(left, right, strict=True))


def _sub(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    return tuple((a - b) % M31_MODULUS for a, b in zip(left, right, strict=True))


def _neg(value: tuple[int, ...]) -> tuple[int, ...]:
    return tuple((-coefficient) % M31_MODULUS for coefficient in value)


def _mul(left: tuple[int, ...], right: tuple[int, ...], level: int) -> tuple[int, ...]:
    if level == 0:
        return ((left[0] * right[0]) % M31_MODULUS,)
    half = 1 << (level - 1)
    left_a, left_b = left[:half], left[half:]
    right_a, right_b = right[:half], right[half:]
    ac = _mul(left_a, right_a, level - 1)
    bd = _mul(left_b, right_b, level - 1)
    real = _add(ac, _mul(bd, _NONRESIDUES[level], level - 1))
    imaginary = _add(
        _mul(left_a, right_b, level - 1),
        _mul(left_b, right_a, level - 1),
    )
    return real + imaginary


def _pow(value: tuple[int, ...], exponent: int, level: int) -> tuple[int, ...]:
    if type(exponent) is not int or exponent < 0:
        raise ValueError("field16_exponent_must_be_nonnegative_integer")
    result = (1,) + (0,) * ((1 << level) - 1)
    base = value
    remaining = exponent
    while remaining:
        if remaining & 1:
            result = _mul(result, base, level)
        base = _mul(base, base, level)
        remaining >>= 1
    return result


def _coefficient_tuple(values: Iterable[int]) -> tuple[int, ...]:
    coefficients = tuple(values)
    if len(coefficients) != EXTENSION_DEGREE:
        raise ValueError("field16_requires_exactly_16_coefficients")
    if any(type(value) is not int or value < 0 or value >= M31_MODULUS for value in coefficients):
        raise ValueError("field16_coefficient_not_canonical_m31")
    return coefficients


@dataclass(frozen=True, slots=True)
class Fp16:
    """One canonical element of M31^16 in the frozen flat tower basis."""

    coefficients: tuple[int, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "coefficients", _coefficient_tuple(self.coefficients))

    @classmethod
    def zero(cls) -> "Fp16":
        return cls((0,) * EXTENSION_DEGREE)

    @classmethod
    def one(cls) -> "Fp16":
        return cls((1,) + (0,) * (EXTENSION_DEGREE - 1))

    @classmethod
    def from_integer(cls, value: int) -> "Fp16":
        if type(value) is not int or value < 0 or value >= FIELD_ORDER:
            raise ValueError("field16_integer_out_of_range")
        coefficients: list[int] = []
        remaining = value
        for _ in range(EXTENSION_DEGREE):
            remaining, coefficient = divmod(remaining, M31_MODULUS)
            coefficients.append(coefficient)
        if remaining:
            raise AssertionError("field16_integer_conversion_overflow")
        return cls(tuple(coefficients))

    def to_integer(self) -> int:
        value = 0
        for coefficient in reversed(self.coefficients):
            value = value * M31_MODULUS + coefficient
        return value

    def encode(self) -> bytes:
        return b"".join(coefficient.to_bytes(4, "big") for coefficient in self.coefficients)

    def is_in_fp8_subfield(self) -> bool:
        """Return whether top quadratic conjugation fixes this element."""

        return self.coefficients[8:] == (0,) * 8

    def conjugate(self) -> "Fp16":
        """Apply the order-two Fp16/Fp8 conjugation in the frozen basis."""

        return Fp16(self.coefficients[:8] + _neg(self.coefficients[8:]))

    @classmethod
    def decode(cls, encoded: bytes) -> "Fp16":
        if type(encoded) is not bytes:
            raise TypeError("field16_encoding_must_be_bytes")
        if len(encoded) != ENCODED_LENGTH:
            raise ValueError("field16_encoding_length_mismatch")
        coefficients = tuple(
            int.from_bytes(encoded[offset : offset + 4], "big")
            for offset in range(0, ENCODED_LENGTH, 4)
        )
        return cls(coefficients)

    def __add__(self, other: object) -> "Fp16":
        if not isinstance(other, Fp16):
            return NotImplemented
        return Fp16(_add(self.coefficients, other.coefficients))

    def __sub__(self, other: object) -> "Fp16":
        if not isinstance(other, Fp16):
            return NotImplemented
        return Fp16(_sub(self.coefficients, other.coefficients))

    def __neg__(self) -> "Fp16":
        return Fp16(_neg(self.coefficients))

    def __mul__(self, other: object) -> "Fp16":
        if not isinstance(other, Fp16):
            return NotImplemented
        return Fp16(_mul(self.coefficients, other.coefficients, 4))

    def __pow__(self, exponent: int) -> "Fp16":
        return Fp16(_pow(self.coefficients, exponent, 4))

    def inverse(self) -> "Fp16":
        if self == Fp16.zero():
            raise ZeroDivisionError("field16_zero_has_no_inverse")
        return self ** (FIELD_ORDER - 2)

    def __truediv__(self, other: object) -> "Fp16":
        if not isinstance(other, Fp16):
            return NotImplemented
        return self * other.inverse()


@dataclass(frozen=True, slots=True)
class SampledFp16:
    element: Fp16
    accepted_attempt: int
    digest: bytes

    def __post_init__(self) -> None:
        if type(self.accepted_attempt) is not int or self.accepted_attempt < 0:
            raise ValueError("field16_sample_attempt_invalid")
        if type(self.digest) is not bytes or len(self.digest) != 64:
            raise ValueError("field16_sample_digest_must_be_64_bytes")


def sample_uniform_fp16(
    seed: bytes,
    *,
    session_id: bytes,
    round_index: int,
    draw_index: int,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> SampledFp16:
    """Rejection-sample one field element from typed SHA3-512 draws.

    The function never reduces an out-of-range digest modulo the field order.
    Exhausting the fixed attempt cap is a hard failure.
    """

    for label, value in (("seed", seed), ("session_id", session_id)):
        if type(value) is not bytes or len(value) != 64:
            raise ValueError(f"field16_sample_{label}_must_be_64_bytes")
    for label, value in (("round_index", round_index), ("draw_index", draw_index)):
        if type(value) is not int or value < 0 or value > 0xFFFFFFFF:
            raise ValueError(f"field16_sample_{label}_not_u32")
    if type(max_attempts) is not int or max_attempts < 1 or max_attempts > 0xFFFF:
        raise ValueError("field16_sample_max_attempts_not_u16_positive")

    prefix = b"".join(
        (
            SAMPLE_MAGIC,
            SAMPLE_VERSION.to_bytes(2, "big"),
            SAMPLE_DOMAIN_CODE.to_bytes(2, "big"),
            session_id,
            seed,
            round_index.to_bytes(4, "big"),
            draw_index.to_bytes(4, "big"),
        )
    )
    for attempt in range(max_attempts):
        digest = sha3_512(prefix + attempt.to_bytes(2, "big")).digest()
        candidate = int.from_bytes(digest, "big")
        if candidate < ACCEPTANCE_LIMIT:
            return SampledFp16(
                element=Fp16.from_integer(candidate % FIELD_ORDER),
                accepted_attempt=attempt,
                digest=digest,
            )
    raise RuntimeError("field16_rejection_sampling_attempt_cap_exhausted")


def rejection_failure_fraction(max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> tuple[int, int]:
    """Return the exact random-oracle abort fraction after the attempt cap."""

    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError("field16_failure_bound_attempts_must_be_positive")
    return REJECTION_COUNT**max_attempts, HASH_SPACE**max_attempts


def tower_irreducibility_report() -> dict[str, bool]:
    """Evaluate the exact Euler criteria for all four quadratic steps."""

    minus_one_is_nonsquare = pow(M31_MODULUS - 1, (M31_MODULUS - 1) // 2, M31_MODULUS) == (
        M31_MODULUS - 1
    )
    checks = (
        ("two_plus_i_is_nonsquare_in_fp2", (2, 1), 1, M31_MODULUS**2),
        ("u_is_nonsquare_in_fp4", (0, 0, 1, 0), 2, M31_MODULUS**4),
        ("v_is_nonsquare_in_fp8", (0, 0, 0, 0, 1, 0, 0, 0), 3, M31_MODULUS**8),
    )
    result = {"minus_one_is_nonsquare_in_m31": minus_one_is_nonsquare}
    for label, value, level, order in checks:
        expected_minus_one = (M31_MODULUS - 1,) + (0,) * ((1 << level) - 1)
        result[label] = _pow(value, (order - 1) // 2, level) == expected_minus_one
    return result
