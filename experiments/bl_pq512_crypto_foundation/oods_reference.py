"""Theorem-matched Fp16/Fp8-excluding OODS parameter reference.

This module samples the stereographic parameter uniformly from ``Fp16 \\ Fp8``.
It is a non-constant-time KAT/reference surface and cannot activate a proof
suite.  The authenticated public-coin transcript fixes its seed and round.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from experiments.bl_pq512_crypto_foundation.field16_reference import (
    ACCEPTANCE_LIMIT,
    ACCEPTANCE_MULTIPLIER,
    FIELD_ORDER,
    HASH_SPACE,
    M31_MODULUS,
    REJECTION_COUNT,
    Fp16,
)


OODS_SAMPLE_MAGIC: Final[bytes] = b"BLPQOODS"
OODS_SAMPLE_VERSION: Final[int] = 1
OODS_SAMPLE_DOMAIN_CODE: Final[int] = 779
OODS_DEFAULT_MAX_ATTEMPTS: Final[int] = 16

# Every accepted Fp16 value has exactly ACCEPTANCE_MULTIPLIER preimages below
# ACCEPTANCE_LIMIT.  Remove all p^8 values in the embedded Fp8 subfield.
OODS_REJECTION_COUNT: Final[int] = (
    REJECTION_COUNT + ACCEPTANCE_MULTIPLIER * M31_MODULUS**8
)


@dataclass(frozen=True, slots=True)
class OodsParameter:
    """An Fp16 stereographic parameter proven not to lie in the fixed Fp8."""

    element: Fp16

    def __post_init__(self) -> None:
        if type(self.element) is not Fp16:
            raise TypeError("oods_parameter_must_be_exact_fp16")
        if self.element.is_in_fp8_subfield():
            raise ValueError("oods_parameter_in_fp8_fixed_subfield")


@dataclass(frozen=True, slots=True)
class SampledOodsParameter:
    """One accepted OODS parameter plus replayable rejection evidence."""

    parameter: OodsParameter
    accepted_attempt: int
    digest: bytes

    def __post_init__(self) -> None:
        if type(self.parameter) is not OodsParameter:
            raise TypeError("oods_sample_parameter_type_invalid")
        if (
            type(self.accepted_attempt) is not int
            or self.accepted_attempt < 0
            or self.accepted_attempt >= OODS_DEFAULT_MAX_ATTEMPTS
        ):
            raise ValueError("oods_sample_attempt_invalid")
        if type(self.digest) is not bytes or len(self.digest) != 64:
            raise ValueError("oods_sample_digest_must_be_64_bytes")


@dataclass(frozen=True, slots=True)
class CirclePoint:
    """One point on x^2 + y^2 = 1 over Fp16."""

    x: Fp16
    y: Fp16

    def __post_init__(self) -> None:
        if type(self.x) is not Fp16 or type(self.y) is not Fp16:
            raise TypeError("oods_circle_point_coordinates_must_be_exact_fp16")


def sample_oods_parameter(
    seed: bytes,
    *,
    session_id: bytes,
    round_index: int,
    max_attempts: int = OODS_DEFAULT_MAX_ATTEMPTS,
) -> SampledOodsParameter:
    """Uniformly sample from Fp16 with the embedded Fp8 removed.

    Both out-of-range 512-bit draws and fixed-subfield field values are
    rejected.  No rejected digest is repaired or remapped.
    """

    for label, value in (("seed", seed), ("session_id", session_id)):
        if type(value) is not bytes or len(value) != 64:
            raise ValueError(f"oods_sample_{label}_must_be_64_bytes")
    if type(round_index) is not int or round_index < 0 or round_index > 0xFFFFFFFF:
        raise ValueError("oods_sample_round_index_not_u32")
    if type(max_attempts) is not int or max_attempts < 1 or max_attempts > 0xFFFF:
        raise ValueError("oods_sample_max_attempts_not_u16_positive")

    prefix = b"".join(
        (
            OODS_SAMPLE_MAGIC,
            OODS_SAMPLE_VERSION.to_bytes(2, "big"),
            OODS_SAMPLE_DOMAIN_CODE.to_bytes(2, "big"),
            session_id,
            seed,
            round_index.to_bytes(4, "big"),
        )
    )
    for attempt in range(max_attempts):
        digest = sha3_512(prefix + attempt.to_bytes(2, "big")).digest()
        candidate = int.from_bytes(digest, "big")
        if candidate >= ACCEPTANCE_LIMIT:
            continue
        element = Fp16.from_integer(candidate % FIELD_ORDER)
        if element.is_in_fp8_subfield():
            continue
        return SampledOodsParameter(
            parameter=OodsParameter(element),
            accepted_attempt=attempt,
            digest=digest,
        )
    raise RuntimeError("oods_rejection_sampling_attempt_cap_exhausted")


def oods_rejection_failure_fraction(
    max_attempts: int = OODS_DEFAULT_MAX_ATTEMPTS,
) -> tuple[int, int]:
    """Return the exact random-oracle OODS-sampler abort fraction."""

    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError("oods_failure_bound_attempts_must_be_positive")
    return OODS_REJECTION_COUNT**max_attempts, HASH_SPACE**max_attempts


def stereographic_circle_point(parameter: OodsParameter) -> CirclePoint:
    """Map a validated parameter to the unit circle without exceptional repair."""

    if type(parameter) is not OodsParameter:
        raise TypeError("oods_parameter_type_required")
    t = parameter.element
    one = Fp16.one()
    two = Fp16((2,) + (0,) * 15)
    t_squared = t * t
    denominator = one + t_squared
    try:
        denominator_inverse = denominator.inverse()
    except ZeroDivisionError as exc:
        # For a validated t outside Fp8 this is algebraically unreachable:
        # both roots of t^2 = -1 lie in Fp2, hence in the excluded Fp8.
        raise RuntimeError("oods_exceptional_denominator") from exc
    return CirclePoint(
        x=(one - t_squared) * denominator_inverse,
        y=(two * t) * denominator_inverse,
    )
