"""Exact loss ledger extracted from ePrint 2025/2239.

The constants here are evidence about the published proof, not a replacement
for formal review of a redesigned protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Final

from experiments.bl_pq512_hint_mlwe_392.parameter_gate import (
    PER_TERM_BITS,
    power_of_two_failure,
)


HINT_MLWE_REDUCTION_EPSILON_MULTIPLIER: Final[int] = 2
FIRST_CONVOLUTION_EPSILON_MULTIPLIER: Final[int] = 8
STRUCTURED_HINT_EPSILON_MULTIPLIER: Final[int] = 2
SECOND_CONVOLUTION_EPSILON_MULTIPLIER: Final[int] = 8
SIMULATABILITY_EPSILON_MULTIPLIER: Final[int] = (
    HINT_MLWE_REDUCTION_EPSILON_MULTIPLIER
    + FIRST_CONVOLUTION_EPSILON_MULTIPLIER
    + STRUCTURED_HINT_EPSILON_MULTIPLIER
    + SECOND_CONVOLUTION_EPSILON_MULTIPLIER
)
PUBLISHED_D64_CHALLENGE_BITS: Final[int] = 129
PUBLISHED_D128_CHALLENGE_BITS: Final[int] = 147


def _bits_floor(probability: Fraction) -> int:
    if not 0 < probability <= 1:
        raise ValueError("probability_must_be_in_zero_one")
    numerator = probability.numerator
    denominator = probability.denominator
    result = denominator.bit_length() - numerator.bit_length()
    if numerator << result > denominator:
        result -= 1
    return result


def minimum_epsilon_bits(multiplier: int, target_bits: int = PER_TERM_BITS) -> int:
    if type(multiplier) is not int or multiplier <= 0:
        raise ValueError("multiplier_must_be_positive_integer")
    if type(target_bits) is not int or target_bits <= 0:
        raise ValueError("target_bits_must_be_positive_integer")
    bits = target_bits
    while _bits_floor(multiplier * power_of_two_failure(bits)) < target_bits:
        bits += 1
    return bits


def completeness_dimension_floor(target_bits: int = PER_TERM_BITS) -> int:
    """Dimension required by the paper's <= 2^(-dimension+1) tail bound."""

    if type(target_bits) is not int or target_bits <= 0:
        raise ValueError("target_bits_must_be_positive_integer")
    return target_bits + 1


def relation_false_positive_bits(modulus: int, ring_degree: int) -> int:
    """Floor bits in the paper's p^(-d/2) relation-combination error."""

    if type(modulus) is not int or modulus <= 1:
        raise ValueError("modulus_must_exceed_one")
    if type(ring_degree) is not int or ring_degree <= 0 or ring_degree % 2:
        raise ValueError("ring_degree_must_be_positive_even")
    return _bits_floor(Fraction(1, modulus ** (ring_degree // 2)))


@dataclass(frozen=True, slots=True)
class PublishedProofFloor:
    epsilon_bits: int
    simulatable_statistical_bits: int
    completeness_dimension: int
    d64_sequential_repetitions_arithmetic_only: int
    d128_sequential_repetitions_arithmetic_only: int
    repetition_theorem_supplied: bool


def derive_published_proof_floor() -> PublishedProofFloor:
    epsilon_bits = minimum_epsilon_bits(SIMULATABILITY_EPSILON_MULTIPLIER)
    epsilon = power_of_two_failure(epsilon_bits)
    return PublishedProofFloor(
        epsilon_bits=epsilon_bits,
        simulatable_statistical_bits=_bits_floor(
            SIMULATABILITY_EPSILON_MULTIPLIER * epsilon
        ),
        completeness_dimension=completeness_dimension_floor(),
        d64_sequential_repetitions_arithmetic_only=(
            PER_TERM_BITS + PUBLISHED_D64_CHALLENGE_BITS - 1
        )
        // PUBLISHED_D64_CHALLENGE_BITS,
        d128_sequential_repetitions_arithmetic_only=(
            PER_TERM_BITS + PUBLISHED_D128_CHALLENGE_BITS - 1
        )
        // PUBLISHED_D128_CHALLENGE_BITS,
        repetition_theorem_supplied=False,
    )
