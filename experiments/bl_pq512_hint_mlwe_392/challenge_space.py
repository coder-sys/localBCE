"""Exact arithmetic screen for autostable Hint-MLWE challenges."""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bl_pq512_hint_mlwe_392.parameter_gate import PER_TERM_BITS


def autostable_coefficients(
    independent_coefficients: tuple[int, ...],
) -> tuple[int, ...]:
    """Match LaZer's `_intvec_urandom_autostable` coefficient layout."""

    if not independent_coefficients:
        raise ValueError("independent_coefficients_required")
    first_half = tuple(independent_coefficients)
    degree = 2 * len(first_half)
    result = [*first_half, 0]
    result.extend(-first_half[degree - index] for index in range(
        len(first_half) + 1, degree
    ))
    return tuple(result)


def negacyclic_product(
    left: tuple[int, ...], right: tuple[int, ...]
) -> tuple[int, ...]:
    if not left or len(left) != len(right):
        raise ValueError("equal_nonempty_polynomials_required")
    degree = len(left)
    result = [0] * degree
    for left_index, left_value in enumerate(left):
        for right_index, right_value in enumerate(right):
            output_index = left_index + right_index
            product = left_value * right_value
            if output_index >= degree:
                result[output_index - degree] -= product
            else:
                result[output_index] += product
    return tuple(result)


def challenge_product_l1(
    independent_coefficients: tuple[int, ...],
) -> int:
    challenge = autostable_coefficients(independent_coefficients)
    product = negacyclic_product(challenge, challenge)
    return sum(abs(coefficient) for coefficient in product)


def challenge_meets_eta(
    independent_coefficients: tuple[int, ...], eta: int
) -> bool:
    if type(eta) is not int or eta <= 0:
        raise ValueError("eta_must_be_positive_integer")
    return challenge_product_l1(independent_coefficients) <= eta * eta


def conservative_challenge_bits(degree: int, omega: int) -> int:
    """Published-source convention: floor(log2(|C|)) minus one bit."""

    if type(degree) is not int or degree <= 0 or degree % 2:
        raise ValueError("degree_must_be_positive_even")
    if type(omega) is not int or omega <= 0:
        raise ValueError("omega_must_be_positive_integer")
    cardinality = (2 * omega + 1) ** (degree // 2)
    return cardinality.bit_length() - 2


def minimum_omega(degree: int, target_bits: int = PER_TERM_BITS) -> int:
    if type(target_bits) is not int or target_bits <= 0:
        raise ValueError("target_bits_must_be_positive_integer")
    omega = 1
    while conservative_challenge_bits(degree, omega) < target_bits:
        omega += 1
    return omega


def fixed_shape_eta_upper(degree: int, omega: int) -> int:
    """No-rejection upper bound from sqrt(||c*c||_1) <= ||c||_1."""

    if type(degree) is not int or degree <= 0 or degree % 2:
        raise ValueError("degree_must_be_positive_even")
    if type(omega) is not int or omega <= 0:
        raise ValueError("omega_must_be_positive_integer")
    return (degree - 1) * omega


@dataclass(frozen=True, slots=True)
class ChallengeCandidate:
    degree: int
    omega: int
    conservative_bits: int
    fixed_shape_eta_upper: int
    encoded_bytes_upper: int


def derive_single_challenge_candidates(
    degrees: tuple[int, ...] = (64, 128, 256, 512, 1024),
) -> tuple[ChallengeCandidate, ...]:
    candidates: list[ChallengeCandidate] = []
    for degree in degrees:
        omega = minimum_omega(degree)
        bits_per_coefficient = (2 * omega + 1).bit_length()
        candidates.append(
            ChallengeCandidate(
                degree=degree,
                omega=omega,
                conservative_bits=conservative_challenge_bits(
                    degree, omega
                ),
                fixed_shape_eta_upper=fixed_shape_eta_upper(degree, omega),
                encoded_bytes_upper=(
                    bits_per_coefficient * degree + 7
                )
                // 8,
            )
        )
    return tuple(candidates)
