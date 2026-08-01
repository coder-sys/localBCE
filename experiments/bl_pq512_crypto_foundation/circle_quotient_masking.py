"""Canonical two-component Circle quotient masking reference.

S-two's current Circle composition split has the pointwise identity

    q(P) = q_left(P) + phi(P) * q_right(P).

The canonical-decomposition mask

    q_left_hat  = q_left + phi * t
    q_right_hat = q_right - t

preserves that identity exactly.  This is the Circle analogue of the
independently randomized canonical quotient decomposition in Section 4.1 of
Haboeck--Al Kindi (2024).  The extension-coefficient mask ``t`` needs
``n_oods + n_fri`` degrees of freedom; the conservative trace-mask bound is
retained unchanged rather than reduced.

This scalar module proves the masking algebra and constructs the conditional
evaluation distribution.  It is not integrated into a prover, does not freeze
the final split factor/degree, and is not the complete interactive simulator.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Sequence

from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import CirclePoint


QUOTIENT_MASK_STATUS: Final[str] = (
    "WAVE1B_CANONICAL_CIRCLE_QUOTIENT_MASK_CONSTRUCTIVE_NONACTIVATING"
)
QUOTIENT_MASK_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/CANONICAL-CIRCLE-QUOTIENT-MASK/v1"
)
EXTENSION_DEGREE: Final[int] = 16
COMPONENT_COUNT: Final[int] = 2
CIRCLE_SPLIT_LOG_REDUCTION: Final[int] = 1
CIRCLE_SPLIT_FACTOR_RULE: Final[str] = (
    "REPEATED_DOUBLE_OODS_X_AT_MAX_LOG_DEGREE_BOUND_MINUS_ONE"
)


def _exact_int(label: str, value: object, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"circle_quotient_{label}_invalid")
    return value


def _poly_eval(coefficients: Sequence[Fp16], point: Fp16) -> Fp16:
    result = Fp16.zero()
    for coefficient in reversed(coefficients):
        if type(coefficient) is not Fp16:
            raise TypeError("circle_quotient_coefficient_must_be_fp16")
        result = result * point + coefficient
    return result


def _poly_add(left: Sequence[Fp16], right: Sequence[Fp16]) -> list[Fp16]:
    size = max(len(left), len(right))
    result = [Fp16.zero()] * size
    for index in range(size):
        result[index] = (
            (left[index] if index < len(left) else Fp16.zero())
            + (right[index] if index < len(right) else Fp16.zero())
        )
    while len(result) > 1 and result[-1] == Fp16.zero():
        result.pop()
    return result


def _poly_scale(coefficients: Sequence[Fp16], scalar: Fp16) -> list[Fp16]:
    if type(scalar) is not Fp16:
        raise TypeError("circle_quotient_scale_must_be_fp16")
    return [coefficient * scalar for coefficient in coefficients]


def _poly_mul(left: Sequence[Fp16], right: Sequence[Fp16]) -> list[Fp16]:
    if not left or not right:
        return [Fp16.zero()]
    result = [Fp16.zero()] * (len(left) + len(right) - 1)
    for left_index, left_value in enumerate(left):
        if type(left_value) is not Fp16:
            raise TypeError("circle_quotient_coefficient_must_be_fp16")
        for right_index, right_value in enumerate(right):
            if type(right_value) is not Fp16:
                raise TypeError("circle_quotient_coefficient_must_be_fp16")
            result[left_index + right_index] = (
                result[left_index + right_index] + left_value * right_value
            )
    return result


@dataclass(frozen=True, slots=True)
class CanonicalCircleQuotientMaskPlan:
    """Exact unselected quotient-mask freedom for one candidate profile."""

    profile_id: str
    reduced_air_degree: int
    oods_query_count: int
    fri_query_count: int
    trace_mask_degree_freedom: int
    quotient_mask_degree_freedom: int
    coefficient_extension_degree: int = EXTENSION_DEGREE
    component_count: int = COMPONENT_COUNT
    decomposition: str = "CANONICAL_TWO_COMPONENT_CIRCLE_SPLIT"
    split_log_reduction: int = CIRCLE_SPLIT_LOG_REDUCTION
    split_factor_rule: str = CIRCLE_SPLIT_FACTOR_RULE
    status: str = QUOTIENT_MASK_STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False
    prover_integrated: bool = False
    simulator_complete: bool = False

    def __post_init__(self) -> None:
        if type(self.profile_id) is not str or not self.profile_id.isascii() or not self.profile_id:
            raise ValueError("circle_quotient_profile_id_invalid")
        _exact_int("reduced_air_degree", self.reduced_air_degree, 1)
        _exact_int("oods_query_count", self.oods_query_count, 1)
        _exact_int("fri_query_count", self.fri_query_count, 1)
        expected_trace = 2 * self.reduced_air_degree * (
            self.coefficient_extension_degree * self.oods_query_count
            + self.fri_query_count
        ) + self.fri_query_count
        if self.trace_mask_degree_freedom != expected_trace:
            raise ValueError("circle_quotient_trace_mask_degree_mismatch")
        expected_quotient = self.oods_query_count + self.fri_query_count
        if self.quotient_mask_degree_freedom != expected_quotient:
            raise ValueError("circle_quotient_mask_degree_mismatch")
        if self.coefficient_extension_degree != EXTENSION_DEGREE:
            raise ValueError("circle_quotient_extension_degree_mismatch")
        if self.component_count != COMPONENT_COUNT:
            raise ValueError("circle_quotient_component_count_mismatch")
        if self.decomposition != "CANONICAL_TWO_COMPONENT_CIRCLE_SPLIT":
            raise ValueError("circle_quotient_decomposition_mismatch")
        if self.split_log_reduction != CIRCLE_SPLIT_LOG_REDUCTION:
            raise ValueError("circle_quotient_split_log_reduction_mismatch")
        if self.split_factor_rule != CIRCLE_SPLIT_FACTOR_RULE:
            raise ValueError("circle_quotient_split_factor_rule_mismatch")
        if (
            self.status != QUOTIENT_MASK_STATUS
            or self.proof_suite_id is not None
            or self.activation_allowed
            or self.prover_integrated
            or self.simulator_complete
        ):
            raise ValueError("circle_quotient_nonactivating_boundary_violated")

    @property
    def canonical_bytes(self) -> bytes:
        profile = self.profile_id.encode("ascii")
        return b"".join(
            (
                QUOTIENT_MASK_DOMAIN,
                len(profile).to_bytes(2, "big"),
                profile,
                self.reduced_air_degree.to_bytes(2, "big"),
                self.oods_query_count.to_bytes(2, "big"),
                self.fri_query_count.to_bytes(4, "big"),
                self.trace_mask_degree_freedom.to_bytes(8, "big"),
                self.quotient_mask_degree_freedom.to_bytes(8, "big"),
                self.coefficient_extension_degree.to_bytes(2, "big"),
                self.component_count.to_bytes(2, "big"),
                self.split_log_reduction.to_bytes(2, "big"),
                bytes((self.activation_allowed, self.prover_integrated, self.simulator_complete)),
            )
        )

    @property
    def commitment_sha3_512(self) -> bytes:
        return sha3_512(self.canonical_bytes).digest()


def build_canonical_circle_quotient_mask_plan(
    *,
    profile_id: str,
    reduced_air_degree: int,
    oods_query_count: int,
    fri_query_count: int,
) -> CanonicalCircleQuotientMaskPlan:
    trace_h = 2 * reduced_air_degree * (
        EXTENSION_DEGREE * oods_query_count + fri_query_count
    ) + fri_query_count
    return CanonicalCircleQuotientMaskPlan(
        profile_id=profile_id,
        reduced_air_degree=reduced_air_degree,
        oods_query_count=oods_query_count,
        fri_query_count=fri_query_count,
        trace_mask_degree_freedom=trace_h,
        quotient_mask_degree_freedom=oods_query_count + fri_query_count,
    )


def canonical_circle_split_factor(
    oods_point: CirclePoint, *, max_log_degree_bound: int
) -> Fp16:
    """Return S-two's exact two-half Circle coefficient split factor.

    If a Circle polynomial's coefficient vector is split into equal left and
    right halves, evaluation reconstructs as ``left(Q) + phi(Q)*right(Q)``
    with ``phi(Q) = repeated_double(Q, L - 1).x``.  ``L`` is the maximum
    composition log-degree bound, which remains a final-AIR-derived input.
    """

    if type(oods_point) is not CirclePoint:
        raise TypeError("circle_quotient_oods_point_required")
    _exact_int("max_log_degree_bound", max_log_degree_bound, 1)
    if oods_point.x * oods_point.x + oods_point.y * oods_point.y != Fp16.one():
        raise ValueError("circle_quotient_oods_point_not_on_circle")
    x = oods_point.x
    y = oods_point.y
    two = Fp16((2,) + (0,) * 15)
    for _ in range(max_log_degree_bound - CIRCLE_SPLIT_LOG_REDUCTION):
        x, y = x * x - y * y, two * x * y
    if x * x + y * y != Fp16.one():
        raise AssertionError("circle_quotient_repeated_double_left_circle")
    return x


def mask_canonical_quotient_pair(
    *,
    left: Fp16,
    right: Fp16,
    split_factor: Fp16,
    mask_value: Fp16,
) -> tuple[Fp16, Fp16]:
    """Mask two component evaluations while preserving their joined value."""

    if any(type(value) is not Fp16 for value in (left, right, split_factor, mask_value)):
        raise TypeError("circle_quotient_mask_inputs_must_be_fp16")
    joined = left + split_factor * right
    masked_left = left + split_factor * mask_value
    masked_right = right - mask_value
    if masked_left + split_factor * masked_right != joined:
        raise AssertionError("circle_quotient_mask_identity_failed")
    return masked_left, masked_right


def interpolate_conditional_quotient_mask(
    *,
    parameters: Sequence[Fp16],
    values: Sequence[Fp16],
    degree_freedom: int,
    free_coefficients: Sequence[Fp16],
) -> tuple[Fp16, ...]:
    """Interpolate the full affine Circle-mask space over Fp16 coefficients."""

    if any(isinstance(item, (bytes, bytearray, str)) for item in (parameters, values, free_coefficients)):
        raise TypeError("circle_quotient_sequences_required")
    points = tuple(parameters)
    targets = tuple(values)
    free = tuple(free_coefficients)
    if not points or len(points) != len(targets):
        raise ValueError("circle_quotient_parameter_value_count_mismatch")
    if any(type(value) is not Fp16 for value in (*points, *targets, *free)):
        raise TypeError("circle_quotient_values_must_be_fp16")
    if len(set(points)) != len(points):
        raise ValueError("circle_quotient_parameters_not_distinct")
    _exact_int("degree_freedom", degree_freedom, 1)
    if degree_freedom < len(points):
        raise ValueError("circle_quotient_degree_freedom_below_rank")
    if len(free) != degree_freedom - len(points):
        raise ValueError("circle_quotient_free_coefficient_count_mismatch")

    circle_degree = degree_freedom // 2
    if degree_freedom > 2 * circle_degree + 1:
        raise ValueError("circle_quotient_basis_dimension_too_small")
    polynomial = [Fp16.zero()]
    modulus = [Fp16.one()]
    for point, value in zip(points, targets, strict=True):
        circle_denominator = (Fp16.one() + point * point) ** circle_degree
        if circle_denominator == Fp16.zero():
            raise ValueError("circle_quotient_circle_denominator_zero")
        numerator_target = value * circle_denominator
        crt_denominator = _poly_eval(modulus, point)
        if crt_denominator == Fp16.zero():
            raise ValueError("circle_quotient_crt_denominator_zero")
        correction = (
            numerator_target - _poly_eval(polynomial, point)
        ) / crt_denominator
        polynomial = _poly_add(polynomial, _poly_scale(modulus, correction))
        modulus = _poly_mul(modulus, (-point, Fp16.one()))

    polynomial = _poly_add(polynomial, _poly_mul(modulus, free))
    polynomial.extend([Fp16.zero()] * (degree_freedom - len(polynomial)))
    if len(polynomial) != degree_freedom:
        raise AssertionError("circle_quotient_interpolation_degree_overflow")
    return tuple(polynomial)


def evaluate_quotient_mask(
    coefficients: Sequence[Fp16], parameter: Fp16
) -> Fp16:
    if not coefficients or type(parameter) is not Fp16:
        raise ValueError("circle_quotient_evaluation_input_invalid")
    degree = len(coefficients) // 2
    denominator = (Fp16.one() + parameter * parameter) ** degree
    if denominator == Fp16.zero():
        raise ValueError("circle_quotient_circle_denominator_zero")
    return _poly_eval(coefficients, parameter) / denominator


__all__ = [
    "CIRCLE_SPLIT_FACTOR_RULE",
    "CIRCLE_SPLIT_LOG_REDUCTION",
    "QUOTIENT_MASK_STATUS",
    "CanonicalCircleQuotientMaskPlan",
    "build_canonical_circle_quotient_mask_plan",
    "canonical_circle_split_factor",
    "evaluate_quotient_mask",
    "interpolate_conditional_quotient_mask",
    "mask_canonical_quotient_pair",
]
