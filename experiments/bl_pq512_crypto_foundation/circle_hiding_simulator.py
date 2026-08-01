"""Constructive direct Circle evaluation-map and conditional-mask reference.

For the stereographic parameter ``t`` of a circle point, the degree-``d``
Circle basis is represented by numerator monomials

    1, t, ..., t^(2d)

scaled by ``(1+t^2)^(-d)``.  Every scaled monomial is a polynomial in the
circle coordinates, so the first ``h <= 2d+1`` monomials form an explicit
``h``-dimensional base-field function subspace.

Every OODS parameter outside Fp8 has exact degree 16 over M31.  Pairwise-
distinct degree-16 minimal polynomials are coprime to each other and to every
M31 query factor ``T-a``.  The Chinese remainder theorem makes simultaneous
evaluation onto those Fp16 values plus the base queries surjective whenever
``h`` is large enough.  The interpolation routine below is constructive and
samples the complete affine solution space when its free coefficients are
uniform.

This module covers the *direct* trace-oracle evaluation map.  It deliberately
does not claim the larger quotient-component closure or the full interactive
simulator: those require the final Circle quotient decomposition and expanded
AIR oracle inventory.

This is a scalar, non-constant-time theorem/KAT surface.  It is not a prover,
does not source production randomness, and cannot activate a proof suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Sequence

from experiments.bl_pq512_crypto_foundation.circle_fri_reference import (
    MAX_CIRCLE_DOMAIN_LOG_SIZE,
    MIN_CIRCLE_DOMAIN_LOG_SIZE,
    BaseCirclePoint,
    bit_reverse_index,
    canonic_circle_point,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import (
    M31_MODULUS,
    Fp16,
)


EVALUATION_MAP_STATUS: Final[str] = (
    "WAVE1B_CIRCLE_DIRECT_EVALUATION_MAP_CONSTRUCTIVE_REFERENCE_NONACTIVATING"
)
EVALUATION_MAP_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/CIRCLE-EVALUATION-MAP/v1"
)
EXTENSION_DEGREE: Final[int] = 16


def _base(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < M31_MODULUS:
        raise ValueError(f"circle_hiding_{label}_not_canonical_m31")
    return value


def _fp16_from_base(value: int) -> Fp16:
    return Fp16((_base(value, "embedded_value"),) + (0,) * 15)


def _poly_eval_base(coefficients: Sequence[int], point: int) -> int:
    point = _base(point, "evaluation_point")
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * point + _base(coefficient, "coefficient")) % M31_MODULUS
    return result


def _poly_eval_fp16(coefficients: Sequence[int], point: Fp16) -> Fp16:
    if type(point) is not Fp16:
        raise TypeError("circle_hiding_fp16_evaluation_point_required")
    result = Fp16.zero()
    for coefficient in reversed(coefficients):
        result = result * point + _fp16_from_base(coefficient)
    return result


def _poly_add(left: Sequence[int], right: Sequence[int]) -> list[int]:
    size = max(len(left), len(right))
    result = [0] * size
    for index in range(size):
        result[index] = (
            (left[index] if index < len(left) else 0)
            + (right[index] if index < len(right) else 0)
        ) % M31_MODULUS
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result


def _poly_sub(left: Sequence[int], right: Sequence[int]) -> list[int]:
    return _poly_add(left, _poly_scale(right, (-1) % M31_MODULUS))


def _poly_scale(coefficients: Sequence[int], scalar: int) -> list[int]:
    scalar = _base(scalar, "scale")
    return [(_base(value, "coefficient") * scalar) % M31_MODULUS for value in coefficients]


def _poly_mul(left: Sequence[int], right: Sequence[int]) -> list[int]:
    if not left or not right:
        return [0]
    result = [0] * (len(left) + len(right) - 1)
    for left_index, left_value in enumerate(left):
        for right_index, right_value in enumerate(right):
            result[left_index + right_index] = (
                result[left_index + right_index]
                + _base(left_value, "coefficient")
                * _base(right_value, "coefficient")
            ) % M31_MODULUS
    return result


def _poly_mul_linear(coefficients: Sequence[int], root: int) -> list[int]:
    root = _base(root, "linear_root")
    return _poly_mul(coefficients, ((-root) % M31_MODULUS, 1))


def _poly_divmod(
    numerator: Sequence[int], denominator: Sequence[int]
) -> tuple[list[int], list[int]]:
    top = [_base(value, "coefficient") for value in numerator]
    bottom = [_base(value, "coefficient") for value in denominator]
    while len(top) > 1 and top[-1] == 0:
        top.pop()
    while len(bottom) > 1 and bottom[-1] == 0:
        bottom.pop()
    if len(bottom) == 1 and bottom[0] == 0:
        raise ZeroDivisionError("circle_hiding_polynomial_division_by_zero")
    if len(top) < len(bottom):
        return [0], top
    quotient = [0] * (len(top) - len(bottom) + 1)
    inverse_lead = pow(bottom[-1], M31_MODULUS - 2, M31_MODULUS)
    while len(top) >= len(bottom) and not (len(top) == 1 and top[0] == 0):
        offset = len(top) - len(bottom)
        factor = top[-1] * inverse_lead % M31_MODULUS
        quotient[offset] = factor
        for index, coefficient in enumerate(bottom):
            top[offset + index] = (
                top[offset + index] - factor * coefficient
            ) % M31_MODULUS
        while len(top) > 1 and top[-1] == 0:
            top.pop()
    return quotient, top


def _poly_mod(numerator: Sequence[int], denominator: Sequence[int]) -> list[int]:
    return _poly_divmod(numerator, denominator)[1]


def _poly_inverse_mod(value: Sequence[int], modulus: Sequence[int]) -> list[int]:
    old_remainder = [_base(coefficient, "coefficient") for coefficient in modulus]
    remainder = _poly_mod(value, modulus)
    old_coefficient = [0]
    coefficient = [1]
    while not (len(remainder) == 1 and remainder[0] == 0):
        quotient, next_remainder = _poly_divmod(old_remainder, remainder)
        old_remainder, remainder = remainder, next_remainder
        old_coefficient, coefficient = coefficient, _poly_sub(
            old_coefficient, _poly_mul(quotient, coefficient)
        )
    if len(old_remainder) != 1 or old_remainder[0] == 0:
        raise ValueError("circle_hiding_crt_factors_not_coprime")
    inverse = pow(old_remainder[0], M31_MODULUS - 2, M31_MODULUS)
    return _poly_mod(_poly_scale(old_coefficient, inverse), modulus)


def _crt_extend(
    polynomial: Sequence[int],
    accumulated_modulus: Sequence[int],
    factor: Sequence[int],
    target_remainder: Sequence[int],
) -> tuple[list[int], list[int]]:
    inverse = _poly_inverse_mod(accumulated_modulus, factor)
    delta = _poly_mod(_poly_sub(target_remainder, polynomial), factor)
    correction = _poly_mod(_poly_mul(delta, inverse), factor)
    combined = _poly_add(polynomial, _poly_mul(accumulated_modulus, correction))
    modulus = _poly_mul(accumulated_modulus, factor)
    if _poly_mod(combined, factor) != _poly_mod(target_remainder, factor):
        raise AssertionError("circle_hiding_crt_extension_failed")
    return combined, modulus


def minimal_polynomial_fp16(value: Fp16) -> tuple[int, ...]:
    """Return the exact monic M31 minimal polynomial of a degree-16 value."""

    if type(value) is not Fp16:
        raise TypeError("circle_hiding_fp16_value_required")
    if value.is_in_fp8_subfield():
        raise ValueError("circle_hiding_extension_value_not_degree_sixteen")

    orbit: list[Fp16] = []
    current = value
    for _ in range(EXTENSION_DEGREE):
        if current in orbit:
            raise ValueError("circle_hiding_frobenius_orbit_too_short")
        orbit.append(current)
        current = current**M31_MODULUS
    if current != value:
        raise AssertionError("circle_hiding_frobenius_orbit_did_not_close")

    polynomial = [Fp16.one()]
    for root in orbit:
        next_polynomial = [Fp16.zero()] * (len(polynomial) + 1)
        for index, coefficient in enumerate(polynomial):
            next_polynomial[index] = next_polynomial[index] - coefficient * root
            next_polynomial[index + 1] = next_polynomial[index + 1] + coefficient
        polynomial = next_polynomial

    coefficients: list[int] = []
    for coefficient in polynomial:
        if coefficient.coefficients[1:] != (0,) * 15:
            raise AssertionError("circle_hiding_minimal_polynomial_not_over_base_field")
        coefficients.append(coefficient.coefficients[0])
    if len(coefficients) != 17 or coefficients[-1] != 1:
        raise AssertionError("circle_hiding_minimal_polynomial_not_monic_degree_sixteen")
    return tuple(coefficients)


def circle_query_parameter(evaluation_log_size: int, query_position: int) -> int:
    if type(evaluation_log_size) is not int or not (
        MIN_CIRCLE_DOMAIN_LOG_SIZE
        <= evaluation_log_size
        <= MAX_CIRCLE_DOMAIN_LOG_SIZE
    ):
        raise ValueError("circle_hiding_evaluation_log_size_invalid")
    domain_size = 1 << evaluation_log_size
    if type(query_position) is not int or not 0 <= query_position < domain_size:
        raise ValueError("circle_hiding_query_position_out_of_range")

    # The PCS trace tree opens the exact sampled position. Adjacent values are
    # needed only for the separately masked FRI layer and must not be aliased
    # here: in Circle order they are distinct conjugate points.
    natural_index = bit_reverse_index(query_position, evaluation_log_size)
    point = canonic_circle_point(evaluation_log_size, natural_index)
    denominator = (1 + point.x) % M31_MODULUS
    if denominator == 0:
        raise ValueError("circle_hiding_stereographic_infinity_in_query_domain")
    return point.y * pow(denominator, M31_MODULUS - 2, M31_MODULUS) % M31_MODULUS


def translate_circle_parameter(parameter: Fp16, step: BaseCirclePoint) -> Fp16:
    """Translate a stereographic Circle parameter by one base-field point."""

    if type(parameter) is not Fp16:
        raise TypeError("circle_hiding_translation_parameter_must_be_fp16")
    if parameter.is_in_fp8_subfield():
        raise ValueError("circle_hiding_translation_parameter_not_degree_sixteen")
    if type(step) is not BaseCirclePoint:
        raise TypeError("circle_hiding_translation_step_must_be_base_circle_point")
    step_denominator = (1 + step.x) % M31_MODULUS
    if step_denominator == 0:
        raise ValueError("circle_hiding_translation_step_is_stereographic_infinity")
    step_parameter = step.y * pow(
        step_denominator, M31_MODULUS - 2, M31_MODULUS
    ) % M31_MODULUS
    embedded_step = _fp16_from_base(step_parameter)
    denominator = Fp16.one() - parameter * embedded_step
    if denominator == Fp16.zero():
        raise ValueError("circle_hiding_translated_parameter_is_stereographic_infinity")
    translated = (parameter + embedded_step) / denominator
    if translated.is_in_fp8_subfield():
        raise AssertionError("circle_hiding_translation_lost_degree_sixteen")
    return translated


@dataclass(frozen=True, slots=True)
class CircleEvaluationMapCertificate:
    """CRT certificate for direct Fp16 and base-field Circle evaluations."""

    extension_parameters: tuple[Fp16, ...]
    extension_minimal_polynomials: tuple[tuple[int, ...], ...]
    evaluation_log_size: int
    query_positions: tuple[int, ...]
    base_query_parameters: tuple[int, ...]
    unique_base_query_parameters: tuple[int, ...]
    degree_freedom: int
    circle_basis_degree: int
    rank: int
    free_dimension: int
    status: str = EVALUATION_MAP_STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if type(self.extension_parameters) is not tuple or not self.extension_parameters:
            raise ValueError("circle_hiding_extension_parameters_required")
        if any(type(parameter) is not Fp16 for parameter in self.extension_parameters):
            raise TypeError("circle_hiding_extension_parameter_must_be_fp16")
        expected_minimals = tuple(
            minimal_polynomial_fp16(parameter)
            for parameter in self.extension_parameters
        )
        if self.extension_minimal_polynomials != expected_minimals:
            raise ValueError("circle_hiding_minimal_polynomial_mismatch")
        if len(set(expected_minimals)) != len(expected_minimals):
            raise ValueError("circle_hiding_extension_frobenius_orbit_duplicate")
        if type(self.query_positions) is not tuple or not self.query_positions:
            raise ValueError("circle_hiding_query_positions_required")
        expected_parameters = tuple(
            circle_query_parameter(self.evaluation_log_size, position)
            for position in self.query_positions
        )
        if self.base_query_parameters != expected_parameters:
            raise ValueError("circle_hiding_base_query_parameter_mismatch")
        expected_unique = tuple(dict.fromkeys(expected_parameters))
        if self.unique_base_query_parameters != expected_unique:
            raise ValueError("circle_hiding_unique_query_parameter_mismatch")
        if any(
            _poly_eval_base(minimal, point) == 0
            for minimal in expected_minimals
            for point in expected_unique
        ):
            raise ValueError("circle_hiding_query_factor_not_coprime_to_extension_factor")
        if type(self.degree_freedom) is not int or self.degree_freedom < (
            EXTENSION_DEGREE * len(expected_minimals) + len(self.query_positions)
        ):
            raise ValueError("circle_hiding_degree_freedom_below_conservative_query_bound")
        expected_basis_degree = self.degree_freedom // 2
        if self.circle_basis_degree != expected_basis_degree:
            raise ValueError("circle_hiding_basis_degree_mismatch")
        if self.degree_freedom > 2 * self.circle_basis_degree + 1:
            raise ValueError("circle_hiding_basis_dimension_too_small")
        expected_rank = EXTENSION_DEGREE * len(expected_minimals) + len(expected_unique)
        if self.rank != expected_rank:
            raise ValueError("circle_hiding_evaluation_map_rank_mismatch")
        if self.free_dimension != self.degree_freedom - self.rank:
            raise ValueError("circle_hiding_free_dimension_mismatch")
        if (
            self.status != EVALUATION_MAP_STATUS
            or self.proof_suite_id is not None
            or self.activation_allowed
        ):
            raise ValueError("circle_hiding_nonactivating_boundary_violated")

    @property
    def surjective(self) -> bool:
        return True

    @property
    def canonical_bytes(self) -> bytes:
        chunks = [
            EVALUATION_MAP_DOMAIN,
            len(self.extension_parameters).to_bytes(2, "big"),
        ]
        for parameter, minimal in zip(
            self.extension_parameters,
            self.extension_minimal_polynomials,
            strict=True,
        ):
            chunks.extend((parameter.encode(), len(minimal).to_bytes(2, "big")))
            chunks.extend(value.to_bytes(4, "big") for value in minimal)
        chunks.extend(
            (
                self.evaluation_log_size.to_bytes(2, "big"),
                len(self.query_positions).to_bytes(4, "big"),
                self.degree_freedom.to_bytes(8, "big"),
                self.circle_basis_degree.to_bytes(8, "big"),
                self.rank.to_bytes(8, "big"),
                self.free_dimension.to_bytes(8, "big"),
            )
        )
        for position, parameter in zip(
            self.query_positions, self.base_query_parameters, strict=True
        ):
            chunks.extend((position.to_bytes(8, "big"), parameter.to_bytes(4, "big")))
        return b"".join(chunks)

    @property
    def commitment_sha3_512(self) -> bytes:
        return sha3_512(self.canonical_bytes).digest()


def build_circle_evaluation_map_certificate(
    *,
    extension_parameters: Sequence[Fp16],
    evaluation_log_size: int,
    query_positions: Sequence[int],
    degree_freedom: int,
) -> CircleEvaluationMapCertificate:
    if not isinstance(extension_parameters, Sequence) or isinstance(
        extension_parameters, (bytes, bytearray, str)
    ):
        raise TypeError("circle_hiding_extension_parameters_must_be_sequence")
    extensions = tuple(extension_parameters)
    if not extensions:
        raise ValueError("circle_hiding_extension_parameters_required")
    if any(type(parameter) is not Fp16 for parameter in extensions):
        raise TypeError("circle_hiding_extension_parameter_must_be_fp16")
    minimals = tuple(minimal_polynomial_fp16(parameter) for parameter in extensions)
    if len(set(minimals)) != len(minimals):
        raise ValueError("circle_hiding_extension_frobenius_orbit_duplicate")
    if not isinstance(query_positions, Sequence) or isinstance(
        query_positions, (bytes, bytearray, str)
    ):
        raise TypeError("circle_hiding_query_positions_must_be_sequence")
    positions = tuple(query_positions)
    if not positions:
        raise ValueError("circle_hiding_query_positions_required")
    parameters = tuple(
        circle_query_parameter(evaluation_log_size, position) for position in positions
    )
    unique_parameters = tuple(dict.fromkeys(parameters))
    if type(degree_freedom) is not int or degree_freedom < (
        EXTENSION_DEGREE * len(extensions) + len(positions)
    ):
        raise ValueError("circle_hiding_degree_freedom_below_conservative_query_bound")
    rank = EXTENSION_DEGREE * len(extensions) + len(unique_parameters)
    return CircleEvaluationMapCertificate(
        extension_parameters=extensions,
        extension_minimal_polynomials=minimals,
        evaluation_log_size=evaluation_log_size,
        query_positions=positions,
        base_query_parameters=parameters,
        unique_base_query_parameters=unique_parameters,
        degree_freedom=degree_freedom,
        circle_basis_degree=degree_freedom // 2,
        rank=rank,
        free_dimension=degree_freedom - rank,
    )


def _solve_extension_power_basis(point: Fp16, value: Fp16) -> list[int]:
    powers = [Fp16.one()]
    for _ in range(1, EXTENSION_DEGREE):
        powers.append(powers[-1] * point)
    matrix = [
        [powers[column].coefficients[row] for column in range(EXTENSION_DEGREE)]
        + [value.coefficients[row]]
        for row in range(EXTENSION_DEGREE)
    ]
    for column in range(EXTENSION_DEGREE):
        pivot = next(
            (row for row in range(column, EXTENSION_DEGREE) if matrix[row][column]),
            None,
        )
        if pivot is None:
            raise ValueError("circle_hiding_extension_power_basis_singular")
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        inverse = pow(matrix[column][column], M31_MODULUS - 2, M31_MODULUS)
        matrix[column] = [(value * inverse) % M31_MODULUS for value in matrix[column]]
        for row in range(EXTENSION_DEGREE):
            if row == column or matrix[row][column] == 0:
                continue
            factor = matrix[row][column]
            matrix[row] = [
                (left - factor * right) % M31_MODULUS
                for left, right in zip(matrix[row], matrix[column], strict=True)
            ]
    return [matrix[row][-1] for row in range(EXTENSION_DEGREE)]


def interpolate_conditional_circle_mask(
    certificate: CircleEvaluationMapCertificate,
    *,
    extension_values: Sequence[Fp16],
    base_query_values: Sequence[int],
    free_coefficients: Sequence[int],
) -> tuple[int, ...]:
    """Construct one uniform-affine conditional mask from explicit randomness."""

    if type(certificate) is not CircleEvaluationMapCertificate:
        raise TypeError("circle_hiding_certificate_required")
    if not isinstance(extension_values, Sequence) or isinstance(
        extension_values, (bytes, bytearray, str)
    ):
        raise TypeError("circle_hiding_extension_values_must_be_sequence")
    extension_targets = tuple(extension_values)
    if len(extension_targets) != len(certificate.extension_parameters):
        raise ValueError("circle_hiding_extension_value_count_mismatch")
    if any(type(value) is not Fp16 for value in extension_targets):
        raise TypeError("circle_hiding_extension_value_must_be_fp16")
    if not isinstance(base_query_values, Sequence) or isinstance(
        base_query_values, (bytes, bytearray, str)
    ):
        raise TypeError("circle_hiding_base_query_values_must_be_sequence")
    values = tuple(_base(value, "query_value") for value in base_query_values)
    if len(values) != len(certificate.base_query_parameters):
        raise ValueError("circle_hiding_base_query_value_count_mismatch")
    if not isinstance(free_coefficients, Sequence) or isinstance(
        free_coefficients, (bytes, bytearray, str)
    ):
        raise TypeError("circle_hiding_free_coefficients_must_be_sequence")
    free = tuple(_base(value, "free_coefficient") for value in free_coefficients)
    if len(free) != certificate.free_dimension:
        raise ValueError("circle_hiding_free_coefficient_count_mismatch")

    degree = certificate.circle_basis_degree
    polynomial = [0]
    modulus = [1]
    for extension_parameter, minimal, target in zip(
        certificate.extension_parameters,
        certificate.extension_minimal_polynomials,
        extension_targets,
        strict=True,
    ):
        extension_denominator = (
            Fp16.one() + extension_parameter * extension_parameter
        ) ** degree
        numerator_value = target * extension_denominator
        target_remainder = _solve_extension_power_basis(
            extension_parameter, numerator_value
        )
        polynomial, modulus = _crt_extend(
            polynomial,
            modulus,
            minimal,
            target_remainder,
        )

    unique_targets: dict[int, int] = {}
    for parameter, value in zip(certificate.base_query_parameters, values, strict=True):
        denominator = pow((1 + parameter * parameter) % M31_MODULUS, degree, M31_MODULUS)
        numerator_value = value * denominator % M31_MODULUS
        prior = unique_targets.setdefault(parameter, numerator_value)
        if prior != numerator_value:
            raise ValueError("circle_hiding_duplicate_query_value_conflict")

    for parameter in certificate.unique_base_query_parameters:
        polynomial, modulus = _crt_extend(
            polynomial,
            modulus,
            ((-parameter) % M31_MODULUS, 1),
            (unique_targets[parameter],),
        )

    if len(modulus) - 1 != certificate.rank:
        raise AssertionError("circle_hiding_crt_modulus_degree_mismatch")
    polynomial = _poly_add(polynomial, _poly_mul(modulus, free))
    polynomial.extend([0] * (certificate.degree_freedom - len(polynomial)))
    if len(polynomial) != certificate.degree_freedom:
        raise AssertionError("circle_hiding_interpolated_degree_overflow")
    return tuple(polynomial)


def evaluate_circle_mask_at_fp16(
    coefficients: Sequence[int], parameter: Fp16
) -> Fp16:
    if not coefficients:
        raise ValueError("circle_hiding_coefficients_required")
    degree = len(coefficients) // 2
    denominator = (Fp16.one() + parameter * parameter) ** degree
    if denominator == Fp16.zero():
        raise ValueError("circle_hiding_circle_basis_denominator_zero")
    return _poly_eval_fp16(coefficients, parameter) / denominator


def evaluate_circle_mask_at_base(coefficients: Sequence[int], parameter: int) -> int:
    if not coefficients:
        raise ValueError("circle_hiding_coefficients_required")
    parameter = _base(parameter, "evaluation_parameter")
    degree = len(coefficients) // 2
    denominator = pow((1 + parameter * parameter) % M31_MODULUS, degree, M31_MODULUS)
    if denominator == 0:
        raise ValueError("circle_hiding_circle_basis_denominator_zero")
    return _poly_eval_base(coefficients, parameter) * pow(
        denominator, M31_MODULUS - 2, M31_MODULUS
    ) % M31_MODULUS


__all__ = [
    "EVALUATION_MAP_STATUS",
    "CircleEvaluationMapCertificate",
    "build_circle_evaluation_map_certificate",
    "circle_query_parameter",
    "evaluate_circle_mask_at_base",
    "evaluate_circle_mask_at_fp16",
    "interpolate_conditional_circle_mask",
    "minimal_polynomial_fp16",
    "translate_circle_parameter",
]
