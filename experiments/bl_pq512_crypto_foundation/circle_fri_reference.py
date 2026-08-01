"""Scalar degree-16 Circle-FRI fold primitives in theorem-compatible order.

The values accepted here are in Circle-FFT bit-reversed order.  The first
fold maps conjugate circle points to their shared x-coordinate; subsequent
folds are line folds.  This is a small independently testable primitive, not a
complete FRI prover, parameter selection, or activation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Sequence

from .field16_reference import Fp16, M31_MODULUS
from .oods_reference import CirclePoint


M31_CIRCLE_LOG_ORDER: Final[int] = 31
M31_CIRCLE_GENERATOR_X: Final[int] = 2
M31_CIRCLE_GENERATOR_Y: Final[int] = 1268011823
MIN_CIRCLE_DOMAIN_LOG_SIZE: Final[int] = 2
MAX_CIRCLE_DOMAIN_LOG_SIZE: Final[int] = 30


def _m31(value: int) -> int:
    return value % M31_MODULUS


def _embed_m31(value: int) -> Fp16:
    if type(value) is not int or not 0 <= value < M31_MODULUS:
        raise ValueError("circle_fri_m31_not_canonical")
    return Fp16((value,) + (0,) * 15)


@dataclass(frozen=True, slots=True)
class BaseCirclePoint:
    x: int
    y: int

    def __post_init__(self) -> None:
        if type(self.x) is not int or not 0 <= self.x < M31_MODULUS:
            raise ValueError("circle_fri_point_x_not_canonical")
        if type(self.y) is not int or not 0 <= self.y < M31_MODULUS:
            raise ValueError("circle_fri_point_y_not_canonical")
        if _m31(self.x * self.x + self.y * self.y) != 1:
            raise ValueError("circle_fri_point_not_on_circle")

    @classmethod
    def identity(cls) -> "BaseCirclePoint":
        return cls(1, 0)

    def __add__(self, other: object) -> "BaseCirclePoint":
        if not isinstance(other, BaseCirclePoint):
            return NotImplemented
        return BaseCirclePoint(
            _m31(self.x * other.x - self.y * other.y),
            _m31(self.x * other.y + self.y * other.x),
        )

    def conjugate(self) -> "BaseCirclePoint":
        return BaseCirclePoint(self.x, _m31(-self.y))

    def double(self) -> "BaseCirclePoint":
        return self + self

    def multiply(self, scalar: int) -> "BaseCirclePoint":
        if type(scalar) is not int or scalar < 0:
            raise ValueError("circle_fri_scalar_invalid")
        result = BaseCirclePoint.identity()
        current = self
        remaining = scalar
        while remaining:
            if remaining & 1:
                result = result + current
            current = current.double()
            remaining >>= 1
        return result


M31_CIRCLE_GENERATOR: Final[BaseCirclePoint] = BaseCirclePoint(
    M31_CIRCLE_GENERATOR_X,
    M31_CIRCLE_GENERATOR_Y,
)


def bit_reverse_index(index: int, log_size: int) -> int:
    if type(log_size) is not int or not 1 <= log_size <= MAX_CIRCLE_DOMAIN_LOG_SIZE:
        raise ValueError("circle_fri_log_size_invalid")
    if type(index) is not int or not 0 <= index < 1 << log_size:
        raise ValueError("circle_fri_index_out_of_bounds")
    result = 0
    value = index
    for _ in range(log_size):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def _point_from_index(index: int) -> BaseCirclePoint:
    if type(index) is not int:
        raise TypeError("circle_fri_point_index_must_be_integer")
    return M31_CIRCLE_GENERATOR.multiply(index & ((1 << M31_CIRCLE_LOG_ORDER) - 1))


def canonic_circle_point(log_size: int, natural_index: int) -> BaseCirclePoint:
    """Return one point of S-two's canonical circle domain in natural order."""

    if type(log_size) is not int or not (
        MIN_CIRCLE_DOMAIN_LOG_SIZE <= log_size <= MAX_CIRCLE_DOMAIN_LOG_SIZE
    ):
        raise ValueError("circle_fri_log_size_invalid")
    size = 1 << log_size
    if type(natural_index) is not int or not 0 <= natural_index < size:
        raise ValueError("circle_fri_index_out_of_bounds")
    half_size = size >> 1
    initial_index = 1 << (M31_CIRCLE_LOG_ORDER - (log_size + 1))
    step_index = 1 << (M31_CIRCLE_LOG_ORDER - (log_size - 1))
    if natural_index < half_size:
        point_index = initial_index + natural_index * step_index
    else:
        point_index = -(initial_index + (natural_index - half_size) * step_index)
    return _point_from_index(point_index)


def circle_domain_step(log_size: int) -> BaseCirclePoint:
    """Return the natural-order transition step for a canonical circle domain."""

    if type(log_size) is not int or not (
        MIN_CIRCLE_DOMAIN_LOG_SIZE <= log_size <= MAX_CIRCLE_DOMAIN_LOG_SIZE
    ):
        raise ValueError("circle_fri_log_size_invalid")
    step = _point_from_index(1 << (M31_CIRCLE_LOG_ORDER - (log_size - 1)))
    first = canonic_circle_point(log_size, 0)
    second = canonic_circle_point(log_size, 1)
    if first + step != second:
        raise AssertionError("circle_fri_domain_step_mismatch")
    return step


def half_odds_line_x(log_size: int, natural_index: int) -> int:
    """Return x for S-two's ``Coset::half_odds(log_size)`` in natural order."""

    if type(log_size) is not int or not 1 <= log_size < MAX_CIRCLE_DOMAIN_LOG_SIZE:
        raise ValueError("circle_fri_line_log_size_invalid")
    size = 1 << log_size
    if type(natural_index) is not int or not 0 <= natural_index < size:
        raise ValueError("circle_fri_index_out_of_bounds")
    initial_index = 1 << (M31_CIRCLE_LOG_ORDER - (log_size + 2))
    step_index = 1 << (M31_CIRCLE_LOG_ORDER - log_size)
    return _point_from_index(initial_index + natural_index * step_index).x


def fold_circle_into_line(
    values: Sequence[Fp16],
    alpha: Fp16,
) -> tuple[Fp16, ...]:
    """Apply the exact conjugate-pair circle-to-line fold once."""

    if not isinstance(alpha, Fp16):
        raise TypeError("circle_fri_alpha_must_be_fp16")
    if not isinstance(values, Sequence) or isinstance(values, (bytes, bytearray, str)):
        raise TypeError("circle_fri_values_must_be_sequence")
    size = len(values)
    if not _power_of_two(size) or size < 1 << MIN_CIRCLE_DOMAIN_LOG_SIZE:
        raise ValueError("circle_fri_evaluation_size_invalid")
    log_size = size.bit_length() - 1
    if log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE:
        raise ValueError("circle_fri_evaluation_size_invalid")
    if any(not isinstance(value, Fp16) for value in values):
        raise TypeError("circle_fri_value_must_be_fp16")

    result: list[Fp16] = []
    for pair_index in range(size >> 1):
        f_p = values[pair_index << 1]
        f_neg_p = values[(pair_index << 1) + 1]
        point = canonic_circle_point(
            log_size,
            bit_reverse_index(pair_index << 1, log_size),
        )
        if point.y == 0:
            raise ZeroDivisionError("circle_fri_circle_fold_y_zero")
        inverse_y = pow(point.y, M31_MODULUS - 2, M31_MODULUS)
        f0 = f_p + f_neg_p
        f1 = (f_p - f_neg_p) * _embed_m31(inverse_y)
        result.append(f0 + alpha * f1)
    return tuple(result)


def fold_line(values: Sequence[Fp16], alpha: Fp16) -> tuple[Fp16, ...]:
    """Apply one exact line-domain fold in bit-reversed order."""

    if not isinstance(alpha, Fp16):
        raise TypeError("circle_fri_alpha_must_be_fp16")
    if not isinstance(values, Sequence) or isinstance(values, (bytes, bytearray, str)):
        raise TypeError("circle_fri_values_must_be_sequence")
    size = len(values)
    if not _power_of_two(size) or size < 2:
        raise ValueError("circle_fri_line_evaluation_size_invalid")
    log_size = size.bit_length() - 1
    if log_size >= MAX_CIRCLE_DOMAIN_LOG_SIZE:
        raise ValueError("circle_fri_line_evaluation_size_invalid")
    if any(not isinstance(value, Fp16) for value in values):
        raise TypeError("circle_fri_value_must_be_fp16")

    result: list[Fp16] = []
    for pair_index in range(size >> 1):
        f_x = values[pair_index << 1]
        f_neg_x = values[(pair_index << 1) + 1]
        x = half_odds_line_x(log_size, bit_reverse_index(pair_index << 1, log_size))
        if x == 0:
            raise ZeroDivisionError("circle_fri_line_fold_x_zero")
        inverse_x = pow(x, M31_MODULUS - 2, M31_MODULUS)
        f0 = f_x + f_neg_x
        f1 = (f_x - f_neg_x) * _embed_m31(inverse_x)
        result.append(f0 + alpha * f1)
    return tuple(result)


def fold_circle_layer(
    values: Sequence[Fp16],
    alpha: Fp16,
    fold_count: int,
) -> tuple[Fp16, ...]:
    """Fold circle-to-line once, then square alpha for each line fold."""

    if type(fold_count) is not int or fold_count < 1:
        raise ValueError("circle_fri_fold_count_invalid")
    if len(values) < 1 << fold_count:
        raise ValueError("circle_fri_fold_count_exceeds_domain")
    result = fold_circle_into_line(values, alpha)
    folding_alpha = alpha * alpha
    for _ in range(fold_count - 1):
        result = fold_line(result, folding_alpha)
        folding_alpha = folding_alpha * folding_alpha
    return result


def validate_oods_query_point(query: CirclePoint) -> None:
    """Require an affine circle point outside the Fp8 fixed subfield."""

    if type(query) is not CirclePoint:
        raise TypeError("circle_fri_oods_query_point_required")
    if query.x * query.x + query.y * query.y != Fp16.one():
        raise ValueError("circle_fri_oods_query_not_on_circle")
    if query.x.is_in_fp8_subfield() and query.y.is_in_fp8_subfield():
        raise ValueError("circle_fri_oods_query_in_fixed_subfield")


def conjugate_pair_zeroifier(
    domain_point: BaseCirclePoint,
    query: CirclePoint,
) -> Fp16:
    """Evaluate the line through ``Q`` and its Fp16/Fp8 conjugate at ``P``.

    The accepted OODS parameter is outside Fp8, so these are two distinct
    circle points.  A line intersects the circle in at most those two points;
    consequently it cannot vanish on the M31 commitment domain.
    """

    if type(domain_point) is not BaseCirclePoint:
        raise TypeError("circle_fri_base_domain_point_required")
    validate_oods_query_point(query)
    conjugate = CirclePoint(query.x.conjugate(), query.y.conjugate())
    if query == conjugate:
        raise ValueError("circle_fri_oods_conjugate_pair_collapsed")
    point_x = _embed_m31(domain_point.x)
    point_y = _embed_m31(domain_point.y)
    zeroifier = (
        (query.y - conjugate.y) * point_x
        + (conjugate.x - query.x) * point_y
        + query.x * conjugate.y
        - query.y * conjugate.x
    )
    if zeroifier == Fp16.zero():
        raise ZeroDivisionError("circle_fri_oods_pair_zeroifier_exceptional_on_base_domain")
    return zeroifier


def _two_point_claim_line(
    *,
    domain_point: BaseCirclePoint,
    query: CirclePoint,
    claim: Fp16,
    conjugate_query_claim: Fp16,
) -> tuple[Fp16, Fp16]:
    """Return ``(scale, line(P))`` for two explicitly claimed evaluations.

    S-two's current quotient code assumes the query's y-coordinate separates
    the pair.  That assumption has a nonzero exceptional set.  This reference
    deterministically prefers y and falls back to x, so every distinct pair is
    covered without an abort-probability gap.  The second evaluation is never
    inferred: ``f(Q^dagger) = f(Q)^dagger`` holds for base-field-defined
    functions, but not for an arbitrary Fp16-coefficient function.
    """

    if type(claim) is not Fp16 or type(conjugate_query_claim) is not Fp16:
        raise TypeError("circle_fri_two_point_claim_must_be_fp16")

    conjugate = CirclePoint(query.x.conjugate(), query.y.conjugate())
    if query.y != conjugate.y:
        query_coordinate = query.y
        conjugate_coordinate = conjugate.y
        domain_coordinate = _embed_m31(domain_point.y)
    elif query.x != conjugate.x:
        query_coordinate = query.x
        conjugate_coordinate = conjugate.x
        domain_coordinate = _embed_m31(domain_point.x)
    else:
        raise ValueError("circle_fri_oods_conjugate_pair_collapsed")

    scale = conjugate_coordinate - query_coordinate
    slope_numerator = conjugate_query_claim - claim
    intercept_numerator = claim * scale - slope_numerator * query_coordinate
    return scale, slope_numerator * domain_coordinate + intercept_numerator


@dataclass(frozen=True, slots=True)
class DegreeCorrectedRow:
    """Original and conjugate-pair-quotient values required by Protocol 4."""

    original_values: tuple[Fp16, ...]
    quotient_values: tuple[Fp16, ...]

    def __post_init__(self) -> None:
        if (
            type(self.original_values) is not tuple
            or not self.original_values
            or any(type(value) is not Fp16 for value in self.original_values)
        ):
            raise ValueError("circle_fri_degree_corrected_original_values_invalid")
        if (
            type(self.quotient_values) is not tuple
            or len(self.quotient_values) != len(self.original_values)
            or any(type(value) is not Fp16 for value in self.quotient_values)
        ):
            raise ValueError("circle_fri_degree_corrected_quotient_values_invalid")

    @property
    def fri_batch_values(self) -> tuple[Fp16, ...]:
        return self.original_values + self.quotient_values


def degree_corrected_row(
    *,
    domain_point: BaseCirclePoint,
    query: CirclePoint,
    original_values: Sequence[Fp16],
    claimed_query_values: Sequence[Fp16],
    claimed_conjugate_query_values: Sequence[Fp16],
) -> DegreeCorrectedRow:
    """Build the exact original-plus-quotient FRI row for one domain point."""

    for label, values in (
        ("original", original_values),
        ("claim", claimed_query_values),
        ("conjugate_claim", claimed_conjugate_query_values),
    ):
        if not isinstance(values, Sequence) or isinstance(values, (bytes, bytearray, str)):
            raise TypeError(f"circle_fri_degree_corrected_{label}_values_must_be_sequence")
        if any(type(value) is not Fp16 for value in values):
            raise TypeError(f"circle_fri_degree_corrected_{label}_value_must_be_fp16")
    if not original_values or not (
        len(original_values)
        == len(claimed_query_values)
        == len(claimed_conjugate_query_values)
    ):
        raise ValueError("circle_fri_degree_corrected_column_count_mismatch")
    zeroifier_inverse = conjugate_pair_zeroifier(domain_point, query).inverse()
    originals = tuple(original_values)
    quotients: list[Fp16] = []
    for original, claim, conjugate_claim in zip(
        original_values,
        claimed_query_values,
        claimed_conjugate_query_values,
        strict=True,
    ):
        scale, claim_line = _two_point_claim_line(
            domain_point=domain_point,
            query=query,
            claim=claim,
            conjugate_query_claim=conjugate_claim,
        )
        quotients.append((scale * original - claim_line) * zeroifier_inverse)
    return DegreeCorrectedRow(originals, tuple(quotients))


def verify_degree_corrected_row(
    *,
    domain_point: BaseCirclePoint,
    query: CirclePoint,
    row: DegreeCorrectedRow,
    claimed_query_values: Sequence[Fp16],
    claimed_conjugate_query_values: Sequence[Fp16],
) -> bool:
    """Verify every original/quotient identity at one opened domain point."""

    if type(row) is not DegreeCorrectedRow:
        raise TypeError("circle_fri_degree_corrected_row_required")
    for label, values in (
        ("claim", claimed_query_values),
        ("conjugate_claim", claimed_conjugate_query_values),
    ):
        if not isinstance(values, Sequence) or isinstance(
            values, (bytes, bytearray, str)
        ):
            raise TypeError(
                f"circle_fri_degree_corrected_{label}_values_must_be_sequence"
            )
        if any(type(value) is not Fp16 for value in values):
            raise TypeError(f"circle_fri_degree_corrected_{label}_value_must_be_fp16")
    if not (
        len(row.original_values)
        == len(claimed_query_values)
        == len(claimed_conjugate_query_values)
    ):
        raise ValueError("circle_fri_degree_corrected_column_count_mismatch")
    zeroifier = conjugate_pair_zeroifier(domain_point, query)
    for original, quotient, claim, conjugate_claim in zip(
        row.original_values,
        row.quotient_values,
        claimed_query_values,
        claimed_conjugate_query_values,
        strict=True,
    ):
        scale, claim_line = _two_point_claim_line(
            domain_point=domain_point,
            query=query,
            claim=claim,
            conjugate_query_claim=conjugate_claim,
        )
        if zeroifier * quotient != scale * original - claim_line:
            return False
    return True


@dataclass(frozen=True, slots=True)
class FriDomainBatch:
    """One equal-width Fp16 function batch on a canonical circle domain."""

    log_size: int
    rows: tuple[tuple[Fp16, ...], ...]

    def __post_init__(self) -> None:
        if type(self.log_size) is not int or not (
            MIN_CIRCLE_DOMAIN_LOG_SIZE <= self.log_size <= MAX_CIRCLE_DOMAIN_LOG_SIZE
        ):
            raise ValueError("circle_fri_batch_log_size_invalid")
        if type(self.rows) is not tuple or len(self.rows) != 1 << self.log_size:
            raise ValueError("circle_fri_batch_row_count_mismatch")
        if not self.rows or type(self.rows[0]) is not tuple or not self.rows[0]:
            raise ValueError("circle_fri_batch_columns_required")
        column_count = len(self.rows[0])
        if any(
            type(row) is not tuple
            or len(row) != column_count
            or any(type(value) is not Fp16 for value in row)
            for row in self.rows
        ):
            raise ValueError("circle_fri_batch_row_shape_invalid")

    @property
    def column_count(self) -> int:
        return len(self.rows[0])


@dataclass(frozen=True, slots=True)
class FriCascade:
    """Masked batched domains and every unnormalized inserted fold layer."""

    domain_log_sizes: tuple[int, ...]
    fold_log_sizes: tuple[int, ...]
    batch_column_counts: tuple[int, ...]
    batch_power_offsets: tuple[int, ...]
    batch_masks: tuple[tuple[Fp16, ...], ...]
    batched_domains: tuple[tuple[Fp16, ...], ...]
    folded_layers: tuple[tuple[Fp16, ...], ...]
    batch_coefficient: Fp16
    fold_coefficients: tuple[Fp16, ...]

    def __post_init__(self) -> None:
        batch_count = len(self.domain_log_sizes)
        fold_count = len(self.fold_log_sizes)
        if (
            batch_count == 0
            or len(self.batch_column_counts) != batch_count
            or len(self.batch_power_offsets) != batch_count
            or len(self.batch_masks) != batch_count
            or len(self.batched_domains) != batch_count
            or len(self.folded_layers) != fold_count
            or len(self.fold_coefficients) != fold_count
        ):
            raise ValueError("circle_fri_cascade_round_count_mismatch")
        if type(self.batch_coefficient) is not Fp16 or any(
            type(value) is not Fp16 for value in self.fold_coefficients
        ):
            raise TypeError("circle_fri_cascade_coefficient_type_invalid")
        if any(
            left <= right
            for left, right in zip(
                self.domain_log_sizes[:-1], self.domain_log_sizes[1:], strict=True
            )
        ):
            raise ValueError("circle_fri_cascade_domains_not_strictly_descending")
        expected_fold_logs = tuple(
            range(self.domain_log_sizes[0], self.domain_log_sizes[-1] - 1, -1)
        )
        if self.fold_log_sizes != expected_fold_logs:
            raise ValueError("circle_fri_cascade_fold_logs_invalid")
        expected_offset = 0
        for column_count, power_offset in zip(
            self.batch_column_counts, self.batch_power_offsets, strict=True
        ):
            if column_count <= 0 or power_offset != expected_offset:
                raise ValueError("circle_fri_cascade_power_offsets_invalid")
            expected_offset += column_count
        for log_size, mask, batched in zip(
            self.domain_log_sizes,
            self.batch_masks,
            self.batched_domains,
            strict=True,
        ):
            if len(mask) != 1 << log_size or len(batched) != 1 << log_size:
                raise ValueError("circle_fri_cascade_layer_shape_invalid")
        for log_size, folded in zip(
            self.fold_log_sizes, self.folded_layers, strict=True
        ):
            if len(folded) != 1 << (log_size - 1):
                raise ValueError("circle_fri_cascade_layer_shape_invalid")

    @property
    def final_line_evaluation(self) -> tuple[Fp16, ...]:
        return self.folded_layers[-1]


def _batch_row(
    row: tuple[Fp16, ...],
    mask: Fp16,
    coefficient: Fp16,
    power_offset: int,
) -> Fp16:
    # Protocol 2: the independent mask has coefficient one; committed data
    # uses globally unique positive powers of the later batching challenge.
    result = mask
    power = Fp16.one()
    for _ in range(power_offset + 1):
        power = power * coefficient
    for value in row:
        result = result + power * value
        power = power * coefficient
    return result


def build_fri_cascade(
    batches: Sequence[FriDomainBatch],
    *,
    batch_masks: Sequence[FriDomainBatch],
    batch_coefficient: Fp16,
    fold_coefficients: Sequence[Fp16],
) -> FriCascade:
    """Apply Protocol 3 batching and folding-with-insertion exactly."""

    if not isinstance(batches, Sequence) or isinstance(batches, (bytes, bytearray, str)):
        raise TypeError("circle_fri_batches_must_be_sequence")
    if not batches or any(type(batch) is not FriDomainBatch for batch in batches):
        raise ValueError("circle_fri_batches_invalid")
    if not isinstance(batch_masks, Sequence) or isinstance(
        batch_masks, (bytes, bytearray, str)
    ):
        raise TypeError("circle_fri_batch_masks_must_be_sequence")
    if len(batch_masks) != len(batches) or any(
        type(batch) is not FriDomainBatch for batch in batch_masks
    ):
        raise ValueError("circle_fri_batch_mask_count_mismatch")
    if type(batch_coefficient) is not Fp16:
        raise TypeError("circle_fri_batch_coefficient_must_be_fp16")
    if not isinstance(fold_coefficients, Sequence) or isinstance(
        fold_coefficients, (bytes, bytearray, str)
    ):
        raise TypeError("circle_fri_fold_coefficients_must_be_sequence")
    if any(
        mask.log_size != batch.log_size or mask.column_count != 1
        for batch, mask in zip(batches, batch_masks, strict=True)
    ):
        raise ValueError("circle_fri_batch_mask_shape_mismatch")
    log_sizes = tuple(batch.log_size for batch in batches)
    if any(
        left <= right
        for left, right in zip(log_sizes[:-1], log_sizes[1:], strict=True)
    ):
        raise ValueError("circle_fri_batch_domains_not_strictly_descending")
    fold_log_sizes = tuple(range(log_sizes[0], log_sizes[-1] - 1, -1))
    if len(fold_coefficients) != len(fold_log_sizes) or any(
        type(value) is not Fp16 for value in fold_coefficients
    ):
        raise ValueError("circle_fri_fold_coefficient_count_mismatch")

    batch_column_counts = tuple(batch.column_count for batch in batches)
    power_offsets: list[int] = []
    next_power_offset = 0
    for column_count in batch_column_counts:
        power_offsets.append(next_power_offset)
        next_power_offset += column_count

    mask_domains: list[tuple[Fp16, ...]] = []
    batched_domains: list[tuple[Fp16, ...]] = []
    for batch, mask_batch, power_offset in zip(
        batches, batch_masks, power_offsets, strict=True
    ):
        mask = tuple(row[0] for row in mask_batch.rows)
        batched = tuple(
            _batch_row(row, mask_value, batch_coefficient, power_offset)
            for row, mask_value in zip(batch.rows, mask, strict=True)
        )
        mask_domains.append(mask)
        batched_domains.append(batched)

    folded_layers: list[tuple[Fp16, ...]] = []
    previous: tuple[Fp16, ...] | None = None
    batch_index_by_log = {
        log_size: index for index, log_size in enumerate(log_sizes)
    }
    for fold_log_size, fold_coefficient in zip(
        fold_log_sizes, fold_coefficients, strict=True
    ):
        batch_index = batch_index_by_log.get(fold_log_size)
        folded_previous = (
            None if previous is None else fold_line(previous, fold_coefficient)
        )
        if batch_index is None:
            if folded_previous is None:
                raise ValueError("circle_fri_first_fold_domain_missing")
            current = folded_previous
        else:
            batched = batched_domains[batch_index]
            folded_batch = fold_circle_into_line(batched, fold_coefficient)
            if folded_previous is None:
                # The largest attached domain is not pointlessly scaled by
                # alpha^2. This is the fail-safer S-two source ordering.
                current = folded_batch
            else:
                if len(folded_previous) != len(folded_batch):
                    raise ValueError("circle_fri_previous_layer_domain_mismatch")
                coefficient_squared = fold_coefficient * fold_coefficient
                current = tuple(
                    coefficient_squared * prior + added
                    for prior, added in zip(
                        folded_previous, folded_batch, strict=True
                    )
                )
        folded_layers.append(current)
        previous = current
    return FriCascade(
        domain_log_sizes=log_sizes,
        fold_log_sizes=fold_log_sizes,
        batch_column_counts=batch_column_counts,
        batch_power_offsets=tuple(power_offsets),
        batch_masks=tuple(mask_domains),
        batched_domains=tuple(batched_domains),
        folded_layers=tuple(folded_layers),
        batch_coefficient=batch_coefficient,
        fold_coefficients=tuple(fold_coefficients),
    )


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0
