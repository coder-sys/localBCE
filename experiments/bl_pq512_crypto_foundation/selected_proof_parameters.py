"""Selected, non-activating BL-PQ512 proof parameters.

Unlike the historical R33 worksheet, this module consumes the executable AIR
itself.  Every bound is exact integer arithmetic.  Selection makes the local
prototype deterministic; it does not authorize production activation.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha3_512
from typing import Final

from experiments.fixed_shape_claim_air.air_binary_ir import (
    air_program_commitment,
    encode_air_program,
)
from experiments.fixed_shape_claim_air.executable_air import AirProgram
from experiments.fixed_shape_claim_air.semantics import StructuralError


SELECTED_PARAMETER_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/SELECTED-PROOF-PARAMETERS/v1\x00"
)
PROOF_SUITE_DOMAIN: Final[bytes] = b"BL/PQ512/PROOF-SUITE-ID/v1\x00"
PARAMETER_VERSION: Final[int] = 1
M31_MODULUS: Final[int] = (1 << 31) - 1
CHALLENGE_EXTENSION_DEGREE: Final[int] = 16
CHALLENGE_FIELD_CARDINALITY: Final[int] = M31_MODULUS**CHALLENGE_EXTENSION_DEGREE
OODS_PARAMETER_SPACE_SIZE: Final[int] = M31_MODULUS**16 - M31_MODULUS**8
LOG_BLOWUP: Final[int] = 1
COMPOSITION_MASK_DEGREE_SLACK_LOG: Final[int] = 1
PER_TERM_SOUNDNESS_BITS: Final[int] = 256
TOTAL_SOUNDNESS_BITS: Final[int] = 256
QUERY_COUNT: Final[int] = 945
OODS_QUERY_COUNT: Final[int] = 1
REDUCED_AIR_DEGREE: Final[int] = 2
TRACE_MASK_COEFFICIENT_COUNT: Final[int] = 4_789
QUOTIENT_MASK_COEFFICIENT_COUNT: Final[int] = 946
MINIMUM_TRACE_ROWS: Final[int] = 8_192
UNIQUE_DECODING_SLACK_BITS: Final[int] = 32
THETA: Final[Fraction] = Fraction((1 << 32) - 1, 1 << 34)
ACTIVATION_ALLOWED: Final[bool] = False
LEGACY_SHA3_ROUND_NONFIXED_COLUMNS: Final[int] = 1_709
LEGACY_SHA3_ROUND_LOOKUP_COLUMNS: Final[int] = 1_025
KECCAK_ROUNDS: Final[int] = 24


def _next_power_of_two(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise StructuralError("selected_proof_positive_integer_required")
    return 1 << (value - 1).bit_length()


def _bits_floor(value: Fraction) -> int:
    if not isinstance(value, Fraction) or not 0 < value <= 1:
        raise StructuralError("selected_proof_probability_invalid")
    numerator, denominator = value.numerator, value.denominator
    result = denominator.bit_length() - numerator.bit_length()
    if numerator << result > denominator:
        result -= 1
    return result


def selected_parameter_bytes() -> bytes:
    return b"".join(
        (
            SELECTED_PARAMETER_DOMAIN,
            PARAMETER_VERSION.to_bytes(2, "big"),
            M31_MODULUS.to_bytes(8, "big"),
            CHALLENGE_EXTENSION_DEGREE.to_bytes(2, "big"),
            LOG_BLOWUP.to_bytes(1, "big"),
            PER_TERM_SOUNDNESS_BITS.to_bytes(2, "big"),
            QUERY_COUNT.to_bytes(4, "big"),
            OODS_QUERY_COUNT.to_bytes(2, "big"),
            REDUCED_AIR_DEGREE.to_bytes(2, "big"),
            TRACE_MASK_COEFFICIENT_COUNT.to_bytes(4, "big"),
            QUOTIENT_MASK_COEFFICIENT_COUNT.to_bytes(4, "big"),
            MINIMUM_TRACE_ROWS.to_bytes(4, "big"),
            UNIQUE_DECODING_SLACK_BITS.to_bytes(2, "big"),
            THETA.numerator.to_bytes(8, "big"),
            THETA.denominator.to_bytes(8, "big"),
            bytes((int(ACTIVATION_ALLOWED),)),
        )
    )


SELECTED_PARAMETER_COMMITMENT: Final[bytes] = sha3_512(
    selected_parameter_bytes()
).digest()


@dataclass(frozen=True, slots=True)
class SelectedProofGeometry:
    program_binary_commitment: bytes
    maximum_evaluation_log_size: int
    query_domain_size: int
    fold_round_count: int
    original_fri_column_count: int
    degree_corrected_fri_column_count: int
    logup_numerator_bound: int
    composition_numerator_bound: int
    deep_numerator_bound: int
    fri_batch_numerator_bound: int
    fri_fold_numerator_bound: int
    error_terms: tuple[tuple[str, Fraction], ...]
    proof_suite_selected: bool = True
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if type(self.program_binary_commitment) is not bytes or len(
            self.program_binary_commitment
        ) != 64 or not any(self.program_binary_commitment):
            raise StructuralError("selected_proof_program_commitment_invalid")
        if not self.proof_suite_selected or self.activation_allowed:
            raise StructuralError("selected_proof_activation_boundary_invalid")
        if type(self.error_terms) is not tuple or len(self.error_terms) != 6:
            raise StructuralError("selected_proof_error_terms_invalid")
        if any(
            not isinstance(value, Fraction) or value <= 0
            for _, value in self.error_terms
        ):
            raise StructuralError("selected_proof_error_term_invalid")
        if any(_bits_floor(value) < PER_TERM_SOUNDNESS_BITS for _, value in self.error_terms):
            raise StructuralError("selected_proof_per_term_soundness_failed")
        if self.total_soundness_bits < TOTAL_SOUNDNESS_BITS:
            raise StructuralError("selected_proof_total_soundness_failed")

    @property
    def total_error(self) -> Fraction:
        return sum((value for _, value in self.error_terms), Fraction())

    @property
    def total_soundness_bits(self) -> int:
        return _bits_floor(self.total_error)

    @property
    def minimum_term_soundness_bits(self) -> int:
        return min(_bits_floor(value) for _, value in self.error_terms)


@dataclass(frozen=True, slots=True)
class LegacyWideSha3LowerBound:
    call_count: int
    minimum_round_rows: int
    evaluation_rows: int
    main_evaluation_bytes: int
    interaction_evaluation_bytes: int
    combined_evaluation_bytes: int


def legacy_wide_sha3_lower_bound(call_count: int) -> LegacyWideSha3LowerBound:
    """Prove a resource floor without assuming any message exceeds one block.

    This deliberately understates the real K128 workload. It exists to prevent
    the old 1,728-column byte-wide SHA3 table from being launched when even its
    best possible geometry cannot fit the selected storage boundary.
    """

    if type(call_count) is not int or call_count <= 0:
        raise StructuralError("selected_proof_sha3_call_count_invalid")
    minimum_round_rows = call_count * KECCAK_ROUNDS
    trace_rows = max(
        _next_power_of_two(minimum_round_rows),
        _next_power_of_two(TRACE_MASK_COEFFICIENT_COUNT),
    )
    masked_bound = _next_power_of_two(
        trace_rows + _next_power_of_two(TRACE_MASK_COEFFICIENT_COUNT)
    )
    composition_bound = _next_power_of_two(masked_bound * 3)
    evaluation_rows = composition_bound << LOG_BLOWUP
    main = evaluation_rows * LEGACY_SHA3_ROUND_NONFIXED_COLUMNS * 4
    interaction = evaluation_rows * LEGACY_SHA3_ROUND_LOOKUP_COLUMNS * 64
    return LegacyWideSha3LowerBound(
        call_count,
        minimum_round_rows,
        evaluation_rows,
        main,
        interaction,
        main + interaction,
    )


def derive_selected_proof_geometry(program: AirProgram) -> SelectedProofGeometry:
    if type(program) is not AirProgram:
        raise TypeError("selected_proof_air_program_required")
    encoded_program = encode_air_program(program)
    table_geometry: list[tuple[int, int, int]] = []
    main_columns = 0
    composition_columns = 0
    for table in program.tables:
        trace_rows = max(
            _next_power_of_two(table.rows),
            _next_power_of_two(TRACE_MASK_COEFFICIENT_COUNT),
        )
        if trace_rows < MINIMUM_TRACE_ROWS:
            raise StructuralError("selected_proof_trace_hiding_domain_too_small")
        mask_size = _next_power_of_two(TRACE_MASK_COEFFICIENT_COUNT)
        masked_bound = _next_power_of_two(trace_rows + mask_size)
        maximum_degree = max(
            (identity.expression.degree for identity in table.identities), default=1
        )
        composition_bound = _next_power_of_two(
            masked_bound * (max(maximum_degree, 1) + 1)
        )
        component_coefficient_log = masked_bound.bit_length() - 1
        composition_work_log = composition_bound.bit_length() - 1
        evaluation_log = (
            component_coefficient_log
            + COMPOSITION_MASK_DEGREE_SLACK_LOG
            + LOG_BLOWUP
        )
        if not 2 <= evaluation_log <= 30:
            raise StructuralError("selected_proof_evaluation_domain_invalid")
        table_geometry.append((trace_rows, evaluation_log, maximum_degree))
        main_columns += len(table.columns) - len(table.fixed_columns or {})
        composition_columns += 1 << (
            composition_work_log - component_coefficient_log
        )

    interaction_columns = 0
    for lookup in program.lookups:
        for table_index in range(len(program.tables)):
            side_count = sum(
                side.table == program.tables[table_index].name
                for side in (*lookup.sources, *lookup.destinations)
            )
            if side_count:
                interaction_columns += side_count + 1

    maximum_log = max(item[1] for item in table_geometry)
    query_domain_size = 1 << maximum_log
    original_columns = main_columns + interaction_columns + composition_columns
    corrected_columns = 2 * original_columns
    total_trace_columns = sum(len(table.columns) for table in program.tables)
    sides = tuple(
        side
        for lookup in program.lookups
        for side in (*lookup.sources, *lookup.destinations)
    )
    maximum_lookup_width = max((len(side.values) for side in sides), default=1)
    logup_rows = sum(
        (len(side.values) + 2) * (side.row_stop - side.row_start) for side in sides
    )
    logup = maximum_lookup_width * total_trace_columns + logup_rows
    composition = 2 + max(
        len(table.columns)
        + sum(side.table == table.name for side in sides)
        for table in program.tables
    )
    maximum_degree = max(item[2] for item in table_geometry)
    maximum_trace_rows = max(item[0] for item in table_geometry)
    deep = 1 + maximum_degree * maximum_trace_rows
    fri_batch = (corrected_columns - 1) * query_domain_size
    fri_fold = 3 * sum(1 << log for log in range(2, maximum_log + 1))
    error_terms = (
        ("logup", Fraction(logup, CHALLENGE_FIELD_CARDINALITY)),
        ("composition", Fraction(composition, CHALLENGE_FIELD_CARDINALITY)),
        ("deep", Fraction(deep, OODS_PARAMETER_SPACE_SIZE)),
        ("fri_batch", Fraction(fri_batch, CHALLENGE_FIELD_CARDINALITY)),
        ("fri_fold", Fraction(fri_fold, CHALLENGE_FIELD_CARDINALITY)),
        ("fri_query", (1 - THETA) ** QUERY_COUNT),
    )
    return SelectedProofGeometry(
        program_binary_commitment=air_program_commitment(encoded_program),
        maximum_evaluation_log_size=maximum_log,
        query_domain_size=query_domain_size,
        fold_round_count=maximum_log - 1,
        original_fri_column_count=original_columns,
        degree_corrected_fri_column_count=corrected_columns,
        logup_numerator_bound=logup,
        composition_numerator_bound=composition,
        deep_numerator_bound=deep,
        fri_batch_numerator_bound=fri_batch,
        fri_fold_numerator_bound=fri_fold,
        error_terms=error_terms,
    )


def proof_suite_id(
    program_binary_commitment: bytes,
    public_coin_schedule_commitment: bytes,
) -> bytes:
    for label, value in (
        ("program", program_binary_commitment),
        ("schedule", public_coin_schedule_commitment),
    ):
        if type(value) is not bytes or len(value) != 64 or not any(value):
            raise StructuralError(f"selected_proof_{label}_commitment_invalid")
    return sha3_512(
        PROOF_SUITE_DOMAIN
        + SELECTED_PARAMETER_COMMITMENT
        + program_binary_commitment
        + public_coin_schedule_commitment
    ).digest()


__all__ = (
    "ACTIVATION_ALLOWED",
    "LOG_BLOWUP",
    "LegacyWideSha3LowerBound",
    "MINIMUM_TRACE_ROWS",
    "PER_TERM_SOUNDNESS_BITS",
    "QUERY_COUNT",
    "QUOTIENT_MASK_COEFFICIENT_COUNT",
    "SELECTED_PARAMETER_COMMITMENT",
    "TRACE_MASK_COEFFICIENT_COUNT",
    "SelectedProofGeometry",
    "derive_selected_proof_geometry",
    "legacy_wide_sha3_lower_bound",
    "proof_suite_id",
    "selected_parameter_bytes",
)
