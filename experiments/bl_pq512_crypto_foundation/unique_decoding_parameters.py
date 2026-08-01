"""Historical R33 unique-decoding interface worksheet.

This module deliberately separates two claims:

* the old R33 metadata inventory fits the degree-16 field budget under a
  conservative interface-only theorem mapping; and
* the final SHA3/PCS/FRI-expanded AIR has not yet been substituted.

The first claim is retained only for audit chronology. R36 proved that the R33
inventory is not executable AIR and it is forbidden as a final theorem input.
The second remains false until the sibling engine consumes the sealed Wave 1A
binary AIR registry and supplies exact oracle and batch dimensions. No value
produced by this module assigns a proof-suite identifier or permits activation.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha3_512
from typing import Final, Iterable


M31_MODULUS: Final[int] = (1 << 31) - 1
CHALLENGE_FIELD_CARDINALITY: Final[int] = M31_MODULUS**16
OODS_PARAMETER_SPACE_SIZE: Final[int] = M31_MODULUS**16 - M31_MODULUS**8
PER_TERM_SECURITY_BITS: Final[int] = 256
UNIQUE_DECODING_BOUNDARY_SLACK_BITS: Final[int] = 32
INTERFACE_STATUS: Final[str] = (
    "R33_HISTORICAL_INTERFACE_SWEEP_NEVER_FINAL_THEOREM_INPUT_NONACTIVATING"
)
WORKSHEET_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1B/UDR-PARAMETER-WORKSHEET/v1"


def _require_exact_int(label: str, value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"wave1b_{label}_invalid")
    return value


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def soundness_bits_floor(value: Fraction) -> int:
    """Return floor(-log2(value)) without floating-point arithmetic."""

    if not isinstance(value, Fraction) or value <= 0 or value > 1:
        raise ValueError("wave1b_soundness_fraction_invalid")
    numerator = value.numerator
    denominator = value.denominator
    bits = denominator.bit_length() - numerator.bit_length()
    if numerator << bits > denominator:
        bits -= 1
    return bits


def meets_per_term_budget(value: Fraction) -> bool:
    if not isinstance(value, Fraction) or value < 0:
        raise ValueError("wave1b_error_fraction_invalid")
    return value.numerator << PER_TERM_SECURITY_BITS <= value.denominator


@dataclass(frozen=True, slots=True)
class InterfaceTableDimensions:
    """The theorem-relevant dimensions of one frozen Wave 1A table."""

    name: str
    padded_rows: int
    trace_columns: int
    constraint_count: int
    maximum_constraint_degree: int
    lookup_coordinate_width: int

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name.isascii() or not self.name:
            raise ValueError("wave1b_table_name_invalid")
        _require_exact_int("table_padded_rows", self.padded_rows, minimum=1)
        if not _power_of_two(self.padded_rows):
            raise ValueError("wave1b_table_padded_rows_not_power_of_two")
        _require_exact_int("table_trace_columns", self.trace_columns, minimum=1)
        _require_exact_int("table_constraint_count", self.constraint_count, minimum=1)
        _require_exact_int(
            "table_maximum_constraint_degree", self.maximum_constraint_degree, minimum=1
        )
        _require_exact_int(
            "table_lookup_coordinate_width", self.lookup_coordinate_width, minimum=0
        )


@dataclass(frozen=True, slots=True)
class InterfaceTheoremEnvelope:
    """Conservative historical mapping for the unexpanded R33 interface.

    ``lookup_coordinate_width`` is treated as the total number of lookup
    coordinates carried by a table.  Because every lookup message has at least
    one coordinate, it upper-bounds both its message count and ``r_t+s_t``.
    Trace-column counts upper-bound public input/output message coordinates.
    These are deliberately loose bounds, not a rewrite of the sealed Wave 1A
    program commitment.
    """

    profile_id: str
    tables: tuple[InterfaceTableDimensions, ...]
    commitment_group_count: int
    final_expansion_substituted: bool = False
    proof_suite_id: None = None
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if type(self.profile_id) is not str or not self.profile_id.isascii() or not self.profile_id:
            raise ValueError("wave1b_profile_id_invalid")
        if type(self.tables) is not tuple or len(self.tables) != 16:
            raise ValueError("wave1b_exactly_sixteen_tables_required")
        if len({table.name for table in self.tables}) != len(self.tables):
            raise ValueError("wave1b_table_name_duplicate")
        _require_exact_int("commitment_group_count", self.commitment_group_count, minimum=1)
        if self.final_expansion_substituted or self.proof_suite_id is not None:
            raise ValueError("wave1b_interface_envelope_cannot_claim_final_expansion")
        if self.activation_allowed:
            raise ValueError("wave1b_interface_envelope_cannot_activate")

    @property
    def maximum_rows(self) -> int:
        return max(table.padded_rows for table in self.tables)

    @property
    def minimum_rows(self) -> int:
        return min(table.padded_rows for table in self.tables)

    @property
    def total_trace_columns(self) -> int:
        return sum(table.trace_columns for table in self.tables)

    @property
    def total_constraints(self) -> int:
        return sum(table.constraint_count for table in self.tables)

    @property
    def total_lookup_coordinate_width(self) -> int:
        return sum(table.lookup_coordinate_width for table in self.tables)

    @property
    def maximum_lookup_coordinate_width(self) -> int:
        return max(table.lookup_coordinate_width for table in self.tables)

    @property
    def maximum_constraint_degree(self) -> int:
        return max(table.maximum_constraint_degree for table in self.tables)

    @property
    def interface_batch_width_upper_bound(self) -> int:
        """Pre-expansion batch bound; concrete SHA3 columns are intentionally absent."""

        return (
            self.total_trace_columns
            + self.total_lookup_coordinate_width
            + self.total_constraints
            + len(self.tables)
            + self.commitment_group_count
            + 1
        )

    @property
    def logup_numerator_upper_bound(self) -> int:
        # S-two UDR numerator: r*(k_in+k_out) + sum((r_t+s_t)*N_t).
        return self.maximum_lookup_coordinate_width * self.total_trace_columns + sum(
            table.lookup_coordinate_width * table.padded_rows for table in self.tables
        )

    @property
    def composition_numerator_upper_bound(self) -> int:
        # S-two UDR numerator: 2 + max_t(k_t+r_t+s_t).
        return 2 + max(
            table.trace_columns + table.lookup_coordinate_width for table in self.tables
        )

    @property
    def deep_numerator_upper_bound(self) -> int:
        # S-two UDR numerator: 1 + deg(A)*N.
        return 1 + self.maximum_constraint_degree * self.maximum_rows

    def canonical_bytes(self) -> bytes:
        chunks = [
            WORKSHEET_DOMAIN,
            len(self.profile_id).to_bytes(2, "big"),
            self.profile_id.encode("ascii"),
            len(self.tables).to_bytes(2, "big"),
            self.commitment_group_count.to_bytes(2, "big"),
            b"\x00",  # final expansion not substituted
            b"\x00",  # activation forbidden
        ]
        for table in self.tables:
            name = table.name.encode("ascii")
            chunks.extend(
                (
                    len(name).to_bytes(2, "big"),
                    name,
                    table.padded_rows.to_bytes(8, "big"),
                    table.trace_columns.to_bytes(4, "big"),
                    table.constraint_count.to_bytes(4, "big"),
                    table.maximum_constraint_degree.to_bytes(2, "big"),
                    table.lookup_coordinate_width.to_bytes(2, "big"),
                )
            )
        return b"".join(chunks)

    @property
    def commitment_sha3_512(self) -> bytes:
        return sha3_512(self.canonical_bytes()).digest()


@dataclass(frozen=True, slots=True)
class UniqueDecodingCandidate:
    """One exact unique-decoding Circle-FRI candidate for comparison."""

    log_blowup: int
    theta: Fraction
    query_count: int
    evaluation_domain_size: int
    terminal_domain_size: int
    interface_error_terms: tuple[tuple[str, Fraction], ...]
    final_expansion_substituted: bool = False
    selected: bool = False

    def __post_init__(self) -> None:
        _require_exact_int("log_blowup", self.log_blowup, minimum=1)
        if not isinstance(self.theta, Fraction) or not 0 < self.theta < 1:
            raise ValueError("wave1b_theta_invalid")
        _require_exact_int("query_count", self.query_count, minimum=1)
        if not _power_of_two(self.evaluation_domain_size):
            raise ValueError("wave1b_evaluation_domain_invalid")
        if not _power_of_two(self.terminal_domain_size):
            raise ValueError("wave1b_terminal_domain_invalid")
        if self.terminal_domain_size > self.evaluation_domain_size:
            raise ValueError("wave1b_terminal_domain_exceeds_initial")
        if not self.interface_error_terms or len(
            {name for name, _ in self.interface_error_terms}
        ) != len(self.interface_error_terms):
            raise ValueError("wave1b_error_term_names_invalid")
        if any(not isinstance(value, Fraction) or value <= 0 for _, value in self.interface_error_terms):
            raise ValueError("wave1b_error_term_invalid")
        relative_distance = 1 - Fraction(1, 1 << self.log_blowup)
        if self.theta >= relative_distance / 2:
            raise ValueError("wave1b_candidate_outside_unique_decoding_regime")
        if 1 - self.theta <= Fraction(1, 1 << self.log_blowup) * (
            1 + Fraction(2, self.terminal_domain_size)
        ):
            raise ValueError("wave1b_degree_correction_condition_failed")
        if self.final_expansion_substituted or self.selected:
            raise ValueError("wave1b_interface_candidate_cannot_be_selected")

    @property
    def rate(self) -> Fraction:
        return Fraction(1, 1 << self.log_blowup)

    @property
    def relative_distance(self) -> Fraction:
        return 1 - self.rate

    @property
    def query_error(self) -> Fraction:
        return dict(self.interface_error_terms)["fri_query"]

    @property
    def interface_error_total(self) -> Fraction:
        return sum((value for _, value in self.interface_error_terms), start=Fraction(0, 1))

    @property
    def all_terms_meet_budget(self) -> bool:
        return all(meets_per_term_budget(value) for _, value in self.interface_error_terms)

    @property
    def unique_decoding_regime(self) -> bool:
        return self.theta < self.relative_distance / 2

    @property
    def degree_correction_condition(self) -> bool:
        # Whitepaper condition: 1-theta > (1-delta)*(1+2/N_i).
        return 1 - self.theta > self.rate * (1 + Fraction(2, self.terminal_domain_size))

    @property
    def fold_round_count(self) -> int:
        """Circle-to-line plus every attached-domain line fold, including the smallest."""

        return (
            self.evaluation_domain_size.bit_length()
            - self.terminal_domain_size.bit_length()
            + 1
        )

    @property
    def final_line_domain_size(self) -> int:
        return self.terminal_domain_size >> 1


def _minimal_query_count(one_minus_theta: Fraction) -> int:
    if not isinstance(one_minus_theta, Fraction) or not 0 < one_minus_theta < 1:
        raise ValueError("wave1b_one_minus_theta_invalid")
    count = 1
    target = Fraction(1, 1 << PER_TERM_SECURITY_BITS)
    while one_minus_theta**count > target:
        count += 1
    return count


def build_unique_decoding_candidate(
    envelope: InterfaceTheoremEnvelope,
    *,
    log_blowup: int,
) -> UniqueDecodingCandidate:
    """Build an unselected exact UDR candidate from a relation envelope."""

    if not isinstance(envelope, InterfaceTheoremEnvelope):
        raise TypeError("wave1b_interface_envelope_required")
    _require_exact_int("log_blowup", log_blowup, minimum=1)
    if log_blowup > 16:
        raise ValueError("wave1b_log_blowup_too_large")

    rate = Fraction(1, 1 << log_blowup)
    relative_distance = 1 - rate
    slack_denominator = 1 << UNIQUE_DECODING_BOUNDARY_SLACK_BITS
    theta = relative_distance * Fraction(slack_denominator - 1, 2 * slack_denominator)
    query_count = _minimal_query_count(1 - theta)
    initial_domain = envelope.maximum_rows << log_blowup
    terminal_domain = envelope.minimum_rows << log_blowup

    logup = Fraction(envelope.logup_numerator_upper_bound, CHALLENGE_FIELD_CARDINALITY)
    composition = Fraction(
        envelope.composition_numerator_upper_bound, CHALLENGE_FIELD_CARDINALITY
    )
    deep = Fraction(envelope.deep_numerator_upper_bound, OODS_PARAMETER_SPACE_SIZE)
    fri_batch = Fraction(
        (envelope.interface_batch_width_upper_bound - 1) * initial_domain,
        CHALLENGE_FIELD_CARDINALITY,
    )

    fold_domain_sum = 0
    layer_size = initial_domain
    while layer_size >= terminal_domain:
        fold_domain_sum += layer_size
        layer_size //= 2
    fri_fold = Fraction(3 * fold_domain_sum, CHALLENGE_FIELD_CARDINALITY)
    fri_query = (1 - theta) ** query_count

    return UniqueDecodingCandidate(
        log_blowup=log_blowup,
        theta=theta,
        query_count=query_count,
        evaluation_domain_size=initial_domain,
        terminal_domain_size=terminal_domain,
        interface_error_terms=(
            ("logup", logup),
            ("composition", composition),
            ("deep", deep),
            ("fri_batch", fri_batch),
            ("fri_fold", fri_fold),
            ("fri_query", fri_query),
        ),
    )


def build_candidate_sweep(
    envelope: InterfaceTheoremEnvelope,
    log_blowups: Iterable[int] = range(1, 7),
) -> tuple[UniqueDecodingCandidate, ...]:
    values = tuple(log_blowups)
    if not values or len(set(values)) != len(values):
        raise ValueError("wave1b_log_blowup_sweep_invalid")
    candidates = tuple(
        build_unique_decoding_candidate(envelope, log_blowup=value) for value in values
    )
    if any(not candidate.unique_decoding_regime for candidate in candidates):
        raise AssertionError("wave1b_candidate_outside_unique_decoding_regime")
    if any(not candidate.degree_correction_condition for candidate in candidates):
        raise AssertionError("wave1b_degree_correction_condition_failed")
    return candidates
