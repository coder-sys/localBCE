"""Exact nonactivating native-hiding parameter worksheet for Wave 1B.

The trace-mask bound is Equation (3) of Haboeck--Al Kindi's 2024 note for
FFT quotient decomposition::

    h >= 2*d*(e*n_oods + n_fri) + n_fri

Here ``d`` is the reduced AIR degree, ``e`` is the challenge-field extension
degree, and the final term covers FRI queries that need not overlap the
implicit quotient queries.  This is deliberately the conservative theorem
mapping.  It is not silently replaced by the smaller canonical-decomposition
bound.

This module applies the bound to every frozen Wave 1A physical table and
computes any row-domain expansion required by ``h <= |H|``.  It also records
the oracle coverage that remains dependent on the final SHA3-expanded AIR and
the Circle-function-space simulator.  Consequently every plan is synthetic,
nonactivating, and refuses an activation-readiness claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Sequence


M31_MODULUS: Final[int] = (1 << 31) - 1
HIDING_PLAN_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1B/NATIVE-HIDING-PLAN/v1"
FRI_DOMAIN_SCHEDULE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/FRI-DOMAIN-SCHEDULE/v1"
)
HIDING_PLAN_STATUS: Final[str] = (
    "WAVE1B_NATIVE_HIDING_DIRECT_MAP_QUOTIENT_MASK_SPLIT_RULE_PROVED_FINAL_SIMULATOR_REQUIRED_NONACTIVATING"
)
REQUIRED_EXTENSION_DEGREE: Final[int] = 16
REQUIRED_OODS_QUERY_COUNT: Final[int] = 1
MAX_CIRCLE_DOMAIN_LOG_SIZE: Final[int] = 30

_FINAL_COVERAGE_GAPS: Final[tuple[str, ...]] = (
    "FINAL_CIRCLE_SPLIT_LOG_DEGREE_AND_PROVER_INTEGRATION",
    "FINAL_SHA3_AIR_INTERACTION_ORACLE_DIMENSIONS",
    "FINAL_MULTI_DOMAIN_FRI_ORACLE_WIDTHS_AFTER_SHA3_AIR_EXPANSION",
    "INTERACTIVE_CIRCLE_SIMULATOR_TRANSCRIPT",
)


def _exact_int(label: str, value: object, *, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"native_hiding_{label}_invalid")
    return value


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _next_power_of_two(value: int) -> int:
    _exact_int("next_power_of_two_input", value, minimum=1)
    return 1 << (value - 1).bit_length()


def _ascii(label: str, value: object) -> bytes:
    if type(value) is not str or not value:
        raise ValueError(f"native_hiding_{label}_invalid")
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"native_hiding_{label}_not_ascii") from exc


@dataclass(frozen=True, slots=True)
class HidingTableDimensions:
    """The native-hiding inputs for one physical table."""

    name: str
    padded_rows: int
    trace_columns: int
    private: bool

    def __post_init__(self) -> None:
        _ascii("table_name", self.name)
        _exact_int("table_padded_rows", self.padded_rows, minimum=1)
        if not _power_of_two(self.padded_rows):
            raise ValueError("native_hiding_table_padded_rows_not_power_of_two")
        _exact_int("table_trace_columns", self.trace_columns, minimum=1)
        if type(self.private) is not bool:
            raise TypeError("native_hiding_table_private_must_be_bool")


@dataclass(frozen=True, slots=True)
class HidingTablePlan:
    """One table's exact trace-mask and padding decision."""

    dimensions: HidingTableDimensions
    mask_degree_freedom: int
    target_trace_rows: int
    randomizer_coefficient_count: int

    def __post_init__(self) -> None:
        if type(self.dimensions) is not HidingTableDimensions:
            raise TypeError("native_hiding_table_dimensions_required")
        _exact_int("mask_degree_freedom", self.mask_degree_freedom, minimum=0)
        _exact_int("target_trace_rows", self.target_trace_rows, minimum=1)
        _exact_int(
            "randomizer_coefficient_count",
            self.randomizer_coefficient_count,
            minimum=0,
        )
        if not _power_of_two(self.target_trace_rows):
            raise ValueError("native_hiding_target_trace_rows_not_power_of_two")
        if self.target_trace_rows < self.dimensions.padded_rows:
            raise ValueError("native_hiding_target_trace_rows_shrank")
        if self.dimensions.private:
            if self.target_trace_rows < self.mask_degree_freedom:
                raise ValueError("native_hiding_mask_degree_exceeds_trace_domain")
            expected = self.dimensions.trace_columns * self.mask_degree_freedom
            if self.randomizer_coefficient_count != expected:
                raise ValueError("native_hiding_randomizer_coefficient_count_mismatch")
        elif self.mask_degree_freedom != 0 or self.randomizer_coefficient_count != 0:
            raise ValueError("native_hiding_public_table_must_not_receive_private_mask")

    @property
    def added_rows(self) -> int:
        return self.target_trace_rows - self.dimensions.padded_rows

    @property
    def requires_row_extension(self) -> bool:
        return self.added_rows != 0


@dataclass(frozen=True, slots=True)
class OracleCoverageRule:
    """One explicit or implicit oracle and its current hiding treatment."""

    name: str
    privacy_sensitive: bool
    strategy: str
    interface_covered: bool
    final_expansion_required: bool

    def __post_init__(self) -> None:
        _ascii("oracle_name", self.name)
        _ascii("oracle_strategy", self.strategy)
        for label, value in (
            ("privacy_sensitive", self.privacy_sensitive),
            ("interface_covered", self.interface_covered),
            ("final_expansion_required", self.final_expansion_required),
        ):
            if type(value) is not bool:
                raise TypeError(f"native_hiding_oracle_{label}_must_be_bool")
        if self.privacy_sensitive and not (
            self.interface_covered or self.final_expansion_required
        ):
            raise ValueError("native_hiding_private_oracle_has_no_strategy")


@dataclass(frozen=True, slots=True)
class FriDomainGroupPlan:
    """One attached trace domain after mandatory hiding-row expansion."""

    trace_log_size: int
    evaluation_log_size: int
    table_names: tuple[str, ...]
    trace_column_count: int
    global_power_offset: int
    mask_column_count: int = 1

    def __post_init__(self) -> None:
        _exact_int("fri_trace_log_size", self.trace_log_size, minimum=2)
        _exact_int("fri_evaluation_log_size", self.evaluation_log_size, minimum=3)
        if self.evaluation_log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE:
            raise ValueError("native_hiding_fri_evaluation_log_size_too_large")
        if self.evaluation_log_size <= self.trace_log_size:
            raise ValueError("native_hiding_fri_evaluation_domain_not_expanded")
        if type(self.table_names) is not tuple or not self.table_names:
            raise ValueError("native_hiding_fri_table_names_required")
        if len(set(self.table_names)) != len(self.table_names):
            raise ValueError("native_hiding_fri_table_name_duplicate")
        for name in self.table_names:
            _ascii("fri_table_name", name)
        _exact_int("fri_trace_column_count", self.trace_column_count, minimum=1)
        _exact_int("fri_global_power_offset", self.global_power_offset, minimum=0)
        if self.mask_column_count != 1:
            raise ValueError("native_hiding_fri_exactly_one_domain_mask_required")


@dataclass(frozen=True, slots=True)
class FriInterfaceDomainSchedule:
    """Metadata-only 16-table FRI schedule; no evaluation allocation or proof claim."""

    log_blowup: int
    groups: tuple[FriDomainGroupPlan, ...]
    fold_log_sizes: tuple[int, ...]

    def __post_init__(self) -> None:
        _exact_int("fri_schedule_log_blowup", self.log_blowup, minimum=1)
        if type(self.groups) is not tuple or not self.groups:
            raise ValueError("native_hiding_fri_domain_groups_required")
        if any(type(group) is not FriDomainGroupPlan for group in self.groups):
            raise TypeError("native_hiding_fri_domain_group_type_invalid")
        if any(
            left.evaluation_log_size <= right.evaluation_log_size
            for left, right in zip(self.groups[:-1], self.groups[1:], strict=True)
        ):
            raise ValueError("native_hiding_fri_domains_not_strictly_descending")
        expected_offset = 0
        table_names: list[str] = []
        for group in self.groups:
            if group.evaluation_log_size != group.trace_log_size + self.log_blowup:
                raise ValueError("native_hiding_fri_blowup_log_mismatch")
            if group.global_power_offset != expected_offset:
                raise ValueError("native_hiding_fri_global_power_offset_mismatch")
            expected_offset += group.trace_column_count
            table_names.extend(group.table_names)
        if len(table_names) != 16 or len(set(table_names)) != 16:
            raise ValueError("native_hiding_fri_schedule_must_cover_sixteen_tables")
        expected_folds = tuple(
            range(
                self.groups[0].evaluation_log_size,
                self.groups[-1].evaluation_log_size - 1,
                -1,
            )
        )
        if self.fold_log_sizes != expected_folds:
            raise ValueError("native_hiding_fri_fold_schedule_mismatch")

    @property
    def trace_column_count(self) -> int:
        return sum(group.trace_column_count for group in self.groups)

    @property
    def mask_column_count(self) -> int:
        return sum(group.mask_column_count for group in self.groups)

    @property
    def canonical_bytes(self) -> bytes:
        chunks = [
            FRI_DOMAIN_SCHEDULE_DOMAIN,
            self.log_blowup.to_bytes(2, "big"),
            len(self.groups).to_bytes(2, "big"),
            len(self.fold_log_sizes).to_bytes(2, "big"),
        ]
        chunks.extend(log_size.to_bytes(2, "big") for log_size in self.fold_log_sizes)
        for group in self.groups:
            chunks.extend(
                (
                    group.trace_log_size.to_bytes(2, "big"),
                    group.evaluation_log_size.to_bytes(2, "big"),
                    group.trace_column_count.to_bytes(4, "big"),
                    group.global_power_offset.to_bytes(4, "big"),
                    group.mask_column_count.to_bytes(2, "big"),
                    len(group.table_names).to_bytes(2, "big"),
                )
            )
            for name in group.table_names:
                encoded = _ascii("fri_table_name", name)
                chunks.extend((len(encoded).to_bytes(2, "big"), encoded))
        return b"".join(chunks)

    @property
    def commitment_sha3_512(self) -> bytes:
        return sha3_512(self.canonical_bytes).digest()


@dataclass(frozen=True, slots=True)
class NativeHidingInterfacePlan:
    """Audit-ready interface worksheet; never a privacy or activation claim."""

    profile_id: str
    log_blowup: int
    fri_query_count: int
    extension_degree: int
    oods_query_count: int
    reduced_air_degree: int
    trace_mask_degree_freedom: int
    table_plans: tuple[HidingTablePlan, ...]
    oracle_rules: tuple[OracleCoverageRule, ...]
    coverage_gaps: tuple[str, ...] = _FINAL_COVERAGE_GAPS
    status: str = HIDING_PLAN_STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False
    simulator_complete: bool = False

    def __post_init__(self) -> None:
        _ascii("profile_id", self.profile_id)
        _exact_int("log_blowup", self.log_blowup, minimum=1)
        _exact_int("fri_query_count", self.fri_query_count, minimum=1)
        if self.extension_degree != REQUIRED_EXTENSION_DEGREE:
            raise ValueError("native_hiding_extension_degree_mismatch")
        if self.oods_query_count != REQUIRED_OODS_QUERY_COUNT:
            raise ValueError("native_hiding_oods_query_count_mismatch")
        _exact_int("reduced_air_degree", self.reduced_air_degree, minimum=1)
        _exact_int(
            "trace_mask_degree_freedom", self.trace_mask_degree_freedom, minimum=1
        )
        expected_h = 2 * self.reduced_air_degree * (
            self.extension_degree * self.oods_query_count + self.fri_query_count
        ) + self.fri_query_count
        if self.trace_mask_degree_freedom != expected_h:
            raise ValueError("native_hiding_trace_mask_degree_formula_mismatch")
        if type(self.table_plans) is not tuple or len(self.table_plans) != 16:
            raise ValueError("native_hiding_exactly_sixteen_table_plans_required")
        if len({plan.dimensions.name for plan in self.table_plans}) != 16:
            raise ValueError("native_hiding_table_name_duplicate")
        if not any(plan.dimensions.private for plan in self.table_plans):
            raise ValueError("native_hiding_private_table_required")
        if not any(not plan.dimensions.private for plan in self.table_plans):
            raise ValueError("native_hiding_public_table_required")
        if type(self.oracle_rules) is not tuple or not self.oracle_rules:
            raise ValueError("native_hiding_oracle_rules_required")
        if len({rule.name for rule in self.oracle_rules}) != len(self.oracle_rules):
            raise ValueError("native_hiding_oracle_name_duplicate")
        if self.coverage_gaps != _FINAL_COVERAGE_GAPS:
            raise ValueError("native_hiding_coverage_gaps_mismatch")
        if (
            self.status != HIDING_PLAN_STATUS
            or self.proof_suite_id is not None
            or self.activation_allowed
            or self.simulator_complete
        ):
            raise ValueError("native_hiding_nonactivating_boundary_violated")

    @property
    def private_trace_columns(self) -> int:
        return sum(
            plan.dimensions.trace_columns
            for plan in self.table_plans
            if plan.dimensions.private
        )

    @property
    def randomizer_coefficient_count(self) -> int:
        return sum(plan.randomizer_coefficient_count for plan in self.table_plans)

    @property
    def entropy_lower_bound_bits(self) -> int:
        # Every independent uniform M31 coefficient contributes more than 30 bits.
        return 30 * self.randomizer_coefficient_count

    @property
    def row_extension_count(self) -> int:
        return sum(plan.requires_row_extension for plan in self.table_plans)

    @property
    def total_added_rows(self) -> int:
        return sum(plan.added_rows for plan in self.table_plans)

    @property
    def uncovered_oracle_names(self) -> tuple[str, ...]:
        return tuple(
            rule.name
            for rule in self.oracle_rules
            if rule.privacy_sensitive and not rule.interface_covered
        )

    @property
    def fri_domain_schedule(self) -> FriInterfaceDomainSchedule:
        grouped: dict[int, list[HidingTablePlan]] = {}
        for plan in self.table_plans:
            grouped.setdefault(plan.target_trace_rows, []).append(plan)
        groups: list[FriDomainGroupPlan] = []
        global_power_offset = 0
        for target_trace_rows in sorted(grouped, reverse=True):
            plans = grouped[target_trace_rows]
            trace_column_count = sum(
                plan.dimensions.trace_columns for plan in plans
            )
            trace_log_size = target_trace_rows.bit_length() - 1
            groups.append(
                FriDomainGroupPlan(
                    trace_log_size=trace_log_size,
                    evaluation_log_size=trace_log_size + self.log_blowup,
                    table_names=tuple(plan.dimensions.name for plan in plans),
                    trace_column_count=trace_column_count,
                    global_power_offset=global_power_offset,
                )
            )
            global_power_offset += trace_column_count
        materialized = tuple(groups)
        return FriInterfaceDomainSchedule(
            log_blowup=self.log_blowup,
            groups=materialized,
            fold_log_sizes=tuple(
                range(
                    materialized[0].evaluation_log_size,
                    materialized[-1].evaluation_log_size - 1,
                    -1,
                )
            ),
        )

    @property
    def canonical_bytes(self) -> bytes:
        chunks = [
            HIDING_PLAN_DOMAIN,
            len(_ascii("profile_id", self.profile_id)).to_bytes(2, "big"),
            _ascii("profile_id", self.profile_id),
            self.log_blowup.to_bytes(2, "big"),
            self.fri_query_count.to_bytes(4, "big"),
            self.extension_degree.to_bytes(2, "big"),
            self.oods_query_count.to_bytes(2, "big"),
            self.reduced_air_degree.to_bytes(2, "big"),
            self.trace_mask_degree_freedom.to_bytes(8, "big"),
            len(self.table_plans).to_bytes(2, "big"),
        ]
        for plan in self.table_plans:
            name = _ascii("table_name", plan.dimensions.name)
            chunks.extend(
                (
                    len(name).to_bytes(2, "big"),
                    name,
                    plan.dimensions.padded_rows.to_bytes(8, "big"),
                    plan.dimensions.trace_columns.to_bytes(4, "big"),
                    bytes((plan.dimensions.private,)),
                    plan.mask_degree_freedom.to_bytes(8, "big"),
                    plan.target_trace_rows.to_bytes(8, "big"),
                    plan.randomizer_coefficient_count.to_bytes(8, "big"),
                )
            )
        for rule in self.oracle_rules:
            name = _ascii("oracle_name", rule.name)
            strategy = _ascii("oracle_strategy", rule.strategy)
            chunks.extend(
                (
                    len(name).to_bytes(2, "big"),
                    name,
                    len(strategy).to_bytes(2, "big"),
                    strategy,
                    bytes(
                        (
                            rule.privacy_sensitive,
                            rule.interface_covered,
                            rule.final_expansion_required,
                        )
                    ),
                )
            )
        for gap in self.coverage_gaps:
            encoded = _ascii("coverage_gap", gap)
            chunks.extend((len(encoded).to_bytes(2, "big"), encoded))
        return b"".join(chunks)

    @property
    def commitment_sha3_512(self) -> bytes:
        return sha3_512(self.canonical_bytes).digest()

    def require_activation_ready(self) -> None:
        gaps = ",".join(self.coverage_gaps)
        raise RuntimeError(f"native_hiding_not_activation_ready:{gaps}")


def _oracle_rules() -> tuple[OracleCoverageRule, ...]:
    return (
        OracleCoverageRule(
            "PRIVATE_MAIN_TRACE",
            True,
            "INDEPENDENT_BASE_FIELD_Z_H_TIMES_R_PER_PRIVATE_COLUMN",
            True,
            False,
        ),
        OracleCoverageRule(
            "PUBLIC_STATEMENT_TRACE",
            False,
            "PUBLIC_BY_SCHEMA_NO_WITNESS_HIDING_CREDIT",
            True,
            False,
        ),
        OracleCoverageRule(
            "NEIGHBOR_AND_ROTATION_OPENINGS",
            True,
            "TWO_TRANSLATE_FACTOR_IN_TRACE_MASK_DEGREE",
            True,
            False,
        ),
        OracleCoverageRule(
            "FP16_FP8_CONJUGATE_OPENINGS",
            True,
            "EXTENSION_DEGREE_CLOSURE_AND_CONJUGATE_PAIR_QUOTIENT",
            True,
            False,
        ),
        OracleCoverageRule(
            "DIRECT_CIRCLE_TRACE_EVALUATION_MAP",
            True,
            "MULTI_FP16_TRANSLATED_OODS_AND_BASE_QUERY_CRT_CERTIFICATE",
            True,
            True,
        ),
        OracleCoverageRule(
            "INTERACTION_TRACE",
            True,
            "INDEPENDENT_MASKS_AFTER_BETA_CHALLENGES",
            False,
            True,
        ),
        OracleCoverageRule(
            "COMPOSITION_AND_QUOTIENT",
            True,
            "SOURCE_ALIGNED_CANONICAL_TWO_COMPONENT_KERNEL_MASK_WITH_HQ_EQUALS_N_OODS_PLUS_N_FRI",
            True,
            True,
        ),
        OracleCoverageRule(
            "DEEP_ORIGINAL_AND_PAIR_QUOTIENT",
            True,
            "JOINT_DEGREE_CORRECTED_FRI_BATCH",
            True,
            False,
        ),
        OracleCoverageRule(
            "FRI_BATCH_MASK",
            True,
            "INDEPENDENT_FP16_MASK_COMMITTED_BEFORE_BATCH_CHALLENGE",
            True,
            True,
        ),
        OracleCoverageRule(
            "FRI_FOLDED_LAYERS",
            True,
            "DECOUPLED_BY_BATCH_MASK_THROUGH_EVERY_INSERTED_FOLD",
            True,
            True,
        ),
    )


def build_native_hiding_interface_plan(
    *,
    profile_id: str,
    tables: Sequence[HidingTableDimensions],
    log_blowup: int,
    fri_query_count: int,
    reduced_air_degree: int,
) -> NativeHidingInterfacePlan:
    """Apply the conservative perfect-HVZK mask bound to all 16 tables."""

    _ascii("profile_id", profile_id)
    _exact_int("log_blowup", log_blowup, minimum=1)
    _exact_int("fri_query_count", fri_query_count, minimum=1)
    _exact_int("reduced_air_degree", reduced_air_degree, minimum=1)
    if isinstance(tables, (str, bytes, bytearray)):
        raise TypeError("native_hiding_tables_must_be_sequence")
    materialized = tuple(tables)
    if len(materialized) != 16 or any(
        type(table) is not HidingTableDimensions for table in materialized
    ):
        raise ValueError("native_hiding_exactly_sixteen_tables_required")

    h = 2 * reduced_air_degree * (
        REQUIRED_EXTENSION_DEGREE * REQUIRED_OODS_QUERY_COUNT + fri_query_count
    ) + fri_query_count
    minimum_private_rows = _next_power_of_two(h)
    table_plans = tuple(
        HidingTablePlan(
            dimensions=table,
            mask_degree_freedom=h if table.private else 0,
            target_trace_rows=(
                max(table.padded_rows, minimum_private_rows)
                if table.private
                else table.padded_rows
            ),
            randomizer_coefficient_count=(
                table.trace_columns * h if table.private else 0
            ),
        )
        for table in materialized
    )
    return NativeHidingInterfacePlan(
        profile_id=profile_id,
        log_blowup=log_blowup,
        fri_query_count=fri_query_count,
        extension_degree=REQUIRED_EXTENSION_DEGREE,
        oods_query_count=REQUIRED_OODS_QUERY_COUNT,
        reduced_air_degree=reduced_air_degree,
        trace_mask_degree_freedom=h,
        table_plans=table_plans,
        oracle_rules=_oracle_rules(),
    )


__all__ = [
    "HIDING_PLAN_STATUS",
    "FRI_DOMAIN_SCHEDULE_DOMAIN",
    "FriDomainGroupPlan",
    "FriInterfaceDomainSchedule",
    "HidingTableDimensions",
    "HidingTablePlan",
    "NativeHidingInterfacePlan",
    "OracleCoverageRule",
    "build_native_hiding_interface_plan",
]
