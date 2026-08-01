from __future__ import annotations

import os
from dataclasses import replace

import pytest

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.native_hiding_parameters import (
    FriInterfaceDomainSchedule,
    HidingTableDimensions,
    build_native_hiding_interface_plan,
)
from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_air_program,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


def _tables() -> tuple[HidingTableDimensions, ...]:
    program = build_wave1a_physical_air_program(PROFILES["K128_CALIBRATION"])
    return tuple(
        HidingTableDimensions(
            table.name,
            table.padded_rows,
            table.trace_columns,
            table.commitment_group != "public_statement",
        )
        for table in program.tables
    )


def _valid_plan():
    return build_native_hiding_interface_plan(
        profile_id="K128_CALIBRATION",
        tables=_tables(),
        log_blowup=1,
        fri_query_count=926,
        reduced_air_degree=2,
    )


def test_off_by_one_mask_degree_and_underpadding_fail_closed() -> None:
    plan = _valid_plan()
    with pytest.raises(ValueError, match="trace_mask_degree_formula_mismatch"):
        replace(plan, trace_mask_degree_freedom=plan.trace_mask_degree_freedom - 1)
    private = next(table for table in plan.table_plans if table.dimensions.private)
    with pytest.raises(ValueError, match="mask_degree_exceeds_trace_domain"):
        replace(private, target_trace_rows=512)


def test_public_trace_cannot_be_silently_counted_as_private_mask_entropy() -> None:
    plan = _valid_plan()
    public_index = next(
        index
        for index, table in enumerate(plan.table_plans)
        if not table.dimensions.private
    )
    public = plan.table_plans[public_index]
    with pytest.raises(ValueError, match="public_table_must_not_receive_private_mask"):
        replace(public, mask_degree_freedom=plan.trace_mask_degree_freedom)


def test_missing_table_invalid_extension_and_activation_claims_fail_closed() -> None:
    with pytest.raises(ValueError, match="exactly_sixteen_tables_required"):
        build_native_hiding_interface_plan(
            profile_id="K128_CALIBRATION",
            tables=_tables()[:-1],
            log_blowup=1,
            fri_query_count=926,
            reduced_air_degree=2,
        )
    plan = _valid_plan()
    with pytest.raises(ValueError, match="extension_degree_mismatch"):
        replace(plan, extension_degree=4)
    with pytest.raises(ValueError, match="nonactivating_boundary_violated"):
        replace(plan, activation_allowed=True)
    with pytest.raises(RuntimeError, match="native_hiding_not_activation_ready"):
        plan.require_activation_ready()


def test_erasing_a_required_coverage_gap_is_rejected() -> None:
    plan = _valid_plan()
    with pytest.raises(ValueError, match="coverage_gaps_mismatch"):
        replace(plan, coverage_gaps=plan.coverage_gaps[:-1])


def test_fri_domain_schedule_rejects_offset_mask_order_and_fold_tampering() -> None:
    schedule = _valid_plan().fri_domain_schedule
    second = schedule.groups[1]
    with pytest.raises(ValueError, match="global_power_offset_mismatch"):
        replace(
            schedule,
            groups=(
                schedule.groups[0],
                replace(second, global_power_offset=second.global_power_offset - 1),
                *schedule.groups[2:],
            ),
        )
    with pytest.raises(ValueError, match="exactly_one_domain_mask_required"):
        replace(schedule.groups[0], mask_column_count=0)
    with pytest.raises(ValueError, match="domains_not_strictly_descending"):
        replace(
            schedule,
            groups=(schedule.groups[1], schedule.groups[0], *schedule.groups[2:]),
        )
    with pytest.raises(ValueError, match="fold_schedule_mismatch"):
        replace(schedule, fold_log_sizes=schedule.fold_log_sizes[:-1])
    with pytest.raises(TypeError, match="domain_group_type_invalid"):
        FriInterfaceDomainSchedule(
            log_blowup=schedule.log_blowup,
            groups=(object(),),  # type: ignore[arg-type]
            fold_log_sizes=schedule.fold_log_sizes,
        )
