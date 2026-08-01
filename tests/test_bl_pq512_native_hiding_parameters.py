from __future__ import annotations

import os

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.native_hiding_parameters import (
    HIDING_PLAN_STATUS,
    HidingTableDimensions,
    build_native_hiding_interface_plan,
)
from experiments.bl_pq512_crypto_foundation.unique_decoding_parameters import (
    InterfaceTableDimensions,
    InterfaceTheoremEnvelope,
    build_unique_decoding_candidate,
)
from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_air_program,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


def _inputs(profile_id: str):
    program = build_wave1a_physical_air_program(PROFILES[profile_id])
    envelope = InterfaceTheoremEnvelope(
        profile_id=program.profile_id,
        tables=tuple(
            InterfaceTableDimensions(
                table.name,
                table.padded_rows,
                table.trace_columns,
                table.constraint_count,
                table.maximum_degree,
                table.lookup_message_width,
            )
            for table in program.tables
        ),
        commitment_group_count=program.commitment_count,
    )
    hiding_tables = tuple(
        HidingTableDimensions(
            table.name,
            table.padded_rows,
            table.trace_columns,
            table.commitment_group != "public_statement",
        )
        for table in program.tables
    )
    return program, envelope, hiding_tables


def _plan(profile_id: str, log_blowup: int):
    program, envelope, hiding_tables = _inputs(profile_id)
    candidate = build_unique_decoding_candidate(envelope, log_blowup=log_blowup)
    return build_native_hiding_interface_plan(
        profile_id=profile_id,
        tables=hiding_tables,
        log_blowup=log_blowup,
        fri_query_count=candidate.query_count,
        reduced_air_degree=program.maximum_constraint_degree - 1,
    )


def test_all_profiles_and_rate_candidates_apply_the_exact_mask_formula() -> None:
    expected_query_counts = (926, 567, 463, 421, 402, 393)
    expected_h = (4694, 2899, 2379, 2169, 2074, 2029)
    for profile_id in PROFILES:
        for log_blowup, (query_count, mask_degree) in enumerate(
            zip(expected_query_counts, expected_h, strict=True), start=1
        ):
            plan = _plan(profile_id, log_blowup)
            assert plan.status == HIDING_PLAN_STATUS
            assert plan.fri_query_count == query_count
            assert plan.trace_mask_degree_freedom == mask_degree
            assert plan.trace_mask_degree_freedom == (
                2
                * plan.reduced_air_degree
                * (
                    plan.extension_degree * plan.oods_query_count
                    + plan.fri_query_count
                )
                + plan.fri_query_count
            )
            assert all(
                not table.dimensions.private
                or table.target_trace_rows >= plan.trace_mask_degree_freedom
                for table in plan.table_plans
            )
            assert plan.proof_suite_id is None
            assert not plan.activation_allowed
            assert not plan.simulator_complete


def test_k512_rate_half_inventory_entropy_and_padding_are_exact() -> None:
    plan = _plan("K512_CALIBRATION", 1)
    assert plan.private_trace_columns == 2_191
    assert plan.randomizer_coefficient_count == 10_284_554
    assert plan.entropy_lower_bound_bits == 308_536_620
    assert plan.row_extension_count == 4
    assert plan.total_added_rows == 27_136
    assert tuple(
        table.dimensions.name
        for table in plan.table_plans
        if table.requires_row_extension
    ) == (
        "canonical_witness",
        "claim_gate_and_money",
        "oracle_facts",
        "payment_operation_log",
    )
    assert all(
        table.target_trace_rows == 8_192
        for table in plan.table_plans
        if table.requires_row_extension
    )
    public = next(
        table
        for table in plan.table_plans
        if table.dimensions.name == "ordered_public_statement"
    )
    assert not public.dimensions.private
    assert public.target_trace_rows == 16
    assert public.mask_degree_freedom == 0
    assert public.randomizer_coefficient_count == 0
    assert plan.commitment_sha3_512.hex() == (
        "0800c37c3896025bff3a61bd16af9deb91dd66a4eb8b2d8886ad05fb71a51685"
        "0c27aaacf5356009deb6c6fdb10736427f3207a5075823722d76edab42e11453"
    )

    schedule = plan.fri_domain_schedule
    assert tuple(group.trace_log_size for group in schedule.groups) == (
        19,
        17,
        16,
        15,
        13,
        4,
    )
    assert tuple(group.evaluation_log_size for group in schedule.groups) == (
        20,
        18,
        17,
        16,
        14,
        5,
    )
    assert tuple(group.trace_column_count for group in schedule.groups) == (
        188,
        372,
        272,
        312,
        1_047,
        88,
    )
    assert tuple(group.global_power_offset for group in schedule.groups) == (
        0,
        188,
        560,
        832,
        1_144,
        2_191,
    )
    assert schedule.trace_column_count == 2_279
    assert schedule.mask_column_count == 6
    assert schedule.fold_log_sizes == tuple(range(20, 4, -1))
    assert schedule.commitment_sha3_512.hex() == (
        "b147a129a899e33a4ed7097ac706c367f971aabe8b6cb1881736959032530c30"
        "b4ccd10caff63b294f7ff9977e21db599515a28c08d56be2e73b84714c7e1373"
    )


def test_oracle_inventory_states_exactly_what_is_and_is_not_covered() -> None:
    plan = _plan("K256_DESIGN_POINT", 2)
    assert tuple(rule.name for rule in plan.oracle_rules) == (
        "PRIVATE_MAIN_TRACE",
        "PUBLIC_STATEMENT_TRACE",
        "NEIGHBOR_AND_ROTATION_OPENINGS",
        "FP16_FP8_CONJUGATE_OPENINGS",
        "DIRECT_CIRCLE_TRACE_EVALUATION_MAP",
        "INTERACTION_TRACE",
        "COMPOSITION_AND_QUOTIENT",
        "DEEP_ORIGINAL_AND_PAIR_QUOTIENT",
        "FRI_BATCH_MASK",
        "FRI_FOLDED_LAYERS",
    )
    assert plan.uncovered_oracle_names == ("INTERACTION_TRACE",)
    assert plan.coverage_gaps == (
        "FINAL_CIRCLE_SPLIT_LOG_DEGREE_AND_PROVER_INTEGRATION",
        "FINAL_SHA3_AIR_INTERACTION_ORACLE_DIMENSIONS",
        "FINAL_MULTI_DOMAIN_FRI_ORACLE_WIDTHS_AFTER_SHA3_AIR_EXPANSION",
        "INTERACTIVE_CIRCLE_SIMULATOR_TRANSCRIPT",
    )
    assert len(plan.commitment_sha3_512) == 64
