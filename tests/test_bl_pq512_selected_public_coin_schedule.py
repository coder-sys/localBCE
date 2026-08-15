from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    RoundKind,
    build_selected_theorem_round_schedule,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    SELECTED_PARAMETER_COMMITMENT,
    derive_selected_proof_geometry,
    proof_suite_id,
)
from tests.fixtures.selected_air import selected_air_fixture


def _schedule():
    program, _ = selected_air_fixture()
    geometry = derive_selected_proof_geometry(program)
    return geometry, build_selected_theorem_round_schedule(geometry)


def test_selected_schedule_binds_air_parameters_and_every_fri_round() -> None:
    geometry, schedule = _schedule()

    assert schedule.selected is True
    assert schedule.final_expansion_substituted is True
    assert schedule.activation_allowed is False
    assert schedule.parameter_commitment == SELECTED_PARAMETER_COMMITMENT
    assert schedule.program_binary_commitment == geometry.program_binary_commitment
    assert schedule.query_count == 945
    assert schedule.query_with_replacement is True
    assert schedule.maximum_attempts_per_query == 1
    assert schedule.fold_round_count == geometry.fold_round_count == 15
    assert schedule.final_line_domain_size == 2
    assert len(schedule.descriptors) == 20
    assert sum(
        item.kind is RoundKind.FRI_FOLD_COEFFICIENT
        for item in schedule.descriptors
    ) == 15
    assert schedule.proof_suite_id == proof_suite_id(
        geometry.program_binary_commitment, schedule.schedule_commitment
    )


def test_selected_schedule_rejects_parameter_program_and_order_tampering() -> None:
    _, schedule = _schedule()
    with pytest.raises(ValueError, match="parameter_commitment_mismatch"):
        replace(schedule, parameter_commitment=bytes([9]) * 64)
    with pytest.raises(ValueError, match="proof_suite_id_mismatch"):
        replace(schedule, proof_suite_id=bytes([8]) * 64)
    with pytest.raises(ValueError, match="order_invalid"):
        replace(
            schedule,
            descriptors=(
                schedule.descriptors[1],
                schedule.descriptors[0],
                *schedule.descriptors[2:],
            ),
        )
    with pytest.raises(ValueError, match="geometry_invalid"):
        replace(schedule, query_count=944)
