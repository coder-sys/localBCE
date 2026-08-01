from __future__ import annotations

from dataclasses import replace
import os

import pytest

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.wave1b_executable_registry import (
    EXECUTABLE_REGISTRY_STATUS,
    Wave1BExecutableRegistry,
    build_executable_air_segment,
)
from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_air_program,
)
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.wave1a_global_sha3_schedule import (
    build_wave1a_global_sha3_schedule,
)
from tests.test_wave1a_executable_air import _fixture


def test_registry_is_derived_from_executable_program_trace_and_binary_ir() -> None:
    program, traces = _fixture()
    segment = build_executable_air_segment("kernel", program, traces)
    schedule = build_wave1a_global_sha3_schedule(PROFILES["K128_CALIBRATION"])
    registry = Wave1BExecutableRegistry(
        profile_id="K128_CALIBRATION",
        global_sha3_schedule_commitment_512=schedule.commitment_512,
        segments=(segment,),
    )

    assert registry.status == EXECUTABLE_REGISTRY_STATUS
    assert not registry.complete_segment_set
    assert not registry.pcs_expansion_substituted
    assert registry.proof_suite_id is None
    assert not registry.activation_allowed
    assert len(registry.commitment_sha3_512) == 64
    assert segment.identities_evaluated == 13
    assert segment.lookup_messages_evaluated == 4
    assert segment.maximum_degree == 2
    assert segment.binary_ir_length > 0
    assert [table.qualified_name for table in segment.tables] == [
        "kernel/source",
        "kernel/destination",
    ]
    source, destination = segment.tables
    assert (
        source.logical_rows,
        source.padded_rows,
        source.trace_columns,
        source.identity_count,
        source.maximum_identity_degree,
    ) == (4, 4, 3, 4, 2)
    assert source.lookup_argument_count == 1
    assert source.lookup_side_count == 1
    assert source.lookup_coordinate_width_sum == 1
    assert source.lookup_row_capacity == 4
    assert destination.trace_columns == 2


def test_historical_r33_inventory_is_rejected_as_active_registry_input() -> None:
    historical = build_wave1a_physical_air_program(PROFILES["K128_CALIBRATION"])
    with pytest.raises(TypeError, match="air_program_required"):
        build_executable_air_segment("historical", historical, {})


def test_registry_refuses_unknown_public_table_and_premature_selection() -> None:
    program, traces = _fixture()
    with pytest.raises(StructuralError, match="public_table_unknown"):
        build_executable_air_segment(
            "kernel",
            program,
            traces,
            public_table_names=frozenset({"absent"}),
        )
    segment = build_executable_air_segment("kernel", program, traces)
    schedule = build_wave1a_global_sha3_schedule(PROFILES["K128_CALIBRATION"])
    registry = Wave1BExecutableRegistry(
        "K128_CALIBRATION", schedule.commitment_512, (segment,)
    )
    with pytest.raises(ValueError, match="registry_invalid"):
        replace(registry, pcs_expansion_substituted=True)
    with pytest.raises(ValueError, match="registry_invalid"):
        replace(registry, activation_allowed=True)
