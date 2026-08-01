from __future__ import annotations

from collections.abc import Mapping

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    M31,
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_wave1a_ordered_map_batch_executable_air import (
    ordered_map_air_instance,
)


def _mutate(
    table: str,
    row: int,
    replacements: Mapping[str, int],
) -> dict[str, TraceTable]:
    instance = ordered_map_air_instance()
    traces = dict(instance.traces)
    columns = {
        name: list(values) for name, values in traces[table].columns.items()
    }
    for column, value in replacements.items():
        columns[column][row] = value
    traces[table] = TraceTable(table, freeze_columns(columns))
    return traces


def _aliased_bytes(value: int) -> dict[str, int]:
    forged = value + M31
    assert forged <= 0xFFFF_FFFF
    return {
        f"sort_gap_byte_{index}": byte
        for index, byte in enumerate(forged.to_bytes(4, "big"))
    }


def test_m31_alias_cannot_counterfeit_proof_sort_order() -> None:
    instance = ordered_map_air_instance()
    row = 0
    value = instance.traces["ordered_map_proof"].columns["sort_gap"][row]

    with pytest.raises(StructuralError, match="air_identity_failed:ordered_map_proof"):
        evaluate_program(
            instance.program,
            _mutate("ordered_map_proof", row, _aliased_bytes(value)),
        )


def test_m31_alias_cannot_counterfeit_u24_memory_position() -> None:
    instance = ordered_map_air_instance()
    row = 0
    value = instance.traces["ordered_map_memory"].columns["position"][row]
    forged = value + M31
    replacements = {
        f"position_byte_{index}": byte
        for index, byte in enumerate(forged.to_bytes(4, "big"))
    }

    with pytest.raises(
        StructuralError,
        match="air_identity_failed:ordered_map_memory:position_u24",
    ):
        evaluate_program(
            instance.program,
            _mutate("ordered_map_memory", row, replacements),
        )


def test_m31_alias_cannot_change_hashed_u64_next_index_encoding() -> None:
    instance = ordered_map_air_instance()
    trace = instance.traces["ordered_map_operation"].columns
    value = trace["target_before_next_index"][0]
    forged = (value + M31).to_bytes(8, "big")
    replacements = {
        f"target_before_next_index_u64_{index}": byte
        for index, byte in enumerate(forged)
    }

    with pytest.raises(
        StructuralError,
        match=(
            "air_identity_failed:ordered_map_operation:"
            "target_before_next_index_u64_byte_"
        ),
    ):
        evaluate_program(
            instance.program,
            _mutate("ordered_map_operation", 0, replacements),
        )


def test_zero_sentinel_operation_key_cannot_be_admitted() -> None:
    instance = ordered_map_air_instance()
    replacements = {
        **{f"key_nonzero_{index}": 0 for index in range(64)},
        "key_nonzero_sum": 0,
        "key_nonzero_sum_inverse": 0,
    }

    with pytest.raises(
        StructuralError,
        match="air_identity_failed:ordered_map_operation:key_not_zero",
    ):
        evaluate_program(
            instance.program,
            _mutate("ordered_map_operation", 0, replacements),
        )


def test_max_sentinel_operation_key_cannot_be_admitted() -> None:
    instance = ordered_map_air_instance()
    replacements = {
        **{f"key_not_max_{index}": 0 for index in range(64)},
        "key_not_max_sum": 0,
        "key_not_max_sum_inverse": 0,
    }

    with pytest.raises(
        StructuralError,
        match="air_identity_failed:ordered_map_operation:key_not_max",
    ):
        evaluate_program(
            instance.program,
            _mutate("ordered_map_operation", 0, replacements),
        )


def test_height_64_cannot_be_smuggled_into_the_topology() -> None:
    instance = ordered_map_air_instance()
    trace = instance.traces["ordered_map_proof"].columns
    forged_sort_key = trace["sort_key"][0] + (64 << 24)

    with pytest.raises(
        StructuralError,
        match="air_identity_failed:ordered_map_proof:height_u6",
    ):
        evaluate_program(
            instance.program,
            _mutate(
                "ordered_map_proof",
                0,
                {
                    "height": 64,
                    "sort_key": forged_sort_key,
                    **{f"height_bit_{index}": 0 for index in range(6)},
                },
            ),
        )


def test_state_cursor_cannot_detach_from_operation_chain() -> None:
    instance = ordered_map_air_instance()
    original = instance.traces["ordered_map_state"].columns["cursor_before"][0]

    with pytest.raises(StructuralError, match="air_identity_failed:ordered_map_state"):
        evaluate_program(
            instance.program,
            _mutate("ordered_map_state", 0, {"cursor_before": original + 1}),
        )


def test_unused_memory_inverse_cannot_carry_malleable_witness_data() -> None:
    instance = ordered_map_air_instance()
    trace = instance.traces["ordered_map_memory"].columns
    row = next(index for index, same in enumerate(trace["same_next"]) if same)

    with pytest.raises(
        StructuralError,
        match=(
            "air_identity_failed:ordered_map_memory:"
            "memory_same_position_inverse_zero"
        ),
    ):
        evaluate_program(
            instance.program,
            _mutate(
                "ordered_map_memory",
                row,
                {"position_delta_inverse": 1},
            ),
        )


def test_live_leaf_digest_cannot_detach_from_hash_port() -> None:
    instance = ordered_map_air_instance()
    trace = instance.traces["ordered_map_hash_port"].columns
    row = next(
        index
        for index in range(instance.schedule.leaf_hash_rows)
        if trace["live"][index]
    )
    replacement = (trace["digest_0"][row] + 1) % 256

    with pytest.raises(
        StructuralError,
        match="air_lookup_multiset_mismatch:ordered_map_leaf_hash_ports",
    ):
        evaluate_program(
            instance.program,
            _mutate("ordered_map_hash_port", row, {"digest_0": replacement}),
        )


def test_fixed_hash_family_schedule_cannot_be_relabelled() -> None:
    instance = ordered_map_air_instance()

    with pytest.raises(
        StructuralError,
        match="air_fixed_column_mismatch:ordered_map_hash_port:family_leaf",
    ):
        evaluate_program(
            instance.program,
            _mutate("ordered_map_hash_port", 0, {"family_leaf": 0}),
        )
