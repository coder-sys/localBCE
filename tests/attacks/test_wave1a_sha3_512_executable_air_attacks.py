from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program, freeze_columns
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.sha3_512_executable_air import (
    build_sha3_512_executable_air,
)


@pytest.fixture(scope="module")
def instance():
    return build_sha3_512_executable_air(b"abc")


def _mutate(instance, table: str, column: str, row: int, value: int):
    traces = dict(instance.traces)
    columns = {name: list(values) for name, values in traces[table].columns.items()}
    columns[column][row] = value
    traces[table] = TraceTable(table, freeze_columns(columns))
    return traces


def test_mutated_theta_byte_is_rejected_by_fixed_truth_lookup(instance) -> None:
    observed = instance.traces["sha3_round"].columns["theta_parity_0"][0]
    traces = _mutate(instance, "sha3_round", "theta_parity_0", 0, observed ^ 1)
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch:sha3_fixed_truth"):
        evaluate_program(instance.program, traces)


def test_mutated_sha3_padding_is_rejected_by_identity(instance) -> None:
    traces = _mutate(instance, "sha3_round", "block_3", 0, 0x07)
    with pytest.raises(StructuralError, match="air_identity_failed:sha3_round:padding_3:0"):
        evaluate_program(instance.program, traces)


def test_message_substitution_is_rejected_by_message_binding(instance) -> None:
    traces = _mutate(instance, "sha3_message", "value", 0, ord("z"))
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch:sha3_message_binding"):
        evaluate_program(instance.program, traces)


def test_truth_table_substitution_is_rejected_as_fixed_column(instance) -> None:
    traces = _mutate(instance, "sha3_truth", "output", 0, 1)
    with pytest.raises(StructuralError, match="air_fixed_column_mismatch:sha3_truth:output"):
        evaluate_program(instance.program, traces)


def test_fixed_capacity_padding_position_cannot_move() -> None:
    fixed = build_sha3_512_executable_air(b"abc", capacity=143)
    traces = dict(fixed.traces)
    columns = {
        name: list(values) for name, values in traces["sha3_message"].columns.items()
    }
    columns["pad_start"][3] = 0
    columns["pad_start"][4] = 1
    columns["padded"][3] = 0
    columns["padded"][4] = 6
    traces["sha3_message"] = TraceTable("sha3_message", freeze_columns(columns))
    with pytest.raises(
        StructuralError, match="air_identity_failed:sha3_message:pad_start_transition"
    ):
        evaluate_program(fixed.program, traces)
