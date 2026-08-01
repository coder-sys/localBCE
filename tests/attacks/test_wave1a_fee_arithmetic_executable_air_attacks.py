from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program, freeze_columns
from experiments.fixed_shape_claim_air.fee_arithmetic_executable_air import (
    build_fee_arithmetic_executable_air,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_wave1a_claim_result_executable_air import _approved, _cover, _denied


@pytest.fixture(scope="module")
def instance():
    return build_fee_arithmetic_executable_air((_approved(), _denied(), _cover()))


def _mutate(instance, table: str, column: str, row: int, value: int):
    traces = dict(instance.traces)
    columns = {name: list(values) for name, values in traces[table].columns.items()}
    columns[column][row] = value
    traces[table] = TraceTable(table, freeze_columns(columns))
    return traces


def test_policy_allowed_cannot_inflate_minimum(instance) -> None:
    traces = _mutate(instance, "claim_fee", "minimum_byte_0", 0, 101)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_fee:minimum_byte_0:0"):
        evaluate_program(instance.program, traces)


def test_candidate_accumulator_cannot_skip_value(instance) -> None:
    traces = _mutate(instance, "claim_fee", "candidate_after_limb_0", 0, 0)
    columns = {name: list(values) for name, values in traces["claim_fee"].columns.items()}
    columns["candidate_after_limb_0_byte_0"][0] = 0
    traces["claim_fee"] = TraceTable("claim_fee", freeze_columns(columns))
    with pytest.raises(StructuralError, match="air_identity_failed:claim_fee:candidate_addition_low:0"):
        evaluate_program(instance.program, traces)


def test_declared_total_cannot_disagree_with_accumulator(instance) -> None:
    traces = _mutate(instance, "claim_fee_slot", "computed_total_limb_0", 0, 99)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_fee_slot:declared_matches_computed_0:0"):
        evaluate_program(instance.program, traces)
