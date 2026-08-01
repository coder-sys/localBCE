from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.claim_gate_executable_air import (
    build_claim_gate_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program, freeze_columns
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_wave1a_claim_result_executable_air import _approved, _cover, _denied


@pytest.fixture(scope="module")
def instance():
    return build_claim_gate_executable_air((_approved(), _denied(), _cover()))


def _mutate(instance, table: str, column: str, row: int, value: int):
    traces = dict(instance.traces)
    columns = {name: list(values) for name, values in traces[table].columns.items()}
    columns[column][row] = value
    traces[table] = TraceTable(table, freeze_columns(columns))
    return traces


def test_missing_member_cannot_pass_gate_one(instance) -> None:
    traces = _mutate(instance, "claim_gate", "raw_gate_0", 1, 1)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_gate:raw_gate_derivation_0:1"):
        evaluate_program(instance.program, traces)


def test_authorization_prefix_cannot_skip_a_line(instance) -> None:
    traces = _mutate(instance, "claim_service", "auth_after", 0, 0)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_service:auth_after:0"):
        evaluate_program(instance.program, traces)


def test_authorization_use_count_cannot_skip_a_line(instance) -> None:
    original = instance.traces["claim_service"].columns["authorization_count_after"][0]
    traces = _mutate(
        instance,
        "claim_service",
        "authorization_count_after",
        0,
        original + 1,
    )
    with pytest.raises(
        StructuralError,
        match="air_identity_failed:claim_service:authorization_count_step:0",
    ):
        evaluate_program(instance.program, traces)


def test_zero_charge_cannot_claim_nonzero(instance) -> None:
    traces = _mutate(instance, "claim_service", "charge_nonzero_0", 100, 1)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_service:charge_zero_step_0:100"):
        evaluate_program(instance.program, traces)


def test_length_presence_cannot_be_forged(instance) -> None:
    traces = _mutate(instance, "claim_gate", "member_present", 1, 1)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_gate:raw_gate_derivation_0:1"):
        evaluate_program(instance.program, traces)
