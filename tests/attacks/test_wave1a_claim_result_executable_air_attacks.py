from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.claim_result_executable_air import (
    build_claim_result_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program, freeze_columns
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_wave1a_claim_result_executable_air import _approved, _cover, _denied


@pytest.fixture(scope="module")
def instance():
    return build_claim_result_executable_air((_approved(), _denied(), _cover()))


def _mutate(instance, column: str, row: int, value: int):
    columns = {name: list(values) for name, values in instance.traces["claim_result"].columns.items()}
    columns[column][row] = value
    return {"claim_result": TraceTable("claim_result", freeze_columns(columns))}


def test_first_failure_cannot_be_moved_to_a_later_gate(instance) -> None:
    traces = _mutate(instance, "failure_code", 1, 2)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_result:failure_code:1"):
        evaluate_program(instance.program, traces)


def test_cover_cannot_be_turned_into_approval(instance) -> None:
    traces = _mutate(instance, "decision", 2, 1)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_result:decision_from_prefix:2"):
        evaluate_program(instance.program, traces)


def test_payment_cannot_exceed_allowed_minus_responsibility(instance) -> None:
    traces = _mutate(instance, "payment_limb_0", 0, 81)
    with pytest.raises(StructuralError, match="air_identity_failed:claim_result:claimed_payment:0"):
        evaluate_program(instance.program, traces)
