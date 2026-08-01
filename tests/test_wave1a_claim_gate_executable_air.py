from __future__ import annotations

from experiments.fixed_shape_claim_air.claim_gate_executable_air import (
    build_claim_gate_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import evaluate_program, evaluate_serialized
from tests.test_wave1a_claim_result_executable_air import _approved, _cover, _denied


def test_all_thirteen_claim_gates_are_derived_from_bounded_inputs() -> None:
    instance = build_claim_gate_executable_air((_approved(), _denied(), _cover()))
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2
    gate = instance.traces["claim_gate"].columns
    assert gate["raw_gate_0"] == (1, 0, 0)
    assert gate["raw_gate_8"] == (1, 1, 1)
    assert gate["raw_gate_9"] == (1, 1, 0)

