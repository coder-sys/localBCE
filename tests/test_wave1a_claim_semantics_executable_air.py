from __future__ import annotations

from dataclasses import replace

from experiments.fixed_shape_claim_air.claim_semantics_executable_air import (
    build_claim_semantics_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import evaluate_program, evaluate_serialized
from tests.test_wave1a_claim_result_executable_air import _approved, _cover, _denied


def test_composed_claim_semantics_air_links_gate_derivation_to_first_failure() -> None:
    instance = build_claim_semantics_executable_air((_approved(), _denied(), _cover()))
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2


def test_claim_semantics_program_is_independent_of_private_witness_class_and_line_count() -> None:
    commitments = tuple(
        build_claim_semantics_executable_air((replace(slot, slot_index=0),)).program.commitment()
        for slot in (_approved(), _denied(), _cover())
    )
    assert len(set(commitments)) == 1
