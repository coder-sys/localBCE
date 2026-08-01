from __future__ import annotations

from dataclasses import replace

from experiments.fixed_shape_claim_air.executable_air import evaluate_program, evaluate_serialized
from experiments.fixed_shape_claim_air.fee_arithmetic_executable_air import (
    build_fee_arithmetic_executable_air,
)
from tests.test_wave1a_claim_result_executable_air import _approved, _cover, _denied, _line


def test_fee_air_constrains_minimum_sum_totals_and_result() -> None:
    split = replace(
        _approved(),
        service_lines=(
            replace(_line(), line_id="LINE-A", charge_cents=100, allowed_cents=70),
            replace(_line(), original_line_index=1, line_id="LINE-B", charge_cents=200, allowed_cents=250),
        ),
        total_charge_cents=300,
        patient_responsibility_cents=20,
        claimed_allowed_cents=270,
        claimed_payment_cents=250,
    )
    instance = build_fee_arithmetic_executable_air((split, _denied(), _cover()))
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2
    slot = instance.traces["claim_fee_slot"].columns
    assert slot["computed_total_limb_0"] == (300, 100, 0)
    assert slot["candidate_limb_0"] == (270, 100, 0)
    assert slot["result_allowed_limb_0"] == (270, 0, 0)
