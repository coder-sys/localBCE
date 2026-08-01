from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.claim_semantics_executable_air import (
    build_claim_semantics_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program, freeze_columns
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_wave1a_claim_result_executable_air import _approved, _cover, _denied


def test_gate_and_result_tables_cannot_disagree() -> None:
    instance = build_claim_semantics_executable_air((_approved(), _denied(), _cover()))
    traces = dict(instance.traces)
    columns = {name: list(values) for name, values in traces["claim_result"].columns.items()}
    # Keep the result table internally satisfiable for this isolated mutation by
    # swapping two raw rows; the cross-table multiset link must still reject it.
    for name in columns:
        if name != "slot_index":
            columns[name][0], columns[name][1] = columns[name][1], columns[name][0]
    traces["claim_result"] = TraceTable("claim_result", freeze_columns(columns))
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch:claim_gate_result_link"):
        evaluate_program(instance.program, traces)


def test_fee_and_result_tables_cannot_disagree() -> None:
    instance = build_claim_semantics_executable_air((_approved(), _denied(), _cover()))
    traces = dict(instance.traces)
    columns = {name: list(values) for name, values in traces["claim_fee_slot"].columns.items()}
    for name in ("decision", "result_allowed_limb_0", "result_allowed_limb_1"):
        columns[name][0], columns[name][1] = columns[name][1], columns[name][0]
    traces["claim_fee_slot"] = TraceTable("claim_fee_slot", freeze_columns(columns))
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch:claim_fee_result_link"):
        evaluate_program(instance.program, traces)
