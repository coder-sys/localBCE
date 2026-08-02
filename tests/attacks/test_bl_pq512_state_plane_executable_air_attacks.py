from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program
from experiments.fixed_shape_claim_air.state_plane_executable_air import (
    build_state_plane_air,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_bl_pq512_state_plane import _proof


def test_mutated_old_slot_fails_the_air_relation() -> None:
    instance = build_state_plane_air(_proof())
    columns = dict(instance.traces["state_slots"].columns)
    columns["before_key_0"] = (columns["before_key_0"][0] ^ 1, *columns["before_key_0"][1:])
    traces = dict(instance.traces)
    traces["state_slots"] = TraceTable("state_slots", columns)
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch|air_identity_failed"):
        evaluate_program(instance.program, traces, instance.public_values)


def test_mutated_public_root_fails_the_ordered_public_binding() -> None:
    instance = build_state_plane_air(_proof())
    with pytest.raises(StructuralError, match="air_public_input_mismatch"):
        evaluate_program(
            instance.program,
            instance.traces,
            (instance.public_values[0] ^ 1, *instance.public_values[1:]),
        )
