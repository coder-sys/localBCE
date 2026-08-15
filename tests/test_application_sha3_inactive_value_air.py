from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.application_sha3_executable_air import (
    Sha3Call,
    build_application_sha3_interface_air,
    build_application_sha3_interface_program,
)
from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program
from experiments.fixed_shape_claim_air.semantics import StructuralError


def test_application_sha3_inactive_message_value_is_constrained_to_zero() -> None:
    instance = build_application_sha3_interface_air(
        (Sha3Call("inactive_value_test", b"a", 72),)
    )
    program_only = build_application_sha3_interface_program((72,))
    assert instance.program.canonical_bytes() == program_only.canonical_bytes()
    evaluate_program(instance.program, instance.traces)

    mutated = dict(instance.traces)
    message = instance.traces["sha3_message_batch"]
    columns = dict(message.columns)
    values = list(columns["value"])
    assert columns["live"][1] == 0
    values[1] = 1
    columns["value"] = tuple(values)
    mutated[message.name] = TraceTable(message.name, columns)

    with pytest.raises(
        StructuralError,
        match="air_identity_failed:sha3_message_batch:inactive_value_zero:1",
    ):
        evaluate_program(instance.program, mutated)
