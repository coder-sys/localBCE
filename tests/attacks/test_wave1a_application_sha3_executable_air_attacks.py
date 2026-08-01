from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.application_sha3_executable_air import (
    Sha3Call,
    build_application_sha3_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program, freeze_columns
from experiments.fixed_shape_claim_air.semantics import StructuralError


def test_one_call_message_cannot_be_rebound_to_another_call() -> None:
    instance = build_application_sha3_executable_air(
        (Sha3Call("left", b"lefts", 71), Sha3Call("right", b"right", 71))
    )
    traces = dict(instance.traces)
    message = traces["sha3_message_batch"]
    columns = {name: list(values) for name, values in message.columns.items()}
    left = instance.call_rows["left"]
    right = instance.call_rows["right"]
    left_values = columns["value"][left.message_start:left.message_stop]
    right_values = columns["value"][right.message_start:right.message_stop]
    columns["value"][left.message_start:left.message_stop] = right_values
    columns["value"][right.message_start:right.message_stop] = left_values
    traces["sha3_message_batch"] = TraceTable(
        "sha3_message_batch", freeze_columns(columns)
    )
    with pytest.raises(StructuralError, match="air_identity_failed:sha3_message_batch:padded_byte"):
        evaluate_program(instance.program, traces)


def test_duplicate_sha3_call_identifier_is_rejected() -> None:
    with pytest.raises(StructuralError, match="application_sha3_call_id_duplicate"):
        build_application_sha3_executable_air(
            (Sha3Call("same", b"a", 71), Sha3Call("same", b"b", 71))
        )
