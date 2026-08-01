from __future__ import annotations

from hashlib import sha3_512
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.authenticated_replay_state_reference import (
    build_authenticated_replay_transitions,
)
from experiments.fixed_shape_claim_air.executable_air import (
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.replay_header_executable_air import (
    build_replay_header_executable_air,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _instance():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        transitions = build_authenticated_replay_transitions(
            (), (sha3_512(b"BL-REPLAY-HEADER-AIR-ATTACK").digest(),)
        )
        return build_replay_header_executable_air(transitions)


@pytest.mark.parametrize("column", ("cursor_after_7", "inserted_index_7", "root_after_0"))
def test_cursor_insertion_or_root_mutation_is_rejected(column: str) -> None:
    instance = _instance()
    traces = dict(instance.traces)
    header = traces["replay_header"]
    columns = {name: list(values) for name, values in header.columns.items()}
    columns[column][0] = (columns[column][0] + 1) % 256
    traces["replay_header"] = TraceTable("replay_header", freeze_columns(columns))
    with pytest.raises(StructuralError, match="air_(identity_failed|lookup_multiset_mismatch)"):
        evaluate_program(instance.program, traces)
