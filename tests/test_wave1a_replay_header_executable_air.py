from __future__ import annotations

from hashlib import sha3_512
import os
from unittest import mock

from experiments.fixed_shape_claim_air.authenticated_replay_state_reference import (
    build_authenticated_replay_transitions,
)
from experiments.fixed_shape_claim_air.executable_air import (
    evaluate_program,
    evaluate_serialized,
)
from experiments.fixed_shape_claim_air.replay_header_executable_air import (
    build_replay_header_executable_air,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _instance(label: bytes):
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        transitions = build_authenticated_replay_transitions(
            (), (sha3_512(label).digest(),)
        )
        return build_replay_header_executable_air(transitions)


def test_replay_header_air_hashes_cursor_and_inner_root_exactly() -> None:
    instance = _instance(b"BL-REPLAY-HEADER-AIR-KAT")
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2
    assert len(instance.program.tables) == 8


def test_replay_header_program_does_not_commit_private_roots() -> None:
    left = _instance(b"BL-REPLAY-HEADER-PRIVATE-A")
    right = _instance(b"BL-REPLAY-HEADER-PRIVATE-B")
    assert left.program.commitment() == right.program.commitment()
    assert left.traces["replay_header"].columns != right.traces["replay_header"].columns
