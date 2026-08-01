from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.authenticated_replay_state_reference import (
    build_authenticated_replay_transitions,
    require_authenticated_replay_transition,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _transition():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        return build_authenticated_replay_transitions(
            (), (sha3_512(b"BL-REPLAY-ORDERED-MAP-KAT").digest(),)
        )[0]


def test_cursor_is_authenticated_and_consumed_exactly() -> None:
    transition = _transition()
    assert transition.next_append_index_before == 2
    assert transition.next_append_index_after == 3
    assert transition.inner.inserted_index == 2
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        require_authenticated_replay_transition(transition)


@pytest.mark.parametrize("field", ("next_append_index_after", "root_before", "root_after"))
def test_cursor_or_header_root_mutation_is_rejected(field: str) -> None:
    transition = _transition()
    value = getattr(transition, field)
    mutated = value + 1 if type(value) is int else sha3_512(value).digest()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        with pytest.raises(ValueError, match="replay_state"):
            replace(transition, **{field: mutated})
