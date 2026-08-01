from __future__ import annotations

from functools import lru_cache
from hashlib import sha3_512
import os
from types import MappingProxyType
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.replay_ordered_map_executable_air import (
    REPLAY_PRESENT_MARKER,
    build_replay_ordered_map_executable_air,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


@lru_cache(maxsize=1)
def _instance():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        return build_replay_ordered_map_executable_air(
            (sha3_512(b"old").digest(),),
            tuple(sha3_512(value).digest() for value in (b"a", b"b", b"c")),
        )


@lru_cache(maxsize=1)
def _hashed_instance():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        return build_replay_ordered_map_executable_air(
            (),
            (sha3_512(b"hashed-replay-insert").digest(),),
            compose_sha3=True,
        )


def _mutate(instance, table: str, column: str, row: int, value: int):
    trace = instance.traces[table]
    columns = {name: list(values) for name, values in trace.columns.items()}
    columns[column][row] = value
    traces = dict(instance.traces)
    traces[table] = TraceTable(
        table, freeze_columns({name: tuple(values) for name, values in columns.items()})
    )
    return MappingProxyType(traces)


def test_replay_registry_reuses_full_ordered_map_paths_and_is_insert_only() -> None:
    instance = _instance()
    report = evaluate_program(instance.program, instance.traces)
    assert report.identities_evaluated == 278_982
    assert report.lookup_messages_evaluated == 396_690
    assert report.maximum_degree == 3
    assert report.program_commitment.hex() == (
        "b1c9cf24ba03eb6e31566605d5668cb1dcb295c47e990a2ca7f7420607fa1196"
        "77d1542fb8dbc6be0bc9837a1a88ef726ff47aeafb9bdbcdeec1d83420636786"
    )
    operation = instance.traces["replay_map__ordered_map_operation"].columns
    assert operation["is_insert"] == (1, 1, 1)
    assert all(
        bytes(operation[f"value_after_{byte}"][row] for byte in range(64))
        == REPLAY_PRESENT_MARKER
        for row in range(3)
    )
    assert instance.replay_paths_constrained is True
    assert instance.replay_insert_only_constrained is True
    assert instance.hashes_constrained is False


def test_duplicate_replay_and_insert_selector_mutation_fail() -> None:
    value = sha3_512(b"duplicate").digest()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        with pytest.raises(StructuralError, match="duplicate_nullifier"):
            build_replay_ordered_map_executable_air((), (value, value))
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed"):
        evaluate_program(
            instance.program,
            _mutate(
                instance,
                "replay_map__ordered_map_operation",
                "is_insert",
                0,
                0,
            ),
        )


def test_replay_hash_ports_are_exactly_sha3_composed() -> None:
    instance = _hashed_instance()
    report = evaluate_program(instance.program, instance.traces)
    assert instance.hashes_constrained is True
    assert instance.application_sha3 is not None
    assert instance.traces["sha3_digest_batch"].rows == 180
    assert report.maximum_degree == 3
