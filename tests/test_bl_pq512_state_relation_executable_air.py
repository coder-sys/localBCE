from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.state_plane import (
    StateEntry,
    StateOperation,
    StateSnapshot,
    build_state_transition,
)
from experiments.fixed_shape_claim_air.air_binary_ir import (
    air_binary_commitment,
    air_program_commitment,
    encode_air_execution,
    encode_air_program,
)
from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.state_relation_executable_air import (
    PACKED_CHUNK_COUNT,
    PACKED_CHUNK_BYTES,
    PROGRAM_ID,
    build_state_relation_air,
)


def _proof():
    before = StateSnapshot.empty("K128_CALIBRATION", capacity=8, epoch=7)
    operations = tuple(
        StateOperation(
            index,
            StateEntry.empty(index),
            StateEntry(index, True, b"K" * 64, b"V" * 64)
            if index == 0
            else StateEntry.empty(index),
        )
        for index in range(before.capacity)
    )
    return build_state_transition(
        before,
        operations,
        tuple(
            sha3_512(b"state-relation-projection" + bytes((index,))).digest()[:32]
            for index in range(12)
        ),
        sha3_512(b"state-relation-coin").digest(),
        sha3_512(b"state-relation-mask").digest(),
    )


def test_compact_state_relation_is_canonical_and_cross_language_encodable() -> None:
    instance = build_state_relation_air(_proof())
    assert instance.program.program_id == PROGRAM_ID
    assert len(instance.program.tables) == 4
    relation, before, after, roots = instance.program.tables
    assert len(relation.columns) == 1 + 2 * (1 + 2 * PACKED_CHUNK_COUNT)
    assert len(before.columns) == 1 + 1 + 2 * PACKED_CHUNK_COUNT
    assert len(after.columns) == 1 + 1 + 2 * PACKED_CHUNK_COUNT
    assert len(roots.columns) == 1 + 64
    assert relation.rows == 8
    assert before.rows == 8
    assert after.rows == 8
    assert roots.rows == 2
    assert "before_key_21" in relation.columns
    assert "before_key_63" not in relation.columns
    assert before.columns == tuple(
        ["index", "present"]
        + [
            f"{field}_{chunk}"
            for field in ("key", "value")
            for chunk in range(PACKED_CHUNK_COUNT)
        ]
    )
    report = evaluate_program(instance.program, instance.traces, instance.public_values)
    assert report.maximum_degree == 2
    assert report.lookup_messages_evaluated == 2 * (8 + 8 + 2)
    program = encode_air_program(instance.program)
    execution = encode_air_execution(
        instance.program, instance.traces, instance.public_values
    )
    assert air_program_commitment(program)
    assert air_binary_commitment(execution)
    assert len(instance.traces["state_relation"].columns["before_key_0"]) == 8
    assert instance.traces["state_relation"].columns["after_key_0"][0] == int.from_bytes(
        b"KKK", "big"
    )
    assert instance.traces["state_before_snapshot"].columns["present"][0] == 0
    assert instance.traces["state_after_snapshot"].columns["present"][0] == 1
    assert PACKED_CHUNK_BYTES == 3


def test_compact_state_relation_rejects_nonzero_empty_chunk() -> None:
    instance = build_state_relation_air(_proof())
    columns = {
        name: list(values)
        for name, values in instance.traces["state_relation"].columns.items()
    }
    columns["before_key_0"][1] = 1
    bad_trace = TraceTable(
        "state_relation", {name: tuple(values) for name, values in columns.items()}
    )
    traces = dict(instance.traces)
    traces["state_relation"] = bad_trace
    with pytest.raises(StructuralError, match="identity"):
        evaluate_program(
            instance.program,
            traces,
            instance.public_values,
        )


def test_compact_state_relation_rejects_snapshot_lookup_mismatch() -> None:
    instance = build_state_relation_air(_proof())
    columns = {
        name: list(values)
        for name, values in instance.traces["state_before_snapshot"].columns.items()
    }
    columns["present"][0] = 1
    bad_trace = TraceTable(
        "state_before_snapshot",
        {name: tuple(values) for name, values in columns.items()},
    )
    traces = dict(instance.traces)
    traces["state_before_snapshot"] = bad_trace
    with pytest.raises(StructuralError, match="lookup_multiset_mismatch"):
        evaluate_program(instance.program, traces, instance.public_values)


def test_compact_state_relation_rejects_snapshot_index_reordering() -> None:
    instance = build_state_relation_air(_proof())
    columns = {
        name: list(values)
        for name, values in instance.traces["state_after_snapshot"].columns.items()
    }
    columns["index"][0] = 1
    bad_trace = TraceTable(
        "state_after_snapshot",
        {name: tuple(values) for name, values in columns.items()},
    )
    traces = dict(instance.traces)
    traces["state_after_snapshot"] = bad_trace
    with pytest.raises(StructuralError, match="fixed_column_mismatch"):
        evaluate_program(instance.program, traces, instance.public_values)
