from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.fixed_shape_claim_air.air_binary_ir import encode_air_program
from experiments.fixed_shape_claim_air.executable_air import (
    TraceTable,
    evaluate_program,
    evaluate_serialized,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.sha3_512_boolean_executable_air import (
    MAXIMUM_DEGREE,
    PARITY_BITS,
    ROWS_PER_PERMUTATION,
    STATE_BITS,
    Sha3BooleanCall,
    build_sha3_boolean_executable_air,
    build_sha3_boolean_permutation_air,
    build_sha3_boolean_permutation_program,
)


ZERO_PERMUTATION_SHA3_512 = (
    "969772f6836db4fc32df06647b6234adaa797c303b5accbc2ca0ceb6e3664be1"
    "722696a8dc172cef021b291cb86565c6b8b6399c08fb4c98218c7e5a337e21bf"
)


@pytest.fixture(scope="module")
def zero_permutation():
    return build_sha3_boolean_permutation_air((bytes(200),))


def test_direct_boolean_permutation_is_exact_low_degree_and_lookup_free(
    zero_permutation,
) -> None:
    instance = zero_permutation
    table = instance.program.tables[0]
    report = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)

    assert table.rows == ROWS_PER_PERMUTATION
    assert len(table.columns) == STATE_BITS + PARITY_BITS + 75
    assert len(table.identities) == 3_527
    assert instance.program.lookups == ()
    assert instance.program.maximum_degree == MAXIMUM_DEGREE == 11
    assert report.identities_evaluated == 86_573
    assert report.lookup_messages_evaluated == 0
    assert serialized == report
    assert sha3_512(instance.outputs[0]).hexdigest() == ZERO_PERMUTATION_SHA3_512


def test_direct_boolean_transition_mutation_is_rejected(zero_permutation) -> None:
    instance = zero_permutation
    trace = instance.traces["sha3_boolean_round"]
    columns = {name: list(values) for name, values in trace.columns.items()}
    columns["state_0"][1] ^= 1
    bad = {
        trace.name: TraceTable(trace.name, freeze_columns(columns)),
    }
    with pytest.raises(StructuralError, match="theta_parity_0"):
        evaluate_program(instance.program, bad)


def test_k128_minimum_permutation_program_is_compact_and_buildable() -> None:
    program = build_sha3_boolean_permutation_program(46_858)
    encoded = encode_air_program(program)
    table = program.tables[0]

    assert table.rows == 1_171_450
    assert len(program.canonical_bytes()) == 6_004_172
    assert len(encoded) == 1_981_854
    assert int.from_bytes(encoded[8:10], "big") == 2


@pytest.fixture(scope="module")
def sponge_instance():
    return build_sha3_boolean_executable_air(
        (
            Sha3BooleanCall("empty", b"", 0),
            Sha3BooleanCall("two_block", b"A" * 72, 72),
        )
    )


def test_boolean_sponge_binds_padding_chaining_and_digest(sponge_instance) -> None:
    instance = sponge_instance
    report = evaluate_program(instance.program, instance.traces)

    assert instance.block_counts == (1, 2)
    assert tuple(table.rows for table in instance.program.tables) == (75, 3, 2)
    assert len(instance.program.lookups) == 3
    assert report.lookup_messages_evaluated == 12
    assert instance.digests == {
        "empty": sha3_512(b"").digest(),
        "two_block": sha3_512(b"A" * 72).digest(),
    }


def test_boolean_sponge_rejects_consistent_message_rewrite_without_round_rewrite(
    sponge_instance,
) -> None:
    instance = sponge_instance
    absorb = instance.traces["sha3_boolean_absorb"]
    columns = {name: list(values) for name, values in absorb.columns.items()}
    columns["block_byte_0"][1] ^= 1
    columns["block_bit_0"][1] ^= 1
    bad = dict(instance.traces)
    bad[absorb.name] = TraceTable(absorb.name, freeze_columns(columns))

    with pytest.raises(StructuralError, match="sha3_boolean_absorb_to_round"):
        evaluate_program(instance.program, bad)


def test_variable_length_boundaries_are_exact_and_fixed_shape() -> None:
    messages = (b"", b"A", b"B" * 71, b"C" * 72, b"D" * 73)
    calls = tuple(
        Sha3BooleanCall(f"boundary_{len(message)}", message, 73)
        for message in messages
    )
    instance = build_sha3_boolean_executable_air(calls)
    report = evaluate_program(instance.program, instance.traces)

    assert instance.block_counts == (2,) * len(messages)
    assert tuple(table.rows for table in instance.program.tables) == (250, 10, 5)
    assert instance.program.maximum_degree == MAXIMUM_DEGREE
    assert report.lookup_messages_evaluated == 34
    assert instance.digests == {
        call.call_id: sha3_512(call.message).digest() for call in calls
    }

    empty = build_sha3_boolean_executable_air((Sha3BooleanCall("same", b"", 73),))
    full = build_sha3_boolean_executable_air((Sha3BooleanCall("same", b"Z" * 73, 73),))
    assert empty.program.canonical_bytes() == full.program.canonical_bytes()
    assert tuple(table.rows for table in empty.program.tables) == tuple(
        table.rows for table in full.program.tables
    )


def test_variable_padding_and_activity_mutations_fail_closed() -> None:
    instance = build_sha3_boolean_executable_air(
        (Sha3BooleanCall("partial", b"A", 73),)
    )
    absorb = instance.traces["sha3_boolean_absorb"]

    live_columns = {name: list(values) for name, values in absorb.columns.items()}
    live_columns["message_live_1"][0] = 1
    live_bad = dict(instance.traces)
    live_bad[absorb.name] = TraceTable(absorb.name, freeze_columns(live_columns))
    with pytest.raises(StructuralError, match="sha3_boolean_absorb"):
        evaluate_program(instance.program, live_bad)

    active_columns = {name: list(values) for name, values in absorb.columns.items()}
    active_columns["block_active"][1] = 1
    active_bad = dict(instance.traces)
    active_bad[absorb.name] = TraceTable(absorb.name, freeze_columns(active_columns))
    with pytest.raises(StructuralError, match="sha3_boolean_absorb"):
        evaluate_program(instance.program, active_bad)


def test_call_rejects_message_larger_than_capacity() -> None:
    with pytest.raises(StructuralError, match="sha3_boolean_fixed_call_invalid"):
        Sha3BooleanCall("overflow", b"AB", 1)
