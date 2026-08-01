from __future__ import annotations

from hashlib import sha3_512

from experiments.fixed_shape_claim_air.application_sha3_executable_air import (
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
    combine_application_sha3_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import evaluate_program, evaluate_serialized


def test_application_sha3_calls_share_one_truth_table() -> None:
    instance = build_application_sha3_executable_air(
        (
            Sha3Call("claim_leaf", b"claim", 143),
            Sha3Call("oracle_bundle", bytes(range(80)), 143),
        )
    )
    assert instance.digests == {
        "claim_leaf": sha3_512(b"claim").digest(),
        "oracle_bundle": sha3_512(bytes(range(80))).digest(),
    }
    assert tuple(table.name for table in instance.program.tables).count("sha3_truth_shared") == 1
    assert sum(table.rows for table in instance.program.tables if table.name == "sha3_truth_shared") == 132_864
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2


def test_application_sha3_program_is_message_length_independent_at_fixed_capacities() -> None:
    left = build_application_sha3_executable_air(
        (Sha3Call("a", b"x", 143), Sha3Call("b", bytes(range(80)), 143))
    )
    right = build_application_sha3_executable_air(
        (Sha3Call("a", bytes(range(70)), 143), Sha3Call("b", b"y", 143))
    )
    assert left.program.commitment() == right.program.commitment()


def test_application_sha3_batches_combine_without_duplicate_engines() -> None:
    left = build_application_sha3_executable_air(
        (Sha3Call("left_a", b"a", 8), Sha3Call("left_b", b"b", 8))
    )
    right = build_application_sha3_executable_air(
        (Sha3Call("right_c", b"c", 8),)
    )
    combined = combine_application_sha3_executable_air((left, right))

    assert combined.call_rows["right_c"].call_index == 2
    assert combined.digests["right_c"] == sha3_512(b"c").digest()
    assert tuple(table.name for table in combined.program.tables).count(
        "sha3_truth_shared"
    ) == 1
    report = evaluate_program(combined.program, combined.traces)
    assert report.maximum_degree == 2


def test_application_sha3_interface_is_compact_exact_and_message_length_private() -> None:
    calls = (
        Sha3Call("empty", b"", 73),
        Sha3Call("partial", b"A", 73),
        Sha3Call("full", b"B" * 73, 73),
    )
    instance = build_application_sha3_interface_air(calls)
    report = evaluate_program(instance.program, instance.traces)

    assert tuple(
        (table.name, table.rows, len(table.columns)) for table in instance.program.tables
    ) == (
        ("sha3_message_batch", 432, 6),
        ("sha3_digest_batch", 3, 65),
        ("sha3_digest_byte_batch", 192, 3),
    )
    assert instance.digests == {
        call.call_id: sha3_512(call.message).digest() for call in calls
    }
    assert report.maximum_degree == 3

    left = build_application_sha3_interface_air((Sha3Call("same", b"", 73),))
    right = build_application_sha3_interface_air(
        (Sha3Call("same", b"Z" * 73, 73),)
    )
    assert left.program.canonical_bytes() == right.program.canonical_bytes()
