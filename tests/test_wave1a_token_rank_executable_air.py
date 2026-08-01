from __future__ import annotations

from types import MappingProxyType

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    TraceTable,
    evaluate_program,
    evaluate_serialized,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.token_rank_executable_air import (
    TOKEN_RANK_MAX_BYTES,
    TokenRankInput,
    build_token_rank_executable_air,
)


TOKENS = (
    TokenRankInput(0, 0, "", False),
    TokenRankInput(0, 1, "A", True),
    TokenRankInput(1, 0, "SYNTHETIC-AUTH-1", True),
    TokenRankInput(1, 1, "Z" * 64, True),
    TokenRankInput(2, 0, "A" + "-" * 63, True),
    TokenRankInput(2, 1, "9" + "-" * 63, True),
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


def test_token_rank_air_evaluates_direct_and_serialized() -> None:
    instance = build_token_rank_executable_air(TOKENS)
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2
    assert direct.identities_evaluated == len(TOKENS) * 93
    assert direct.lookup_messages_evaluated == len(TOKENS) * 168
    assert instance.encoded_ranks[-1] == TOKEN_RANK_MAX_BYTES


def test_program_commitment_is_independent_of_private_token_and_required_state() -> None:
    empty = build_token_rank_executable_air(
        (TokenRankInput(7, 11, "", False),)
    )
    present = build_token_rank_executable_air(
        (TokenRankInput(7, 11, "PRIVATE-TOKEN", True),)
    )
    assert empty.program.commitment() == present.program.commitment()


def test_empty_required_and_duplicate_coordinates_fail_before_trace() -> None:
    with pytest.raises(StructuralError, match="required_token_empty"):
        TokenRankInput(0, 0, "", True)
    with pytest.raises(StructuralError, match="coordinate_duplicate"):
        build_token_rank_executable_air((TOKENS[1], TOKENS[1]))


def test_rank_bound_borrow_and_difference_mutations_fail() -> None:
    instance = build_token_rank_executable_air(TOKENS)
    with pytest.raises(StructuralError, match="rank_bound_step"):
        evaluate_program(
            instance.program,
            _mutate(instance, "token_rank", "difference_byte_41", 2, 1),
        )
    with pytest.raises(StructuralError, match="borrow_1_boolean|rank_bound_step"):
        evaluate_program(
            instance.program,
            _mutate(instance, "token_rank", "borrow_1", 2, 2),
        )


def test_out_of_range_rank_bytes_cannot_be_repaired_locally() -> None:
    instance = build_token_rank_executable_air(TOKENS)
    traces = instance.traces
    changed = _mutate(
        instance,
        "token_rank",
        "rank_byte_0",
        0,
        TOKEN_RANK_MAX_BYTES[0] + 1,
    )
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(instance.program, changed)
    assert traces["token_rank"].columns["rank_byte_0"][0] == 0


def test_rank_byte_mutation_breaks_sum_or_byte_lookup() -> None:
    instance = build_token_rank_executable_air(TOKENS)
    with pytest.raises(StructuralError, match="byte_sum|rank_bound_step|lookup_multiset"):
        evaluate_program(
            instance.program,
            _mutate(instance, "token_rank", "rank_byte_41", 1, 2),
        )
