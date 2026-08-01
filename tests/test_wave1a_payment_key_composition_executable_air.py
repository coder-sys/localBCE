from __future__ import annotations

from dataclasses import replace
from functools import lru_cache

import pytest

from experiments.fixed_shape_claim_air.claim_payment_maps_executable_air import (
    _bridge_table,
    _payment_key_sha3,
)
from experiments.fixed_shape_claim_air.executable_air import (
    M31,
    AirProgram,
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_wave1a_payment_log_cross_language import _transition


@lru_cache(maxsize=1)
def _instance():
    slots, _, transition = _transition()
    sha3, key_table, key_trace, key_lookups, source = _payment_key_sha3(
        slots, transition
    )
    bridge_table, bridge_trace, _ = _bridge_table(slots, transition)
    local_lookups = tuple(
        lookup
        for lookup in key_lookups
        if lookup.name != "claim_payment_keys_match_operations"
    )
    program = AirProgram(
        "BL-WAVE1A-PAYMENT-KEY-COMPOSITION-KAT-v1",
        (*source.program.tables, key_table, *sha3.program.tables),
        (*source.program.lookups, *sha3.program.lookups, *local_lookups),
    )
    traces = {
        **dict(source.traces),
        key_trace.name: key_trace,
        **dict(sha3.traces),
    }
    return (
        program,
        traces,
        key_table,
        key_trace,
        key_lookups,
        source,
        bridge_table,
        bridge_trace,
    )


def _mutate(trace: TraceTable, column: str, rows: tuple[int, ...]) -> TraceTable:
    columns = {name: list(values) for name, values in trace.columns.items()}
    for row in rows:
        columns[column][row] = (columns[column][row] + 1) % M31
    return TraceTable(trace.name, freeze_columns(columns))


def test_k128_payment_key_source_sha3_composition_evaluates() -> None:
    program, traces, *_ = _instance()
    report = evaluate_program(program, traces)

    assert len(program.tables) == 20
    assert len(program.lookups) == 33
    assert report.identities_evaluated == 40_090_490
    assert report.lookup_messages_evaluated == 83_850_786
    assert report.maximum_degree == 2
    assert report.program_commitment.hex() == (
        "295134938dbf2fec7a868b35dee6f62e349b72b6d98b40245de268081076d58c0"
        "73146e90546d86ed6882a1af644f06ef04c3ba97fbe79210f1bb07fd75106bd"
    )
    assert report.trace_commitment.hex() == (
        "346c8a277b4cf2e30e708ca1401f8496837721495f1b94a69c4d1a1f1923df8a"
        "fade076fbb8349c50ac3ea0c7225bc5c533444c4c87f0bfdbd4c496b718ed000"
    )


def test_payment_key_message_mutation_fails_local_identity() -> None:
    _, _, key_table, key_trace, *_ = _instance()
    bad = _mutate(key_trace, "message_byte_0", (0,))
    with pytest.raises(StructuralError, match="air_identity_failed"):
        evaluate_program(AirProgram("payment-key-local-attack", (key_table,)), {bad.name: bad})


def test_payment_key_rank_and_matching_message_mutation_fails_source_link() -> None:
    _, _, key_table, key_trace, key_lookups, source, *_ = _instance()
    # Slot zero occupies four consecutive lanes.  Change the repeated authority
    # rank everywhere and the obligation message at its matching byte so every
    # local preimage identity still holds; the canonical source-rank lookup must
    # be the boundary that rejects it.
    bad = _mutate(key_trace, "authority_rank_0", (0, 1, 2, 3))
    bad = _mutate(bad, "message_byte_33", (1,))
    authority = next(
        lookup
        for lookup in key_lookups
        if lookup.name == "claim_payment_key_authority_rank_matches_source"
    )
    token_table = next(
        table for table in source.program.tables if table.name == "claim_source_token_link"
    )
    reduced_key = replace(key_table, identities=key_table.identities)
    program = AirProgram(
        "payment-key-source-link-attack",
        (token_table, reduced_key),
        (authority,),
    )
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch"):
        evaluate_program(
            program,
            {
                "claim_source_token_link": source.traces["claim_source_token_link"],
                bad.name: bad,
            },
        )


def test_payment_key_digest_substitution_fails_operation_link() -> None:
    _, _, key_table, key_trace, key_lookups, _, bridge_table, bridge_trace = _instance()
    operation = next(
        lookup
        for lookup in key_lookups
        if lookup.name == "claim_payment_keys_match_operations"
    )
    bad = _mutate(key_trace, "digest_byte_0", (0,))
    program = AirProgram(
        "payment-key-operation-link-attack",
        (bridge_table, key_table),
        (operation,),
    )
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch"):
        evaluate_program(program, {bridge_trace.name: bridge_trace, bad.name: bad})
