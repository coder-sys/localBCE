from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_wave1a_ordered_map_batch_sha3_composition import (
    ordered_map_sha3_air_instance,
)


def test_dummy_hash_digest_substitution_is_rejected_by_exact_sha3() -> None:
    instance = ordered_map_sha3_air_instance()
    traces = dict(instance.traces)
    trace = traces["ordered_map_hash_port"]
    columns = {name: list(values) for name, values in trace.columns.items()}
    row = next(
        index
        for index in range(instance.schedule.leaf_hash_rows)
        if not columns["live"][index]
    )
    original = columns["digest_0"][row]
    replacement = (original + 1) % 256
    columns["digest_0"][row] = replacement
    traces[trace.name] = TraceTable(trace.name, freeze_columns(columns))

    # Give the attacker a consistent byte-range multiset so this test reaches
    # the hash relation rather than relying on an earlier independent gate.
    byte_trace = traces["ordered_map_byte"]
    byte_columns = {
        name: list(values) for name, values in byte_trace.columns.items()
    }
    byte_columns["multiplicity"][original] -= 1
    byte_columns["multiplicity"][replacement] += 1
    traces[byte_trace.name] = TraceTable(
        byte_trace.name,
        freeze_columns(byte_columns),
    )

    with pytest.raises(
        StructuralError,
        match="air_lookup_multiset_mismatch:ordered_map_sha3_digest_binding",
    ):
        evaluate_program(instance.program, traces)
