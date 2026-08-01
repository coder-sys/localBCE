from __future__ import annotations

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    StructuralError,
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.master_commitments_executable_air import (
    build_master_commitments_executable_air,
)
from tests.test_bl_pq512_master_commitments_v2 import _inputs


@pytest.fixture(scope="module")
def instance():
    return build_master_commitments_executable_air(_inputs())


def _mutate(instance, table: str, column: str, row: int):
    traces = dict(instance.traces)
    columns = dict(traces[table].columns)
    values = list(columns[column])
    values[row] ^= 1
    columns[column] = tuple(values)
    traces[table] = TraceTable(table, freeze_columns(columns))
    return traces


def test_master_commitments_are_one_exact_chained_sha3_air(instance) -> None:
    report = evaluate_program(instance.program, instance.traces)
    assert instance.master_hashes_constrained is True
    assert len(instance.sha3.digests) == 4
    assert instance.traces["sha3_digest_batch"].rows == 4
    assert report.identities_evaluated == 4_197_487
    assert report.lookup_messages_evaluated == 9_524_516
    assert report.maximum_degree == 2


@pytest.mark.parametrize(
    ("table", "column", "failure"),
    (
        ("master_commitment_material_byte", "value", "master_commitment_material_reuse"),
        ("master_commitment_chain_message_byte", "value", "master_commitment_digest_chain"),
        ("master_commitment_output_byte", "value", "master_commitment_digest_chain"),
        ("master_commitment_constant_message_byte", "value", "air_fixed_column_mismatch"),
        ("master_commitment_slot", "gross_after_0", "slot_gross_accumulate_0"),
    ),
)
def test_master_material_chain_output_and_constants_fail_closed(
    instance, table: str, column: str, failure: str
) -> None:
    with pytest.raises(StructuralError, match=failure):
        evaluate_program(instance.program, _mutate(instance, table, column, 0))
