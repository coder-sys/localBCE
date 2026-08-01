from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program, freeze_columns
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.stark252_projection_air import (
    Stark252ProjectionRequest,
    build_stark252_projection_air,
)


@pytest.fixture(scope="module")
def instance():
    return build_stark252_projection_air(
        (Stark252ProjectionRequest("projection", sha3_512(b"projection attack fixture").digest()),)
    )


def _mutate(instance, column: str, value: int):
    traces = dict(instance.traces)
    columns = {name: list(values) for name, values in traces["stark252_projection"].columns.items()}
    columns[column][0] = value
    traces["stark252_projection"] = TraceTable("stark252_projection", freeze_columns(columns))
    return traces


@pytest.mark.parametrize(
    ("column", "value", "failure"),
    (
        ("digest_0", 0, "projection_coefficient_63"),
        ("quotient_0", 0, "projection_coefficient_24"),
        ("remainder_0", 0, "projection_coefficient_0"),
        ("remainder_delta_0", 0, "remainder_canonical_0"),
        ("projection_carry_bias_1", 0, "projection_coefficient_0"),
    ),
)
def test_projection_witness_mutations_are_rejected(instance, column: str, value: int, failure: str) -> None:
    original = instance.traces["stark252_projection"].columns[column][0]
    replacement = value if value != original else (value + 1)
    with pytest.raises(StructuralError, match=f"air_identity_failed:stark252_projection:{failure}"):
        evaluate_program(instance.program, _mutate(instance, column, replacement))


def test_out_of_range_projection_byte_is_rejected(instance) -> None:
    # The exact integer identity may reject first; either ordering is fail-closed.
    with pytest.raises(StructuralError):
        evaluate_program(instance.program, _mutate(instance, "digest_0", 256))
