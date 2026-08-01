from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.fixed_shape_claim_air.a12_nullifier_executable_air import (
    AttemptNullifierAirRequest,
    CoverNullifierAirRequest,
    build_a12_nullifier_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import TraceTable, evaluate_program, freeze_columns
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_a12_nullifier_derivation import _authority, _cover_context_v2, _identity


@pytest.fixture(scope="module")
def instance():
    return build_a12_nullifier_executable_air(
        (
            AttemptNullifierAirRequest("attempt", _identity()),
            CoverNullifierAirRequest(
                "cover", _cover_context_v2(), sha3_512(b"BL-A12-COVER-NONCE").digest()
            ),
        ),
        _authority(),
    )


def _mutate(instance, table: str, column: str, row: int, value: int):
    traces = dict(instance.traces)
    columns = {name: list(values) for name, values in traces[table].columns.items()}
    columns[column][row] = value
    traces[table] = TraceTable(table, freeze_columns(columns))
    return traces


def test_attempt_identity_byte_cannot_be_detached_from_strong_hash(instance) -> None:
    traces = _mutate(instance, "a12_request", "authority_byte_0", 0, ord("C"))
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch:a12_preimage_binding_0"):
        evaluate_program(instance.program, traces)


def test_strong_nullifier_output_cannot_be_replaced(instance) -> None:
    traces = _mutate(instance, "a12_output", "strong_0", 1, 0)
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch:a12_strong_output_1"):
        evaluate_program(instance.program, traces)


def test_compatibility_alias_cannot_be_detached_from_strong_nullifier(instance) -> None:
    observed = instance.traces["a12_output"].columns["compatibility_0"][1]
    traces = _mutate(instance, "a12_output", "compatibility_0", 1, observed ^ 1)
    with pytest.raises(
        StructuralError, match="air_lookup_multiset_mismatch:a12_compatibility_output_1"
    ):
        evaluate_program(instance.program, traces)


def test_pepper_commitment_cannot_be_detached_from_private_pepper(instance) -> None:
    traces = _mutate(instance, "a12_authority", "commitment_0", 0, 0)
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch:a12_pepper_commitment"):
        evaluate_program(instance.program, traces)
