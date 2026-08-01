from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.fixed_shape_claim_air.executable_air import evaluate_program
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.wide_public_executable_air import (
    build_wide_public_executable_air,
)


def _instance():
    wide = tuple(sha3_512(f"BL-WIDE-PUBLIC-{index}".encode()).digest() for index in range(9))
    return build_wide_public_executable_air(2, 7001, 9001, wide)


def test_public_byte_mutation_and_field_reordering_fail_closed() -> None:
    instance = _instance()
    mutated = list(instance.public_input_bytes)
    mutated[-1] ^= 1
    with pytest.raises(StructuralError, match="air_public_input_mismatch"):
        evaluate_program(instance.program, instance.traces, mutated)

    reordered = (
        *instance.public_input_bytes[: 3 * 32],
        *instance.public_input_bytes[4 * 32 : 5 * 32],
        *instance.public_input_bytes[3 * 32 : 4 * 32],
        *instance.public_input_bytes[5 * 32 :],
    )
    with pytest.raises(StructuralError, match="air_public_input_mismatch"):
        evaluate_program(instance.program, instance.traces, reordered)


def test_noncanonical_stark252_public_value_is_rejected_before_trace_build() -> None:
    wide = tuple(sha3_512(f"BL-WIDE-PUBLIC-{index}".encode()).digest() for index in range(9))
    with pytest.raises(StructuralError, match="wide_public_value_not_canonical"):
        build_wide_public_executable_air(2, 2**251 + 17 * 2**192 + 1, 9001, wide)

