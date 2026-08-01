from __future__ import annotations

from experiments.fixed_shape_claim_air.executable_air import (
    evaluate_program,
    evaluate_serialized,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.ruleset_commitment_executable_air import (
    build_ruleset_commitment_executable_air,
)


def test_k128_ruleset_bytes_and_root_are_exactly_sha3_bound() -> None:
    instance = build_ruleset_commitment_executable_air(
        get_profile("K128_CALIBRATION")
    )
    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(), instance.traces
    )
    assert direct == serialized
    assert instance.ruleset_hash_constrained is True
    assert instance.traces["sha3_digest_batch"].rows == 1
    assert direct.maximum_degree == 2
