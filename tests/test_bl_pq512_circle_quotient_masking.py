from __future__ import annotations

from experiments.bl_pq512_crypto_foundation.circle_hiding_simulator import (
    circle_query_parameter,
)
from experiments.bl_pq512_crypto_foundation.circle_quotient_masking import (
    CIRCLE_SPLIT_FACTOR_RULE,
    QUOTIENT_MASK_STATUS,
    build_canonical_circle_quotient_mask_plan,
    canonical_circle_split_factor,
    evaluate_quotient_mask,
    interpolate_conditional_quotient_mask,
    mask_canonical_quotient_pair,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    sample_oods_parameter,
    stereographic_circle_point,
)


def _fp16(value: int) -> Fp16:
    return Fp16((value,) + (0,) * 15)


def _oods_parameter() -> Fp16:
    return sample_oods_parameter(
        bytes(range(64)),
        session_id=bytes(range(64, 128)),
        round_index=3,
    ).parameter.element


def test_k512_canonical_quotient_mask_plan_is_exact_and_nonactivating() -> None:
    plan = build_canonical_circle_quotient_mask_plan(
        profile_id="K512_CALIBRATION",
        reduced_air_degree=2,
        oods_query_count=1,
        fri_query_count=926,
    )
    assert plan.status == QUOTIENT_MASK_STATUS
    assert plan.trace_mask_degree_freedom == 4_694
    assert plan.quotient_mask_degree_freedom == 927
    assert plan.component_count == 2
    assert plan.decomposition == "CANONICAL_TWO_COMPONENT_CIRCLE_SPLIT"
    assert plan.split_factor_rule == CIRCLE_SPLIT_FACTOR_RULE
    assert plan.split_log_reduction == 1
    assert plan.proof_suite_id is None
    assert not plan.activation_allowed
    assert not plan.prover_integrated
    assert not plan.simulator_complete
    assert plan.commitment_sha3_512.hex() == (
        "8b577a857db1f9ae09b0382039bf1af47bd7fbd0b4f42fb3643039233852b1ac"
        "d56887c45710fb42e733d12024c48ee0c6a334aebdc064fd86d341f1896e6f3a"
    )


def test_source_aligned_circle_split_factor_is_exact() -> None:
    sample = sample_oods_parameter(
        bytes(range(64)),
        session_id=bytes(range(64, 128)),
        round_index=3,
    )
    point = stereographic_circle_point(sample.parameter)
    assert canonical_circle_split_factor(point, max_log_degree_bound=1) == point.x
    assert canonical_circle_split_factor(point, max_log_degree_bound=21).encode().hex() == (
        "2c2ef3f200470e3f16a140270c1f9e9a451cfd791cc2587f63d18d395ece5473"
        "2ccf39e70f9ab53e19e773cc623a1da32a4355f83810202c14a20e304f577f9e"
    )


def test_canonical_mask_preserves_joined_quotient_for_zero_and_nonzero_factors() -> None:
    left = Fp16(tuple(range(1, 17)))
    right = Fp16(tuple(range(17, 33)))
    mask = Fp16(tuple(range(33, 49)))
    for factor in (Fp16.zero(), _fp16(7), Fp16(tuple(range(49, 65)))):
        masked_left, masked_right = mask_canonical_quotient_pair(
            left=left,
            right=right,
            split_factor=factor,
            mask_value=mask,
        )
        assert masked_left + factor * masked_right == left + factor * right
        assert masked_right != right


def test_conditional_quotient_mask_hits_all_extension_and_base_queries() -> None:
    parameters = (
        _oods_parameter(),
        *(
            _fp16(circle_query_parameter(8, position))
            for position in (0, 1, 2, 3)
        ),
    )
    values = tuple(Fp16(tuple(range(seed, seed + 16))) for seed in range(1, 6))
    first = interpolate_conditional_quotient_mask(
        parameters=parameters,
        values=values,
        degree_freedom=7,
        free_coefficients=(_fp16(101), _fp16(202)),
    )
    second = interpolate_conditional_quotient_mask(
        parameters=parameters,
        values=values,
        degree_freedom=7,
        free_coefficients=(_fp16(303), _fp16(404)),
    )
    assert first != second
    for coefficients in (first, second):
        assert tuple(
            evaluate_quotient_mask(coefficients, parameter)
            for parameter in parameters
        ) == values
