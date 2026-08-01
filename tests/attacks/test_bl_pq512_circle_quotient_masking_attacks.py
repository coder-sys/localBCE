from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.circle_quotient_masking import (
    build_canonical_circle_quotient_mask_plan,
    canonical_circle_split_factor,
    interpolate_conditional_quotient_mask,
    mask_canonical_quotient_pair,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import CirclePoint


def _fp16(value: int) -> Fp16:
    return Fp16((value,) + (0,) * 15)


def _plan():
    return build_canonical_circle_quotient_mask_plan(
        profile_id="K512_CALIBRATION",
        reduced_air_degree=2,
        oods_query_count=1,
        fri_query_count=926,
    )


def test_mask_plan_rejects_formula_decomposition_and_activation_tampering() -> None:
    plan = _plan()
    with pytest.raises(ValueError, match="trace_mask_degree_mismatch"):
        replace(plan, trace_mask_degree_freedom=4_693)
    with pytest.raises(ValueError, match="mask_degree_mismatch"):
        replace(plan, quotient_mask_degree_freedom=926)
    with pytest.raises(ValueError, match="decomposition_mismatch"):
        replace(plan, decomposition="FFT_IMPLICIT_ROOTS")
    with pytest.raises(ValueError, match="split_log_reduction_mismatch"):
        replace(plan, split_log_reduction=2)
    with pytest.raises(ValueError, match="nonactivating_boundary_violated"):
        replace(plan, prover_integrated=True)


def test_conditional_mask_rejects_duplicate_short_and_wrong_free_inputs() -> None:
    with pytest.raises(ValueError, match="parameters_not_distinct"):
        interpolate_conditional_quotient_mask(
            parameters=(_fp16(1), _fp16(1)),
            values=(_fp16(2), _fp16(3)),
            degree_freedom=3,
            free_coefficients=(_fp16(4),),
        )
    with pytest.raises(ValueError, match="below_rank"):
        interpolate_conditional_quotient_mask(
            parameters=(_fp16(1), _fp16(2)),
            values=(_fp16(2), _fp16(3)),
            degree_freedom=1,
            free_coefficients=(),
        )
    with pytest.raises(ValueError, match="free_coefficient_count_mismatch"):
        interpolate_conditional_quotient_mask(
            parameters=(_fp16(1), _fp16(2)),
            values=(_fp16(2), _fp16(3)),
            degree_freedom=3,
            free_coefficients=(),
        )


def test_mask_pair_requires_exact_extension_values() -> None:
    with pytest.raises(TypeError, match="inputs_must_be_fp16"):
        mask_canonical_quotient_pair(
            left=_fp16(1),
            right=_fp16(2),
            split_factor=_fp16(3),
            mask_value=4,  # type: ignore[arg-type]
        )


def test_split_factor_rejects_invalid_bound_type_and_off_circle_point() -> None:
    point = CirclePoint(_fp16(1), _fp16(0))
    with pytest.raises(ValueError, match="max_log_degree_bound_invalid"):
        canonical_circle_split_factor(point, max_log_degree_bound=0)
    with pytest.raises(TypeError, match="oods_point_required"):
        canonical_circle_split_factor(object(), max_log_degree_bound=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="oods_point_not_on_circle"):
        canonical_circle_split_factor(
            CirclePoint(_fp16(1), _fp16(1)), max_log_degree_bound=1
        )
