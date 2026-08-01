from __future__ import annotations

import os
from dataclasses import replace

import pytest

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.circle_hiding_simulator import (
    build_circle_evaluation_map_certificate,
    interpolate_conditional_circle_mask,
    minimal_polynomial_fp16,
    translate_circle_parameter,
)
from experiments.bl_pq512_crypto_foundation.circle_fri_reference import (
    circle_domain_step,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    OodsParameter,
    sample_oods_parameter,
)


def _oods() -> OodsParameter:
    return sample_oods_parameter(
        bytes(range(64)),
        session_id=bytes(range(64, 128)),
        round_index=3,
    ).parameter


def _certificate():
    return build_circle_evaluation_map_certificate(
        extension_parameters=(_oods().element,),
        evaluation_log_size=8,
        query_positions=(0, 2, 4, 6),
        degree_freedom=24,
    )


def test_fixed_subfield_low_degree_and_out_of_domain_inputs_fail_closed() -> None:
    with pytest.raises(ValueError, match="not_degree_sixteen"):
        minimal_polynomial_fp16(Fp16((7,) + (0,) * 15))
    with pytest.raises(ValueError, match="below_conservative_query_bound"):
        build_circle_evaluation_map_certificate(
            extension_parameters=(_oods().element,),
            evaluation_log_size=8,
            query_positions=(0, 2, 4, 6),
            degree_freedom=19,
        )
    with pytest.raises(ValueError, match="query_position_out_of_range"):
        build_circle_evaluation_map_certificate(
            extension_parameters=(_oods().element,),
            evaluation_log_size=8,
            query_positions=(256,),
            degree_freedom=17,
        )


def test_certificate_and_conditional_solution_tampering_fail_closed() -> None:
    certificate = _certificate()
    bad_minimal = certificate.extension_minimal_polynomials[0][:-1] + (0,)
    with pytest.raises(ValueError, match="minimal_polynomial_mismatch"):
        replace(certificate, extension_minimal_polynomials=(bad_minimal,))
    with pytest.raises(ValueError, match="base_query_parameter_mismatch"):
        replace(
            certificate,
            base_query_parameters=(
                (certificate.base_query_parameters[0] + 1) % ((1 << 31) - 1),
                *certificate.base_query_parameters[1:],
            ),
        )
    with pytest.raises(ValueError, match="free_coefficient_count_mismatch"):
        interpolate_conditional_circle_mask(
            certificate,
            extension_values=(Fp16.one(),),
            base_query_values=(1, 2, 3, 4),
            free_coefficients=(1, 2, 3),
        )


def test_duplicate_query_cannot_receive_conflicting_simulated_values() -> None:
    certificate = build_circle_evaluation_map_certificate(
        extension_parameters=(_oods().element,),
        evaluation_log_size=8,
        query_positions=(0, 0),
        degree_freedom=20,
    )
    assert certificate.base_query_parameters[0] == certificate.base_query_parameters[1]
    with pytest.raises(ValueError, match="duplicate_query_value_conflict"):
        interpolate_conditional_circle_mask(
            certificate,
            extension_values=(Fp16.one(),),
            base_query_values=(1, 2),
            free_coefficients=(3, 4, 5),
        )


def test_adjacent_circle_positions_are_not_aliased() -> None:
    certificate = build_circle_evaluation_map_certificate(
        extension_parameters=(_oods().element,),
        evaluation_log_size=8,
        query_positions=(0, 1),
        degree_freedom=20,
    )
    assert certificate.base_query_parameters[0] != certificate.base_query_parameters[1]


def test_duplicate_extension_orbit_and_missing_translated_rank_fail_closed() -> None:
    oods = _oods()
    with pytest.raises(ValueError, match="frobenius_orbit_duplicate"):
        build_circle_evaluation_map_certificate(
            extension_parameters=(oods.element, oods.element),
            evaluation_log_size=8,
            query_positions=(0, 2, 4, 6),
            degree_freedom=40,
        )

    translated = translate_circle_parameter(
        oods.element,
        circle_domain_step(7),
    )
    with pytest.raises(ValueError, match="below_conservative_query_bound"):
        build_circle_evaluation_map_certificate(
            extension_parameters=(oods.element, translated),
            evaluation_log_size=8,
            query_positions=(0, 2, 4, 6),
            degree_freedom=35,
        )
