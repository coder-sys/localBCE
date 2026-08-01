from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.circle_hiding_simulator import (
    EVALUATION_MAP_STATUS,
    build_circle_evaluation_map_certificate,
    evaluate_circle_mask_at_base,
    evaluate_circle_mask_at_fp16,
    interpolate_conditional_circle_mask,
    minimal_polynomial_fp16,
    translate_circle_parameter,
)
from experiments.bl_pq512_crypto_foundation.circle_fri_reference import (
    circle_domain_step,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    OODS_DEFAULT_MAX_ATTEMPTS,
    OodsParameter,
    sample_oods_parameter,
    stereographic_circle_point,
)


SEED = bytes(range(64))
SESSION = bytes(range(64, 128))
VECTOR = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "test_data"
        / "bl_pq512_wave1b_hiding_vectors_v1.json"
    ).read_text(encoding="utf-8")
)


def _oods():
    return sample_oods_parameter(
        SEED,
        session_id=SESSION,
        round_index=3,
        max_attempts=OODS_DEFAULT_MAX_ATTEMPTS,
    ).parameter


def test_stereographic_translation_matches_circle_group_addition() -> None:
    oods = _oods()
    step = circle_domain_step(20)
    translated = translate_circle_parameter(oods.element, step)
    source_point = stereographic_circle_point(oods)
    translated_point = stereographic_circle_point(OodsParameter(translated))
    embedded_x = Fp16((step.x,) + (0,) * 15)
    embedded_y = Fp16((step.y,) + (0,) * 15)

    assert translated_point.x == source_point.x * embedded_x - source_point.y * embedded_y
    assert translated_point.y == source_point.x * embedded_y + source_point.y * embedded_x


def test_k512_evaluation_map_certificate_is_exact_and_surjective() -> None:
    positions = tuple(range(0, 2 * 926, 2))
    oods = _oods()
    translated = translate_circle_parameter(
        oods.element,
        circle_domain_step(20),
    )
    certificate = build_circle_evaluation_map_certificate(
        extension_parameters=(oods.element, translated),
        evaluation_log_size=21,
        query_positions=positions,
        degree_freedom=4_694,
    )

    assert certificate.status == EVALUATION_MAP_STATUS
    assert certificate.extension_minimal_polynomials == tuple(
        minimal_polynomial_fp16(parameter)
        for parameter in certificate.extension_parameters
    )
    assert all(
        len(minimal) == 17 and minimal[-1] == 1
        for minimal in certificate.extension_minimal_polynomials
    )
    assert len(certificate.unique_base_query_parameters) == 926
    assert certificate.rank == 2 * 16 + 926 == 958
    assert certificate.circle_basis_degree == 2_347
    assert certificate.free_dimension == 3_736
    assert certificate.surjective
    assert certificate.proof_suite_id is None
    assert not certificate.activation_allowed
    step = circle_domain_step(20)
    assert VECTOR["transitionStep"] == {"x": step.x, "y": step.y}
    assert VECTOR["oodsParameterHex"] == oods.element.encode().hex()
    assert VECTOR["translatedOodsParameterHex"] == translated.encode().hex()
    assert VECTOR["extensionMinimalPolynomials"] == [
        list(minimal) for minimal in certificate.extension_minimal_polynomials
    ]
    assert VECTOR["rank"] == certificate.rank
    assert VECTOR["freeDimension"] == certificate.free_dimension
    assert (
        VECTOR["certificateSha3_512"]
        == certificate.commitment_sha3_512.hex()
        == "79148ba5b5ee6655478cd478cf3dd159bb8d458d1b6dad0245ee2db0ba223d4c7"
        "66e0764f9909d05cba9efd0ea98329f53a70618553bf53ea1cd3ead86b6fb04"
    )
    assert not VECTOR["fullQuotientClosureProved"]
    assert VECTOR["quotientMaskDegreeFreedom"] == 927
    assert VECTOR["quotientMaskPlanSha3_512"] == (
        "8b577a857db1f9ae09b0382039bf1af47bd7fbd0b4f42fb3643039233852b1ac"
        "d56887c45710fb42e733d12024c48ee0c6a334aebdc064fd86d341f1896e6f3a"
    )
    assert VECTOR["quotientSplitLogReduction"] == 1
    assert not VECTOR["simulatorComplete"]


def test_conditional_interpolation_hits_every_claim_and_uses_all_free_randomness() -> None:
    oods = _oods()
    translated = translate_circle_parameter(oods.element, circle_domain_step(7))
    certificate = build_circle_evaluation_map_certificate(
        extension_parameters=(oods.element, translated),
        evaluation_log_size=8,
        query_positions=(0, 2, 4, 6),
        degree_freedom=40,
    )
    extension_values = (
        Fp16(tuple(range(1, 17))),
        Fp16(tuple(range(17, 33))),
    )
    base_values = (101, 202, 303, 404)
    first = interpolate_conditional_circle_mask(
        certificate,
        extension_values=extension_values,
        base_query_values=base_values,
        free_coefficients=(11, 22, 33, 44),
    )
    second = interpolate_conditional_circle_mask(
        certificate,
        extension_values=extension_values,
        base_query_values=base_values,
        free_coefficients=(55, 66, 77, 88),
    )

    assert len(first) == len(second) == certificate.degree_freedom
    assert first != second
    for coefficients in (first, second):
        assert tuple(
            evaluate_circle_mask_at_fp16(coefficients, parameter)
            for parameter in certificate.extension_parameters
        ) == extension_values
        assert tuple(
            evaluate_circle_mask_at_base(coefficients, parameter)
            for parameter in certificate.base_query_parameters
        ) == base_values
