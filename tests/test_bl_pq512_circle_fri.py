from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation.circle_fri_reference import (
    M31_CIRCLE_GENERATOR,
    M31_CIRCLE_LOG_ORDER,
    bit_reverse_index,
    canonic_circle_point,
    circle_domain_step,
    build_fri_cascade,
    conjugate_pair_zeroifier,
    degree_corrected_row,
    fold_circle_into_line,
    fold_circle_layer,
    verify_degree_corrected_row,
    FriDomainBatch,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    CirclePoint,
    OodsParameter,
    stereographic_circle_point,
)


ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads(
    (ROOT / "test_data" / "bl_pq512_s09_foundation_vectors.json").read_text(encoding="utf-8")
)["circleFriKat"]


def _fp16(value: int) -> Fp16:
    return Fp16((value,) + (0,) * 15)


def test_m31_circle_generator_and_canonic_domains() -> None:
    assert M31_CIRCLE_GENERATOR.multiply(1 << M31_CIRCLE_LOG_ORDER).x == 1
    assert M31_CIRCLE_GENERATOR.multiply(1 << M31_CIRCLE_LOG_ORDER).y == 0
    for log_size in range(2, 13):
        size = 1 << log_size
        step = circle_domain_step(log_size)
        for index in range(size):
            point = canonic_circle_point(log_size, index)
            conjugate = canonic_circle_point(log_size, index ^ (size >> 1))
            assert point == conjugate.conjugate()
            if index + 1 < (size >> 1):
                assert point + step == canonic_circle_point(log_size, index + 1)


def test_bit_reverse_is_involution() -> None:
    for log_size in range(1, 13):
        for index in range(1 << log_size):
            assert bit_reverse_index(bit_reverse_index(index, log_size), log_size) == index


def test_circle_fold_constant_polynomial_and_shapes() -> None:
    alpha = _fp16(7)
    values = (_fp16(1),) * 16
    assert fold_circle_into_line(values, alpha) == (_fp16(2),) * 8
    assert fold_circle_layer(values, alpha, 3) == (_fp16(8),) * 2


def test_circle_fold_recovers_even_and_odd_linear_parts() -> None:
    log_size = 5
    alpha = _fp16(7)
    values = []
    for bit_reversed_index in range(1 << log_size):
        point = canonic_circle_point(
            log_size,
            bit_reverse_index(bit_reversed_index, log_size),
        )
        values.append(_fp16((3 + 5 * point.y) % 2147483647))
    expected = _fp16(2 * (3 + 7 * 5))
    assert fold_circle_into_line(tuple(values), alpha) == (expected,) * (1 << (log_size - 1))


def test_circle_fold_nontrivial_vector() -> None:
    alpha = Fp16(tuple(range(1, 17)))
    values = tuple(Fp16(tuple((row * 17 + index) % 2147483647 for index in range(16))) for row in range(16))
    folded = fold_circle_layer(values, alpha, 3)
    assert [value.encode().hex() for value in folded] == VECTOR["foldedValuesHex"]


def test_circle_fold_rejects_invalid_shapes_and_counts() -> None:
    with pytest.raises(ValueError, match="evaluation_size_invalid"):
        fold_circle_into_line((_fp16(1),) * 3, _fp16(2))
    with pytest.raises(ValueError, match="fold_count_exceeds_domain"):
        fold_circle_layer((_fp16(1),) * 4, _fp16(2), 3)
    with pytest.raises(TypeError, match="alpha_must_be_fp16"):
        fold_circle_into_line((_fp16(1),) * 4, 2)  # type: ignore[arg-type]


def test_degree_corrected_row_tests_original_and_quotient_together() -> None:
    query = stereographic_circle_point(
        OodsParameter(Fp16((1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0)))
    )
    point = canonic_circle_point(5, 7)
    original = _fp16(3) + _fp16(5) * _fp16(point.x) + _fp16(11) * _fp16(point.y)
    claim = _fp16(3) + _fp16(5) * query.x + _fp16(11) * query.y
    row = degree_corrected_row(
        domain_point=point,
        query=query,
        original_values=(original,),
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )
    zeroifier = conjugate_pair_zeroifier(point, query)
    kat = VECTOR["degreeCorrected"]
    assert point.x == kat["domainPointX"]
    assert point.y == kat["domainPointY"]
    assert original.encode().hex() == kat["originalValueHex"]
    assert claim.encode().hex() == kat["claimedQueryValueHex"]
    assert zeroifier.encode().hex() == kat["zeroifierHex"]
    assert row.quotient_values[0].encode().hex() == kat["quotientValueHex"]
    assert verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=row,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )
    assert row.fri_batch_values == (original, row.quotient_values[0])


def test_degree_corrected_row_rejects_fixed_subfield_and_bad_shapes() -> None:
    with pytest.raises(ValueError, match="query_in_fixed_subfield"):
        conjugate_pair_zeroifier(
            canonic_circle_point(5, 0), CirclePoint(Fp16.one(), Fp16.zero())
        )
    query = stereographic_circle_point(OodsParameter(Fp16((0,) * 8 + (1,) + (0,) * 7)))
    with pytest.raises(ValueError, match="column_count_mismatch"):
        degree_corrected_row(
            domain_point=canonic_circle_point(5, 0),
            query=query,
            original_values=(),
            claimed_query_values=(),
            claimed_conjugate_query_values=(),
        )


def test_conjugate_claim_line_falls_back_to_x_when_y_is_fixed() -> None:
    w = Fp16((0,) * 8 + (1,) + (0,) * 7)
    parameter = OodsParameter((Fp16.one() + w) / (Fp16.one() - w))
    query = stereographic_circle_point(parameter)
    assert query != CirclePoint(query.x.conjugate(), query.y.conjugate())
    assert query.y == query.y.conjugate()
    assert query.x != query.x.conjugate()

    point = canonic_circle_point(5, 3)
    original = _fp16(71)
    claim = Fp16(tuple(range(16)))
    row = degree_corrected_row(
        domain_point=point,
        query=query,
        original_values=(original,),
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )
    assert verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=row,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )


def test_extension_function_requires_an_explicit_second_query_claim() -> None:
    query = stereographic_circle_point(
        OodsParameter(Fp16((1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0)))
    )
    point = canonic_circle_point(5, 9)
    original = _fp16(37)
    claim = Fp16((1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16))
    explicit_second_claim = claim.conjugate() + _fp16(29)
    assert explicit_second_claim != claim.conjugate()

    row = degree_corrected_row(
        domain_point=point,
        query=query,
        original_values=(original,),
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(explicit_second_claim,),
    )

    assert verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=row,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(explicit_second_claim,),
    )
    assert not verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=row,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )


def test_multi_domain_fri_batching_and_insertion_on_constants() -> None:
    batch_coefficient = _fp16(3)
    fold_coefficients = (_fp16(5), _fp16(7))
    batches = (
        FriDomainBatch(4, ((_fp16(2), _fp16(11)),) * 16),
        FriDomainBatch(3, ((_fp16(13), _fp16(17)),) * 8),
    )
    masks = (
        FriDomainBatch(4, ((_fp16(19),),) * 16),
        FriDomainBatch(3, ((_fp16(23),),) * 8),
    )
    cascade = build_fri_cascade(
        batches,
        batch_masks=masks,
        batch_coefficient=batch_coefficient,
        fold_coefficients=fold_coefficients,
    )

    first_batched = 19 + 3 * 2 + 3**2 * 11
    second_batched = 23 + 3**3 * 13 + 3**4 * 17
    first_folded = 2 * first_batched
    second_folded = 7**2 * 2 * first_folded + 2 * second_batched
    assert cascade.batched_domains[0] == (_fp16(first_batched),) * 16
    assert cascade.batched_domains[1] == (_fp16(second_batched),) * 8
    assert cascade.batch_masks[0] == (_fp16(19),) * 16
    assert cascade.batch_masks[1] == (_fp16(23),) * 8
    assert cascade.domain_log_sizes == (4, 3)
    assert cascade.fold_log_sizes == (4, 3)
    assert cascade.batch_column_counts == (2, 2)
    assert cascade.batch_power_offsets == (0, 2)
    assert cascade.folded_layers[0] == (_fp16(first_folded),) * 8
    assert cascade.folded_layers[1] == (_fp16(second_folded),) * 4
    assert cascade.final_line_evaluation == (_fp16(second_folded),) * 4


def test_multi_domain_fri_folds_gaps_and_accepts_varying_widths() -> None:
    batches = (
        FriDomainBatch(5, ((_fp16(2), _fp16(11)),) * 32),
        FriDomainBatch(3, ((_fp16(13),),) * 8),
        FriDomainBatch(2, ((_fp16(17), _fp16(19), _fp16(23)),) * 4),
    )
    masks = (
        FriDomainBatch(5, ((_fp16(19),),) * 32),
        FriDomainBatch(3, ((_fp16(23),),) * 8),
        FriDomainBatch(2, ((_fp16(29),),) * 4),
    )
    cascade = build_fri_cascade(
        batches,
        batch_masks=masks,
        batch_coefficient=_fp16(3),
        fold_coefficients=(_fp16(5), _fp16(7), _fp16(11), _fp16(13)),
    )

    first_batched = 19 + 3 * 2 + 3**2 * 11
    second_batched = 23 + 3**3 * 13
    third_batched = 29 + 3**4 * 17 + 3**5 * 19 + 3**6 * 23
    first_folded = 2 * first_batched
    gap_folded = 2 * first_folded
    second_folded = 11**2 * 2 * gap_folded + 2 * second_batched
    third_folded = 13**2 * 2 * second_folded + 2 * third_batched

    assert cascade.domain_log_sizes == (5, 3, 2)
    assert cascade.fold_log_sizes == (5, 4, 3, 2)
    assert cascade.batch_column_counts == (2, 1, 3)
    assert cascade.batch_power_offsets == (0, 2, 3)
    assert cascade.batched_domains[0] == (_fp16(first_batched),) * 32
    assert cascade.batched_domains[1] == (_fp16(second_batched),) * 8
    assert cascade.batched_domains[2] == (_fp16(third_batched),) * 4
    assert tuple(map(len, cascade.folded_layers)) == (16, 8, 4, 2)
    assert cascade.folded_layers[0] == (_fp16(first_folded),) * 16
    assert cascade.folded_layers[1] == (_fp16(gap_folded),) * 8
    assert cascade.folded_layers[2] == (_fp16(second_folded),) * 4
    assert cascade.folded_layers[3] == (_fp16(third_folded),) * 2
    assert cascade.final_line_evaluation == (_fp16(third_folded),) * 2
