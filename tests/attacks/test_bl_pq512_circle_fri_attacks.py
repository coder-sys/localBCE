from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.circle_fri_reference import (
    FriDomainBatch,
    build_fri_cascade,
    canonic_circle_point,
    degree_corrected_row,
    verify_degree_corrected_row,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    CirclePoint,
    OodsParameter,
    stereographic_circle_point,
)


def _fp16(value: int) -> Fp16:
    return Fp16((value,) + (0,) * 15)


def _valid_case():
    query = stereographic_circle_point(OodsParameter(Fp16((0,) * 8 + (1,) + (0,) * 7)))
    point = canonic_circle_point(6, 9)
    claim = _fp16(23)
    original = _fp16(41)
    row = degree_corrected_row(
        domain_point=point,
        query=query,
        original_values=(original,),
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )
    return query, point, claim, row


def test_quotient_original_claim_and_domain_substitutions_are_rejected() -> None:
    query, point, claim, row = _valid_case()
    assert verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=row,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )

    bad_quotient = replace(row, quotient_values=(row.quotient_values[0] + Fp16.one(),))
    bad_original = replace(row, original_values=(row.original_values[0] + Fp16.one(),))
    assert not verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=bad_quotient,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )
    assert not verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=bad_original,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )
    assert not verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=row,
        claimed_query_values=(claim + Fp16.one(),),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )
    assert not verify_degree_corrected_row(
        domain_point=point,
        query=query,
        row=row,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate() + Fp16.one(),),
    )
    assert not verify_degree_corrected_row(
        domain_point=canonic_circle_point(6, 10),
        query=query,
        row=row,
        claimed_query_values=(claim,),
        claimed_conjugate_query_values=(claim.conjugate(),),
    )


def test_noncircle_and_fixed_subfield_queries_fail_closed() -> None:
    _, point, claim, row = _valid_case()
    with pytest.raises(ValueError, match="not_on_circle"):
        verify_degree_corrected_row(
            domain_point=point,
            query=CirclePoint(_fp16(2), _fp16(2)),
            row=row,
            claimed_query_values=(claim,),
            claimed_conjugate_query_values=(claim.conjugate(),),
        )
    with pytest.raises(ValueError, match="fixed_subfield"):
        verify_degree_corrected_row(
            domain_point=point,
            query=CirclePoint(Fp16.one(), Fp16.zero()),
            row=row,
            claimed_query_values=(claim,),
            claimed_conjugate_query_values=(claim.conjugate(),),
        )


def test_mismatched_claim_count_fails_closed() -> None:
    query, point, _, row = _valid_case()
    with pytest.raises(ValueError, match="column_count_mismatch"):
        verify_degree_corrected_row(
            domain_point=point,
            query=query,
            row=row,
            claimed_query_values=(),
            claimed_conjugate_query_values=(Fp16.one(),),
        )


def test_fri_cascade_rejects_domain_order_and_challenge_mismatches() -> None:
    valid_large = FriDomainBatch(4, ((_fp16(1), _fp16(2)),) * 16)
    skipped = FriDomainBatch(2, ((_fp16(3), _fp16(4)),) * 4)
    large_mask = FriDomainBatch(4, ((_fp16(13),),) * 16)
    skipped_mask = FriDomainBatch(2, ((_fp16(19),),) * 4)
    with pytest.raises(ValueError, match="not_strictly_descending"):
        build_fri_cascade(
            (skipped, valid_large),
            batch_masks=(skipped_mask, large_mask),
            batch_coefficient=_fp16(5),
            fold_coefficients=(_fp16(7), _fp16(11), _fp16(13)),
        )
    with pytest.raises(ValueError, match="coefficient_count_mismatch"):
        build_fri_cascade(
            (valid_large, skipped),
            batch_masks=(large_mask, skipped_mask),
            batch_coefficient=_fp16(5),
            fold_coefficients=(_fp16(7), _fp16(11)),
        )
    with pytest.raises(ValueError, match="batch_mask_count_mismatch"):
        build_fri_cascade(
            (valid_large,),
            batch_masks=(),
            batch_coefficient=_fp16(5),
            fold_coefficients=(_fp16(7),),
        )
    with pytest.raises(ValueError, match="batch_mask_shape_mismatch"):
        build_fri_cascade(
            (valid_large,),
            batch_masks=(FriDomainBatch(4, ((_fp16(1), _fp16(2)),) * 16),),
            batch_coefficient=_fp16(5),
            fold_coefficients=(_fp16(7),),
        )
