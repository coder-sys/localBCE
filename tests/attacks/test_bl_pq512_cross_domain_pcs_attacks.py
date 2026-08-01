from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.cross_domain_pcs_reference import (
    CommitmentStage,
    CrossDomainLayout,
    CrossDomainTree,
    DomainEvaluationBatch,
    DomainSpec,
    EvaluationField,
    build_fri_batch_mask_tree,
)
from experiments.bl_pq512_crypto_foundation.circle_fri_reference import FriDomainBatch
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16, M31_MODULUS


def _fixture() -> CrossDomainTree:
    small = DomainSpec(2, EvaluationField.M31, 1)
    large = DomainSpec(3, EvaluationField.M31, 1)
    layout = CrossDomainLayout(CommitmentStage.MAIN_TRACE, bytes([0xA5]) * 64, (small, large))
    return CrossDomainTree.build(
        layout,
        tuple(
            DomainEvaluationBatch(
                spec,
                tuple((row + 1).to_bytes(4, "big") for row in range(1 << spec.log_size)),
            )
            for spec in (small, large)
        ),
    )


def test_payload_sibling_index_and_layout_substitution_fail() -> None:
    tree = _fixture()
    proof = tree.proof(5)

    openings = list(proof.openings)
    openings[0] = replace(openings[0], payload=bytes([1]) + openings[0].payload[1:])
    assert not replace(proof, openings=tuple(openings)).verify(tree.layout, tree.root)

    siblings = list(proof.siblings)
    siblings[0] = bytes([siblings[0][0] ^ 1]) + siblings[0][1:]
    assert not replace(proof, siblings=tuple(siblings)).verify(tree.layout, tree.root)

    openings = list(proof.openings)
    openings[0] = replace(openings[0], fft_index=openings[0].fft_index ^ 1)
    with pytest.raises(ValueError, match="opening_index_mismatch"):
        replace(proof, openings=tuple(openings)).verify(tree.layout, tree.root)

    altered = CrossDomainLayout(
        CommitmentStage.INTERACTION_TRACE,
        tree.layout.commitment_id,
        tree.layout.specs,
    )
    assert not proof.verify(altered, tree.root)


def test_malformed_shapes_and_noncanonical_fields_fail_before_hashing() -> None:
    spec = DomainSpec(2, EvaluationField.M31, 1)
    with pytest.raises(ValueError, match="row_count_mismatch"):
        DomainEvaluationBatch(spec, (bytes(4),) * 3)
    with pytest.raises(ValueError, match="row_length_mismatch"):
        DomainEvaluationBatch(spec, (bytes(3),) * 4)
    with pytest.raises(ValueError, match="m31_not_canonical"):
        DomainEvaluationBatch(spec, (M31_MODULUS.to_bytes(4, "big"),) * 4)
    with pytest.raises(ValueError, match="not_strictly_increasing"):
        CrossDomainLayout(CommitmentStage.MAIN_TRACE, bytes([1]) * 64, (spec, spec))


def test_fri_batch_mask_commitment_rejects_missing_wide_and_duplicate_domains() -> None:
    fp16 = lambda value: Fp16((value,) + (0,) * 15)
    valid = FriDomainBatch(3, ((fp16(1),),) * 8)
    wide = FriDomainBatch(3, ((fp16(1), fp16(2)),) * 8)
    with pytest.raises(ValueError, match="batch_masks_required"):
        build_fri_batch_mask_tree(commitment_id=bytes([1]) * 64, batch_masks=())
    with pytest.raises(ValueError, match="must_have_one_column"):
        build_fri_batch_mask_tree(
            commitment_id=bytes([1]) * 64, batch_masks=(wide,)
        )
    with pytest.raises(ValueError, match="domain_duplicate"):
        build_fri_batch_mask_tree(
            commitment_id=bytes([1]) * 64, batch_masks=(valid, valid)
        )
