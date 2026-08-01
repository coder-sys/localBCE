from __future__ import annotations

import json
from pathlib import Path

from experiments.bl_pq512_crypto_foundation.cross_domain_pcs_reference import (
    CommitmentStage,
    CrossDomainLayout,
    CrossDomainTree,
    DomainEvaluationBatch,
    DomainSpec,
    EvaluationField,
    build_fri_batch_mask_tree,
    project_circle_fft_index,
    transpose_circle_fft_index,
    inverse_transpose_circle_fft_index,
)
from experiments.bl_pq512_crypto_foundation.circle_fri_reference import FriDomainBatch
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16


ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads(
    (ROOT / "test_data" / "bl_pq512_s09_foundation_vectors.json").read_text(encoding="utf-8")
)


def _rows(log_size: int, columns: int, offset: int) -> tuple[bytes, ...]:
    return tuple(
        b"".join((offset + row * 17 + column).to_bytes(4, "big") for column in range(columns))
        for row in range(1 << log_size)
    )


def _fixture() -> CrossDomainTree:
    small = DomainSpec(2, EvaluationField.M31, 2)
    large = DomainSpec(4, EvaluationField.M31, 1)
    layout = CrossDomainLayout(CommitmentStage.MAIN_TRACE, bytes([0x5A]) * 64, (small, large))
    return CrossDomainTree.build(
        layout,
        (
            DomainEvaluationBatch(small, _rows(2, 2, 100)),
            DomainEvaluationBatch(large, _rows(4, 1, 200)),
        ),
    )


def test_projection_consistent_transposition_is_exhaustive() -> None:
    for log_size in range(2, 13):
        for index in range(1 << log_size):
            transposed = transpose_circle_fft_index(index, log_size)
            assert inverse_transpose_circle_fft_index(transposed, log_size) == index
            projected = project_circle_fft_index(index, log_size)
            assert transpose_circle_fft_index(projected, log_size - 1) == transposed >> 1


def test_cross_domain_root_and_opening_match_rust_kat() -> None:
    kat = VECTORS["crossDomainPcsKat"]
    tree = _fixture()
    assert tree.layout.identity.hex() == kat["layoutIdentityHex"]
    assert tree.root.hex() == kat["rootHex"]
    proof = tree.proof(kat["queryFftIndex"])
    assert [opening.fft_index for opening in proof.openings] == kat["openingFftIndices"]
    assert [sibling.hex() for sibling in proof.siblings] == kat["siblingsHex"]
    assert proof.verify(tree.layout, tree.root)


def test_fri_batch_masks_have_a_typed_shared_commitment_before_batching() -> None:
    fp16 = lambda value: Fp16((value,) + (0,) * 15)
    tree = build_fri_batch_mask_tree(
        commitment_id=bytes([0x6B]) * 64,
        batch_masks=(
            FriDomainBatch(4, tuple((fp16(19 + row),) for row in range(16))),
            FriDomainBatch(3, tuple((fp16(23 + row),) for row in range(8))),
        ),
    )
    assert tree.layout.stage is CommitmentStage.FRI_BATCH_MASK
    assert tuple(spec.log_size for spec in tree.layout.specs) == (3, 4)
    assert all(spec.field is EvaluationField.FP16 for spec in tree.layout.specs)
    assert all(spec.column_count == 1 for spec in tree.layout.specs)
    assert tree.root.hex() == (
        "81c47e0626132b05d1f9095e9f56fa90b37356fd7d8ad4846d644bfe4a3ec825"
        "94e4d3b139fc9490981ca6507e7967bb6688a8bd333fd06fd67ebef76bdaa38e"
    )
    for query in range(16):
        proof = tree.proof(query)
        assert proof.verify(tree.layout, tree.root)
