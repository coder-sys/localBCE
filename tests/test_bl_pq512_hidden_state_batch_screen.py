from fractions import Fraction

import pytest

from experiments.bl_pq512_hint_mlwe_392.hidden_state_batch_screen import (
    affine_model,
    project_batch,
)


def test_affine_model_preserves_both_unqualified_inputs() -> None:
    fixed, per_claim = affine_model()
    assert fixed == Fraction(2234, 3)
    assert per_claim == Fraction(7, 24)
    assert fixed + 128 * per_claim == 782
    assert fixed + 512 * per_claim == 894


def test_larger_batch_projections_are_conservative_and_labeled() -> None:
    k1024 = project_batch(1_024)
    k2048 = project_batch(2_048)
    assert k1024.sha3_permutations == 1_044
    assert k1024.packed_gates == 60_364_800
    assert k2048.sha3_permutations == 1_342
    assert k2048.packed_gates == 77_414_400
    assert (
        k1024.evidence_class
        == "TWO_POINT_AFFINE_PROJECTION_UNQUALIFIED"
    )
    assert (
        k2048.evidence_class
        == "TWO_POINT_AFFINE_PROJECTION_UNQUALIFIED"
    )


def test_phase_one_projection_requires_positive_measured_rate() -> None:
    result = project_batch(2_048, gates_per_second=9_405_023.31)
    assert result.phase_one_seconds == pytest.approx(8.23117577)
    with pytest.raises(ValueError, match="gates_per_second_must_be_positive"):
        project_batch(2_048, gates_per_second=0)
