from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.oracle_layout_optimizer import (
    OracleLayoutCandidate,
)


def test_selected_layout_cannot_delete_authorizations() -> None:
    with pytest.raises(ValueError, match="selected_without_authorizations"):
        OracleLayoutCandidate(
            "bad",
            1,
            49,
            True,
            True,
            True,
            True,
            True,
            None,
        )


@pytest.mark.parametrize(
    "field",
    (
        "fixed_shape",
        "per_claim_leaf_boundary",
        "independent_audit_path",
        "attestation_binds_execution_and_audit",
    ),
)
def test_selected_layout_cannot_delete_hard_boundaries(field: str) -> None:
    baseline = OracleLayoutCandidate(
        "good",
        1,
        50,
        True,
        True,
        True,
        True,
        True,
        None,
    )
    with pytest.raises(ValueError, match="selected_without_hard_requirements"):
        replace(baseline, **{field: False})


def test_selected_layout_cannot_carry_a_rejection_reason() -> None:
    with pytest.raises(ValueError, match="selected_without_hard_requirements"):
        OracleLayoutCandidate(
            "bad",
            1,
            50,
            True,
            True,
            True,
            True,
            True,
            "unsafe",
        )
