from __future__ import annotations

from experiments.bl_pq512_crypto_foundation.h6_privacy_boundary import (
    run_h6_privacy_boundary,
)


def test_h6_privacy_boundary_is_fixed_shape_and_fail_closed() -> None:
    result = run_h6_privacy_boundary()
    assert result["fixed_shape_for_all_outcomes"] is True
    assert result["fixed_shape_for_all_malformed_cases"] is True
    assert result["abort_shape_matches_malformed"] is True
    assert result["telemetry_private_payload_absent"] is True
    assert result["zeroization_verified"] is True
    assert result["cleanup_verified"] is True
    assert result["unlinkability_observable_shapes_verified"] is True
    assert result["proofSuiteId"] is None
    assert result["activationAllowed"] is False
