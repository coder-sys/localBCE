from __future__ import annotations

from pathlib import Path

from tools.privacy_v2_conformance import build_receipt


def test_privacy_v2_bounded_boundary_is_fixed_shape_and_nonactivating() -> None:
    receipt = build_receipt(Path(__file__).resolve().parents[1])
    assert receipt["status"] == "PRIVACY_V2_BOUNDED_CONFORMANCE_VERIFIED_NONACTIVATING"
    assert receipt["sidecar_bytes"] == 744
    assert receipt["mutation_cases"] == 34
    assert receipt["artifact_findings"] == 0
    assert receipt["private_public_payload"] is False
    assert receipt["proofSuiteId"] is None
    assert receipt["activationAllowed"] is False
    assert receipt["productionUsable"] is False
    assert set(receipt["package_status"]) == {"Z02", "Z11", "Z12"}
