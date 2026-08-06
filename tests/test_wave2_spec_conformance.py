from __future__ import annotations

from pathlib import Path

from tools.wave2_spec_conformance import build_receipt


def test_wave2_spec_packages_close_only_at_nonactivating_candidate_boundary() -> None:
    receipt = build_receipt(Path(__file__).resolve().parents[1])
    assert receipt["status"] == "WAVE2_SPECIFICATION_CONFORMANCE_VERIFIED_NONACTIVATING"
    assert set(receipt["package_status"]) == {
        "S02",
        "S04",
        "S07",
        "S08",
        "S09",
        "S10",
        "S11",
        "S12",
    }
    assert all(status == "COMPLETE_INTERNAL_NONACTIVATING" for status in receipt["package_status"].values())
    assert receipt["sidecar_bytes"] == 744
    assert receipt["receipt_bytes"] == 512
    assert receipt["security_ledger_qualifies"] is True
    assert receipt["proofSuiteId"] is None
    assert receipt["activationAllowed"] is False
    assert receipt["productionUsable"] is False
