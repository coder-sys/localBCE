from __future__ import annotations

import json
from pathlib import Path

from tools.wave2_internal_conformance import build_receipt


ROOT = Path(__file__).resolve().parents[1]


def test_wave2_internal_conformance_receipt_is_local_and_fail_closed() -> None:
    receipt = build_receipt(ROOT)
    assert receipt["internal_only"] is True
    assert receipt["network_access"] is False
    assert receipt["live_credentials"] is False
    assert receipt["activation_allowed"] is False
    assert receipt["proofSuiteId"] is None
    assert receipt["privacy"]["reference_boundary_ok"] is True  # type: ignore[index]
    assert receipt["privacy"]["h6_candidate_controls_ok"] is True  # type: ignore[index]
    assert receipt["custody"]["software_kms_roundtrip"] is True  # type: ignore[index]
    assert all(profile["fixed_shape"] for profile in receipt["profiles"])  # type: ignore[index]
    encoded = json.dumps(receipt, sort_keys=True)
    assert "approvedAmountCents" not in encoded
    assert "paymentAmountCents" not in encoded
    assert '"witness":' not in encoded


def test_wave2_release_profile_matches_the_internal_receipt_boundary() -> None:
    profile = json.loads(
        (ROOT / "ops" / "wave2_internal_release_profile.json").read_text(encoding="utf-8")
    )
    assert profile["public_boundary"] == {
        "field_count": 12,
        "sidecar_bytes": 744,
        "proof_body_grammar": "BLPQPF01_REFERENCE_ONLY",
    }
    assert profile["production_usable"] is False
    assert profile["proofSuiteId"] is None
    assert profile["activation_allowed"] is False
    assert profile["network_access"] is False
    assert profile["live_credentials"] is False
    assert profile["package_evidence"]["T13"] == (
        "not_run_reference_path_not_qualification_benchmark"
    )
