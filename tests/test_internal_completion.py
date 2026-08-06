from __future__ import annotations

from experiments.bl_pq512_crypto_foundation.internal_completion import (
    PACKAGE_COUNT,
    PACKAGE_IDS,
    PACKAGE_STATUS,
    PROOF_SUITE_STATE,
    RELEASE_CANDIDATE_STATE,
    build_internal_completion_receipt,
)


def test_all_internal_packages_reconcile_without_activation() -> None:
    receipt = build_internal_completion_receipt()
    assert receipt["status"] == "INTERNAL_ENGINEERING_COMPLETE_NONACTIVATING"
    assert receipt["release_candidate_state"] == RELEASE_CANDIDATE_STATE
    assert receipt["proof_suite_state"] == PROOF_SUITE_STATE == "UNSELECTED"
    assert receipt["internal_engineering_packages"] == PACKAGE_COUNT == 93
    assert receipt["internal_complete"] == 93
    assert receipt["internal_open"] == 0
    assert tuple(receipt["package_statuses"]) == PACKAGE_IDS
    assert set(receipt["package_statuses"].values()) == {PACKAGE_STATUS}
    assert receipt["proofSuiteId"] is None
    assert receipt["activation_allowed"] is False
    assert receipt["production_usable"] is False
    assert receipt["network_access"] is False
    assert receipt["live_credentials"] is False
    assert receipt["external_assurance_open"] == ("LB-002",)
    assert receipt["activation_inputs_open"] == ("LB-003", "LB-004", "LB-005")


def test_every_package_has_existing_source_and_test_ownership() -> None:
    receipt = build_internal_completion_receipt()
    evidence = receipt["package_evidence"]
    assert len(evidence) == PACKAGE_COUNT
    assert tuple(item["package_id"] for item in evidence) == PACKAGE_IDS
    for item in evidence:
        assert item["status"] == PACKAGE_STATUS
        assert item["sources"]
        assert item["tests"]
        assert len(item["evidence_sha3_512"]) == 128
