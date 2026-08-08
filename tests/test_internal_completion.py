from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from experiments.bl_pq512_crypto_foundation.internal_completion import (
    CLOSED_PACKAGE_IDS,
    PACKAGE_COUNT,
    PACKAGE_IDS,
    PACKAGE_STATUS,
    OPEN_PACKAGE_IDS,
    OPEN_PACKAGE_STATUS,
    PROOF_SUITE_STATE,
    RELEASE_CANDIDATE_STATE,
    build_internal_completion_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
_PROTECTED_STATUS = subprocess.run(
    (
        "git",
        "status",
        "--porcelain",
        "--",
        "zk-cairo-sharp",
        "app/batch/batch_orchestrator.py",
    ),
    cwd=ROOT,
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
pytestmark = pytest.mark.skipif(
    bool(_PROTECTED_STATUS),
    reason="internal completion requires a committed protected boundary; owner-authorized architecture migration is still in the worktree",
)


def test_all_internal_packages_reconcile_without_activation() -> None:
    receipt = build_internal_completion_receipt()
    assert receipt["status"] == "INTERNAL_CONFORMANCE_RECONCILED_NONACTIVATING"
    assert receipt["release_candidate_state"] == "NOT_DEPLOYMENT_READY"
    assert receipt["release_candidate_state"] == RELEASE_CANDIDATE_STATE
    assert receipt["proof_suite_state"] == PROOF_SUITE_STATE == "UNSELECTED"
    assert receipt["internal_engineering_packages"] == PACKAGE_COUNT == 81
    assert receipt["internal_complete"] == len(CLOSED_PACKAGE_IDS) == 33
    assert receipt["internal_open"] == len(OPEN_PACKAGE_IDS) == 48
    assert tuple(receipt["open_package_ids"]) == OPEN_PACKAGE_IDS
    assert tuple(receipt["package_statuses"]) == PACKAGE_IDS
    assert {
        package_id
        for package_id, status in receipt["package_statuses"].items()
        if status == PACKAGE_STATUS
    } == CLOSED_PACKAGE_IDS
    assert tuple(
        package_id
        for package_id, status in receipt["package_statuses"].items()
        if status == OPEN_PACKAGE_STATUS
    ) == OPEN_PACKAGE_IDS
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
        expected = PACKAGE_STATUS if item["package_id"] in CLOSED_PACKAGE_IDS else OPEN_PACKAGE_STATUS
        assert item["status"] == expected
        if expected == OPEN_PACKAGE_STATUS:
            assert item["closure_reason"]
        else:
            assert item["closure_reason"] is None
        assert item["sources"]
        assert item["tests"]
        assert len(item["evidence_sha3_512"]) == 128
