from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARDENING_ROOT = ROOT / "docs" / "security-freeze" / "BL-PQ512-v1"
HARDENING_PATH = HARDENING_ROOT / "hardening.json"
ABI_PATH = ROOT / "ops" / "native_stark_public_inputs_v2.json"

EXPECTED_ABI = [
    (0, "protocolVersion", "bytes32"),
    (1, "settlementDomain", "bytes32"),
    (2, "batchNonce", "bytes32"),
    (3, "nullifierRootBefore", "bytes32"),
    (4, "nullifierRootAfter", "bytes32"),
    (5, "claimSourceRoot", "bytes32"),
    (6, "oracleFactsRoot", "bytes32"),
    (7, "policyRoot", "bytes32"),
    (8, "rulesetRoot", "bytes32"),
    (9, "opaqueBatchCommitment", "bytes32"),
    (10, "valueConservationCommitment", "bytes32"),
    (11, "settlementCommitment", "bytes32"),
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_tracked_ops_is_the_exact_commit_bound_authority() -> None:
    from experiments.bl_pq512_crypto_foundation.ops_authority import (
        OPS_AUTHORITY_STATUS,
        verify_ops_authority,
    )

    assert verify_ops_authority() == OPS_AUTHORITY_STATUS


def test_ops_authority_text_preserves_the_current_payment_and_custody_meaning() -> None:
    deployment = _read(ROOT / "ops" / "DEPLOYMENT_RUNBOOK.md")
    checklist = _read(ROOT / "ops" / "PRODUCTION_CONFIG_CHECKLIST.md")
    custody = _read(ROOT / "ops" / "KEY_CUSTODY_AND_ROTATION.md")
    risks = _read(ROOT / "ops" / "RISK_REGISTER.md")
    assert "clearance-state mutation must remain one atomic" in deployment
    assert "official" in deployment and "state payment rails execute the later payment" in deployment
    assert "disabled legacy" in checklist
    assert "not a selected verifier, evaluator, or production backend" in checklist
    assert "Category 1 or stronger" in custody
    assert "only when an explicit deployment threat model calls for it" in custody
    assert "do not establish that the signed facts are" in custody
    assert "dual-PQ only when the approved threat model requires it" in risks


def test_legacy_security_prose_is_retired_while_machine_evidence_remains_nonactivating() -> None:
    hardening = json.loads(_read(HARDENING_PATH))
    assert hardening["status"] == "REJECTED_KERNEL_INTERNAL_REPLACEMENT_SELECTED_S09_OPEN"
    assert hardening["historical_r23_status"] == (
        "CURRENT_CONFIGURATION_REJECTED_REPLACEMENT_REVIEW_REQUIRED"
    )
    assert hardening["constraints"] == {
        "synthetic_only": True,
        "external_abi_fields": 12,
        "abi_change_allowed": False,
        "dependency_upgrade_allowed": False,
        "real_data_allowed": False,
    }
    assert hardening["observed_current_profile"]["library_nominal_bits"] == 13
    assert hardening["observed_current_profile"]["witness_hiding"] is False
    assert not (ROOT / "experiments" / "stwo_batch_air").exists()
    assert not (ROOT / "docs" / "BL_PQ512_SECURITY_FREEZE.md").exists()
    assert not (ROOT / "docs" / "REJECTED_ARCHITECTURES.md").exists()


def test_hardening_machine_artifact_is_snapshot_consistent_and_markdown_is_retired() -> None:
    hardening = json.loads(_read(HARDENING_PATH))
    assert hardening["source_snapshot_sha256"] == (
        "382c02a9a9890251f167f3e28023ae4a2caf67c28ee24075a69b587bb6b9b20e"
    )
    assert {proposal["id"] for proposal in hardening["proposals"]} == {
        "BLH-001",
        "BLH-002",
    }
    for proposal in hardening["proposals"]:
        assert proposal["disposition"] == "git-history-and-retained-archives"
        assert "file" not in proposal


def test_legacy_twelve_field_manifest_is_exact_but_does_not_govern_native_v3() -> None:
    manifest = json.loads(_read(ABI_PATH))
    observed = [
        (field["index"], field["name"], field["solidity_type"])
        for field in manifest["fields"]
    ]
    assert observed == EXPECTED_ABI
    assert "atomic database transition" in manifest["statement"]

    native_v3 = _read(ROOT / "docs" / "NATIVE_V3_ARCHITECTURE.md")
    roadmap = _read(ROOT / "docs" / "IMPLEMENTATION_ROADMAP.md")
    assert "It is not the old 12-field `bytes32` ABI" in native_v3
    assert "does not carry felt or Poseidon compatibility projections" in native_v3
    assert "Retired BL-PQ512/H4 package counts" in roadmap
    assert "proofSuiteId=null" in roadmap
    assert not (
        ROOT / "docs" / "history" / "IMPLEMENTATION_ROADMAP_THROUGH_2026-08-01.md"
    ).exists()
