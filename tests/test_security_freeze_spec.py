from __future__ import annotations

import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
FREEZE_PATH = ROOT / "docs" / "BL_PQ512_SECURITY_FREEZE.md"
THREAT_MODEL_PATH = ROOT / "docs" / "BL_PQ512_THREAT_MODEL.md"
HARDENING_ROOT = ROOT / "docs" / "security-freeze" / "BL-PQ512-v1"
HARDENING_PATH = HARDENING_ROOT / "hardening.json"
ABI_PATH = ROOT / "ops" / "native_stark_public_inputs_v2.json"
ROADMAP_PATH = ROOT / "docs" / "IMPLEMENTATION_ROADMAP.md"
HISTORICAL_ROADMAP_PATH = (
    ROOT / "docs" / "history" / "IMPLEMENTATION_ROADMAP_THROUGH_2026-08-01.md"
)
REJECTION_PATH = ROOT / "docs" / "REJECTED_ARCHITECTURES.md"

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


def test_security_freeze_rejects_retired_suite_and_keeps_replacement_nonactivating() -> None:
    freeze = _read(FREEZE_PATH)
    hardening = json.loads(_read(HARDENING_PATH))
    rejection = _read(REJECTION_PATH)

    assert "S-two proof configuration does not" in freeze
    assert "no production proof\nsuite is selected or activated" in freeze
    assert "More FRI queries or more grinding cannot remove the QM31 field-error terms" in freeze
    assert "M31 degree-16" in freeze
    assert "conditional lead" in freeze.lower()
    assert "external cryptographic review" in freeze.lower()

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
    assert hardening["conditional_lead"]["status"] == (
        "LOCAL_ALGEBRA_AND_PUBLIC_COIN_REFERENCE_KATS_PASSED_PRODUCTION_MODULES_OPEN"
    )
    assert hardening["conditional_lead"]["authoritative_transcript"] == (
        "PQ_AUTHENTICATED_PUBLIC_COIN_INTERACTIVE"
    )
    assert hardening["conditional_lead"]["fiat_shamir_allowed"] is False
    assert hardening["conditional_lead"]["qrom_reduction_required_for_authoritative_mode"] is False
    assert hardening["conditional_lead"]["grinding_security_credit_bits"] == 0

    assert not (ROOT / "experiments" / "stwo_batch_air").exists()
    assert "Official Stwo/QM31/Blake2s experiment" in rejection
    assert "witness_hiding=false" in rejection
    assert "nominally about 13 security bits" in rejection
    assert "D8136C780F28D9503E979AA895DAEE51D63B293EE414E739AD1D6FFA660B402F" in rejection


def test_hardening_artifacts_are_complete_and_snapshot_consistent() -> None:
    hardening = json.loads(_read(HARDENING_PATH))
    context = _read(HARDENING_ROOT / "context.md")
    assert hardening["source_snapshot_sha256"] == (
        "382c02a9a9890251f167f3e28023ae4a2caf67c28ee24075a69b587bb6b9b20e"
    )
    assert (HARDENING_ROOT / "context.md").is_file()
    assert (HARDENING_ROOT / "hardening.md").is_file()
    assert f"Run: `{hardening['run_id']}`" in context
    assert f"`{hardening['source_snapshot_sha256']}`" in context
    for proposal in hardening["proposals"]:
        assert (HARDENING_ROOT / proposal["file"]).is_file()
    assert {proposal["id"] for proposal in hardening["proposals"]} == {
        "BLH-001",
        "BLH-002",
    }


def test_threat_model_matches_database_and_mandatory_zk_boundary() -> None:
    threat_model = _read(THREAT_MODEL_PATH)
    assert "native verifier result is committed atomically" in threat_model
    assert "Serializable transaction" in threat_model
    assert "No L2 is treated as a mitigating boundary" in threat_model
    assert "proofSuiteId=null" in threat_model


def test_direct_state_manifest_matches_the_frozen_abi_exactly() -> None:
    manifest = json.loads(_read(ABI_PATH))
    assert [
        (field["index"], field["name"], field["solidity_type"])
        for field in manifest["fields"]
    ] == EXPECTED_ABI
    assert "atomic database transition" in manifest["statement"]


def test_roadmap_closure_does_not_change_the_twelve_field_boundary() -> None:
    manifest = json.loads(_read(ABI_PATH))
    observed = [
        (field["index"], field["name"], field["solidity_type"])
        for field in manifest["fields"]
    ]
    assert observed == EXPECTED_ABI

    roadmap = _read(ROADMAP_PATH)
    assert "All **81 counted packages are internal engineering work**" in roadmap
    assert "No L2" in roadmap
    assert "| S07 |" in roadmap
    assert "| S08 |" in roadmap
    assert "| S09 |" in roadmap
    assert "`proofSuiteId=null`" in roadmap

    historical = _read(HISTORICAL_ROADMAP_PATH)
    assert "R24 corrects the worksheet" in historical
    assert "conclusively rejected" in historical
    assert "Status: authoritative current execution plan" not in historical
