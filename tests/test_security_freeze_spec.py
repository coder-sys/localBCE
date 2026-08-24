from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARDENING_ROOT = ROOT / "docs" / "security-freeze" / "BL-PQ512-v1"
HARDENING_PATH = HARDENING_ROOT / "hardening.json"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_tracked_ops_is_the_exact_commit_bound_authority() -> None:
    from tools.ops_authority import (
        OPS_AUTHORITY_STATUS,
        verify_ops_authority,
    )

    assert verify_ops_authority() == OPS_AUTHORITY_STATUS


def test_ops_authority_text_preserves_the_current_payment_and_custody_meaning() -> None:
    deployment = _read(ROOT / "ops" / "DEPLOYMENT_RUNBOOK.md")
    checklist = _read(ROOT / "ops" / "PRODUCTION_CONFIG_CHECKLIST.md")
    custody = _read(ROOT / "ops" / "KEY_CUSTODY_AND_ROTATION.md")
    risks = _read(ROOT / "ops" / "RISK_REGISTER.md")
    assert "atomic clearance-state" in deployment
    assert "official state payment system" in deployment
    assert "5,000,000,000 decimal-byte floor" in checklist
    assert "require-production" in checklist and "require-activation" in checklist
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
    rejected = ROOT / "docs" / "REJECTED_ARCHITECTURES.md"
    assert rejected.exists()
    assert "BL-PQ512, H4, K128, and K512" in _read(rejected)


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
