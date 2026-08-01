from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
FREEZE_PATH = ROOT / "docs" / "BL_PQ512_SECURITY_FREEZE.md"
THREAT_MODEL_PATH = ROOT / "docs" / "BL_PQ512_THREAT_MODEL.md"
HARDENING_ROOT = ROOT / "docs" / "security-freeze" / "BL-PQ512-v1"
HARDENING_PATH = HARDENING_ROOT / "hardening.json"
ABI_PATH = ROOT / "ops" / "native_stark_public_inputs_v2.json"
CANONICAL_OPS_PATH = ROOT.parent / "ops"
MIRRORED_OPS_PATH = ROOT / "ops"
ROADMAP_PATH = ROOT / "docs" / "IMPLEMENTATION_ROADMAP.md"
REJECTION_PATH = ROOT / "docs" / "REJECTED_ARCHITECTURES.md"
SOLIDITY_PATH = ROOT / "contracts" / "src" / "stark" / "StarkBatchSettlementV2.sol"

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


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops() -> None:
    assert _file_hashes(MIRRORED_OPS_PATH) == _file_hashes(CANONICAL_OPS_PATH)


def test_security_freeze_rejects_retired_suite_and_keeps_replacement_nonactivating() -> None:
    freeze = _read(FREEZE_PATH)
    hardening = json.loads(_read(HARDENING_PATH))
    rejection = _read(REJECTION_PATH)

    assert "current S-two parameters rejected" in freeze
    assert "no\nproduction proof suite selected or activated" in freeze
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


def test_threat_model_body_is_preserved_and_snapshot_footer_is_exact() -> None:
    threat_model = _read(THREAT_MODEL_PATH)
    body, footer = threat_model.split("\nRepository:", 1)
    canonical_body = body.rstrip() + "\n"
    assert sha256(canonical_body.encode("utf-8")).hexdigest() == (
        "a452ef36982cf8a2aff478338c7142b2a4629dd457f2716d9cdbdc05c3cedac2"
    )
    assert "Repository:" + footer == (
        "Repository: target_sha256_d77e640ac3f4e6013bf9ef4b711a8d6f94e4f70f03b78efebd06f2473045db10\n"
        "Version: codex-security-snapshot/v1:sha256:"
        "382c02a9a9890251f167f3e28023ae4a2caf67c28ee24075a69b587bb6b9b20e\n\n"
    )


def test_solidity_submission_and_output_mapping_match_the_manifest_exactly() -> None:
    solidity = _read(SOLIDITY_PATH)
    names = [name for _, name, _ in EXPECTED_ABI]

    submission_match = re.search(r"struct Submission\s*\{(?P<body>.*?)\n\s*\}", solidity, re.DOTALL)
    assert submission_match is not None
    assert re.findall(r"\bbytes32\s+([A-Za-z0-9_]+)\s*;", submission_match.group("body")) == names

    outputs_match = re.search(
        r"function _publicOutputs\(.*?\)\s+internal pure returns \(bytes32\[12\] memory outputs\)\s*"
        r"\{(?P<body>.*?)\n\s*\}",
        solidity,
        re.DOTALL,
    )
    assert outputs_match is not None
    assert [
        (int(index), name)
        for index, name in re.findall(
            r"outputs\[(\d+)\]\s*=\s*submission\.([A-Za-z0-9_]+)\s*;",
            outputs_match.group("body"),
        )
    ] == [(index, name) for index, name, _ in EXPECTED_ABI]


def test_roadmap_closure_does_not_change_the_twelve_field_boundary() -> None:
    manifest = json.loads(_read(ABI_PATH))
    observed = [
        (field["index"], field["name"], field["solidity_type"])
        for field in manifest["fields"]
    ]
    assert observed == EXPECTED_ABI

    roadmap = _read(ROADMAP_PATH)
    assert "Packages `S01`, `S03`, `S05`, `S06`, and `A12` are complete" in roadmap
    assert "**6 of 93 internal engineering packages are complete and 87 remain open**" in roadmap
    assert "R25 closes only `Z01`" in roadmap
    assert "This is not a privacy, strict-PQ, full-claim, or production claim" in roadmap
    assert "| S07 |" in roadmap and "R24 corrects the worksheet" in roadmap
    assert "| S08 |" in roadmap and "conclusively rejected" in roadmap
    assert "| S09 |" in roadmap and "`proofSuiteId=null`" in roadmap
