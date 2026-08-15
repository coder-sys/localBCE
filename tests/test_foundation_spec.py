from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
ABI_PATH = ROOT / "ops" / "native_stark_public_inputs_v2.json"
BASELINE_PATH = ROOT / "docs" / "SUPPLY_CHAIN_BASELINE.md"
SBOM_PATH = ROOT / "docs" / "SBOM.foundation.spdx.json"

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

EXPECTED_INPUT_HASHES = {
    "requirements.txt": "EDA95DF33668EC01F5E2510B7AA75FEB03A00F481F156D0A655D988D15BDC140",
    "requirements-dev.txt": "A661109F7B40536E8E338C722E1F3D34B01711FE099618924016D86F70478FA3",
    "requirements/inputs/production.in": "2050A155100500D97530DA85D2205EEDDD08FE5CA64702FE8AF12DB256A48902",
    "requirements/inputs/development.in": "F33E88E3CFA20BDDEA42CCA8C32B862896EE8F5F006D556E194B90BB093C54B8",
    "requirements/locks/cp314-linux_x86_64-development.lock": "8621000886C629D35D6B6F87952C344609114CC80ECF9F92A27B1335A3D80ABC",
    "requirements/locks/cp314-linux_x86_64-production.lock": "081C3FE192E59A51B63ECD8C727D0A33217319C74D1C661B31BAE522C16C7ED4",
    "requirements/locks/cp314-win_amd64-development.lock": "75890E1EA4529BCD9F64AA6B4EB1050ECAFAC333D7CFCCCB00DC5FB988E52729",
    "requirements/locks/cp314-win_amd64-production.lock": "02A78AF3E0AA561BBECE3EC9F564568E13150B2CEFF90A8B7198DB27DAF9DBC8",
    "requirements/locks/python-artifacts.lock.json": "877771819CAE97CA055C1654099CB1A4296DE3A93C517BFFEAB1843CCE75BB26",
    "docs/SBOM.python.spdx.json": "5B50546F69C55CCC65B869598BF5200A7F261DFBA5D5C92514801159820C7EB7",
    "rules-engine-rust/Cargo.lock": "41F3EA56CF81155CFFBF915A52DB129686EA62B497DC6057676079BEB7B43068",
    "app/batch/poseidon_helper/Cargo.lock": "16361544525B678209E42802CB3D8B7AC0F682D54AA6AE2B98125377AD8AC8D0",
    "zk-cairo-sharp/Scarb.lock": "FF53F3FF8C739DFE844C38E2A72347AAEAAE257F27BCCDC2217938B60BD19588",
}

RETIRED_DOCS = (
    "docs/BL_PQ512_FOUNDATION_SPEC.md",
    "docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md",
    "docs/REJECTED_ARCHITECTURES.md",
    "docs/FIXED_SHAPE_CLAIM_AIR_DRAFT.md",
    "docs/DEPLOYMENT_READY_BUILD_CONTRACT.md",
)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_legacy_external_abi_manifest_remains_exact_but_non_governing() -> None:
    manifest = json.loads(ABI_PATH.read_text(encoding="utf-8"))
    observed = [
        (field["index"], field["name"], field["solidity_type"])
        for field in manifest["fields"]
    ]
    assert observed == EXPECTED_ABI
    assert manifest["forbidden_public_fields"] == [
        "approvedAmountCents",
        "paymentAmountCents",
        "claimCount",
        "approvedCount",
        "deniedCount",
        "encryptedPayload",
    ]
    native = _read("docs/NATIVE_V3_ARCHITECTURE.md")
    assert "It is not the old 12-field `bytes32` ABI" in native
    assert "does not carry felt or Poseidon compatibility projections" in native


def test_reviewed_dependency_inputs_retain_exact_source_hashes() -> None:
    for relative, expected in EXPECTED_INPUT_HASHES.items():
        assert sha256((ROOT / relative).read_bytes()).hexdigest().upper() == expected


def test_retired_documents_are_unambiguous_compatibility_markers() -> None:
    for relative in RETIRED_DOCS:
        text = _read(relative)
        assert text.startswith("# Retired architecture evidence")
        assert "not architecture, execution, security, or release authority" in text
        assert "docs/NATIVE_V3_ARCHITECTURE.md" in text


def test_current_documents_form_one_fail_closed_contract() -> None:
    architecture = _read("ARCHITECTURE.md")
    state = _read("STATE.md")
    roadmap = _read("docs/IMPLEMENTATION_ROADMAP.md")
    stack = _read("docs/CURRENT_TECH_STACK.md")
    database = _read("docs/DATABASE_ZK_ARCHITECTURE.md")
    task = _read("CURRENT_TASK.md")

    assert "state-side payment-clearance" in architecture
    assert "system remains the money mover" in architecture
    assert "Proof/session acceptance never means `CLEAR`" in state
    assert "Current private-proof blocker" in roadmap
    assert "No backend is selected" in stack
    assert "No payment state transition occurs inside Blind Ledger" in database
    assert "proofSuiteId=null" in task
    assert "production_usable=false" in task

    combined = "\n".join((architecture, state, roadmap, stack, database, task))
    assert "33 of 81" not in combined
    assert "retained only as historical, differential, or migration" in architecture
    assert "WAVE2_HANDOFF_2026-07-26.md" not in combined


def test_dated_markdown_history_copies_were_removed() -> None:
    history = ROOT / "docs" / "history"
    removed = (
        "IMPLEMENTATION_ROADMAP_THROUGH_2026-08-01.md",
        "BL_PQ512_THROUGHPUT_RECOVERY_PLAN_THROUGH_2026-08-01.md",
        "BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR_THROUGH_2026-08-01.md",
        "BL_PQ512_CRYPTO_CORE_README_THROUGH_2026-08-01.md",
        "PROVING_OPTIMIZATION_REVIEW_THROUGH_2026-08-01.md",
    )
    assert all(not (history / name).exists() for name in removed)
    index = (history / "README.md").read_text(encoding="utf-8")
    assert "Git history and retained source archives preserve their exact bytes" in index


def test_foundation_sbom_is_valid_internal_spdx_inventory_with_honest_unknowns() -> None:
    sbom = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["dataLicense"] == "CC0-1.0"
    assert sbom["documentDescribes"] == ["SPDXRef-Package-Blind-Ledger-App-Layer"]

    packages = sbom["packages"]
    ids = [package["SPDXID"] for package in packages]
    assert len(ids) == len(set(ids))
    assert all(package["filesAnalyzed"] is False for package in packages)
    assert all(package["licenseConcluded"] for package in packages)
    assert all(package["licenseDeclared"] for package in packages)

    versions = {package["name"]: package["versionInfo"] for package in packages}
    assert versions["fastapi"] == "0.136.3"
    assert versions["uvicorn"] == "0.49.0"
    assert versions["cryptography"] == "49.0.0"
    assert versions["pqcrypto"] == "0.4.0"
    assert versions["pytest"] == "9.0.3"
    assert versions["httpx"] == "0.28.1"
    assert versions["bl_pq512_crypto_core"] == "0.1.0"
    assert versions["cairo_execute"] == "NOASSERTION"
    assert versions["forge-std"] == "NOASSERTION"

    known_ids = {"SPDXRef-DOCUMENT", *ids}
    for relationship in sbom["relationships"]:
        assert relationship["spdxElementId"] in known_ids
        assert relationship["relatedSpdxElement"] in known_ids

    serialized = json.dumps(sbom, sort_keys=True)
    assert "INCOMPLETE FOUNDATION DRAFT" in serialized
    assert "NOASSERTION is intentional" in serialized


def test_current_foundation_documents_contain_no_obvious_real_data_or_credentials() -> None:
    combined = "\n".join(
        _read(relative)
        for relative in (
            "docs/SUPPLY_CHAIN_BASELINE.md",
            "docs/CURRENT_TECH_STACK.md",
            "docs/NATIVE_V3_ARCHITECTURE.md",
        )
    )
    assert "BEGIN PRIVATE KEY" not in combined
    assert not re.search(r"\b\d{3}-\d{2}-\d{4}\b", combined)
    assert "PHI" in combined
    assert "synthetic" in combined.lower()
