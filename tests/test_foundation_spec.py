
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "docs" / "BL_PQ512_FOUNDATION_SPEC.md"
BASELINE_PATH = ROOT / "docs" / "SUPPLY_CHAIN_BASELINE.md"
SBOM_PATH = ROOT / "docs" / "SBOM.foundation.spdx.json"
ABI_PATH = ROOT / "ops" / "native_stark_public_inputs_v2.json"
REJECTION_PATH = ROOT / "docs" / "REJECTED_ARCHITECTURES.md"
CURRENT_STACK_PATH = ROOT / "docs" / "CURRENT_TECH_STACK.md"
ROADMAP_PATH = ROOT / "docs" / "IMPLEMENTATION_ROADMAP.md"
STATE_PLAN_PATH = ROOT / "docs" / "BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md"
DATABASE_ARCHITECTURE_PATH = ROOT / "docs" / "DATABASE_ZK_ARCHITECTURE.md"
ACTIVE_HANDOFF_PATHS = (
    ROADMAP_PATH,
    ROOT / "docs" / "BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md",
    ROOT / "docs" / "BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md",
    ROOT / "docs" / "PROVING_OPTIMIZATION_REVIEW.md",
    ROOT / "experiments" / "bl_pq512_crypto_core" / "README.md",
)
HISTORY_INDEX_PATH = ROOT / "docs" / "history" / "README.md"

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

EXPECTED_FORBIDDEN = [
    "approvedAmountCents",
    "paymentAmountCents",
    "claimCount",
    "approvedCount",
    "deniedCount",
    "encryptedPayload",
]

EXPECTED_INPUT_HASHES = {
    "requirements.txt": "EDA95DF33668EC01F5E2510B7AA75FEB03A00F481F156D0A655D988D15BDC140",
    "requirements-dev.txt": "A661109F7B40536E8E338C722E1F3D34B01711FE099618924016D86F70478FA3",
    "requirements/inputs/production.in": (
        "2050A155100500D97530DA85D2205EEDDD08FE5CA64702FE8AF12DB256A48902"
    ),
    "requirements/inputs/development.in": (
        "F33E88E3CFA20BDDEA42CCA8C32B862896EE8F5F006D556E194B90BB093C54B8"
    ),
    "requirements/locks/cp314-linux_x86_64-development.lock": (
        "8621000886C629D35D6B6F87952C344609114CC80ECF9F92A27B1335A3D80ABC"
    ),
    "requirements/locks/cp314-linux_x86_64-production.lock": (
        "081C3FE192E59A51B63ECD8C727D0A33217319C74D1C661B31BAE522C16C7ED4"
    ),
    "requirements/locks/cp314-win_amd64-development.lock": (
        "75890E1EA4529BCD9F64AA6B4EB1050ECAFAC333D7CFCCCB00DC5FB988E52729"
    ),
    "requirements/locks/cp314-win_amd64-production.lock": (
        "02A78AF3E0AA561BBECE3EC9F564568E13150B2CEFF90A8B7198DB27DAF9DBC8"
    ),
    "requirements/locks/python-artifacts.lock.json": (
        "877771819CAE97CA055C1654099CB1A4296DE3A93C517BFFEAB1843CCE75BB26"
    ),
    "docs/SBOM.python.spdx.json": (
        "5B50546F69C55CCC65B869598BF5200A7F261DFBA5D5C92514801159820C7EB7"
    ),
    "rules-engine-rust/Cargo.lock": "41F3EA56CF81155CFFBF915A52DB129686EA62B497DC6057676079BEB7B43068",
    "app/batch/poseidon_helper/Cargo.lock": (
        "16361544525B678209E42802CB3D8B7AC0F682D54AA6AE2B98125377AD8AC8D0"
    ),
    "experiments/bl_pq512_crypto_core/Cargo.lock": (
        "D607C77AD4DCD384A848FB514145B44A862731A983580397354BE157B91B9360"
    ),
    "zk-cairo-sharp/Scarb.lock": (
        "FF53F3FF8C739DFE844C38E2A72347AAEAAE257F27BCCDC2217938B60BD19588"
    ),
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _governed_source_locks() -> list[str]:
    excluded_directories = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "cache",
        "node_modules",
        "target",
    }
    observed: list[str] = []
    for directory, child_directories, filenames in os.walk(ROOT):
        child_directories[:] = sorted(
            name for name in child_directories if name not in excluded_directories
        )
        for filename in sorted(filenames):
            if filename in {"Cargo.lock", "Scarb.lock"}:
                observed.append((Path(directory) / filename).relative_to(ROOT).as_posix())
    return sorted(observed)


def _markdown_rows_between(text: str, start_heading: str, end_heading: str) -> list[list[str]]:
    section = text.split(start_heading, 1)[1].split(end_heading, 1)[0]
    rows: list[list[str]] = []
    for line in section.splitlines():
        if not line.startswith("|") or set(line.replace("|", "").strip()) <= {"-", ":", " "}:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] not in {"Index", "Field"}:
            rows.append(cells)
    return rows


def test_external_abi_manifest_and_foundation_table_are_exact() -> None:
    manifest = json.loads(_read(ABI_PATH))
    observed = [
        (field["index"], field["name"], field["solidity_type"])
        for field in manifest["fields"]
    ]
    assert observed == EXPECTED_ABI
    assert manifest["forbidden_public_fields"] == EXPECTED_FORBIDDEN

    spec = _read(SPEC_PATH)
    rows = _markdown_rows_between(spec, "## S03: preserved external ABI", "## S04:")
    abi_rows = [row for row in rows if row[0].isdigit()]
    assert [
        (int(row[0]), row[1].strip("`"), row[2].strip("`")) for row in abi_rows
    ] == EXPECTED_ABI
    for forbidden in EXPECTED_FORBIDDEN:
        assert f"`{forbidden}`" in spec


def test_claim_language_is_gated_and_does_not_assert_current_security() -> None:
    spec = _read(SPEC_PATH)
    assert "The selected target profile label is exactly `BL-PQ512-v1`." in spec
    assert "Privacy V2 12-field application ABI secured by `BL-PQ512-v1`." in spec
    assert "not yet\n> implemented, cryptographically qualified, independently audited" in spec
    assert "No numeric\nsecurity budget is asserted" in spec
    assert "TBD-S07" in spec
    assert "TBD-S08" in spec
    assert "TBD-S09" in spec
    assert "This earlier foundation draft did not select them." in spec
    assert "BL_PQ512_S09_INTERNAL_SOLUTION.md" in spec
    assert "interactive public-coin construction direction" in spec
    assert "`proofSuiteId` fail-closed" in spec


def test_sidecar_is_metadata_not_proof_and_pins_the_review_ready_candidate_inventory() -> None:
    spec = _read(SPEC_PATH)
    sidecar = spec.split("## S04:", 1)[1].split("## S05:", 1)[0]
    assert "fixed-shape authenticated **metadata sidecar**" in sidecar
    assert "separate opaque **proof body**" in sidecar
    assert "`zkProof` is not a field inside the metadata sidecar" in sidecar
    assert "`verifierArtifactIdentity`" in sidecar
    assert "`strongSettlementDomainId`" in sidecar
    assert "`strongPaymentStateRootBefore`" in sidecar
    assert "`strongPaymentStateRootAfter`" in sidecar
    assert "`proofSuiteId`" in sidecar
    assert "deliberately `null` in the unqualified registry" in sidecar
    assert "744-byte format candidate" in sidecar


def test_threat_matrix_and_exact_twelve_field_notion_rows_are_present() -> None:
    spec = _read(SPEC_PATH)
    for threat in (
        "Malicious prover",
        "Compromised proving worker",
        "Metadata inference",
        "Quantum attacker",
        "Parser disagreement",
        "Governance compromise",
        "Build/dependency compromise",
        "High-capacity batching",
        "Verifier/state-owner split",
        "Oracle or KMS insider",
        "Relayer and resource abuse",
        "Recovery ambiguity",
        "Direct state-publication gap",
    ):
        assert f"| {threat} |" in spec

    notion_rows = _markdown_rows_between(spec, "## S06:", "### S07 handoff ledger")
    fields = [row[0].strip("`") for row in notion_rows]
    assert fields == [name for _, name, _ in EXPECTED_ABI]
    notion_header = spec.split("## S06:", 1)[1].splitlines()
    table_header = next(line for line in notion_header if line.startswith("| Field |"))
    assert table_header == (
        "| Field | Equality purpose | Replay purpose | Target-preimage reliance | "
        "Second-preimage reliance | Arbitrary-collision reliance | Hiding purpose | Strong authority |"
    )
    for row in notion_rows:
        assert len(row) == 8
    for name in (
        "nullifierRootBefore",
        "nullifierRootAfter",
        "claimSourceRoot",
        "oracleFactsRoot",
        "policyRoot",
        "rulesetRoot",
        "opaqueBatchCommitment",
        "valueConservationCommitment",
        "settlementCommitment",
    ):
        row = notion_rows[[item[0].strip("`") for item in notion_rows].index(name)]
        assert "MUST NOT be strict-PQ anchor" in row[5]

    handoff_rows = _markdown_rows_between(spec, "### S07 handoff ledger", "## S10:")
    assert [row[0].strip("`") for row in handoff_rows] == [
        name for _, name, _ in EXPECTED_ABI
    ]
    handoff_section = spec.split("### S07 handoff ledger", 1)[1].split("## S10:", 1)[0]
    handoff_header = next(line for line in handoff_section.splitlines() if line.startswith("| Field |"))
    assert handoff_header == (
        "| Field | Attacker influence | Lifetime/target treatment | Authoritative value | "
        "Failure consequence |"
    )
    assert all(len(row) == 5 for row in handoff_rows)
    assert all(row[1] and row[2] and row[3] and row[4] for row in handoff_rows)


def test_lifecycle_draft_is_provisional_complete_in_scope_and_non_activating() -> None:
    spec = _read(SPEC_PATH)
    lifecycle = spec.split("## S10:", 1)[1]
    assert "**exact local lifecycle candidate; no live-state operation authorized.**" in lifecycle
    assert "S10 remains open" in lifecycle
    for phase in (
        "Genesis draft",
        "Migration preparation",
        "Activation preflight",
        "Atomic activation",
        "Normal transition",
        "Upgrade",
        "Pre-activation rollback",
        "Post-activation recovery",
        "Mixed-profile rejection",
    ):
        assert phase in lifecycle
    for unresolved in ("TBD-S07", "TBD-S08", "TBD-S09", "A11/P05", "P07-P10"):
        assert unresolved in lifecycle


def test_supply_chain_hashes_match_current_source_bytes_and_documented_values() -> None:
    baseline = _read(BASELINE_PATH)
    for relative, expected in EXPECTED_INPUT_HASHES.items():
        observed = sha256((ROOT / relative).read_bytes()).hexdigest().upper()
        assert observed == expected
        assert f"| `{relative}` | `{expected}` |" in baseline
    assert "NOASSERTION" in baseline
    assert "incomplete and not release evidence" in baseline
    documented_locks = sorted(
        relative
        for relative in EXPECTED_INPUT_HASHES
        if relative.endswith(("Cargo.lock", "Scarb.lock"))
    )
    assert _governed_source_locks() == documented_locks
    assert "three `Cargo.lock` files and one `Scarb.lock`" in baseline


def test_retired_backend_sources_are_absent_and_rejection_evidence_is_pinned() -> None:
    rejection = _read(REJECTION_PATH)
    assert not (ROOT / "experiments" / "risc0_privacy_v2").exists()
    assert not (ROOT / "experiments" / "stwo_batch_air").exists()
    core = ROOT / "experiments" / "bl_pq512_crypto_core"
    for relative in (
        "src/fp16_basefold_hiding.rs",
        "src/bin/zk_basefold_stateless_merkle_benchmark.rs",
        "src/bin/zk_basefold_security_ledger.rs",
        "src/bin/fp16_basefold_security_ledger.rs",
        "src/bin/zk_basefold_query_verifier_benchmark.rs",
        "src/bin/fp16_basefold_query_verifier_benchmark.rs",
        "src/bin/packed_boolean_sumcheck_b64_spike.rs",
    ):
        assert not (core / relative).exists()
    assert "basefold" not in _read(core / "Cargo.toml").lower()
    assert "pub mod fp16_basefold_hiding;" not in _read(core / "src" / "lib.rs")
    for identity in (
        "2D4B81A46864741474432DE6C01FCE0AAA119E7D10F96B29788CB3C0A7C084A7",
        "F8B76FE443668B989FC71C2C310755CC5A79F8C14F292B92F44DEFFD4B1342C6",
        "aeceb74c58184d7886ebd7f34a7453fee714ca40",
        "D8136C780F28D9503E979AA895DAEE51D63B293EE414E739AD1D6FFA660B402F",
        "F245C0DFCB724F1D40DCACE6B3D58C8827F2D647C7CB22FA02A1026F985E62D5",
        "7EFC72ECC6FAB4CF014AD5676200FAB10B7528CB75800C6EF2507C1EC184A342",
        "6FC3AE0CC00EEAC4C08B33D060CE3725438DCDE152DC571E08F3D8E6F86B3B8F",
    ):
        assert identity in rejection


def test_current_stack_and_roadmap_form_a_context_free_execution_contract() -> None:
    stack = _read(CURRENT_STACK_PATH)
    roadmap = _read(ROADMAP_PATH)
    state_plan = _read(STATE_PLAN_PATH)

    for heading in (
        "## Product architecture",
        "## Application and state",
        "## Proof system",
        "## Source and policy trust",
        "## Operational state",
        "## Retained research",
    ):
        assert heading in stack
    for invariant in (
        "12-field Privacy V2 boundary",
        "SHA3-512",
        "M31",
        "Fp16",
        "32.360845",
        "148.861885",
        "proofSuiteId=null",
        "production_usable=false",
    ):
        assert invariant in stack

    required_order = ("## Phase 0", "## Phase 1", "## Phase 2")
    positions = [roadmap.index(marker) for marker in required_order]
    assert positions == sorted(positions)
    assert "All **81 counted packages are internal engineering work**" in roadmap
    assert "No L2" in roadmap
    assert "`proofSuiteId=null`" in roadmap
    assert "This selects the Gate 2E candidate; it is not H5 qualification" in state_plan
    assert "Bind the selected state plane into\n   the actual H4 parent" in state_plan


def test_active_handoff_is_physically_separated_from_dated_execution_history() -> None:
    forbidden_active_headings = (
        "## Historical R24 parallel lanes",
        "## R25 terminal result",
        "## R26 interrupted",
        "## 2026-07-29 Wave 2 PCS architecture correction",
        "## 2026-07-30 Wave 2 H3 prototype closure",
        "## 2026-07-30 Wave 2 H4 K128 functional composition",
        "### Historical 2026-07-28 selection screen",
    )
    for path in ACTIVE_HANDOFF_PATHS:
        text = _read(path)
        assert not any(heading in text for heading in forbidden_active_headings), path
        assert "29.974129" in text and "120.460733" in text

    history_index = _read(HISTORY_INDEX_PATH)
    for archived_name in (
        "IMPLEMENTATION_ROADMAP_THROUGH_2026-08-01.md",
        "BL_PQ512_THROUGHPUT_RECOVERY_PLAN_THROUGH_2026-08-01.md",
        "BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR_THROUGH_2026-08-01.md",
        "BL_PQ512_CRYPTO_CORE_README_THROUGH_2026-08-01.md",
        "PROVING_OPTIMIZATION_REVIEW_THROUGH_2026-08-01.md",
    ):
        assert archived_name in history_index
        assert (HISTORY_INDEX_PATH.parent / archived_name).is_file()

    assert "Never execute" in history_index


def test_database_zk_architecture_is_direct_mandatory_and_fail_closed() -> None:
    architecture = _read(DATABASE_ARCHITECTURE_PATH)
    roadmap = _read(ROADMAP_PATH)

    assert "mandatory zero-knowledge proof" in architecture.lower()
    assert "native verifier" in architecture.lower()
    assert "one atomic database transaction" in architecture.lower()
    assert "Ethereum is not a dependency through Phase 2" in architecture
    assert "No L2" in architecture
    assert "No payment state transition occurs" in architecture
    assert "All **81 counted packages are internal engineering work**" in roadmap
    assert "No L2" in roadmap
    assert "| R01 |" not in roadmap and "| R12 |" not in roadmap


def test_foundation_sbom_is_valid_internal_spdx_inventory_with_honest_unknowns() -> None:
    sbom = json.loads(_read(SBOM_PATH))
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
    forge_std = next(package for package in packages if package["name"] == "forge-std")
    assert forge_std["licenseConcluded"] == "NOASSERTION"
    assert forge_std["licenseDeclared"] == "NOASSERTION"

    known_ids = {"SPDXRef-DOCUMENT", *ids}
    for relationship in sbom["relationships"]:
        assert relationship["spdxElementId"] in known_ids
        assert relationship["relatedSpdxElement"] in known_ids

    serialized = json.dumps(sbom, sort_keys=True)
    assert "INCOMPLETE FOUNDATION DRAFT" in serialized
    assert "NOASSERTION is intentional" in serialized
    assert "BL-PQ512" in _read(BASELINE_PATH)


def test_foundation_artifacts_contain_no_real_data_or_credentials() -> None:
    combined = "\n".join(_read(path) for path in (SPEC_PATH, BASELINE_PATH, SBOM_PATH))
    assert "BEGIN PRIVATE KEY" not in combined
    assert not re.search(r"\b\d{3}-\d{2}-\d{4}\b", combined)
    assert "real PHI" in combined
    assert "synthetic" in combined.lower()
