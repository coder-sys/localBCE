from __future__ import annotations

import json
from pathlib import Path
import re

from experiments.bl_pq512_crypto_foundation.ops_authority import OPS_AUTHORITY_STATUS, verify_ops_authority


ROOT = Path(__file__).resolve().parents[1]
ROADMAP = ROOT / "docs" / "IMPLEMENTATION_ROADMAP.md"
ARCHITECTURE = ROOT / "ARCHITECTURE.md"
FORMAL_KERNEL = ROOT / "docs" / "LEAN_FORMAL_KERNEL.md"
PLAINTEXT_CONTINUITY = ROOT / "docs" / "NATIVE_V3_PLAINTEXT_CONTINUITY.md"
CONTRACT = ROOT / "docs" / "DEPLOYMENT_READY_BUILD_CONTRACT.md"
BLOCKERS = ROOT / "ops" / "launch_blockers.json"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _package_rows(roadmap: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in roadmap.splitlines():
        match = re.match(r"^\| ((?:S|A|Z|P|T|O|I)\d{2}) \|.*?\| (.*?) \|$", line)
        if match:
            package_id, status = match.groups()
            assert package_id not in rows, f"duplicate roadmap package {package_id}"
            rows[package_id] = status
    return rows


def test_native_v3_roadmap_has_no_retired_package_ledger() -> None:
    roadmap = _text(ROADMAP)
    rows = _package_rows(roadmap)
    assert rows == {}
    assert "Retired BL-PQ512/H4 package counts" in roadmap
    assert "## Completed foundation" in roadmap
    assert "## Current private-proof blocker" in roadmap
    assert "33 of 81" not in roadmap


def test_retired_build_contract_cannot_override_current_fail_closed_roadmap() -> None:
    roadmap = _text(ROADMAP)
    contract = _text(CONTRACT)
    assert contract.startswith("# Retired architecture evidence")
    assert "not architecture, execution, security, or release authority" in contract
    assert "complete theorem ledger" in roadmap
    assert "`proofSuiteId=null`" in roadmap
    assert "`production_usable=false`" in roadmap


def test_lean_kernel_is_an_executable_target_not_a_detached_model() -> None:
    architecture = _text(ARCHITECTURE)
    roadmap = _text(ROADMAP)
    formal = _text(FORMAL_KERNEL)
    assert "## Executable formal kernel" in architecture
    assert "## Later mandatory formal-kernel gate" in roadmap
    assert "This is not the current or next implementation stage" in roadmap
    assert "not a current implementation stage" in formal
    assert "not yet implemented" in formal
    assert "not production credit" in formal
    assert "execute the proved Lean definitions" in formal
    assert "proof_acceptance_ne_clear" in formal
    assert "observe_only_no_operative_clearance" in formal
    assert "absence_requires_authoritative_completeness" in formal
    assert "nonclear_no_economic_mutation" in formal
    assert "canonical_encoding_injective" in formal
    assert "checkpoint_chain_append_only" in formal


def test_commercial_continuity_wedge_cannot_become_clearance_api() -> None:
    architecture = _text(ARCHITECTURE)
    continuity = _text(PLAINTEXT_CONTINUITY)
    assert "The first commercial wedge belongs externally to Mirror's Provider Trust Graph" in architecture
    assert "does not expose a Blind Ledger clearance receipt" in architecture
    assert "internal Blind Ledger conformance harness" in continuity
    assert "without creating an operative" in continuity


def test_launch_blocker_manifest_has_only_one_external_assurance_dependency() -> None:
    assert verify_ops_authority() == OPS_AUTHORITY_STATUS
    payload = json.loads(_text(BLOCKERS))
    planning = payload["planning_model"]
    assert planning["internal_engineering_packages"] == 81
    assert planning["internal_complete"] == 33
    assert planning["internal_open"] == 48
    assert planning["external_assurance_gates"] == 1
    assert planning["release_candidate_state"] == "NOT_DEPLOYMENT_READY"
    assert planning["proof_suite_state"] == "UNSELECTED"
    assert planning["production_usable"] is False

    blockers = payload["blockers"]
    external = [item for item in blockers if item["external_required"]]
    assert [(item["id"], item["classification"]) for item in external] == [("LB-002", "security_audit_gate")]
    assert "LB-008" not in {item["id"] for item in blockers}
    open_internal = [
        item["id"]
        for item in blockers
        if item["classification"] == "internal_engineering"
        and item["status"] == "open"
        and item["release_candidate_blocker"] is True
    ]
    assert open_internal == ["LB-001", "LB-009", "LB-010"]
    lb006 = next(item for item in blockers if item["id"] == "LB-006")
    assert lb006["status"] == "closed_internal_nonactivating"
    assert lb006["release_candidate_blocker"] is False
    assert lb006["production_activation_blocker"] is True
    lb007 = next(item for item in blockers if item["id"] == "LB-007")
    assert lb007["status"] == "closed_internal_nonactivating"
    assert lb007["release_candidate_blocker"] is False
    assert lb007["production_activation_blocker"] is True
