from __future__ import annotations

import json
from pathlib import Path
import re

from experiments.bl_pq512_crypto_foundation.ops_authority import OPS_AUTHORITY_STATUS, verify_ops_authority


ROOT = Path(__file__).resolve().parents[1]
ROADMAP = ROOT / "docs" / "IMPLEMENTATION_ROADMAP.md"
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


def test_phase_two_roadmap_has_exactly_81_surviving_internal_packages() -> None:
    roadmap = _text(ROADMAP)
    rows = _package_rows(roadmap)
    expected = {
        *(f"S{i:02d}" for i in range(1, 13)),
        *(f"A{i:02d}" for i in range(1, 17)),
        *(f"Z{i:02d}" for i in range(1, 13)),
        *(f"P{i:02d}" for i in range(1, 13)),
        *(f"T{i:02d}" for i in range(1, 15)),
        *(f"O{i:02d}" for i in range(1, 7)),
        "O12",
        *(f"I{i:02d}" for i in range(1, 9)),
    }
    assert len(rows) == 81
    assert set(rows) == expected
    assert len({package_id for package_id, status in rows.items() if status.startswith("Complete")}) == 33
    assert len({package_id for package_id, status in rows.items() if status.startswith("Open")}) == 48
    assert "| R01 |" not in roadmap and "| R12 |" not in roadmap


def test_build_contract_preserves_fail_closed_release_lifecycle() -> None:
    roadmap = _text(ROADMAP)
    contract = _text(CONTRACT)
    assert "All **81 counted packages are internal engineering work**" in roadmap
    assert "## Final independent Security Audit Gate - not counted" in roadmap
    assert "No L2" in roadmap
    assert "UNSELECTED" in contract
    assert "BUILT_AUDIT_PENDING" in contract
    assert "AUDIT_ACCEPTED" in contract
    assert "production_usable` remains `false" in contract
    assert "mandatory" in contract.lower() and "zero-knowledge" in contract.lower()


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
    assert open_internal == ["LB-001", "LB-006", "LB-007", "LB-009", "LB-010"]
