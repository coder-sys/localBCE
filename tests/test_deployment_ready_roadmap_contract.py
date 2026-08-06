from __future__ import annotations

import json
from pathlib import Path
import re

from experiments.bl_pq512_crypto_foundation.ops_authority import (
    OPS_AUTHORITY_STATUS,
    verify_ops_authority,
)


ROOT = Path(__file__).resolve().parents[1]
ROADMAP = ROOT / "docs" / "IMPLEMENTATION_ROADMAP.md"
CONTRACT = ROOT / "docs" / "DEPLOYMENT_READY_BUILD_CONTRACT.md"
BLOCKERS = ROOT / "ops" / "launch_blockers.json"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _package_rows(roadmap: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in roadmap.splitlines():
        match = re.match(r"^\| ((?:S|A|Z|P|T|O|I|R)\d{2}) \|.*?\| (.*?) \|$", line)
        if match:
            package_id, status = match.groups()
            assert package_id not in rows, f"duplicate roadmap package {package_id}"
            rows[package_id] = status
    return rows


def test_whole_product_roadmap_has_exactly_93_internal_packages() -> None:
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
        *(f"R{i:02d}" for i in range(1, 13)),
    }
    assert len(rows) == 93
    assert set(rows) == expected
    assert {package_id for package_id, status in rows.items() if status.startswith("Complete")} == {
        "S01",
        "S03",
        "S05",
        "S06",
        "A12",
        "Z01",
        *(f"P{i:02d}" for i in range(1, 13)),
        *(f"I{i:02d}" for i in range(1, 9)),
        *(f"O{i:02d}" for i in range(1, 7)),
        "O12",
    }
    assert not {f"O{i:02d}" for i in range(7, 12)} & set(rows)


def test_audit_is_one_uncounted_gate_and_every_package_is_internally_finishable() -> None:
    roadmap = _text(ROADMAP)
    contract = _text(CONTRACT)
    rows = _package_rows(roadmap)

    assert "**33 of 93 internal engineering packages are complete and 60 remain open**" in " ".join(roadmap.split())
    assert "## Final independent Security Audit Gate - not counted" in roadmap
    assert "The five former O07-O11 rows are audit workstreams, not engineering packages" in roadmap
    assert "All **93 counted packages are internal engineering work**" in roadmap
    assert "Government API and oracle adapters - 8 packages" in roadmap
    assert "Containing based rollup and end-to-end deployment - 12 packages" in roadmap

    forbidden_status_phrases = (
        "external gate",
        "external cryptographic review required",
        "external library/kms gate",
        "external infrastructure and governance gate",
        "cannot be closed",
    )
    for package_id, status in rows.items():
        lowered = status.lower()
        assert not any(phrase in lowered for phrase in forbidden_status_phrases), package_id

    assert "UNSELECTED" in contract
    assert "BUILT_AUDIT_PENDING" in contract
    assert "AUDIT_ACCEPTED" in contract
    assert "production_usable` remains `false" in contract
    assert "Live service credentials" in " ".join(contract.split())
    assert "not missing engineering" in contract


def test_launch_blocker_manifest_has_only_one_external_assurance_dependency() -> None:
    assert verify_ops_authority() == OPS_AUTHORITY_STATUS
    payload = json.loads(_text(BLOCKERS))
    planning = payload["planning_model"]
    assert planning == {
        "internal_engineering_packages": 93,
        "internal_complete": 33,
        "internal_open": 60,
        "external_assurance_gates": 1,
        "release_candidate_state": "NOT_DEPLOYMENT_READY",
        "proof_suite_state": "UNSELECTED",
        "production_usable": False,
        "contract": "docs/DEPLOYMENT_READY_BUILD_CONTRACT.md",
    }

    blockers = payload["blockers"]
    external = [item for item in blockers if item["external_required"]]
    assert [(item["id"], item["classification"]) for item in external] == [
        ("LB-002", "security_audit_gate")
    ]

    engineering = [item for item in blockers if item["classification"] == "internal_engineering"]
    assert engineering
    assert all(item["release_candidate_blocker"] for item in engineering)
    assert all(not item["external_required"] for item in engineering)

    activation = [item for item in blockers if item["classification"] == "activation_input"]
    assert {item["id"] for item in activation} == {"LB-003", "LB-004", "LB-005"}
    assert all(not item["release_candidate_blocker"] for item in activation)
    assert all(item["production_activation_blocker"] for item in activation)
