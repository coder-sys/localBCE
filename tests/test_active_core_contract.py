from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACTIVE_OWNER_ROOTS = (
    ROOT / "app" / "governance",
    ROOT / "app" / "mirror",
    ROOT / "experiments" / "native_v3_phase0",
    ROOT / "experiments" / "native_v3_plaintext_continuity",
    ROOT / "experiments" / "native_v3_trust_boundary",
)
RETIRED_IMPORT_PREFIXES = (
    "app.privacy_v2",
    "experiments.fixed_k_privacy_v2",
    "experiments.fixed_shape_claim_air",
    "experiments.bl_pq512_crypto_foundation",
    "experiments.bl_pq512_crypto_core",
)


def _python_files() -> list[Path]:
    return sorted(
        path
        for root in ACTIVE_OWNER_ROOTS
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_current_owner_modules_do_not_import_retired_compatibility_lanes() -> None:
    paths = _python_files()
    assert paths
    violations = {
        f"{path.relative_to(ROOT)} -> {module}"
        for path in paths
        for module in _imported_modules(path)
        if any(
            module == prefix or module.startswith(prefix + ".")
            for prefix in RETIRED_IMPORT_PREFIXES
        )
    }
    assert not violations


def test_current_authority_keeps_the_nonpayment_nonproof_boundary() -> None:
    architecture = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
    state = (ROOT / "STATE.md").read_text(encoding="utf-8")
    native = (ROOT / "docs" / "NATIVE_V3_ARCHITECTURE.md").read_text(encoding="utf-8")
    database = (ROOT / "docs" / "DATABASE_ZK_ARCHITECTURE.md").read_text(encoding="utf-8")
    continuity = (ROOT / "docs" / "NATIVE_V3_PLAINTEXT_CONTINUITY.md").read_text(encoding="utf-8")

    assert "state-side payment-clearance" in architecture
    assert "Proof/session acceptance never means `CLEAR`" in state
    assert "It is not the old 12-field `bytes32` ABI" in native
    assert "No payment state transition occurs inside Blind Ledger" in database
    assert "does not expose a Blind Ledger clearance receipt" in architecture
    assert "internal Blind Ledger conformance harness" in continuity


def test_current_authority_keeps_private_run_and_resource_claims_closed() -> None:
    state = (ROOT / "STATE.md").read_text(encoding="utf-8")
    native = (ROOT / "docs" / "NATIVE_V3_ARCHITECTURE.md").read_text(encoding="utf-8")

    assert "No production proof backend is selected." in state
    assert "`proofSuiteId=null`" in state
    assert "`production_usable=false`" in state
    assert "Complete prover process-tree peak resident memory is at most 5,000,000,000" in native
    assert "Do not begin another synthetic exact-K128 hash bakeoff" in native
