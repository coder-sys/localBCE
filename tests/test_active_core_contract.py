from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "tests"
ACTIVE_OWNER_ROOTS = (
    ROOT / "app" / "governance",
    ROOT / "app" / "mirror",
    ROOT / "experiments" / "native_v3_phase0",
    ROOT / "experiments" / "native_v3_plaintext_continuity",
    ROOT / "experiments" / "native_v3_trust_boundary",
)
TRANSITIVE_SOURCE_ROOTS = (
    ROOT / "app",
    ROOT / "tools",
    ROOT / "experiments" / "native_v3_phase0",
    ROOT / "experiments" / "native_v3_phase0_rust",
    ROOT / "experiments" / "native_v3_plaintext_continuity",
    ROOT / "experiments" / "native_v3_trust_boundary",
    ROOT / "experiments" / "native_v3_trust_boundary_rust",
)
RETIRED_IMPORT_PREFIXES = (
    "app.privacy_v2",
    "experiments.fixed_k_privacy_v2",
    "experiments.fixed_shape_claim_air",
    "experiments.bl_pq512_crypto_foundation",
    "experiments.bl_pq512_crypto_core",
)
RETIRED_CORE_MARKERS = (
    "experiments.bl_pq512_crypto_core",
    "experiments/bl_pq512_crypto_core",
    "experiments\\bl_pq512_crypto_core",
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
        elif isinstance(node, ast.Call):
            function = node.func
            is_import_call = (
                isinstance(function, ast.Name) and function.id == "__import__"
            ) or (
                isinstance(function, ast.Attribute)
                and function.attr == "import_module"
            )
            if is_import_call and node.args:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    modules.add(argument.value)
    return modules


def _resolve_local_module(module: str) -> Path | None:
    if not module.startswith(("app", "experiments", "tools")):
        return None
    relative = Path(*module.split("."))
    candidates = (ROOT / relative.with_suffix(".py"), ROOT / relative / "__init__.py")
    return next((path for path in candidates if path.is_file()), None)


def _resolve_local_test_module(module: str) -> Path | None:
    if module != "tests" and not module.startswith("tests."):
        return None
    relative = Path(*module.split("."))
    candidates = (
        ROOT / relative.with_suffix(".py"),
        ROOT / relative / "__init__.py",
    )
    resolved = next((path for path in candidates if path.is_file()), None)
    if resolved is not None:
        return resolved
    directory = ROOT / relative
    return directory if directory.is_dir() else None


def _transitive_source_files() -> list[Path]:
    return sorted(
        {
            path
            for root in TRANSITIVE_SOURCE_ROOTS
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts
        }
    )


def _transitive_core_violations(paths: list[Path]) -> set[str]:
    pending = list(paths)
    visited: set[Path] = set()
    violations: set[str] = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        source = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        for marker in RETIRED_CORE_MARKERS:
            if marker in source:
                violations.add(f"{relative} contains {marker}")
        for module in _imported_modules(path):
            if any(
                module == prefix or module.startswith(prefix + ".")
                for prefix in ("experiments.bl_pq512_crypto_core",)
            ):
                violations.add(f"{relative} imports {module}")
            resolved = _resolve_local_module(module)
            if resolved is not None:
                pending.append(resolved)
    return violations


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


def test_active_application_transitive_closure_has_no_retired_core_or_pin_reference() -> None:
    paths = _transitive_source_files()
    assert paths
    violations = _transitive_core_violations(paths)
    pin = (ROOT / "ops" / "verifier_artifact_pin.example.json").read_text(
        encoding="utf-8"
    )
    violations.update(
        f"ops/verifier_artifact_pin.example.json contains {marker}"
        for marker in RETIRED_CORE_MARKERS
        if marker in pin
    )
    assert not violations


def test_test_integrity_has_no_unresolved_local_imports_or_duplicate_names() -> None:
    unresolved: set[str] = set()
    duplicates: set[str] = set()
    for path in sorted(TEST_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(
                    alias.name
                    for alias in node.names
                    if alias.name == "tests" or alias.name.startswith("tests.")
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "tests" or node.module.startswith("tests."):
                    imported_modules.add(node.module)
        for module in imported_modules:
            if _resolve_local_test_module(module) is None:
                unresolved.add(f"{path.relative_to(ROOT)} -> {module}")
        names: dict[str, int] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "test_"
            ):
                names[node.name] = names.get(node.name, 0) + 1
        duplicates.update(
            f"{path.relative_to(ROOT)} -> {name} x{count}"
            for name, count in names.items()
            if count > 1
        )
    assert not unresolved, f"unresolved local tests.* imports: {sorted(unresolved)}"
    assert not duplicates, f"duplicate top-level test names: {sorted(duplicates)}"


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
    assert "no K128, K512, production-proof, or scale claim is permitted" in state
    assert "`proofSuiteId=null`" in state
    assert "`production_usable=false`" in state
    assert "Complete prover process-tree peak resident memory is at most 5,000,000,000" in native
    assert "Do not begin another synthetic exact-K128 hash bakeoff" in native


def test_component_benchmark_cannot_qualify_the_private_backend() -> None:
    state = (ROOT / "STATE.md").read_text(encoding="utf-8")
    ideology = (ROOT / "docs" / "DESIGN_IDEOLOGY.md").read_text(encoding="utf-8")

    assert "No production proof backend is selected." in state
    assert "complete bound covering concrete SHA3-512" in state
    assert "A component benchmark, cached proof, clean process exit" in ideology
    assert "cannot become complete-proof credit" in ideology


def test_current_owner_keeps_the_threat_boundary_fail_closed() -> None:
    native = (ROOT / "docs" / "NATIVE_V3_ARCHITECTURE.md").read_text(encoding="utf-8")
    database = (ROOT / "docs" / "DATABASE_ZK_ARCHITECTURE.md").read_text(encoding="utf-8")
    state = (ROOT / "STATE.md").read_text(encoding="utf-8")

    assert "The prover cannot omit an applicable rule" in native
    assert "authoritative completeness/nonmembership" in native
    assert "A verifier failure returns no receipt and no directive" in native
    assert "rechecks the batch nonce, state-before roots" in database
    assert "Proof/session acceptance never means `CLEAR`" in state
    assert "The complete process tree, scratch, and pagefile gates" in state
