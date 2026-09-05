"""Small deterministic gate for the live Markdown authority tree."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
from typing import Iterable


class DocumentationGovernanceError(RuntimeError):
    """A Markdown registration, ownership, link, or authority failure."""


@dataclass(frozen=True)
class MarkdownRegistration:
    parent: str | None
    role: str
    purpose: str
    independent_authority: bool = False


def _registration(
    parent: str | None,
    role: str,
    purpose: str,
    *,
    independent_authority: bool = False,
) -> MarkdownRegistration:
    return MarkdownRegistration(parent, role, purpose, independent_authority)


ROOT_AUTHORITIES = frozenset(
    {"AGENTS.md", "ARCHITECTURE.md", "CURRENT_TASK.md", "README.md", "STATE.md"}
)
ROOT_PROTECTED_COMPATIBILITY = frozenset()

# This is deliberately a finite registry, not a documentation framework.  Every surviving
# Markdown file has one parent link, one owner role, and one purpose.
MARKDOWN_REGISTRY = {
    "AGENTS.md": _registration(None, "execution", "mandatory execution and precedence rules"),
    "ARCHITECTURE.md": _registration(None, "architecture", "whole-system ownership and boundaries"),
    "CURRENT_TASK.md": _registration(None, "current-task", "current bounded objective and blockers"),
    "README.md": _registration(None, "entry", "product identity and reading route"),
    "STATE.md": _registration(None, "state", "verified implementation evidence and nonclaims"),
    "docs/DATABASE_ZK_ARCHITECTURE.md": _registration(
        "README.md", "database-boundary", "verifier-to-database transaction boundary"
    ),
    "docs/DESIGN_IDEOLOGY.md": _registration(
        "README.md",
        "design-ideology",
        "independent smallest-correct design contract",
        independent_authority=True,
    ),
    "docs/IMPLEMENTATION_ROADMAP.md": _registration(
        "README.md", "roadmap", "Native-v3 and nonpayment dependency order"
    ),
    "docs/LEAN_FORMAL_KERNEL.md": _registration(
        "README.md", "lean-target", "authorized mandatory formal semantic/state gate"
    ),
    "docs/MIRROR_ARCHITECTURE.md": _registration(
        "README.md", "mirror-architecture", "read-only source trust, custody, reconciliation, and recovery boundary"
    ),
    "docs/NATIVE_V3_ARCHITECTURE.md": _registration(
        "README.md", "native-v3", "private-proof, security, state, and CPU target"
    ),
    "docs/NATIVE_V3_PLAINTEXT_CONTINUITY.md": _registration(
        "README.md", "plaintext-continuity", "internal deterministic continuity harness"
    ),
    "docs/NATIVE_V3_TRUST_BOUNDARY_PROFILE.md": _registration(
        "README.md", "trust-boundary", "session framing and independent parser profile"
    ),
    "docs/PYTHON_DEPENDENCY_LOCKING.md": _registration(
        "README.md", "python-dependencies", "offline Python lock and wheelhouse contract"
    ),
    "ops/DEPLOYMENT_RUNBOOK.md": _registration(
        "ARCHITECTURE.md", "deployment-runbook", "synthetic deployment preflight"
    ),
    "ops/KEY_CUSTODY_AND_ROTATION.md": _registration(
        "ARCHITECTURE.md", "key-custody", "synthetic key custody and rotation"
    ),
    "ops/MONITORING_AUDIT_EVENTS.md": _registration(
        "ARCHITECTURE.md", "monitoring", "non-PHI monitoring and audit events"
    ),
    "ops/PRODUCTION_CONFIG_CHECKLIST.md": _registration(
        "ARCHITECTURE.md", "production-checklist", "nonactivating deployment checklist"
    ),
    "ops/RISK_REGISTER.md": _registration(
        "ARCHITECTURE.md", "risk-register", "launch blocker and risk treatment index"
    ),
    "docs/RARC_PENDING_DECISION.md": _registration(
        "README.md", "pending-domain-decision", "open RARC/CARC mapping ratification decisions"
    ),
    "docs/REJECTED_ARCHITECTURES.md": _registration(
        "README.md", "rejected-architectures", "current prohibitions against retired directions"
    ),
}

# These are the executable paths named by the maintained command instructions.  The check is
# intentionally explicit: a command may be source-checkout-only, but it must never point at a
# file that no longer exists.  Git-only checks are validated by the command itself and are not
# replaced with an extracted-tree approximation.
DOCUMENTED_COMMAND_FILE_REFERENCES = {
    "README.md": frozenset(
        {
            "experiments/native_v3_phase0/native_v3_fixture.py",
            "experiments/native_v3_phase0_rust/Cargo.toml",
            "profile11_complete_path.py",
            "tests/test_active_core_contract.py",
            "tests/test_documentation_governance.py",
            "tests/test_minimal_clearance_verifier_process.py",
            "tests/test_native_v3_plaintext_continuity.py",
            "tests/test_native_v3_trust_boundary_profile.py",
            "tests/test_profile11_complete_path.py",
            "tests/test_profile11_source_boundary.py",
            "tests/test_qualification_gate.py",
            "tests/test_security_freeze_spec.py",
            "tools/locked_python_dependencies.py",
            "tools/ops_authority.py",
            "tools/qualification_gate.py",
        }
    ),
    "docs/IMPLEMENTATION_ROADMAP.md": frozenset({"ops/launch_blockers.json"}),
    "docs/PYTHON_DEPENDENCY_LOCKING.md": frozenset(
        {
            "docs/SBOM.python.spdx.json",
            "requirements/locks/cp314-linux_x86_64-development.lock",
            "requirements/locks/cp314-linux_x86_64-production.lock",
            "requirements/locks/cp314-win_amd64-development.lock",
            "requirements/locks/cp314-win_amd64-production.lock",
            "requirements/locks/python-artifacts.lock.json",
            "tools/locked_python_dependencies.py",
        }
    ),
    "ops/DEPLOYMENT_RUNBOOK.md": frozenset(
        {"tools/ops_authority.py", "tools/qualification_gate.py"}
    ),
    "ops/PRODUCTION_CONFIG_CHECKLIST.md": frozenset(
        {"tools/ops_authority.py", "tools/qualification_gate.py"}
    ),
    "ops/RISK_REGISTER.md": frozenset({"ops/launch_blockers.json"}),
}

# These exact strings identify the previous combined-integration task, not a historical fact that
# should survive in an active task document.  The current task must carry one candidate identity,
# one phase, and one next bounded action instead.
_INCOMPATIBLE_ACTIVE_INSTRUCTIONS = (
    (
        "CURRENT_TASK.md",
        re.compile(r"(?im)^\s*PHASE:\s*Combined controlled integration candidate\b"),
    ),
    (
        "CURRENT_TASK.md",
        re.compile(r"(?im)^\s*authoritative main remains read-only; no archive action\.?\s*$"),
    ),
    (
        "docs/IMPLEMENTATION_ROADMAP.md",
        re.compile(r"(?im)^\s*This is not the current or next implementation stage\.?\s*$"),
    ),
)
_REQUIRED_CURRENT_TASK_MARKERS = (
    "Immutable input base commit:",
    "Input base tree:",
    "Next bounded action:",
)

REMOVED_MARKDOWN_PATHS = frozenset(
    {
        "CONTINUATION_MANDATE.md",
        "PROJECT_MAP.md",
        "QUICKSTART.md",
        "rarc_ratification_proposal.md",
        "docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md",
        "docs/BL_PQ512_SECURITY_FREEZE.md",
        "docs/security-freeze/BL-PQ512-v1/context.md",
        "docs/security-freeze/BL-PQ512-v1/hardening.md",
        "docs/security-freeze/BL-PQ512-v1/proposals/001-wide-challenge-and-proof-commitments.md",
        "docs/security-freeze/BL-PQ512-v1/proposals/002-native-witness-hiding.md",
        "PROOF_PROVENANCE.md",
        "docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md",
        "docs/CURRENT_TECH_STACK.md",
        "docs/SUPPLY_CHAIN_BASELINE.md",
        "app/batch/PEPPER_ROTATION.md",
        "app/batch/leaf_format.md",
        "docs/DEPLOYMENT_READY_BUILD_CONTRACT.md",
        "experiments/bl_pq512_crypto_foundation/README.md",
        "experiments/fixed_shape_claim_air/README.md",
        "experiments/README.md",
    }
)

_MARKDOWN_LINK_DESTINATION = re.compile(
    r"\]\(((?:\.\.?/|[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.md(?:#[A-Za-z0-9_.-]+)?)\)"
)
_MARKDOWN_CODE_REFERENCE = re.compile(r"`([^`]*\.md(?:#[A-Za-z0-9_.-]+)?)`")
# These are deliberately exact, mechanically reliable stale assertions.  Historical labels and
# a disabled sentinel are permitted when the surrounding sentence explicitly marks them as such.
_EXACT_ACTIVE_LEGACY_MARKERS = (
    re.compile(r"(?im)^\s*the current target is the\b[^\n]*\b(?:BL[- ]PQ512|H4|CUDA|GKR)\b"),
    re.compile(r"(?im)^\s*[^\n]*\bselected\b[^\n]*\b(?:BL[- ]PQ512|H4|CUDA|K128|K512|Binius64|GKR)\b"),
    re.compile(r"(?im)^\s*[^\n]*\bproduction[-_ ]ready\b[^\n]*\b(?:BL[- ]PQ512|H4|CUDA|K128|K512|Binius64|GKR)\b"),
)
_TEXT_SUFFIXES = {".md", ".py", ".rs", ".json", ".jsonl", ".tsv", ".toml", ".txt", ".yaml", ".yml"}
_IGNORED_PARTS = {".git", ".pytest_cache", "__pycache__", "_handoff_support", "work"}
_ROOT_MARKDOWN_NAMES = ROOT_AUTHORITIES | ROOT_PROTECTED_COMPATIBILITY
_REPOSITORY_TOP_LEVELS = {
    "app",
    "docs",
    "experiments",
    "ops",
}
_PROTECTED_ROLES = frozenset()
_REJECTED_ARCHITECTURES_PATH = "docs/REJECTED_ARCHITECTURES.md"
_RETIRED_MARKDOWN_PREFIXES = ("experiments/",)
_RETIRED_MARKDOWN_STRUCTURE = (
    re.compile(r"(?im)^\s*#\s+(?:retired|historical|differential|compatibility)\b"),
    re.compile(
        r"(?im)^\s*(?:Status|Purpose|Role|Owner):\s*(?:the\s+)?"
        r"(?:retired|historical|differential|compatibility)\b"
    ),
)

# Two current negative tests intentionally construct deleted paths to prove absence.  They are
# the only construction references exempted; all production/tooling constructions remain visible.
_ALLOWED_PATH_CONSTRUCTION_REFERENCES = {
    ("tests/test_security_freeze_spec.py", "docs/BL_PQ512_SECURITY_FREEZE.md"),
    ("tests/test_documentation_governance.py", "docs/CURRENT_TECH_STACK.md"),
    ("tests/test_documentation_governance.py", "experiments/README.md"),
}


def _normalise(path: str) -> str:
    value = path.replace("\\", "/")
    value = posixpath.normpath(value)
    return "" if value == "." else value


def _current_paths(repo_root: Path) -> tuple[str, ...]:
    result: set[str] = set()
    git_paths = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=repo_root
    ).decode("utf-8").split("\0")
    result.update(
        _normalise(path)
        for path in git_paths
        if path and (repo_root / Path(*_normalise(path).split("/"))).is_file()
    )
    for path in repo_root.rglob("*"):
        relative = path.relative_to(repo_root)
        if not path.is_file() or any(part in _IGNORED_PARTS for part in relative.parts):
            continue
        result.add(relative.as_posix())
    return tuple(sorted(result))


def _resolve_markdown_reference(document: str, reference: str) -> str | None:
    reference = reference.split("#", 1)[0]
    if not reference or reference.startswith(("http://", "https://", "mailto:", "/")):
        return None
    if reference in _ROOT_MARKDOWN_NAMES:
        return reference
    first = reference.split("/", 1)[0]
    if first in _REPOSITORY_TOP_LEVELS:
        return _normalise(reference)
    parent = PurePosixPath(document).parent
    return _normalise(str(parent / reference))


def _references(document: str, text: str) -> set[str]:
    resolved: set[str] = set()
    raw_references = [
        match.group(1) for match in _MARKDOWN_LINK_DESTINATION.finditer(text)
    ]
    raw_references.extend(
        match.group(1) for match in _MARKDOWN_CODE_REFERENCE.finditer(text)
    )
    for reference in raw_references:
        value = _resolve_markdown_reference(document, reference)
        if value is not None:
            resolved.add(value)
    return resolved


def _read_text(repo_root: Path, relative: str) -> str:
    return (repo_root / Path(*relative.split("/"))).read_text(encoding="utf-8")


def _validate_documented_command_paths(
    repo_root: Path, texts: dict[str, str], errors: list[str]
) -> None:
    for document, references in DOCUMENTED_COMMAND_FILE_REFERENCES.items():
        if document not in texts:
            errors.append(f"documented command owner is missing: {document}")
            continue
        for reference in sorted(references):
            candidate = repo_root / Path(*reference.split("/"))
            if not candidate.is_file():
                errors.append(
                    f"documented command references missing file: {document} -> {reference}"
                )


def _validate_active_instruction_coherence(
    texts: dict[str, str], errors: list[str]
) -> None:
    task = texts.get("CURRENT_TASK.md", "")
    for marker in _REQUIRED_CURRENT_TASK_MARKERS:
        if marker not in task:
            errors.append(f"CURRENT_TASK.md is missing active marker: {marker}")
    for document, marker in _INCOMPATIBLE_ACTIVE_INSTRUCTIONS:
        if marker.search(texts.get(document, "")):
            errors.append(f"incompatible active instruction remains: {document}")


def _constructed_reference_patterns(removed: str) -> tuple[re.Pattern[str], ...]:
    components = removed.split("/")
    quoted = [re.escape(component) for component in components]
    slash = r"\s*/\s*".join(fr"[\"']{component}[\"']" for component in quoted)
    call = r"[^)]*".join(fr"[\"']{component}[\"']" for component in quoted)
    return (
        re.compile(slash),
        re.compile(fr"(?:Path|joinpath|os\.path\.join|join)\({call}\)"),
    )


def _has_constructed_reference(path: str, text: str, removed: str) -> bool:
    if (path, removed) in _ALLOWED_PATH_CONSTRUCTION_REFERENCES:
        return False
    return any(pattern.search(text) for pattern in _constructed_reference_patterns(removed))


def validate_markdown_tree(
    repo_root: Path, *, current_paths: Iterable[str] | None = None
) -> dict[str, object]:
    """Validate the live Markdown registry and all deterministic doc-level controls."""

    paths = tuple(sorted(_normalise(path) for path in (current_paths or _current_paths(repo_root))))
    markdown = tuple(path for path in paths if path.casefold().endswith(".md"))
    errors: list[str] = []
    expected = set(MARKDOWN_REGISTRY)
    observed = set(markdown)
    for path in sorted(observed - expected):
        errors.append(f"unregistered Markdown path: {path}")
    for path in sorted(expected - observed):
        errors.append(f"registered Markdown path is missing: {path}")

    root_markdown = {path for path in markdown if "/" not in path}
    allowed_root = ROOT_AUTHORITIES | ROOT_PROTECTED_COMPATIBILITY
    if not ROOT_AUTHORITIES <= root_markdown:
        errors.append("missing one of the five root Markdown authorities")
    if root_markdown - allowed_root:
        errors.append(f"unpermitted root Markdown authorities: {sorted(root_markdown - allowed_root)}")

    ownership_keys: dict[tuple[str | None, str, str], str] = {}
    roles: dict[str, str] = {}
    for path, registration in MARKDOWN_REGISTRY.items():
        key = (registration.parent, registration.role, registration.purpose)
        previous = ownership_keys.setdefault(key, path)
        if previous != path:
            errors.append(f"duplicate Markdown owner/purpose: {previous} and {path}")
        previous_role = roles.setdefault(registration.role, path)
        if previous_role != path:
            errors.append(f"duplicate Markdown authority/owner role: {previous_role} and {path}")

    if not MARKDOWN_REGISTRY["docs/DESIGN_IDEOLOGY.md"].independent_authority:
        errors.append("docs/DESIGN_IDEOLOGY.md lost independent authority")

    texts: dict[str, str] = {}
    for path in markdown:
        if path not in MARKDOWN_REGISTRY:
            continue
        try:
            texts[path] = _read_text(repo_root, path)
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"cannot read registered Markdown {path}: {exc}")

    for path, registration in MARKDOWN_REGISTRY.items():
        if not registration.purpose.strip():
            errors.append(f"Markdown registration has no purpose: {path}")
        if registration.parent is not None:
            if registration.parent not in observed:
                errors.append(f"Markdown owner is missing: {path} -> {registration.parent}")
            elif path not in _references(registration.parent, texts.get(registration.parent, "")):
                errors.append(f"missing canonical inbound link: {registration.parent} -> {path}")

    for path, text in texts.items():
        registration = MARKDOWN_REGISTRY[path]
        references = _references(path, text)
        for reference in sorted(references):
            if reference not in observed:
                errors.append(f"broken Markdown reference: {path} -> {reference}")
        if path.startswith("docs/history/"):
            if path != "docs/history/README.md" or "Historical evidence" not in text:
                errors.append(f"active Markdown under history path: {path}")
        elif registration.role not in _PROTECTED_ROLES and text.startswith("# Retired architecture evidence"):
            errors.append(f"historical marker masquerades as active Markdown: {path}")
        if registration.role not in _PROTECTED_ROLES:
            if path != _REJECTED_ARCHITECTURES_PATH and any(
                path.startswith(prefix) for prefix in _RETIRED_MARKDOWN_PREFIXES
            ):
                errors.append(f"retired implementation Markdown path is forbidden: {path}")
            if path != _REJECTED_ARCHITECTURES_PATH and any(
                marker.search(text) for marker in _RETIRED_MARKDOWN_STRUCTURE
            ):
                errors.append(f"retired-status Markdown structure is forbidden: {path}")
            for marker in _EXACT_ACTIVE_LEGACY_MARKERS:
                if marker.search(text):
                    errors.append(f"active Markdown contains an exact superseded backend claim: {path}")

    searchable = tuple(path for path in paths if Path(path).suffix.casefold() in _TEXT_SUFFIXES)
    for path in searchable:
        if path == "tools/documentation_governance.py":
            continue
        try:
            text = _read_text(repo_root, path)
        except (OSError, UnicodeDecodeError):
            continue
        for removed in sorted(REMOVED_MARKDOWN_PATHS):
            if (removed in text or removed.replace("/", "\\") in text) and (
                path,
                removed,
            ) not in _ALLOWED_PATH_CONSTRUCTION_REFERENCES:
                errors.append(f"reference to removed Markdown: {path} -> {removed}")
            elif _has_constructed_reference(path, text, removed):
                errors.append(f"constructed reference to removed Markdown: {path} -> {removed}")

    _validate_documented_command_paths(repo_root, texts, errors)
    _validate_active_instruction_coherence(texts, errors)

    if errors:
        raise DocumentationGovernanceError("; ".join(sorted(set(errors))))
    return {
        "markdown_count": len(markdown),
        "root_authority_count": len(ROOT_AUTHORITIES),
        "root_protected_compatibility_count": len(ROOT_PROTECTED_COMPATIBILITY),
        "registered_count": len(MARKDOWN_REGISTRY),
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate_markdown_tree(args.repo_root.resolve())
    except DocumentationGovernanceError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
