"""Project-wide candidate inventory and evidence-bound acceptance entry point.

Run this module from the separate qualification checkout, never from candidate
test code. A local result is advisory until the runner and policy are pinned by
an independently controlled integration/release environment.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Mapping

from tools import deployment_bundle, documentation_governance, ops_authority, release_manifest_gate


SCHEMA = "RR/PROJECT-ACCEPTANCE/v1"
ACTIVE_ROOTS: Mapping[str, str] = {
    "financial": "rightrail-financial-workflow-20260913",
    "engine": "lean-engine-20260913",
    "queue": "lean-queue-20260913",
    "security": "lean-security-20260913",
    "state": "lean-state-20260913",
    "native": "pq-wide-seed-native-20260913",
    "provider": "rightrail-provider-app-20260923",
    "qualification": "rightrail-qualification-gate-v3-20260923",
    "mirror_research": "mirror-directory-corrections-20260913",
}
BASELINE_HEADS: Mapping[str, str] = {
    "financial": "8f75f527ae6717001978ac7401853c2aaae55f2b",
    "engine": "907e32de63ab0d8133f2a7aff1441b06a1a884e8",
    "queue": "b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55",
    "security": "4452126284007a836c5801606bcbd713393274ed",
    "state": "ab66da45854e3cb1c35a620b0c1aa3a3051f79ac",
    "native": "78bcdc77def21f6ef2a862e15d042d26dee26718",
    "provider": "aaf02419f91cc5f688a4b21cb44ff7769d409adc",
    "qualification": "2a1b573f91e8f3a5c5b1e44fc55594b9ee3b19c1",
    "mirror_research": "43052285078bd1eed2ee9b11eddad1ef9513eb72",
}
MODULE_SUFFIXES = frozenset({
    ".py", ".lean", ".rs", ".c", ".h", ".cpp", ".hpp", ".ts", ".tsx", ".js", ".mjs",
})
PROTECTED_PATHS = frozenset({
    "AGENTS.md", "AGENTS.override.md", "ARCHITECTURE.md",
    "docs/DESIGN_IDEOLOGY.md", "docs/LEAN_FORMAL_KERNEL.md",
    "docs/DATABASE_ZK_ARCHITECTURE.md", "docs/RIGHTRAIL_FULL_STACK_TARGET.md",
    "ops/launch_blockers.json", "tools/project_acceptance.py",
    "tools/release_manifest_gate.py", "tools/semantic_assurance_gate.py",
    "tools/qualification_gate.py", "tools/qualification_gate_v3.py",
    "tools/ops_authority.py",
    "tests/rightrail_financial_expected_cases.py",
    "app/minimal_clearance_resource_limits.py",
    "parked/private_zk/tools/direct_mask_contract/calculator_v2.py",
})
REQUIRED_FINANCIAL_CHECKS = frozenset({
    "lean_transition_execution",
    "financial_atomic_commit_and_retry",
    "independent_expected_answers",
    "privacy_outputs",
})
SHARED_GUARD_SHA256 = "57f9ec8aefe1d0e281b3bb0d76f2f057c8295f99afdd04305dfc777703ed99fb"
WORKSPACE_MAP_SHA256 = "ae4d9271e55e35602c731a7174c4613727f29bb16ceda7f2d0724cdddceec244b"
DRIVER_AGENTS_SHA256 = "6e2cf34d234ff4069b16934072f05f9a7e099ef6c559411766911bce394be5f7"
WORK_DIRECTORY_NAMES_SHA256 = "bc93729eeac3cd6133987af4a10095ef424a6e8f7b4b39d1b569a938f35b8d71"
WORK_FILE_NAMES_SHA256 = "3952bf7c04ea5fedd22f755dda704bf34eb66529fd8a6fc2c303da787ada5ae1"
WORK_DIRECTORY_COUNT = 75
WORK_FILE_COUNT = 41
MAX_IGNORED_LIST_BYTES = 32 * 1024 * 1024
GENERATED_PARTS = frozenset({
    ".lake", ".pytest_cache", "__pycache__", "node_modules", "target",
})
GENERATED_TOP_LEVELS = frozenset({
    "build-filter-native", "build-performance", "cache", "work",
})
GENERATED_SUFFIXES = frozenset({
    ".dll", ".exe", ".lib", ".log", ".o", ".obj", ".pdb", ".pyc",
})
ARTIFACT_SUFFIXES = frozenset({".7z", ".dll", ".exe", ".gz", ".tar", ".tgz", ".whl", ".zip"})
SECRET_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx"})
CONFIG_CANDIDATES = (
    "semantic_kernel/lean/lean-toolchain",
    "formal/lean/lean-toolchain",
    "lean/ProviderApp/lean-toolchain",
    "requirements/locks/python-artifacts.lock.json",
    "pytest.ini",
)
CONFIG_BASENAMES = frozenset({
    "Cargo.toml", "Cargo.lock", "CMakeLists.txt", "Dockerfile",
    "lakefile.lean", "lakefile.toml", "lean-toolchain",
    "package.json", "pyproject.toml", "pytest.ini",
})
REPRESENTATIVE_SUBDIRS = (
    "app", "docs", "formal", "lean", "semantic_kernel", "tests", "tools",
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_HEX = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class AcceptanceError(ValueError):
    """An inventory or evidence record cannot be trusted."""


@dataclass(frozen=True)
class RootIdentity:
    role: str
    path: str
    head: str
    tree: str
    status_sha256: str
    dirty: tuple[tuple[str, str], ...]
    new_paths: tuple[str, ...]
    new_modules: tuple[str, ...]
    protected_changes: tuple[str, ...]
    committed_changes: tuple[str, ...] = ()
    config_sha256: tuple[tuple[str, str], ...] = ()
    release_artifacts: tuple[str, ...] = ()
    excluded_dirty: tuple[tuple[str, int], ...] = ()
    instruction_file: str = ""
    instruction_sha256: str = ""
    instruction_bytes: int = 0
    representative_overrides: tuple[str, ...] = ()
    ignored_candidates: tuple[str, ...] = ()
    excluded_ignored: tuple[tuple[str, int], ...] = ()

    def as_record(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": self.path,
            "head": self.head,
            "tree": self.tree,
            "status_sha256": self.status_sha256,
            "dirty": [
                {"path": path, "sha256": digest} for path, digest in self.dirty
            ],
            "new_paths": list(self.new_paths),
            "new_modules": list(self.new_modules),
            "protected_changes": list(self.protected_changes),
            "committed_changes": list(self.committed_changes),
            "config_sha256": dict(self.config_sha256),
            "release_artifacts": list(self.release_artifacts),
            "excluded_dirty": dict(self.excluded_dirty),
            "instruction_file": self.instruction_file,
            "instruction_sha256": self.instruction_sha256,
            "instruction_bytes": self.instruction_bytes,
            "representative_overrides": list(self.representative_overrides),
            "ignored_candidates": list(self.ignored_candidates),
            "excluded_ignored": dict(self.excluded_ignored),
        }


def _git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError(f"git {' '.join(args)} could not finish at {root}: {exc}") from exc
    if result.returncode:
        raise AcceptanceError(
            f"git {' '.join(args)} failed at {root}: "
            f"exit={result.returncode} stderr={result.stderr.decode('utf-8', 'replace')}"
        )
    return result.stdout


def _paths(raw: bytes) -> tuple[str, ...]:
    try:
        entries = raw.decode("utf-8").split("\0")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("Git path output is not UTF-8") from exc
    if entries[-1] != "":
        raise AcceptanceError("Git path output has no NUL terminator")
    return tuple(entries[:-1])


def _validate_inventory_paths(paths: tuple[str, ...]) -> None:
    folded: set[str] = set()
    for relative in paths:
        if (
            not relative or relative.startswith("/") or "\\" in relative
            or ":" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise AcceptanceError(f"unsafe tracked path: {relative!r}")
        key = relative.casefold()
        if key in folded:
            raise AcceptanceError(f"case-colliding tracked path: {relative}")
        folded.add(key)


def _source_file(root: Path, relative: str) -> Path:
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise AcceptanceError(f"unsafe repository path: {relative!r}")
    path = root.joinpath(*relative.split("/"))
    if not path.resolve().is_relative_to(root.resolve()):
        raise AcceptanceError(f"dirty path escapes checkout: {relative}")
    if path.is_symlink() or not path.is_file():
        raise AcceptanceError(f"missing or redirected dirty file: {relative}")
    max_bytes = (
        8 * 1024 * 1024 * 1024
        if path.suffix.casefold() in ARTIFACT_SUFFIXES
        else 64 * 1024 * 1024
    )
    if path.stat().st_size > max_bytes:
        raise AcceptanceError(f"dirty file exceeds identity limit: {relative}")
    return path


def _dirty_digest(root: Path, relative: str) -> str:
    path = root.joinpath(*relative.split("/"))
    if path.is_symlink():
        raise AcceptanceError(f"redirected dirty file: {relative}")
    if not path.exists():
        return "DELETED"
    path = _source_file(root, relative)
    before = path.stat()
    digest = sha256()
    read_bytes = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            read_bytes += len(chunk)
    after = path.stat()
    if (
        before.st_dev != after.st_dev or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or read_bytes != after.st_size
    ):
        raise AcceptanceError(f"dirty file changed while hashing: {relative}")
    return digest.hexdigest()


def _dirty_paths(root: Path) -> tuple[str, ...]:
    changed = set(_paths(_git(root, "diff", "--name-only", "-z", "HEAD")))
    added = set(_paths(_git(root, "ls-files", "--others", "--exclude-standard", "-z")))
    # A deleted tracked path has no working bytes; its deletion is still
    # represented in the status identity and protected-path check.
    return tuple(sorted(changed | added))


def _in_generated_directory(relative: str) -> bool:
    parts = relative.split("/")
    return parts[0] in GENERATED_TOP_LEVELS or any(
        part in GENERATED_PARTS for part in parts[:-1]
    )


def _generated_reason(relative: str) -> str | None:
    parts = relative.split("/")
    if parts[-1].casefold() == ".env" or Path(relative).suffix.casefold() in SECRET_SUFFIXES:
        return "possible_secret_not_hashed"
    if (
        Path(relative).suffix.casefold() in MODULE_SUFFIXES | ARTIFACT_SUFFIXES
        or _is_configuration(relative)
    ):
        return None
    if _in_generated_directory(relative):
        return "generated_or_workspace_directory"
    if Path(relative).suffix.casefold() in GENERATED_SUFFIXES:
        return "generated_binary_or_log_suffix"
    return None


def _protected_path(relative: str) -> bool:
    return (
        relative in PROTECTED_PATHS
        or relative.endswith(("/AGENTS.md", "/AGENTS.override.md"))
        or relative.endswith(("/Theorems.lean", "/Specification.lean", "/AxiomCheck.lean"))
        or relative.endswith("_expected_cases.py")
        or relative.startswith(("tests/fixtures/", "test_data/"))
        or "/Theorems/" in relative
        or "/CodecLaws/" in relative
    )


def _is_configuration(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1]
    return (
        relative in CONFIG_CANDIDATES
        or name in {".gitignore", ".gitattributes"}
        or name in CONFIG_BASENAMES
        or name.endswith(".lock.json")
        or relative.startswith(".github/workflows/")
    )


def _ignored_source_candidates(root: Path) -> tuple[tuple[str, ...], tuple[tuple[str, int], ...]]:
    command = ["git", "-C", str(root), "ls-files", "--others", "--ignored", "--exclude-standard", "-z"]
    try:
        with tempfile.TemporaryFile() as stream:
            result = subprocess.run(
                command, stdout=stream, stderr=subprocess.PIPE,
                check=False, timeout=60,
            )
            if result.returncode:
                raise AcceptanceError(
                    f"ignored-path inventory failed at {root}: exit={result.returncode} "
                    f"stderr={result.stderr.decode('utf-8', 'replace')}"
                )
            size = stream.seek(0, 2)
            if size > MAX_IGNORED_LIST_BYTES:
                raise AcceptanceError(f"ignored-path inventory exceeds limit at {root}: {size}")
            stream.seek(0)
            paths = _paths(stream.read())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError(f"ignored-path inventory could not finish at {root}: {exc}") from exc
    candidates: list[str] = []
    excluded: dict[str, int] = {}
    for relative in paths:
        if not (_is_configuration(relative) or Path(relative).suffix.casefold() in MODULE_SUFFIXES):
            continue
        if _in_generated_directory(relative):
            excluded["known_generated_ignored_source"] = excluded.get("known_generated_ignored_source", 0) + 1
            continue
        reason = _generated_reason(relative)
        if reason is not None:
            excluded[reason] = excluded.get(reason, 0) + 1
        else:
            candidates.append(relative)
    return tuple(sorted(candidates)), tuple(sorted(excluded.items()))


def _instruction_identity(root: Path) -> tuple[str, str, int, tuple[str, ...]]:
    chosen = "AGENTS.override.md" if (root / "AGENTS.override.md").exists() else "AGENTS.md"
    path = _source_file(root, chosen)
    size = path.stat().st_size
    if not 0 < size <= 32 * 1024:
        raise AcceptanceError(f"instruction entry point exceeds default limit: {root / chosen} ({size} bytes)")
    nested: list[str] = []
    for directory in REPRESENTATIVE_SUBDIRS:
        for name in ("AGENTS.override.md", "AGENTS.md"):
            relative = f"{directory}/{name}"
            target = root / directory / name
            if target.exists() or target.is_symlink():
                _source_file(root, relative)
                nested.append(relative)
    return chosen, sha256(path.read_bytes()).hexdigest(), size, tuple(nested)


def inventory_root(role: str, root: Path, baseline_head: str) -> RootIdentity:
    if not root.is_dir() or not (root / ".git").exists():
        raise AcceptanceError(f"{role} is not a Git checkout: {root}")
    observed_root = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if observed_root != root.resolve():
        raise AcceptanceError(f"{role} Git root mismatch: {observed_root}")
    head = _git(root, "rev-parse", "HEAD").decode().strip().lower()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode().strip().lower()
    if not _GIT_HEX.fullmatch(head) or not _GIT_HEX.fullmatch(tree):
        raise AcceptanceError(f"{role} Git identity malformed")
    _git(root, "cat-file", "-e", f"{baseline_head}^{{commit}}")
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    dirty_paths = _dirty_paths(root)
    dirty: list[tuple[str, str]] = []
    excluded: dict[str, int] = {}
    for relative in dirty_paths:
        reason = _generated_reason(relative)
        if reason is not None:
            excluded[reason] = excluded.get(reason, 0) + 1
            continue
        digest = _dirty_digest(root, relative)
        dirty.append((relative, digest))
    baseline = set(_paths(_git(root, "ls-tree", "-r", "--name-only", "-z", baseline_head)))
    current = set(_paths(_git(root, "ls-files", "-z"))) | set(
        _paths(_git(root, "ls-files", "--others", "--exclude-standard", "-z"))
    )
    new_paths = tuple(sorted(
        path for path in current - baseline
        if _generated_reason(path) is None
    ))
    new_modules = tuple(sorted(
        path for path in new_paths
        if Path(path).suffix.casefold() in MODULE_SUFFIXES
    ))
    committed_changes = set(_paths(_git(root, "diff", "--name-only", "-z", baseline_head, "HEAD")))
    protected = tuple(sorted(
        path for path in set(dirty_paths) | committed_changes
        if _protected_path(path)
    ))
    config = tuple(
        (relative, _dirty_digest(root, relative))
        for relative in sorted(current)
        if _generated_reason(relative) is None and _is_configuration(relative)
    )
    release_artifacts = tuple(sorted(
        path for path in current
        if Path(path).suffix.casefold() in ARTIFACT_SUFFIXES
    ))
    ignored_candidates, excluded_ignored = _ignored_source_candidates(root)
    instruction_file, instruction_sha256, instruction_bytes, nested = _instruction_identity(root)
    if _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all") != status:
        raise AcceptanceError(f"{role} Git status changed during inventory")
    if _git(root, "rev-parse", "HEAD").decode().strip().lower() != head:
        raise AcceptanceError(f"{role} HEAD changed during inventory")
    for relative, digest in dirty:
        if _dirty_digest(root, relative) != digest:
            raise AcceptanceError(f"{role} dirty file changed during inventory: {relative}")
    return RootIdentity(
        role=role,
        path=str(root.resolve()),
        head=head,
        tree=tree,
        status_sha256=sha256(status).hexdigest(),
        dirty=tuple(dirty),
        new_paths=new_paths,
        new_modules=new_modules,
        protected_changes=protected,
        committed_changes=tuple(sorted(committed_changes)),
        config_sha256=config,
        release_artifacts=release_artifacts,
        excluded_dirty=tuple(sorted(excluded.items())),
        instruction_file=instruction_file,
        instruction_sha256=instruction_sha256,
        instruction_bytes=instruction_bytes,
        representative_overrides=nested,
        ignored_candidates=ignored_candidates,
        excluded_ignored=excluded_ignored,
    )


def inventory_project(workspace_root: Path) -> dict[str, RootIdentity]:
    work = workspace_root.resolve() / "work"
    workspace_map = workspace_root / "WORKSPACE_MAP.md"
    if work.is_symlink() or not work.is_dir() or workspace_map.is_symlink() or not workspace_map.is_file():
        raise AcceptanceError("workspace root or WORKSPACE_MAP.md missing")
    entries = tuple(work.iterdir())
    if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in entries):
        raise AcceptanceError("redirected or unsupported immediate work entry")
    directories = tuple(sorted(path.name for path in entries if path.is_dir()))
    files = tuple(sorted(path.name for path in entries if path.is_file()))
    directory_digest = sha256("\n".join(directories).encode("utf-8")).hexdigest()
    file_digest = sha256("\n".join(files).encode("utf-8")).hexdigest()
    if (
        len(directories) != WORK_DIRECTORY_COUNT
        or directory_digest != WORK_DIRECTORY_NAMES_SHA256
        or len(files) != WORK_FILE_COUNT
        or file_digest != WORK_FILE_NAMES_SHA256
    ):
        raise AcceptanceError(
            "unclassified immediate work entry change: "
            f"directories={len(directories)} sha256={directory_digest} "
            f"files={len(files)} sha256={file_digest}; "
            f"observed_entries={list(directories + files)}"
        )
    map_bytes = workspace_map.read_bytes()
    if sha256(map_bytes).hexdigest() != WORKSPACE_MAP_SHA256:
        raise AcceptanceError("workspace map changed without applicability review")
    instructions = workspace_root / "AGENTS.md"
    if instructions.is_symlink() or not instructions.is_file():
        raise AcceptanceError("Driver instructions missing or redirected")
    if sha256(instructions.read_bytes()).hexdigest() != DRIVER_AGENTS_SHA256:
        raise AcceptanceError("Driver instructions changed without applicability review")
    try:
        map_text = map_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("workspace map is not UTF-8") from exc
    mapped = set(re.findall(r"\bwork/([a-z0-9-]+)", map_text))
    mapped.discard("instruction-history")
    expected = set(ACTIVE_ROOTS.values())
    if mapped != expected:
        raise AcceptanceError(
            f"workspace root inventory changed: missing={sorted(expected - mapped)} "
            f"unclassified={sorted(mapped - expected)}"
        )
    seen: set[Path] = set()
    roots: dict[str, RootIdentity] = {}
    for role, directory in ACTIVE_ROOTS.items():
        path = work / directory
        resolved = path.resolve()
        if resolved in seen or resolved.parent != work:
            raise AcceptanceError(f"duplicate or escaped worktree: {role}")
        seen.add(resolved)
        roots[role] = inventory_root(role, path, BASELINE_HEADS[role])
    return roots


def verify_shared_guard(workspace_root: Path) -> str:
    path = (
        workspace_root / "work" / "pq-wide-seed-native-20260913"
        / "build-filter-native" / "run_guarded_v4.ps1"
    )
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise AcceptanceError("shared guard missing, redirected, or oversized")
    digest = sha256(path.read_bytes()).hexdigest()
    if digest != SHARED_GUARD_SHA256:
        raise AcceptanceError(f"shared guard identity mismatch: {digest}")
    return digest


def evaluate_required_checks(
    expected: frozenset[str],
    evidence: Mapping[str, Mapping[str, Any]],
    current_sources: Mapping[str, str],
) -> tuple[dict[str, str], ...]:
    """Validate a bounded check record; supplied records are still advisory."""
    results: list[dict[str, str]] = []
    for check_id in sorted(expected):
        record = evidence.get(check_id)
        if record is None:
            results.append({"id": check_id, "status": "MISSING"})
            continue
        if type(record) is not dict or set(record) != {
            "status", "source_sha256", "command", "exit_code", "tests", "raw_sha256"
        }:
            results.append({"id": check_id, "status": "INVALID"})
            continue
        if record["status"] != "PASS" or type(record["exit_code"]) is not int or record["exit_code"] != 0:
            results.append({"id": check_id, "status": "FAILED"})
            continue
        if type(record["tests"]) is not int or record["tests"] < 1:
            results.append({"id": check_id, "status": "EMPTY"})
            continue
        if (
            not isinstance(record["command"], list)
            or not record["command"]
            or not all(isinstance(item, str) and item for item in record["command"])
            or not isinstance(record["raw_sha256"], str)
            or not _HEX64.fullmatch(record["raw_sha256"])
        ):
            results.append({"id": check_id, "status": "INVALID"})
            continue
        sources = record["source_sha256"]
        if (
            not isinstance(sources, dict)
            or not sources
            or set(sources) != set(current_sources)
            or any(sources[key] != value for key, value in current_sources.items())
        ):
            results.append({"id": check_id, "status": "STALE"})
            continue
        results.append({"id": check_id, "status": "RECORDED_UNVERIFIED"})
    return tuple(results)


def run_development_checks(roots: Mapping[str, RootIdentity]) -> dict[str, dict[str, Any]]:
    """Run existing fast gates from this separate qualification checkout."""
    observed: dict[str, dict[str, Any]] = {}
    for role, identity in roots.items():
        root = Path(identity.path)
        try:
            tracked = _paths(_git(root, "ls-files", "-z"))
            _validate_inventory_paths(tracked)
            observed[f"{role}:inventory_paths"] = {
                "status": "PASS", "count": len(tracked),
                "runner": "tools.project_acceptance._validate_inventory_paths",
            }
        except AcceptanceError as exc:
            observed[f"{role}:inventory_paths"] = {
                "status": "FAIL", "reason": str(exc),
                "runner": "tools.project_acceptance._validate_inventory_paths",
            }
            if role == "qualification":
                observed["qualification:tracked_paths"] = {
                    "status": "NOT_RUN", "reason": "tracked inventory failed",
                    "runner": "tools.release_manifest_gate.validate_tracked_paths",
                }
        else:
            if role == "qualification":
                try:
                    classifications = release_manifest_gate.validate_tracked_paths(tracked)
                    observed["qualification:tracked_paths"] = {
                        "status": "PASS", "count": len(classifications),
                        "runner": "tools.release_manifest_gate.validate_tracked_paths",
                    }
                except release_manifest_gate.ManifestGateError as exc:
                    observed["qualification:tracked_paths"] = {
                        "status": "FAIL", "reason": str(exc),
                        "runner": "tools.release_manifest_gate.validate_tracked_paths",
                    }
        if any(path.casefold().endswith(".md") for path in identity.committed_changes) or any(
            path.casefold().endswith(".md") for path, _ in identity.dirty
        ):
            if role != "qualification":
                observed[f"{role}:documentation"] = {
                    "status": "UNMAPPED",
                    "reason": "no root-specific documentation gate is integrated",
                }
                continue
            try:
                result = documentation_governance.validate_markdown_tree(root)
                observed[f"{role}:documentation"] = {
                    "status": "PASS", "result": result,
                    "runner": "tools.documentation_governance.validate_markdown_tree",
                }
            except (documentation_governance.DocumentationGovernanceError, OSError) as exc:
                observed[f"{role}:documentation"] = {
                    "status": "FAIL", "reason": str(exc),
                    "runner": "tools.documentation_governance.validate_markdown_tree",
                }
    try:
        status = ops_authority.verify_ops_authority()
        observed["qualification:ops_authority"] = {
            "status": "PASS", "result": status,
            "runner": "tools.ops_authority.verify_ops_authority",
        }
    except (OSError, ValueError, TypeError) as exc:
        observed["qualification:ops_authority"] = {
            "status": "FAIL", "reason": str(exc),
            "runner": "tools.ops_authority.verify_ops_authority",
        }
    command = [sys.executable, "-m", "unittest", "tests.test_project_acceptance"]
    try:
        completed = subprocess.run(
            command,
            cwd=Path(roots["qualification"].path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
        )
        stdout = completed.stdout.decode("utf-8", "replace")
        stderr = completed.stderr.decode("utf-8", "replace")
        count_match = re.search(r"Ran (\d+) tests?", stdout + stderr)
        test_count = int(count_match.group(1)) if count_match else 0
        observed["qualification:acceptance_selftest"] = {
            "status": "PASS" if completed.returncode == 0 and test_count > 0 else "FAIL",
            "command": command,
            "exit_code": completed.returncode,
            "tests": test_count,
            "stdout": stdout,
            "stderr": stderr,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        observed["qualification:acceptance_selftest"] = {
            "status": "FAIL", "command": command, "reason": str(exc),
        }
    workspace_root = Path(roots["qualification"].path).resolve().parent.parent
    try:
        _, bundle_report = deployment_bundle.build_candidate(workspace_root)
        validation = bundle_report["validation"]
        if (
            not validation["structural_valid"]
            or validation["archive_sha256"] != bundle_report["archive_sha256"]
        ):
            raise deployment_bundle.DeploymentBundleError("assembled archive failed its byte-validation receipt")
        observed["qualification:deployment_bundle"] = {
            "status": "PASS_LOCAL_STRUCTURAL",
            "authority": "LOCAL_ADVISORY_ONLY",
            "archive_size": bundle_report["archive_size"],
            "archive_sha256": bundle_report["archive_sha256"],
            "source_identity_sha256": bundle_report["source_identity_sha256"],
            "included_file_count": bundle_report["included_file_count"],
            "missing_file_count": bundle_report["missing_file_count"],
            "evidence_statuses": bundle_report["evidence_statuses"],
            "release_status": "BLOCKED",
        }
    except (deployment_bundle.DeploymentBundleError, OSError) as exc:
        observed["qualification:deployment_bundle"] = {
            "status": "BLOCKED_LOCAL_ASSEMBLY",
            "authority": "LOCAL_ADVISORY_ONLY",
            "reason": str(exc),
        }
    return observed


def assess(
    roots: Mapping[str, RootIdentity],
    evidence: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    phase: str = "development",
    guard_sha256: str | None = None,
    observed_checks: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if set(roots) != set(ACTIVE_ROOTS):
        raise AcceptanceError("active product inventory incomplete")
    if phase not in {"development", "integration", "release"}:
        raise AcceptanceError("unknown acceptance phase")
    all_new = [
        f"{role}:{path}" for role, identity in roots.items()
        for path in identity.new_modules
    ]
    new_paths = [
        f"{role}:{path}" for role, identity in roots.items()
        for path in identity.new_paths
    ]
    protected = [
        f"{role}:{path}" for role, identity in roots.items()
        for path in identity.protected_changes
    ]
    sources = {
        role: sha256(json.dumps(identity.as_record(), sort_keys=True).encode()).hexdigest()
        for role, identity in roots.items()
    }
    changed_paths = {
        role: set(identity.committed_changes) | {path for path, _ in identity.dirty}
        for role, identity in roots.items()
    }
    financial_impact = any(
        Path(path).suffix.casefold() in MODULE_SUFFIXES
        for role in ("financial", "engine")
        for path in changed_paths[role]
    )
    other_code_impact = any(
        Path(path).suffix.casefold() in MODULE_SUFFIXES
        for role in roots if role not in {"financial", "engine"}
        for path in changed_paths[role]
    )
    release_artifact_impact = any(
        Path(path).suffix.casefold() in ARTIFACT_SUFFIXES
        for role in roots for path in changed_paths[role]
    )
    config_impact = any(
        _is_configuration(path)
        for role in roots for path in changed_paths[role]
    )
    unmapped_non_document_impact = any(
        Path(path).suffix.casefold() != ".md"
        and Path(path).suffix.casefold() not in MODULE_SUFFIXES | ARTIFACT_SUFFIXES
        and not _is_configuration(path)
        for role in roots for path in changed_paths[role]
    )
    ignored_candidates = [
        f"{role}:{path}" for role, identity in roots.items()
        for path in identity.ignored_candidates
    ]
    required_checks = REQUIRED_FINANCIAL_CHECKS if financial_impact else frozenset()
    evidence = evidence or {}
    checks = evaluate_required_checks(required_checks, evidence, sources)
    unknown_evidence = sorted(set(evidence) - required_checks)
    reasons: list[str] = []
    observed_checks = observed_checks or {}
    for role, identity in roots.items():
        key = f"{role}:inventory_paths"
        if observed_checks.get(key, {}).get("status") != "PASS":
            reasons.append(f"{key}_missing_or_failed")
        if role == "qualification" and observed_checks.get("qualification:tracked_paths", {}).get("status") != "PASS":
            reasons.append("qualification:tracked_paths_missing_or_failed")
        if any(path.casefold().endswith(".md") for path in changed_paths[role]):
            key = f"{role}:documentation"
            if observed_checks.get(key, {}).get("status") != "PASS":
                reasons.append(f"{key}_missing_or_failed")
    if observed_checks.get("qualification:ops_authority", {}).get("status") != "PASS":
        reasons.append("qualification:ops_authority_missing_or_failed")
    if observed_checks.get("qualification:acceptance_selftest", {}).get("status") != "PASS":
        reasons.append("qualification:acceptance_selftest_missing_or_failed")
    if observed_checks.get("qualification:deployment_bundle", {}).get("status") != "PASS_LOCAL_STRUCTURAL":
        reasons.append("qualification:deployment_bundle_missing_or_invalid")
    if new_paths:
        reasons.append("unclassified_new_paths")
    if ignored_candidates:
        reasons.append("ignored_source_or_config_requires_review")
    if unknown_evidence:
        reasons.append("unrecognized_evidence_records")
    if protected:
        reasons.append("protected_changes_require_independent_review")
    if any(check["status"] != "RECORDED_UNVERIFIED" for check in checks):
        reasons.append("required_financial_checks_incomplete")
    if other_code_impact:
        reasons.append("other_code_impact_requires_applicable_check_review")
    if release_artifact_impact:
        reasons.append("release_artifact_requires_independent_build_provenance")
    if config_impact:
        reasons.append("configuration_change_requires_applicable_check_review")
    if unmapped_non_document_impact:
        reasons.append("unmapped_non_document_change_requires_review")
    if phase != "development":
        reasons.append("trusted_runner_and_release_authorization_not_configured")
    if checks and not reasons:
        # Supplied evidence is not a runner-observed result.
        reasons.append("supplied_check_records_unverified")
    status = "PASS_DEVELOPMENT" if not reasons else "INCOMPLETE"
    return {
        "schema": SCHEMA,
        "status": status,
        "phase": phase,
        "scope": "synthetic_project_candidate",
        "new_modules": all_new,
        "new_paths": new_paths,
        "ignored_candidates": ignored_candidates,
        "protected_changes": protected,
        "financial_checks": list(checks),
        "unrecognized_evidence_records": unknown_evidence,
        "observed_checks": dict(observed_checks),
        "reasons": reasons,
        "source_identities": {role: identity.as_record() for role, identity in roots.items()},
        "claims": {
            "proofSuiteId": None,
            "production_usable": False,
            "activation": False,
        },
        "shared_guard_sha256": guard_sha256,
    }


def _load_evidence(path: Path | None) -> Mapping[str, Mapping[str, Any]]:
    if path is None:
        return {}
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
        raise AcceptanceError("evidence file missing, redirected, or oversized")
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AcceptanceError(f"duplicate evidence key: {key}")
            result[key] = value
        return result
    def no_nonfinite(value: str) -> None:
        raise AcceptanceError(f"nonfinite evidence number: {value}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=no_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError("evidence JSON malformed") from exc
    if not isinstance(value, dict):
        raise AcceptanceError("evidence must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", required=True, type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--phase", choices=("development", "integration", "release"), default="development")
    args = parser.parse_args(argv)
    try:
        roots = inventory_project(args.workspace_root)
        guard_sha256 = verify_shared_guard(args.workspace_root)
        observed_checks = run_development_checks(roots)
        post_roots = inventory_project(args.workspace_root)
        if any(
            post_roots[role].as_record() != identity.as_record()
            for role, identity in roots.items()
        ):
            raise AcceptanceError("project source identity changed while checks executed")
        if verify_shared_guard(args.workspace_root) != guard_sha256:
            raise AcceptanceError("shared guard identity changed while checks executed")
        result = assess(
            roots, _load_evidence(args.evidence), phase=args.phase,
            guard_sha256=guard_sha256,
            observed_checks=observed_checks,
        )
    except AcceptanceError as exc:
        print(json.dumps({"schema": SCHEMA, "status": "BLOCKED", "reason": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS_DEVELOPMENT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
