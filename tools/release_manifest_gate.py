"""Generate a deterministic v2 release manifest from reviewed committed bytes.

The Git checkout is the source authority.  ``source_root`` is deliberately a separate,
bounded staging root containing only the reviewed release selection.  This keeps the
selection decision explicit while making every emitted digest and size come from the
selected commit object, not from a mutable working-tree read.

This is a release/cleanliness gate only.  It does not build or publish an archive and it
does not make any proof, activation, payment, or production-readiness claim.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import unicodedata
from typing import Iterable, Sequence

from tools import build_release_archive as archive_builder
from tools.documentation_governance import (
    MARKDOWN_REGISTRY,
    ROOT_AUTHORITIES,
    ROOT_PROTECTED_COMPATIBILITY,
)


POLICY_VERSION = "blind-ledger-release-policy-v1"
MANIFEST_VERSION = 2
SOURCE_MANIFEST_NAME = archive_builder.SOURCE_MANIFEST_NAME
DEFAULT_ARCHIVE_ROOT = "Blind-Ledger-Release"
MAX_FILE_BYTES = archive_builder.MAX_FILE_BYTES
POLICY_INPUT_SHA256 = {
    ".archiveignore": "a6b8981b81255c914df2fd7fb60cbab3266922b748492aad08f82c6e6e25c6d6",
    ".gitignore": "8e62c95885ead2e9d03a65568ccc425d01b0b92a3f3f7d9bb89b7d85c558cdc9",
    ".gitattributes": "898abe08ca35ca160d2c17fe86dcc93cf846576444a6902063f2fed3e18bb086",
}


class ManifestGateError(RuntimeError):
    """A fail-closed source, policy, or manifest-generation error."""


class PathLane(str, Enum):
    CURRENT_SOURCE = "current_source"
    RETAINED_COMPATIBILITY = "retained_compatibility"
    SOURCE_ONLY = "source_only"
    EXCLUDED_GENERATED_PRIVATE = "excluded_generated_private"
    RETIRED_FORBIDDEN = "retired_forbidden"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PathClassification:
    path: str
    lane: PathLane
    reason: str


# Root files are intentionally explicit.  A new root file must be reviewed and added to
# this executable policy; otherwise root-level accumulation is silent and hard to audit.
ROOT_PATH_ALLOWLIST = frozenset(
    {
        ".archiveignore",
        ".gitignore",
        ".gitattributes",
        "AGENTS.md",
        "ARCHITECTURE.md",
        "CURRENT_TASK.md",
        "pytest.ini",
        "rarc_mapping.tsv",
        "README.md",
        "STATE.md",
        "requirements-dev.txt",
        "requirements.txt",
    }
)

# These two allowlists are the authority-document guard.  DESIGN_IDEOLOGY.md is kept as
# a distinct canonical document; it is not merged into another authority file.
ROOT_MARKDOWN_ALLOWLIST = frozenset(ROOT_AUTHORITIES | ROOT_PROTECTED_COMPATIBILITY)
DOC_MARKDOWN_ALLOWLIST = frozenset(
    path for path in MARKDOWN_REGISTRY if path.casefold().startswith("docs/")
)

CURRENT_TOP_LEVELS = frozenset(
    {
        "app",
        "config",
        "docs",
        "experiments",
        "ops",
        "requirements",
        "schemas",
        "test_data",
        "tests",
        "tools",
    }
)

# These prefixes are classification hints for retained evidence/migration lanes.  They are
# never, by themselves, a release-selection rule.
RETAINED_PREFIXES = (
    "app/batch/",
    "experiments/bl_pq512_crypto_foundation/",
    "experiments/fixed_shape_claim_air/",
)

# The current candidate retains these compatibility modules. Keep the closure explicit so a
# default release cannot silently grow by prefix.
CURRENT_RELEASE_DEPENDENCY_PATHS = frozenset(
    {
        "app/batch/__init__.py",
        "app/batch/poseidon.py",
    }
)

# These paths are abandoned compatibility designs.  A tracked path in one of them is a
# policy error even if a caller tries to omit it from a release selection.
RETIRED_PREFIXES = (
    "contracts/",
    "experiments/binary_field_k128/",
    "l2/",
    "zk-stark/",
)

EXCLUDED_SEGMENTS = frozenset(
    {
        ".agents",
        ".claude",
        ".codex",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "_handoff_support",
        "a",
        "cache",
        "malformed-target-path",
        "node_modules",
        "out",
        "p",
        "proof",
        "proofs",
        "r",
        "scratch",
        "target",
        "work",
        "wsl-target",
        "x",
        "y",
    }
)
EXCLUDED_FILENAMES = frozenset(
    {
        "APP_RELEASE_FILE_MANIFEST.json".casefold(),
        "RELEASE_FILE_MANIFEST.json".casefold(),
        "batch_main_args.json",
        "batch_package.json",
        "proof.json",
    }
)
EXCLUDED_SUFFIXES = frozenset(
    {
        ".7z",
        ".bin",
        ".bz2",
        ".dmp",
        ".docx",
        ".gz",
        ".jar",
        ".log",
        ".png",
        ".pptx",
        ".pyo",
        ".pyc",
        ".rar",
        ".tar",
        ".tgz",
        ".tmp",
        ".whl",
        ".xlsx",
        ".xz",
        ".zip",
        ".zst",
    }
)
# These source-only harness files intentionally remain in Git and are exercised by tests,
# but are not publishable release inputs. Keep this boundary explicit and finite.
RELEASE_SOURCE_ONLY_PATHS = frozenset(
    {
        "profile11_complete_path.py",
        "profile11_complete_path_manifest.json",
        "profile11_source_boundary.py",
    }
)

# These exact files intentionally remain in Git and are exercised by tests or retained as
# evidence, but their synthetic privacy fixtures, scanner vocabulary, or private build-path
# metadata cannot be serialized into the source archive. Keep this boundary explicit and
# finite; it is a reviewed data-role classification, never a content-based omission rule.
RELEASE_EXCLUSION_REASONS: dict[str, str] = {
    "docs/security-freeze/BL-PQ512-v1/hardening.json": "retained generated security evidence with private-path metadata",
    "experiments/longfellow_v09_native_v3/evidence/longfellow_v09_native_v3_debloat_evidence.json": "retained generated measurement evidence with private build-path metadata",
    "experiments/longfellow_v09_native_v3/evidence/longfellow_v09_native_v3_failure.json": "retained generated failure evidence with private build-path metadata",
    "experiments/profile11_source_host/Cargo.lock": "source-only external Profile 11 host harness",
    "experiments/profile11_source_host/Cargo.toml": "source-only external Profile 11 host harness with private dependency path",
    "experiments/profile11_source_host/src/main.rs": "source-only external Profile 11 host harness",
    "tests/test_build_release_archive.py": "source-only privacy fixture or scanner tool",
    "tests/test_minimal_clearance_source_auth_verifier_adapter.py": "source-only external Profile 11 artifact/path fixture",
    "tests/test_minimal_clearance_verifier_process.py": "source-only synthetic Windows namespace fixture",
    "tests/test_mirror_external_governance_approval.py": "source-only synthetic privacy-canary fixture",
    "tests/test_mirror_external_privacy_support_approval.py": "source-only synthetic privacy-canary fixture",
    "tests/test_mirror_qualification_independent.py": "source-only synthetic privacy-canary fixture",
    "tests/test_mirror_v2_consolidation.py": "source-only synthetic privacy/path-canary fixture",
    "tests/test_nc_medicaid_fhir_source.py": "source-only synthetic privacy/path-canary fixture",
    "tests/test_privacy_artifact_scan.py": "source-only privacy fixture or scanner tool",
    "tests/test_profile11_complete_path.py": "source-only Profile 11 external-workspace fixture",
    "tests/test_profile11_source_boundary.py": "source-only Profile 11 external-workspace fixture",
    "tests/test_qualification_gate.py": "source-only synthetic private-path error fixture",
    "tools/privacy_artifact_scan.py": "source-only privacy fixture or scanner tool",
}
RELEASE_EXCLUDED_PATHS = frozenset(RELEASE_EXCLUSION_REASONS)
_WINDOWS_RESERVED = re.compile(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])")


def _normalise_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestGateError("path must be a non-empty string")
    if "\\" in value or value.startswith("/") or value.endswith("/"):
        raise ManifestGateError("path must use relative POSIX syntax")
    if "\x00" in value or len(value.encode("utf-8")) > 4096:
        raise ManifestGateError("path is absolute, contains NUL, or exceeds the byte limit")
    if value != unicodedata.normalize("NFC", value):
        raise ManifestGateError(f"path is not Unicode NFC normalized: {value}")
    parts = value.split("/")
    for part in parts:
        if not part or part in {".", ".."}:
            raise ManifestGateError(f"path has an empty or traversal component: {value}")
        if part.endswith((" ", ".")):
            raise ManifestGateError(f"path has a trailing space or dot: {value}")
        if ":" in part:
            raise ManifestGateError(f"path contains alternate-data-stream syntax: {value}")
        if any(
            ord(character) < 32
            or ord(character) == 0x7F
            or unicodedata.category(character) in {"Cf", "Cs", "Zl", "Zp"}
            for character in part
        ):
            raise ManifestGateError(f"path contains a control character: {value}")
        stem = unicodedata.normalize("NFKC", part.split(".", 1)[0])
        if _WINDOWS_RESERVED.fullmatch(stem) or stem.casefold() in {"conin$", "conout$"}:
            raise ManifestGateError(f"path uses a reserved Windows device name: {value}")
    return value


def _fold_path(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _is_excluded(path: str) -> tuple[bool, str]:
    if path in RELEASE_EXCLUDED_PATHS:
        return True, RELEASE_EXCLUSION_REASONS[path]
    parts = path.casefold().split("/")
    if any(part in EXCLUDED_SEGMENTS for part in parts):
        return True, "generated/cache/private/proof-output path segment"
    filename = parts[-1]
    if filename in EXCLUDED_FILENAMES:
        return True, "generated release/proof artifact filename"
    suffix = PurePosixPath(filename).suffix.casefold()
    if suffix in EXCLUDED_SUFFIXES:
        return True, f"archive-forbidden/generated artifact suffix {suffix}"
    if suffix == ".json" and "proof" in PurePosixPath(filename).stem.casefold():
        return True, "proof-result JSON"
    return False, ""


def classify_path(path: str) -> PathClassification:
    """Classify one repository-relative path without silently widening policy."""

    normalised = _normalise_path(path)
    if normalised in {"CURRENT_TASK.md", "STATE.md"}:
        return PathClassification(normalised, PathLane.EXCLUDED_GENERATED_PRIVATE, "workspace-only authority record")
    if normalised in RELEASE_SOURCE_ONLY_PATHS:
        return PathClassification(normalised, PathLane.SOURCE_ONLY, "retained source/test-only nonrelease harness")
    excluded, excluded_reason = _is_excluded(normalised)
    if excluded:
        return PathClassification(normalised, PathLane.EXCLUDED_GENERATED_PRIVATE, excluded_reason)
    if any(normalised.startswith(prefix) for prefix in RETIRED_PREFIXES):
        return PathClassification(normalised, PathLane.RETIRED_FORBIDDEN, "retired compatibility lane")

    top_level = normalised.split("/", 1)[0]
    if "/" not in normalised:
        if normalised not in ROOT_PATH_ALLOWLIST:
            return PathClassification(normalised, PathLane.UNKNOWN, "unallowlisted root path")
        if normalised.casefold().endswith(".md") and normalised not in ROOT_MARKDOWN_ALLOWLIST:
            return PathClassification(normalised, PathLane.UNKNOWN, "unallowlisted root Markdown authority")
        return PathClassification(normalised, PathLane.CURRENT_SOURCE, "reviewed root source/policy file")

    if top_level not in CURRENT_TOP_LEVELS:
        return PathClassification(normalised, PathLane.UNKNOWN, "unclassified top-level path")
    if top_level == "docs" and normalised.casefold().endswith(".md"):
        if normalised not in DOC_MARKDOWN_ALLOWLIST:
            return PathClassification(normalised, PathLane.UNKNOWN, "unallowlisted docs Markdown authority")
    if any(normalised.startswith(prefix) for prefix in RETAINED_PREFIXES):
        return PathClassification(normalised, PathLane.RETAINED_COMPATIBILITY, "retained regression/evidence lane")
    return PathClassification(normalised, PathLane.CURRENT_SOURCE, "reviewed current source lane")


def classify_paths(paths: Iterable[str]) -> tuple[PathClassification, ...]:
    """Classify paths and reject exact, case, and Unicode collisions."""

    classifications: list[PathClassification] = []
    exact: set[str] = set()
    folded: set[str] = set()
    for raw_path in paths:
        classification = classify_path(raw_path)
        if classification.path in exact or _fold_path(classification.path) in folded:
            raise ManifestGateError(
                f"duplicate or case/Unicode-colliding path: {classification.path}"
            )
        exact.add(classification.path)
        folded.add(_fold_path(classification.path))
        classifications.append(classification)
    return tuple(classifications)


def validate_tracked_paths(paths: Iterable[str]) -> tuple[PathClassification, ...]:
    """Validate the full tracked tree while allowing known excluded paths to stay unselected."""

    classifications = classify_paths(paths)
    failures = [
        item
        for item in classifications
        if item.lane in {PathLane.UNKNOWN, PathLane.RETIRED_FORBIDDEN}
    ]
    if failures:
        details = "; ".join(f"{item.path}: {item.reason}" for item in failures[:8])
        suffix = "" if len(failures) <= 8 else f"; plus {len(failures) - 8} more"
        raise ManifestGateError(f"tracked-path policy is stale or forbidden: {details}{suffix}")
    return classifications


def validate_release_paths(paths: Iterable[str]) -> tuple[str, ...]:
    """Validate the explicit bounded release selection against the builder's path rules."""

    classifications = classify_paths(paths)
    failures = [
        item
        for item in classifications
        if item.lane not in {PathLane.CURRENT_SOURCE, PathLane.RETAINED_COMPATIBILITY}
        or (
            item.lane is PathLane.RETAINED_COMPATIBILITY
            and item.path not in CURRENT_RELEASE_DEPENDENCY_PATHS
        )
    ]
    if failures:
        details = "; ".join(f"{item.path}: {item.lane.value} ({item.reason})" for item in failures[:8])
        suffix = "" if len(failures) <= 8 else f"; plus {len(failures) - 8} more"
        raise ManifestGateError(f"release selection contains forbidden paths: {details}{suffix}")
    ordered: list[str] = []
    for item in classifications:
        try:
            archive_builder._validate_relative_path(item.path)
        except archive_builder.ReleaseArchiveError as exc:
            raise ManifestGateError(
                f"release selection is incompatible with manifest-v2 builder: {item.path}: {exc}"
            ) from None
        ordered.append(item.path)
    return tuple(sorted(ordered))


def default_release_selection(paths: Iterable[str]) -> tuple[str, ...]:
    """Return the dependency-closed current release selection.

    Current source is selected by lane.  Retained paths are selected only when they are in the
    explicit, reviewed dependency closure above; an unlisted path under a retained prefix is a
    policy error rather than an implicit release input.
    """

    classifications = validate_tracked_paths(paths)
    retained = {
        item.path
        for item in classifications
        if item.lane is PathLane.RETAINED_COMPATIBILITY
    }
    unreviewed_retained = sorted(retained - CURRENT_RELEASE_DEPENDENCY_PATHS)
    if unreviewed_retained:
        raise ManifestGateError(
            "retained compatibility paths are outside the reviewed dependency closure: "
            + ", ".join(unreviewed_retained[:8])
        )
    selected = {
        item.path
        for item in classifications
        if item.lane is PathLane.CURRENT_SOURCE
    }
    selected.update(retained & CURRENT_RELEASE_DEPENDENCY_PATHS)
    return validate_release_paths(selected)


def _git(repo: Path, args: Sequence[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ManifestGateError(f"git command failed: {' '.join(args)}: {message or 'unknown error'}")
    return result.stdout


def _require_clean_commit(repo: Path, revision: str) -> tuple[str, tuple[str, ...]]:
    if not repo.exists() or not repo.is_dir() or repo.is_symlink():
        raise ManifestGateError("git root is missing, not a directory, or linked")
    resolved = repo.resolve(strict=True)
    try:
        top = _git(resolved, ["rev-parse", "--show-toplevel"]).decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ManifestGateError("git top-level path is not valid UTF-8") from None
    if Path(top).resolve() != resolved:
        raise ManifestGateError("git root does not match the repository top level")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        raise ManifestGateError("revision must be a full 40-hex commit id")
    expected = _git(resolved, ["rev-parse", "--verify", f"{revision}^{{commit}}"]).decode("ascii").strip()
    head = _git(resolved, ["rev-parse", "HEAD"]).decode("ascii").strip()
    if expected != revision.casefold() or head != expected:
        raise ManifestGateError("git HEAD is not the selected committed revision")
    status = _git(
        resolved,
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignored"],
    )
    if status.strip():
        raise ManifestGateError("git checkout is dirty, untracked, or ignored artifacts are present")
    raw_tree = _git(resolved, ["ls-tree", "-r", "-z", "--name-only", expected])
    try:
        tree_paths = tuple(part.decode("utf-8") for part in raw_tree.split(b"\x00") if part)
    except UnicodeDecodeError:
        raise ManifestGateError("selected commit contains a non-UTF-8 path") from None
    return expected, tree_paths


def _git_blob(repo: Path, revision: str, path: str) -> bytes:
    return _git(repo, ["cat-file", "blob", f"{revision}:{path}"])


def _validate_policy_identity(repo: Path, revision: str, tracked_paths: set[str]) -> None:
    for path, expected_sha256 in POLICY_INPUT_SHA256.items():
        if path not in tracked_paths:
            raise ManifestGateError(f"release policy input is missing from the selected commit: {path}")
        actual_sha256 = hashlib.sha256(_git_blob(repo, revision, path)).hexdigest()
        if actual_sha256 != expected_sha256:
            raise ManifestGateError(f"release policy identity is stale: {path}")


def _inventory_source(root: Path) -> tuple[set[str], set[str]]:
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise ManifestGateError("bounded source root is missing, not a directory, or linked")
    files: set[str] = set()
    directories: set[str] = set()
    walk_errors: list[OSError] = []

    def on_walk_error(error: OSError) -> None:
        walk_errors.append(error)

    if archive_builder._is_reparse_point(root):
        raise ManifestGateError("bounded source root is a reparse point")
    for current, dir_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=on_walk_error
    ):
        current_path = Path(current)
        dir_names.sort()
        file_names.sort()
        for name in dir_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or archive_builder._is_reparse_point(path):
                raise ManifestGateError(f"bounded source contains a linked directory: {relative}")
            directories.add(relative)
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or archive_builder._is_reparse_point(path):
                raise ManifestGateError(f"bounded source contains a linked file: {relative}")
            try:
                details = path.lstat()
            except OSError as exc:
                raise ManifestGateError(f"bounded source entry is unreadable: {relative}") from exc
            if not stat.S_ISREG(details.st_mode) or details.st_nlink > 1:
                raise ManifestGateError(f"bounded source entry is special or hardlinked: {relative}")
            if details.st_size > MAX_FILE_BYTES:
                raise ManifestGateError(f"bounded source file exceeds the builder limit: {relative}")
            files.add(relative)
    if walk_errors:
        raise ManifestGateError("bounded source directory enumeration failed")
    return files, directories


def _expected_directories(paths: Iterable[str]) -> set[str]:
    directories: set[str] = set()
    for relative in paths:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _read_selection_file(path: Path) -> tuple[str, ...]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ManifestGateError("reviewed selection file is missing or unreadable") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestGateError("reviewed selection file is not strict UTF-8") from exc
    if not text.endswith("\n"):
        raise ManifestGateError("reviewed selection file must end with a newline")
    paths = tuple(line[:-1] if line.endswith("\r") else line for line in text.splitlines())
    if not paths or any(not path for path in paths):
        raise ManifestGateError("reviewed selection file contains an empty path")
    return paths


def generate_manifest(
    *,
    git_root: Path,
    source_root: Path,
    output_path: Path,
    revision: str,
    archive_root: str = DEFAULT_ARCHIVE_ROOT,
    selected_paths: Iterable[str] | None = None,
    policy_version: str = POLICY_VERSION,
) -> dict[str, object]:
    """Generate a canonical builder-v2 manifest and return its verified receipt."""

    if policy_version != POLICY_VERSION:
        raise ManifestGateError(
            f"stale policy version {policy_version!r}; expected {POLICY_VERSION!r}"
        )
    try:
        archive_builder._validate_archive_root(archive_root)
    except archive_builder.ReleaseArchiveError as exc:
        raise ManifestGateError(f"archive root is incompatible with manifest-v2: {exc}") from None

    git_root = Path(git_root)
    source_root = Path(source_root)
    output_path = Path(output_path)
    expected_revision, tracked_paths = _require_clean_commit(git_root, revision)
    _validate_policy_identity(git_root.resolve(strict=True), expected_revision, set(tracked_paths))
    tracked = validate_tracked_paths(tracked_paths)
    tracked_set = {item.path for item in tracked}

    try:
        resolved_source = source_root.resolve(strict=True)
    except OSError as exc:
        raise ManifestGateError("bounded source root is missing or unreadable") from exc
    resolved_output = output_path.resolve(strict=False)
    if resolved_output.parent != resolved_source:
        raise ManifestGateError("manifest output must be directly inside the bounded source root")
    if output_path.name != SOURCE_MANIFEST_NAME:
        raise ManifestGateError(f"manifest output must be named {SOURCE_MANIFEST_NAME}")
    if os.path.lexists(str(resolved_output)):
        raise ManifestGateError("stale release manifest already exists; remove it before regeneration")
    if not resolved_output.parent.exists():
        raise ManifestGateError("manifest output parent is missing")

    source_files, source_directories = _inventory_source(resolved_source)
    expected_selection = (
        tuple(selected_paths)
        if selected_paths is not None
        else default_release_selection(tracked_paths)
    )
    release_paths = validate_release_paths(expected_selection)
    release_set = set(release_paths)
    if source_files != release_set:
        missing = sorted(release_set - source_files)
        extra = sorted(source_files - release_set)
        detail = []
        if missing:
            detail.append(f"missing={missing[:4]}")
        if extra:
            detail.append(f"extra={extra[:4]}")
        raise ManifestGateError(
            "bounded source inventory does not exactly match reviewed selection: "
            + ", ".join(detail)
        )
    if source_directories != _expected_directories(release_set):
        raise ManifestGateError("bounded source contains an empty or unreviewed directory")

    entries: list[dict[str, object]] = []
    for relative in release_paths:
        if relative not in tracked_set:
            raise ManifestGateError(f"reviewed release input is missing from selected commit: {relative}")
        committed = _git_blob(git_root.resolve(strict=True), expected_revision, relative)
        source_path = resolved_source.joinpath(*relative.split("/"))
        try:
            actual = source_path.read_bytes()
        except OSError as exc:
            raise ManifestGateError(f"reviewed release input is missing or unreadable: {relative}") from exc
        if actual != committed:
            raise ManifestGateError(f"bounded source bytes do not match selected commit: {relative}")
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(committed).hexdigest(),
                "size": len(committed),
            }
        )
    if not entries:
        raise ManifestGateError("release manifest requires at least one selected source file")

    document = {
        "archive_root": archive_root,
        "files": entries,
        "manifest_version": MANIFEST_VERSION,
    }
    manifest_bytes = (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    try:
        with resolved_output.open("xb") as stream:
            stream.write(manifest_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise ManifestGateError("stale release manifest appeared during generation") from None
    except OSError as exc:
        raise ManifestGateError("release manifest could not be written") from exc

    return {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "manifest_bytes": len(manifest_bytes),
        "manifest_version": MANIFEST_VERSION,
        "policy_version": POLICY_VERSION,
        "policy_input_sha256": dict(POLICY_INPUT_SHA256),
        "revision": expected_revision,
        "payload_file_count": len(entries),
        "excluded_tracked_count": sum(
            item.lane is PathLane.EXCLUDED_GENERATED_PRIVATE for item in tracked
        ),
        "source_only_tracked_count": sum(
            item.lane is PathLane.SOURCE_ONLY for item in tracked
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic manifest-v2 file from a reviewed commit selection."
    )
    parser.add_argument("--git-root", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--archive-root", default=DEFAULT_ARCHIVE_ROOT)
    parser.add_argument("--paths-file", type=Path)
    parser.add_argument("--policy-version", default=POLICY_VERSION)
    args = parser.parse_args()
    try:
        selected = _read_selection_file(args.paths_file) if args.paths_file else None
        receipt = generate_manifest(
            git_root=args.git_root,
            source_root=args.source_root,
            output_path=args.output,
            revision=args.revision,
            archive_root=args.archive_root,
            selected_paths=selected,
            policy_version=args.policy_version,
        )
    except ManifestGateError as exc:
        print(f"manifest_status=blocked reason={exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
