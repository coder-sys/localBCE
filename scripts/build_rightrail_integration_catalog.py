#!/usr/bin/env python3
"""Build and validate the deterministic RightRail integration catalog.

The source bundle is evidence, not an instruction set. This tool accounts for
every manifest entry without executing preserved binaries or treating archived
prototype code as active localBCE behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA_VERSION = "localbce-rightrail-integration-catalog-v1"
SUMMARY_SCHEMA_VERSION = "localbce-rightrail-integration-summary-v1"
WORKSPACE_SCHEMA_VERSION = "localbce-rightrail-workspace-dispositions-v1"
EXPECTED_MANIFEST_ENTRIES = 14_877
README_ORIGINAL_ENTRIES = 14_874
EXPECTED_WORKSPACES = tuple(f"r{number:03d}" for number in range(1, 74))

ALLOWED_DISPOSITIONS = frozenset(
    {
        "active_port",
        "active_test",
        "experimental_build",
        "formal_reference",
        "audit_evidence",
        "generated_reproducible",
        "duplicate_superseded",
        "incompatible_design",
        "unsafe_binary",
        "incomplete_or_unbuildable",
    }
)

UNSAFE_BINARY_SUFFIXES = frozenset(
    {
        ".a",
        ".dll",
        ".dylib",
        ".exe",
        ".exp",
        ".ilk",
        ".lib",
        ".o",
        ".obj",
        ".pdb",
        ".so",
    }
)
GENERATED_SUFFIXES = frozenset(
    {
        ".build",
        ".cache",
        ".iobj",
        ".ipdb",
        ".lastbuildstate",
        ".log",
        ".out",
        ".pyc",
        ".tlog",
    }
)
SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cmake",
        ".cpp",
        ".cs",
        ".h",
        ".hpp",
        ".inc",
        ".in",
        ".lean",
        ".ps1",
        ".py",
        ".rs",
        ".sh",
        ".sol",
        ".tcl",
        ".toml",
        ".vcxproj",
        ".xml",
        ".yaml",
        ".yml",
    }
)
DOCUMENT_SUFFIXES = frozenset({".docx", ".md", ".pdf", ".rtf", ".txt"})
GENERATED_PARTS = frozenset(
    {
        ".cache",
        ".vs",
        "__pycache__",
        "build",
        "cmakefiles",
        "debug",
        "release",
        "target",
    }
)

FORMAL_WORKSPACES = frozenset(
    {"r002", "r003", "r004", "r005", "r069", "r070", "r071", "r072", "r073"}
)
PQ_WORKSPACES = frozenset(f"r{number:03d}" for number in range(7, 67))


class CatalogError(RuntimeError):
    pass


@dataclass(frozen=True)
class BuildOutputs:
    catalog_bytes: bytes
    summary_bytes: bytes
    workspaces_bytes: bytes
    summary: dict[str, Any]


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def workspace_id(path: str) -> str | None:
    match = re.match(r"^w/(r\d{3})(?:/|$)", path)
    return match.group(1) if match else None


def workspace_focus(identifier: str) -> str:
    if identifier == "r001":
        return "evidence_baseline"
    if identifier in FORMAL_WORKSPACES:
        return "formal_semantics"
    if identifier == "r006":
        return "source_corrections"
    if identifier in PQ_WORKSPACES:
        return "post_quantum_research"
    if identifier == "r067":
        return "financial_and_operational_workflow"
    if identifier == "r068":
        return "reproduction_runner"
    return "unmapped_workspace"


def file_kind(path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in UNSAFE_BINARY_SUFFIXES:
        return "binary"
    if suffix in GENERATED_SUFFIXES:
        return "generated"
    if suffix in SOURCE_SUFFIXES:
        return "source"
    if suffix in DOCUMENT_SUFFIXES:
        return "document"
    if suffix in {".json", ".lock"}:
        return "metadata"
    if suffix in {".png", ".jpg", ".jpeg", ".svg"}:
        return "image"
    if not suffix:
        return "extensionless"
    return "other"


def base_disposition(path: str) -> tuple[str, str]:
    pure = PurePosixPath(path)
    suffix = pure.suffix.lower()
    parts = {part.lower() for part in pure.parts}
    identifier = workspace_id(path)

    if suffix in UNSAFE_BINARY_SUFFIXES:
        return "unsafe_binary", "preserved executable or linked artifact; never execute from archive"
    if suffix in GENERATED_SUFFIXES or parts.intersection(GENERATED_PARTS):
        return "generated_reproducible", "generated/build evidence must be reproduced from source"
    if path.startswith(("original/", "root/")):
        return "audit_evidence", "handoff evidence or archived instruction; never runtime authority"
    if path in {"README.md", "PATH_MAP.json", "WORKSPACES.json"}:
        return "audit_evidence", "package-level integrity and navigation evidence"
    if identifier == "r001":
        return "audit_evidence", "evidence portability baseline"
    if identifier in FORMAL_WORKSPACES:
        return "formal_reference", "formal candidate remains inactive pending reproduction and linkage"
    if suffix in DOCUMENT_SUFFIXES:
        return "audit_evidence", "design or historical evidence requiring requirements crosswalk"
    if identifier == "r006":
        return "experimental_build", "source-correction candidate pending reproduction"
    if identifier in PQ_WORKSPACES:
        return "experimental_build", "post-quantum research candidate pending qualification"
    if identifier in {"r067", "r068"}:
        return "experimental_build", "application or runner candidate pending isolated reproduction"
    if file_kind(path) in {"source", "metadata"}:
        return "experimental_build", "source candidate pending isolated reproduction"
    return "audit_evidence", "preserved archive content pending requirements review"


def canonical_duplicate_path(paths: Iterable[str]) -> str:
    def rank(path: str) -> tuple[int, int, str]:
        prefix = path.split("/", 1)[0]
        identifier = workspace_id(path)
        if identifier == "r067":
            prefix_rank = 0
        elif identifier == "r068":
            prefix_rank = 1
        elif identifier in {"r001", "r006"}:
            prefix_rank = 2
        elif prefix == "w":
            prefix_rank = 3
        else:
            prefix_rank = {"original": 4, "root": 5, "long": 6}.get(prefix, 7)
        return prefix_rank, len(path), path

    return min(paths, key=rank)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogError(f"could not read {path}: {exc}") from exc


def build_catalog(
    archive_root: Path,
    *,
    verify_bytes: bool = True,
    expected_manifest_entries: int | None = EXPECTED_MANIFEST_ENTRIES,
    expected_workspaces: tuple[str, ...] | None = EXPECTED_WORKSPACES,
) -> BuildOutputs:
    manifest_path = archive_root / "MANIFEST.json"
    workspace_path = archive_root / "WORKSPACES.json"
    manifest = load_json(manifest_path)
    workspace_map = load_json(workspace_path)
    if not isinstance(manifest, list) or not manifest:
        raise CatalogError("MANIFEST.json must contain a non-empty array")
    if not isinstance(workspace_map, dict) or not workspace_map:
        raise CatalogError("WORKSPACES.json must contain a non-empty object")
    if expected_manifest_entries is not None and len(manifest) != expected_manifest_entries:
        raise CatalogError(
            f"manifest entry count mismatch: expected {expected_manifest_entries}, got {len(manifest)}"
        )

    original_name_by_workspace: dict[str, str] = {}
    for original_name, mapped in workspace_map.items():
        if not isinstance(original_name, str) or not isinstance(mapped, str):
            raise CatalogError("workspace map entries must be strings")
        identifier = mapped.removeprefix("w/")
        if not re.fullmatch(r"r\d{3}", identifier):
            raise CatalogError(f"invalid workspace mapping: {original_name} -> {mapped}")
        if identifier in original_name_by_workspace:
            raise CatalogError(f"duplicate workspace ID: {identifier}")
        original_name_by_workspace[identifier] = original_name

    actual_workspaces = tuple(sorted(original_name_by_workspace))
    if expected_workspaces is not None and actual_workspaces != expected_workspaces:
        raise CatalogError(
            f"workspace IDs mismatch: expected {len(expected_workspaces)}, got {len(actual_workspaces)}"
        )

    normalized: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    by_digest: dict[str, list[str]] = defaultdict(list)
    integrity_statuses: dict[str, str] = {}
    integrity_errors: list[dict[str, str]] = []
    for index, raw in enumerate(manifest):
        if not isinstance(raw, dict) or set(raw) not in (
            {"path", "original_path", "bytes", "sha256"},
            {"path", "bytes", "sha256"},
        ):
            raise CatalogError(f"invalid manifest entry shape at index {index}")
        path = raw["path"]
        original_path = raw.get("original_path", path)
        byte_count = raw["bytes"]
        digest = raw["sha256"]
        if not isinstance(path, str) or not path or "\\" in path or path.startswith("/") or ".." in PurePosixPath(path).parts:
            raise CatalogError(f"invalid stored path at index {index}: {path!r}")
        if path in seen_paths:
            raise CatalogError(f"duplicate manifest path: {path}")
        if not isinstance(original_path, str) or not original_path:
            raise CatalogError(f"invalid original path for {path}")
        if not isinstance(byte_count, int) or byte_count < 0:
            raise CatalogError(f"invalid byte count for {path}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise CatalogError(f"invalid SHA-256 for {path}")
        digest = digest.lower()
        seen_paths.add(path)
        by_digest[digest].append(path)
        normalized.append(
            {"path": path, "original_path": original_path, "bytes": byte_count, "sha256": digest}
        )

        if verify_bytes:
            source = archive_root.joinpath(*PurePosixPath(path).parts)
            try:
                if not source.is_file():
                    status = "missing"
                elif source.stat().st_size != byte_count:
                    status = "size_mismatch"
                elif sha256_file(source) != digest:
                    status = "sha256_mismatch"
                else:
                    status = "verified"
            except OSError as exc:
                status = "unreadable"
                integrity_errors.append(
                    {"path": path, "status": status, "error_type": type(exc).__name__}
                )
            integrity_statuses[path] = status
            if status != "verified" and not any(error["path"] == path for error in integrity_errors):
                integrity_errors.append({"path": path, "status": status, "error_type": "integrity"})
        else:
            integrity_statuses[path] = "not_checked"

    canonical_by_digest = {
        digest: canonical_duplicate_path(paths) for digest, paths in by_digest.items() if len(paths) > 1
    }
    catalog: list[dict[str, Any]] = []
    disposition_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    workspace_counts: dict[str, Counter[str]] = defaultdict(Counter)
    workspace_bytes: Counter[str] = Counter()
    duplicate_entries = 0

    for item in sorted(normalized, key=lambda value: value["path"]):
        path = item["path"]
        identifier = workspace_id(path)
        kind = file_kind(path)
        base, rationale = base_disposition(path)
        duplicate_of = canonical_by_digest.get(item["sha256"])
        if duplicate_of == path:
            duplicate_of = None
        disposition = "duplicate_superseded" if duplicate_of else base
        if duplicate_of:
            duplicate_entries += 1
        if disposition not in ALLOWED_DISPOSITIONS:
            raise CatalogError(f"unclassified disposition for {path}: {disposition}")
        record = {
            "schema_version": SCHEMA_VERSION,
            **item,
            "workspace_id": identifier,
            "workspace_name": original_name_by_workspace.get(identifier) if identifier else None,
            "workspace_focus": workspace_focus(identifier) if identifier else "package_evidence",
            "file_kind": kind,
            "integrity_status": integrity_statuses[path],
            "base_disposition": base,
            "disposition": disposition,
            "duplicate_of": duplicate_of,
            "rationale": (
                f"exact duplicate of {duplicate_of}" if duplicate_of else rationale
            ),
            "runtime_eligible": False,
            "requires_reproduction": base in {"experimental_build", "formal_reference", "generated_reproducible"},
        }
        catalog.append(record)
        disposition_counts[disposition] += 1
        kind_counts[kind] += 1
        if identifier:
            workspace_counts[identifier][disposition] += 1
            workspace_bytes[identifier] += item["bytes"]

    catalog_bytes = b"".join(canonical_json(record) for record in catalog)
    catalog_hash = hashlib.sha256(catalog_bytes).hexdigest()
    workspace_records = []
    for identifier in actual_workspaces:
        counts = workspace_counts[identifier]
        workspace_records.append(
            {
                "workspace_id": identifier,
                "original_workspace": original_name_by_workspace[identifier],
                "focus": workspace_focus(identifier),
                "entry_count": sum(counts.values()),
                "bytes": workspace_bytes[identifier],
                "dispositions": dict(sorted(counts.items())),
                "reproduction_status": "not_started",
                "active_runtime": False,
            }
        )
    workspaces_document = {
        "schema_version": WORKSPACE_SCHEMA_VERSION,
        "catalog_sha256": catalog_hash,
        "workspace_count": len(workspace_records),
        "workspaces": workspace_records,
    }
    workspaces_bytes = json.dumps(workspaces_document, indent=2, sort_keys=True).encode("ascii") + b"\n"

    duplicate_clusters = sum(1 for paths in by_digest.values() if len(paths) > 1)
    summary_body = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_bundle": archive_root.name,
        "manifest_entry_count": len(catalog),
        "readme_reported_original_entry_count": README_ORIGINAL_ENTRIES,
        "package_record_delta": len(catalog) - README_ORIGINAL_ENTRIES,
        "workspace_count": len(workspace_records),
        "catalog_sha256": catalog_hash,
        "byte_verification_attempted": verify_bytes,
        "archive_bytes_verified": verify_bytes and not integrity_errors,
        "integrity_failure_count": len(integrity_errors),
        "integrity_failures": integrity_errors,
        "unclassified_count": 0,
        "runtime_eligible_count": 0,
        "active_port_count": disposition_counts["active_port"],
        "duplicate_cluster_count": duplicate_clusters,
        "duplicate_entry_count": duplicate_entries,
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "file_kind_counts": dict(sorted(kind_counts.items())),
        "safety_boundary": {
            "archived_instructions_are_authority": False,
            "preserved_binaries_may_execute": False,
            "automatic_runtime_promotion": False,
            "groth16_default_changed": False,
            "stark_activation_changed": False,
            "rules_runtime_changed": False,
        },
    }
    checkpoint_hash = hashlib.sha256(canonical_json(summary_body)).hexdigest()
    summary = {**summary_body, "checkpoint_sha256": checkpoint_hash}
    summary_bytes = json.dumps(summary, indent=2, sort_keys=True).encode("ascii") + b"\n"
    return BuildOutputs(catalog_bytes, summary_bytes, workspaces_bytes, summary)


def write_or_check(outputs: BuildOutputs, output_dir: Path, *, check: bool) -> None:
    files = {
        "catalog_v1.jsonl": outputs.catalog_bytes,
        "catalog_summary_v1.json": outputs.summary_bytes,
        "workspace_dispositions_v1.json": outputs.workspaces_bytes,
    }
    if check:
        mismatches = []
        for name, expected in files.items():
            path = output_dir / name
            try:
                actual = path.read_bytes()
            except OSError:
                mismatches.append(f"missing:{path}")
                continue
            if actual != expected:
                mismatches.append(f"changed:{path}")
        if mismatches:
            raise CatalogError("catalog outputs are stale: " + ", ".join(mismatches))
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (output_dir / name).write_bytes(content)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive_root", type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "right-rail-integration" / "reports",
    )
    parser.add_argument("--check", action="store_true", help="verify committed outputs are current")
    parser.add_argument(
        "--skip-byte-verification",
        action="store_true",
        help="classify metadata without rehashing source bytes; not valid for a release checkpoint",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        outputs = build_catalog(args.archive_root.resolve(), verify_bytes=not args.skip_byte_verification)
        write_or_check(outputs, args.output_dir.resolve(), check=args.check)
    except CatalogError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(outputs.summary, sort_keys=True))
    if outputs.summary["integrity_failure_count"]:
        print(
            f"[FAIL] {outputs.summary['integrity_failure_count']} archive entries could not be verified",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
