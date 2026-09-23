#!/usr/bin/env python3
"""Statically analyze every mapped RightRail workspace without executing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = "localbce-rightrail-workspace-static-analysis-v1"
SUMMARY_SCHEMA_VERSION = "localbce-rightrail-workspace-static-summary-v1"
EXPECTED_WORKSPACES = tuple(f"r{number:03d}" for number in range(1, 74))
MAX_SCAN_BYTES = 2 * 1024 * 1024

TEXT_SUFFIXES = frozenset(
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
        ".json",
        ".lean",
        ".lock",
        ".md",
        ".ps1",
        ".py",
        ".rs",
        ".sh",
        ".sol",
        ".tcl",
        ".toml",
        ".txt",
        ".vcxproj",
        ".xml",
        ".yaml",
        ".yml",
    }
)

LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".h": "c_header",
    ".hpp": "cpp_header",
    ".lean": "lean",
    ".ps1": "powershell",
    ".py": "python",
    ".rs": "rust",
    ".sh": "shell",
    ".sol": "solidity",
    ".tcl": "tcl",
}

BUILD_NAMES = frozenset(
    {
        "cargo.lock",
        "cargo.toml",
        "cmakelists.txt",
        "lake-manifest.json",
        "lakefile.lean",
        "lakefile.toml",
        "lean-toolchain",
        "makefile",
        "pyproject.toml",
        "requirements-dev.txt",
        "requirements.txt",
    }
)

REVIEW_PATTERNS = {
    "dynamic_code_execution": re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
    "native_library_loading": re.compile(
        r"\b(?:ctypes|LoadLibrary|dlopen|libloading)\b", re.IGNORECASE
    ),
    "network_access": re.compile(
        r"\b(?:requests\.|urllib\.|socket\.|TcpStream|WinHTTP|curl\s|wget\s)", re.IGNORECASE
    ),
    "process_execution": re.compile(
        r"\b(?:subprocess\.|os\.system\s*\(|std::process::Command|CreateProcess|ShellExecute|WinExec|popen\s*\()",
        re.IGNORECASE,
    ),
    "unsafe_rust": re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b)", re.IGNORECASE),
}


class AnalysisError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"could not read {path}: {exc}") from exc


def load_catalog(path: Path) -> list[dict[str, Any]]:
    entries = []
    try:
        with path.open("r", encoding="ascii") as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AnalysisError(f"invalid catalog JSON at line {line_number}: {exc}") from exc
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    raise AnalysisError(f"invalid catalog entry at line {line_number}")
                entries.append(entry)
    except OSError as exc:
        raise AnalysisError(f"could not read catalog {path}: {exc}") from exc
    return entries


def priority(identifier: str) -> tuple[int, str]:
    if identifier == "r067":
        return 1, "operational ledger, Mirror, source admission, and financial owner"
    if identifier == "r068":
        return 2, "reproduction and orchestration runner"
    if identifier in {"r001", "r006"}:
        return 3, "evidence baseline or source corrections"
    if identifier in {"r002", "r003", "r004", "r005", "r069", "r070", "r071", "r072", "r073"}:
        return 4, "formal semantics and codec lane"
    return 5, "post-quantum research lane"


def is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return "tests" in {part.lower() for part in pure.parts} or pure.name.lower().startswith("test_")


def static_scan_file(path: Path) -> tuple[Counter[str], str | None]:
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return Counter(), "too_large"
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return Counter(), "non_utf8"
    except OSError:
        return Counter(), "unreadable"
    findings = Counter()
    for name, pattern in REVIEW_PATTERNS.items():
        if pattern.search(text):
            findings[name] += 1
    return findings, None


def analyze(archive_root: Path, reports_dir: Path) -> tuple[bytes, bytes, dict[str, Any]]:
    catalog_path = reports_dir / "catalog_v1.jsonl"
    summary_path = reports_dir / "catalog_summary_v1.json"
    catalog_summary = load_json(summary_path)
    catalog_entries = load_catalog(catalog_path)
    if catalog_summary.get("manifest_entry_count") != len(catalog_entries):
        raise AnalysisError("catalog summary entry count does not match catalog")

    by_workspace: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in catalog_entries:
        identifier = entry.get("workspace_id")
        if isinstance(identifier, str):
            by_workspace[identifier].append(entry)
    if tuple(sorted(by_workspace)) != EXPECTED_WORKSPACES:
        raise AnalysisError(f"expected 73 complete workspaces, got {len(by_workspace)}")

    workspace_records = []
    total_markers: Counter[str] = Counter()
    total_scan_errors: Counter[str] = Counter()
    scan_cache: dict[str, Counter[str]] = {}
    for identifier in EXPECTED_WORKSPACES:
        entries = by_workspace[identifier]
        kinds = Counter(str(entry["file_kind"]) for entry in entries)
        dispositions = Counter(str(entry["disposition"]) for entry in entries)
        languages: Counter[str] = Counter()
        review_markers: Counter[str] = Counter()
        marker_paths: dict[str, list[str]] = defaultdict(list)
        scan_errors: Counter[str] = Counter()
        build_descriptors: list[str] = []
        tests = 0
        scanned = 0

        for entry in entries:
            stored_path = str(entry["path"])
            pure = PurePosixPath(stored_path)
            suffix = pure.suffix.lower()
            if suffix in LANGUAGES:
                languages[LANGUAGES[suffix]] += 1
            if is_test_path(stored_path):
                tests += 1
            if pure.name.lower() in BUILD_NAMES or suffix in {".sln", ".vcxproj"}:
                build_descriptors.append(stored_path)
            if suffix not in TEXT_SUFFIXES or entry["base_disposition"] == "generated_reproducible":
                continue
            content_hash = str(entry["sha256"])
            cached_findings = scan_cache.get(content_hash)
            if cached_findings is None:
                source = archive_root.joinpath(*pure.parts)
                findings, error = static_scan_file(source)
                if error is None:
                    scan_cache[content_hash] = findings
            else:
                findings, error = cached_findings, None
            if error:
                scan_errors[error] += 1
                continue
            scanned += 1
            for marker, count in findings.items():
                review_markers[marker] += count
                if len(marker_paths[marker]) < 20:
                    marker_paths[marker].append(stored_path)

        total_markers.update(review_markers)
        total_scan_errors.update(scan_errors)
        rank, rationale = priority(identifier)
        blockers = ["archive_security_quarantine", "workspace_reproduction_not_run"]
        if kinds["binary"]:
            blockers.append("preserved_binary_present")
        if build_descriptors:
            blockers.append("dependency_review_required")
        if scan_errors:
            blockers.append("static_scan_incomplete")
        workspace_records.append(
            {
                "workspace_id": identifier,
                "original_workspace": entries[0].get("workspace_name"),
                "focus": entries[0].get("workspace_focus"),
                "priority": rank,
                "priority_rationale": rationale,
                "entry_count": len(entries),
                "total_bytes": sum(int(entry["bytes"]) for entry in entries),
                "file_kind_counts": dict(sorted(kinds.items())),
                "disposition_counts": dict(sorted(dispositions.items())),
                "language_counts": dict(sorted(languages.items())),
                "test_file_count": tests,
                "build_descriptors": sorted(build_descriptors),
                "static_text_files_scanned": scanned,
                "static_scan_errors": dict(sorted(scan_errors.items())),
                "review_marker_counts": dict(sorted(review_markers.items())),
                "review_marker_paths": {key: sorted(value) for key, value in sorted(marker_paths.items())},
                "execution_allowed": False,
                "reproduction_status": "blocked_pending_archive_security_review",
                "blocker_codes": blockers,
                "runtime_eligible": False,
            }
        )

    document_body = {
        "schema_version": SCHEMA_VERSION,
        "source_bundle": archive_root.name,
        "catalog_sha256": catalog_summary.get("catalog_sha256"),
        "workspace_count": len(workspace_records),
        "execution_allowed": False,
        "workspaces": workspace_records,
    }
    document_bytes = json.dumps(document_body, indent=2, sort_keys=True).encode("ascii") + b"\n"
    analysis_hash = hashlib.sha256(document_bytes).hexdigest()
    summary_body = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_bundle": archive_root.name,
        "catalog_sha256": catalog_summary.get("catalog_sha256"),
        "analysis_sha256": analysis_hash,
        "workspace_count": len(workspace_records),
        "execution_allowed_workspace_count": 0,
        "blocked_workspace_count": len(workspace_records),
        "total_entry_count": sum(record["entry_count"] for record in workspace_records),
        "total_test_file_count": sum(record["test_file_count"] for record in workspace_records),
        "review_marker_counts": dict(sorted(total_markers.items())),
        "static_scan_errors": dict(sorted(total_scan_errors.items())),
        "priority_order": [record["workspace_id"] for record in sorted(workspace_records, key=lambda item: (item["priority"], item["workspace_id"]))],
        "security_blocker": "archive_security_quarantine",
        "runtime_eligible_count": 0,
    }
    checkpoint_hash = hashlib.sha256(canonical_json(summary_body)).hexdigest()
    summary = {**summary_body, "checkpoint_sha256": checkpoint_hash}
    summary_bytes = json.dumps(summary, indent=2, sort_keys=True).encode("ascii") + b"\n"
    return document_bytes, summary_bytes, summary


def write_or_check(reports_dir: Path, document: bytes, summary: bytes, *, check: bool) -> None:
    outputs = {
        "workspace_static_analysis_v1.json": document,
        "workspace_static_analysis_summary_v1.json": summary,
    }
    if check:
        stale = []
        for name, expected in outputs.items():
            path = reports_dir / name
            try:
                actual = path.read_bytes()
            except OSError:
                stale.append(f"missing:{path}")
                continue
            if actual != expected:
                stale.append(f"changed:{path}")
        if stale:
            raise AnalysisError("static analysis reports are stale: " + ", ".join(stale))
        return
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (reports_dir / name).write_bytes(content)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive_root", type=Path)
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "right-rail-integration" / "reports",
    )
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        document, summary_bytes, summary = analyze(args.archive_root.resolve(), args.reports_dir.resolve())
        write_or_check(args.reports_dir.resolve(), document, summary_bytes, check=args.check)
    except AnalysisError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
