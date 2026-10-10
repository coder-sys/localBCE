#!/usr/bin/env python3
"""Catalog a RightRail handoff without extracting or executing its contents."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA_VERSION = "localbce-rightrail-handoff-catalog-v1"
SUMMARY_SCHEMA_VERSION = "localbce-rightrail-handoff-summary-v1"
SECURITY_SCHEMA_VERSION = "localbce-rightrail-handoff-security-v1"
SOURCE_BUNDLE = "RightRail-handoff-2026-10-03_0916"
EXPECTED_MANIFEST_ENTRIES = 322
EXPECTED_PACKAGE_FILES = 323
EXPECTED_TRUNK_FILES = 637
EXPECTED_TRUNK_COMMIT = "058ff4e9a7b4547d25fd0de9a1177c53357b2ea3"
EXPECTED_HEAD_REFS = 144
EXPECTED_TAG_REFS = 1
EXPECTED_NOTE_REFS = 1
EXPECTED_ALL_REFS = 148
EXPECTED_SKIPPED_BIG = 29
MAX_ZIP_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100.0

CATALOG_NAME = "handoff_20261003_catalog_v1.jsonl"
SUMMARY_NAME = "handoff_20261003_catalog_summary_v1.json"
SECURITY_NAME = "handoff_20261003_security_report_v1.json"

BINARY_SUFFIXES = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".o",
        ".obj",
        ".a",
        ".lib",
        ".wasm",
        ".jar",
        ".pyc",
    }
)
FORMAL_SUFFIXES = frozenset({".lean", ".tla", ".cfg"})
SCRIPT_SUFFIXES = frozenset({".py", ".ps1", ".sh", ".bat", ".cmd"})
CANONICAL_CONTROL_PATHS = frozenset(
    {
        "CONSTITUTION.md",
        "ARCHITECTURE.md",
        "STATUS.md",
        "docs/RIGHTRAIL_FULL_STACK_TARGET.md",
    }
)


class HandoffCatalogError(RuntimeError):
    pass


@dataclass(frozen=True)
class CatalogOutputs:
    catalog: bytes
    summary: bytes
    security: bytes
    summary_value: dict[str, Any]


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise HandoffCatalogError(f"could not hash {path}: {exc}") from exc
    return digest.hexdigest()


def stable_id(surface: str, locator: str) -> str:
    value = hashlib.sha256(f"{surface}\0{locator}".encode("utf-8")).hexdigest()[:24]
    return f"rrhandoff-{value}"


def safe_relative_path(raw: str, *, label: str) -> str:
    if not raw or "\x00" in raw or "\\" in raw:
        raise HandoffCatalogError(f"unsafe {label} path: {raw!r}")
    if any(part in {"", ".", ".."} for part in raw.split("/")):
        raise HandoffCatalogError(f"unsafe {label} path: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute():
        raise HandoffCatalogError(f"unsafe {label} path: {raw!r}")
    if re.match(r"^[A-Za-z]:", raw):
        raise HandoffCatalogError(f"unsafe {label} path: {raw!r}")
    return path.as_posix()


def parse_manifest(path: Path) -> dict[str, str]:
    records: dict[str, str] = {}
    pattern = re.compile(r"([0-9a-f]{64}) [ *](.+)")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise HandoffCatalogError(f"could not read manifest {path}: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        match = pattern.fullmatch(line)
        if not match:
            raise HandoffCatalogError(f"invalid manifest line {line_number}")
        relative = safe_relative_path(match.group(2), label="manifest")
        if relative in records:
            raise HandoffCatalogError(f"duplicate manifest path: {relative}")
        records[relative] = match.group(1)
    if len(records) != EXPECTED_MANIFEST_ENTRIES:
        raise HandoffCatalogError(
            f"expected {EXPECTED_MANIFEST_ENTRIES} manifest entries, got {len(records)}"
        )
    return records


def source_domain(path: str) -> str:
    lower = path.lower()
    if "mldsa" in lower or "pq" in lower or "sign" in lower:
        return "post_quantum_research"
    if lower.endswith(tuple(FORMAL_SUFFIXES)) or "/lean/" in f"/{lower}":
        return "formal_verification"
    if "rule" in lower or "control_pack" in lower or "control-pack" in lower:
        return "adjudication_and_rules"
    if any(token in lower for token in ("settle", "payment", "cash", "financial", "outbox")):
        return "settlement_and_recovery"
    if any(token in lower for token in ("database", "state", "history", "continuity", "checkpoint")):
        return "state_and_audit_history"
    if any(token in lower for token in ("privacy", "phi", "source", "evidence", "mirror")):
        return "privacy_and_source_evidence"
    if any(token in lower for token in ("staff_workspace", "provider_app", "ui-", "color")):
        return "ui_and_operations"
    return "authorization_and_governance"


def disposition(path: str, *, surface: str) -> tuple[str, str]:
    lower = path.lower()
    suffix = PurePosixPath(path).suffix.lower()
    if surface == "git_ref":
        return "reference_only", "historical Git ref; never merged or executed automatically"
    if suffix in BINARY_SUFFIXES:
        return "quarantine", "preserved binary or opaque executable artifact"
    if surface == "package_file" and path in {"RightRail.bundle", "trunk-source.zip"}:
        return "quarantine", "archive retained externally; inspect only through bounded readers"
    if lower.startswith("work-in-progress/") or suffix == ".patch":
        return "quarantine", "unapplied work-in-progress patch"
    if lower.startswith("claude-setup/") or lower.startswith("test-runner/"):
        return "reference_only", "archived automation or agent instruction; not project authority"
    if lower.startswith("lead-notes/") or lower.startswith("lead-state/"):
        return "reference_only", "historical planning and handoff evidence"
    if lower.startswith("reviews/"):
        return "reference_only", "historical review evidence"
    if lower.startswith("parked/"):
        return "reference_only", "explicitly parked source"
    if surface == "trunk_member" and path in CANONICAL_CONTROL_PATHS:
        return "adopt_control", "canonical control document proposed for localBCE crosswalk review"
    if suffix in FORMAL_SUFFIXES:
        return "shadow_candidate", "formal artifact candidate; isolated from runtime"
    if source_domain(path) == "post_quantum_research":
        return "shadow_candidate", "post-quantum compatibility research only"
    if lower.startswith("tests/") or lower.startswith("conformance/"):
        return "shadow_candidate", "test or conformance behavior proposed for adaptation"
    if lower.startswith("app/") or lower.startswith("tools/") or lower.startswith("rust/"):
        return "adapt_specification", "source behavior may inform rewritten localBCE controls"
    if suffix in SCRIPT_SUFFIXES:
        return "reference_only", "script is documentary input and must not execute from the handoff"
    if suffix in {".md", ".txt", ".json", ".tsv", ".toml"}:
        return "adapt_specification", "document or data specification proposed for review"
    return "reference_only", "fully accounted reference material"


def common_record(
    *,
    surface: str,
    locator: str,
    sha256: str | None,
    bytes_count: int | None,
    disposition_value: str,
    rationale: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": stable_id(surface, locator),
        "source_bundle": SOURCE_BUNDLE,
        "source_surface": surface,
        "locator": locator,
        "sha256": sha256,
        "bytes": bytes_count,
        "domain": source_domain(locator),
        "disposition": disposition_value,
        "rationale": rationale,
        "execution_allowed": False,
        "runtime_eligible": False,
        "proof_binding": False,
        "human_approved": False,
        "legally_verified": False,
    }


def load_prior_catalog(path: Path) -> dict[str, list[str]]:
    by_hash: dict[str, list[str]] = defaultdict(list)
    try:
        with path.open("r", encoding="ascii") as handle:
            for line_number, line in enumerate(handle, start=1):
                value = json.loads(line)
                digest = value.get("sha256")
                locator = value.get("original_path") or value.get("path")
                if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
                    by_hash[digest].append(str(locator or f"line:{line_number}"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoffCatalogError(f"could not read prior catalog {path}: {exc}") from exc
    return by_hash


def package_records(root: Path, manifest: dict[str, str]) -> list[dict[str, Any]]:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    symlinks = [path for path in root.rglob("*") if path.is_symlink()]
    if symlinks:
        relative = [path.relative_to(root).as_posix() for path in symlinks]
        raise HandoffCatalogError(f"package contains symbolic links: {relative}")
    if len(files) != EXPECTED_PACKAGE_FILES:
        raise HandoffCatalogError(
            f"expected {EXPECTED_PACKAGE_FILES} package files, got {len(files)}"
        )
    actual_relative = {path.relative_to(root).as_posix() for path in files}
    expected_relative = set(manifest) | {"MANIFEST.sha256"}
    if actual_relative != expected_relative:
        missing = sorted(expected_relative - actual_relative)
        extra = sorted(actual_relative - expected_relative)
        raise HandoffCatalogError(f"package file mismatch; missing={missing}, extra={extra}")

    records = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest = sha256_file(path)
        expected = manifest.get(relative)
        if expected is not None and digest != expected:
            raise HandoffCatalogError(f"manifest hash mismatch: {relative}")
        value, rationale = disposition(relative, surface="package_file")
        record = common_record(
            surface="package_file",
            locator=relative,
            sha256=digest,
            bytes_count=path.stat().st_size,
            disposition_value=value,
            rationale=rationale,
        )
        record["integrity_status"] = "manifest_self" if expected is None else "verified"
        records.append(record)
    return records


def trunk_records(zip_path: Path, prior: dict[str, list[str]]) -> list[dict[str, Any]]:
    records = []
    seen: set[str] = set()
    total_uncompressed = 0
    try:
        archive = zipfile.ZipFile(zip_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise HandoffCatalogError(f"could not read trunk ZIP: {exc}") from exc
    with archive:
        members = [member for member in archive.infolist() if not member.is_dir()]
        if len(members) != EXPECTED_TRUNK_FILES:
            raise HandoffCatalogError(
                f"expected {EXPECTED_TRUNK_FILES} trunk files, got {len(members)}"
            )
        for member in members:
            relative = safe_relative_path(member.filename, label="ZIP member")
            if relative in seen:
                raise HandoffCatalogError(f"duplicate ZIP member: {relative}")
            seen.add(relative)
            if member.file_size > MAX_ZIP_MEMBER_BYTES:
                raise HandoffCatalogError(f"ZIP member exceeds size limit: {relative}")
            ratio = member.file_size / max(member.compress_size, 1)
            if ratio > MAX_COMPRESSION_RATIO:
                raise HandoffCatalogError(f"ZIP member exceeds compression-ratio limit: {relative}")
            total_uncompressed += member.file_size
            if total_uncompressed > MAX_ZIP_TOTAL_BYTES:
                raise HandoffCatalogError("trunk ZIP exceeds total uncompressed size limit")
            content = archive.read(member)
            digest = sha256_bytes(content)
            value, rationale = disposition(relative, surface="trunk_member")
            record = common_record(
                surface="trunk_member",
                locator=relative,
                sha256=digest,
                bytes_count=member.file_size,
                disposition_value=value,
                rationale=rationale,
            )
            matches = sorted(prior.get(digest, []))
            record.update(
                {
                    "compressed_bytes": member.compress_size,
                    "compression_ratio": round(ratio, 6),
                    "prior_catalog_content_match": bool(matches),
                    "prior_catalog_match_count": len(matches),
                    "prior_catalog_sample_paths": matches[:5],
                }
            )
            records.append(record)
    return records


def run_git_bundle(args: list[str], *, timeout: int = 60) -> str:
    try:
        completed = subprocess.run(
            ["git", "bundle", *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HandoffCatalogError(f"could not inspect Git bundle: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise HandoffCatalogError(f"Git bundle inspection failed: {detail}")
    return completed.stdout + completed.stderr


def ref_records(bundle_path: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    run_git_bundle(["verify", str(bundle_path)])
    output = run_git_bundle(["list-heads", str(bundle_path)])
    records = []
    counts = Counter()
    seen = set()
    for raw in output.splitlines():
        match = re.fullmatch(r"([0-9a-f]{40}) (.+)", raw.strip())
        if not match:
            continue
        object_id, ref = match.groups()
        if ref in seen:
            raise HandoffCatalogError(f"duplicate Git bundle ref: {ref}")
        seen.add(ref)
        if ref.startswith("refs/heads/"):
            kind = "head"
        elif ref.startswith("refs/tags/"):
            kind = "tag"
        elif ref.startswith("refs/notes/"):
            kind = "note"
        elif ref == "HEAD":
            kind = "HEAD"
        else:
            kind = "other"
        counts[kind] += 1
        value, rationale = disposition(ref, surface="git_ref")
        record = common_record(
            surface="git_ref",
            locator=ref,
            sha256=None,
            bytes_count=None,
            disposition_value=value,
            rationale=rationale,
        )
        record.update({"git_object_id": object_id, "ref_kind": kind})
        records.append(record)
    if len(records) != EXPECTED_ALL_REFS:
        raise HandoffCatalogError(f"expected {EXPECTED_ALL_REFS} Git refs, got {len(records)}")
    if counts["head"] != EXPECTED_HEAD_REFS:
        raise HandoffCatalogError(f"expected {EXPECTED_HEAD_REFS} branch refs, got {counts['head']}")
    if counts["tag"] != EXPECTED_TAG_REFS or counts["note"] != EXPECTED_NOTE_REFS:
        raise HandoffCatalogError("unexpected tag or notes ref count")
    head = next((item for item in records if item["locator"] == "HEAD"), None)
    if head is None or head["git_object_id"] != EXPECTED_TRUNK_COMMIT:
        raise HandoffCatalogError("Git bundle HEAD does not match expected trunk commit")
    return records, dict(sorted(counts.items()))


def parse_security_report(path: Path) -> tuple[list[dict[str, Any]], int, int]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise HandoffCatalogError(f"could not read scan report: {exc}") from exc
    pattern = re.compile(r"SKIPPED_BIG ([0-9a-f]{40}) (\d+) ([^;]+)")
    skipped = []
    seen = set()
    for match in pattern.finditer(text):
        path_value = safe_relative_path(match.group(3), label="history blob")
        identity = (match.group(1), path_value)
        if identity in seen:
            raise HandoffCatalogError(f"duplicate skipped history blob: {path_value}")
        seen.add(identity)
        skipped.append(
            {
                "git_object_id": match.group(1),
                "bytes": int(match.group(2)),
                "path": path_value,
                "disposition": "quarantine",
                "execution_allowed": False,
                "blocker": "history_blob_not_secret_scanned_due_to_size",
            }
        )
    if len(skipped) != EXPECTED_SKIPPED_BIG:
        raise HandoffCatalogError(
            f"expected {EXPECTED_SKIPPED_BIG} skipped large blobs, got {len(skipped)}"
        )
    result = re.search(r"SCANNED (\d+) blobs in \d+ s, (\d+) hits", text)
    if result is None:
        raise HandoffCatalogError("scan report is missing history scan totals")
    return skipped, int(result.group(1)), int(result.group(2))


def assert_safe(records: Iterable[dict[str, Any]]) -> None:
    for record in records:
        for field in ("execution_allowed", "runtime_eligible", "proof_binding", "human_approved", "legally_verified"):
            if record.get(field) is not False:
                raise HandoffCatalogError(f"unsafe {field} in {record.get('record_id')}")
        if record.get("disposition") not in {
            "adopt_control",
            "adapt_specification",
            "shadow_candidate",
            "reference_only",
            "superseded_duplicate",
            "quarantine",
        }:
            raise HandoffCatalogError(f"unsupported disposition in {record.get('record_id')}")


def build_catalog(root: Path, prior_catalog_path: Path) -> CatalogOutputs:
    root = root.resolve()
    manifest = parse_manifest(root / "MANIFEST.sha256")
    prior = load_prior_catalog(prior_catalog_path)
    packages = package_records(root, manifest)
    trunks = trunk_records(root / "trunk-source.zip", prior)
    refs, ref_counts = ref_records(root / "RightRail.bundle")
    skipped, scanned_blobs, scan_hits = parse_security_report(root / "scan-report.txt")
    records = sorted(
        [*packages, *trunks, *refs],
        key=lambda item: (item["source_surface"], item["locator"], item["record_id"]),
    )
    assert_safe(records)
    catalog = b"".join(canonical_json(record) for record in records)
    disposition_counts = Counter(record["disposition"] for record in records)
    domain_counts = Counter(record["domain"] for record in records)
    surface_counts = Counter(record["source_surface"] for record in records)
    prior_matches = sum(
        1 for record in trunks if record.get("prior_catalog_content_match") is True
    )
    security_body = {
        "schema_version": SECURITY_SCHEMA_VERSION,
        "source_bundle": SOURCE_BUNDLE,
        "history_scan_blob_count": scanned_blobs,
        "history_scan_hit_count": scan_hits,
        "skipped_large_blob_count": len(skipped),
        "skipped_large_blobs": skipped,
        "binary_execution_allowed": False,
        "archive_extraction_allowed": False,
        "security_status": "quarantine_required",
    }
    security = {
        **security_body,
        "checkpoint_sha256": sha256_bytes(canonical_json(security_body)),
    }
    summary_body = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_bundle": SOURCE_BUNDLE,
        "source_bundle_path_committed": False,
        "trunk_commit": EXPECTED_TRUNK_COMMIT,
        "manifest_entry_count": len(manifest),
        "package_file_count": len(packages),
        "trunk_file_count": len(trunks),
        "git_ref_count": len(refs),
        "git_ref_counts": ref_counts,
        "catalog_record_count": len(records),
        "source_surface_counts": dict(sorted(surface_counts.items())),
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "domain_counts": dict(sorted(domain_counts.items())),
        "prior_catalog_content_match_count": prior_matches,
        "new_or_changed_trunk_file_count": len(trunks) - prior_matches,
        "catalog_sha256": sha256_bytes(catalog),
        "security_checkpoint_sha256": security["checkpoint_sha256"],
        "security_status": security["security_status"],
        "execution_allowed_count": 0,
        "runtime_eligible_count": 0,
        "proof_binding_count": 0,
        "complete_disposition": True,
    }
    summary = {
        **summary_body,
        "checkpoint_sha256": sha256_bytes(canonical_json(summary_body)),
    }
    return CatalogOutputs(
        catalog=catalog,
        summary=json.dumps(summary, indent=2, sort_keys=True).encode("ascii") + b"\n",
        security=json.dumps(security, indent=2, sort_keys=True).encode("ascii") + b"\n",
        summary_value=summary,
    )


def write_or_check(outputs: CatalogOutputs, reports_dir: Path, *, check: bool) -> None:
    values = {
        CATALOG_NAME: outputs.catalog,
        SUMMARY_NAME: outputs.summary,
        SECURITY_NAME: outputs.security,
    }
    if check:
        stale = []
        for name, expected in values.items():
            path = reports_dir / name
            try:
                current = path.read_bytes()
            except OSError:
                stale.append(f"missing:{path}")
                continue
            if current != expected:
                stale.append(f"changed:{path}")
        if stale:
            raise HandoffCatalogError("handoff reports are stale: " + ", ".join(stale))
        return
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name, content in values.items():
        (reports_dir / name).write_bytes(content)


def parse_args(argv: list[str]) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handoff_root", type=Path)
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=root / "right-rail-integration" / "reports",
    )
    parser.add_argument(
        "--prior-catalog",
        type=Path,
        default=root / "right-rail-integration" / "reports" / "catalog_v1.jsonl",
    )
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        outputs = build_catalog(args.handoff_root, args.prior_catalog.resolve())
        write_or_check(outputs, args.reports_dir.resolve(), check=args.check)
    except HandoffCatalogError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    summary = outputs.summary_value
    print(
        json.dumps(
            {
                "status": "ok",
                "catalog_record_count": summary["catalog_record_count"],
                "trunk_file_count": summary["trunk_file_count"],
                "git_ref_count": summary["git_ref_count"],
                "checkpoint_sha256": summary["checkpoint_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
