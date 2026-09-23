#!/usr/bin/env python3
"""Inventory the fixed RightRail PDF set without retaining extracted document text."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from pypdf import PdfReader


SCHEMA_VERSION = "localbce-rightrail-pdf-inventory-v1"
PDF_SPECS = {
    "original/reference/RightRail_Architecture_and_Operating_Plan.pdf": {
        "content_role": "operating_plan_review_candidate",
        "text_twin": None,
    },
    "root/work/unruh-2017-398.pdf": {
        "content_role": "cryptographic_research_reference",
        "text_twin": "root/work/unruh-2017-398.txt",
    },
    "w/r012/dfms-2022-270.pdf": {
        "content_role": "cryptographic_research_reference",
        "text_twin": None,
    },
    "w/r038/katsumata-2021-927.pdf": {
        "content_role": "cryptographic_research_reference",
        "text_twin": None,
    },
}


class PdfInventoryError(RuntimeError):
    pass


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


def load_catalog(path: Path) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    try:
        with path.open("r", encoding="ascii") as handle:
            for line_number, line in enumerate(handle, start=1):
                entry = json.loads(line)
                stored_path = entry.get("path") if isinstance(entry, dict) else None
                if not isinstance(stored_path, str):
                    raise PdfInventoryError(f"invalid catalog entry at line {line_number}")
                entries[stored_path] = entry
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PdfInventoryError(f"could not read catalog {path}: {exc}") from exc
    return entries


def extract_pdf(path: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    try:
        reader = PdfReader(path, strict=True)
        pages = []
        for page_number, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            pages.append(
                {
                    "page_number": page_number,
                    "text_chars": len(text),
                    "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "text_layer_present": bool(text.strip()),
                }
            )
        metadata = reader.metadata or {}
    except Exception as exc:
        raise PdfInventoryError(f"could not extract {path}: {exc}") from exc
    return pages, {
        "title": str(metadata.get("/Title") or ""),
        "author": str(metadata.get("/Author") or ""),
        "creator": str(metadata.get("/Creator") or ""),
        "producer": str(metadata.get("/Producer") or ""),
    }


def build_inventory(archive_root: Path, reports_dir: Path) -> tuple[bytes, dict[str, Any]]:
    catalog = load_catalog(reports_dir / "catalog_v1.jsonl")
    documents = []
    for stored_path, spec in PDF_SPECS.items():
        entry = catalog.get(stored_path)
        if entry is None:
            raise PdfInventoryError(f"PDF is absent from catalog: {stored_path}")
        source = archive_root.joinpath(*PurePosixPath(stored_path).parts)
        try:
            size = source.stat().st_size
            source_hash = sha256_file(source)
        except OSError as exc:
            raise PdfInventoryError(f"could not read {source}: {exc}") from exc
        if size != entry.get("bytes") or source_hash != entry.get("sha256"):
            raise PdfInventoryError(f"PDF does not match catalog: {stored_path}")
        pages, metadata = extract_pdf(source)
        if not pages or not all(page["text_layer_present"] for page in pages):
            raise PdfInventoryError(f"PDF has an incomplete text layer: {stored_path}")
        documents.append(
            {
                "path": stored_path,
                "workspace_id": entry.get("workspace_id"),
                "bytes": size,
                "source_sha256": source_hash,
                "content_role": spec["content_role"],
                "text_twin": spec["text_twin"],
                "metadata": metadata,
                "page_count": len(pages),
                "extracted_text_chars": sum(page["text_chars"] for page in pages),
                "pages": pages,
                "status": "extracted_for_static_review",
                "human_review_status": "not_reviewed",
                "runtime_eligible": False,
                "execution_allowed": False,
            }
        )

    body = {
        "schema_version": SCHEMA_VERSION,
        "source_bundle": archive_root.name,
        "extractor": {"name": "pypdf", "version": importlib.metadata.version("pypdf")},
        "document_count": len(documents),
        "page_count": sum(document["page_count"] for document in documents),
        "text_layer_complete_count": len(documents),
        "runtime_eligible_count": 0,
        "execution_allowed": False,
        "documents": documents,
    }
    checkpoint = hashlib.sha256(canonical_json(body)).hexdigest()
    report = {**body, "checkpoint_sha256": checkpoint}
    report_bytes = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True).encode("ascii") + b"\n"
    return report_bytes, report


def write_or_check(path: Path, content: bytes, *, check: bool) -> None:
    if check:
        try:
            current = path.read_bytes()
        except OSError as exc:
            raise PdfInventoryError(f"could not read report {path}: {exc}") from exc
        if current != content:
            raise PdfInventoryError(f"PDF inventory is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


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
    report_path = args.reports_dir.resolve() / "pdf_document_inventory_v1.json"
    try:
        report_bytes, report = build_inventory(args.archive_root.resolve(), args.reports_dir.resolve())
        write_or_check(report_path, report_bytes, check=args.check)
    except PdfInventoryError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "document_count": report["document_count"],
                "page_count": report["page_count"],
                "checkpoint_sha256": report["checkpoint_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
