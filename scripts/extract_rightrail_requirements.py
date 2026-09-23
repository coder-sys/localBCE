#!/usr/bin/env python3
"""Extract reviewable RightRail requirement candidates without executing archive code."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = "localbce-rightrail-requirement-candidate-v1"
SUMMARY_SCHEMA_VERSION = "localbce-rightrail-requirements-crosswalk-summary-v1"
MAX_TEXT_BYTES = 2 * 1024 * 1024
TEXT_DOCUMENT_SUFFIXES = frozenset({".md", ".txt"})
PDF_REQUIREMENT_PATH = "original/reference/RightRail_Architecture_and_Operating_Plan.pdf"
PDF_TEXT_TWIN_PATH = "root/work/unruh-2017-398.pdf"
PDF_DOCUMENTARY_PATHS = frozenset(
    {
        PDF_TEXT_TWIN_PATH,
        "w/r012/dfms-2022-270.pdf",
        "w/r038/katsumata-2021-927.pdf",
    }
)

NORMATIVE_PATTERN = re.compile(
    r"\b(?:must|must not|shall|shall not|required|requires|never|only|cannot|may not|do not|does not|remains?|fails? closed|prohibited|forbidden)\b",
    re.IGNORECASE,
)

DOMAIN_PATTERNS = {
    "rules_and_policy": re.compile(r"\b(?:rule|policy|control pack|jurisdiction|effective date|authority)\b", re.IGNORECASE),
    "source_and_evidence": re.compile(r"\b(?:source|evidence|citation|provenance|observation|FHIR)\b", re.IGNORECASE),
    "privacy_and_phi": re.compile(r"\b(?:privacy|PHI|patient|claimant|zero-PHI|secret)\b", re.IGNORECASE),
    "proof_and_crypto": re.compile(r"\b(?:proof|verifier|prover|commitment|STARK|Groth16|post-quantum|PQ|signature)\b", re.IGNORECASE),
    "state_and_database": re.compile(r"\b(?:database|transaction|state|root|rollback|recovery|continuity|outbox|SQLite)\b", re.IGNORECASE),
    "settlement_and_payment": re.compile(r"\b(?:settlement|payment|cash|funds|Ethereum|Solidity|directive|clearance)\b", re.IGNORECASE),
    "governance_and_operations": re.compile(r"\b(?:governance|approval|review|activation|production|custody|monitoring|audit)\b", re.IGNORECASE),
    "build_and_release": re.compile(r"\b(?:build|test|release|dependency|toolchain|workspace|artifact)\b", re.IGNORECASE),
}

CONFLICT_PATTERNS = {
    "conflicts_with_current_ethereum_settlement": re.compile(
        r"(?:Ethereum is not a dependency|No .*Solidity|no Solidity ABI)", re.IGNORECASE
    ),
    "requires_postgresql_adaptation": re.compile(r"\bSQLite\b", re.IGNORECASE),
    "requires_current_proof_profile_review": re.compile(
        r"\b(?:Profile 11|Profile 12|native-v3|PRIVATE_ZK)\b", re.IGNORECASE
    ),
}

SAFETY_PATTERNS = {
    "reinforces_nonactivation": re.compile(
        r"(?:activation\s*=\s*false|production_usable\s*=\s*false|nonactivating|not production qualified|unqualified|distinct from production results)",
        re.IGNORECASE,
    ),
    "reinforces_no_automatic_fallback": re.compile(
        r"(?:no runtime fallback|no automatic fallback|fallback or downgrade)", re.IGNORECASE
    ),
    "reinforces_proof_non_dispositive": re.compile(
        r"(?:proof acceptance .* not sufficient|proof acceptance .* cannot imply|proof .* does not .* authorize|non-dispositive)",
        re.IGNORECASE,
    ),
    "reinforces_no_direct_payment_authority": re.compile(
        r"(?:does not .* move money|no live payments|not .* payment authority|never .* cash evidence|power to .* requires .* authorization|(?:true-up|withholding|settlement).* must have .* authority)",
        re.IGNORECASE,
    ),
    "reinforces_sensitive_data_boundary": re.compile(
        r"(?:receive only approved non-sensitive material|no PHI|zero-PHI)", re.IGNORECASE
    ),
}


class RequirementsError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RequirementsError(f"could not read {path}: {exc}") from exc


def load_catalog(path: Path) -> list[dict[str, Any]]:
    entries = []
    try:
        with path.open("r", encoding="ascii") as handle:
            for line_number, line in enumerate(handle, start=1):
                entry = json.loads(line)
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    raise RequirementsError(f"invalid catalog entry at line {line_number}")
                entries.append(entry)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RequirementsError(f"could not read catalog {path}: {exc}") from exc
    return entries


def authority_class(path: str) -> str:
    name = PurePosixPath(path).name.lower()
    if name in {"agents.reference.txt", "current_task.md"} or path.endswith(
        "original/reference/implementation-request.txt"
    ):
        return "historical_instruction"
    if name in {"state.md", "start_here.md"}:
        return "status_evidence"
    if "architecture" in name or "/docs/" in path:
        return "architecture_candidate"
    if name == "readme.md":
        return "workspace_guide"
    return "documentary_evidence"


def normalize_statement(line: str) -> str:
    text = re.sub(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|>\s*)", "", line.strip())
    return re.sub(r"\s+", " ", text)


def statement_domains(text: str) -> list[str]:
    domains = [name for name, pattern in DOMAIN_PATTERNS.items() if pattern.search(text)]
    return domains or ["general"]


def crosswalk(text: str, authority: str) -> tuple[str, list[str]]:
    flags = [name for name, pattern in CONFLICT_PATTERNS.items() if pattern.search(text)]
    safety = [name for name, pattern in SAFETY_PATTERNS.items() if pattern.search(text)]
    flags.extend(safety)
    if authority == "historical_instruction":
        return "reference_only", sorted(set(flags + ["archived_instruction_not_authority"]))
    if any(flag.startswith("conflicts_") for flag in flags):
        return "conflict_review", sorted(set(flags))
    if safety:
        return "adopt_safety_boundary", sorted(set(flags))
    if "requires_postgresql_adaptation" in flags:
        return "adapt_candidate", sorted(set(flags))
    return "review_candidate", sorted(set(flags))


def candidate_id(path: str, line_number: int, statement: str) -> str:
    material = f"{path}\x00{line_number}\x00{statement}".encode("utf-8")
    return "rrreq-" + hashlib.sha256(material).hexdigest()[:24]


def pdf_page_statements(text: str, *, first_page: bool = False) -> list[str]:
    text = re.sub(r"(?<=\w)-\n(?=\w)", "", text)
    lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if first_page and line == "In this document":
            break
        if line == "RightRail Product & operating plan":
            continue
        if re.fullmatch(r"September 2026\s*\|\s*Internal working plan\s+\d+", line):
            continue
        if line:
            lines.append(line)
    joined = re.sub(r"\s+", " ", " ".join(lines)).strip()
    if not joined:
        return []
    return [
        statement.strip()
        for statement in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9`])", joined)
        if statement.strip()
    ]


def extract_pdf_lines(path: Path) -> tuple[list[tuple[int, int, str]], int, str]:
    try:
        from pypdf import PdfReader

        reader = PdfReader(path, strict=True)
        extracted: list[tuple[int, int, str]] = []
        text_digest = hashlib.sha256()
        statement_number = 0
        for page_number, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            if not text.strip():
                raise RequirementsError(f"PDF page {page_number} has no text layer: {path}")
            text_digest.update(text.encode("utf-8"))
            text_digest.update(b"\n\f\n")
            for statement in pdf_page_statements(text, first_page=page_number == 1):
                statement_number += 1
                extracted.append((page_number, statement_number, statement))
    except RequirementsError:
        raise
    except Exception as exc:
        raise RequirementsError(f"could not extract PDF {path}: {exc}") from exc
    return extracted, len(reader.pages), text_digest.hexdigest()


def extract(archive_root: Path, reports_dir: Path) -> tuple[bytes, bytes, dict[str, Any]]:
    catalog_summary = load_json(reports_dir / "catalog_summary_v1.json")
    catalog = load_catalog(reports_dir / "catalog_v1.jsonl")
    candidates: list[dict[str, Any]] = []
    document_statuses: list[dict[str, Any]] = []
    domain_counts: Counter[str] = Counter()
    authority_counts: Counter[str] = Counter()
    disposition_counts: Counter[str] = Counter()
    flag_counts: Counter[str] = Counter()
    workspace_counts: Counter[str] = Counter()

    canonical_documents = [
        entry
        for entry in catalog
        if entry.get("file_kind") == "document" and entry.get("duplicate_of") is None
    ]
    for entry in sorted(canonical_documents, key=lambda item: item["path"]):
        stored_path = str(entry["path"])
        pure = PurePosixPath(stored_path)
        suffix = pure.suffix.lower()
        status = {
            "path": stored_path,
            "workspace_id": entry.get("workspace_id"),
            "suffix": suffix,
            "bytes": entry.get("bytes"),
            "status": "not_scanned",
            "candidate_count": 0,
        }
        source = archive_root.joinpath(*pure.parts)
        source_format = "text"
        page_count = None
        text_sha256 = None
        if stored_path in PDF_DOCUMENTARY_PATHS:
            status["status"] = (
                "documentary_text_twin"
                if stored_path == PDF_TEXT_TWIN_PATH
                else "documentary_evidence_only"
            )
            document_statuses.append(status)
            continue
        if stored_path == PDF_REQUIREMENT_PATH:
            source_format = "pdf"
            located_lines, page_count, text_sha256 = extract_pdf_lines(source)
        elif suffix not in TEXT_DOCUMENT_SUFFIXES:
            status["status"] = "requires_format_extractor"
            document_statuses.append(status)
            continue
        else:
            try:
                if source.stat().st_size > MAX_TEXT_BYTES:
                    status["status"] = "too_large"
                    document_statuses.append(status)
                    continue
                located_lines = [
                    (0, line_number, raw_line)
                    for line_number, raw_line in enumerate(
                        source.read_text(encoding="utf-8").splitlines(), start=1
                    )
                ]
            except UnicodeDecodeError:
                status["status"] = "non_utf8"
                document_statuses.append(status)
                continue
            except OSError:
                status["status"] = "unreadable"
                document_statuses.append(status)
                continue

        authority = authority_class(stored_path)
        in_code_fence = False
        added_count = 0
        for page_number, line_number, raw_line in located_lines:
            if raw_line.strip().startswith("```"):
                in_code_fence = not in_code_fence
                continue
            if in_code_fence or not NORMATIVE_PATTERN.search(raw_line):
                continue
            statement = normalize_statement(raw_line)
            if len(statement) < 16 or len(statement.encode("utf-8")) > 2_000:
                continue
            disposition, flags = crosswalk(statement, authority)
            domains = statement_domains(statement)
            record = {
                "schema_version": SCHEMA_VERSION,
                "requirement_id": candidate_id(stored_path, line_number, statement),
                "source_path": stored_path,
                "source_sha256": entry["sha256"],
                "workspace_id": entry.get("workspace_id"),
                "line_number": line_number,
                "page_number": page_number or None,
                "source_format": source_format,
                "statement": statement,
                "authority_class": authority,
                "domains": domains,
                "crosswalk_disposition": disposition,
                "crosswalk_flags": flags,
                "human_review_status": "not_reviewed",
                "runtime_eligible": False,
            }
            candidates.append(record)
            added_count += 1
            authority_counts[authority] += 1
            disposition_counts[disposition] += 1
            domain_counts.update(domains)
            flag_counts.update(flags)
            if isinstance(entry.get("workspace_id"), str):
                workspace_counts[str(entry["workspace_id"])] += 1
        status["status"] = "scanned"
        status["candidate_count"] = added_count
        if page_count is not None:
            status["page_count"] = page_count
            status["extracted_text_sha256"] = text_sha256
        document_statuses.append(status)

    candidates.sort(key=lambda item: (item["source_path"], item["line_number"], item["requirement_id"]))
    candidate_bytes = b"".join(canonical_json(candidate) for candidate in candidates)
    candidates_hash = hashlib.sha256(candidate_bytes).hexdigest()
    status_counts = Counter(item["status"] for item in document_statuses)
    summary_body = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_bundle": archive_root.name,
        "catalog_sha256": catalog_summary.get("catalog_sha256"),
        "requirements_sha256": candidates_hash,
        "canonical_document_count": len(canonical_documents),
        "document_status_counts": dict(sorted(status_counts.items())),
        "requirement_candidate_count": len(candidates),
        "authority_counts": dict(sorted(authority_counts.items())),
        "domain_counts": dict(sorted(domain_counts.items())),
        "crosswalk_disposition_counts": dict(sorted(disposition_counts.items())),
        "crosswalk_flag_counts": dict(sorted(flag_counts.items())),
        "workspace_candidate_counts": dict(sorted(workspace_counts.items())),
        "human_reviewed_count": 0,
        "runtime_eligible_count": 0,
        "automatic_adoption": False,
        "execution_allowed": False,
        "document_extraction_status": document_statuses,
    }
    checkpoint_hash = hashlib.sha256(canonical_json(summary_body)).hexdigest()
    summary = {**summary_body, "checkpoint_sha256": checkpoint_hash}
    summary_bytes = json.dumps(summary, indent=2, sort_keys=True).encode("ascii") + b"\n"
    return candidate_bytes, summary_bytes, summary


def write_or_check(reports_dir: Path, candidates: bytes, summary: bytes, *, check: bool) -> None:
    outputs = {
        "requirements_candidates_v1.jsonl": candidates,
        "requirements_crosswalk_summary_v1.json": summary,
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
            raise RequirementsError("requirements reports are stale: " + ", ".join(stale))
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
        candidates, summary_bytes, summary = extract(
            args.archive_root.resolve(), args.reports_dir.resolve()
        )
        write_or_check(args.reports_dir.resolve(), candidates, summary_bytes, check=args.check)
    except RequirementsError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "requirement_candidate_count": summary["requirement_candidate_count"],
                "canonical_document_count": summary["canonical_document_count"],
                "checkpoint_sha256": summary["checkpoint_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
