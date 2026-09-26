#!/usr/bin/env python3
"""Build a non-runtime human review queue for the RightRail operating plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "localbce-rightrail-operating-plan-review-item-v1"
SUMMARY_SCHEMA_VERSION = "localbce-rightrail-operating-plan-review-summary-v1"
SOURCE_PATH = "original/reference/RightRail_Architecture_and_Operating_Plan.pdf"
EXPECTED_CANDIDATE_COUNT = 110
ALLOWED_DECISIONS = ("adopt", "adapt", "reject", "reference_only")

DOMAIN_TARGETS = {
    "general": "ARCHITECTURE_ALIGNMENT.md",
    "rules_and_policy": "RULES_ENGINE.md",
    "source_and_evidence": "gov-rules-kg-prototype/README.md",
    "privacy_and_phi": "ops/RISK_REGISTER.md",
    "proof_and_crypto": "STARK_RUNTIME.md",
    "state_and_database": "ARCHITECTURE_ALIGNMENT.md",
    "settlement_and_payment": "STARK_RUNTIME.md",
    "governance_and_operations": "ops/PRODUCTION_CONFIG_CHECKLIST.md",
    "build_and_release": "PROJECT_STATE.md",
}


class ReviewQueueError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewQueueError(f"could not read {path}: {exc}") from exc


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    try:
        with path.open("r", encoding="ascii") as handle:
            for line_number, line in enumerate(handle, start=1):
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ReviewQueueError(f"invalid JSON object at {path}:{line_number}")
                records.append(record)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewQueueError(f"could not read {path}: {exc}") from exc
    return records


def review_priority(record: dict[str, Any]) -> tuple[int, str]:
    disposition = record.get("crosswalk_disposition")
    flags = record.get("crosswalk_flags") or []
    if disposition == "adopt_safety_boundary":
        return 1, "existing safety boundary"
    if disposition in {"conflict_review", "adapt_candidate"} or flags:
        return 2, "conflict or adaptation review"
    return 3, "architecture review"


def target_paths(domains: Iterable[str]) -> list[str]:
    return sorted({DOMAIN_TARGETS.get(domain, DOMAIN_TARGETS["general"]) for domain in domains})


def reviewer_roles(domains: Iterable[str], flags: Iterable[str]) -> list[str]:
    roles = {"architecture_owner"}
    domain_set = set(domains)
    if "rules_and_policy" in domain_set:
        roles.add("rules_owner")
    if "privacy_and_phi" in domain_set:
        roles.add("privacy_owner")
    if "settlement_and_payment" in domain_set:
        roles.add("settlement_owner")
    if list(flags):
        roles.add("security_owner")
    return sorted(roles)


def queue_id(requirement_id: str) -> str:
    return "rrreview-" + hashlib.sha256(requirement_id.encode("ascii")).hexdigest()[:24]


def build_queue(
    requirement_records: list[dict[str, Any]],
    requirement_summary: dict[str, Any],
    repo_root: Path,
    *,
    expected_count: int | None = EXPECTED_CANDIDATE_COUNT,
) -> tuple[bytes, bytes, dict[str, Any]]:
    source_records = [record for record in requirement_records if record.get("source_path") == SOURCE_PATH]
    if expected_count is not None and len(source_records) != expected_count:
        raise ReviewQueueError(
            f"expected {expected_count} operating-plan candidates, got {len(source_records)}"
        )
    requirement_ids = [record.get("requirement_id") for record in source_records]
    if any(not isinstance(identifier, str) for identifier in requirement_ids):
        raise ReviewQueueError("operating-plan candidate is missing requirement_id")
    if len(set(requirement_ids)) != len(requirement_ids):
        raise ReviewQueueError("operating-plan requirement IDs are not unique")

    missing_targets = sorted(
        target for target in set(DOMAIN_TARGETS.values()) if not (repo_root / target).exists()
    )
    if missing_targets:
        raise ReviewQueueError("cross-reference targets are missing: " + ", ".join(missing_targets))

    queue = []
    for record in source_records:
        if record.get("runtime_eligible") is not False:
            raise ReviewQueueError(f"source requirement is not safely blocked: {record['requirement_id']}")
        priority, rationale = review_priority(record)
        domains = list(record.get("domains") or ["general"])
        flags = list(record.get("crosswalk_flags") or [])
        queue.append(
            {
                "schema_version": SCHEMA_VERSION,
                "queue_id": queue_id(record["requirement_id"]),
                "requirement_id": record["requirement_id"],
                "source_path": SOURCE_PATH,
                "source_sha256": record.get("source_sha256"),
                "page_number": record.get("page_number"),
                "source_statement_number": record.get("line_number"),
                "statement": record.get("statement"),
                "domains": domains,
                "crosswalk_disposition": record.get("crosswalk_disposition"),
                "crosswalk_flags": flags,
                "review_priority": priority,
                "review_priority_rationale": rationale,
                "suggested_target_paths": target_paths(domains),
                "cross_reference_status": "suggested_not_verified",
                "required_reviewer_roles": reviewer_roles(domains, flags),
                "allowed_decisions": list(ALLOWED_DECISIONS),
                "decision_status": "pending_human_review",
                "human_decision": None,
                "decision_rationale": None,
                "reviewer_identity": None,
                "reviewed_at": None,
                "automatic_adoption": False,
                "runtime_eligible": False,
                "proof_binding": False,
                "execution_allowed": False,
            }
        )

    queue.sort(key=lambda item: (item["review_priority"], item["page_number"], item["queue_id"]))
    queue_bytes = b"".join(canonical_json(item) for item in queue)
    queue_hash = hashlib.sha256(queue_bytes).hexdigest()
    priority_counts = Counter(str(item["review_priority"]) for item in queue)
    disposition_counts = Counter(str(item["crosswalk_disposition"]) for item in queue)
    target_counts = Counter(path for item in queue for path in item["suggested_target_paths"])
    summary_body = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_requirements_checkpoint_sha256": requirement_summary.get("checkpoint_sha256"),
        "source_requirements_sha256": requirement_summary.get("requirements_sha256"),
        "source_path": SOURCE_PATH,
        "queue_sha256": queue_hash,
        "queue_item_count": len(queue),
        "priority_counts": dict(sorted(priority_counts.items())),
        "crosswalk_disposition_counts": dict(sorted(disposition_counts.items())),
        "suggested_target_counts": dict(sorted(target_counts.items())),
        "pending_human_review_count": len(queue),
        "human_reviewed_count": 0,
        "automatic_adoption": False,
        "runtime_eligible_count": 0,
        "proof_binding_count": 0,
        "execution_allowed": False,
    }
    checkpoint = hashlib.sha256(canonical_json(summary_body)).hexdigest()
    summary = {**summary_body, "checkpoint_sha256": checkpoint}
    summary_bytes = json.dumps(summary, indent=2, sort_keys=True).encode("ascii") + b"\n"
    return queue_bytes, summary_bytes, summary


def write_or_check(reports_dir: Path, queue: bytes, summary: bytes, *, check: bool) -> None:
    outputs = {
        "operating_plan_review_queue_v1.jsonl": queue,
        "operating_plan_review_queue_summary_v1.json": summary,
    }
    if check:
        stale = []
        for name, expected in outputs.items():
            path = reports_dir / name
            try:
                current = path.read_bytes()
            except OSError:
                stale.append(f"missing:{path}")
                continue
            if current != expected:
                stale.append(f"changed:{path}")
        if stale:
            raise ReviewQueueError("operating-plan review queue is stale: " + ", ".join(stale))
        return
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (reports_dir / name).write_bytes(content)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "right-rail-integration" / "reports",
    )
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    reports_dir = args.reports_dir.resolve()
    try:
        queue, summary_bytes, summary = build_queue(
            load_jsonl(reports_dir / "requirements_candidates_v1.jsonl"),
            load_json(reports_dir / "requirements_crosswalk_summary_v1.json"),
            Path(__file__).resolve().parents[1],
        )
        write_or_check(reports_dir, queue, summary_bytes, check=args.check)
    except ReviewQueueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "queue_item_count": summary["queue_item_count"],
                "pending_human_review_count": summary["pending_human_review_count"],
                "checkpoint_sha256": summary["checkpoint_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
