#!/usr/bin/env python3
"""Build a non-binding evidence packet for RightRail safety review."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "localbce-rightrail-safety-review-packet-v1"
OUTPUT_NAME = "operating_plan_safety_review_packet_v1.json"
EXPECTED_QUEUE_CHECKPOINT = "c4b933a7a095134a53eae0f49d58b3e0f7e2fae6e060629b2fa53f3e2351d66d"

RECOMMENDATIONS: dict[str, dict[str, Any]] = {
    "rrreq-67912f32e7f312fa84682009": {
        "proposed_decision": "adopt",
        "compatibility_assessment": "already_reinforced",
        "recommendation_rationale": (
            "The governed V2 design already separates administrative, emergency, "
            "and treasury authority and subjects configuration changes to a timelock."
        ),
        "remaining_gaps": [
            "A named architecture owner and security owner must confirm that every "
            "transaction hold or release path is covered by an explicit role."
        ],
        "evidence": [
            {
                "path": "STARK_RUNTIME.md",
                "marker": "- V2 separates the timelocked administrator, emergency pauser, and treasury.",
                "relation": "separates operational authorities",
            },
            {
                "path": "STARK_RUNTIME.md",
                "marker": (
                    "- A 72-hour OpenZeppelin `TimelockController` governs attestor, policy,"
                ),
                "relation": "places governed changes behind an explicit authorization delay",
            },
        ],
    },
    "rrreq-a12d621a2ca01539ab58ac39": {
        "proposed_decision": "adapt",
        "compatibility_assessment": "partial_control_with_policy_gap",
        "recommendation_rationale": (
            "Settlement configuration is governed, but localBCE does not yet define the "
            "legal or program authority for true-ups and withholding."
        ),
        "remaining_gaps": [
            "Define and review the authority record required for each true-up, withholding, "
            "or settlement action before adding any executable behavior.",
            "Keep payment orchestration outside active adjudication until proof, policy, and "
            "external approval gates are complete.",
        ],
        "evidence": [
            {
                "path": "ARCHITECTURE_ALIGNMENT.md",
                "marker": "- batch ingestion and payment orchestration after proof and policy controls",
                "relation": "keeps payment orchestration behind policy controls",
            },
            {
                "path": "ops/RISK_REGISTER.md",
                "marker": "- Real production claims/payments: blocked until production STARK proving,",
                "relation": "blocks real claims and payments pending external gates",
            },
        ],
    },
    "rrreq-1b3cd95e3a11c2424f08b587": {
        "proposed_decision": "adapt",
        "compatibility_assessment": "privacy_goal_present_policy_gap",
        "recommendation_rationale": (
            "The repository states a privacy-preserving goal and protects production secrets, "
            "but it does not yet codify an approved-data boundary for analytics, monitoring, "
            "external AI tools, and shared libraries."
        ),
        "remaining_gaps": [
            "Create a separately reviewed data-classification and external-tool policy that "
            "defines approved non-sensitive material.",
            "Require privacy-owner review before any RightRail language is ported into an "
            "active operational control.",
        ],
        "evidence": [
            {
                "path": "README.md",
                "marker": (
                    "Blind Ledger is a local prototype for privacy-preserving healthcare claims adjudication using:"
                ),
                "relation": "states the current privacy objective",
            },
            {
                "path": "ops/KEY_CUSTODY_AND_ROTATION.md",
                "marker": "1. Production secrets must never be stored in the repo.",
                "relation": "provides a narrower sensitive-secret boundary",
            },
        ],
    },
    "rrreq-943958497348dcb629992a81": {
        "proposed_decision": "adopt",
        "compatibility_assessment": "already_reinforced",
        "recommendation_rationale": (
            "Active documentation already distinguishes production-shaped design and examples "
            "from audited or production-approved results."
        ),
        "remaining_gaps": [
            "A named architecture owner and security owner must approve the wording before it "
            "is treated as an adopted project requirement."
        ],
        "evidence": [
            {
                "path": "STARK_RUNTIME.md",
                "marker": (
                    "Until those gates are approved, this remains a production-shaped prototype and"
                ),
                "relation": "distinguishes the prototype from production approval",
            },
            {
                "path": "ops/DEPLOYMENT_RUNBOOK.md",
                "marker": "Status: local and pilot-prep runbook. This is not production approval.",
                "relation": "labels operating instructions as non-production evidence",
            },
        ],
    },
}


class SafetyReviewPacketError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafetyReviewPacketError(f"could not read {path}: {exc}") from exc


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="ascii") as handle:
            for line_number, line in enumerate(handle, start=1):
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise SafetyReviewPacketError(f"invalid object at {path}:{line_number}")
                records.append(record)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafetyReviewPacketError(f"could not read {path}: {exc}") from exc
    return records


def resolve_evidence(repo_root: Path, spec: dict[str, str]) -> dict[str, Any]:
    relative_path = Path(spec["path"])
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise SafetyReviewPacketError(f"unsafe evidence path: {relative_path}")
    path = repo_root / relative_path
    try:
        content = path.read_bytes()
        text = content.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SafetyReviewPacketError(f"could not read evidence {relative_path}: {exc}") from exc
    matches = [
        line_number
        for line_number, line in enumerate(text.splitlines(), start=1)
        if line == spec["marker"]
    ]
    if len(matches) != 1:
        raise SafetyReviewPacketError(
            f"expected one evidence marker in {relative_path}, found {len(matches)}"
        )
    return {
        "path": relative_path.as_posix(),
        "line_number": matches[0],
        "excerpt": spec["marker"],
        "file_sha256": hashlib.sha256(content).hexdigest(),
        "relation": spec["relation"],
    }


def validate_queue_boundary(record: dict[str, Any]) -> None:
    identifier = record.get("requirement_id", "<missing>")
    required_false = ("automatic_adoption", "runtime_eligible", "proof_binding", "execution_allowed")
    for field in required_false:
        if record.get(field) is not False:
            raise SafetyReviewPacketError(f"unsafe {field} for {identifier}")
    required_null = ("human_decision", "decision_rationale", "reviewer_identity", "reviewed_at")
    for field in required_null:
        if record.get(field) is not None:
            raise SafetyReviewPacketError(f"unexpected human review data in {identifier}: {field}")
    if record.get("decision_status") != "pending_human_review":
        raise SafetyReviewPacketError(f"unexpected decision status for {identifier}")


def build_packet(
    queue_records: list[dict[str, Any]],
    queue_summary: dict[str, Any],
    repo_root: Path,
    *,
    expected_queue_checkpoint: str = EXPECTED_QUEUE_CHECKPOINT,
) -> tuple[bytes, dict[str, Any]]:
    if queue_summary.get("checkpoint_sha256") != expected_queue_checkpoint:
        raise SafetyReviewPacketError("operating-plan review queue checkpoint changed")
    queue_bytes = b"".join(canonical_json(record) for record in queue_records)
    if hashlib.sha256(queue_bytes).hexdigest() != queue_summary.get("queue_sha256"):
        raise SafetyReviewPacketError("operating-plan review queue hash mismatch")

    priority_records = [record for record in queue_records if record.get("review_priority") == 1]
    priority_by_id = {record.get("requirement_id"): record for record in priority_records}
    if set(priority_by_id) != set(RECOMMENDATIONS):
        raise SafetyReviewPacketError("priority safety candidate set changed")
    if len(priority_records) != len(priority_by_id):
        raise SafetyReviewPacketError("duplicate priority safety candidate")

    candidates = []
    for identifier in sorted(priority_by_id, key=lambda item: priority_by_id[item]["page_number"]):
        source = priority_by_id[identifier]
        validate_queue_boundary(source)
        recommendation = RECOMMENDATIONS[identifier]
        if recommendation["proposed_decision"] not in source.get("allowed_decisions", []):
            raise SafetyReviewPacketError(f"unsupported recommendation for {identifier}")
        candidates.append(
            {
                "queue_id": source["queue_id"],
                "requirement_id": identifier,
                "source_path": source["source_path"],
                "source_sha256": source["source_sha256"],
                "page_number": source["page_number"],
                "source_statement_number": source["source_statement_number"],
                "statement": source["statement"],
                "crosswalk_flags": source["crosswalk_flags"],
                "required_reviewer_roles": source["required_reviewer_roles"],
                "proposed_decision": recommendation["proposed_decision"],
                "compatibility_assessment": recommendation["compatibility_assessment"],
                "recommendation_rationale": recommendation["recommendation_rationale"],
                "remaining_gaps": recommendation["remaining_gaps"],
                "evidence": [
                    resolve_evidence(repo_root, spec) for spec in recommendation["evidence"]
                ],
                "recommendation_only": True,
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

    counts = Counter(item["proposed_decision"] for item in candidates)
    body = {
        "schema_version": SCHEMA_VERSION,
        "source_queue_checkpoint_sha256": queue_summary["checkpoint_sha256"],
        "source_queue_sha256": queue_summary["queue_sha256"],
        "source_queue_item_count": queue_summary["queue_item_count"],
        "priority_candidate_count": len(candidates),
        "prepared_recommendation_count": len(candidates),
        "proposed_decision_counts": dict(sorted(counts.items())),
        "review_status": "pending_named_human_review",
        "human_reviewed_count": 0,
        "final_decision_count": 0,
        "automatic_adoption": False,
        "runtime_eligible_count": 0,
        "proof_binding_count": 0,
        "execution_allowed": False,
        "candidates": candidates,
    }
    packet = {**body, "checkpoint_sha256": hashlib.sha256(canonical_json(body)).hexdigest()}
    return json.dumps(packet, indent=2, sort_keys=True).encode("ascii") + b"\n", packet


def write_or_check(path: Path, content: bytes, *, check: bool) -> None:
    if check:
        try:
            current = path.read_bytes()
        except OSError as exc:
            raise SafetyReviewPacketError(f"could not read {path}: {exc}") from exc
        if current != content:
            raise SafetyReviewPacketError(f"safety review packet is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


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
        content, packet = build_packet(
            load_jsonl(reports_dir / "operating_plan_review_queue_v1.jsonl"),
            load_json(reports_dir / "operating_plan_review_queue_summary_v1.json"),
            Path(__file__).resolve().parents[1],
        )
        write_or_check(reports_dir / OUTPUT_NAME, content, check=args.check)
    except SafetyReviewPacketError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "priority_candidate_count": packet["priority_candidate_count"],
                "human_reviewed_count": packet["human_reviewed_count"],
                "checkpoint_sha256": packet["checkpoint_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
