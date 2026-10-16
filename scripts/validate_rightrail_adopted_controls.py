#!/usr/bin/env python3
"""Validate inactive RightRail-derived operational controls."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATA_POLICY_PATH = ROOT / "ops" / "approved_data_boundary_v1.json"
AUTHORITY_POLICY_PATH = ROOT / "ops" / "settlement_authority_policy_v1.json"


class ControlValidationError(ValueError):
    """Raised when an adopted control violates its fail-closed boundary."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ControlValidationError(f"could not read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ControlValidationError(f"{path} must contain a JSON object")
    return value


def canonical_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def require_inactive_candidate(value: dict[str, Any], label: str) -> None:
    if value.get("policy_status") != "candidate_not_approved":
        raise ControlValidationError(f"{label} must remain an unapproved candidate")
    for field in ("runtime_enforced", "human_approved", "legal_verified"):
        if value.get(field) is not False:
            raise ControlValidationError(f"{label} {field} must be false")
    if value.get("default_decision") != "deny":
        raise ControlValidationError(f"{label} must deny by default")


def validate_data_policy(value: dict[str, Any]) -> str:
    if value.get("schema_version") != "localbce-approved-data-boundary-v1":
        raise ControlValidationError("unexpected approved-data schema")
    require_inactive_candidate(value, "approved-data policy")

    classes = value.get("data_classes")
    if not isinstance(classes, list) or not classes:
        raise ControlValidationError("approved-data policy requires data classes")
    class_by_id = {
        item.get("id"): item
        for item in classes
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if len(class_by_id) != len(classes):
        raise ControlValidationError("data classes must have unique string IDs")
    required_classes = {
        "public",
        "approved_non_sensitive",
        "confidential",
        "phi",
        "credential_or_secret",
        "private_proof_material",
    }
    if set(class_by_id) != required_classes:
        raise ControlValidationError("approved-data policy has unexpected data classes")

    destinations = value.get("destinations")
    if not isinstance(destinations, list) or not destinations:
        raise ControlValidationError("approved-data policy requires destinations")
    destination_ids: set[str] = set()
    for destination in destinations:
        if not isinstance(destination, dict) or not isinstance(destination.get("id"), str):
            raise ControlValidationError("destination records require string IDs")
        destination_id = destination["id"]
        if destination_id in destination_ids:
            raise ControlValidationError("destination IDs must be unique")
        destination_ids.add(destination_id)
        if destination.get("approval_record_required") is not True:
            raise ControlValidationError(f"{destination_id} must require an approval record")
        allowed = destination.get("allowed_classes")
        if not isinstance(allowed, list) or not allowed:
            raise ControlValidationError(f"{destination_id} requires allowed classes")
        for class_id in allowed:
            data_class = class_by_id.get(class_id)
            if data_class is None:
                raise ControlValidationError(f"{destination_id} references an unknown class")
            if data_class.get("sensitive") is not False:
                raise ControlValidationError(
                    f"{destination_id} cannot allow sensitive class {class_id}"
                )

    required_destinations = {
        "support",
        "product_analytics",
        "ordinary_monitoring",
        "external_ai",
        "shared_multistate_library",
    }
    if destination_ids != required_destinations:
        raise ControlValidationError("approved-data policy has unexpected destinations")
    if set(value.get("required_review_roles", [])) != {
        "privacy_owner",
        "security_owner",
    }:
        raise ControlValidationError("approved-data policy requires privacy and security review")
    if value.get("right_rail_source_requirement_id") != "rrreq-1b3cd95e3a11c2424f08b587":
        raise ControlValidationError("approved-data policy lost RightRail lineage")
    return canonical_sha256(value)


def validate_authority_policy(value: dict[str, Any]) -> str:
    if value.get("schema_version") != "localbce-settlement-authority-policy-v1":
        raise ControlValidationError("unexpected settlement-authority schema")
    require_inactive_candidate(value, "settlement-authority policy")
    if value.get("no_implicit_authority") is not True:
        raise ControlValidationError("settlement authority must be explicit")
    if value.get("separation_of_duties_required") is not True:
        raise ControlValidationError("settlement authority requires separation of duties")

    actions = value.get("action_types")
    expected_actions = {
        "true_up",
        "withholding",
        "settlement",
        "treasury_transfer",
        "configuration_change",
    }
    if not isinstance(actions, list) or set(actions) != expected_actions:
        raise ControlValidationError("settlement-authority action types are incomplete")

    required_fields = set(value.get("required_authority_record_fields", []))
    expected_fields = {
        "authority_id",
        "action_type",
        "program",
        "jurisdiction",
        "scope",
        "decision",
        "issuer",
        "source_reference",
        "effective_from",
        "effective_through",
        "approver_roles",
        "record_sha256",
    }
    if required_fields != expected_fields:
        raise ControlValidationError("authority-record fields are incomplete")

    roles_by_action = value.get("required_roles_by_action")
    if not isinstance(roles_by_action, dict) or set(roles_by_action) != expected_actions:
        raise ControlValidationError("every action requires an explicit role set")
    for action, roles in roles_by_action.items():
        if not isinstance(roles, list) or len(set(roles)) < 2:
            raise ControlValidationError(f"{action} requires two distinct authority roles")

    retry = value.get("retry_semantics")
    if retry != {
        "exact_retry": "idempotent_duplicate",
        "changed_retry": "conflict_fail_closed",
    }:
        raise ControlValidationError("authority retries must be idempotent and fail closed")
    if value.get("right_rail_source_requirement_id") != "rrreq-a12d621a2ca01539ab58ac39":
        raise ControlValidationError("settlement-authority policy lost RightRail lineage")
    return canonical_sha256(value)


def main() -> int:
    data_hash = validate_data_policy(load_json(DATA_POLICY_PATH))
    authority_hash = validate_authority_policy(load_json(AUTHORITY_POLICY_PATH))
    print(
        json.dumps(
            {
                "status": "ok",
                "runtime_behavior_changed": False,
                "human_approval_implied": False,
                "approved_data_boundary_sha256": data_hash,
                "settlement_authority_policy_sha256": authority_hash,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
