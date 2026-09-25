"""Same-owner Mirror and bounded Continuity adapter for RightRail financial state.

The financial owner remains the only writer and the only balance calculator.  This
module owns no database, opens no SQLite connection, and persists no projection.
It only delegates to one :class:`FinancialOwner`, bounds read pages, removes raw
event/action payloads from the read model, and enforces the shadow/test-only
continuity boundary around the owner's public API.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
from collections.abc import Mapping
from typing import Any, Final

from app.right_rail_financial_owner import (
    FinancialContinuityError,
    FinancialDispatchError,
    FinancialOwner,
    ProgramFundingReceipt,
    SyntheticTrustedAuthority,
)


MIRROR_SCHEMA: Final[str] = "RR/FINANCIAL/MIRROR/v1"
_DECISION_PACKAGE_CONTRACT: Final[str] = "RR/FINANCIAL/DECISION-PACKAGE/v2"
CONTINUITY_SCHEMA: Final[str] = "RR/FINANCIAL/CONTINUITY/v8"
MAX_PACKAGE_BYTES: Final[int] = 8 * 1024 * 1024
MAX_CORRECTION_FOLLOWUP_PAGE_BYTES: Final[int] = 32 * 1024 * 1024
MAX_LIST_PAGE: Final[int] = 100
MAX_DETAIL_PAGE: Final[int] = 200
MAX_OFFSET: Final[int] = 10_000
STAFF_READ_ENVELOPE_CONTRACT: Final[str] = "RR/FINANCIAL/STAFF-READ-ENVELOPE/v1"
OWNER_VERIFIED_STAFF_SNAPSHOT_CONTRACT: Final[str] = "RR/FINANCIAL/OWNER-VERIFIED-STAFF-SNAPSHOT/v1"
STAFF_SNAPSHOT_ID_CONTRACT: Final[str] = "RR/FINANCIAL/STAFF-SNAPSHOT-ID/v1"

_DROP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "payload",
        "payload_json",
        "raw",
        "raw_payload",
        "raw_bytes",
        "content",
        "content_bytes",
        "source_bytes",
        "private_proof_material",
        "secret",
        "credential",
    }
)
_POPULATION_LINKABLE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "population_id",
        "manifest_id",
        "manifest_digest",
        "member_id",
        "member_ids",
        "member_digest",
        "source_digest",
        "source_owner_id",
        "approval_ref",
    }
)
_DECISION_DROP_KEYS: Final[frozenset[str]] = _DROP_KEYS | frozenset(
    {"content_digest", "input_snapshot", "input_snapshot_json", "input_snapshot_digest"}
) | _POPULATION_LINKABLE_KEYS
_JSON_REFERENCE_KEYS: Final[dict[str, str]] = {
    "evidence_ids_json": "evidence_ids",
    "evidence_bindings_json": "evidence_bindings",
    "supporting_evidence_json": "supporting_evidence_ids",
    "completion_conditions_json": "completion_conditions",
}
_ACTION_FIELDS: Final[tuple[str, ...]] = (
    "action",
    "action_id",
    "obligation_id",
    "determination_id",
    "kind",
    "claim_id",
    "amount_cents",
    "currency",
    "revision",
    "input_evaluation_id",
    "input_evaluation_result_digest",
    "dispatch",
)
_STAFF_OBLIGATION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "obligation_id", "item_id", "population_id", "period_id", "currency", "revision",
        "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents",
        "received_cash_cents", "shortfall_cents", "overage_cents", "cash_satisfied",
        "amount_satisfied", "timely", "reporting_complete", "verification_status",
        "case_status", "delivery_status", "current_evaluation_id", "due_at_ms",
    }
)
_STAFF_SUMMARY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema", "state_id", "deployment_id", "program_id", "period_id", "currency",
        "sequence", "population_count", "obligation_count", "owed_cents",
        "received_cash_cents", "lawful_adjustment_cents", "shortfall_cents", "open_count",
        "cash_satisfied_count", "amount_satisfied_count", "dispatch_enabled", "egress_enabled",
        "production_usable", "activation", "proof_suite_id",
    }
)
_STAFF_DETAIL_COLLECTIONS: Final[dict[str, tuple[str, frozenset[str]]]] = {
    "evidence": ("evidence_references", frozenset({
        "evidence_id", "kind", "common_origin_id", "source_id", "source_version", "local_ref",
        "applicable_at_ms", "event_at_ms", "received_at_ms", "amount_cents", "reversal_of",
        "supersedes", "record_digest",
    })),
    "payments": ("payment_references", frozenset({
        "payment_id", "evidence_id", "common_origin_id", "amount_cents", "event_at_ms",
        "active", "reversed_by_evidence_id",
    })),
    "cases": ("case_references", frozenset({
        "case_id", "reason", "contractual_accountability", "next_action_owner", "due_at_ms",
        "completion_conditions_json", "status", "updated_at_ms",
    })),
    "determinations": ("determination_references", frozenset({
        "determination_id", "claim_id", "actor_id", "actor_role", "authority_id",
        "authority_epoch", "authority_digest", "decision", "amount_cents",
        "supporting_evidence_json", "expected_revision", "resulting_revision", "decided_at_ms",
        "determination_digest", "input_evaluation_id", "input_evaluation_result_digest",
    })),
    "actions": ("action_references", frozenset({
        "action_id", "determination_id", "kind", "status", "revision", "payload_digest",
        "idempotency_key", "created_at_ms",
    })),
    "conflicts": ("conflict_references", frozenset({
        "conflict_id", "common_origin_id", "existing_payment_id", "candidate_evidence_id",
        "existing_amount_cents", "candidate_amount_cents", "reason", "visible_at_ms",
    })),
    "evaluations": ("evaluation_references", frozenset({
        "evaluation_id", "revision", "rule_version", "evidence_ids_json", "authority_id",
        "authority_epoch", "authority_digest", "evaluated_at_ms", "owed_cents",
        "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents",
        "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely",
        "reporting_complete", "verification_status", "case_status", "delivery_status",
        "result_digest", "contract_version", "scope_json", "control_pack_id",
        "control_pack_version", "control_pack_digest", "evidence_bindings_json",
        "input_snapshot_json", "input_snapshot_digest", "receipt_digest",
    })),
}

_RESTORE_LOCK = threading.Lock()
_ACTIVE_DESTINATIONS: set[str] = set()


class FinancialMirrorError(RuntimeError):
    """Base class for bounded Mirror-side input and boundary failures."""


class FinancialMirrorInputError(FinancialMirrorError):
    pass


class FinancialMirrorContinuityError(FinancialMirrorError):
    pass


class FinancialMirrorDispatchError(FinancialMirrorError):
    pass


def _fail(error_type: type[FinancialMirrorError], code: str) -> None:
    error = error_type(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _page_bounds(limit: object, offset: object, *, maximum: int, code: str) -> tuple[int, int]:
    if type(limit) is not int or not 1 <= limit <= maximum:
        _fail(FinancialMirrorInputError, code)
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        _fail(FinancialMirrorInputError, code)
    return limit, offset


def _safe_json_reference(value: str, output_key: str) -> Any:
    import json

    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, UnicodeError):
        return None
    if output_key.endswith("_ids"):
        if type(parsed) is dict and set(parsed) == {"values"} and type(parsed["values"]) is list:
            return [item for item in parsed["values"] if type(item) is str]
        if type(parsed) is dict and set(parsed) == {"bindings"} and type(parsed["bindings"]) is list:
            if all(type(item) is dict and set(item) == {"evidence_id", "record_digest"} for item in parsed["bindings"]):
                return [item["evidence_id"] for item in parsed["bindings"] if type(item["evidence_id"]) is str]
        return None
    if output_key == "evidence_bindings":
        if type(parsed) is dict and set(parsed) == {"bindings"} and type(parsed["bindings"]) is list:
            return [
                {"evidence_id": item["evidence_id"], "record_digest": item["record_digest"]}
                for item in parsed["bindings"]
                if type(item) is dict and set(item) == {"evidence_id", "record_digest"}
                and type(item["evidence_id"]) is str and type(item["record_digest"]) is str
            ]
        return None
    if output_key == "completion_conditions":
        if type(parsed) is dict and set(parsed) == {"amount_satisfied", "reporting_complete", "delivery_acknowledged_or_not_required"}:
            return {key: bool(parsed[key]) for key in sorted(parsed)}
        return None
    return None


def _safe_value(value: Any) -> Any:
    if type(value) is bytes:
        return value.hex().upper()
    if type(value) is dict:
        return {
            str(key): _safe_value(item)
            for key, item in value.items()
            if str(key) not in _POPULATION_LINKABLE_KEYS
        }
    if type(value) is list:
        return [_safe_value(item) for item in value]
    if type(value) is tuple:
        return [_safe_value(item) for item in value]
    if value is None or type(value) in {str, int, float, bool}:
        return value
    _fail(FinancialMirrorContinuityError, "unsafe_owner_value")


def _safe_decision_value(value: Any) -> Any:
    """Recursively remove source and payload fields from decision packages."""

    if type(value) is dict:
        return {
            str(key): _safe_decision_value(item)
            for key, item in value.items()
            if str(key) not in _DECISION_DROP_KEYS
        }
    if type(value) is list:
        return [_safe_decision_value(item) for item in value]
    if type(value) is tuple:
        return [_safe_decision_value(item) for item in value]
    return _safe_value(value)


def _safe_record(record: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, raw_value in record.items():
        key = str(raw_key)
        if key in _DROP_KEYS or key in _POPULATION_LINKABLE_KEYS:
            continue
        if key in _JSON_REFERENCE_KEYS:
            reference_key = _JSON_REFERENCE_KEYS[key]
            reference = _safe_json_reference(raw_value, reference_key)
            if reference is not None:
                result[reference_key] = reference
            continue
        result[key] = _safe_value(raw_value)
    return result


def _staff_json_digest(value: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _fail(FinancialMirrorContinuityError, "staff_read_canonical")
    return hashlib.sha256(encoded).hexdigest().upper()


def _page(schema: str, resource: str, items: list[dict[str, Any]], *, limit: int, offset: int) -> dict[str, Any]:
    return {
        "schema": schema,
        "resource": resource,
        "offset": offset,
        "limit": limit,
        "count": len(items),
        "items": items,
        "next_offset": offset + len(items) if len(items) == limit else None,
    }


def _normalized_path(path: Path) -> str:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        _fail(FinancialMirrorContinuityError, "continuity_destination")
    return os.path.normcase(os.path.normpath(os.fspath(resolved)))


def _cleanup_new_destination(path: Path) -> None:
    """Remove only the exact destination allocated by a failed restore attempt."""

    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(os.fspath(path) + suffix)
        try:
            if candidate.is_symlink() or candidate.is_file():
                candidate.unlink()
        except OSError:
            # Preserve the original owner/checker failure.  The path was required
            # to be absent before the restore, so no pre-existing file is removed.
            continue


def _staff_source_facts(support_count: int) -> dict[str, Any]:
    """Source and freshness facts a staff view states as UNKNOWN (no source is connected)."""

    return {
        "source_assessment": {
            "status": "UNKNOWN",
            "reason": "The manifest digest is a synthetic caller assertion. No source bytes, State authority, external confirmation, or freshness watermark is connected.",
            "h_support_status": "MISSING" if support_count == 0 else "RECORDED_UNVERIFIED",
        },
        "freshness": {
            "status": "UNKNOWN",
            "reason": "No source-specific watermark or approved maximum-age rule is present.",
        },
    }


def _allowlisted_action_fields(payload: object) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    return {key: _safe_value(payload[key]) for key in _ACTION_FIELDS if key in payload}


class FinancialMirror:
    """A bounded read/command adapter over exactly one ``FinancialOwner``."""

    def __init__(self, owner: FinancialOwner) -> None:
        if not isinstance(owner, FinancialOwner):
            _fail(FinancialMirrorInputError, "owner_required")
        self.owner = owner

    def summary(self) -> dict[str, Any]:
        value = self.owner.summary()
        result = _safe_record(value)
        result["schema"] = MIRROR_SCHEMA
        result["owner_schema"] = value.get("schema")
        return result

    def list_obligations(self, *, status: str = "OPEN", limit: int = 100, offset: int = 0) -> dict[str, Any]:
        limit, offset = _page_bounds(limit, offset, maximum=MAX_LIST_PAGE, code="obligation_page")
        rows = self.owner.list_obligations(status=status, limit=limit, offset=offset)
        return _page(MIRROR_SCHEMA, "obligations", [_safe_record(row) for row in rows], limit=limit, offset=offset)

    def obligation_detail(self, item_id: str, *, limit: int = 100) -> dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= MAX_DETAIL_PAGE:
            _fail(FinancialMirrorInputError, "detail_limit")
        raw = self.owner.obligation_detail(item_id, limit=limit)
        result = _safe_record({key: value for key, value in raw.items() if key not in {"evidence", "payments", "cases", "determinations", "actions", "conflicts", "evaluations"}})
        collections = (
            ("evidence", "evidence_references"),
            ("payments", "payment_references"),
            ("cases", "case_references"),
            ("determinations", "determination_references"),
            ("actions", "action_references"),
            ("conflicts", "conflict_references"),
            ("evaluations", "evaluation_references"),
        )
        for source_key, reference_key in collections:
            references = [_safe_record(row) for row in raw.get(source_key, [])]
            result[reference_key] = references
            # These compatibility aliases still contain references only; they
            # never expose the owner's raw JSON/payload fields.
            result[source_key] = references
        result["schema"] = MIRROR_SCHEMA
        result["resource"] = "obligation"
        result["reference_limit"] = limit
        return result

    def current_evaluation_receipt(self, item_id: str) -> dict[str, Any]:
        raw = self.owner.current_evaluation_receipt(item_id)
        result = _safe_record(raw)
        result["schema"] = MIRROR_SCHEMA
        result["resource"] = "evaluation_receipt"
        return result

    def decision_package(
        self,
        item_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        expected_evaluation_id: str | None = None,
        expected_evaluation_result_digest: str | bytes | None = None,
    ) -> dict[str, Any]:
        limit, offset = _page_bounds(limit, offset, maximum=MAX_DETAIL_PAGE, code="decision_package_page")
        if (expected_evaluation_id is None) != (expected_evaluation_result_digest is None):
            _fail(FinancialMirrorInputError, "evaluation_reference_required")
        raw = self.owner.decision_package(
            item_id,
            limit=limit,
            offset=offset,
            expected_evaluation_id=expected_evaluation_id,
            expected_evaluation_result_digest=expected_evaluation_result_digest,
        )
        result = _safe_decision_value(raw)
        if type(result) is not dict or result.get("contract") != _DECISION_PACKAGE_CONTRACT:
            _fail(FinancialMirrorContinuityError, "decision_package_contract")
        result["schema"] = MIRROR_SCHEMA
        result["resource"] = "decision_package"
        return result

    def staff_read_snapshot(
        self,
        query: Mapping[str, Any],
        *,
        read_at: str,
        labels: Mapping[str, str] | None = None,
        gate_checks: list[dict[str, Any]] | None = None,
        continuity: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Allowlist one Owner snapshot and bind its public resources to verification."""

        if not isinstance(query, Mapping) or type(read_at) is not str or not read_at or len(read_at) > 64:
            _fail(FinancialMirrorInputError, "staff_read_input")
        raw = self.owner.read_verified_staff_snapshot(query)
        required_raw = {"contract", "query", "snapshot", "resources", "item_bindings", "verification", "read_cost"}
        if (
            type(raw) is not dict
            or set(raw) != required_raw
            or raw.get("contract") != OWNER_VERIFIED_STAFF_SNAPSHOT_CONTRACT
            or type(raw.get("query")) is not dict
            or raw.get("query") != dict(query)
        ):
            _fail(FinancialMirrorContinuityError, "staff_owner_snapshot_contract")

        snapshot = raw["snapshot"]
        snapshot_keys = {
            "schema", "schema_version", "scope", "mode", "owner_id", "continuity_epoch",
            "sequence", "history_head", "snapshot_id",
        }
        if type(snapshot) is not dict or set(snapshot) != snapshot_keys:
            _fail(FinancialMirrorContinuityError, "staff_snapshot_identity")
        scope = snapshot["scope"]
        scope_keys = {"state_id", "deployment_id", "program_id", "period_id", "currency"}
        if (
            type(scope) is not dict
            or set(scope) != scope_keys
            or any(type(value) is not str or not value for value in scope.values())
            or type(snapshot["schema"]) is not str
            or type(snapshot["schema_version"]) is not int
            or type(snapshot["mode"]) is not str
            or type(snapshot["owner_id"]) is not str
            or type(snapshot["continuity_epoch"]) is not int
            or type(snapshot["sequence"]) is not int
            or snapshot["sequence"] < 0
        ):
            _fail(FinancialMirrorContinuityError, "staff_snapshot_identity")
        snapshot_base = {key: snapshot[key] for key in snapshot_keys if key != "snapshot_id"}
        if snapshot["snapshot_id"] != _staff_json_digest({"contract": STAFF_SNAPSHOT_ID_CONTRACT, **snapshot_base}):
            _fail(FinancialMirrorContinuityError, "staff_snapshot_digest")

        verification = raw["verification"]
        if (
            type(verification) is not dict
            or verification.get("owner_id") != snapshot["owner_id"]
            or verification.get("schema") != snapshot["schema"]
            or verification.get("schema_version") != snapshot["schema_version"]
            or verification.get("scope") != scope
            or verification.get("mode") != snapshot["mode"]
            or verification.get("continuity_epoch") != snapshot["continuity_epoch"]
            or verification.get("sequence") != snapshot["sequence"]
            or verification.get("history_head") != snapshot["history_head"]
        ):
            _fail(FinancialMirrorContinuityError, "staff_verification_binding")
        counts = verification.get("counts")
        count_keys = {
            "events", "packs", "populations", "items", "obligations", "evidence", "payments",
            "claims", "determinations", "actions", "conflicts", "evaluations",
        }
        if type(counts) is not dict or set(counts) != count_keys or any(type(value) is not int or value < 0 for value in counts.values()):
            _fail(FinancialMirrorContinuityError, "staff_verification_counts")
        verification_digest = _staff_json_digest(verification)
        public_verification = {
            "status": "VERIFIED",
            "schema": verification["schema"],
            "schema_version": verification["schema_version"],
            "scope": _safe_value(scope),
            "mode": verification["mode"],
            "owner_id": verification["owner_id"],
            "continuity_epoch": verification["continuity_epoch"],
            "sequence": verification["sequence"],
            "history_head": verification["history_head"],
            "counts": {key: counts[key] for key in sorted(counts)},
            "result_digest": verification_digest,
        }

        cost = raw["read_cost"]
        cost_keys = {
            "owner_connection_acquisitions", "independent_verifier_connection_acquisitions",
            "owner_read_statement_count", "independent_verifier_statement_count",
            "independent_verifier_microseconds", "snapshot_transaction_microseconds",
        }
        if (
            type(cost) is not dict
            or set(cost) != cost_keys
            or cost["owner_connection_acquisitions"] != 1
            or cost["independent_verifier_connection_acquisitions"] != 0
            or any(type(cost[key]) is not int or cost[key] < 0 for key in (
                "owner_read_statement_count", "independent_verifier_statement_count",
            ))
            or any(type(cost[key]) is not int or cost[key] < 0 for key in (
                "independent_verifier_microseconds", "snapshot_transaction_microseconds",
            ))
        ):
            _fail(FinancialMirrorContinuityError, "staff_read_cost")
        public_cost = {key: cost[key] for key in sorted(cost)}

        raw_bindings = raw["item_bindings"]
        binding_keys = {
            "item_id", "obligation_id", "revision", "evaluation_id", "evaluation_result_digest",
            "control_pack_id", "control_pack_version", "control_pack_digest",
        }
        if type(raw_bindings) is not list:
            _fail(FinancialMirrorContinuityError, "staff_item_bindings")
        bindings: dict[str, dict[str, Any]] = {}
        for binding in raw_bindings:
            if (
                type(binding) is not dict
                or set(binding) != binding_keys
                or any(type(binding[key]) is not str or not binding[key] for key in (
                    "item_id", "obligation_id", "evaluation_id", "control_pack_id",
                ))
                or type(binding["revision"]) is not int
                or binding["revision"] < 0
                or type(binding["control_pack_version"]) is not int
                or binding["control_pack_version"] < 1
                or any(
                    type(binding[key]) is not str
                    or len(binding[key]) != 128
                    or binding[key] != binding[key].upper()
                    or any(char not in "0123456789ABCDEF" for char in binding[key])
                    for key in ("evaluation_result_digest", "control_pack_digest")
                )
                or binding["item_id"] in bindings
            ):
                _fail(FinancialMirrorContinuityError, "staff_item_bindings")
            bindings[binding["item_id"]] = {key: binding[key] for key in sorted(binding)}

        resources_raw = raw["resources"]
        if type(resources_raw) is not dict:
            _fail(FinancialMirrorContinuityError, "staff_resource_contract")
        resource_type = raw["query"].get("resource")
        if resource_type == "workspace":
            expected_resources = {"summary", "population", "items_page", "detail", "decision_package", "timeline", "support_counts"}
            if set(resources_raw) != expected_resources:
                _fail(FinancialMirrorContinuityError, "staff_resource_contract")
            summary_raw = resources_raw["summary"]
            page_raw = resources_raw["items_page"]
            population_raw = resources_raw["population"]
            detail_raw = resources_raw["detail"]
            package_raw = resources_raw["decision_package"]
            timeline_raw = resources_raw["timeline"]
            support_counts = resources_raw["support_counts"]
            if (
                type(summary_raw) is not dict
                or set(summary_raw) != _STAFF_SUMMARY_FIELDS
                or summary_raw.get("sequence") != snapshot["sequence"]
                or type(page_raw) is not dict
                or set(page_raw) != {"status", "limit", "offset", "total_count", "next_offset", "items"}
                or page_raw["status"] not in {"ALL", "OPEN", "SATISFIED", "CASH_UNSATISFIED"}
                or type(page_raw["limit"]) is not int
                or not 1 <= page_raw["limit"] <= MAX_LIST_PAGE
                or type(page_raw["offset"]) is not int
                or page_raw["offset"] < 0
                or type(page_raw["total_count"]) is not int
                or page_raw["status"] == "ALL" and page_raw["total_count"] != summary_raw["obligation_count"]
                or type(page_raw["items"]) is not list
                or len(page_raw["items"]) > page_raw["limit"]
                or page_raw["next_offset"] != (
                    page_raw["offset"] + len(page_raw["items"])
                    if page_raw["offset"] + len(page_raw["items"]) < page_raw["total_count"]
                    else None
                )
                or type(support_counts) is not dict
            ):
                _fail(FinancialMirrorContinuityError, "staff_resource_binding")
            visible_items = page_raw["items"]
            visible_ids = [row.get("item_id") for row in visible_items if type(row) is dict]
            if len(visible_ids) != len(visible_items) or len(set(visible_ids)) != len(visible_ids):
                _fail(FinancialMirrorContinuityError, "staff_resource_items")
            required_binding_ids = set(visible_ids) | {str(raw["query"]["item_id"])}
            if set(bindings) != required_binding_ids or set(support_counts) != required_binding_ids:
                _fail(FinancialMirrorContinuityError, "staff_resource_bindings")
            label_values = dict(labels or {})
            if set(label_values) != set(visible_ids) or any(
                type(value) is not str or not value or len(value) > 128 for value in label_values.values()
            ):
                _fail(FinancialMirrorInputError, "staff_labels")
            public_items: list[dict[str, Any]] = []
            for row in visible_items:
                item_id = str(row["item_id"])
                binding = bindings[item_id]
                if (
                    row.get("obligation_id") != binding["obligation_id"]
                    or row.get("revision") != binding["revision"]
                    or row.get("current_evaluation_id") != binding["evaluation_id"]
                    or type(support_counts[item_id]) is not int
                    or support_counts[item_id] < 0
                ):
                    _fail(FinancialMirrorContinuityError, "staff_item_snapshot_mismatch")
                item = self._staff_obligation_projection(row)
                item.update(
                    {
                        "label": label_values[item_id],
                        "current_evaluation_id": binding["evaluation_id"],
                        "current_evaluation_result_digest": binding["evaluation_result_digest"],
                        "control_pack_id": binding["control_pack_id"],
                        "control_pack_version": binding["control_pack_version"],
                        "control_pack_digest": binding["control_pack_digest"],
                        "support_evidence_count": support_counts[item_id],
                        "source_status": (
                            "UNVERIFIED" if support_counts[item_id] else "MISSING"
                        ),
                    }
                )
                public_items.append(item)

            item_id = str(raw["query"]["item_id"])
            h_binding = bindings[item_id]
            if type(support_counts[item_id]) is not int or support_counts[item_id] < 0:
                _fail(FinancialMirrorContinuityError, "staff_support_count")
            detail = self._staff_obligation_detail(detail_raw, limit=int(raw["query"]["detail_limit"]))
            if (
                detail.get("item_id") != item_id
                or detail.get("obligation_id") != h_binding["obligation_id"]
                or detail.get("revision") != h_binding["revision"]
                or detail.get("current_evaluation_id") != h_binding["evaluation_id"]
            ):
                _fail(FinancialMirrorContinuityError, "staff_detail_binding")
            detail.update(
                {
                    "current_evaluation_result_digest": h_binding["evaluation_result_digest"],
                    "control_pack_id": h_binding["control_pack_id"],
                    "control_pack_version": h_binding["control_pack_version"],
                    "control_pack_digest": h_binding["control_pack_digest"],
                }
            )
            package = self._staff_decision_package(package_raw)
            self._staff_bind_package(package, h_binding, scope)
            timeline, timeline_total, timeline_truncated = self._staff_timeline(
                timeline_raw,
                obligation_id=h_binding["obligation_id"],
            )
            population = self._staff_population_status(population_raw, str(raw["query"]["population_id"]))
            summary = _safe_record(summary_raw)
            owner_schema = summary.get("schema")
            summary["schema"] = MIRROR_SCHEMA
            summary["owner_schema"] = owner_schema
            h_obligation = dict(detail)
            h_obligation["label"] = label_values.get(item_id, "Synthetic recipient H")
            h_obligation["support_evidence_count"] = support_counts[item_id]
            h_obligation["source_status"] = "MISSING_SUPPORT_UNVERIFIED" if support_counts[item_id] == 0 else "UNVERIFIED"
            if item_id in {row["item_id"] for row in public_items}:
                h_obligation = next(row for row in public_items if row["item_id"] == item_id)
            integrity = self._staff_integrity_projection(public_verification)
            continuity_value = self._staff_continuity_value(continuity)
            gates = self._staff_gate_checks(gate_checks)
            resources: dict[str, Any] = {
                "schema": "RR/FINANCIAL/STAFF-DEMO/v2",
                "read_at": read_at,
                "summary": summary,
                "population": population,
                "items": public_items,
                "item_page": {
                    "resource": "obligations",
                    "status": page_raw["status"],
                    "limit": page_raw["limit"],
                    "offset": page_raw["offset"],
                    "count": len(public_items),
                    "total_count": page_raw["total_count"],
                    "next_offset": page_raw["next_offset"],
                },
                "h": {
                    "obligation": h_obligation,
                    "detail": detail,
                    "decision_package": package,
                    "timeline": timeline,
                    "timeline_total_count": timeline_total,
                    "timeline_truncated": timeline_truncated,
                },
                "gate_checks": gates,
                **_staff_source_facts(support_counts[item_id]),
                "integrity": integrity,
                "continuity": continuity_value,
                "nonactivation": {
                    "dispatch_enabled": False,
                    "egress_enabled": False,
                    "production_usable": False,
                    "activation": False,
                    "proof_suite_id": None,
                    "money_movement": False,
                },
            }
            page_identity = dict(raw["query"])
        elif resource_type == "decision_package":
            if set(resources_raw) != {"decision_package", "timeline", "support_counts"}:
                _fail(FinancialMirrorContinuityError, "staff_resource_contract")
            item_id = str(raw["query"]["item_id"])
            binding = bindings.get(item_id)
            support_counts = resources_raw["support_counts"]
            if (
                binding is None
                or set(bindings) != {item_id}
                or type(support_counts) is not dict
                or set(support_counts) != {item_id}
                or type(support_counts[item_id]) is not int
                or support_counts[item_id] < 0
            ):
                _fail(FinancialMirrorContinuityError, "staff_resource_bindings")
            package = self._staff_decision_package(resources_raw["decision_package"])
            self._staff_bind_package(package, binding, scope)
            timeline, timeline_total, timeline_truncated = self._staff_timeline(
                resources_raw["timeline"],
                obligation_id=binding["obligation_id"],
            )
            resources = {
                "schema": "RR/FINANCIAL/STAFF-DECISION-VIEW/v1",
                "read_at": read_at,
                "sequence": snapshot["sequence"],
                "decision_package": package,
                "timeline": timeline,
                "timeline_total_count": timeline_total,
                "timeline_truncated": timeline_truncated,
                **_staff_source_facts(support_counts[item_id]),
                "integrity": self._staff_integrity_projection(public_verification),
            }
            page_identity = dict(raw["query"])
        else:
            _fail(FinancialMirrorContinuityError, "staff_query_resource")

        public_bindings = [bindings[key] for key in sorted(bindings)]
        envelope: dict[str, Any] = {
            "contract": STAFF_READ_ENVELOPE_CONTRACT,
            "query": page_identity,
            "query_digest": _staff_json_digest(raw["query"]),
            "scope": _safe_value(scope),
            "schema": snapshot["schema"],
            "schema_version": snapshot["schema_version"],
            "mode": snapshot["mode"],
            "owner_id": snapshot["owner_id"],
            "continuity_epoch": snapshot["continuity_epoch"],
            "sequence": snapshot["sequence"],
            "history_head": snapshot["history_head"],
            "snapshot_id": snapshot["snapshot_id"],
            "item_bindings": public_bindings,
            "verification": public_verification,
            "read_cost": public_cost,
            "resources_digest": _staff_json_digest(resources),
        }
        envelope["envelope_digest"] = _staff_json_digest(envelope)
        return {**resources, "read_envelope": envelope}

    @staticmethod
    def _staff_population_status(raw: object, expected_population_id: str) -> dict[str, Any]:
        owner_fields = {
            "population_id", "status", "imported_count", "expected_count", "validated_count",
            "manifest_status", "completeness", "source_complete", "manifest_version", "manifest_digest",
        }
        public_fields = (
            "status", "imported_count", "expected_count", "validated_count", "manifest_status",
            "completeness", "source_complete", "manifest_version",
        )
        if type(raw) is not dict or set(raw) != owner_fields or raw.get("population_id") != expected_population_id:
            _fail(FinancialMirrorContinuityError, "population_status_contract")
        if type(raw["status"]) is not str or raw["status"] not in {"STAGED", "VALIDATED", "PUBLISHED"}:
            _fail(FinancialMirrorContinuityError, "population_status_state")
        counts = (raw["imported_count"], raw["expected_count"], raw["validated_count"])
        if any(type(value) is not int or value < 0 for value in counts) or raw["expected_count"] < 1 or raw["validated_count"] > raw["imported_count"] or raw["imported_count"] > raw["expected_count"]:
            _fail(FinancialMirrorContinuityError, "population_status_counts")
        if type(raw["manifest_status"]) is not str or raw["manifest_status"] not in {"CURRENT", "SUPERSEDED", "MISSING"}:
            _fail(FinancialMirrorContinuityError, "population_status_manifest")
        if type(raw["completeness"]) is not str or raw["completeness"] not in {"EXACT", "INCOMPLETE", "STALE", "UNVERIFIED"} or type(raw["source_complete"]) is not bool:
            _fail(FinancialMirrorContinuityError, "population_status_completeness")
        if raw["manifest_status"] == "CURRENT":
            if raw["completeness"] not in {"EXACT", "INCOMPLETE"} or raw["source_complete"] != (raw["completeness"] == "EXACT"):
                _fail(FinancialMirrorContinuityError, "population_status_consistency")
        elif raw["completeness"] != ("STALE" if raw["manifest_status"] == "SUPERSEDED" else "UNVERIFIED") or raw["source_complete"]:
            _fail(FinancialMirrorContinuityError, "population_status_consistency")
        if raw["manifest_status"] in {"CURRENT", "SUPERSEDED"}:
            digest = raw["manifest_digest"]
            if type(raw["manifest_version"]) is not int or raw["manifest_version"] < 1 or type(digest) is not str or len(digest) != 128 or digest != digest.upper() or any(char not in "0123456789ABCDEF" for char in digest):
                _fail(FinancialMirrorContinuityError, "population_status_manifest_binding")
        elif raw["manifest_version"] is not None or raw["manifest_digest"] is not None:
            _fail(FinancialMirrorContinuityError, "population_status_manifest_binding")
        return {**{key: raw[key] for key in public_fields}, "schema": MIRROR_SCHEMA, "resource": "population_status"}

    @staticmethod
    def _staff_obligation_projection(raw: object) -> dict[str, Any]:
        if type(raw) is not dict or set(raw) != _STAFF_OBLIGATION_FIELDS:
            _fail(FinancialMirrorContinuityError, "staff_obligation_projection")
        return _safe_record({key: raw[key] for key in _STAFF_OBLIGATION_FIELDS})

    @staticmethod
    def _staff_obligation_detail(raw: object, *, limit: int) -> dict[str, Any]:
        expected_fields = set(_STAFF_OBLIGATION_FIELDS) | set(_STAFF_DETAIL_COLLECTIONS)
        if type(raw) is not dict or set(raw) != expected_fields:
            _fail(FinancialMirrorContinuityError, "staff_detail_contract")
        result = FinancialMirror._staff_obligation_projection(
            {key: raw[key] for key in _STAFF_OBLIGATION_FIELDS}
        )
        for source_key, (reference_key, allowed_fields) in _STAFF_DETAIL_COLLECTIONS.items():
            rows = raw.get(source_key)
            if type(rows) is not list or len(rows) > limit:
                _fail(FinancialMirrorContinuityError, "staff_detail_page")
            references: list[dict[str, Any]] = []
            for row in rows:
                if type(row) is not dict or set(row) != allowed_fields:
                    _fail(FinancialMirrorContinuityError, "staff_detail_page")
                redacted_fields = set(allowed_fields)
                if source_key == "actions":
                    redacted_fields.discard("idempotency_key")
                if source_key == "evaluations":
                    redacted_fields.difference_update({"scope_json", "input_snapshot_json", "input_snapshot_digest"})
                references.append(_safe_record({key: row[key] for key in redacted_fields}))
            result[reference_key] = references
            result[source_key] = references
        result["schema"] = MIRROR_SCHEMA
        result["resource"] = "obligation"
        result["reference_limit"] = limit
        return result

    @staticmethod
    def _staff_decision_package(raw: object) -> dict[str, Any]:
        def require_fields(value: object, fields: set[str], code: str) -> dict[str, Any]:
            if type(value) is not dict or set(value) != fields:
                _fail(FinancialMirrorContinuityError, code)
            return value

        base_fields = {
            "contract", "scope", "obligation", "evaluation_receipt", "control_pack", "case",
            "current_determination", "current_action", "cash", "reporting", "references", "conclusions",
        }
        if (
            type(raw) is not dict
            or raw.get("contract") != _DECISION_PACKAGE_CONTRACT
            or set(raw) != base_fields | {"population_binding"}
            or type(raw.get("scope")) is not dict
            or set(raw["scope"]) != {"state_id", "deployment_id", "program_id", "period_id", "currency"}
            or type(raw.get("obligation")) is not dict
            or set(raw["obligation"]) != _STAFF_OBLIGATION_FIELDS
            or type(raw.get("control_pack")) is not dict
            or set(raw["control_pack"]) != {
                "pack_id", "version", "digest", "calculation_rule_id", "adjustment_rule_id", "source_refs",
                "authorized_roles", "effective_start_ms", "effective_end_ms", "recorded_at_ms", "approved_at_ms",
            }
            or type(raw.get("cash")) is not dict
            or set(raw["cash"]) != {
                "recorded_received_cash_cents", "cash_satisfied", "claimed_adjustment_cents",
                "lawful_adjustment_cents", "amount_satisfied", "shortfall_cents", "overage_cents",
                "active_payment_count", "authorized_adjustment_count",
            }
            or type(raw.get("reporting")) is not dict
            or set(raw["reporting"]) != {"complete", "evidence_count"}
            or type(raw.get("references")) is not dict
            or set(raw["references"]) != {
                "cases", "evidence", "payments", "claims", "determinations", "actions", "conflicts", "reporting_evidence",
            }
            or type(raw.get("conclusions")) is not dict
            or set(raw["conclusions"]) != {
                "cash_satisfaction", "amount_satisfaction", "reporting_completion", "action_acknowledgment", "case_resolution",
            }
        ):
            _fail(FinancialMirrorContinuityError, "decision_package_allowlist")
        require_fields(raw["evaluation_receipt"], {
            "contract_version", "scope", "evaluation_id", "obligation_id", "revision", "control_pack",
            "evidence_bindings", "input_snapshot_digest", "authority", "rule_version", "evidence_ids",
            "authority_id", "evaluated_at_ms", "owed_cents", "claimed_adjustment_cents",
            "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents",
            "cash_satisfied", "amount_satisfied", "timely", "reporting_complete", "verification_status",
            "case_status", "delivery_status", "result_digest", "receipt_digest", "evaluation_result_digest",
        }, "decision_package_receipt_allowlist")
        if raw.get("case") is not None:
            require_fields(raw["case"], {
                "case_id", "obligation_id", "reason", "contractual_accountability", "next_action_owner",
                "due_at_ms", "completion_conditions", "status", "updated_at_ms",
            }, "decision_package_case_allowlist")
        if raw.get("current_determination") is not None:
            determination = require_fields(raw["current_determination"], {
                "determination_id", "obligation_id", "claim_id", "actor_id", "actor_role", "authority",
                "decision", "amount_cents", "supporting_evidence", "expected_revision", "resulting_revision",
                "decided_at_ms", "determination_digest", "input_evaluation_id", "input_evaluation_result_digest",
            }, "decision_package_determination_allowlist")
            require_fields(determination["authority"], {"authority_id", "epoch", "digest"}, "decision_package_authority_allowlist")
            if type(determination["supporting_evidence"]) is not list or any(
                type(row) is not dict or set(row) != {"evidence_id", "record_digest"}
                for row in determination["supporting_evidence"]
            ):
                _fail(FinancialMirrorContinuityError, "decision_package_determination_evidence_allowlist")
        action_fields = {
            "action_id", "obligation_id", "determination_id", "kind", "status", "revision", "payload_digest",
            "payload_fields", "created_at_ms", "acknowledgment",
        }
        if raw.get("current_action") is not None:
            action = require_fields(raw["current_action"], action_fields, "decision_package_action_allowlist")
            if type(action["payload_fields"]) is not dict or not set(action["payload_fields"]) <= set(_ACTION_FIELDS):
                _fail(FinancialMirrorContinuityError, "decision_package_action_payload_allowlist")
            require_fields(action["acknowledgment"], {
                "status", "reference", "attempt", "updated_at_ms", "cash_effect_cents",
            }, "decision_package_acknowledgment_allowlist")
        require_fields(raw["population_binding"], {
            "population_id", "status", "completeness", "source_complete", "manifest_id", "manifest_version",
            "manifest_digest", "member_id", "member_count", "member_digest",
        }, "decision_package_population_binding_allowlist")
        row_fields = {
            "cases": {"case_id", "obligation_id", "reason", "contractual_accountability", "next_action_owner", "due_at_ms", "completion_conditions", "status", "updated_at_ms"},
            "evidence": {"evidence_id", "item_id", "kind", "common_origin_id", "source_id", "source_version", "local_ref", "applicable_at_ms", "event_at_ms", "received_at_ms", "amount_cents", "reversal_of", "supersedes", "record_digest", "obligation_id"},
            "payments": {"payment_id", "obligation_id", "evidence_id", "common_origin_id", "amount_cents", "event_at_ms", "active", "reversed_by_evidence_id"},
            "claims": {"claim_id", "obligation_id", "evidence_id", "amount_cents", "owner_role", "deadline_ms", "status", "created_at_ms", "updated_at_ms"},
            "determinations": {"determination_id", "obligation_id", "claim_id", "actor_id", "actor_role", "authority", "decision", "amount_cents", "supporting_evidence", "expected_revision", "resulting_revision", "decided_at_ms", "determination_digest", "input_evaluation_id", "input_evaluation_result_digest"},
            "actions": action_fields,
            "conflicts": {"conflict_id", "obligation_id", "common_origin_id", "existing_payment_id", "candidate_evidence_id", "existing_amount_cents", "candidate_amount_cents", "reason", "visible_at_ms"},
            "reporting_evidence": {"evidence_id", "item_id", "kind", "common_origin_id", "source_id", "source_version", "local_ref", "applicable_at_ms", "event_at_ms", "received_at_ms", "amount_cents", "reversal_of", "supersedes", "record_digest", "obligation_id"},
        }
        for name, page in raw["references"].items():
            page = require_fields(page, {"offset", "limit", "count", "total", "next_offset", "items"}, "decision_package_page_allowlist")
            if (
                type(page["items"]) is not list
                or page["count"] != len(page["items"])
                or type(page["count"]) is not int
                or type(page["total"]) is not int
                or page["total"] < page["count"]
                or type(page["offset"]) is not int
                or type(page["limit"]) is not int
                or not 1 <= page["limit"] <= MAX_DETAIL_PAGE
                or page["count"] > page["limit"]
                or page["next_offset"] != (page["offset"] + page["count"] if page["offset"] + page["count"] < page["total"] else None)
                or any(type(row) is not dict or set(row) != row_fields[name] for row in page["items"])
            ):
                _fail(FinancialMirrorContinuityError, "decision_package_page_allowlist")
        conclusion_fields = {
            "cash_satisfaction": {"result", "evidence_status", "recorded_received_cash_cents", "required_cents", "missing_cents", "supporting_evidence_ids", "supporting_references_complete"},
            "amount_satisfaction": {"result", "evidence_status", "supporting_evidence_ids", "supporting_references_complete"},
            "reporting_completion": {"result", "supporting_evidence_ids", "supporting_references_complete"},
            "action_acknowledgment": {"result", "action_id", "reference", "cash_effect_cents"},
            "case_resolution": {"case_id", "obligation_id", "observed_status", "assessment", "required_conditions", "missing_requirements", "supporting_evidence_ids", "supporting_references_complete", "conflict_count", "conflict_ids"},
        }
        for name, fields in conclusion_fields.items():
            value = require_fields(raw["conclusions"][name], fields, "decision_package_conclusion_allowlist")
            if name == "case_resolution":
                require_fields(value["required_conditions"], {
                    "amount_satisfied", "delivery_acknowledged_or_not_required", "reporting_complete",
                }, "decision_package_requirements_allowlist")
        result = _safe_decision_value(raw)
        if type(result) is not dict or result.get("contract") != _DECISION_PACKAGE_CONTRACT:
            _fail(FinancialMirrorContinuityError, "decision_package_contract")
        result["schema"] = MIRROR_SCHEMA
        result["resource"] = "decision_package"
        return result

    @staticmethod
    def _staff_bind_package(package: Mapping[str, Any], binding: Mapping[str, Any], scope: Mapping[str, Any]) -> None:
        obligation = package.get("obligation")
        receipt = package.get("evaluation_receipt")
        pack = package.get("control_pack")
        if (
            type(obligation) is not dict
            or type(receipt) is not dict
            or type(pack) is not dict
            or package.get("scope") != dict(scope)
            or obligation.get("item_id") != binding["item_id"]
            or obligation.get("obligation_id") != binding["obligation_id"]
            or obligation.get("revision") != binding["revision"]
            or obligation.get("current_evaluation_id") != binding["evaluation_id"]
            or receipt.get("evaluation_id") != binding["evaluation_id"]
            or receipt.get("revision") != binding["revision"]
            or receipt.get("result_digest") != binding["evaluation_result_digest"]
            or pack.get("pack_id") != binding["control_pack_id"]
            or pack.get("version") != binding["control_pack_version"]
            or pack.get("digest") != binding["control_pack_digest"]
        ):
            _fail(FinancialMirrorContinuityError, "staff_package_binding")

    @staticmethod
    def _staff_timeline(raw: object, *, obligation_id: str) -> tuple[list[dict[str, Any]], int, bool]:
        if (
            type(raw) is not dict
            or set(raw) != {"limit", "total_count", "truncated", "items"}
            or type(raw["limit"]) is not int
            or not 1 <= raw["limit"] <= MAX_DETAIL_PAGE
            or type(raw["total_count"]) is not int
            or raw["total_count"] < 0
            or type(raw["truncated"]) is not bool
            or raw["truncated"] != (raw["total_count"] > raw["limit"])
            or type(raw["items"]) is not list
            or len(raw["items"]) > raw["limit"]
        ):
            _fail(FinancialMirrorContinuityError, "staff_timeline_contract")
        timeline: list[dict[str, Any]] = []
        previous_sequence = 0
        for event in raw["items"]:
            if (
                type(event) is not dict
                or event.get("aggregate_type") != "OBLIGATION"
                or event.get("aggregate_id") != obligation_id
                or type(event.get("event_sequence")) is not int
                or event["event_sequence"] <= previous_sequence
            ):
                _fail(FinancialMirrorContinuityError, "staff_timeline_binding")
            previous_sequence = event["event_sequence"]
            timeline.append(
                {
                    "event_sequence": event["event_sequence"],
                    "kind": str(event["kind"]),
                    "before_revision": event["before_revision"],
                    "after_revision": event["after_revision"],
                    "committed_at_ms": int(event["committed_at_ms"]),
                }
            )
        return timeline, raw["total_count"], raw["truncated"]

    @staticmethod
    def _staff_integrity_projection(verification: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "status": verification["status"],
            "schema": verification["schema"],
            "schema_version": verification["schema_version"],
            "mode": verification["mode"],
            "owner_id": verification["owner_id"],
            "continuity_epoch": verification["continuity_epoch"],
            "scope": verification["scope"],
            "sequence": verification["sequence"],
            "history_head": verification["history_head"],
            "counts": verification["counts"],
        }

    @staticmethod
    def _staff_gate_checks(raw: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        if raw is None:
            return []
        if type(raw) is not list or len(raw) > 8:
            _fail(FinancialMirrorInputError, "staff_gate_checks")
        result = []
        for row in raw:
            if (
                type(row) is not dict
                or set(row) != {"name", "status", "code", "state_unchanged"}
                or type(row["name"]) is not str
                or type(row["status"]) is not str
                or type(row["code"]) is not str
                or type(row["state_unchanged"]) is not bool
            ):
                _fail(FinancialMirrorContinuityError, "staff_gate_check_contract")
            result.append({key: row[key] for key in ("name", "status", "code", "state_unchanged")})
        return result

    @staticmethod
    def _staff_continuity_value(raw: Mapping[str, Any] | None) -> dict[str, Any]:
        expected = {"restored", "mode", "package_digest", "package_bytes", "decision_package_equal"}
        if raw is None:
            return {"restored": False, "mode": "UNKNOWN", "package_digest": None, "package_bytes": None, "decision_package_equal": None}
        if (
            not isinstance(raw, Mapping)
            or set(raw) != expected
            or type(raw["restored"]) is not bool
            or type(raw["mode"]) is not str
            or raw["package_digest"] is not None and (type(raw["package_digest"]) is not str or len(raw["package_digest"]) != 128)
            or raw["package_bytes"] is not None and (type(raw["package_bytes"]) is not int or raw["package_bytes"] < 0)
            or raw["decision_package_equal"] is not None and type(raw["decision_package_equal"]) is not bool
        ):
            _fail(FinancialMirrorContinuityError, "staff_continuity_contract")
        return {key: raw[key] for key in sorted(expected)}

    @staticmethod
    def _validated_correction_followup_output(raw: Any) -> dict[str, Any]:
        result = _safe_decision_value(raw)
        if type(result) is not dict or set(result) != {
            "followup_status", "work_id", "source_event_sequence", "mirror_explanation",
            "state_report", "corporate_support",
        }:
            _fail(FinancialMirrorContinuityError, "correction_followup_contract")
        status = result["followup_status"]
        if (
            type(status) is not str
            or status not in {"CURRENT", "REOPENED", "REVIEW_REQUIRED"}
            or type(result["work_id"]) is not str
            or not result["work_id"]
            or len(result["work_id"]) > 256
            or type(result["source_event_sequence"]) is not int
            or not 1 <= result["source_event_sequence"] <= MAX_OFFSET
        ):
            _fail(FinancialMirrorContinuityError, "correction_followup_status")
        explanation = result["mirror_explanation"]
        report = result["state_report"]
        if (
            type(explanation) is not dict
            or set(explanation)
            != {
                "contract", "transition", "followup_status", "source_event_sequence",
                "accepted_basis", "current_basis", "decision_package",
            }
            or type(report) is not dict
            or set(report)
            != {
                "contract", "followup_status", "source_event_sequence", "accepted_basis",
                "current_basis", "decision_package",
            }
            or explanation.get("contract") != "RR/FINANCIAL/CORRECTION-EXPLANATION/v1"
            or explanation.get("transition") != "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
            or report.get("contract") != "RR/FINANCIAL/CORRECTION-REPORT/v1"
            or explanation.get("followup_status") != status
            or report.get("followup_status") != status
            or explanation.get("source_event_sequence") != result["source_event_sequence"]
            or report.get("source_event_sequence") != result["source_event_sequence"]
            or explanation.get("decision_package") != report.get("decision_package")
            or type(explanation.get("decision_package")) is not dict
        ):
            _fail(FinancialMirrorContinuityError, "correction_followup_projection")
        support = result["corporate_support"]
        if type(support) is not dict or set(support) != {
            "contract", "status", "component", "artifact", "failure_stage", "error_class", "reproduction",
        }:
            _fail(FinancialMirrorContinuityError, "corporate_support_allowlist")
        expected_failure = {
            "CURRENT": ("NONE", "NONE"),
            "REOPENED": ("FOLLOWUP_RECONCILIATION", "STALE_DEPENDENCY"),
            "REVIEW_REQUIRED": ("FOLLOWUP_RECONCILIATION", "UNSUPPORTED_DEPENDENCY"),
        }[status]
        artifact = support["artifact"]
        if artifact is not None and (
            type(artifact) is not dict
            or set(artifact) != {"contract", "version", "sha256"}
            or type(artifact["contract"]) is not str
            or type(artifact["version"]) is not int
            or artifact["version"] < 1
            or type(artifact["sha256"]) is not str
            or len(artifact["sha256"]) != 64
            or any(character not in "0123456789ABCDEF" for character in artifact["sha256"])
        ):
            _fail(FinancialMirrorContinuityError, "corporate_support_artifact")
        if (
            support["contract"] != "RR/FINANCIAL/CORPORATE-SUPPORT/v1"
            or support["status"] != status
            or support["component"] != "FINANCIAL_CORRECTION"
            or (support["failure_stage"], support["error_class"]) != expected_failure
            or support["reproduction"] != {"scenario": "SYNTHETIC_CORRECTION", "real_data": False}
        ):
            _fail(FinancialMirrorContinuityError, "corporate_support_allowlist")
        return result

    def correction_followup_outputs(self, item_id: str, action_id: str) -> dict[str, Any]:
        result = self._validated_correction_followup_output(
            self.owner.correction_followup_outputs(item_id, action_id)
        )
        result["schema"] = MIRROR_SCHEMA
        result["resource"] = "correction_followup"
        return result

    def drain_correction_followups(
        self,
        *,
        after_event_sequence: int = 0,
        limit: int = 25,
    ) -> dict[str, Any]:
        if type(after_event_sequence) is not int or not 0 <= after_event_sequence <= MAX_OFFSET:
            _fail(FinancialMirrorInputError, "correction_followup_cursor")
        if type(limit) is not int or not 1 <= limit <= 100:
            _fail(FinancialMirrorInputError, "correction_followup_limit")
        raw = self.owner.drain_correction_followups(
            after_event_sequence=after_event_sequence,
            limit=limit,
        )
        if type(raw) is not dict or set(raw) != {
            "contract", "items", "count", "after_event_sequence",
            "next_after_event_sequence", "has_more", "skipped",
        } or raw.get("contract") != "RR/FINANCIAL/CORRECTION-FOLLOWUP-DRAIN/v1":
            _fail(FinancialMirrorContinuityError, "correction_followup_drain_contract")
        skipped = raw.get("skipped")
        if (
            type(raw.get("items")) is not list
            or type(raw.get("count")) is not int
            or raw["count"] != len(raw["items"])
            or raw.get("after_event_sequence") != after_event_sequence
            or type(raw.get("next_after_event_sequence")) is not int
            or not after_event_sequence <= raw["next_after_event_sequence"] <= MAX_OFFSET
            or type(raw.get("has_more")) is not bool
            or type(skipped) is not dict
            or set(skipped) != {"count", "reasons"}
            or type(skipped.get("count")) is not int
            or skipped["count"] < 0
            or type(skipped.get("reasons")) is not dict
            or any(type(key) is not str or type(value) is not int or value < 0 for key, value in skipped["reasons"].items())
            or sum(skipped["reasons"].values()) != skipped["count"]
        ):
            _fail(FinancialMirrorContinuityError, "correction_followup_drain_contract")
        items = [self._validated_correction_followup_output(item) for item in raw["items"]]
        result = {
            **raw,
            "items": items,
            "schema": MIRROR_SCHEMA,
            "resource": "correction_followup_drain",
        }
        try:
            page_bytes = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        except (TypeError, ValueError, UnicodeError):
            _fail(FinancialMirrorContinuityError, "correction_followup_drain_value")
        if len(page_bytes) > MAX_CORRECTION_FOLLOWUP_PAGE_BYTES:
            _fail(FinancialMirrorContinuityError, "correction_followup_drain_size")
        return result

    def program_funding_summary(self) -> dict[str, Any]:
        raw = self.owner.program_funding_summary()
        result = _safe_record(raw)
        result["resource"] = "program_funding"
        return result

    def population_status(self, population_id: str) -> dict[str, Any]:
        """Expose only the owner's safe population completeness projection."""

        raw = self.owner.population_status(population_id)
        owner_fields = (
            "population_id",
            "status",
            "imported_count",
            "expected_count",
            "validated_count",
            "manifest_status",
            "completeness",
            "source_complete",
            "manifest_version",
            "manifest_digest",
        )
        public_fields = (
            "status",
            "imported_count",
            "expected_count",
            "validated_count",
            "manifest_status",
            "completeness",
            "source_complete",
            "manifest_version",
        )
        if type(raw) is not dict or set(raw) != set(owner_fields):
            _fail(FinancialMirrorContinuityError, "population_status_contract")
        if type(raw["population_id"]) is not str:
            _fail(FinancialMirrorContinuityError, "population_status_contract")
        if type(raw["status"]) is not str or raw["status"] not in {"STAGED", "VALIDATED", "PUBLISHED"}:
            _fail(FinancialMirrorContinuityError, "population_status_state")
        counts = (raw["imported_count"], raw["expected_count"], raw["validated_count"])
        if (
            any(type(value) is not int or value < 0 for value in counts)
            or raw["expected_count"] < 1
            or raw["validated_count"] > raw["imported_count"]
            or raw["imported_count"] > raw["expected_count"]
        ):
            _fail(FinancialMirrorContinuityError, "population_status_counts")
        if type(raw["manifest_status"]) is not str or raw["manifest_status"] not in {"CURRENT", "SUPERSEDED", "MISSING"}:
            _fail(FinancialMirrorContinuityError, "population_status_manifest")
        if type(raw["completeness"]) is not str or raw["completeness"] not in {"EXACT", "INCOMPLETE", "STALE", "UNVERIFIED"}:
            _fail(FinancialMirrorContinuityError, "population_status_completeness")
        if type(raw["source_complete"]) is not bool:
            _fail(FinancialMirrorContinuityError, "population_status_complete")
        if raw["manifest_status"] == "CURRENT":
            if (
                raw["completeness"] not in {"EXACT", "INCOMPLETE"}
                or raw["source_complete"] != (raw["completeness"] == "EXACT")
            ):
                _fail(FinancialMirrorContinuityError, "population_status_consistency")
        elif (
            raw["completeness"] != ("STALE" if raw["manifest_status"] == "SUPERSEDED" else "UNVERIFIED")
            or raw["source_complete"]
        ):
            _fail(FinancialMirrorContinuityError, "population_status_consistency")
        if raw["manifest_status"] in {"CURRENT", "SUPERSEDED"}:
            digest = raw["manifest_digest"]
            if (
                type(raw["manifest_version"]) is not int
                or raw["manifest_version"] < 1
                or type(digest) is not str
                or len(digest) != 128
                or digest != digest.upper()
                or any(char not in "0123456789ABCDEF" for char in digest)
            ):
                _fail(FinancialMirrorContinuityError, "population_status_manifest_binding")
        elif raw["manifest_version"] is not None or raw["manifest_digest"] is not None:
            _fail(FinancialMirrorContinuityError, "population_status_manifest_binding")
        result = {key: raw[key] for key in public_fields}
        result["schema"] = MIRROR_SCHEMA
        result["resource"] = "population_status"
        return result

    def record_program_funding_receipt(self, receipt: ProgramFundingReceipt) -> dict[str, Any]:
        return self._command_result(self.owner.record_program_funding_receipt(receipt))

    def history(self, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        limit, offset = _page_bounds(limit, offset, maximum=MAX_DETAIL_PAGE, code="history_page")
        rows = self.owner.history(limit=limit, offset=offset)
        references: list[dict[str, Any]] = []
        for row in rows:
            reference = _safe_record(row)
            reference.pop("payload", None)
            reference.pop("payload_json", None)
            if reference.get("aggregate_type") in {"POPULATION", "POPULATION_MANIFEST"}:
                reference.pop("aggregate_id", None)
            references.append(reference)
        return _page(MIRROR_SCHEMA, "history", references, limit=limit, offset=offset)

    def action_payload(self, action_id: str) -> dict[str, Any]:
        raw = self.owner.action_payload(action_id)
        result = {
            "schema": MIRROR_SCHEMA,
            "resource": "action",
            "action_id": raw.get("action_id"),
            "payload_digest": _safe_value(raw.get("payload_digest")),
            "payload_fields": _allowlisted_action_fields(raw.get("payload")),
        }
        return result

    def _command_result(self, value: Mapping[str, Any]) -> dict[str, Any]:
        result = _safe_record(value)
        result["schema"] = MIRROR_SCHEMA
        result["resource"] = "command_result"
        return result

    def authorize_offset(
        self,
        *,
        item_id: str,
        claim_id: str,
        actor_id: str = "synthetic-official",
        actor_role: str = "FINANCE_DECISION",
        expected_revision: int | None = None,
        action_id: str | None = None,
        decision_at_ms: int | None = None,
        evaluation_id: str | None = None,
        evaluation_result_digest: str | bytes | None = None,
    ) -> dict[str, Any]:
        return self._command_result(
            self.owner.authorize_offset(
                item_id=item_id,
                claim_id=claim_id,
                actor_id=actor_id,
                actor_role=actor_role,
                expected_revision=expected_revision,
                action_id=action_id,
                decision_at_ms=decision_at_ms,
                evaluation_id=evaluation_id,
                evaluation_result_digest=evaluation_result_digest,
            )
        )

    def reject_offset_and_authorize_correction(
        self,
        *,
        item_id: str,
        claim_id: str,
        actor_id: str = "synthetic-official",
        actor_role: str = "FINANCE_DECISION",
        expected_revision: int | None = None,
        action_id: str | None = None,
        decision_at_ms: int | None = None,
        evaluation_id: str | None = None,
        evaluation_result_digest: str | bytes | None = None,
        staff_read_binding: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._command_result(
            self.owner.reject_offset_and_authorize_correction(
                item_id=item_id,
                claim_id=claim_id,
                actor_id=actor_id,
                actor_role=actor_role,
                expected_revision=expected_revision,
                action_id=action_id,
                decision_at_ms=decision_at_ms,
                evaluation_id=evaluation_id,
                evaluation_result_digest=evaluation_result_digest,
                staff_read_binding=staff_read_binding,
            )
        )

    def acknowledge_action(
        self,
        action_id: str,
        acknowledgment_ref: str,
        *,
        actor_id: str = "synthetic-receiver",
        actor_role: str = "RECEIVER",
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        return self._command_result(
            self.owner.acknowledge_action(
                action_id,
                acknowledgment_ref,
                actor_id=actor_id,
                actor_role=actor_role,
                expected_revision=expected_revision,
            )
        )

    def retry_action(self, action_id: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self._command_result(self.owner.retry_action(action_id, payload=payload))

    def record_payment_evidence(
        self,
        *,
        item_id: str,
        payment_id: str,
        common_origin_id: str,
        amount_cents: int,
        evidence_id: str,
        event_at_ms: int,
        source_id: str = "synthetic-payment-source",
        source_version: str = "fixture-v1",
        local_ref: str | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        return self._command_result(
            self.owner.record_payment_evidence(
                item_id=item_id,
                payment_id=payment_id,
                common_origin_id=common_origin_id,
                amount_cents=amount_cents,
                evidence_id=evidence_id,
                event_at_ms=event_at_ms,
                source_id=source_id,
                source_version=source_version,
                local_ref=local_ref,
                expected_revision=expected_revision,
            )
        )

    def record_reporting_correction(
        self,
        *,
        item_id: str,
        report_id: str,
        evidence_id: str | None = None,
        actor_id: str = "synthetic-reporter",
        actor_role: str = "REPORTING_EDITOR",
        expected_revision: int | None = None,
        event_at_ms: int | None = None,
        supersedes: str | None = None,
    ) -> dict[str, Any]:
        return self._command_result(
            self.owner.record_reporting_correction(
                item_id=item_id,
                report_id=report_id,
                evidence_id=evidence_id,
                actor_id=actor_id,
                actor_role=actor_role,
                expected_revision=expected_revision,
                event_at_ms=event_at_ms,
                supersedes=supersedes,
            )
        )

    def record_reporting_evidence(
        self,
        *,
        item_id: str,
        report_id: str,
        evidence_id: str | None = None,
        actor_id: str = "synthetic-reporter",
        actor_role: str = "REPORTING_EDITOR",
        expected_revision: int | None = None,
        event_at_ms: int | None = None,
    ) -> dict[str, Any]:
        return self._command_result(
            self.owner.record_reporting_evidence(
                item_id=item_id,
                report_id=report_id,
                evidence_id=evidence_id,
                actor_id=actor_id,
                actor_role=actor_role,
                expected_revision=expected_revision,
                event_at_ms=event_at_ms,
            )
        )

    def verify_integrity(self) -> dict[str, Any]:
        raw = self.owner.verify_integrity()
        allowed = (
            "schema",
            "schema_version",
            "scope",
            "authority",
            "mode",
            "owner_id",
            "continuity_epoch",
            "sequence",
            "history_head",
            "counts",
            "totals",
            "continuity",
            "program_funding",
        )
        result = {key: _safe_value(raw[key]) for key in allowed if key in raw}
        result["mirror_schema"] = MIRROR_SCHEMA
        result["integrity"] = "VERIFIED"
        return result

    def dispatch_outbox(self, *args: Any, **kwargs: Any) -> None:
        """Keep corporate egress and live dispatch permanently disabled."""

        try:
            self.owner.dispatch_outbox(*args, **kwargs)
        except FinancialDispatchError:
            _fail(FinancialMirrorDispatchError, "dispatch_disabled")
        _fail(FinancialMirrorDispatchError, "dispatch_disabled")

    @staticmethod
    def validate_continuity_package(
        package_bytes: bytes,
        *,
        trusted_authority: SyntheticTrustedAuthority,
        expected_scope: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate package bytes against caller-supplied trusted authority and scope.

        The authority (including its digest-bound roster) and the scope always
        come from the caller, never from the package being checked, so a
        package cannot certify itself (Articles V.2, XI.10).
        """

        if type(package_bytes) is not bytes:
            _fail(FinancialMirrorContinuityError, "continuity_package_type")
        if len(package_bytes) > MAX_PACKAGE_BYTES:
            _fail(FinancialMirrorContinuityError, "continuity_package_size")
        if type(trusted_authority) is not SyntheticTrustedAuthority:
            _fail(FinancialMirrorContinuityError, "continuity_trusted_authority_required")
        if not isinstance(expected_scope, Mapping):
            _fail(FinancialMirrorContinuityError, "continuity_expected_scope_required")
        package = FinancialOwner.validate_continuity_package(package_bytes)
        tables = package.get("tables")
        if not isinstance(tables, Mapping):
            _fail(FinancialMirrorContinuityError, "continuity_package_tables")
        if package.get("scope") != dict(expected_scope):
            _fail(FinancialMirrorContinuityError, "continuity_scope_mismatch")
        if package.get("authority") != {
            "authority_id": trusted_authority.authority_id,
            "epoch": trusted_authority.epoch,
            "digest": trusted_authority.digest.hex().upper(),
        }:
            _fail(FinancialMirrorContinuityError, "continuity_authority_mismatch")
        from app.right_rail_financial_owner_independent import verify_continuity_package

        independently_verified = verify_continuity_package(
            package_bytes,
            expected_scope=dict(expected_scope),
            expected_authority=trusted_authority,
            expected_schema_version=package["version"],
        )
        result = {
            "mirror_schema": MIRROR_SCHEMA,
            "schema": package.get("schema"),
            "version": package.get("version"),
            "scope": _safe_value(package.get("scope")),
            "authority": _safe_value(package.get("authority")),
            "continuity_epoch": package.get("continuity_epoch"),
            "sequence": package.get("sequence"),
            "history_head": package.get("history_head"),
            "mode": package.get("mode"),
            "dispatch_enabled": package.get("dispatch_enabled"),
            "egress_enabled": package.get("egress_enabled"),
            "table_counts": {str(table): len(value) for table, value in tables.items()},
            "package_digest": package.get("package_digest"),
            "package_bytes": len(package_bytes),
        }
        if "program_funding" in independently_verified:
            result["program_funding"] = _safe_value(independently_verified["program_funding"])
        return result

    def validate_owner_continuity_package(self, package_bytes: bytes) -> dict[str, Any]:
        """Validate package bytes against this Mirror's Owner authority and scope."""

        config = self.owner.config
        return self.validate_continuity_package(
            package_bytes,
            trusted_authority=self.owner.trusted_authority,
            expected_scope={
                "state_id": config.state_id,
                "deployment_id": config.deployment_id,
                "program_id": config.program_id,
                "period_id": config.period_id,
                "currency": config.currency,
            },
        )

    def export_continuity(self) -> bytes:
        package = self.owner.export_continuity()
        if type(package) is not bytes:
            _fail(FinancialMirrorContinuityError, "continuity_export_type")
        # Validate the exact bytes produced by the owner before exposing them.
        self.validate_owner_continuity_package(package)
        return package

    def _validate_restore_binding(self, package_bytes: bytes) -> None:
        # Scope and authority were already bound by validate_owner_continuity_package.
        package = FinancialOwner.validate_continuity_package(package_bytes)
        if package.get("schema") != self.owner.continuity_schema or package.get("version") != self.owner.schema_version:
            _fail(FinancialMirrorContinuityError, "continuity_package_schema")
        if package.get("dispatch_enabled") is not False or package.get("egress_enabled") is not False:
            _fail(FinancialMirrorContinuityError, "continuity_nonactivating_boundary")

    def _restore_continuity(self, package_bytes: bytes, recovered_path: Path, *, restore_mode: str) -> "FinancialMirror":
        """Validate and restore into a new independently verified non-live owner."""

        if restore_mode not in {"SHADOW", "TEST"}:
            _fail(FinancialMirrorContinuityError, "continuity_restore_mode")
        if not isinstance(recovered_path, Path):
            _fail(FinancialMirrorContinuityError, "continuity_destination")
        self.validate_owner_continuity_package(package_bytes)
        self._validate_restore_binding(package_bytes)
        source_name = _normalized_path(self.owner.path)
        destination_name = _normalized_path(recovered_path)
        if source_name == destination_name:
            _fail(FinancialMirrorContinuityError, "continuity_source_overwrite")
        if recovered_path.is_symlink() or recovered_path.exists() or not recovered_path.parent.is_dir():
            _fail(FinancialMirrorContinuityError, "continuity_destination")

        with _RESTORE_LOCK:
            if destination_name in _ACTIVE_DESTINATIONS:
                _fail(FinancialMirrorContinuityError, "continuity_second_writer")
            _ACTIVE_DESTINATIONS.add(destination_name)
            try:
                restored_owner = type(self.owner).restore_continuity(
                    package_bytes=package_bytes,
                    recovered_path=recovered_path,
                    trusted_authority=self.owner.trusted_authority,
                    restore_mode=restore_mode,
                    correction_transition_release=self.owner.correction_transition_release,
                )
                summary = restored_owner.summary()
                integrity = restored_owner.verify_integrity()
                expected_owner_id = "continuity-shadow-owner-v1" if restore_mode == "SHADOW" else "continuity-test-owner-v1"
                if restored_owner.mode != restore_mode or summary.get("dispatch_enabled") is not False or summary.get("egress_enabled") is not False or integrity.get("mode") != restore_mode:
                    _fail(FinancialMirrorContinuityError, f"continuity_{restore_mode.lower()}_boundary")
                if restored_owner.owner_id != expected_owner_id:
                    _fail(FinancialMirrorContinuityError, "continuity_owner_identity")
                return type(self)(restored_owner)
            except BaseException:
                _cleanup_new_destination(recovered_path)
                raise
            finally:
                _ACTIVE_DESTINATIONS.discard(destination_name)

    def restore_continuity(self, package_bytes: bytes, recovered_path: Path) -> "FinancialMirror":
        """Validate and restore into a new, independently verified SHADOW owner."""

        return self._restore_continuity(package_bytes, recovered_path, restore_mode="SHADOW")

    def restore_test_continuity(self, package_bytes: bytes, recovered_path: Path) -> "FinancialMirror":
        """Restore into an explicitly TEST-only owner for synthetic continuation."""

        return self._restore_continuity(package_bytes, recovered_path, restore_mode="TEST")

    restore_shadow = restore_continuity
    restore_test = restore_test_continuity


RightRailFinancialMirror = FinancialMirror
Mirror = FinancialMirror


__all__ = (
    "CONTINUITY_SCHEMA",
    "FinancialMirror",
    "FinancialMirrorContinuityError",
    "FinancialMirrorDispatchError",
    "FinancialMirrorError",
    "FinancialMirrorInputError",
    "MAX_PACKAGE_BYTES",
    "MIRROR_SCHEMA",
    "Mirror",
    "RightRailFinancialMirror",
)
