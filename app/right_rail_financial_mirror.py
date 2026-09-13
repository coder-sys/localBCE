"""Same-owner Mirror and bounded Continuity adapter for RightRail financial state.

The financial owner remains the only writer and the only balance calculator.  This
module owns no database, opens no SQLite connection, and persists no projection.
It only delegates to one :class:`FinancialOwner`, bounds read pages, removes raw
event/action payloads from the read model, and enforces the shadow-only continuity
boundary around the owner's public API.
"""

from __future__ import annotations

from pathlib import Path
import os
import threading
from collections.abc import Mapping
from typing import Any, Final

from app.right_rail_financial_owner import (
    FinancialContinuityError,
    FinancialDispatchError,
    FinancialOwner,
)


MIRROR_SCHEMA: Final[str] = "RR/FINANCIAL/MIRROR/v1"
CONTINUITY_SCHEMA: Final[str] = "RR/FINANCIAL/CONTINUITY/v1"
MAX_PACKAGE_BYTES: Final[int] = 8 * 1024 * 1024
MAX_LIST_PAGE: Final[int] = 100
MAX_DETAIL_PAGE: Final[int] = 200
MAX_OFFSET: Final[int] = 10_000

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
_JSON_REFERENCE_KEYS: Final[dict[str, str]] = {
    "evidence_ids_json": "evidence_ids",
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
    "dispatch",
)

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
        return {str(key): _safe_value(item) for key, item in value.items()}
    if type(value) is list:
        return [_safe_value(item) for item in value]
    if type(value) is tuple:
        return [_safe_value(item) for item in value]
    if value is None or type(value) in {str, int, float, bool}:
        return value
    _fail(FinancialMirrorContinuityError, "unsafe_owner_value")


def _safe_record(record: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, raw_value in record.items():
        key = str(raw_key)
        if key in _DROP_KEYS:
            continue
        if key in _JSON_REFERENCE_KEYS:
            reference_key = _JSON_REFERENCE_KEYS[key]
            reference = _safe_json_reference(raw_value, reference_key)
            if reference is not None:
                result[reference_key] = reference
            continue
        result[key] = _safe_value(raw_value)
    return result


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

    def history(self, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        limit, offset = _page_bounds(limit, offset, maximum=MAX_DETAIL_PAGE, code="history_page")
        rows = self.owner.history(limit=limit, offset=offset)
        references: list[dict[str, Any]] = []
        for row in rows:
            reference = _safe_record(row)
            reference.pop("payload", None)
            reference.pop("payload_json", None)
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
            )
        )

    def acknowledge_action(
        self,
        action_id: str,
        acknowledgment_ref: str,
        *,
        actor_id: str = "synthetic-receiver",
        actor_role: str = "RECEIVER",
    ) -> dict[str, Any]:
        return self._command_result(
            self.owner.acknowledge_action(
                action_id,
                acknowledgment_ref,
                actor_id=actor_id,
                actor_role=actor_role,
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
    def validate_continuity_package(package_bytes: bytes) -> dict[str, Any]:
        if type(package_bytes) is not bytes:
            _fail(FinancialMirrorContinuityError, "continuity_package_type")
        if len(package_bytes) > MAX_PACKAGE_BYTES:
            _fail(FinancialMirrorContinuityError, "continuity_package_size")
        package = FinancialOwner.validate_continuity_package(package_bytes)
        tables = package.get("tables")
        if not isinstance(tables, Mapping):
            _fail(FinancialMirrorContinuityError, "continuity_package_tables")
        return {
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

    def export_continuity(self) -> bytes:
        package = self.owner.export_continuity()
        if type(package) is not bytes:
            _fail(FinancialMirrorContinuityError, "continuity_export_type")
        # Validate the exact bytes produced by the owner before exposing them.
        self.validate_continuity_package(package)
        return package

    def _validate_restore_binding(self, package_bytes: bytes) -> None:
        package = FinancialOwner.validate_continuity_package(package_bytes)
        expected_scope = {
            "state_id": self.owner.config.state_id,
            "deployment_id": self.owner.config.deployment_id,
            "program_id": self.owner.config.program_id,
            "period_id": self.owner.config.period_id,
            "currency": self.owner.config.currency,
        }
        if package.get("schema") != CONTINUITY_SCHEMA or package.get("version") != 1:
            _fail(FinancialMirrorContinuityError, "continuity_package_schema")
        if package.get("scope") != expected_scope:
            _fail(FinancialMirrorContinuityError, "continuity_scope_mismatch")
        expected_authority = {
            "authority_id": self.owner.trusted_authority.authority_id,
            "epoch": self.owner.trusted_authority.epoch,
            "digest": self.owner.trusted_authority.digest.hex().upper(),
        }
        if package.get("authority") != expected_authority:
            _fail(FinancialMirrorContinuityError, "continuity_authority_mismatch")
        if package.get("dispatch_enabled") is not False or package.get("egress_enabled") is not False:
            _fail(FinancialMirrorContinuityError, "continuity_nonactivating_boundary")

    def restore_continuity(self, package_bytes: bytes, recovered_path: Path) -> "FinancialMirror":
        """Validate and restore into a new, independently verified SHADOW owner."""

        if not isinstance(recovered_path, Path):
            _fail(FinancialMirrorContinuityError, "continuity_destination")
        self.validate_continuity_package(package_bytes)
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
                )
                summary = restored_owner.summary()
                integrity = restored_owner.verify_integrity()
                if restored_owner.mode != "SHADOW" or summary.get("dispatch_enabled") is not False or summary.get("egress_enabled") is not False or integrity.get("mode") != "SHADOW":
                    _fail(FinancialMirrorContinuityError, "continuity_shadow_boundary")
                if restored_owner.owner_id != "continuity-shadow-owner-v1":
                    _fail(FinancialMirrorContinuityError, "continuity_owner_identity")
                return type(self)(restored_owner)
            except BaseException:
                _cleanup_new_destination(recovered_path)
                raise
            finally:
                _ACTIVE_DESTINATIONS.discard(destination_name)

    restore_shadow = restore_continuity


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
