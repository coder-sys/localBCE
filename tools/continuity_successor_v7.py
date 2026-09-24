"""Independent, integrity-only receiver for synthetic RightRail Continuity v7.

This module has no dependency on the financial owner, its checker, or Mirror.
It never opens a database, dispatches an action, or treats an acknowledgment
or funding record as evidence of cash movement. A valid package digest proves
only internal consistency because the producer contract has no signature.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from typing import Any, Mapping


MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_ROWS = 10_000
MAX_CENTS = (1 << 63) - 1
V7_SCHEMA = "RR/FINANCIAL/CONTINUITY/v7"
OWNER_SCHEMA = "RR/FINANCIAL/OWNER/v7"
VIEW_SCHEMA = "RR/FINANCIAL/CONTINUITY-SUCCESSOR/v7"
CONTINUITY_DOMAIN = b"RR/FINANCIAL/CONTINUITY/v7\x00"
GENESIS_DOMAIN = b"RR/FINANCIAL/GENESIS/v7\x00"
EVENT_DOMAIN = b"RR/FINANCIAL/EVENT/v2\x00"
HEAD_DOMAIN = b"RR/FINANCIAL/HEAD/v2\x00"
IDENTITY_DOMAIN = b"RR/FINANCIAL/IDENTITY/v1\x00"
POPULATION_MANIFEST_DOMAIN = b"RR/FINANCIAL/POPULATION-MANIFEST/v1\x00"
POPULATION_MANIFEST_MEMBERS_DOMAIN = b"RR/FINANCIAL/POPULATION-MANIFEST-MEMBERS/v1\x00"
EVIDENCE_DOMAIN = b"RR/FINANCIAL/EVIDENCE/v1\x00"
ACTION_DOMAIN = b"RR/FINANCIAL/ACTION/v1\x00"
IDEMPOTENCY_DOMAIN = b"RR/FINANCIAL/IDEMPOTENCY/v1\x00"
EVALUATION_INPUT_DOMAIN = b"RR/FINANCIAL/EVALUATION-INPUT/v1\x00"
EVALUATION_RESULT_DOMAIN = b"RR/FINANCIAL/EVALUATION/v5\x00"
EVALUATION_RECEIPT_DOMAIN = b"RR/FINANCIAL/EVALUATION-RECEIPT/v1\x00"
EVALUATION_EVENT_DOMAIN = b"RR/FINANCIAL/EVALUATION-EVENT/v1\x00"
PROGRAM_FUNDING_RECEIPT_DOMAIN = b"RR/FINANCIAL/PROGRAM-FUNDING-RECEIPT/v1\x00"
ZERO_DIGEST = b"\x00" * 64
HEX128 = re.compile(r"[0-9A-Fa-f]{128}\Z", re.ASCII)
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
KIND_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)
SHADOW_OWNER_ID = "continuity-shadow-owner-v1"
TEST_OWNER_ID = "continuity-test-owner-v1"
RECEIPT_CONTRACT = "RR/FINANCIAL/EVALUATION-RECEIPT/v1"
MANIFEST_CONTRACT = "RR/FINANCIAL/POPULATION-MANIFEST/v1"
FUNDING_CONTRACT = "RR/FINANCIAL/PROGRAM-FUNDING-RECEIPT/v1"
FUNDING_CLASS = "STATE_PAYMENT_RECORD"
FUNDING_STATUS = "SYNTHETIC_UNAPPROVED"

# Each table grammar copies the v7 SQLite column order and storage class from
# the current owner export contract. I=INTEGER, T=TEXT, B=BLOB.
_FIELD_SPEC_TEXT = {
    "financial_identity": "I id I schema_version T provenance T bound_mode T bound_owner_id I anchor_sequence B anchor_head B genesis_head B source_package_digest B identity_digest",
    "financial_meta": "I id I schema_version T schema T state_id T deployment_id T program_id T period_id T currency I sequence B history_head I continuity_epoch I dispatch_enabled I egress_enabled T trusted_authority_id I trusted_authority_epoch B trusted_authority_digest T mode T owner_id",
    "control_packs": "T pack_id T state_id T deployment_id T program_id T period_id I version T source_refs_json I effective_start_ms I effective_end_ms I recorded_at_ms I approved_at_ms T calculation_rule_id T adjustment_rule_id T authorized_roles_json T expected_tests_json B pack_digest T status",
    "population_imports": "T population_id T pack_id I cutoff_ms T inclusion_rules_json I expected_count I source_complete I imported_count I validated_count B validation_digest T status I created_at_ms I updated_at_ms",
    "population_items": "T population_id T item_id T display_label I owed_cents I due_at_ms T currency",
    "obligations": "T obligation_id T population_id T item_id T period_id T currency I owed_cents I due_at_ms I rule_version I revision I claimed_adjustment_cents I lawful_adjustment_cents I received_cash_cents I shortfall_cents I overage_cents I cash_satisfied I amount_satisfied I timely I reporting_complete T verification_status T case_status T delivery_status T current_evaluation_id I updated_at_ms",
    "evidence": "T evidence_id T item_id T kind T common_origin_id T source_id T source_version T local_ref I applicable_at_ms I event_at_ms I received_at_ms B content_digest B record_digest I amount_cents T reversal_of T supersedes",
    "payments": "T payment_id T obligation_id T item_id T evidence_id T common_origin_id I amount_cents I event_at_ms I active T reversed_by_evidence_id",
    "claimed_adjustments": "T claim_id T obligation_id T evidence_id I amount_cents T owner_role I deadline_ms T status I created_at_ms I updated_at_ms",
    "cases": "T case_id T obligation_id T reason T contractual_accountability T next_action_owner I due_at_ms T completion_conditions_json T status I updated_at_ms",
    "determinations": "T determination_id T obligation_id T claim_id T actor_id T actor_role T authority_id I authority_epoch B authority_digest T decision I amount_cents T supporting_evidence_json I expected_revision I resulting_revision I decided_at_ms B determination_digest T input_evaluation_id B input_evaluation_result_digest",
    "actions": "T action_id T obligation_id T determination_id T kind T status I revision T payload_json B payload_digest B idempotency_key I created_at_ms",
    "action_outbox": "T action_id T status I attempt B payload_digest T acknowledgment_ref I updated_at_ms",
    "financial_events": "I event_sequence B event_id T aggregate_type T aggregate_id T kind I before_revision I after_revision T payload_json B payload_digest B previous_head B head I committed_at_ms",
    "financial_conflicts": "T conflict_id T obligation_id T common_origin_id T existing_payment_id T candidate_evidence_id I existing_amount_cents I candidate_amount_cents T reason I visible_at_ms",
    "evaluations": "T evaluation_id T obligation_id I revision I rule_version T evidence_ids_json T authority_id I evaluated_at_ms I owed_cents I claimed_adjustment_cents I lawful_adjustment_cents I received_cash_cents I shortfall_cents I overage_cents I cash_satisfied I amount_satisfied I timely I reporting_complete T verification_status T case_status T delivery_status B result_digest T contract_version T scope_json T control_pack_id I control_pack_version B control_pack_digest I authority_epoch B authority_digest T evidence_bindings_json T input_snapshot_json B input_snapshot_digest B receipt_digest",
    "program_funding_receipts": "T receipt_id T state_id T deployment_id T program_id T period_id T currency T source_record_ref I amount_cents T confirmation_class T evidence_status I event_at_ms I recorded_at_ms T supersedes_receipt_id B receipt_digest",
    "program_funding_projection": "T source_record_ref T receipt_id I amount_cents I event_at_ms I revision B receipt_digest",
    "population_manifests": "T manifest_id T contract I manifest_version T state_id T deployment_id T program_id T period_id T currency T pack_id I cutoff_ms T inclusion_rules_json T source_owner_id T authority_id I authority_epoch B authority_digest T approved_by T approval_ref T source_id T source_version B source_digest I member_count B member_digest T supersedes_manifest_id B supersedes_digest B manifest_digest I registered_at_ms",
    "population_manifest_members": "T manifest_id I position T member_id",
    "population_manifest_heads": "T state_id T deployment_id T program_id T period_id T currency T pack_id I cutoff_ms T source_owner_id T manifest_id I manifest_version B manifest_digest I updated_at_ms",
    "population_manifest_bindings": "T population_id T manifest_id I manifest_version B manifest_digest",
}


def _parse_field_spec(spec: str) -> tuple[tuple[str, str], ...]:
    parts = spec.split()
    if len(parts) % 2:
        raise RuntimeError("invalid_static_table_contract")
    pairs = tuple((parts[index + 1], parts[index]) for index in range(0, len(parts), 2))
    if len({column for column, _kind in pairs}) != len(pairs):
        raise RuntimeError("invalid_static_table_contract")
    return pairs


TABLE_SPECS = {table: _parse_field_spec(spec) for table, spec in _FIELD_SPEC_TEXT.items()}
TABLE_NAMES = frozenset(TABLE_SPECS)
PRIMARY_KEYS = {
    "financial_identity": ("id",),
    "financial_meta": ("id",),
    "control_packs": ("pack_id",),
    "population_imports": ("population_id",),
    "population_items": ("population_id", "item_id"),
    "obligations": ("obligation_id",),
    "evidence": ("evidence_id",),
    "payments": ("payment_id",),
    "claimed_adjustments": ("claim_id",),
    "cases": ("case_id",),
    "determinations": ("determination_id",),
    "actions": ("action_id",),
    "action_outbox": ("action_id",),
    "financial_events": ("event_sequence",),
    "financial_conflicts": ("conflict_id",),
    "evaluations": ("evaluation_id",),
    "program_funding_receipts": ("receipt_id",),
    "program_funding_projection": ("source_record_ref",),
    "population_manifests": ("manifest_id",),
    "population_manifest_members": ("manifest_id", "position"),
    "population_manifest_heads": (
        "state_id", "deployment_id", "program_id", "period_id",
        "pack_id", "cutoff_ms", "source_owner_id",
    ),
    "population_manifest_bindings": ("population_id",),
}
EVENT_KINDS = {
    "CONTROL_PACK": {"CONTROL_PACK_PUBLISHED"},
    "POPULATION": {
        "POPULATION_STAGED",
        "POPULATION_SOURCE_COMPLETED",
        "POPULATION_VALIDATED",
        "POPULATION_PUBLISHED",
    },
    "POPULATION_MANIFEST": {
        "POPULATION_MANIFEST_REGISTERED",
        "POPULATION_MANIFEST_SUPERSEDED",
    },
    "PROGRAM_FUNDING_RECEIPT": {
        "FUNDING_RECEIPT_RECORDED",
        "FUNDING_RECEIPT_SUPERSEDED",
    },
    "OBLIGATION": {
        "SUPPORT_EVIDENCE_RECORDED",
        "PAYMENT_RECEIVED",
        "PAYMENT_DUPLICATE_EVIDENCE",
        "PAYMENT_CONFLICT_VISIBLE",
        "PAYMENT_REVERSED",
        "OFFSET_CLAIMED",
        "OFFSET_AUTHORIZED",
        "OFFSET_REJECTED_CORRECTION_AUTHORIZED",
        "ACTION_ACKNOWLEDGED",
        "REPORTING_EVIDENCE_RECORDED",
        "REPORTING_CORRECTION_RECORDED",
        "EVALUATION_RECORDED",
    },
}
CASE_STATUSES = {"OPEN", "AUTHORIZED", "CORRECTION_REQUIRED", "ACTIONED", "RESOLVED"}
ACTION_STATUSES = {"READY", "ACKNOWLEDGED", "CANCELLED"}
ACTION_KINDS = {"OFFSET_AUTHORIZATION", "CORRECTION_PAYMENT_REQUEST"}
CLAIM_STATUSES = {"CLAIMED", "AUTHORIZED", "REJECTED"}
CASE_COMPLETION_CONDITIONS = {
    "amount_satisfied": True,
    "delivery_acknowledged_or_not_required": True,
    "reporting_complete": True,
}


class ContinuityError(ValueError):
    """Stable, bounded rejection code suitable for a recipient CLI."""

    def __init__(self, code: str, exit_code: int = 4) -> None:
        self.code = code
        self.exit_code = exit_code
        super().__init__(code)


def _reject(code: str, exit_code: int = 4) -> None:
    raise ContinuityError(code, exit_code)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _reject("canonical_json")


def _digest(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes:
            _reject("digest_part")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            _reject("json_duplicate_key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    _reject("json_nonfinite")


def _check_json_tree(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [500_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 64:
        _reject("json_complexity")
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                _reject("json_key")
            _check_json_tree(child, depth=depth + 1, budget=budget)
    elif type(value) is list:
        for child in value:
            _check_json_tree(child, depth=depth + 1, budget=budget)


def _parse_json_text(raw: str, code: str) -> Any:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except ContinuityError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        _reject(code)
    _check_json_tree(value)
    return value


def _decode_package(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_PACKAGE_BYTES:
        _reject("package_size")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        _reject("package_ascii")
    value = _parse_json_text(text, "package_json")
    if type(value) is not dict:
        _reject("package_object")
    if _canonical(value) != raw:
        _reject("package_noncanonical")
    return value


def _decode_cell(value: Any, code: str) -> Any:
    if type(value) is dict:
        if set(value) != {"hex"} or type(value["hex"]) is not str:
            _reject(code)
        encoded = value["hex"]
        if len(encoded) % 2 or re.fullmatch(r"[0-9A-Fa-f]*", encoded, re.ASCII) is None:
            _reject(code)
        try:
            return bytes.fromhex(encoded)
        except ValueError:
            _reject(code)
    if value is None or type(value) in {str, int, float, bool}:
        if type(value) is float and not math.isfinite(value):
            _reject(code)
        return value
    _reject(code)


def _decode_tables(value: Any) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    if type(value) is not dict or set(value) != TABLE_NAMES:
        _reject("table_set")
    decoded: dict[str, list[dict[str, Any]]] = {}
    counts: dict[str, int] = {}
    for table in sorted(TABLE_NAMES):
        raw_rows = value[table]
        if type(raw_rows) is not list or len(raw_rows) > MAX_ROWS:
            _reject("table_rows")
        specs = TABLE_SPECS[table]
        expected_columns = {column for column, _kind in specs}
        rows: list[dict[str, Any]] = []
        keys: set[tuple[Any, ...]] = set()
        for raw_row in raw_rows:
            if type(raw_row) is not dict or set(raw_row) != expected_columns:
                _reject("table_row_shape")
            row: dict[str, Any] = {}
            for column, declared_type in specs:
                item = _decode_cell(raw_row[column], "table_cell")
                if item is not None:
                    if declared_type == "I" and type(item) is not int:
                        _reject("table_cell_type")
                    if declared_type == "T" and type(item) is not str:
                        _reject("table_cell_type")
                    if declared_type == "B" and type(item) is not bytes:
                        _reject("table_cell_type")
                row[column] = item
            key = tuple(row[column] for column in PRIMARY_KEYS[table])
            if any(item is None for item in key) or key in keys:
                _reject("table_primary_key")
            keys.add(key)
            rows.append(row)
        decoded[table] = rows
        counts[table] = len(rows)
    return decoded, counts


def _id(value: Any, code: str) -> str:
    if type(value) is not str or ID_PATTERN.fullmatch(value) is None:
        _reject(code)
    return value


def _text(value: Any, code: str, *, max_bytes: int = 512) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _reject(code)
    try:
        if len(value.encode("utf-8")) > max_bytes:
            _reject(code)
    except UnicodeEncodeError:
        _reject(code)
    return value


def _kind(value: Any, code: str) -> str:
    if type(value) is not str or KIND_PATTERN.fullmatch(value) is None:
        _reject(code)
    return value


def _integer(value: Any, code: str, *, minimum: int = 0, maximum: int = MAX_CENTS) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(code)
    return value


def _time(value: Any, code: str) -> int:
    return _integer(value, code, maximum=MAX_CENTS)


def _flag(value: Any, code: str) -> int:
    if type(value) is not int or value not in {0, 1}:
        _reject(code)
    return value


def _blob64(value: Any, code: str) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        _reject(code)
    return value


def _hex_digest(value: Any, code: str) -> bytes:
    if type(value) is bytes:
        return _blob64(value, code)
    if type(value) is not str or HEX128.fullmatch(value) is None:
        _reject(code)
    try:
        return bytes.fromhex(value)
    except ValueError:
        _reject(code)


def _inner_json(raw: Any, code: str) -> Any:
    if type(raw) is not str:
        _reject(code)
    value = _parse_json_text(raw, code)
    try:
        encoded = raw.encode("ascii")
    except UnicodeEncodeError:
        _reject(code)
    if encoded != _canonical(value):
        _reject(f"{code}_noncanonical")
    return value


def _digest_hex(raw: Any, code: str) -> str:
    return _blob64(raw, code).hex().upper()


def _verify_identity(
    row: Mapping[str, Any],
    *,
    authority_digest: bytes,
    scope: Mapping[str, Any],
    mode: str,
    owner_id: str,
    sequence: int,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    if row["id"] != 1 or row["schema_version"] != 7:
        _reject("identity_schema")
    provenance = row["provenance"]
    bound_mode = row["bound_mode"]
    bound_owner_id = _id(row["bound_owner_id"], "identity_owner")
    if provenance not in {"ROOT", "CONTINUITY_RESTORE"} or bound_mode not in {"LIVE", "SHADOW", "TEST"}:
        _reject("identity_contract")
    if (bound_mode, bound_owner_id) != (mode, owner_id):
        _reject("identity_binding")
    if provenance == "CONTINUITY_RESTORE":
        if bound_mode == "LIVE":
            _reject("identity_restore_live")
        expected_owner = SHADOW_OWNER_ID if bound_mode == "SHADOW" else TEST_OWNER_ID
        if bound_owner_id != expected_owner:
            _reject("identity_restore_owner")
    anchor_sequence = _integer(row["anchor_sequence"], "identity_anchor", maximum=MAX_ROWS)
    anchor_head = _blob64(row["anchor_head"], "identity_anchor_head")
    genesis_head = _blob64(row["genesis_head"], "identity_genesis_head")
    source_digest = _blob64(row["source_package_digest"], "identity_source_digest")
    identity_digest = _blob64(row["identity_digest"], "identity_digest")
    expected_identity_digest = _digest(
        IDENTITY_DOMAIN,
        _canonical(
            {
                "anchor_sequence": anchor_sequence,
                "bound_mode": bound_mode,
                "bound_owner_id": bound_owner_id,
                "provenance": provenance,
                "source_package_digest": source_digest.hex().upper(),
            }
        ),
    )
    if identity_digest != expected_identity_digest:
        _reject("identity_digest")
    if provenance == "ROOT":
        expected_genesis = _digest(
            GENESIS_DOMAIN,
            _canonical(dict(scope)),
            authority_digest,
            identity_digest,
        )
        if (
            source_digest != ZERO_DIGEST
            or anchor_sequence != 0
            or anchor_head != expected_genesis
            or genesis_head != expected_genesis
        ):
            _reject("identity_genesis")
    else:
        if source_digest == ZERO_DIGEST or anchor_sequence > sequence:
            _reject("identity_anchor")
        if anchor_sequence == 0:
            if anchor_head != genesis_head:
                _reject("identity_anchor")
        else:
            anchor_row = next((event for event in events if event["event_sequence"] == anchor_sequence), None)
            if anchor_row is None or anchor_row["head"] != anchor_head:
                _reject("identity_history_anchor")
    return {
        "provenance": provenance,
        "bound_mode": bound_mode,
        "bound_owner_id": bound_owner_id,
        "anchor_sequence": anchor_sequence,
        "anchor_head": anchor_head,
        "genesis_head": genesis_head,
        "source_package_digest": source_digest,
        "identity_digest": identity_digest,
    }


def _verify_events(
    rows: list[dict[str, Any]],
    *,
    identity_row: Mapping[str, Any],
    sequence: int,
    expected_head: bytes,
) -> list[dict[str, Any]]:
    if len(rows) != sequence or len(rows) > MAX_ROWS:
        _reject("history_sequence_count")
    previous = _blob64(identity_row["genesis_head"], "identity_genesis_head")
    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        if row["event_sequence"] != index:
            _reject("history_sequence")
        event_id = _blob64(row["event_id"], "history_event_id")
        aggregate_type = _kind(row["aggregate_type"], "history_aggregate_type")
        aggregate_id = _id(row["aggregate_id"], "history_aggregate_id")
        kind = _kind(row["kind"], "history_kind")
        if aggregate_type not in EVENT_KINDS or kind not in EVENT_KINDS[aggregate_type]:
            _reject("history_event_kind")
        before = _integer(row["before_revision"], "history_before")
        after = _integer(row["after_revision"], "history_after")
        if after < before:
            _reject("history_revision_order")
        committed = _time(row["committed_at_ms"], "history_time")
        payload = _inner_json(row["payload_json"], "history_payload_json")
        if type(payload) is not dict:
            _reject("history_payload_shape")
        try:
            payload_bytes = row["payload_json"].encode("ascii")
        except UnicodeEncodeError:
            _reject("history_payload_ascii")
        canonical_payload = _canonical(payload)
        if payload_bytes != canonical_payload:
            _reject("history_payload_noncanonical")
        payload_digest = _blob64(row["payload_digest"], "history_payload_digest")
        if payload_digest != _digest(EVENT_DOMAIN, payload_bytes):
            _reject("history_payload_digest")
        header = b"".join(value.to_bytes(8, "big") for value in (before, after, committed))
        expected_event_id = _digest(
            EVENT_DOMAIN,
            index.to_bytes(8, "big"),
            aggregate_type.encode("ascii"),
            aggregate_id.encode("ascii"),
            kind.encode("ascii"),
            header,
            payload_digest,
        )
        if event_id != expected_event_id:
            _reject("history_event_id")
        previous_head = _blob64(row["previous_head"], "history_previous_head")
        head = _blob64(row["head"], "history_head")
        if previous_head != previous:
            _reject("history_predecessor")
        if head != _digest(HEAD_DOMAIN, previous_head, event_id, header, payload_digest):
            _reject("history_head")
        previous = head
        events.append({**row, "payload": payload})
    if previous != expected_head:
        _reject("history_meta_head")
    anchor = _integer(identity_row["anchor_sequence"], "identity_anchor", maximum=MAX_ROWS)
    if anchor > 0 and (anchor > len(events) or events[anchor - 1]["head"] != identity_row["anchor_head"]):
        _reject("identity_history_anchor")
    return events


def _values_json(raw: Any, code: str) -> list[Any]:
    value = _inner_json(raw, code)
    if type(value) is not dict or set(value) != {"values"} or type(value["values"]) is not list:
        _reject(code)
    return value["values"]


def _check_population_item_identity(
    item_populations: dict[str, set[str]],
    *,
    item_id: str,
    population_id: str,
    population_status: str,
    populations: Mapping[str, Mapping[str, Any]],
) -> None:
    previous = item_populations.get(item_id, set())
    if population_id in previous or (
        population_status == "PUBLISHED"
        and any(populations[old_id]["status"] == "PUBLISHED" for old_id in previous)
    ):
        _reject("population_item_duplicate")
    item_populations.setdefault(item_id, set()).add(population_id)


def _verify_manifests_and_populations(
    tables: Mapping[str, list[dict[str, Any]]],
    events: list[dict[str, Any]],
    *,
    scope: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    manifest_rows = tables["population_manifests"]
    member_rows = tables["population_manifest_members"]
    head_rows = tables["population_manifest_heads"]
    binding_rows = tables["population_manifest_bindings"]
    population_rows = tables["population_imports"]
    item_rows = tables["population_items"]
    packs = {row["pack_id"]: row for row in tables["control_packs"]}
    manifests = {row["manifest_id"]: row for row in manifest_rows}
    if len(manifests) != len(manifest_rows):
        _reject("manifest_duplicate")
    positions: dict[str, dict[int, str]] = {manifest_id: {} for manifest_id in manifests}
    for row in member_rows:
        manifest_id = _id(row["manifest_id"], "manifest_member_id")
        position = _integer(row["position"], "manifest_member_position", maximum=MAX_ROWS)
        member_id = _id(row["member_id"], "manifest_member_value")
        if manifest_id not in manifests or position in positions[manifest_id]:
            _reject("manifest_member_reference")
        positions[manifest_id][position] = member_id

    events_by_manifest: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["aggregate_type"] == "POPULATION_MANIFEST":
            manifest_id = _id(event["aggregate_id"], "manifest_event_id")
            if manifest_id in events_by_manifest:
                _reject("manifest_event_duplicate")
            events_by_manifest[manifest_id] = event

    members_by_manifest: dict[str, tuple[str, ...]] = {}
    event_sequences: dict[str, int] = {}
    source_keys: dict[tuple[Any, ...], dict[int, str]] = {}
    children: dict[str, str] = {}
    for manifest_id, row in manifests.items():
        if row["contract"] != MANIFEST_CONTRACT:
            _reject("manifest_contract")
        version = _integer(row["manifest_version"], "manifest_version", minimum=1, maximum=MAX_ROWS)
        manifest_scope = {
            "state_id": _id(row["state_id"], "manifest_state"),
            "deployment_id": _id(row["deployment_id"], "manifest_deployment"),
            "program_id": _id(row["program_id"], "manifest_program"),
            "period_id": _id(row["period_id"], "manifest_period"),
            "currency": row["currency"],
        }
        if manifest_scope != dict(scope) or manifest_scope["currency"] != "USD":
            _reject("manifest_scope")
        pack_id = _id(row["pack_id"], "manifest_pack")
        pack = packs.get(pack_id)
        if pack is None or pack["status"] != "APPROVED":
            _reject("manifest_pack")
        if any(pack[key] != manifest_scope[key] for key in ("state_id", "deployment_id", "program_id", "period_id")):
            _reject("manifest_pack_scope")
        cutoff = _time(row["cutoff_ms"], "manifest_cutoff")
        if not _time(pack["effective_start_ms"], "manifest_pack_start") <= cutoff < _time(pack["effective_end_ms"], "manifest_pack_end"):
            _reject("manifest_pack_cutoff")
        rules = _values_json(row["inclusion_rules_json"], "manifest_rules")
        if not rules or any(type(rule) is not str or not rule for rule in rules):
            _reject("manifest_rules")
        source_owner = _id(row["source_owner_id"], "manifest_source_owner")
        if (
            row["authority_id"] != authority["authority_id"]
            or row["authority_epoch"] != authority["epoch"]
            or row["authority_digest"] != bytes.fromhex(authority["digest"])
        ):
            _reject("manifest_authority_binding")
        _id(row["approved_by"], "manifest_approved_by")
        _id(row["approval_ref"], "manifest_approval_ref")
        _id(row["source_id"], "manifest_source_id")
        if type(row["source_version"]) is not str or not row["source_version"]:
            _reject("manifest_source_version")
        _blob64(row["source_digest"], "manifest_source_digest")
        member_count = _integer(row["member_count"], "manifest_member_count", minimum=1, maximum=MAX_ROWS)
        indexed = positions[manifest_id]
        if sorted(indexed) != list(range(member_count)):
            _reject("manifest_member_positions")
        member_ids = tuple(indexed[position] for position in range(member_count))
        if tuple(sorted(set(member_ids))) != member_ids:
            _reject("manifest_member_order")
        member_digest = _blob64(row["member_digest"], "manifest_member_digest")
        if member_digest != _digest(
            POPULATION_MANIFEST_MEMBERS_DOMAIN,
            _canonical({"member_ids": list(member_ids)}),
        ):
            _reject("manifest_member_digest")
        parent_id = row["supersedes_manifest_id"]
        parent_digest_value = row["supersedes_digest"]
        if (parent_id is None) != (parent_digest_value is None):
            _reject("manifest_parent_binding")
        parent_digest = None if parent_digest_value is None else _blob64(parent_digest_value, "manifest_parent_digest")
        source_key = (
            manifest_scope["state_id"],
            manifest_scope["deployment_id"],
            manifest_scope["program_id"],
            manifest_scope["period_id"],
            manifest_scope["currency"],
            pack_id,
            cutoff,
            source_owner,
        )
        versions = source_keys.setdefault(source_key, {})
        if version in versions:
            _reject("manifest_version_duplicate")
        versions[version] = manifest_id
        if version == 1:
            if parent_id is not None:
                _reject("manifest_root_parent")
        else:
            parent_id = _id(parent_id, "manifest_parent")
            parent = manifests.get(parent_id)
            if parent is None:
                _reject("manifest_parent_missing")
            parent_version = _integer(parent["manifest_version"], "manifest_parent_version", minimum=1, maximum=MAX_ROWS)
            parent_key = (
                parent["state_id"], parent["deployment_id"], parent["program_id"], parent["period_id"],
                parent["currency"], parent["pack_id"], parent["cutoff_ms"], parent["source_owner_id"],
            )
            if (
                parent_key != source_key
                or parent_version + 1 != version
                or _blob64(parent["manifest_digest"], "manifest_parent_digest") != parent_digest
            ):
                _reject("manifest_parent_binding")
            if parent_id in children:
                _reject("manifest_fork")
            children[parent_id] = manifest_id

        body = {
            "contract": MANIFEST_CONTRACT,
            "manifest_id": manifest_id,
            "manifest_version": version,
            "scope": manifest_scope,
            "pack_id": pack_id,
            "cutoff_ms": cutoff,
            "inclusion_rules": rules,
            "source_owner_id": source_owner,
            "authority": {
                "authority_id": authority["authority_id"],
                "epoch": authority["epoch"],
                "digest": authority["digest"].upper(),
            },
            "approved_by": row["approved_by"],
            "approval_ref": row["approval_ref"],
            "source": {
                "source_id": row["source_id"],
                "version": row["source_version"],
                "digest": row["source_digest"].hex().upper(),
            },
            "member_count": member_count,
            "member_ids": list(member_ids),
            "member_digest": member_digest.hex().upper(),
            "supersedes": None if parent_id is None else {
                "manifest_id": parent_id,
                "digest": parent_digest.hex().upper(),
            },
        }
        manifest_digest = _blob64(row["manifest_digest"], "manifest_digest")
        if manifest_digest != _digest(POPULATION_MANIFEST_DOMAIN, _canonical(body)):
            _reject("manifest_digest")
        registered_at = _time(row["registered_at_ms"], "manifest_registered_at")
        members_by_manifest[manifest_id] = member_ids

        event = events_by_manifest.get(manifest_id)
        if event is None:
            _reject("manifest_event_missing")
        event_sequence = _integer(event["event_sequence"], "manifest_event_sequence", minimum=1, maximum=MAX_ROWS)
        event_sequences[manifest_id] = event_sequence
        if parent_id is not None:
            parent_event = events_by_manifest.get(parent_id)
            if parent_event is None or event_sequence <= parent_event["event_sequence"]:
                _reject("manifest_event_lineage")
        expected_kind = "POPULATION_MANIFEST_REGISTERED" if version == 1 else "POPULATION_MANIFEST_SUPERSEDED"
        expected_payload = {
            "contract": MANIFEST_CONTRACT,
            "manifest_id": manifest_id,
            "manifest_version": version,
            "manifest_digest": manifest_digest.hex().upper(),
            "member_digest": member_digest.hex().upper(),
            "member_count": member_count,
            "supersedes_manifest_id": parent_id,
            "supersedes_digest": None if parent_digest is None else parent_digest.hex().upper(),
        }
        if (
            event["kind"] != expected_kind
            or event["before_revision"] != (0 if version == 1 else version - 1)
            or event["after_revision"] != version
            or event["committed_at_ms"] != registered_at
            or _canonical(event["payload"]) != _canonical(expected_payload)
        ):
            _reject("manifest_event_binding")

    if set(events_by_manifest) != set(manifests):
        _reject("manifest_event_cardinality")
    expected_heads: dict[tuple[Any, ...], tuple[str, Mapping[str, Any]]] = {}
    for source_key, version_map in source_keys.items():
        versions = sorted(version_map)
        if versions != list(range(1, max(versions) + 1)):
            _reject("manifest_version_sequence")
        leaves = set(version_map.values()) - {parent_id for parent_id in children if parent_id in version_map.values()}
        if len(leaves) != 1:
            _reject("manifest_head_lineage")
        head_id = next(iter(leaves))
        expected_heads[source_key] = (head_id, manifests[head_id])

    actual_heads: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in head_rows:
        key = (
            _id(row["state_id"], "manifest_head_state"),
            _id(row["deployment_id"], "manifest_head_deployment"),
            _id(row["program_id"], "manifest_head_program"),
            _id(row["period_id"], "manifest_head_period"),
            row["currency"],
            _id(row["pack_id"], "manifest_head_pack"),
            _time(row["cutoff_ms"], "manifest_head_cutoff"),
            _id(row["source_owner_id"], "manifest_head_owner"),
        )
        if key in actual_heads:
            _reject("manifest_head_duplicate")
        actual_heads[key] = row
    if set(actual_heads) != set(expected_heads):
        _reject("manifest_head_cardinality")
    for key, (manifest_id, expected_row) in expected_heads.items():
        actual = actual_heads[key]
        if (
            actual["manifest_id"] != manifest_id
            or actual["manifest_version"] != expected_row["manifest_version"]
            or actual["manifest_digest"] != expected_row["manifest_digest"]
            or actual["updated_at_ms"] != expected_row["registered_at_ms"]
        ):
            _reject("manifest_head_binding")

    bindings: dict[str, dict[str, Any]] = {}
    bound_manifests: set[str] = set()
    for row in binding_rows:
        population_id = _id(row["population_id"], "population_binding_population")
        manifest_id = _id(row["manifest_id"], "population_binding_manifest")
        manifest = manifests.get(manifest_id)
        if (
            population_id in bindings
            or manifest is None
            or manifest_id in bound_manifests
            or row["manifest_version"] != manifest["manifest_version"]
            or row["manifest_digest"] != manifest["manifest_digest"]
        ):
            _reject("population_manifest_binding")
        bindings[population_id] = row
        bound_manifests.add(manifest_id)
    imports = {row["population_id"]: row for row in population_rows}
    if len(imports) != len(population_rows) or set(bindings) != set(imports):
        _reject("population_binding_set")

    items_by_population: dict[str, set[str]] = {}
    item_rows_by_population: dict[str, list[dict[str, Any]]] = {}
    item_to_populations: dict[str, set[str]] = {}
    for row in item_rows:
        population_id = _id(row["population_id"], "population_item_population")
        item_id = _id(row["item_id"], "population_item_id")
        population = imports.get(population_id)
        if population is None:
            _reject("population_item_reference")
        _check_population_item_identity(
            item_to_populations,
            item_id=item_id,
            population_id=population_id,
            population_status=population["status"],
            populations=imports,
        )
        if item_id in items_by_population.setdefault(population_id, set()):
            _reject("population_item_duplicate")
        items_by_population[population_id].add(item_id)
        item_rows_by_population.setdefault(population_id, []).append(row)
        if (
            type(row["display_label"]) is not str
            or len(row["display_label"].encode("utf-8")) > 128
            or _integer(row["owed_cents"], "population_item_owed", minimum=1, maximum=MAX_CENTS) < 1
            or row["currency"] != scope["currency"]
        ):
            _reject("population_item_value")
        _time(row["due_at_ms"], "population_item_due")

    population_views: list[dict[str, Any]] = []
    for population_id, population in imports.items():
        binding = bindings[population_id]
        manifest_id = str(binding["manifest_id"])
        manifest = manifests[manifest_id]
        member_ids = members_by_manifest[manifest_id]
        actual_members = items_by_population.get(population_id, set())
        expected_count = _integer(population["expected_count"], "population_expected", minimum=1, maximum=MAX_ROWS)
        imported_count = _integer(population["imported_count"], "population_imported", maximum=MAX_ROWS)
        validated_count = _integer(population["validated_count"], "population_validated", maximum=MAX_ROWS)
        source_complete = _flag(population["source_complete"], "population_source_complete")
        status = population["status"]
        if status not in {"STAGED", "VALIDATED", "PUBLISHED"}:
            _reject("population_status")
        if (
            population["pack_id"] != manifest["pack_id"]
            or population["cutoff_ms"] != manifest["cutoff_ms"]
            or _values_json(population["inclusion_rules_json"], "population_rules")
            != _values_json(manifest["inclusion_rules_json"], "manifest_rules")
            or expected_count != manifest["member_count"]
            or imported_count != len(actual_members)
            or imported_count > expected_count
            or validated_count > expected_count
            or not actual_members <= set(member_ids)
        ):
            _reject("population_manifest_binding")
        if source_complete == 1 and actual_members != set(member_ids):
            _reject("population_source_complete_members")
        if status in {"VALIDATED", "PUBLISHED"} and (
            source_complete != 1 or actual_members != set(member_ids)
            or validated_count != imported_count or imported_count != expected_count
        ):
            _reject("population_validated_members")
        created_at = _time(population["created_at_ms"], "population_created")
        updated_at = _time(population["updated_at_ms"], "population_updated")
        if updated_at < created_at:
            _reject("population_chronology")
        if status == "STAGED":
            if validated_count != 0 or population["validation_digest"] is not None:
                _reject("population_staged_validation")
        else:
            validation_digest = _blob64(population["validation_digest"], "population_validation_digest")
            material = b"".join(
                _digest(
                    EVIDENCE_DOMAIN,
                    _canonical({
                        "item_id": item["item_id"],
                        "display_label": item["display_label"],
                        "owed_cents": item["owed_cents"],
                        "due_at_ms": item["due_at_ms"],
                        "currency": item["currency"],
                    }),
                )
                for item in sorted(item_rows_by_population.get(population_id, []), key=lambda item: item["item_id"])
            )
            if validation_digest != _digest(EVIDENCE_DOMAIN, material):
                _reject("population_validation_digest")
        source_key = (
            manifest["state_id"], manifest["deployment_id"], manifest["program_id"],
            manifest["period_id"], manifest["currency"], manifest["pack_id"],
            manifest["cutoff_ms"], manifest["source_owner_id"],
        )
        if status == "PUBLISHED" and actual_heads[source_key]["manifest_id"] != manifest_id:
            _reject("population_manifest_stale")
        population_views.append({
            "population_id": population_id,
            "status": status,
            "source_complete": bool(source_complete),
            "expected_count": expected_count,
            "imported_count": imported_count,
            "manifest_version": manifest["manifest_version"],
            "manifest_member_count": len(member_ids),
        })

    return {
        "manifests": manifests,
        "members_by_manifest": members_by_manifest,
        "bindings": bindings,
        "heads": actual_heads,
        "event_sequences": event_sequences,
        "superseded_at": {parent: event_sequences[child] for parent, child in children.items()},
        "populations": imports,
        "population_items": item_rows_by_population,
        "population_views": population_views,
        "packs": packs,
    }


def _verify_population_history(events: list[dict[str, Any]], state: Mapping[str, Any]) -> None:
    populations = state["populations"]
    manifests = state["manifests"]
    bindings = state["bindings"]
    event_sequences = state["event_sequences"]
    superseded_at = state["superseded_at"]
    by_population: dict[str, list[dict[str, Any]]] = {key: [] for key in populations}
    for event in events:
        if event["aggregate_type"] == "POPULATION":
            population_id = event["aggregate_id"]
            if population_id not in populations:
                _reject("population_history_reference")
            by_population[population_id].append(event)
    for population_id, population in populations.items():
        expected = _integer(population["expected_count"], "population_history_expected", minimum=1, maximum=MAX_ROWS)
        manifest_id = str(bindings[population_id]["manifest_id"])
        manifest = manifests[manifest_id]
        manifest_sequence = event_sequences[manifest_id]
        stale_sequence = superseded_at.get(manifest_id)
        manifest_fields = {
            "manifest_id": manifest_id,
            "manifest_version": manifest["manifest_version"],
            "manifest_digest": manifest["manifest_digest"].hex().upper(),
            "member_digest": manifest["member_digest"].hex().upper(),
        }
        imported = 0
        source_completed = False
        validated = False
        published = False
        previous_time: int | None = None
        for event in by_population[population_id]:
            event_sequence = event["event_sequence"]
            if event_sequence <= manifest_sequence or (stale_sequence is not None and event_sequence >= stale_sequence):
                _reject("population_history_manifest_order")
            committed_at = event["committed_at_ms"]
            if previous_time is not None and committed_at < previous_time:
                _reject("population_history_chronology")
            previous_time = committed_at
            before = event["before_revision"]
            after = event["after_revision"]
            payload = event["payload"]
            kind = event["kind"]
            if kind == "POPULATION_STAGED":
                if source_completed or validated or published:
                    _reject("population_history_stage_order")
                expected_keys = {"population_id", "imported_count", "chunk_count"} | set(manifest_fields)
                if set(payload) != expected_keys or any(
                    _canonical(payload.get(key)) != _canonical(value)
                    for key, value in manifest_fields.items()
                ):
                    _reject("population_history_stage_payload")
                count = _integer(payload["imported_count"], "population_history_stage_count", maximum=MAX_ROWS)
                chunk_count = _integer(payload["chunk_count"], "population_history_chunk", minimum=1, maximum=MAX_ROWS)
                if payload["population_id"] != population_id or before != imported or after != count or count != imported + chunk_count or count > expected:
                    _reject("population_history_stage_revision")
                imported = count
                continue
            if kind == "POPULATION_SOURCE_COMPLETED":
                if source_completed or validated or published:
                    _reject("population_history_completion_order")
                expected_keys = {"population_id", "imported_count", "expected_count"} | set(manifest_fields)
                if set(payload) != expected_keys or any(
                    _canonical(payload.get(key)) != _canonical(value)
                    for key, value in manifest_fields.items()
                ):
                    _reject("population_history_completion_payload")
                count = _integer(payload["imported_count"], "population_history_completion_count", maximum=MAX_ROWS)
                declared = _integer(payload["expected_count"], "population_history_declared_expected", minimum=1, maximum=MAX_ROWS)
                if payload["population_id"] != population_id or before != 0 or after != count or population["source_complete"] != 1 or count != expected or declared != expected:
                    _reject("population_history_completion_binding")
                source_completed = True
                continue
            if kind == "POPULATION_VALIDATED":
                if not source_completed or validated or published:
                    _reject("population_history_validation_order")
                expected_keys = {"population_id", "validated_count", "validation_digest"} | set(manifest_fields)
                if set(payload) != expected_keys or any(
                    _canonical(payload.get(key)) != _canonical(value)
                    for key, value in manifest_fields.items()
                ):
                    _reject("population_history_validation_payload")
                count = _integer(payload["validated_count"], "population_history_validation_count", minimum=1, maximum=MAX_ROWS)
                if (
                    payload["population_id"] != population_id or before != 0 or after != count
                    or count != expected or count != imported
                    or population["status"] not in {"VALIDATED", "PUBLISHED"}
                    or population["validated_count"] != count
                    or _hex_digest(payload["validation_digest"], "population_history_validation_digest") != population["validation_digest"]
                ):
                    _reject("population_history_validation_binding")
                validated = True
                continue
            if kind == "POPULATION_PUBLISHED":
                if not validated or published:
                    _reject("population_history_publication_order")
                expected_keys = {
                    "population_id", "item_count", "pack_id", "pack_version",
                    "evaluation_count", "evaluation_binding_digest",
                } | set(manifest_fields)
                if set(payload) != expected_keys or any(
                    _canonical(payload.get(key)) != _canonical(value)
                    for key, value in manifest_fields.items()
                ):
                    _reject("population_history_publication_payload")
                item_count = _integer(payload["item_count"], "population_history_publication_count", minimum=1, maximum=MAX_ROWS)
                if (
                    payload["population_id"] != population_id or before != 0 or after != item_count
                    or item_count != expected or item_count != imported or population["status"] != "PUBLISHED"
                    or payload["pack_id"] != population["pack_id"]
                    or _integer(payload["pack_version"], "population_history_pack_version", minimum=1, maximum=MAX_ROWS)
                    != state["packs"][population["pack_id"]]["version"]
                ):
                    _reject("population_history_publication_binding")
                published = True
        persisted_imported = _integer(population["imported_count"], "population_history_imported", maximum=MAX_ROWS)
        if imported != persisted_imported:
            _reject("population_history_imported_binding")
        source_complete = _flag(population["source_complete"], "population_history_source_complete")
        if source_completed and imported != expected:
            _reject("population_history_completion_count")
        if (source_complete == 1) != source_completed:
            _reject("population_history_completion_presence")
        status = population["status"]
        if status == "STAGED" and (validated or published):
            _reject("population_history_status")
        if status == "VALIDATED" and (not validated or published):
            _reject("population_history_status")
        if status == "PUBLISHED" and (not validated or not published):
            _reject("population_history_status")


def _verify_program_funding(tables: Mapping[str, list[dict[str, Any]]], events: list[dict[str, Any]], scope: Mapping[str, Any]) -> dict[str, Any]:
    receipts: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[str]] = {}
    for row in tables["program_funding_receipts"]:
        receipt_id = _id(row["receipt_id"], "funding_receipt_id")
        if receipt_id in receipts:
            _reject("funding_receipt_duplicate")
        row_scope = {key: row[key] for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")}
        if row_scope != dict(scope) or row_scope["currency"] != "USD" or row_scope["period_id"] in {"PROGRAM", "ALL"}:
            _reject("funding_scope")
        source_ref = _id(row["source_record_ref"], "funding_source_ref")
        amount = _integer(row["amount_cents"], "funding_amount", minimum=1, maximum=MAX_CENTS)
        if row["confirmation_class"] != FUNDING_CLASS or row["evidence_status"] != FUNDING_STATUS:
            _reject("funding_unapproved_class")
        event_at = _time(row["event_at_ms"], "funding_event_at")
        recorded_at = _time(row["recorded_at_ms"], "funding_recorded_at")
        parent_id = None if row["supersedes_receipt_id"] is None else _id(row["supersedes_receipt_id"], "funding_parent")
        record = {
            "schema": FUNDING_CONTRACT, "receipt_id": receipt_id, **row_scope,
            "source_record_ref": source_ref, "amount_cents": amount,
            "confirmation_class": row["confirmation_class"], "evidence_status": row["evidence_status"],
            "event_at_ms": event_at, "supersedes_receipt_id": parent_id,
        }
        digest = _blob64(row["receipt_digest"], "funding_digest")
        if digest != _digest(PROGRAM_FUNDING_RECEIPT_DOMAIN, _canonical(record)):
            _reject("funding_digest")
        receipts[receipt_id] = {**record, "recorded_at_ms": recorded_at, "receipt_digest": digest}
        grouped.setdefault(source_ref, []).append(receipt_id)

    children: dict[str, str] = {}
    for receipt_id, receipt in receipts.items():
        parent_id = receipt["supersedes_receipt_id"]
        if parent_id is None:
            continue
        parent = receipts.get(parent_id)
        if parent is None or parent["source_record_ref"] != receipt["source_record_ref"]:
            _reject("funding_parent_binding")
        if receipt["recorded_at_ms"] < parent["recorded_at_ms"] or parent_id in children:
            _reject("funding_parent_order")
        children[parent_id] = receipt_id

    events_by_id: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["aggregate_type"] == "PROGRAM_FUNDING_RECEIPT":
            receipt_id = _id(event["aggregate_id"], "funding_event_id")
            if receipt_id in events_by_id:
                _reject("funding_event_duplicate")
            events_by_id[receipt_id] = event
    if set(events_by_id) != set(receipts):
        _reject("funding_event_cardinality")
    projection_rows = tables["program_funding_projection"]
    projections = {_id(row["source_record_ref"], "funding_projection_ref"): row for row in projection_rows}
    if len(projections) != len(projection_rows) or set(projections) != set(grouped):
        _reject("funding_projection_cardinality")

    leaves: list[tuple[str, dict[str, Any], int]] = []
    visited: set[str] = set()
    for source_ref, ids in grouped.items():
        roots = [receipt_id for receipt_id in ids if receipts[receipt_id]["supersedes_receipt_id"] is None]
        if len(roots) != 1:
            _reject("funding_lineage_root")
        receipt_id = roots[0]
        revision = 0
        prior_sequence = 0
        lineage_seen: set[str] = set()
        while True:
            if receipt_id in lineage_seen:
                _reject("funding_lineage_cycle")
            lineage_seen.add(receipt_id)
            visited.add(receipt_id)
            revision += 1
            receipt = receipts[receipt_id]
            event = events_by_id[receipt_id]
            expected_kind = "FUNDING_RECEIPT_SUPERSEDED" if receipt["supersedes_receipt_id"] is not None else "FUNDING_RECEIPT_RECORDED"
            if event["kind"] != expected_kind or event["before_revision"] != revision - 1 or event["after_revision"] != revision or event["committed_at_ms"] != receipt["recorded_at_ms"]:
                _reject("funding_event_binding")
            event_sequence = _integer(event["event_sequence"], "funding_event_sequence", minimum=1, maximum=MAX_ROWS)
            if event_sequence <= prior_sequence:
                _reject("funding_event_order")
            prior_sequence = event_sequence
            expected_payload = {key: value for key, value in receipt.items() if key != "receipt_digest"}
            expected_payload["receipt_digest"] = receipt["receipt_digest"].hex().upper()
            expected_payload["projection_revision"] = revision
            if _canonical(event["payload"]) != _canonical(expected_payload):
                _reject("funding_event_payload")
            child_id = children.get(receipt_id)
            if child_id is None:
                leaves.append((source_ref, receipt, revision))
                break
            if events_by_id[child_id]["event_sequence"] <= event_sequence:
                _reject("funding_event_lineage_order")
            receipt_id = child_id
        if len(lineage_seen) != len(ids):
            _reject("funding_lineage_disconnected")
    if visited != set(receipts):
        _reject("funding_lineage_unreachable")
    for source_ref, receipt, revision in leaves:
        projection = projections[source_ref]
        if (
            projection["receipt_id"] != receipt["receipt_id"]
            or projection["amount_cents"] != receipt["amount_cents"]
            or projection["event_at_ms"] != receipt["event_at_ms"]
            or projection["revision"] != revision
            or projection["receipt_digest"] != receipt["receipt_digest"]
        ):
            _reject("funding_projection_reconstruction")
    return {
        "current_receipt_count": len(leaves),
        "historical_receipt_count": len(receipts),
        "classification": FUNDING_STATUS,
        "cash_effect": "NOT_ASSERTED",
    }


def _evaluation_result(row: Mapping[str, Any], evidence_ids: list[str]) -> dict[str, Any]:
    return {
        "evaluation_id": row["evaluation_id"],
        "obligation_id": row["obligation_id"],
        "revision": row["revision"],
        "rule_version": row["rule_version"],
        "evidence_ids": evidence_ids,
        "authority_id": row["authority_id"],
        "evaluated_at_ms": row["evaluated_at_ms"],
        "owed_cents": row["owed_cents"],
        "claimed_adjustment_cents": row["claimed_adjustment_cents"],
        "lawful_adjustment_cents": row["lawful_adjustment_cents"],
        "received_cash_cents": row["received_cash_cents"],
        "shortfall_cents": row["shortfall_cents"],
        "overage_cents": row["overage_cents"],
        "cash_satisfied": row["cash_satisfied"],
        "amount_satisfied": row["amount_satisfied"],
        "timely": row["timely"],
        "reporting_complete": row["reporting_complete"],
        "verification_status": row["verification_status"],
        "case_status": row["case_status"],
        "delivery_status": row["delivery_status"],
    }


def _evaluation_bindings(row: Mapping[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    ids_value = _inner_json(row["evidence_ids_json"], "receipt_evidence_ids")
    if type(ids_value) is not dict or set(ids_value) != {"evidence_ids"} or type(ids_value["evidence_ids"]) is not list:
        _reject("receipt_evidence_ids")
    evidence_ids = [_id(value, "receipt_evidence_id") for value in ids_value["evidence_ids"]]
    if evidence_ids != sorted(evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
        _reject("receipt_evidence_order")
    binding_value = _inner_json(row["evidence_bindings_json"], "receipt_evidence_bindings")
    if type(binding_value) is not dict or set(binding_value) != {"bindings"} or type(binding_value["bindings"]) is not list:
        _reject("receipt_evidence_bindings")
    bindings: list[dict[str, str]] = []
    for binding in binding_value["bindings"]:
        if type(binding) is not dict or set(binding) != {"evidence_id", "record_digest"}:
            _reject("receipt_evidence_binding")
        bindings.append({
            "evidence_id": _id(binding["evidence_id"], "receipt_evidence_id"),
            "record_digest": _hex_digest(binding["record_digest"], "receipt_evidence_digest").hex().upper(),
        })
    if [binding["evidence_id"] for binding in bindings] != evidence_ids:
        _reject("receipt_evidence_binding_order")
    return evidence_ids, bindings


def _evaluation_binding_digest(bindings: list[dict[str, str]]) -> bytes:
    ordered = sorted(
        ({
            "evaluation_id": item["evaluation_id"],
            "input_snapshot_digest": item["input_snapshot_digest"],
            "result_digest": item["result_digest"],
            "receipt_digest": item["receipt_digest"],
        } for item in bindings),
        key=lambda item: item["evaluation_id"],
    )
    return _digest(EVALUATION_EVENT_DOMAIN, _canonical({"evaluations": ordered}))


def _items_by_population(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        result.setdefault(row["population_id"], []).append(row)
    return result


def _verify_evidence_records(tables: Mapping[str, list[dict[str, Any]]]) -> None:
    item_ids = {_id(row["item_id"], "evidence_population_item") for row in tables["population_items"]}
    obligation_item_ids = {
        _id(row["item_id"], "evidence_obligation_item") for row in tables["obligations"]
    }
    evidence_ids: set[str] = set()
    for row in tables["evidence"]:
        evidence_id = _id(row["evidence_id"], "evidence_id")
        if evidence_id in evidence_ids:
            _reject("evidence_duplicate")
        evidence_ids.add(evidence_id)
        item_id = _id(row["item_id"], "evidence_item")
        if item_id not in item_ids or item_id not in obligation_item_ids:
            _reject("evidence_item_binding")
        kind = _kind(row["kind"], "evidence_kind")
        common_origin_id = _id(row["common_origin_id"], "evidence_common_origin")
        source_id = _id(row["source_id"], "evidence_source")
        source_version = _id(row["source_version"], "evidence_source_version")
        local_ref = _id(row["local_ref"], "evidence_local_ref")
        applicable_at = _time(row["applicable_at_ms"], "evidence_applicable_at")
        event_at = _time(row["event_at_ms"], "evidence_event_at")
        received_at = _time(row["received_at_ms"], "evidence_received_at")
        if event_at > received_at:
            _reject("evidence_chronology")
        amount = row["amount_cents"]
        if amount is not None:
            amount = _integer(amount, "evidence_amount")
        reversal = None if row["reversal_of"] is None else _id(row["reversal_of"], "evidence_reversal")
        supersedes = None if row["supersedes"] is None else _id(row["supersedes"], "evidence_supersedes")
        content_digest = _blob64(row["content_digest"], "evidence_content_digest")
        record_digest = _blob64(row["record_digest"], "evidence_record_digest")
        expected_content_digest = _digest(
            EVIDENCE_DOMAIN,
            _canonical({
                "source_id": source_id,
                "source_version": source_version,
                "local_ref": local_ref,
                "common_origin_id": common_origin_id,
                "kind": kind,
            }),
        )
        if content_digest != expected_content_digest:
            _reject("evidence_content_digest")
        expected_record_digest = _digest(
            EVIDENCE_DOMAIN,
            _canonical({
                "evidence_id": evidence_id,
                "item_id": item_id,
                "kind": kind,
                "common_origin_id": common_origin_id,
                "source_id": source_id,
                "source_version": source_version,
                "local_ref": local_ref,
                "applicable_at_ms": applicable_at,
                "event_at_ms": event_at,
                "received_at_ms": received_at,
                "content_digest": content_digest.hex().upper(),
                "amount_cents": amount,
                "reversal_of": reversal,
                "supersedes": supersedes,
            }),
        )
        if record_digest != expected_record_digest:
            _reject("evidence_record_digest")


def _verify_evaluation_receipts(
    tables: Mapping[str, list[dict[str, Any]]],
    events: list[dict[str, Any]],
    *,
    scope: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    obligations = {row["obligation_id"]: row for row in tables["obligations"]}
    if len(obligations) != len(tables["obligations"]):
        _reject("obligation_duplicate")
    populations = {row["population_id"]: row for row in tables["population_imports"]}
    items_by_population = {
        population_id: {row["item_id"]: row for row in rows}
        for population_id, rows in _items_by_population(tables["population_items"]).items()
    }
    for obligation_id, obligation in obligations.items():
        population = populations.get(obligation["population_id"])
        if population is None or population["status"] != "PUBLISHED":
            _reject("obligation_population")
        item = items_by_population.get(obligation["population_id"], {}).get(obligation["item_id"])
        if (
            item is None
            or obligation["period_id"] != scope["period_id"]
            or obligation["currency"] != scope["currency"]
            or obligation["owed_cents"] != item["owed_cents"]
            or obligation["due_at_ms"] != item["due_at_ms"]
        ):
            _reject("obligation_population_member")

    packs = {row["pack_id"]: row for row in tables["control_packs"]}
    evidence = {row["evidence_id"]: row for row in tables["evidence"]}
    evaluations_by_id: dict[str, dict[str, Any]] = {}
    evaluations_by_obligation: dict[str, list[dict[str, Any]]] = {}
    for row in tables["evaluations"]:
        evaluation_id = _id(row["evaluation_id"], "receipt_evaluation_id")
        obligation_id = _id(row["obligation_id"], "receipt_obligation_id")
        obligation = obligations.get(obligation_id)
        if obligation is None or evaluation_id in evaluations_by_id:
            _reject("receipt_obligation_binding")
        revision = _integer(row["revision"], "receipt_revision", maximum=MAX_ROWS)
        if evaluation_id != f"evaluation:{obligation_id}:r{revision}":
            _reject("receipt_evaluation_id")
        scope_value = _inner_json(row["scope_json"], "receipt_scope")
        if type(scope_value) is not dict or scope_value != dict(scope):
            _reject("receipt_scope")
        if row["contract_version"] != RECEIPT_CONTRACT:
            _reject("receipt_contract")
        pack = packs.get(row["control_pack_id"])
        if pack is None or row["control_pack_version"] != pack["version"] or row["control_pack_digest"] != pack["pack_digest"]:
            _reject("receipt_control_pack")
        auth_digest = _blob64(row["authority_digest"], "receipt_authority_digest")
        if (
            row["authority_id"] != authority["authority_id"]
            or row["authority_epoch"] != authority["epoch"]
            or auth_digest != bytes.fromhex(authority["digest"])
        ):
            _reject("receipt_authority")
        evaluated_at = _time(row["evaluated_at_ms"], "receipt_evaluated_at")
        evidence_ids, bindings = _evaluation_bindings(row)
        for binding in bindings:
            evidence_row = evidence.get(binding["evidence_id"])
            if (
                evidence_row is None
                or evidence_row["item_id"] != obligation["item_id"]
                or binding["record_digest"] != _blob64(evidence_row["record_digest"], "receipt_evidence_record_digest").hex().upper()
            ):
                _reject("receipt_evidence_binding")
            if evidence_row["received_at_ms"] > evaluated_at:
                _reject("receipt_evidence_chronology")
        snapshot = _inner_json(row["input_snapshot_json"], "receipt_input_snapshot")
        if type(snapshot) is not dict:
            _reject("receipt_input_snapshot")
        input_digest = _blob64(row["input_snapshot_digest"], "receipt_input_digest")
        if input_digest != _digest(EVALUATION_INPUT_DOMAIN, _canonical(snapshot)):
            _reject("receipt_input_digest")
        result = _evaluation_result(row, evidence_ids)
        result_digest = _blob64(row["result_digest"], "receipt_result_digest")
        if result_digest != _digest(EVALUATION_RESULT_DOMAIN, _canonical(result)):
            _reject("receipt_result_digest")
        receipt_body = {
            "contract_version": RECEIPT_CONTRACT,
            "scope": dict(scope_value),
            "evaluation_id": evaluation_id,
            "obligation_id": obligation_id,
            "revision": revision,
            "control_pack": {
                "pack_id": pack["pack_id"],
                "version": pack["version"],
                "digest": _blob64(pack["pack_digest"], "receipt_pack_digest").hex().upper(),
            },
            "evidence_bindings": bindings,
            "input_snapshot_digest": input_digest.hex().upper(),
            "authority": {
                "authority_id": row["authority_id"],
                "epoch": row["authority_epoch"],
                "digest": auth_digest.hex().upper(),
            },
            **result,
            "result_digest": result_digest.hex().upper(),
        }
        receipt_digest = _blob64(row["receipt_digest"], "receipt_digest")
        if receipt_digest != _digest(EVALUATION_RECEIPT_DOMAIN, _canonical(receipt_body)):
            _reject("receipt_digest")
        evaluated = {
            **row,
            "input_snapshot_digest_hex": input_digest.hex().upper(),
            "result_digest_hex": result_digest.hex().upper(),
            "receipt_digest_hex": receipt_digest.hex().upper(),
            "receipt": {
                **receipt_body,
                "receipt_digest": receipt_digest.hex().upper(),
            },
        }
        evaluations_by_id[evaluation_id] = evaluated
        evaluations_by_obligation.setdefault(obligation_id, []).append(evaluated)

    for obligation_id, obligation in obligations.items():
        history = sorted(evaluations_by_obligation.get(obligation_id, []), key=lambda item: item["revision"])
        revision = _integer(obligation["revision"], "obligation_revision", maximum=MAX_ROWS)
        if [item["revision"] for item in history] != list(range(revision + 1)) or not history:
            _reject("receipt_revision_chain")
        if obligation["current_evaluation_id"] != history[-1]["evaluation_id"]:
            _reject("receipt_current_binding")

    population_bound: set[str] = set()
    recorded_events: set[str] = set()
    for event in events:
        payload = event["payload"]
        if event["aggregate_type"] == "POPULATION" and event["kind"] == "POPULATION_PUBLISHED":
            population_id = event["aggregate_id"]
            initial = [
                {
                    "evaluation_id": item["evaluation_id"],
                    "input_snapshot_digest": item["input_snapshot_digest_hex"],
                    "result_digest": item["result_digest_hex"],
                    "receipt_digest": item["receipt_digest_hex"],
                }
                for obligation_id, history in evaluations_by_obligation.items()
                if obligations[obligation_id]["population_id"] == population_id
                for item in history
                if item["revision"] == 0
            ]
            if (
                _integer(payload.get("evaluation_count"), "population_evaluation_count", maximum=MAX_ROWS)
                != len(initial)
                or _hex_digest(payload.get("evaluation_binding_digest"), "population_evaluation_binding_digest")
                != _evaluation_binding_digest(initial)
            ):
                _reject("receipt_population_binding")
            for item in initial:
                population_bound.add(item["evaluation_id"])
            continue
        if event["aggregate_type"] != "OBLIGATION":
            continue
        if event["kind"] == "EVALUATION_RECORDED" and "evaluation_id" not in payload:
            _reject("receipt_event_shape")
        if "evaluation_id" not in payload:
            continue
        # The owner appends receipt digests to every obligation event that
        # references an evaluation. Only EVALUATION_RECORDED creates a unique
        # receipt-history entry; acknowledgments and reporting events reuse it.
        required = {
            "evaluation_id",
            "evaluation_input_digest",
            "evaluation_result_digest",
            "evaluation_receipt_digest",
        }
        if not required <= set(payload):
            _reject("receipt_event_shape")
        evaluation_id = _id(payload["evaluation_id"], "receipt_event_id")
        item = evaluations_by_id.get(evaluation_id)
        if (
            item is None
            or item["obligation_id"] != event["aggregate_id"]
            or item["revision"] != event["after_revision"]
            or payload["evaluation_input_digest"] != item["input_snapshot_digest_hex"]
            or payload["evaluation_result_digest"] != item["result_digest_hex"]
            or payload["evaluation_receipt_digest"] != item["receipt_digest_hex"]
        ):
            _reject("receipt_event_binding")
        if event["kind"] == "EVALUATION_RECORDED":
            if evaluation_id in recorded_events:
                _reject("receipt_event_duplicate")
            recorded_events.add(evaluation_id)
    if population_bound | recorded_events != set(evaluations_by_id):
        _reject("receipt_event_missing")
    return evaluations_by_id, obligations


def _verify_population_publication_bindings(
    events: list[dict[str, Any]],
    state: Mapping[str, Any],
    obligations: Mapping[str, Mapping[str, Any]],
) -> None:
    for event in events:
        if event["aggregate_type"] != "POPULATION" or event["kind"] != "POPULATION_PUBLISHED":
            continue
        population = state["populations"][event["aggregate_id"]]
        payload = event["payload"]
        pack = state["packs"][population["pack_id"]]
        if (
            population["status"] != "PUBLISHED"
            or payload.get("pack_id") != population["pack_id"]
            or _integer(payload.get("pack_version"), "population_publication_pack_version", minimum=1, maximum=MAX_ROWS)
            != pack["version"]
        ):
            _reject("population_publication_pack")
        initial_count = sum(
            1 for row in obligations.values()
            if row["population_id"] == event["aggregate_id"]
        )
        if _integer(payload.get("evaluation_count"), "population_publication_evaluation_count", maximum=MAX_ROWS) != initial_count:
            _reject("population_publication_evaluations")


def _verify_action_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    action_id = _id(row["action_id"], "action_id")
    obligation_id = _id(row["obligation_id"], "action_obligation")
    determination_id = _id(row["determination_id"], "action_determination")
    kind = _kind(row["kind"], "action_kind")
    status = row["status"]
    if kind not in ACTION_KINDS or status not in ACTION_STATUSES:
        _reject("action_status_binding")
    revision = _integer(row["revision"], "action_revision", maximum=MAX_ROWS)
    payload = _inner_json(row["payload_json"], "action_payload_json")
    if type(payload) is not dict or set(payload) != {
        "action_id", "obligation_id", "determination_id", "kind", "claim_id",
        "amount_cents", "currency", "revision", "input_evaluation_id",
        "input_evaluation_result_digest", "dispatch",
    }:
        _reject("action_payload_shape")
    try:
        payload_bytes = row["payload_json"].encode("ascii")
    except UnicodeEncodeError:
        _reject("action_payload_ascii")
    if payload_bytes != _canonical(payload):
        _reject("action_payload_noncanonical")
    payload_input_digest = _hex_digest(
        payload["input_evaluation_result_digest"], "action_input_evaluation_digest"
    )
    payload_revision = _integer(payload["revision"], "action_payload_revision", maximum=MAX_ROWS)
    if (
        payload["action_id"] != action_id
        or payload["obligation_id"] != obligation_id
        or payload["determination_id"] != determination_id
        or payload["kind"] != kind
        or _id(payload["claim_id"], "action_claim_id") != payload["claim_id"]
        or _integer(payload["amount_cents"], "action_amount", minimum=1) < 1
        or payload["currency"] != "USD"
        or payload_revision != revision
        or _id(payload["input_evaluation_id"], "action_evaluation_id") != payload["input_evaluation_id"]
        or payload["input_evaluation_result_digest"] != payload_input_digest.hex().upper()
        or payload["dispatch"] != "SYNTHETIC_RECORD_ONLY"
    ):
        _reject("action_payload_binding")
    payload_digest = _blob64(row["payload_digest"], "action_payload_digest")
    if payload_digest != _digest(ACTION_DOMAIN, payload_bytes):
        _reject("action_payload_digest")
    if _blob64(row["idempotency_key"], "action_idempotency") != _digest(
        IDEMPOTENCY_DOMAIN, action_id.encode("ascii")
    ):
        _reject("action_idempotency")
    return payload


def _verify_action_outbox(
    tables: Mapping[str, list[dict[str, Any]]],
    evaluations: Mapping[str, Mapping[str, Any]],
    events: list[dict[str, Any]],
    *,
    scope: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> None:
    actions = {row["action_id"]: row for row in tables["actions"]}
    outbox = {row["action_id"]: row for row in tables["action_outbox"]}
    if len(actions) != len(tables["actions"]) or len(outbox) != len(tables["action_outbox"]):
        _reject("action_duplicate")
    if set(actions) != set(outbox):
        _reject("action_outbox_cardinality")
    obligations = {row["obligation_id"]: row for row in tables["obligations"]}
    claims = {row["claim_id"]: row for row in tables["claimed_adjustments"]}
    determinations = {row["determination_id"]: row for row in tables["determinations"]}
    if len(claims) != len(tables["claimed_adjustments"]) or len(determinations) != len(tables["determinations"]):
        _reject("action_determination_duplicate")
    populations = {row["population_id"]: row for row in tables["population_imports"]}
    packs = {row["pack_id"]: row for row in tables["control_packs"]}
    evidence = {row["evidence_id"]: row for row in tables["evidence"]}
    used_determinations: set[str] = set()
    used_evaluations: set[str] = set()
    action_details: dict[str, dict[str, Any]] = {}
    for action_id, action in actions.items():
        action_id = _id(action_id, "action_id")
        payload = _verify_action_payload(action)
        obligation_id = _id(action["obligation_id"], "action_obligation")
        obligation = obligations.get(obligation_id)
        determination_id = _id(action["determination_id"], "action_determination")
        determination = determinations.get(determination_id)
        if obligation is None or determination is None or determination["obligation_id"] != obligation_id:
            _reject("action_determination_binding")
        if determination_id in used_determinations or not determination_id.startswith("determination:"):
            _reject("action_determination_duplicate")
        expected_action_id = determination_id[len("determination:"):]
        if expected_action_id != action_id:
            _reject("action_determination_id")
        used_determinations.add(determination_id)

        decision = determination["decision"]
        if decision not in {"OFFSET_AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}:
            _reject("action_decision")
        kind = "OFFSET_AUTHORIZATION" if decision == "OFFSET_AUTHORIZED" else "CORRECTION_PAYMENT_REQUEST"
        if action["kind"] != kind:
            _reject("action_decision_binding")
        revision = _integer(action["revision"], "action_revision", maximum=MAX_ROWS)
        expected_revision = _integer(determination["expected_revision"], "action_expected_revision", maximum=MAX_ROWS)
        resulting_revision = _integer(determination["resulting_revision"], "action_resulting_revision", maximum=MAX_ROWS)
        if resulting_revision != expected_revision + 1 or revision != resulting_revision:
            _reject("action_revision_binding")

        claim_id = _id(determination["claim_id"], "action_claim_id")
        claim = claims.get(claim_id)
        amount = _integer(determination["amount_cents"], "action_amount", minimum=1)
        if (
            claim is None
            or claim["obligation_id"] != obligation_id
            or claim["amount_cents"] != amount
            or (decision == "OFFSET_AUTHORIZED" and claim["status"] != "AUTHORIZED")
            or (decision == "OFFSET_REJECTED_CORRECTION_AUTHORIZED" and claim["status"] != "REJECTED")
        ):
            _reject("action_claim_binding")
        claim_evidence = evidence.get(claim["evidence_id"])
        if (
            claim_evidence is None
            or claim_evidence["kind"] != "OFFSET_CLAIM"
            or claim_evidence["item_id"] != obligation["item_id"]
            or claim_evidence["common_origin_id"] != claim_id
            or claim_evidence["amount_cents"] != amount
        ):
            _reject("action_claim_evidence")

        evaluation_id = _id(determination["input_evaluation_id"], "action_evaluation_id")
        if evaluation_id in used_evaluations:
            _reject("action_evaluation_duplicate")
        used_evaluations.add(evaluation_id)
        evaluation = evaluations.get(evaluation_id)
        evaluation_digest = _blob64(
            determination["input_evaluation_result_digest"], "action_evaluation_digest"
        )
        if (
            evaluation is None
            or evaluation["obligation_id"] != obligation_id
            or evaluation["revision"] != expected_revision
            or evaluation["result_digest"] != evaluation_digest
        ):
            _reject("action_evaluation_binding")
        evaluation_ids, evaluation_bindings = _evaluation_bindings(evaluation)
        support = _inner_json(determination["supporting_evidence_json"], "action_supporting_evidence")
        if type(support) is not dict or set(support) != {"bindings"} or type(support["bindings"]) is not list:
            _reject("action_supporting_evidence")
        normalized_support: list[dict[str, str]] = []
        for binding in support["bindings"]:
            if type(binding) is not dict or set(binding) != {"evidence_id", "record_digest"}:
                _reject("action_supporting_evidence")
            normalized_support.append({
                "evidence_id": _id(binding["evidence_id"], "action_supporting_evidence_id"),
                "record_digest": _hex_digest(binding["record_digest"], "action_supporting_evidence_digest").hex().upper(),
            })
        support_ids = [binding["evidence_id"] for binding in normalized_support]
        if (
            normalized_support != evaluation_bindings
            or len(support_ids) != len(evaluation_ids)
            or claim["evidence_id"] not in support_ids
        ):
            _reject("action_supporting_evidence_binding")
        for binding in normalized_support:
            evidence_row = evidence.get(binding["evidence_id"])
            if (
                evidence_row is None
                or evidence_row["item_id"] != obligation["item_id"]
                or binding["record_digest"] != _blob64(evidence_row["record_digest"], "action_evidence_digest").hex().upper()
            ):
                _reject("action_supporting_evidence_binding")

        population = populations.get(obligation["population_id"])
        pack = None if population is None else packs.get(population["pack_id"])
        if pack is None:
            _reject("action_control_pack")
        actor_id = _id(determination["actor_id"], "action_actor")
        actor_role = _kind(determination["actor_role"], "action_actor_role")
        roles = _values_json(pack["authorized_roles_json"], "action_authorized_roles")
        if actor_role not in roles:
            _reject("action_actor_role")
        authority_id = _id(determination["authority_id"], "action_authority_id")
        authority_epoch = _integer(determination["authority_epoch"], "action_authority_epoch", minimum=1)
        authority_digest = _blob64(determination["authority_digest"], "action_authority_digest")
        if (
            authority_id != authority["authority_id"]
            or authority_epoch != authority["epoch"]
            or authority_digest.hex().upper() != authority["digest"]
        ):
            _reject("action_authority")
        decided_at = _time(determination["decided_at_ms"], "action_decided_at")
        if evaluation["evaluated_at_ms"] > decided_at:
            _reject("action_evaluation_chronology")

        determination_payload = {
            "action_id": action_id,
            "determination_id": determination_id,
            "obligation_id": obligation_id,
            "kind": kind,
            "claim_id": claim_id,
            "decision": decision,
            "amount_cents": amount,
            "input_evaluation_id": evaluation_id,
            "input_evaluation_result_digest": evaluation_digest.hex().upper(),
            "actor_id": actor_id,
            "actor_role": actor_role,
            "authority_id": authority_id,
            "authority_epoch": authority_epoch,
            "authority_digest": authority_digest.hex().upper(),
            "supporting_evidence": normalized_support,
            "expected_revision": expected_revision,
            "resulting_revision": resulting_revision,
            "decided_at_ms": decided_at,
        }
        if _blob64(determination["determination_digest"], "action_determination_digest") != _digest(
            ACTION_DOMAIN, _canonical(determination_payload)
        ):
            _reject("action_determination_digest")

        expected_payload = {
            "action_id": action_id,
            "obligation_id": obligation_id,
            "determination_id": determination_id,
            "kind": kind,
            "claim_id": claim_id,
            "amount_cents": amount,
            "currency": scope["currency"],
            "revision": resulting_revision,
            "input_evaluation_id": evaluation_id,
            "input_evaluation_result_digest": evaluation_digest.hex().upper(),
            "dispatch": "SYNTHETIC_RECORD_ONLY",
        }
        if payload != expected_payload:
            _reject("action_payload_determination_binding")
        if _time(action["created_at_ms"], "action_created_at") < decided_at:
            _reject("action_chronology")
        action_details[determination_id] = {
            "action_id": action_id,
            "obligation_id": obligation_id,
            "amount_cents": amount,
            "decision": decision,
            "revision": resulting_revision,
            "evaluation_id": evaluation_id,
            "decided_at_ms": decided_at,
        }

        box = outbox[action_id]
        status = action["status"]
        if status not in ACTION_STATUSES or box["status"] != status:
            _reject("action_status_binding")
        _integer(box["attempt"], "action_attempt", maximum=MAX_ROWS)
        if action["payload_digest"] != box["payload_digest"]:
            _reject("action_payload_binding")
        if _time(box["updated_at_ms"], "action_outbox_updated_at") < _time(action["created_at_ms"], "action_created_at"):
            _reject("action_outbox_chronology")
        acknowledgment = box["acknowledgment_ref"]
        if status == "READY" and acknowledgment is not None:
            _reject("action_ready_acknowledgment")
        if status == "ACKNOWLEDGED":
            _id(acknowledgment, "action_acknowledgment")
            if box["attempt"] < 1:
                _reject("action_acknowledgment_attempt")
    if set(used_determinations) != set(determinations):
        _reject("action_determination_cardinality")

    decision_events: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["aggregate_type"] != "OBLIGATION" or event["kind"] not in {
            "OFFSET_AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
        }:
            continue
        payload = event["payload"]
        determination_id = _id(payload.get("determination_id"), "action_event_determination")
        detail = action_details.get(determination_id)
        if detail is None or determination_id in decision_events:
            _reject("action_event_determination")
        expected_event_kind = (
            "OFFSET_AUTHORIZED"
            if detail["decision"] == "OFFSET_AUTHORIZED"
            else "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
        )
        resulting_evaluation = next((
            item for item in evaluations.values()
            if item["obligation_id"] == detail["obligation_id"]
            and item["revision"] == detail["revision"]
        ), None)
        if resulting_evaluation is None:
            _reject("action_event_evaluation")
        if (
            event["kind"] != expected_event_kind
            or event["aggregate_id"] != detail["obligation_id"]
            or event["before_revision"] + 1 != event["after_revision"]
            or event["after_revision"] != detail["revision"]
            or event["committed_at_ms"] != detail["decided_at_ms"]
            or _canonical(payload) != _canonical({
                "determination_id": determination_id,
                "action_id": detail["action_id"],
                "amount_cents": detail["amount_cents"],
                "evaluation_id": resulting_evaluation["evaluation_id"],
            })
        ):
            _reject("action_event_binding")
        decision_events[determination_id] = event
    if set(decision_events) != set(determinations):
        _reject("action_event_cardinality")

    acknowledgment_events: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["aggregate_type"] != "OBLIGATION" or event["kind"] != "ACTION_ACKNOWLEDGED":
            continue
        payload = event["payload"]
        action_id = _id(payload.get("action_id"), "action_ack_event_id")
        action = actions.get(action_id)
        if action is None or action_id in acknowledgment_events:
            _reject("action_ack_event_binding")
        box = outbox[action_id]
        evaluation_id = _id(payload.get("evaluation_id"), "action_ack_event_evaluation")
        resulting_evaluation = evaluations.get(evaluation_id)
        if (
            set(payload) != {"action_id", "acknowledgment_ref", "evaluation_id", "cash_mutation"}
            or action["status"] != "ACKNOWLEDGED"
            or payload.get("acknowledgment_ref") != box["acknowledgment_ref"]
            or payload.get("cash_mutation") is not False
            or event["aggregate_id"] != action["obligation_id"]
            or event["after_revision"] != event["before_revision"] + 1
            or resulting_evaluation is None
            or resulting_evaluation["obligation_id"] != action["obligation_id"]
            or resulting_evaluation["revision"] != event["after_revision"]
            or resulting_evaluation["evaluated_at_ms"] != event["committed_at_ms"]
        ):
            _reject("action_ack_event_binding")
        acknowledgment_events[action_id] = event
    expected_acknowledged = {action_id for action_id, row in actions.items() if row["status"] == "ACKNOWLEDGED"}
    if set(acknowledgment_events) != expected_acknowledged:
        _reject("action_ack_event_cardinality")

    latest_action_by_obligation: dict[str, dict[str, Any]] = {}
    for action in actions.values():
        obligation_id = action["obligation_id"]
        prior = latest_action_by_obligation.get(obligation_id)
        if prior is None or (action["revision"], action["action_id"]) > (prior["revision"], prior["action_id"]):
            latest_action_by_obligation[obligation_id] = action
    for obligation_id, obligation in obligations.items():
        latest_action = latest_action_by_obligation.get(obligation_id)
        expected_delivery_status = "NONE" if latest_action is None else latest_action["status"]
        current_evaluation_id = _id(obligation["current_evaluation_id"], "action_current_evaluation")
        current_evaluation = evaluations.get(current_evaluation_id)
        if (
            obligation["delivery_status"] != expected_delivery_status
            or current_evaluation is None
            or current_evaluation["delivery_status"] != expected_delivery_status
        ):
            _reject("action_delivery_projection")


def _verify_cases(
    tables: Mapping[str, list[dict[str, Any]]],
    evaluations: Mapping[str, Mapping[str, Any]],
) -> None:
    obligation_ids = {row["obligation_id"] for row in tables["obligations"]}
    cases_by_obligation: dict[str, list[dict[str, Any]]] = {}
    for row in tables["cases"]:
        _id(row["case_id"], "case_id")
        obligation_id = _id(row["obligation_id"], "case_obligation")
        if obligation_id not in obligation_ids or row["status"] not in CASE_STATUSES:
            _reject("case_binding")
        _text(row["reason"], "case_reason")
        _text(row["contractual_accountability"], "case_accountability")
        _kind(row["next_action_owner"], "case_owner")
        conditions = _inner_json(row["completion_conditions_json"], "case_conditions")
        if (
            type(conditions) is not dict
            or set(conditions) != set(CASE_COMPLETION_CONDITIONS)
            or any(type(value) is not bool for value in conditions.values())
            or conditions != CASE_COMPLETION_CONDITIONS
        ):
            _reject("case_conditions")
        _time(row["due_at_ms"], "case_due")
        _time(row["updated_at_ms"], "case_updated")
        cases_by_obligation.setdefault(obligation_id, []).append(row)
    for row in tables["obligations"]:
        obligation_id = _id(row["obligation_id"], "case_projection_obligation")
        rows = cases_by_obligation.get(obligation_id, [])
        latest = max(rows, key=lambda item: item["case_id"]) if rows else None
        expected_status = "OPEN" if latest is None else latest["status"]
        current_evaluation_id = _id(row["current_evaluation_id"], "case_current_evaluation")
        current_evaluation = evaluations.get(current_evaluation_id)
        if (
            row["case_status"] != expected_status
            or current_evaluation is None
            or current_evaluation["case_status"] != expected_status
        ):
            _reject("case_projection")
    for row in tables["actions"]:
        if row["obligation_id"] not in obligation_ids:
            _reject("action_obligation")


def _view(
    package: Mapping[str, Any],
    tables: Mapping[str, list[dict[str, Any]]],
    counts: Mapping[str, int],
    evaluations: Mapping[str, Mapping[str, Any]],
    population_state: Mapping[str, Any],
    funding: Mapping[str, Any],
) -> dict[str, Any]:
    obligations = sorted(tables["obligations"], key=lambda row: (row["item_id"], row["obligation_id"]))
    obligation_by_id = {row["obligation_id"]: row for row in obligations}
    obligation_views = [
        {
            "obligation_id": row["obligation_id"],
            "population_id": row["population_id"],
            "item_id": row["item_id"],
            "revision": row["revision"],
            "verification_status": row["verification_status"],
            "case_status": row["case_status"],
            "delivery_status": row["delivery_status"],
            "evaluation_id": evaluations[row["current_evaluation_id"]]["evaluation_id"],
            "evaluation_receipt_digest": evaluations[row["current_evaluation_id"]]["receipt_digest_hex"],
        }
        for row in obligations
    ]
    open_cases = []
    for row in sorted(tables["cases"], key=lambda item: item["case_id"]):
        if row["status"] == "RESOLVED":
            continue
        open_cases.append({
            "case_id": row["case_id"],
            "obligation_id": row["obligation_id"],
            "item_id": obligation_by_id.get(row["obligation_id"], {}).get("item_id"),
            "status": row["status"],
            "next_action_owner": row["next_action_owner"],
            "due_at_ms": row["due_at_ms"],
        })
    outbox = {row["action_id"]: row for row in tables["action_outbox"]}
    pending_actions = []
    acknowledged_count = 0
    for row in sorted(tables["actions"], key=lambda item: item["action_id"]):
        box = outbox[row["action_id"]]
        if row["status"] == "ACKNOWLEDGED":
            acknowledged_count += 1
        if row["status"] != "READY":
            continue
        pending_actions.append({
            "action_id": row["action_id"],
            "obligation_id": row["obligation_id"],
            "item_id": obligation_by_id.get(row["obligation_id"], {}).get("item_id"),
            "kind": row["kind"],
            "status": row["status"],
            "outbox_attempt": box["attempt"],
            "acknowledgment_recorded": box["acknowledgment_ref"] is not None,
        })
    return {
        "schema": VIEW_SCHEMA,
        "version": 7,
        "scope": dict(package["scope"]),
        "source": {
            "schema": package["schema"],
            "owner_mode": package["mode"],
            "continuity_epoch": package["continuity_epoch"],
            "sequence": package["sequence"],
            "history_head": package["history_head"].upper(),
            "package_digest": package["package_digest"],
            "authentication": "NOT_ESTABLISHED_UNSIGNED_PACKAGE",
        },
        "verification": {
            "canonical_package_digest": "PASS",
            "allowlisted_table_grammar": "PASS",
            "owner_history_chain_and_head": "PASS",
            "manifest_population_binding": "PASS",
            "funding_record_lineage": "PASS",
            "evidence_record_digests": "PASS",
            "evaluation_receipt_digests": "PASS",
            "evaluation_semantic_replay": "NOT_PERFORMED",
            "external_source_authentication": "NOT_ESTABLISHED",
        },
        "receiver": {
            "view_mode": "READ_ONLY_SHADOW",
            "dispatch_enabled": False,
            "egress_enabled": False,
            "database_created": False,
            "second_writer_created": False,
        },
        "table_counts": dict(sorted(counts.items())),
        "populations": sorted(population_state["population_views"], key=lambda item: item["population_id"]),
        "obligations": obligation_views,
        "open_cases": open_cases,
        "pending_actions": pending_actions,
        "acknowledged_action_count": acknowledged_count,
        "program_funding": {
            **dict(funding),
            "recipient_cash_effect": "NOT_ASSERTED",
        },
        "external_effects": {
            "status": "UNKNOWN_FROM_CONTINUITY_PACKAGE",
            "dispatch_enabled": False,
            "egress_enabled": False,
            "action_acknowledgment_is_cash_receipt": False,
            "queue_to_fin_receipt_mapping": "NONE_ASSUMED",
        },
        "proofSuiteId": None,
        "production_usable": False,
        "activation": False,
    }


def build_readonly_view(raw: bytes, expected_scope: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one synthetic v7 package and build a detached non-live view."""
    package = _decode_package(raw)
    required_keys = {
        "schema", "version", "scope", "authority", "continuity_epoch", "sequence",
        "history_head", "dispatch_enabled", "egress_enabled", "mode", "tables", "package_digest",
    }
    if set(package) != required_keys:
        _reject("package_shape")
    if type(package["version"]) is not int or package["version"] != 7 or package["schema"] != V7_SCHEMA:
        _reject("schema_version")
    scope = package["scope"]
    scope_keys = {"state_id", "deployment_id", "program_id", "period_id", "currency"}
    if type(scope) is not dict or set(scope) != scope_keys:
        _reject("scope_shape")
    if not isinstance(expected_scope, Mapping) or set(expected_scope) != scope_keys:
        _reject("expected_scope_shape")
    normalized_expected = {
        "state_id": _id(expected_scope["state_id"], "expected_scope"),
        "deployment_id": _id(expected_scope["deployment_id"], "expected_scope"),
        "program_id": _id(expected_scope["program_id"], "expected_scope"),
        "period_id": _id(expected_scope["period_id"], "expected_scope"),
        "currency": expected_scope["currency"],
    }
    if normalized_expected["currency"] != "USD":
        _reject("expected_scope_currency")
    if scope != normalized_expected or scope.get("currency") != "USD":
        _reject("scope_mismatch", 5)
    for key in ("state_id", "deployment_id", "program_id", "period_id"):
        _id(scope[key], "scope_id")

    authority = package["authority"]
    if type(authority) is not dict or set(authority) != {"authority_id", "epoch", "digest"}:
        _reject("authority_shape")
    authority_id = _id(authority["authority_id"], "authority_id")
    authority_epoch = _integer(authority["epoch"], "authority_epoch", minimum=1)
    authority_digest = _hex_digest(authority["digest"], "authority_digest")
    package_epoch = _integer(package["continuity_epoch"], "continuity_epoch", minimum=1)
    sequence = _integer(package["sequence"], "sequence", maximum=MAX_ROWS)
    history_head = _hex_digest(package["history_head"], "history_head")
    if type(package["mode"]) is not str or package["mode"] not in {"LIVE", "SHADOW", "TEST"}:
        _reject("mode")
    if package["dispatch_enabled"] is not False or package["egress_enabled"] is not False:
        _reject("nonactivating_boundary")
    if type(package["package_digest"]) is not str or HEX128.fullmatch(package["package_digest"]) is None:
        _reject("package_digest_shape")

    tables, counts = _decode_tables(package["tables"])
    if len(tables["financial_identity"]) != 1 or len(tables["financial_meta"]) != 1:
        _reject("owner_identity_cardinality")
    meta = tables["financial_meta"][0]
    if (
        meta["id"] != 1 or meta["schema_version"] != 7 or meta["schema"] != OWNER_SCHEMA
        or meta["state_id"] != scope["state_id"] or meta["deployment_id"] != scope["deployment_id"]
        or meta["program_id"] != scope["program_id"] or meta["period_id"] != scope["period_id"]
        or meta["currency"] != scope["currency"] or meta["sequence"] != sequence
        or meta["history_head"] != history_head or meta["continuity_epoch"] != package_epoch
        or meta["dispatch_enabled"] != 0 or meta["egress_enabled"] != 0
        or meta["trusted_authority_id"] != authority_id
        or meta["trusted_authority_epoch"] != authority_epoch
        or meta["trusted_authority_digest"] != authority_digest or meta["mode"] != package["mode"]
    ):
        _reject("meta_binding")
    owner_id = _id(meta["owner_id"], "owner_id")

    body = dict(package)
    del body["package_digest"]
    expected_digest = _digest(CONTINUITY_DOMAIN, _canonical(body)).hex().upper()
    if package["package_digest"] != expected_digest:
        _reject("package_digest_mismatch")

    events = _verify_events(
        tables["financial_events"],
        identity_row=tables["financial_identity"][0],
        sequence=sequence,
        expected_head=history_head,
    )
    identity = _verify_identity(
        tables["financial_identity"][0],
        authority_digest=authority_digest,
        scope=scope,
        mode=package["mode"],
        owner_id=owner_id,
        sequence=sequence,
        events=events,
    )
    _ = identity
    funding = _verify_program_funding(tables, events, scope)
    population_state = _verify_manifests_and_populations(
        tables,
        events,
        scope=scope,
        authority={"authority_id": authority_id, "epoch": authority_epoch, "digest": authority_digest.hex().upper()},
    )
    _verify_evidence_records(tables)
    evaluations, obligations = _verify_evaluation_receipts(
        tables,
        events,
        scope=scope,
        authority={"authority_id": authority_id, "epoch": authority_epoch, "digest": authority_digest.hex().upper()},
    )
    _verify_population_history(events, population_state)
    _verify_population_publication_bindings(events, population_state, obligations)
    _verify_action_outbox(
        tables,
        evaluations,
        events,
        scope=scope,
        authority={"authority_id": authority_id, "epoch": authority_epoch, "digest": authority_digest.hex().upper()},
    )
    _verify_cases(tables, evaluations)
    return _view(package, tables, counts, evaluations, population_state, funding)


def _safe_parent(path: Path) -> Path:
    if path.name in {"", ".", ".."}:
        _reject("output_path", 6)
    parent = path.parent
    try:
        if not parent.is_dir():
            _reject("output_parent", 6)
        for ancestor in (parent, *parent.parents):
            if ancestor.is_symlink():
                _reject("output_parent", 6)
        resolved = parent.resolve(strict=True)
    except (OSError, RuntimeError):
        _reject("output_parent", 6)
    if not resolved.is_dir():
        _reject("output_parent", 6)
    return resolved / path.name


def _file_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _reject("output_identity_read_failed", 7)
    if stat.S_ISREG(info.st_mode) and info.st_ino:
        return int(info.st_dev), int(info.st_ino)
    return None


def _unlink_if_owned(
    path: Path,
    identity: tuple[int, int] | None,
    *,
    code: str,
) -> None:
    if identity is None or _file_identity(path) != identity:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        _reject(code, 7)


def publish_readonly_view(path: Path, view: Mapping[str, Any]) -> None:
    """Publish atomically with no replacement; clean up only this attempt."""
    destination = _safe_parent(path)
    if destination.exists() or destination.is_symlink():
        _reject("output_exists", 6)
    payload = _canonical(view)
    temporary = destination.parent / f".{destination.name}.continuity-v7-{uuid.uuid4().hex}.tmp"
    descriptor = None
    owned_identity: tuple[int, int] | None = None
    published = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not info.st_ino:
            _reject("output_identity", 7)
        owned_identity = int(info.st_dev), int(info.st_ino)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(descriptor)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IREAD)
        else:
            os.chmod(temporary, stat.S_IREAD)
        if _file_identity(temporary) != owned_identity:
            _reject("output_attempt_replaced", 7)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            _reject("output_exists", 6)
        except OSError:
            _reject("output_no_replace_unavailable", 7)
        if _file_identity(destination) != owned_identity:
            _reject("output_publication_identity", 7)
        try:
            with destination.open("rb") as published_file:
                if published_file.read(MAX_PACKAGE_BYTES + 1) != payload:
                    _reject("output_publication_bytes", 7)
        except OSError:
            _reject("output_publication_readback", 7)
        if _file_identity(destination) != owned_identity:
            _reject("output_publication_identity", 7)
        published = True
    except ContinuityError:
        if not published:
            _unlink_if_owned(destination, owned_identity, code="output_destination_cleanup_failed")
        raise
    except OSError:
        _unlink_if_owned(destination, owned_identity, code="output_destination_cleanup_failed")
        _reject("output_publication_failed", 7)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _unlink_if_owned(temporary, owned_identity, code="output_attempt_cleanup_failed")
    if not published:
        _reject("output_publication_failed", 7)


def _read_package(path: Path) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size > MAX_PACKAGE_BYTES:
            _reject("input_file", 3)
        with path.open("rb") as stream:
            descriptor_info = os.fstat(stream.fileno())
            if not stat.S_ISREG(descriptor_info.st_mode) or descriptor_info.st_size > MAX_PACKAGE_BYTES:
                _reject("input_file", 3)
            raw = stream.read(MAX_PACKAGE_BYTES + 1)
    except ContinuityError:
        raise
    except OSError:
        _reject("input_read", 3)
    if not raw or len(raw) > MAX_PACKAGE_BYTES:
        _reject("input_size", 3)
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="synthetic FIN Continuity v7 package")
    parser.add_argument("--state-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--program-id", required=True)
    parser.add_argument("--period-id", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new receiver-owned JSON view path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = _read_package(args.package)
        view = build_readonly_view(
            raw,
            {
                "state_id": args.state_id,
                "deployment_id": args.deployment_id,
                "program_id": args.program_id,
                "period_id": args.period_id,
                "currency": "USD",
            },
        )
        publish_readonly_view(args.output, view)
        sys.stdout.buffer.write(_canonical(view) + b"\n")
        return 0
    except ContinuityError as error:
        sys.stderr.write(f"ERROR continuity_successor_v7 code={error.code}\n")
        return error.exit_code
    except (OSError, ValueError):
        sys.stderr.write("ERROR continuity_successor_v7 code=unexpected\n")
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
