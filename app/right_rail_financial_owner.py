"""Synthetic, state-local financial responsibility owner for RightRail.

This is a separate application generation from the retained direct-clearance
Queue/Composition path.  It records descriptive financial history and
authorized local actions only.  It never calls a payment processor, emits a
live directive, stores raw evidence, or claims production authority.
"""

from __future__ import annotations

from contextlib import closing, contextmanager, nullcontext
from dataclasses import dataclass, replace
import ctypes
import gc
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
import time
from typing import Any, Final, Iterable, Iterator, Mapping, Protocol


class FinancialError(RuntimeError):
    """Base error with a stable, redacted code in ``str(error)``."""


class FinancialInputError(FinancialError):
    pass


class FinancialIntegrityError(FinancialError):
    pass


class FinancialAuthorityError(FinancialError):
    pass


class FinancialConflictError(FinancialError):
    pass


class FinancialRevisionError(FinancialError):
    pass


class FinancialStaleError(FinancialRevisionError):
    """Raised inside ``_write`` before its first statement (a stale cash plan): rolled back, and the writer this begin checked is kept."""


class FinancialContinuityError(FinancialError):
    pass


class FinancialDispatchError(FinancialError):
    pass


class FinancialBusyError(FinancialError):
    """Retryable: another connection held the store's lock past the busy timeout; nothing was written."""


def _fail(error_type: type[FinancialError], code: str) -> None:
    error = error_type(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _one(connection: sqlite3.Connection, code: str, sql: str, params: Any = ()) -> sqlite3.Row:
    row = connection.execute(sql, params).fetchone()
    if row is None:
        _fail(FinancialIntegrityError, code)
    return row


def _cols(row: sqlite3.Row, convert: type, *names: str) -> dict[str, Any]:
    return {name: convert(row[name]) for name in names}


def _opt(value: Any, convert: Any) -> Any:
    return None if value is None else convert(value)


def _attrs(source: object, *names: str) -> dict[str, Any]:
    return {name: getattr(source, name) for name in names}


_SCOPE_KEYS = ("state_id", "deployment_id", "program_id", "period_id", "currency")


def _raise_if_busy(error: BaseException) -> None:
    """A lock held past the busy timeout is ``store_busy``, never an integrity finding or a raw sqlite error."""
    if isinstance(error, sqlite3.OperationalError) and getattr(error, "sqlite_errorcode", 0) & 0xFF in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
        _fail(FinancialBusyError, "store_busy")


# The owner opens one store version, v8; any other fails closed.
_SCHEMA_VERSION: Final[int] = 8
_SCHEMA: Final[str] = "RR/FINANCIAL/OWNER/v8"
_CONTINUITY_SCHEMA: Final[str] = "RR/FINANCIAL/CONTINUITY/v8"
_DECISION_PACKAGE_CONTRACT: Final[str] = "RR/FINANCIAL/DECISION-PACKAGE/v3"
_POPULATION_MANIFEST_CONTRACT: Final[str] = "RR/FINANCIAL/POPULATION-MANIFEST/v1"
_CURRENCY: Final[str] = "USD"
_MAX_CENTS: Final[int] = (1 << 63) - 1
_MAX_ROWS: Final[int] = 10_000
_MAX_DUPLICATE_INPUTS: Final[int] = 256
# run_batch commands: all their work is on the one write connection and they catch nothing.
_BATCH_COMMANDS: Final = frozenset({"record_payment_evidence", "record_support_evidence", "evaluate_obligation", "reverse_payment"})
_MAX_PACKAGE_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_DECISION_PACKAGE_BYTES: Final[int] = _MAX_PACKAGE_BYTES - 512
_MAX_CORRECTION_FOLLOWUP_BYTES: Final[int] = 3 * _MAX_DECISION_PACKAGE_BYTES + 64 * 1024
_VERIFIED_STAFF_SNAPSHOT_CONTRACT: Final[str] = "RR/FINANCIAL/OWNER-VERIFIED-STAFF-SNAPSHOT/v1"
_STAFF_SNAPSHOT_ID_CONTRACT: Final[str] = "RR/FINANCIAL/STAFF-SNAPSHOT-ID/v1"
_STAFF_WORKSPACE_QUERY: Final[str] = "workspace"
_OBLIGATION_STATUS_CLAUSES: Final[dict[str, str]] = {"ALL": "1=1", "OPEN": "amount_satisfied=0", "SATISFIED": "amount_satisfied=1", "CASH_UNSATISFIED": "cash_satisfied=0"}
_STAFF_DECISION_PACKAGE_QUERY: Final[str] = "decision_package"
_MAX_CORRECTION_FOLLOWUP_PAGE_BYTES: Final[int] = 32 * 1024 * 1024
# History segments (docs/CORE_REDESIGN.md "History segments"): one format with the gate.
_SEGMENT_FORMAT: Final[str] = "RR/GATE/SEGMENT/v1"
_SEGMENT_DOMAIN: Final[bytes] = b"RR/GATE/SEGMENT/v1\x00"
_MAX_SEGMENT_BYTES: Final[int] = 2 * _MAX_PACKAGE_BYTES  # holds the one catch-up segment of any store the old 8 MiB cap admitted
_MAX_SEGMENT_EVENTS: Final[int] = _MAX_ROWS
_SEAL_SEGMENT_BYTES: Final[int] = _MAX_PACKAGE_BYTES // 2  # soft bounds: seal after the write that reaches either
_SEAL_SEGMENT_EVENTS: Final[int] = 4096
_SEGMENT_FRAME_BYTES: Final[int] = 4096  # seal, digests and framing, which records do not count
_SEGMENT_TABLES: Final[frozenset[str]] = frozenset({"history_segments", "history_pending", "history_open"})
# Moves on every committed insert into a history table (a new pending key, or a seal adds a segment), and names
# the exact history: the chain head differs between any two histories, so a swapped-in fork never matches.
_HISTORY_MARK: Final[str] = "SELECT (SELECT MAX(segment_index) FROM history_segments),(SELECT COUNT(*) FROM history_pending),sequence,history_head FROM financial_meta WHERE id=1"
_CHECK_ROW_CACHE: Final[bool] = os.environ.get("RIGHTRAIL_CHECK_ROW_CACHE") == "1"  # tests: recount after every write
_PRIVATE_INDEX_SET_VERSION: Final[int] = 3  # v2 adds the events lookup the checker runs per obligation; v3 its store-wide lookups by kind
# The history is append-only in the database itself (Art. III.4); stores
# created before these triggers get them once, atomically, on open.
_HISTORY_APPEND_ONLY_TRIGGERS: Final[dict[str, str]] = {
    "financial_event_update_immutable": "CREATE TRIGGER financial_event_update_immutable BEFORE UPDATE ON financial_events BEGIN SELECT RAISE(ABORT,'financial_event_immutable'); END",
    "financial_event_delete_immutable": "CREATE TRIGGER financial_event_delete_immutable BEFORE DELETE ON financial_events BEGIN SELECT RAISE(ABORT,'financial_event_immutable'); END",
}
_PRIVATE_INDEX_SET_V1: Final[tuple[tuple[str, str, tuple[str, ...]], ...]] = (
    ("rr_financial_v1_evidence_item_id", "evidence", ("item_id", "evidence_id")),
    ("rr_financial_v1_claims_obligation_id", "claimed_adjustments", ("obligation_id", "claim_id")),
    ("rr_financial_v1_cases_obligation_id", "cases", ("obligation_id", "case_id")),
    ("rr_financial_v1_actions_obligation_id", "actions", ("obligation_id", "action_id")),
    ("rr_financial_v1_conflicts_obligation_id", "financial_conflicts", ("obligation_id", "conflict_id")),
    ("rr_financial_v1_evaluations_obligation_revision", "evaluations", ("obligation_id", "revision")),
    ("rr_financial_v1_determinations_obligation_id", "determinations", ("obligation_id", "determination_id")),
)
_PRIVATE_INDEX_SETS: Final[dict[int, tuple[tuple[str, str, tuple[str, ...]], ...]]] = {
    1: _PRIVATE_INDEX_SET_V1,
    2: (*_PRIVATE_INDEX_SET_V1, ("rr_financial_v2_events_aggregate_kind", "financial_events", ("aggregate_type", "aggregate_id", "kind"))),
}
_PRIVATE_INDEX_SETS[3] = (*_PRIVATE_INDEX_SETS[2], ("rr_financial_v3_events_kind", "financial_events", ("kind", "aggregate_type")))
_CORRECTION_FOLLOWUP_CONTRACT: Final[str] = "RR/FINANCIAL/CORRECTION-FOLLOWUP/v1"
_CORRECTION_FOLLOWUP_DEPENDENCIES: Final[tuple[str, ...]] = (
    "OBLIGATION_REVISION",
    "CURRENT_EVALUATION_RECEIPT",
    "CONTROL_PACK",
    "TRUSTED_AUTHORITY",
    "SUPPORTING_EVIDENCE",
    "CURRENT_DETERMINATION",
    "ACTION_DELIVERY",
)
# Which derived dependency families of a committed correction each event kind can move.
# A kind missing here makes follow-up status REVIEW_REQUIRED, never CURRENT.
_FOLLOWUP_TOUCHES: Final[dict[str, tuple[str, ...]]] = {
    "CONTROL_PACK_PUBLISHED": ("RULE",),
    "EVALUATION_RECORDED": ("AUTHORITY",),
    "SUPPORT_EVIDENCE_RECORDED": ("AUTHORITY", "SUPPORT_EVIDENCE"),
    "PAYMENT_RECEIVED": ("AUTHORITY", "PAYMENT_EVIDENCE"),
    "PAYMENT_REVERSED": ("AUTHORITY", "PAYMENT_EVIDENCE"),
    "PAYMENT_CONFLICT_VISIBLE": ("AUTHORITY", "PAYMENT_EVIDENCE"),
    "PAYMENT_DUPLICATE_EVIDENCE": (),  # repeats an existing payment (the checker binds it); money is unchanged
    "INTAKE_RECEIVED": (),  # a raw file's intake facts and row outcomes; its rows' own events move money
    "FOLLOWTHROUGH_DECIDED": (),  # an official's act moves no correction dependency
    "OFFSET_CLAIMED": ("AUTHORITY", "OFFSET_EVIDENCE"),
    "OFFSET_AUTHORIZED": ("AUTHORITY", "DETERMINATION"),
    "OFFSET_REJECTED_CORRECTION_AUTHORIZED": ("AUTHORITY", "DETERMINATION"),
    "ACTION_ACKNOWLEDGED": ("AUTHORITY",),  # an acknowledgment never reopens; nothing records a rejection
    "REPORTING_EVIDENCE_RECORDED": ("AUTHORITY", "REPORT_EVIDENCE"),
    "REPORTING_CORRECTION_RECORDED": ("AUTHORITY", "REPORT_EVIDENCE"),
    **dict.fromkeys(
        (
            "POPULATION_MANIFEST_REGISTERED", "POPULATION_MANIFEST_SUPERSEDED", "POPULATION_STAGED",
            "POPULATION_IMPORT_OPENED", "POPULATION_SOURCE_COMPLETED", "POPULATION_VALIDATED",
            "POPULATION_PUBLISHED", "FUNDING_RECEIPT_RECORDED", "FUNDING_RECEIPT_SUPERSEDED",
        ),
        (),
    ),
}
_EVIDENCE_COLLECTION: Final[dict[str, str]] = {
    "SUPPORT": "SUPPORT_EVIDENCE",
    "PAYMENT_CONFIRMATION": "PAYMENT_EVIDENCE",
    "PAYMENT_REVERSAL": "PAYMENT_EVIDENCE",
    "OFFSET_CLAIM": "OFFSET_EVIDENCE",
    "REPORT": "REPORT_EVIDENCE",
    "REPORT_CORRECTION": "REPORT_EVIDENCE",
}
_MODES: Final[frozenset[str]] = frozenset({"LIVE", "SHADOW", "TEST"})
_TEST_OWNER_ID: Final[str] = "continuity-test-owner-v1"
_SHADOW_OWNER_ID: Final[str] = "continuity-shadow-owner-v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_UPPER_HEX128 = re.compile(r"[0-9A-F]{128}\Z")
_UPPER_HEX64 = re.compile(r"[0-9A-F]{64}\Z")
_ROLE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_KIND = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_WILDCARD_PERIODS: Final[frozenset[str]] = frozenset({"PROGRAM", "ALL"})
_CONTROL_PACK_ALLOWED_ROLES: Final[frozenset[str]] = frozenset(
    {"FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"}
)
_CONTROL_PACK_REQUIRED_ROLES: Final[frozenset[str]] = frozenset(
    {"FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER"}
)
_CONTROL_PACK_POLICIES: Final[dict[tuple[str, str], tuple[tuple[str, ...], str, str]]] = {
    (
        "calculation:per-recipient:v1",
        "adjustment:offset:v1",
    ): (
        (
            "program-total=100000000",
            "H-owed=10000000",
            "other-total=90000000",
            "timeliness-separate",
        ),
        "PER_RECIPIENT",
        "AUTHORIZED_OFFSET",
    ),
    (
        "calculation:per-recipient:v2",
        "adjustment:offset:v2",
    ): (
        (
            "period-02-uses-rule-v2",
            "period-01-evaluation-preserved",
            "retrospective-authority-required",
        ),
        "PER_RECIPIENT",
        "AUTHORIZED_OFFSET",
    ),
}
_EVENT_DOMAIN = b"RR/FINANCIAL/EVENT/v2\x00"
_HEAD_DOMAIN = b"RR/FINANCIAL/HEAD/v2\x00"
_GENESIS_DOMAIN = b"RR/FINANCIAL/GENESIS/v7\x00"
_EVIDENCE_DOMAIN = b"RR/FINANCIAL/EVIDENCE/v1\x00"
_ACTION_DOMAIN = b"RR/FINANCIAL/ACTION/v1\x00"
_IDEMPOTENCY_DOMAIN = b"RR/FINANCIAL/IDEMPOTENCY/v1\x00"
_EVALUATION_RESULT_DOMAIN = b"RR/FINANCIAL/EVALUATION/v5\x00"
_EVALUATION_INPUT_DOMAIN = b"RR/FINANCIAL/EVALUATION-INPUT/v1\x00"
_EVALUATION_EVENT_DOMAIN = b"RR/FINANCIAL/EVALUATION-EVENT/v1\x00"
_EVALUATION_RECEIPT_DOMAIN = b"RR/FINANCIAL/EVALUATION-RECEIPT/v1\x00"
_CONTINUITY_DOMAIN = b"RR/FINANCIAL/CONTINUITY/v8\x00"
_COMMAND_DOMAIN = b"RR/FINANCIAL/COMMAND/v1\x00"
_POPULATION_MANIFEST_DOMAIN = b"RR/FINANCIAL/POPULATION-MANIFEST/v1\x00"
_POPULATION_MANIFEST_MEMBERS_DOMAIN = b"RR/FINANCIAL/POPULATION-MANIFEST-MEMBERS/v1\x00"
_POPULATION_STAGING_DOMAIN = b"RR/FINANCIAL/POPULATION-STAGING/v1\x00"
_PROGRAM_FUNDING_RECEIPT_DOMAIN = b"RR/FINANCIAL/PROGRAM-FUNDING-RECEIPT/v1\x00"
_PROGRAM_FUNDING_RECEIPT_SCHEMA: Final[str] = "RR/FINANCIAL/PROGRAM-FUNDING-RECEIPT/v1"
_PROGRAM_FUNDING_CONFIRMATION_CLASS: Final[str] = "STATE_PAYMENT_RECORD"
_PROGRAM_FUNDING_EVIDENCE_STATUS: Final[str] = "SYNTHETIC_UNAPPROVED"
_IDENTITY_DOMAIN = b"RR/FINANCIAL/IDENTITY/v1\x00"
_EVALUATION_RECEIPT_CONTRACT: Final[str] = "RR/FINANCIAL/EVALUATION-RECEIPT/v1"
# The Lean result fields an evaluation row stores as decided (V.1); flags are stored as 0/1.
_DECIDED_VALUES: Final[tuple[str, ...]] = (
    "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents",
    "shortfall_cents", "overage_cents", "verification_status", "case_status", "delivery_status",
)
_DECIDED_FLAGS: Final[tuple[str, ...]] = ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete")
_ZERO_DIGEST: Final[bytes] =b"\x00" * 64

# Exported (Continuity v8) tables and their exact column order.
_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "financial_identity": (
        "id", "schema_version", "provenance", "bound_mode", "bound_owner_id",
        "anchor_sequence", "anchor_head", "genesis_head", "source_package_digest", "identity_digest",
    ),
    "financial_meta": (
        "id", "schema_version", "schema", "state_id", "deployment_id", "program_id",
        "period_id", "currency", "sequence", "history_head", "continuity_epoch",
        "dispatch_enabled", "egress_enabled", "trusted_authority_id",
        "trusted_authority_epoch", "trusted_authority_digest", "mode", "owner_id",
    ),
    "control_packs": (
        "pack_id", "state_id", "deployment_id", "program_id", "period_id", "version",
        "source_refs_json", "effective_start_ms", "effective_end_ms", "recorded_at_ms",
        "approved_at_ms", "calculation_rule_id", "adjustment_rule_id", "authorized_roles_json",
        "expected_tests_json", "pack_digest", "status",
    ),
    "population_imports": (
        "population_id", "pack_id", "cutoff_ms", "inclusion_rules_json", "expected_count",
        "source_complete", "imported_count", "validated_count", "validation_digest", "status",
        "created_at_ms", "updated_at_ms",
    ),
    "population_items": (
        "population_id", "item_id", "display_label", "owed_cents", "due_at_ms", "currency",
    ),
    "obligations": (
        "obligation_id", "population_id", "item_id", "period_id", "currency", "owed_cents",
        "due_at_ms", "rule_version", "revision", "claimed_adjustment_cents",
        "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents",
        "cash_satisfied", "amount_satisfied", "timely", "reporting_complete",
        "verification_status", "case_status", "delivery_status", "current_evaluation_id",
        "updated_at_ms",
    ),
    "evidence": (
        "evidence_id", "item_id", "kind", "common_origin_id", "source_id", "source_version",
        "local_ref", "applicable_at_ms", "event_at_ms", "received_at_ms", "content_digest",
        "record_digest", "amount_cents", "reversal_of", "supersedes",
    ),
    "payments": (
        "payment_id", "obligation_id", "item_id", "evidence_id", "common_origin_id",
        "amount_cents", "event_at_ms", "active", "reversed_by_evidence_id",
    ),
    "claimed_adjustments": (
        "claim_id", "obligation_id", "evidence_id", "amount_cents", "owner_role", "deadline_ms",
        "status", "created_at_ms", "updated_at_ms",
    ),
    "cases": (
        "case_id", "obligation_id", "reason", "contractual_accountability", "next_action_owner",
        "due_at_ms", "completion_conditions_json", "status", "updated_at_ms",
    ),
    "determinations": (
        "determination_id", "obligation_id", "claim_id", "actor_id", "actor_role", "authority_id",
        "authority_epoch", "authority_digest", "decision", "amount_cents",
        "supporting_evidence_json", "expected_revision", "resulting_revision", "decided_at_ms",
        "determination_digest", "input_evaluation_id", "input_evaluation_result_digest",
    ),
    "actions": (
        "action_id", "obligation_id", "determination_id", "kind", "status", "revision",
        "payload_json", "payload_digest", "idempotency_key", "created_at_ms",
    ),
    "action_outbox": (
        "action_id", "status", "attempt", "payload_digest", "acknowledgment_ref", "updated_at_ms",
    ),
    "financial_events": (
        "event_sequence", "event_id", "aggregate_type", "aggregate_id", "kind", "before_revision",
        "after_revision", "payload_json", "payload_digest", "previous_head", "head",
        "committed_at_ms",
    ),
    "financial_conflicts": (
        "conflict_id", "obligation_id", "common_origin_id", "existing_payment_id",
        "candidate_evidence_id", "existing_amount_cents", "candidate_amount_cents", "reason",
        "visible_at_ms",
    ),
    "evaluations": (
        "evaluation_id", "obligation_id", "revision", "rule_version", "evidence_ids_json",
        "authority_id", "evaluated_at_ms", "owed_cents", "claimed_adjustment_cents",
        "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents",
        "cash_satisfied", "amount_satisfied", "timely", "reporting_complete", "verification_status",
        "case_status", "delivery_status", "result_digest", "contract_version", "scope_json",
        "control_pack_id", "control_pack_version", "control_pack_digest", "authority_epoch",
        "authority_digest", "evidence_bindings_json", "input_snapshot_json",
        "input_snapshot_digest", "receipt_digest",
    ),
    "program_funding_receipts": (
        "receipt_id", "state_id", "deployment_id", "program_id", "period_id", "currency",
        "source_record_ref", "amount_cents", "confirmation_class", "evidence_status",
        "event_at_ms", "recorded_at_ms", "supersedes_receipt_id", "receipt_digest",
    ),
    "program_funding_projection": (
        "source_record_ref", "receipt_id", "amount_cents", "event_at_ms", "revision", "receipt_digest",
    ),
    "population_manifests": (
        "manifest_id", "contract", "manifest_version", "state_id", "deployment_id",
        "program_id", "period_id", "currency", "pack_id", "cutoff_ms",
        "inclusion_rules_json", "source_owner_id", "authority_id", "authority_epoch",
        "authority_digest", "approved_by", "approval_ref", "source_id", "source_version",
        "source_digest", "member_count", "member_digest", "supersedes_manifest_id",
        "supersedes_digest", "manifest_digest", "registered_at_ms",
    ),
    "population_manifest_members": ("manifest_id", "position", "member_id"),
    "population_manifest_heads": (
        "state_id", "deployment_id", "program_id", "period_id", "currency", "pack_id",
        "cutoff_ms", "source_owner_id", "manifest_id", "manifest_version",
        "manifest_digest", "updated_at_ms",
    ),
    "population_manifest_bindings": (
        "population_id", "manifest_id", "manifest_version", "manifest_digest",
    ),
    "commands": ("command_id", "kind", "request_json", "request_digest", "event_sequence"),
}
_TABLES: Final[frozenset[str]] = frozenset(_TABLE_COLUMNS)
_PACKAGE_TABLES: Final[frozenset[str]] = _TABLES - {"commands"}  # the command log is derived, never exported
# Every write to these rows is carried in the next event's ``rows`` (step 6): the chain holds their full facts.
_CAPTURED_TABLES: Final = ("action_outbox", "cases", "claimed_adjustments", "evidence", "financial_conflicts")
# A history segment carries its events and the end-of-segment image of every row these tables changed in it.
_PROJECTION_TABLES: Final = tuple(sorted(_PACKAGE_TABLES - {"financial_events", "financial_identity", "financial_meta"}))

# The command log (Art. III.3): one row per request the Owner accepted, keyed by
# the caller's natural key and bound to the history event that request produced.
# The request fields are read back from the rows that request wrote, so the
# independent checker can recompute every row.
_COMMAND_EVENTS: Final[dict[str, tuple[str, str | None]]] = {
    # event kind: (command kind, payload field naming the key; None = aggregate id)
    "CONTROL_PACK_PUBLISHED": ("CONTROL_PACK", None),
    "POPULATION_MANIFEST_REGISTERED": ("POPULATION_MANIFEST", None),
    "POPULATION_MANIFEST_SUPERSEDED": ("POPULATION_MANIFEST", None),
    "FUNDING_RECEIPT_RECORDED": ("FUNDING_RECEIPT", None),
    "FUNDING_RECEIPT_SUPERSEDED": ("FUNDING_RECEIPT", None),
    "SUPPORT_EVIDENCE_RECORDED": ("SUPPORT_EVIDENCE", "evidence_id"),
    "PAYMENT_RECEIVED": ("PAYMENT", "payment_id"),
    "PAYMENT_REVERSED": ("PAYMENT_REVERSAL", "evidence_id"),
    "OFFSET_CLAIMED": ("OFFSET_CLAIM", "claim_id"),
    "OFFSET_AUTHORIZED": ("OFFSET_DECISION", "action_id"),
    "OFFSET_REJECTED_CORRECTION_AUTHORIZED": ("OFFSET_DECISION", "action_id"),
    "ACTION_ACKNOWLEDGED": ("ACTION_ACKNOWLEDGMENT", "action_id"),
    "REPORTING_EVIDENCE_RECORDED": ("REPORT", "evidence_id"),
    "REPORTING_CORRECTION_RECORDED": ("REPORT", "evidence_id"),
    "FOLLOWTHROUGH_DECIDED": ("FOLLOWTHROUGH_DECISION", "decision_id"),
}
_OPTIONAL_REQUEST_FIELDS: Final = frozenset({"evaluation_id", "evaluation_result_digest", "expected_revision", "decided_at_ms"})
_COMMAND_REQUEST_SQL: Final[dict[str, str]] = {
    "CONTROL_PACK": "SELECT pack_digest FROM control_packs WHERE pack_id=?",
    "POPULATION_MANIFEST": "SELECT manifest_digest FROM population_manifests WHERE manifest_id=?",
    "FUNDING_RECEIPT": "SELECT receipt_digest FROM program_funding_receipts WHERE receipt_id=?",
    "SUPPORT_EVIDENCE": "SELECT item_id,record_digest FROM evidence WHERE evidence_id=?",
    "PAYMENT": (
        "SELECT p.item_id,p.evidence_id,p.common_origin_id,p.amount_cents,p.event_at_ms,"
        "e.source_id,e.source_version,e.local_ref "
        "FROM payments p JOIN evidence e ON e.evidence_id=p.evidence_id WHERE p.payment_id=?"
    ),
    "PAYMENT_REVERSAL": "SELECT item_id,reversal_of AS payment_id,record_digest FROM evidence WHERE evidence_id=?",
    "OFFSET_CLAIM": (
        "SELECT o.item_id,c.evidence_id,c.amount_cents,c.owner_role,c.deadline_ms "
        "FROM claimed_adjustments c JOIN obligations o ON o.obligation_id=c.obligation_id WHERE c.claim_id=?"
    ),
    "OFFSET_DECISION": (
        "SELECT o.item_id,d.claim_id,d.decision,d.actor_id,d.actor_role,"
        "d.input_evaluation_id AS evaluation_id,d.input_evaluation_result_digest AS evaluation_result_digest,"
        "d.expected_revision,d.decided_at_ms "
        "FROM actions a JOIN determinations d ON d.determination_id=a.determination_id "
        "JOIN obligations o ON o.obligation_id=a.obligation_id WHERE a.action_id=?"
    ),
    "ACTION_ACKNOWLEDGMENT": "SELECT acknowledgment_ref FROM action_outbox WHERE action_id=?",
    "REPORT": "SELECT item_id,record_digest FROM evidence WHERE evidence_id=?",
    "FOLLOWTHROUGH_DECISION": "SELECT payload_digest FROM financial_events NOT INDEXED WHERE kind='FOLLOWTHROUGH_DECIDED' AND json_extract(payload_json,'$.decision_id')=?",  # NOT INDEXED: exactly one, counting copies an index hides
}


# Every code a Continuity restore can raise (FinancialError here, FinancialMirrorError in the Mirror); a support package
# names one of these or UNCLASSIFIED, never other text. A test keeps this closed set equal to the codes in the source.
CONTINUITY_ERROR_CODES: Final[tuple[str, ...]] = tuple("continuity_" + code for code in (
    "authority_digest authority_epoch authority_id authority_mismatch columns destination destination_claim dispatch_boundary "
    "expected_scope_required export_type hex history_head identity:shape identity:id identity:schema identity:provenance "
    "identity:mode identity:owner identity:restore-live identity:restore-owner identity:anchor-sequence identity:anchor_head "
    "identity:genesis_head identity:source_package_digest identity:identity_digest identity:digest identity_anchor "
    "identity_binding identity_cardinality identity_genesis identity_history_anchor identity_id identity_rows meta_binding "
    "meta_columns meta_rows owner_identity package_authority package_binding package_canonical package_digest package_epoch "
    "package_json package_row package_rows package_schema package_scope package_sequence package_shape package_size "
    "package_tables package_type restore_checkpoint restore_cleanup restore_integrity restore_mode restore_owner row_cap schema_columns "
    "scope_currency scope_deployment_id scope_mismatch scope_period_id scope_program_id scope_state_id second_writer "
    "shadow_boundary source source_overwrite test_boundary trusted_authority_required value"
).split())


def _known_correction_engine(sha256: object) -> bool:
    """Whether committed correction history may name this engine (the checker's registry); a missing,
    altered or malformed registry is an integrity refusal."""
    from app.right_rail_financial_owner_independent import IndependentFinancialError, correction_engines

    try:
        return str(sha256) in correction_engines()
    except IndependentFinancialError as error:
        _fail(FinancialIntegrityError, str(error))


def _correction_paid(connection: sqlite3.Connection, obligation_id: str) -> list[dict[str, Any]]:
    """What active linked payments paid on each correction request of the obligation, by action id."""
    return [
        {"action_id": action_id, "paid_cents": paid}
        for action_id, paid in connection.execute(
            "SELECT json_extract(e.payload_json,'$.pays_action_id'),SUM(p.amount_cents) FROM financial_events e "
            "JOIN payments p ON p.payment_id=json_extract(e.payload_json,'$.payment_id') "
            "WHERE e.aggregate_type='OBLIGATION' AND e.aggregate_id=? AND e.kind='PAYMENT_RECEIVED' "
            "AND json_extract(e.payload_json,'$.pays_action_id') IS NOT NULL AND p.active=1 GROUP BY 1 ORDER BY 1",
            (obligation_id,),
        )
    ]


def _open_requests(connection: sqlite3.Connection, obligation_id: str, shortfall: int) -> dict[str, int]:
    """R2: what each correction request may still collect, oldest first, within the unpaid balance (derived, never stored)."""
    paid = {e["action_id"]: e["paid_cents"] for e in _correction_paid(connection, obligation_id)}
    left, open_ = shortfall, {}
    for action_id, amount in connection.execute("SELECT action_id,json_extract(payload_json,'$.amount_cents') FROM actions WHERE obligation_id=? AND kind='CORRECTION_PAYMENT_REQUEST' AND status<>'CANCELLED' ORDER BY revision,action_id", (obligation_id,)):
        open_[action_id] = min(max(amount - paid.get(action_id, 0), 0), left)  # clamped: a request is never open below zero
        left -= open_[action_id]
    return open_


def _payment_receipts(connection: sqlite3.Connection, obligation_id: str) -> list[tuple[str, int, str | None]]:
    """Each payment row's PAYMENT_RECEIVED event: the revision it was recorded at and the request it pays."""
    return connection.execute("SELECT json_extract(payload_json,'$.payment_id'),before_revision,json_extract(payload_json,'$.pays_action_id') FROM financial_events WHERE aggregate_type='OBLIGATION' AND aggregate_id=? AND kind='PAYMENT_RECEIVED' ORDER BY 1", (obligation_id,)).fetchall()



_PAYMENT_REFUSALS: Final = (None,  # Lean `refusals` order (Codec.lean), codes 1..16
    (FinancialInputError, "payment_amount_zero"), (FinancialConflictError, "payment_request_conflict"),
    (FinancialConflictError, "payment_origin_reversed"), (FinancialRevisionError, "obligation_revision_conflict"),
    (FinancialConflictError, "evidence_identity_conflict"), (FinancialInputError, "evidence_chronology"),
    (FinancialConflictError, "payment_request_unknown"), (FinancialConflictError, "payment_exceeds_unpaid_balance"),
    (FinancialIntegrityError, "payment_missing"), (FinancialConflictError, "payment_already_reversed"),
    (FinancialInputError, "common_origin_id"), (FinancialInputError, "local_ref"),
    (FinancialIntegrityError, "conflict_id_form"), (FinancialIntegrityError, "payment_capacity"),
    (FinancialIntegrityError, "lean_payment:post_rejected"), (FinancialDispatchError, "shadow_owner_read_only"))


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail(FinancialIntegrityError, "canonical_json")


def _digest(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes:
            _fail(FinancialIntegrityError, "digest_part")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _id(value: object, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(FinancialInputError, label)
    return value


def _role(value: object, label: str) -> str:
    if type(value) is not str or _ROLE.fullmatch(value) is None:
        _fail(FinancialInputError, label)
    return value


def _kind(value: object, label: str) -> str:
    if type(value) is not str or _KIND.fullmatch(value) is None:
        _fail(FinancialInputError, label)
    return value


def _text(value: object, label: str, *, max_bytes: int = 512) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > max_bytes or "\x00" in value:
        _fail(FinancialInputError, label)
    return value


def _cents(value: object, label: str, *, nonnegative: bool = False) -> int:
    if type(value) is not int or abs(value) > _MAX_CENTS or (nonnegative and value < 0):
        _fail(FinancialInputError, label)
    return value


def _add(left: int, right: int) -> int:
    value = left + right
    if value < -_MAX_CENTS or value > _MAX_CENTS:
        _fail(FinancialIntegrityError, "cents_overflow")
    return value


def _sum_cents(values: Iterable[int]) -> int:
    total = 0
    for value in values:
        total = _add(total, value)
    return total


def _hex(value: bytes) -> str:
    if type(value) is not bytes:
        _fail(FinancialIntegrityError, "bytes_required")
    return value.hex().upper()


def _values_json(values: Iterable[Any]) -> str:
    """Persisted ``{"values": [...]}`` column encoding."""

    return _canonical({"values": list(values)}).decode("ascii")


def _stored_values(raw: object, code: str) -> tuple[Any, ...]:
    """Decode one persisted ``{"values": [...]}`` column or fail closed with ``code``."""

    try:
        value = json.loads(str(raw))
    except (TypeError, ValueError):
        _fail(FinancialIntegrityError, code)
    if type(value) is not dict or set(value) != {"values"} or type(value["values"]) is not list:
        _fail(FinancialIntegrityError, code)
    return tuple(value["values"])


def _stored_object(raw: object, code: str) -> dict[str, Any]:
    """Decode one persisted JSON object column or fail closed with ``code``."""

    try:
        value = json.loads(str(raw))
    except (TypeError, ValueError):
        _fail(FinancialIntegrityError, code)
    if type(value) is not dict:
        _fail(FinancialIntegrityError, code)
    return value


def _population_validation_digest(rows: Iterable[Any]) -> bytes:
    """Digest of ordered (item_id, display_label, owed_cents, due_at_ms, currency) rows."""

    material = b"".join(
        _digest(
            _EVIDENCE_DOMAIN,
            _canonical({
                "item_id": str(row[0]),
                "display_label": str(row[1]),
                "owed_cents": int(row[2]),
                "due_at_ms": int(row[3]),
                "currency": str(row[4]),
            }),
        )
        for row in rows
    )
    return _digest(_EVIDENCE_DOMAIN, material)


def _is_upper_hex128(value: object) -> bool:
    return type(value) is str and _UPPER_HEX128.match(value) is not None


def _is_upper_hex64(value: object) -> bool:
    return type(value) is str and _UPPER_HEX64.match(value) is not None


def _is_str(value: object) -> bool:
    return type(value) is str


def _is_int(value: object) -> bool:
    return type(value) is int


def _shaped(value: object, spec: Mapping[str, Any]) -> bool:
    """True when ``value`` is a dict with exactly ``spec``'s keys and each value passes its check."""
    return type(value) is dict and set(value) == set(spec) and all(check(value[key]) for key, check in spec.items())


def _row_authority(row: sqlite3.Row) -> dict[str, Any]:
    return {"authority_id": str(row["authority_id"]), "epoch": int(row["authority_epoch"]), "digest": _hex(bytes(row["authority_digest"]))}


_STAFF_SCOPE_SHAPE = dict.fromkeys(_SCOPE_KEYS, lambda value: type(value) is str and value != "")
# snapshot_id is the SHA-256 staff snapshot identity (_staff_snapshot_id), 64 hex digits, recomputed and compared exactly.
_STAFF_SNAPSHOT_SHAPE = {
    "schema": _is_str, "schema_version": _is_int, "scope": lambda value: _shaped(value, _STAFF_SCOPE_SHAPE), "mode": _is_str,
    "owner_id": _is_str, "continuity_epoch": _is_int, "sequence": lambda value: type(value) is int and value >= 0,
    "history_head": _is_upper_hex128, "snapshot_id": _is_upper_hex64,
}
_STAFF_ITEM_BINDING_SHAPE = {
    "item_id": _is_str, "obligation_id": _is_str, "revision": _is_int, "evaluation_id": _is_str,
    "evaluation_result_digest": _is_upper_hex128, "control_pack_id": _is_str, "control_pack_version": _is_int,
    "control_pack_digest": _is_upper_hex128,
}
_STAFF_AUTHORITY_SHAPE = {"authority_id": _is_str, "epoch": _is_int, "digest": _is_upper_hex128}
# v2: the Mirror never shows staff the evaluation's input_snapshot_digest (Art. IV.2), so the binding carries the
# receipt_digest, whose receipt body includes the input_snapshot_digest; v1 demanded the hidden field.
_STAFF_INPUT_SHAPE = {"evaluation_id": _is_str, "evaluation_result_digest": _is_upper_hex128, "receipt_digest": _is_upper_hex128}


def _staff_snapshot_id(fields: Mapping[str, Any]) -> str:
    """Versioned SHA-256 identity of one staff-visible Owner snapshot (fields exclude ``snapshot_id``).

    SHA-256 because the browser recomputes it with WebCrypto, which has no SHA3.
    """

    material = {"contract": _STAFF_SNAPSHOT_ID_CONTRACT, **dict(fields)}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest().upper()


def _population_staging_digest(
    *,
    population_id: str,
    pack_id: str,
    cutoff_ms: int,
    inclusion_rules_json: str,
    expected_count: int,
    created_at_ms: int,
) -> bytes:
    """Digest of the immutable identity columns of one staged population_imports row."""

    return _digest(
        _POPULATION_STAGING_DOMAIN,
        _canonical(
            {
                "population_id": population_id,
                "pack_id": pack_id,
                "cutoff_ms": cutoff_ms,
                "inclusion_rules_json": inclusion_rules_json,
                "expected_count": expected_count,
                "created_at_ms": created_at_ms,
            }
        ),
    )


def _identity_digest(
    *,
    provenance: str,
    bound_mode: str,
    bound_owner_id: str,
    anchor_sequence: int,
    source_package_digest: bytes,
) -> bytes:
    if provenance not in {"ROOT", "CONTINUITY_RESTORE"}:
        _fail(FinancialIntegrityError, "identity_provenance")
    if bound_mode not in _MODES:
        _fail(FinancialIntegrityError, "identity_mode")
    _id(bound_owner_id, "identity_owner_id")
    if type(anchor_sequence) is not int or not 0 <= anchor_sequence < 2**63:
        _fail(FinancialIntegrityError, "identity_anchor_sequence")
    source_package_digest = _blob(source_package_digest, 64, "identity_source_package_digest")
    return _digest(
        _IDENTITY_DOMAIN,
        _canonical(
            {
                "anchor_sequence": anchor_sequence,
                "bound_mode": bound_mode,
                "bound_owner_id": bound_owner_id,
                "provenance": provenance,
                "source_package_digest": _hex(source_package_digest),
            }
        ),
    )


def _blob(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _fail(FinancialInputError, label)
    return bytes(value)


def _time(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 2**63:
        _fail(FinancialInputError, label)
    return value


def _followthrough_shape(act: object, reason_code: object, owner_id: object, code: str | None = None) -> None:
    """The one shape of a follow-through act: CLOSE names a reason and no owner, ASSIGN an owner and no reason.
    A defect raises its own code, or ``code`` for every defect (a suggestion)."""
    reason = None if type(reason_code) is str and _KIND.fullmatch(reason_code) else "followthrough_reason"
    owner = None if type(owner_id) is str and _ID.fullmatch(owner_id) else "followthrough_owner"
    if act not in ("ASSIGN", "CLOSE"):
        bad = "followthrough_act"
    elif act == "CLOSE":
        bad = reason or ("followthrough_owner" if owner_id is not None else None)
    else:
        bad = owner or ("followthrough_reason" if reason_code is not None else None)
    if bad is not None:
        _fail(FinancialInputError, code or bad)


def _identity_record(
    value: Mapping[str, Any],
    *,
    error_type: type[FinancialError] = FinancialIntegrityError,
    code_prefix: str = "identity",
) -> dict[str, Any]:
    fields = set(_TABLE_COLUMNS["financial_identity"])
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(error_type, f"{code_prefix}:shape")
    if value["id"] != 1:
        _fail(error_type, f"{code_prefix}:id")
    if type(value["schema_version"]) is not int or value["schema_version"] != _SCHEMA_VERSION:
        _fail(error_type, f"{code_prefix}:schema")
    provenance = value["provenance"]
    bound_mode = value["bound_mode"]
    bound_owner_id = value["bound_owner_id"]
    if provenance not in {"ROOT", "CONTINUITY_RESTORE"}:
        _fail(error_type, f"{code_prefix}:provenance")
    if bound_mode not in _MODES:
        _fail(error_type, f"{code_prefix}:mode")
    if type(bound_owner_id) is not str or _ID.fullmatch(bound_owner_id) is None:
        _fail(error_type, f"{code_prefix}:owner")
    if provenance == "CONTINUITY_RESTORE":
        if bound_mode == "LIVE":
            _fail(error_type, f"{code_prefix}:restore-live")
        expected_owner_id = _SHADOW_OWNER_ID if bound_mode == "SHADOW" else _TEST_OWNER_ID
        if bound_owner_id != expected_owner_id:
            _fail(error_type, f"{code_prefix}:restore-owner")
    anchor_sequence = value["anchor_sequence"]
    if type(anchor_sequence) is not int or not 0 <= anchor_sequence < 2**63:
        _fail(error_type, f"{code_prefix}:anchor-sequence")
    byte_values: dict[str, bytes] = {}
    for field in ("anchor_head", "genesis_head", "source_package_digest", "identity_digest"):
        raw = value[field]
        if type(raw) is not bytes or len(raw) != 64:
            _fail(error_type, f"{code_prefix}:{field}")
        byte_values[field] = bytes(raw)
    expected_digest = _identity_digest(
        provenance=provenance,
        bound_mode=bound_mode,
        bound_owner_id=bound_owner_id,
        anchor_sequence=anchor_sequence,
        source_package_digest=byte_values["source_package_digest"],
    )
    if byte_values["identity_digest"] != expected_digest:
        _fail(error_type, f"{code_prefix}:digest")
    return {
        "id": value["id"],
        "schema_version": _SCHEMA_VERSION,
        "provenance": provenance,
        "bound_mode": bound_mode,
        "bound_owner_id": bound_owner_id,
        "anchor_sequence": anchor_sequence,
        "anchor_head": byte_values["anchor_head"],
        "genesis_head": byte_values["genesis_head"],
        "source_package_digest": byte_values["source_package_digest"],
        "identity_digest": byte_values["identity_digest"],
    }


class FinancialClock(Protocol):
    def now_ms(self) -> int: ...


# One wall-clock step ahead (NTP, VM resume, a manual change) that commits and is then corrected leaves every
# later write refused as event_commit_order, store-wide. Ten minutes covers real drift; more is refused unwritten
# until the new wall time has held in step with the monotonic clock for as long, then it is the new baseline. An
# operator-mistake guard, not a tamper control: setting the clock back before the first reading, or restarting, passes it.
_CLOCK_SKEW_MS: Final = 600_000


class _SystemClock:
    def __init__(self) -> None:
        self._seen: tuple[int, int] | None = None  # (wall ms, monotonic ms) of the last accepted reading
        self._held: tuple[int, int] | None = None  # the first refused reading of the current stable stretch

    def now_ms(self) -> int:
        wall, mono = time.time_ns() // 1_000_000, time.monotonic_ns() // 1_000_000
        if self._seen is not None and wall > self._seen[0] + (mono - self._seen[1]) + _CLOCK_SKEW_MS:
            if self._held is None or abs(wall - self._held[0] - (mono - self._held[1])) > _CLOCK_SKEW_MS:
                self._held = (wall, mono)
            if mono - self._held[1] < _CLOCK_SKEW_MS:
                _fail(FinancialIntegrityError, "clock_jump_ahead")
        self._seen, self._held = (wall, mono), None
        return wall


@dataclass(frozen=True, slots=True)
class AuthorityActor:
    actor_id: str
    roles: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.actor_id, "actor_id")
        if type(self.roles) is not tuple or not self.roles or len(set(self.roles)) != len(self.roles):
            _fail(FinancialAuthorityError, "actor_roles")
        for role in self.roles:
            _role(role, "actor_role")


@dataclass(frozen=True, slots=True)
class SyntheticTrustedAuthority:
    authority_id: str = "synthetic-authority-v1"
    epoch: int = 1
    actors: tuple[AuthorityActor, ...] = (
        AuthorityActor("synthetic-official", ("FINANCE_DECISION", "CASE_OWNER")),
        AuthorityActor("synthetic-reporter", ("REPORTING_EDITOR",)),
        AuthorityActor("synthetic-receiver", ("RECEIVER",)),
    )
    synthetic_only: bool = True

    def __post_init__(self) -> None:
        _id(self.authority_id, "authority_id")
        if type(self.epoch) is not int or self.epoch < 1 or type(self.synthetic_only) is not bool or not self.synthetic_only:
            _fail(FinancialAuthorityError, "synthetic_authority_required")
        if type(self.actors) is not tuple or not self.actors:
            _fail(FinancialAuthorityError, "authority_actors")
        actor_ids: set[str] = set()
        for actor in self.actors:
            if type(actor) is not AuthorityActor or actor.actor_id in actor_ids:
                _fail(FinancialAuthorityError, "authority_actor_duplicate")
            actor_ids.add(actor.actor_id)

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(
            {
                "authority_id": self.authority_id,
                "epoch": self.epoch,
                "actors": [{"actor_id": actor.actor_id, "roles": list(actor.roles)} for actor in self.actors],
                "synthetic_only": True,
            }
        )

    @property
    def digest(self) -> bytes:
        return _digest(_EVIDENCE_DOMAIN, self.canonical_bytes)

    def require(self, actor_id: str, role: str) -> None:
        _id(actor_id, "actor_id")
        _role(role, "actor_role")
        for actor in self.actors:
            if actor.actor_id == actor_id and role in actor.roles:
                return
        _fail(FinancialAuthorityError, "authority_actor_not_authorized")


# Named synthetic staff of the staff workspace: (actor id, name, staff role, owner roles). The owner records the actor id; the name is
# for screens. A director and an auditor decide nothing, so the owner holds no roles for them.
SYNTHETIC_STAFF: Final = (
    ("staff:maria-alvarez", "Maria Alvarez", "approver", ("FINANCE_DECISION", "CASE_OWNER")),
    ("staff:devon-brooks", "Devon Brooks", "approver", ("FINANCE_DECISION", "CASE_OWNER")),
    ("staff:priya-nair", "Priya Nair", "analyst", ("RECEIVER",)),
    ("staff:tom-reyes", "Tom Reyes", "analyst", ("REPORTING_EDITOR",)),
    ("staff:grace-okafor", "Grace Okafor", "director", ()),
    ("staff:li-wei", "Li Wei", "auditor", ()),
)


def staff_authority() -> SyntheticTrustedAuthority:
    """The fixture authority plus the named staff who hold owner roles. Epoch 2: epoch 1 names the three fixture actors only."""
    return SyntheticTrustedAuthority(epoch=2, actors=SyntheticTrustedAuthority().actors + tuple(AuthorityActor(i, r) for i, _n, _s, r in SYNTHETIC_STAFF if r))


def _authority_ref(authority: SyntheticTrustedAuthority) -> dict[str, Any]:
    return {"authority_id": authority.authority_id, "epoch": authority.epoch, "digest": _hex(authority.digest)}


def _checker_authority(authority: SyntheticTrustedAuthority) -> dict[str, Any]:
    """Trusted authority binding for the independent checker, including its digest-bound roster."""
    return {**_authority_ref(authority), "actors": [{"actor_id": actor.actor_id, "roles": list(actor.roles)} for actor in authority.actors]}


@dataclass(frozen=True, slots=True)
class ControlPack:
    pack_id: str
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    version: int
    source_refs: tuple[str, ...]
    effective_start_ms: int
    effective_end_ms: int
    recorded_at_ms: int
    approved_at_ms: int
    calculation_rule_id: str
    adjustment_rule_id: str
    authorized_roles: tuple[str, ...]
    expected_tests: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, label in (
            (self.pack_id, "pack_id"),
            (self.state_id, "state_id"),
            (self.deployment_id, "deployment_id"),
            (self.program_id, "program_id"),
            (self.period_id, "period_id"),
            (self.calculation_rule_id, "calculation_rule_id"),
            (self.adjustment_rule_id, "adjustment_rule_id"),
        ):
            _id(value, label)
        if self.period_id in _WILDCARD_PERIODS:
            _fail(FinancialInputError, "period_scope_required")
        if type(self.version) is not int or not 1 <= self.version <= _MAX_ROWS:
            _fail(FinancialInputError, "pack_version")
        if type(self.source_refs) is not tuple or not self.source_refs:
            _fail(FinancialInputError, "pack_source_refs")
        for value in self.source_refs:
            _text(value, "pack_source_ref")
        if self.effective_start_ms >= self.effective_end_ms:
            _fail(FinancialInputError, "pack_effective_period")
        for value, label in ((self.effective_start_ms, "pack_effective_start"), (self.effective_end_ms, "pack_effective_end"), (self.recorded_at_ms, "pack_recorded"), (self.approved_at_ms, "pack_approved")):
            _time(value, label)
        if self.approved_at_ms < self.recorded_at_ms:
            _fail(FinancialInputError, "pack_approval_chronology")
        if type(self.authorized_roles) is not tuple or not self.authorized_roles or len(set(self.authorized_roles)) != len(self.authorized_roles):
            _fail(FinancialInputError, "pack_authorized_roles")
        for role in self.authorized_roles:
            _role(role, "pack_authorized_role")
        if type(self.expected_tests) is not tuple or not self.expected_tests:
            _fail(FinancialInputError, "pack_expected_tests")
        for test in self.expected_tests:
            _text(test, "pack_expected_test")

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(
            {
                **_attrs(self, "pack_id", "state_id", "deployment_id", "program_id", "period_id", "version"),
                "source_refs": list(self.source_refs),
                **_attrs(self, "effective_start_ms", "effective_end_ms", "recorded_at_ms", "approved_at_ms", "calculation_rule_id", "adjustment_rule_id"),
                "authorized_roles": list(self.authorized_roles),
                "expected_tests": list(self.expected_tests),
            }
        )

    @property
    def digest(self) -> bytes:
        return _digest(_EVIDENCE_DOMAIN, self.canonical_bytes)


def _control_pack_policy(
    *,
    calculation_rule_id: object,
    adjustment_rule_id: object,
    authorized_roles: object,
    expected_tests: object,
) -> tuple[str, str]:
    if type(calculation_rule_id) is not str or type(adjustment_rule_id) is not str:
        _fail(FinancialIntegrityError, "control_pack_policy_unsupported")
    if type(authorized_roles) not in (tuple, list) or type(expected_tests) not in (tuple, list):
        _fail(FinancialIntegrityError, "control_pack_policy_unsupported")
    roles = tuple(authorized_roles)
    tests = tuple(expected_tests)
    policy = _CONTROL_PACK_POLICIES.get((calculation_rule_id, adjustment_rule_id))
    if policy is None or tests != policy[0]:
        _fail(FinancialIntegrityError, "control_pack_policy_unsupported")
    if not roles or len(set(roles)) != len(roles):
        _fail(FinancialIntegrityError, "control_pack_roles_unsupported")
    for role in roles:
        _role(role, "control_pack_role")
    if not set(roles) <= _CONTROL_PACK_ALLOWED_ROLES or not _CONTROL_PACK_REQUIRED_ROLES <= set(roles):
        _fail(FinancialIntegrityError, "control_pack_roles_unsupported")
    return policy[1], policy[2]


def _control_pack_from_row(row: Mapping[str, Any]) -> ControlPack:
    """Rebuild one persisted control pack; malformed JSON columns fail closed."""

    source_refs = _stored_values(row["source_refs_json"], "control_pack_binding")
    authorized_roles = _stored_values(row["authorized_roles_json"], "control_pack_binding")
    expected_tests = _stored_values(row["expected_tests_json"], "control_pack_binding")
    try:
        return ControlPack(
            pack_id=str(row["pack_id"]),
            state_id=str(row["state_id"]),
            deployment_id=str(row["deployment_id"]),
            program_id=str(row["program_id"]),
            period_id=str(row["period_id"]),
            version=int(row["version"]),
            source_refs=source_refs,
            effective_start_ms=int(row["effective_start_ms"]),
            effective_end_ms=int(row["effective_end_ms"]),
            recorded_at_ms=int(row["recorded_at_ms"]),
            approved_at_ms=int(row["approved_at_ms"]),
            calculation_rule_id=str(row["calculation_rule_id"]),
            adjustment_rule_id=str(row["adjustment_rule_id"]),
            authorized_roles=authorized_roles,
            expected_tests=expected_tests,
        )
    except (TypeError, ValueError):
        _fail(FinancialIntegrityError, "control_pack_binding")


_EVALUATION_RESULT_FIELDS: Final[tuple[str, ...]] = (
    "evaluation_id", "obligation_id", "revision", "rule_version", "evidence_ids",
    "authority_id", "evaluated_at_ms", "owed_cents", "claimed_adjustment_cents",
    "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents",
    "cash_satisfied", "amount_satisfied", "timely", "reporting_complete",
    "verification_status", "case_status", "delivery_status",
)


def _digest_input(value: object, label: str) -> bytes:
    if type(value) is bytes:
        if len(value) != 64:
            _fail(FinancialInputError, label)
        return value
    if type(value) is not str or re.fullmatch(r"[0-9A-Fa-f]{128}", value) is None:
        _fail(FinancialInputError, label)
    try:
        result = bytes.fromhex(value)
    except ValueError:
        _fail(FinancialInputError, label)
    if len(result) != 64:
        _fail(FinancialInputError, label)
    return result


def _evaluation_result_body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in _EVALUATION_RESULT_FIELDS}


# Obligation projection columns an evaluation writes, in the order the UPDATE statements bind them.
_PROJECTION_FIELDS: Final[tuple[str, ...]] = (*_DECIDED_VALUES[1:6], *_DECIDED_FLAGS, *_DECIDED_VALUES[6:])


def _decided_evaluation(decided: Any, evaluation_id: str, obligation_id: str, revision: int) -> dict[str, Any]:
    """Evaluation result fields from a decided outcome (batch decision or accepted correction)."""
    return {
        "evaluation_id": evaluation_id,
        "obligation_id": obligation_id,
        "revision": revision,
        "rule_version": decided.rule_version,
        "evidence_ids": list(decided.evidence_ids),
        "authority_id": decided.authority_id,
        "evaluated_at_ms": decided.evaluated_at_ms,
        **{field: getattr(decided, field) for field in _DECIDED_VALUES},
        **{field: int(getattr(decided, field)) for field in _DECIDED_FLAGS},
    }


def _evaluation_receipt_body(
    *,
    result: Mapping[str, Any],
    scope: Mapping[str, str],
    control_pack_id: str,
    control_pack_version: int,
    control_pack_digest: bytes,
    evidence_bindings: list[dict[str, str]],
    authority_id: str,
    authority_epoch: int,
    authority_digest: bytes,
    input_snapshot_digest: bytes,
    result_digest: bytes,
) -> dict[str, Any]:
    return {
        "contract_version": _EVALUATION_RECEIPT_CONTRACT,
        "scope": dict(scope),
        "evaluation_id": str(result["evaluation_id"]),
        "obligation_id": str(result["obligation_id"]),
        "revision": int(result["revision"]),
        "control_pack": {
            "pack_id": control_pack_id,
            "version": control_pack_version,
            "digest": _hex(control_pack_digest),
        },
        "evidence_bindings": evidence_bindings,
        "input_snapshot_digest": _hex(input_snapshot_digest),
        "authority": {
            "authority_id": authority_id,
            "epoch": authority_epoch,
            "digest": _hex(authority_digest),
        },
        **_evaluation_result_body(result),
        "result_digest": _hex(result_digest),
    }


def _evaluation_binding_digest(bindings: Iterable[Mapping[str, Any]]) -> bytes:
    ordered = sorted(
        (_cols(binding, str, "evaluation_id", "input_snapshot_digest", "result_digest", "receipt_digest") for binding in bindings),
        key=lambda binding: binding["evaluation_id"],
    )
    return _digest(_EVALUATION_EVENT_DOMAIN, _canonical({"evaluations": ordered}))


def _determination_digest_payload(
    *,
    action_id: str,
    determination_id: str,
    obligation_id: str,
    kind: str,
    claim_id: str,
    decision: str,
    amount_cents: int,
    input_evaluation_id: str,
    input_evaluation_result_digest: bytes,
    actor_id: str,
    actor_role: str,
    authority_id: str,
    authority_epoch: int,
    authority_digest: bytes,
    supporting_evidence: list[dict[str, str]],
    expected_revision: int,
    resulting_revision: int,
    decided_at_ms: int,
) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "determination_id": determination_id,
        "obligation_id": obligation_id,
        "kind": kind,
        "claim_id": claim_id,
        "decision": decision,
        "amount_cents": amount_cents,
        "input_evaluation_id": input_evaluation_id,
        "input_evaluation_result_digest": _hex(input_evaluation_result_digest),
        "actor_id": actor_id,
        "actor_role": actor_role,
        "authority_id": authority_id,
        "authority_epoch": authority_epoch,
        "authority_digest": _hex(authority_digest),
        "supporting_evidence": supporting_evidence,
        "expected_revision": expected_revision,
        "resulting_revision": resulting_revision,
        "decided_at_ms": decided_at_ms,
    }


@dataclass(frozen=True, slots=True)
class PopulationItem:
    population_id: str
    item_id: str
    display_label: str
    owed_cents: int
    due_at_ms: int
    currency: str = _CURRENCY
    included: bool = True

    def __post_init__(self) -> None:
        _id(self.population_id, "population_id")
        _id(self.item_id, "item_id")
        _text(self.display_label, "display_label", max_bytes=128)
        _cents(self.owed_cents, "owed_cents", nonnegative=True)
        if self.owed_cents == 0:
            _fail(FinancialInputError, "owed_cents_zero")
        _time(self.due_at_ms, "due_at_ms")
        if self.currency != _CURRENCY or type(self.included) is not bool or not self.included:
            _fail(FinancialInputError, "population_item_scope")

    @property
    def digest(self) -> bytes:
        return _digest(_EVIDENCE_DOMAIN, _canonical({"population_id": self.population_id, "item_id": self.item_id, "display_label": self.display_label, "owed_cents": self.owed_cents, "due_at_ms": self.due_at_ms, "currency": self.currency}))


@dataclass(frozen=True, slots=True)
class PopulationManifest:
    """Separately authored synthetic source receipt for an exact population."""

    manifest_id: str
    manifest_version: int
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    pack_id: str
    cutoff_ms: int
    inclusion_rules: tuple[str, ...]
    source_owner_id: str
    authority_id: str
    authority_epoch: int
    authority_digest: bytes
    approved_by: str
    approval_ref: str
    source_id: str
    source_version: str
    source_digest: bytes
    member_ids: tuple[str, ...]
    supersedes_manifest_id: str | None = None
    supersedes_digest: bytes | None = None
    currency: str = _CURRENCY

    def __post_init__(self) -> None:
        for value, label in (
            (self.manifest_id, "population_manifest_id"),
            (self.state_id, "population_manifest_state"),
            (self.deployment_id, "population_manifest_deployment"),
            (self.program_id, "population_manifest_program"),
            (self.period_id, "population_manifest_period"),
            (self.pack_id, "population_manifest_pack"),
            (self.source_owner_id, "population_manifest_source_owner"),
            (self.authority_id, "population_manifest_authority"),
            (self.approved_by, "population_manifest_approver"),
            (self.approval_ref, "population_manifest_approval_ref"),
            (self.source_id, "population_manifest_source"),
        ):
            _id(value, label)
        if self.supersedes_manifest_id is not None:
            _id(self.supersedes_manifest_id, "population_manifest_supersedes")
        if type(self.manifest_version) is not int or not 1 <= self.manifest_version <= _MAX_ROWS:
            _fail(FinancialInputError, "population_manifest_version")
        if type(self.authority_epoch) is not int or self.authority_epoch < 1:
            _fail(FinancialInputError, "population_manifest_authority_epoch")
        _time(self.cutoff_ms, "population_manifest_cutoff")
        if self.currency != _CURRENCY:
            _fail(FinancialInputError, "population_manifest_currency")
        if type(self.inclusion_rules) is not tuple or not self.inclusion_rules:
            _fail(FinancialInputError, "population_manifest_rules")
        for rule in self.inclusion_rules:
            _text(rule, "population_manifest_rule")
        _text(self.source_version, "population_manifest_source_version")
        _blob(self.authority_digest, 64, "population_manifest_authority_digest")
        _blob(self.source_digest, 64, "population_manifest_source_digest")
        if type(self.member_ids) is not tuple or not 1 <= len(self.member_ids) <= _MAX_ROWS:
            _fail(FinancialInputError, "population_manifest_members")
        for member_id in self.member_ids:
            _id(member_id, "population_manifest_member")
        if tuple(sorted(set(self.member_ids))) != self.member_ids:
            _fail(FinancialInputError, "population_manifest_member_order")
        if (self.supersedes_manifest_id is None) != (self.supersedes_digest is None):
            _fail(FinancialInputError, "population_manifest_supersedes_binding")
        if self.supersedes_digest is not None:
            _blob(self.supersedes_digest, 64, "population_manifest_supersedes_digest")

    @property
    def member_digest(self) -> bytes:
        return _digest(
            _POPULATION_MANIFEST_MEMBERS_DOMAIN,
            _canonical({"member_ids": list(self.member_ids)}),
        )

    @property
    def canonical_bytes(self) -> bytes:
        body = {
            "contract": _POPULATION_MANIFEST_CONTRACT,
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "scope": _attrs(self, *_SCOPE_KEYS),
            "pack_id": self.pack_id,
            "cutoff_ms": self.cutoff_ms,
            "inclusion_rules": list(self.inclusion_rules),
            "source_owner_id": self.source_owner_id,
            "authority": {
                "authority_id": self.authority_id,
                "epoch": self.authority_epoch,
                "digest": _hex(self.authority_digest),
            },
            "approved_by": self.approved_by,
            "approval_ref": self.approval_ref,
            "source": {
                "source_id": self.source_id,
                "version": self.source_version,
                "digest": _hex(self.source_digest),
            },
            "member_count": len(self.member_ids),
            "member_ids": list(self.member_ids),
            "member_digest": _hex(self.member_digest),
            "supersedes": None
            if self.supersedes_manifest_id is None
            else {
                "manifest_id": self.supersedes_manifest_id,
                "digest": _hex(self.supersedes_digest),
            },
        }
        return _canonical(body)

    @property
    def digest(self) -> bytes:
        return _digest(_POPULATION_MANIFEST_DOMAIN, self.canonical_bytes)


def _manifest_event_fields(manifest: PopulationManifest, manifest_row: Mapping[str, Any]) -> dict[str, Any]:
    """Manifest binding carried by every POPULATION history event payload."""

    return {
        "manifest_id": manifest.manifest_id,
        "manifest_version": manifest.manifest_version,
        "manifest_digest": _hex(manifest.digest),
        "member_digest": _hex(bytes(manifest_row["member_digest"])),
    }


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    item_id: str
    kind: str
    common_origin_id: str
    source_id: str
    source_version: str
    local_ref: str
    applicable_at_ms: int
    event_at_ms: int
    received_at_ms: int
    content_digest: bytes
    amount_cents: int | None = None
    reversal_of: str | None = None
    supersedes: str | None = None

    def __post_init__(self) -> None:
        for value, label in ((self.evidence_id, "evidence_id"), (self.item_id, "item_id"), (self.common_origin_id, "common_origin_id"), (self.source_id, "source_id"), (self.source_version, "source_version"), (self.local_ref, "local_ref")):
            _id(value, label)
        _kind(self.kind, "evidence_kind")
        for value, label in ((self.applicable_at_ms, "evidence_applicable"), (self.event_at_ms, "evidence_event"), (self.received_at_ms, "evidence_received")):
            _time(value, label)
        if self.event_at_ms > self.received_at_ms:
            _fail(FinancialInputError, "evidence_chronology")
        _blob(self.content_digest, 64, "evidence_content_digest")
        if self.amount_cents is not None:
            _cents(self.amount_cents, "evidence_amount", nonnegative=True)
        if self.reversal_of is not None:
            _id(self.reversal_of, "evidence_reversal_of")
        if self.supersedes is not None:
            _id(self.supersedes, "evidence_supersedes")

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(
            {
                **_attrs(self, "evidence_id", "item_id", "kind", "common_origin_id", "source_id", "source_version", "local_ref", "applicable_at_ms", "event_at_ms", "received_at_ms"),
                "content_digest": _hex(self.content_digest),
                **_attrs(self, "amount_cents", "reversal_of", "supersedes"),
            }
        )

    @property
    def record_digest(self) -> bytes:
        return _digest(_EVIDENCE_DOMAIN, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class FinancialOwnerConfig:
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str = "PROGRAM"
    currency: str = _CURRENCY
    schema_version: int = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        for value, label in ((self.state_id, "state_id"), (self.deployment_id, "deployment_id"), (self.program_id, "program_id"), (self.period_id, "period_id")):
            _id(value, label)
        if self.period_id in _WILDCARD_PERIODS:
            _fail(FinancialInputError, "period_scope_required")
        if self.currency != _CURRENCY:
            _fail(FinancialInputError, "currency")
        if type(self.schema_version) is not int or self.schema_version != _SCHEMA_VERSION:
            _fail(FinancialInputError, "schema_version")

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(_attrs(self, *_SCOPE_KEYS))


@dataclass(frozen=True, slots=True)
class ProgramFundingReceipt:
    """Fictional synthetic, explicitly unapproved evidence about a funding record.

    This record stores no source bytes, authenticates no source, establishes no
    source rights or State approval, authorizes no payment, and makes no claim
    about recipient cash.
    """

    receipt_id: str
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    source_record_ref: str
    amount_cents: int
    event_at_ms: int
    supersedes_receipt_id: str | None = None
    currency: str = _CURRENCY
    confirmation_class: str = _PROGRAM_FUNDING_CONFIRMATION_CLASS
    evidence_status: str = _PROGRAM_FUNDING_EVIDENCE_STATUS

    def __post_init__(self) -> None:
        for value, label in (
            (self.receipt_id, "funding_receipt_id"),
            (self.state_id, "funding_state_id"),
            (self.deployment_id, "funding_deployment_id"),
            (self.program_id, "funding_program_id"),
            (self.period_id, "funding_period_id"),
            (self.source_record_ref, "funding_source_record_ref"),
        ):
            _id(value, label)
        if self.period_id in _WILDCARD_PERIODS:
            _fail(FinancialInputError, "funding_period_scope")
        if self.currency != _CURRENCY:
            _fail(FinancialInputError, "funding_currency")
        if type(self.amount_cents) is not int or not 1 <= self.amount_cents <= _MAX_CENTS:
            _fail(FinancialInputError, "funding_amount_cents")
        _time(self.event_at_ms, "funding_event_at_ms")
        if self.confirmation_class != _PROGRAM_FUNDING_CONFIRMATION_CLASS:
            _fail(FinancialInputError, "funding_confirmation_class")
        if self.evidence_status != _PROGRAM_FUNDING_EVIDENCE_STATUS:
            _fail(FinancialInputError, "funding_evidence_status")
        if self.supersedes_receipt_id is not None:
            _id(self.supersedes_receipt_id, "funding_supersedes_receipt_id")

    def as_record(self) -> dict[str, Any]:
        return {
            "schema": _PROGRAM_FUNDING_RECEIPT_SCHEMA,
            **_attrs(self, "receipt_id", *_SCOPE_KEYS, "source_record_ref", "amount_cents", "confirmation_class", "evidence_status", "event_at_ms", "supersedes_receipt_id"),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(self.as_record())

    @property
    def digest(self) -> bytes:
        return _digest(_PROGRAM_FUNDING_RECEIPT_DOMAIN, self.canonical_bytes)


def _private_index_sql(name: str, table: str, columns: tuple[str, ...]) -> str:
    return f"CREATE INDEX {name} ON {table}({','.join(columns)})"


def _normalized_schema_sql(value: str) -> str:
    return re.sub(r"\s+", "", value).replace('"', "").lower()


def _private_index_set_version(connection: sqlite3.Connection) -> int:
    """The exact private index set present: 0 for none (a store from before them), else its version."""
    version_row = connection.execute("PRAGMA user_version").fetchone()
    version = version_row[0] if version_row is not None else None
    actual: dict[str, str] = {}
    for row in connection.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
    ):
        name, sql = row[0], row[1]
        if type(name) is not str or type(sql) is not str or name in actual:
            _fail(FinancialIntegrityError, "schema_private_indexes")
        actual[name] = sql
    if type(version) is int and version == 0 and not actual:
        return 0
    if type(version) is not int or version not in _PRIVATE_INDEX_SETS:
        _fail(FinancialIntegrityError, "schema_private_indexes")
    expected = {name: _private_index_sql(name, table, columns) for name, table, columns in _PRIVATE_INDEX_SETS[version]}
    if set(actual) != set(expected):
        _fail(FinancialIntegrityError, "schema_private_indexes")
    if any(_normalized_schema_sql(actual[name]) != _normalized_schema_sql(sql) for name, sql in expected.items()):
        _fail(FinancialIntegrityError, "schema_private_indexes")
    for name, table, columns in _PRIVATE_INDEX_SETS[version]:
        listed = [
            row
            for row in connection.execute(f'PRAGMA index_list("{table}")')
            if str(row[1]) == name
        ]
        if len(listed) != 1 or int(listed[0][2]) != 0 or str(listed[0][3]) != "c" or int(listed[0][4]) != 0:
            _fail(FinancialIntegrityError, "schema_private_indexes")
        key_parts = tuple(
            (str(row[2]), int(row[3]), str(row[4]).upper())
            for row in connection.execute(f'PRAGMA index_xinfo("{name}")')
            if int(row[5]) == 1
        )
        if key_parts != tuple((column, 0, "BINARY") for column in columns):
            _fail(FinancialIntegrityError, "schema_private_indexes")
    return version


def _count_rows(connection: sqlite3.Connection) -> dict[str, int]:
    return {table: connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] for table in ("financial_events", *_PROJECTION_TABLES)}


def _install_private_index_set(connection: sqlite3.Connection) -> None:
    found = _private_index_set_version(connection)
    if found == _PRIVATE_INDEX_SET_VERSION:
        return
    present = {name for name, _table, _columns in _PRIVATE_INDEX_SETS.get(found, ())}
    for name, table, columns in _PRIVATE_INDEX_SETS[_PRIVATE_INDEX_SET_VERSION]:
        if name not in present:
            connection.execute(_private_index_sql(name, table, columns))
    connection.execute(f"PRAGMA user_version={_PRIVATE_INDEX_SET_VERSION}")
    if _private_index_set_version(connection) != _PRIVATE_INDEX_SET_VERSION:
        _fail(FinancialIntegrityError, "schema_private_indexes")


def _install_history_append_only(connection: sqlite3.Connection, *, read_only: bool) -> None:
    actual: dict[str, str] = {}
    for row in connection.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='financial_events'"
    ):
        name, sql = row[0], row[1]
        if type(name) is not str or type(sql) is not str or name in actual:
            _fail(FinancialIntegrityError, "schema_history_triggers")
        actual[name] = sql
    if not actual:
        if read_only:
            _fail(FinancialIntegrityError, "shadow_requires_migration")
        for sql in _HISTORY_APPEND_ONLY_TRIGGERS.values():
            connection.execute(sql)
        return
    if set(actual) != set(_HISTORY_APPEND_ONLY_TRIGGERS) or any(
        _normalized_schema_sql(actual[name]) != _normalized_schema_sql(sql)
        for name, sql in _HISTORY_APPEND_ONLY_TRIGGERS.items()
    ):
        _fail(FinancialIntegrityError, "schema_history_triggers")


def _execute_script(connection: sqlite3.Connection, script: str) -> None:
    """Run DDL one statement at a time inside the caller's transaction (``executescript`` would COMMIT first)."""
    statement = ""
    for part in script.split(";"):
        statement += part + ";"
        if sqlite3.complete_statement(statement):
            if statement.strip(" \n;"):
                connection.execute(statement)
            statement = ""
    if statement.strip(" \n;"):
        _fail(FinancialIntegrityError, "schema_script")


def _sql_schema(connection: sqlite3.Connection) -> None:
    _execute_script(
        connection,
        """
        CREATE TABLE financial_identity (
            id INTEGER PRIMARY KEY CHECK (id=1),
            schema_version INTEGER NOT NULL,
            provenance TEXT NOT NULL CHECK (provenance IN ('ROOT','CONTINUITY_RESTORE')),
            bound_mode TEXT NOT NULL CHECK (bound_mode IN ('LIVE','SHADOW','TEST')),
            bound_owner_id TEXT NOT NULL,
            anchor_sequence INTEGER NOT NULL CHECK (anchor_sequence>=0),
            anchor_head BLOB NOT NULL CHECK (length(anchor_head)=64),
            genesis_head BLOB NOT NULL CHECK (length(genesis_head)=64),
            source_package_digest BLOB NOT NULL CHECK (length(source_package_digest)=64),
            identity_digest BLOB NOT NULL CHECK (length(identity_digest)=64)
        );
        CREATE TABLE financial_meta (
            id INTEGER PRIMARY KEY CHECK (id=1),
            schema_version INTEGER NOT NULL,
            schema TEXT NOT NULL,
            state_id TEXT NOT NULL,
            deployment_id TEXT NOT NULL,
            program_id TEXT NOT NULL,
            period_id TEXT NOT NULL,
            currency TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence>=0),
            history_head BLOB NOT NULL CHECK (length(history_head)=64),
            continuity_epoch INTEGER NOT NULL CHECK (continuity_epoch>=1),
            dispatch_enabled INTEGER NOT NULL CHECK (dispatch_enabled=0),
            egress_enabled INTEGER NOT NULL CHECK (egress_enabled=0),
            trusted_authority_id TEXT NOT NULL,
            trusted_authority_epoch INTEGER NOT NULL CHECK (trusted_authority_epoch>=1),
            trusted_authority_digest BLOB NOT NULL CHECK (length(trusted_authority_digest)=64),
            mode TEXT NOT NULL CHECK (mode IN ('LIVE','SHADOW','TEST')),
            owner_id TEXT NOT NULL
        );
        CREATE TABLE control_packs (
            pack_id TEXT PRIMARY KEY,
            state_id TEXT NOT NULL,
            deployment_id TEXT NOT NULL,
            program_id TEXT NOT NULL,
            period_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            source_refs_json TEXT NOT NULL,
            effective_start_ms INTEGER NOT NULL,
            effective_end_ms INTEGER NOT NULL,
            recorded_at_ms INTEGER NOT NULL,
            approved_at_ms INTEGER NOT NULL,
            calculation_rule_id TEXT NOT NULL,
            adjustment_rule_id TEXT NOT NULL,
            authorized_roles_json TEXT NOT NULL,
            expected_tests_json TEXT NOT NULL,
            pack_digest BLOB NOT NULL CHECK (length(pack_digest)=64),
            status TEXT NOT NULL CHECK (status IN ('APPROVED','WITHDRAWN'))
        );
        CREATE TABLE population_imports (
            population_id TEXT PRIMARY KEY,
            pack_id TEXT NOT NULL REFERENCES control_packs(pack_id) DEFERRABLE INITIALLY DEFERRED,
            cutoff_ms INTEGER NOT NULL,
            inclusion_rules_json TEXT NOT NULL,
            expected_count INTEGER NOT NULL CHECK (expected_count>0),
            source_complete INTEGER NOT NULL CHECK (source_complete IN (0,1)),
            imported_count INTEGER NOT NULL CHECK (imported_count>=0),
            validated_count INTEGER NOT NULL CHECK (validated_count>=0),
            validation_digest BLOB,
            status TEXT NOT NULL CHECK (status IN ('STAGED','VALIDATED','PUBLISHED')),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE population_items (
            population_id TEXT NOT NULL REFERENCES population_imports(population_id) DEFERRABLE INITIALLY DEFERRED,
            item_id TEXT NOT NULL,
            display_label TEXT NOT NULL,
            owed_cents INTEGER NOT NULL CHECK (owed_cents>0),
            due_at_ms INTEGER NOT NULL,
            currency TEXT NOT NULL,
            PRIMARY KEY (population_id,item_id)
        );
        CREATE TABLE obligations (
            obligation_id TEXT PRIMARY KEY,
            population_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            period_id TEXT NOT NULL,
            currency TEXT NOT NULL,
            owed_cents INTEGER NOT NULL CHECK (owed_cents>0),
            due_at_ms INTEGER NOT NULL,
            rule_version INTEGER NOT NULL CHECK (rule_version>0),
            revision INTEGER NOT NULL CHECK (revision>=0),
            claimed_adjustment_cents INTEGER NOT NULL CHECK (claimed_adjustment_cents>=0),
            lawful_adjustment_cents INTEGER NOT NULL CHECK (lawful_adjustment_cents>=0),
            received_cash_cents INTEGER NOT NULL CHECK (received_cash_cents>=0),
            shortfall_cents INTEGER NOT NULL CHECK (shortfall_cents>=0),
            overage_cents INTEGER NOT NULL CHECK (overage_cents>=0),
            cash_satisfied INTEGER NOT NULL CHECK (cash_satisfied IN (0,1)),
            amount_satisfied INTEGER NOT NULL CHECK (amount_satisfied IN (0,1)),
            timely INTEGER NOT NULL CHECK (timely IN (0,1)),
            reporting_complete INTEGER NOT NULL CHECK (reporting_complete IN (0,1)),
            verification_status TEXT NOT NULL,
            case_status TEXT NOT NULL,
            delivery_status TEXT NOT NULL,
            current_evaluation_id TEXT REFERENCES evaluations(evaluation_id) DEFERRABLE INITIALLY DEFERRED,
            updated_at_ms INTEGER NOT NULL,
            UNIQUE (population_id,item_id),
            FOREIGN KEY (population_id,item_id) REFERENCES population_items(population_id,item_id) DEFERRABLE INITIALLY DEFERRED
        );
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            item_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            common_origin_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_version TEXT NOT NULL,
            local_ref TEXT NOT NULL,
            applicable_at_ms INTEGER NOT NULL,
            event_at_ms INTEGER NOT NULL,
            received_at_ms INTEGER NOT NULL,
            content_digest BLOB NOT NULL CHECK (length(content_digest)=64),
            record_digest BLOB NOT NULL CHECK (length(record_digest)=64),
            amount_cents INTEGER,
            reversal_of TEXT REFERENCES payments(payment_id) DEFERRABLE INITIALLY DEFERRED,
            supersedes TEXT REFERENCES evidence(evidence_id) DEFERRABLE INITIALLY DEFERRED
        );
        CREATE TABLE payments (
            payment_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL REFERENCES obligations(obligation_id) DEFERRABLE INITIALLY DEFERRED,
            item_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) DEFERRABLE INITIALLY DEFERRED,
            common_origin_id TEXT NOT NULL,
            amount_cents INTEGER NOT NULL CHECK (amount_cents>0),
            event_at_ms INTEGER NOT NULL,
            active INTEGER NOT NULL CHECK (active IN (0,1)),
            reversed_by_evidence_id TEXT REFERENCES evidence(evidence_id) DEFERRABLE INITIALLY DEFERRED,
            UNIQUE (obligation_id,common_origin_id)
        );
        CREATE TABLE claimed_adjustments (
            claim_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL REFERENCES obligations(obligation_id) DEFERRABLE INITIALLY DEFERRED,
            evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) DEFERRABLE INITIALLY DEFERRED,
            amount_cents INTEGER NOT NULL CHECK (amount_cents>0),
            owner_role TEXT NOT NULL,
            deadline_ms INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('CLAIMED','AUTHORIZED','REJECTED')),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE cases (
            case_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL REFERENCES obligations(obligation_id) DEFERRABLE INITIALLY DEFERRED,
            reason TEXT NOT NULL,
            contractual_accountability TEXT NOT NULL,
            next_action_owner TEXT NOT NULL,
            due_at_ms INTEGER NOT NULL,
            completion_conditions_json TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE determinations (
            determination_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL REFERENCES obligations(obligation_id) DEFERRABLE INITIALLY DEFERRED,
            claim_id TEXT REFERENCES claimed_adjustments(claim_id) DEFERRABLE INITIALLY DEFERRED,
            actor_id TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            authority_id TEXT NOT NULL,
            authority_epoch INTEGER NOT NULL,
            authority_digest BLOB NOT NULL CHECK (length(authority_digest)=64),
            decision TEXT NOT NULL,
            amount_cents INTEGER NOT NULL CHECK (amount_cents>=0),
            supporting_evidence_json TEXT NOT NULL,
            expected_revision INTEGER NOT NULL,
            resulting_revision INTEGER NOT NULL,
            decided_at_ms INTEGER NOT NULL,
            determination_digest BLOB NOT NULL CHECK (length(determination_digest)=64),
            input_evaluation_id TEXT NOT NULL REFERENCES evaluations(evaluation_id) DEFERRABLE INITIALLY DEFERRED,
            input_evaluation_result_digest BLOB NOT NULL CHECK (length(input_evaluation_result_digest)=64),
            UNIQUE (input_evaluation_id)
        );
        CREATE TABLE actions (
            action_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL REFERENCES obligations(obligation_id) DEFERRABLE INITIALLY DEFERRED,
            determination_id TEXT NOT NULL REFERENCES determinations(determination_id) DEFERRABLE INITIALLY DEFERRED,
            kind TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('READY','ACKNOWLEDGED','CANCELLED')),
            revision INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            payload_digest BLOB NOT NULL CHECK (length(payload_digest)=64),
            idempotency_key BLOB NOT NULL CHECK (length(idempotency_key)=64),
            created_at_ms INTEGER NOT NULL
        );
        CREATE TABLE action_outbox (
            action_id TEXT PRIMARY KEY REFERENCES actions(action_id) DEFERRABLE INITIALLY DEFERRED,
            status TEXT NOT NULL CHECK (status IN ('READY','ACKNOWLEDGED','CANCELLED')),
            attempt INTEGER NOT NULL CHECK (attempt>=0),
            payload_digest BLOB NOT NULL CHECK (length(payload_digest)=64),
            acknowledgment_ref TEXT,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE financial_events (
            event_sequence INTEGER PRIMARY KEY,
            event_id BLOB NOT NULL UNIQUE CHECK (length(event_id)=64),
            aggregate_type TEXT NOT NULL,
            aggregate_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            before_revision INTEGER NOT NULL,
            after_revision INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            payload_digest BLOB NOT NULL CHECK (length(payload_digest)=64),
            previous_head BLOB NOT NULL CHECK (length(previous_head)=64),
            head BLOB NOT NULL CHECK (length(head)=64),
            committed_at_ms INTEGER NOT NULL
        );
        CREATE TABLE financial_conflicts (
            conflict_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL REFERENCES obligations(obligation_id) DEFERRABLE INITIALLY DEFERRED,
            common_origin_id TEXT NOT NULL,
            existing_payment_id TEXT REFERENCES payments(payment_id) DEFERRABLE INITIALLY DEFERRED,
            candidate_evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) DEFERRABLE INITIALLY DEFERRED,
            existing_amount_cents INTEGER,
            candidate_amount_cents INTEGER,
            reason TEXT NOT NULL,
            visible_at_ms INTEGER NOT NULL
        );
        CREATE TABLE evaluations (
            evaluation_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL REFERENCES obligations(obligation_id) DEFERRABLE INITIALLY DEFERRED,
            revision INTEGER NOT NULL,
            rule_version INTEGER NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            authority_id TEXT NOT NULL,
            evaluated_at_ms INTEGER NOT NULL,
            owed_cents INTEGER NOT NULL,
            claimed_adjustment_cents INTEGER NOT NULL,
            lawful_adjustment_cents INTEGER NOT NULL,
            received_cash_cents INTEGER NOT NULL,
            shortfall_cents INTEGER NOT NULL,
            overage_cents INTEGER NOT NULL,
            cash_satisfied INTEGER NOT NULL,
            amount_satisfied INTEGER NOT NULL,
            timely INTEGER NOT NULL,
            reporting_complete INTEGER NOT NULL,
            verification_status TEXT NOT NULL,
            case_status TEXT NOT NULL,
            delivery_status TEXT NOT NULL,
            result_digest BLOB NOT NULL CHECK (length(result_digest)=64),
            contract_version TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            control_pack_id TEXT NOT NULL REFERENCES control_packs(pack_id) DEFERRABLE INITIALLY DEFERRED,
            control_pack_version INTEGER NOT NULL,
            control_pack_digest BLOB NOT NULL CHECK (length(control_pack_digest)=64),
            authority_epoch INTEGER NOT NULL,
            authority_digest BLOB NOT NULL CHECK (length(authority_digest)=64),
            evidence_bindings_json TEXT NOT NULL,
            input_snapshot_json TEXT NOT NULL,
            input_snapshot_digest BLOB NOT NULL CHECK (length(input_snapshot_digest)=64),
            receipt_digest BLOB NOT NULL CHECK (length(receipt_digest)=64)
        );
        CREATE TRIGGER action_payload_immutable
        BEFORE UPDATE OF action_id,obligation_id,determination_id,kind,revision,payload_json,payload_digest,idempotency_key,created_at_ms ON actions
        BEGIN SELECT RAISE(ABORT,'action_payload_immutable'); END;
        CREATE TRIGGER action_outbox_payload_immutable
        BEFORE UPDATE OF action_id,payload_digest ON action_outbox
        BEGIN SELECT RAISE(ABORT,'action_outbox_payload_immutable'); END;
        CREATE TRIGGER evidence_record_immutable
        BEFORE UPDATE OF evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,content_digest,record_digest,amount_cents,reversal_of,supersedes ON evidence
        BEGIN SELECT RAISE(ABORT,'evidence_record_immutable'); END;
        CREATE TRIGGER financial_identity_insert_immutable
        BEFORE INSERT ON financial_identity
        WHEN EXISTS (SELECT 1 FROM financial_identity)
        BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END;
        CREATE TRIGGER financial_identity_update_immutable
        BEFORE UPDATE OF schema_version,provenance,bound_mode,bound_owner_id,anchor_sequence,anchor_head,genesis_head,source_package_digest,identity_digest ON financial_identity
        BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END;
        CREATE TRIGGER financial_identity_delete_immutable
        BEFORE DELETE ON financial_identity
        BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END;
            CREATE TABLE program_funding_receipts (
                receipt_id TEXT PRIMARY KEY,
                state_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                program_id TEXT NOT NULL,
                period_id TEXT NOT NULL,
                currency TEXT NOT NULL CHECK (currency='USD'),
                source_record_ref TEXT NOT NULL,
                amount_cents INTEGER NOT NULL CHECK (amount_cents>0),
                confirmation_class TEXT NOT NULL CHECK (confirmation_class='STATE_PAYMENT_RECORD'),
                evidence_status TEXT NOT NULL CHECK (evidence_status='SYNTHETIC_UNAPPROVED'),
                event_at_ms INTEGER NOT NULL CHECK (event_at_ms>=0),
                recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms>=0),
                supersedes_receipt_id TEXT UNIQUE REFERENCES program_funding_receipts(receipt_id) DEFERRABLE INITIALLY DEFERRED,
                receipt_digest BLOB NOT NULL CHECK (length(receipt_digest)=64)
            );
            CREATE TABLE program_funding_projection (
                source_record_ref TEXT PRIMARY KEY,
                receipt_id TEXT NOT NULL UNIQUE REFERENCES program_funding_receipts(receipt_id) DEFERRABLE INITIALLY DEFERRED,
                amount_cents INTEGER NOT NULL CHECK (amount_cents>0),
                event_at_ms INTEGER NOT NULL CHECK (event_at_ms>=0),
                revision INTEGER NOT NULL CHECK (revision>0),
                receipt_digest BLOB NOT NULL CHECK (length(receipt_digest)=64)
            );
            CREATE TRIGGER program_funding_receipt_update_immutable
            BEFORE UPDATE ON program_funding_receipts
            BEGIN SELECT RAISE(ABORT,'program_funding_receipt_immutable'); END;
            CREATE TRIGGER program_funding_receipt_delete_immutable
            BEFORE DELETE ON program_funding_receipts
            BEGIN SELECT RAISE(ABORT,'program_funding_receipt_immutable'); END;
            CREATE TABLE population_manifests (
                manifest_id TEXT PRIMARY KEY,
                contract TEXT NOT NULL CHECK (contract='RR/FINANCIAL/POPULATION-MANIFEST/v1'),
                manifest_version INTEGER NOT NULL CHECK (manifest_version>0),
                state_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                program_id TEXT NOT NULL,
                period_id TEXT NOT NULL,
                currency TEXT NOT NULL CHECK (currency='USD'),
                pack_id TEXT NOT NULL REFERENCES control_packs(pack_id) DEFERRABLE INITIALLY DEFERRED,
                cutoff_ms INTEGER NOT NULL CHECK (cutoff_ms>=0),
                inclusion_rules_json TEXT NOT NULL,
                source_owner_id TEXT NOT NULL,
                authority_id TEXT NOT NULL,
                authority_epoch INTEGER NOT NULL CHECK (authority_epoch>0),
                authority_digest BLOB NOT NULL CHECK (length(authority_digest)=64),
                approved_by TEXT NOT NULL,
                approval_ref TEXT NOT NULL,
                source_id TEXT NOT NULL,
                source_version TEXT NOT NULL,
                source_digest BLOB NOT NULL CHECK (length(source_digest)=64),
                member_count INTEGER NOT NULL CHECK (member_count>0),
                member_digest BLOB NOT NULL CHECK (length(member_digest)=64),
                supersedes_manifest_id TEXT UNIQUE REFERENCES population_manifests(manifest_id) DEFERRABLE INITIALLY DEFERRED,
                supersedes_digest BLOB CHECK (supersedes_digest IS NULL OR length(supersedes_digest)=64),
                manifest_digest BLOB NOT NULL CHECK (length(manifest_digest)=64),
                registered_at_ms INTEGER NOT NULL CHECK (registered_at_ms>=0),
                UNIQUE (state_id,deployment_id,program_id,period_id,pack_id,cutoff_ms,source_owner_id,manifest_version)
            );
            CREATE TABLE population_manifest_members (
                manifest_id TEXT NOT NULL REFERENCES population_manifests(manifest_id) DEFERRABLE INITIALLY DEFERRED,
                position INTEGER NOT NULL CHECK (position>=0),
                member_id TEXT NOT NULL,
                PRIMARY KEY (manifest_id,position),
                UNIQUE (manifest_id,member_id)
            );
            CREATE TABLE population_manifest_heads (
                state_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                program_id TEXT NOT NULL,
                period_id TEXT NOT NULL,
                currency TEXT NOT NULL CHECK (currency='USD'),
                pack_id TEXT NOT NULL REFERENCES control_packs(pack_id) DEFERRABLE INITIALLY DEFERRED,
                cutoff_ms INTEGER NOT NULL CHECK (cutoff_ms>=0),
                source_owner_id TEXT NOT NULL,
                manifest_id TEXT NOT NULL UNIQUE REFERENCES population_manifests(manifest_id) DEFERRABLE INITIALLY DEFERRED,
                manifest_version INTEGER NOT NULL CHECK (manifest_version>0),
                manifest_digest BLOB NOT NULL CHECK (length(manifest_digest)=64),
                updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms>=0),
                PRIMARY KEY (state_id,deployment_id,program_id,period_id,pack_id,cutoff_ms,source_owner_id)
            );
            CREATE TABLE population_manifest_bindings (
                population_id TEXT PRIMARY KEY REFERENCES population_imports(population_id) DEFERRABLE INITIALLY DEFERRED,
                manifest_id TEXT NOT NULL UNIQUE REFERENCES population_manifests(manifest_id) DEFERRABLE INITIALLY DEFERRED,
                manifest_version INTEGER NOT NULL CHECK (manifest_version>0),
                manifest_digest BLOB NOT NULL CHECK (length(manifest_digest)=64)
            );
            CREATE TRIGGER population_manifest_update_immutable
            BEFORE UPDATE ON population_manifests
            BEGIN SELECT RAISE(ABORT,'population_manifest_immutable'); END;
            CREATE TRIGGER population_manifest_delete_immutable
            BEFORE DELETE ON population_manifests
            BEGIN SELECT RAISE(ABORT,'population_manifest_immutable'); END;
            CREATE TRIGGER population_manifest_member_update_immutable
            BEFORE UPDATE ON population_manifest_members
            BEGIN SELECT RAISE(ABORT,'population_manifest_member_immutable'); END;
            CREATE TRIGGER population_manifest_member_delete_immutable
            BEFORE DELETE ON population_manifest_members
            BEGIN SELECT RAISE(ABORT,'population_manifest_member_immutable'); END;
            CREATE TRIGGER population_manifest_binding_update_immutable
            BEFORE UPDATE ON population_manifest_bindings
            BEGIN SELECT RAISE(ABORT,'population_manifest_binding_immutable'); END;
            CREATE TRIGGER population_manifest_binding_delete_immutable
            BEFORE DELETE ON population_manifest_bindings
            BEGIN SELECT RAISE(ABORT,'population_manifest_binding_immutable'); END;
            CREATE TABLE commands (
                command_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                request_json TEXT NOT NULL,
                request_digest BLOB NOT NULL CHECK (length(request_digest)=64),
                event_sequence INTEGER NOT NULL UNIQUE REFERENCES financial_events(event_sequence) DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TRIGGER command_update_immutable
            BEFORE UPDATE ON commands
            BEGIN SELECT RAISE(ABORT,'command_immutable'); END;
            CREATE TRIGGER command_delete_immutable
            BEFORE DELETE ON commands
            BEGIN SELECT RAISE(ABORT,'command_immutable'); END;
        """,
    )
    for sql in _HISTORY_APPEND_ONLY_TRIGGERS.values():
        connection.execute(sql)
    _execute_script(connection, _SEGMENT_SCHEMA)
    _install_private_index_set(connection)  # born current: a read-only (SHADOW) open never upgrades


# Sealed segments keep only what history cannot regenerate (their row images);
# pending holds the events and rows the open segment has touched, open its size.
_SEGMENT_SCHEMA: Final[str] = """
    CREATE TABLE history_segments (
        segment_index INTEGER PRIMARY KEY CHECK (segment_index>=0),
        first_sequence INTEGER NOT NULL CHECK (first_sequence>=1),
        last_sequence INTEGER NOT NULL UNIQUE CHECK (last_sequence>=first_sequence),
        previous_digest BLOB NOT NULL CHECK (length(previous_digest)=64),
        event_head BLOB NOT NULL CHECK (length(event_head)=64),
        projection_root BLOB NOT NULL CHECK (length(projection_root)=64),
        segment_digest BLOB NOT NULL UNIQUE CHECK (length(segment_digest)=64),
        rows_json TEXT NOT NULL
    );
    CREATE TRIGGER history_segment_update_immutable BEFORE UPDATE ON history_segments BEGIN SELECT RAISE(ABORT,'history_segment_immutable'); END;
    CREATE TRIGGER history_segment_delete_immutable BEFORE DELETE ON history_segments BEGIN SELECT RAISE(ABORT,'history_segment_immutable'); END;
    CREATE TABLE history_pending (
        table_name TEXT NOT NULL,
        row_key INTEGER NOT NULL,
        record_bytes INTEGER NOT NULL CHECK (record_bytes>0),
        PRIMARY KEY (table_name,row_key)
    ) WITHOUT ROWID;
    CREATE TABLE history_open (
        id INTEGER PRIMARY KEY CHECK (id=1),
        event_count INTEGER NOT NULL CHECK (event_count>=0),
        byte_count INTEGER NOT NULL CHECK (byte_count>=0)
    );
    INSERT INTO history_open VALUES (1,0,0);
"""


def _replace_file(path: Path, data: bytes) -> None:
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.unlink(missing_ok=True)  # a leftover, or a planted link, is removed itself, never written through
    with temporary.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name == "nt":  # Windows cannot sync a directory; the rename itself is written through
        if not ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW(str(temporary), str(path), 0x1 | 0x8):  # REPLACE_EXISTING | WRITE_THROUGH
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _segment_seal(index: int, first: int, last: int, previous: bytes, head: bytes, root: bytes) -> dict[str, Any]:
    return {"format": _SEGMENT_FORMAT, "segment_index": index, "first_sequence": first, "last_sequence": last, "event_count": last - first + 1, "previous_digest": _hex(previous), "event_head": _hex(head), "projection_root": _hex(root)}


class FinancialOwner:
    """The sole writer for the synthetic financial responsibility."""

    def __init__(
        self,
        *,
        path: Path,
        config: FinancialOwnerConfig,
        trusted_authority: SyntheticTrustedAuthority | None,
        clock: FinancialClock | None = None,
        mode: str = "LIVE",
        owner_id: str = "financial-owner-v1",
        existing_only: bool = False,
        custody: Any = None,
    ) -> None:
        created = isinstance(path, Path) and not path.exists()
        self._initialize(
            path=path,
            config=config,
            trusted_authority=trusted_authority,
            clock=clock,
            mode=mode,
            owner_id=owner_id,
            identity_contract=None,
            existing_only=existing_only,
        )
        self._verify_open_identity(verify_history=True)
        if custody is not None:  # H2: the custody log outside the store (app/right_rail_financial_custody.py), before any write
            try:
                custody.open(self.owner_id, path, self._high, self._head_at, created=created)
            except BaseException:
                self._discard_writer()
                raise
        self._custody = custody

    def _verify_history_in_transaction(self, connection: sqlite3.Connection) -> None:
        """Replay the stored history against its projections before any use (Art. III.5).

        The independent checker recomputes the hash chain and the
        history-to-projection bindings on this uncommitted open transaction; on a
        mismatch the open (and any migration in it) rolls back, so the Owner never
        writes on top of state its own history does not explain.
        """
        from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_database_connection

        try:
            verify_database_connection(connection, **self._checker_expectations())
        except IndependentFinancialError as error:
            _fail(FinancialIntegrityError, f"open_verification:{error}")

    @classmethod
    def _open_restore_destination(
        cls,
        *,
        path: Path,
        config: FinancialOwnerConfig,
        trusted_authority: SyntheticTrustedAuthority,
        clock: FinancialClock | None,
        mode: str,
        owner_id: str,
        identity_contract: Mapping[str, Any],
    ) -> "FinancialOwner":
        """Create a fresh restore target; only ``restore_continuity`` may call this.

        The imported rows do not exist yet, so identity verification is deferred
        to ``restore_continuity``, which verifies the open identity and runs the
        independent checker before the destination is published.
        """
        if not isinstance(identity_contract, Mapping):
            _fail(FinancialIntegrityError, "identity_contract_required")
        owner = cls.__new__(cls)
        owner._initialize(
            path=path,
            config=config,
            trusted_authority=trusted_authority,
            clock=clock,
            mode=mode,
            owner_id=owner_id,
            identity_contract=identity_contract,
        )
        return owner

    def _initialize(
        self,
        *,
        path: Path,
        config: FinancialOwnerConfig,
        trusted_authority: SyntheticTrustedAuthority | None,
        clock: FinancialClock | None,
        mode: str,
        owner_id: str,
        identity_contract: Mapping[str, Any] | None,
        existing_only: bool = False,
    ) -> None:
        if not isinstance(path, Path) or not path.parent.is_dir() or path.is_symlink():
            _fail(FinancialIntegrityError, "owner_path")
        if mode not in _MODES:
            _fail(FinancialInputError, "owner_mode")
        if trusted_authority is None or type(trusted_authority) is not SyntheticTrustedAuthority:
            _fail(FinancialAuthorityError, "trusted_authority_required")
        if type(clock) is not type(None) and not hasattr(clock, "now_ms"):
            _fail(FinancialInputError, "clock")
        self.path = path
        self._existing_only = existing_only
        self.config = config
        self.schema_version = _SCHEMA_VERSION
        self.schema = _SCHEMA
        self.continuity_schema = _CONTINUITY_SCHEMA
        self._tables = _PACKAGE_TABLES
        self._table_columns = _TABLE_COLUMNS
        self.trusted_authority = trusted_authority
        self.clock: FinancialClock = clock if clock is not None else _SystemClock()
        self.mode = mode
        self.owner_id = _id(owner_id, "owner_id")
        self._batch = threading.local()  # .connection: the open run_batch transaction on this thread; .rows: its base counts
        self._lock = threading.RLock()  # R1a: one writer connection, one transaction at a time
        self._writer: sqlite3.Connection | None = None  # R1a: kept from the open; any error discards it with the mark and cache
        self._mark: tuple[int, int, int] | None = None  # (data_version, device, file index) where the writer last verified or wrote
        self._row_cache: tuple[tuple[object, ...], dict[str, int]] | None = None  # (history mark, rows per table) at that point
        self._refusal: FinancialError | None = None  # a failed re-verification, raised once the command's own checks pass
        self._high: tuple[object, ...] | None = None  # (sequence, head) last verified or committed; kept for the object's life
        self._packs: dict[tuple[object, ...], tuple[ControlPack, str, str]] = {}  # the pack, its digest check and its policy are pure functions of the exact row
        self._custody: Any = None  # H2: set once the open's custody check passes
        if self.mode == "TEST" and self.owner_id != _TEST_OWNER_ID:
            _fail(FinancialInputError, "test_owner_identity")
        existed = path.exists()
        if existing_only and (not existed or path.stat().st_size == 0):
            _fail(FinancialIntegrityError, "existing_database_required")
        if existed and path.stat().st_size == 0:  # a creator holds its new file empty until its schema commits: wait for it
            try:
                with closing(sqlite3.connect(str(path), timeout=5.0, isolation_level=None)) as probe:
                    probe.execute("BEGIN IMMEDIATE")
                    probe.execute("ROLLBACK")
            except sqlite3.Error as error:  # a file nobody can open or write stays empty: refused just below
                _raise_if_busy(error)
            if path.stat().st_size == 0:
                _fail(FinancialIntegrityError, "empty_database")
        if existed and identity_contract is not None:
            _fail(FinancialIntegrityError, "identity_contract_destination")
        if not existed:
            if identity_contract is None:
                identity_digest = _identity_digest(
                    provenance="ROOT",
                    bound_mode=mode,
                    bound_owner_id=self.owner_id,
                    anchor_sequence=0,
                    source_package_digest=_ZERO_DIGEST,
                )
                genesis = _digest(_GENESIS_DOMAIN, config.canonical_bytes, trusted_authority.digest, identity_digest)
                identity = {
                    "id": 1,
                    "schema_version": self.schema_version,
                    "provenance": "ROOT",
                    "bound_mode": mode,
                    "bound_owner_id": self.owner_id,
                    "anchor_sequence": 0,
                    "anchor_head": genesis,
                    "genesis_head": genesis,
                    "source_package_digest": _ZERO_DIGEST,
                    "identity_digest": identity_digest,
                }
                initial_sequence = 0
                initial_history_head = genesis
            else:
                identity = _identity_record(identity_contract, code_prefix="identity_contract")
                if identity["provenance"] != "CONTINUITY_RESTORE" or identity["bound_mode"] != mode or identity["bound_owner_id"] != self.owner_id:
                    _fail(FinancialIntegrityError, "identity_contract_binding")
                if identity["source_package_digest"] == _ZERO_DIGEST:
                    _fail(FinancialIntegrityError, "identity_contract_source")
                initial_sequence = int(identity["anchor_sequence"])
                initial_history_head = bytes(identity["anchor_head"])
            connection = self._connect()
            try:
                try:
                    if connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":  # R0.5: born WAL (persistent header)
                        _fail(FinancialIntegrityError, "journal_mode")
                    connection.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as error:  # another creator holds the new file
                    _raise_if_busy(error)
                    raise
                if connection.execute("SELECT 1 FROM sqlite_master").fetchone() is not None:  # another creator won: a retry opens its store
                    _fail(FinancialBusyError, "store_busy")
                _sql_schema(connection)
                connection.execute(
                    "INSERT INTO financial_meta VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (1, self.schema_version, self.schema, config.state_id, config.deployment_id, config.program_id, config.period_id, config.currency, initial_sequence, initial_history_head, 1, 0, 0, trusted_authority.authority_id, trusted_authority.epoch, trusted_authority.digest, mode, self.owner_id),
                )
                self._insert_row(connection, "financial_identity", identity)
                self._adopt(connection)  # what this owner just wrote needs no verification (a restore imports here)
                connection.execute("COMMIT")
            except BaseException:
                self._discard_writer()
                connection.close()  # closing rolls back
                raise

    def _connect(self) -> sqlite3.Connection:
        connection = None
        try:
            location = self.path.resolve().as_uri() + "?mode=rw" if self._existing_only else str(self.path)
            connection = sqlite3.connect(location, uri=self._existing_only, timeout=5.0, isolation_level=None, check_same_thread=False)  # the writer serves any thread, under _lock
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA recursive_triggers=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA synchronous=FULL")  # R0.5: with WAL, an acknowledged commit survives power loss
            connection.execute("PRAGMA cache_size=-65536")
            connection.create_function("rr_segment_bytes", -1, lambda table, *values: len(_canonical(self._segment_record(table, values))) + 1)
            connection.create_function("rr_captured_row", -1, self._captured_row_for_sql)
            connection.execute("CREATE TEMP TABLE rr_captured_rows(image TEXT NOT NULL)")
            return connection
        except sqlite3.Error as error:
            if connection is not None:
                connection.close()  # a refused open leaves no handle on the store
            _raise_if_busy(error)
            _fail(FinancialIntegrityError, "database_open")

    def _captured_row_for_sql(self, table: str, *values: object) -> str | None:
        """One row image for the next event: an insert's full row, or an update's changed columns."""
        columns = _TABLE_COLUMNS[table]
        new = {column: self._export_value(value) for column, value in zip(columns, values)}
        if len(values) == len(columns):
            return _canonical({"table": table, "row": new}).decode("ascii")
        old = {column: self._export_value(value) for column, value in zip(columns, values[len(columns):])}
        changed = {column: value for column, value in new.items() if old[column] != value}
        return _canonical({"table": table, "key": old[columns[0]], "set": changed}).decode("ascii") if changed else None

    def _install_capture_triggers(self, connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TEMP TABLE rr_row_inserts(table_name TEXT PRIMARY KEY, n INTEGER NOT NULL)")  # rolls back with the write
        # The open history segment tracks each event and changed row with its record size: O(this write) (IX.3).
        for table in ("financial_events", *_PROJECTION_TABLES):
            new_values = ",".join(f'NEW."{column}"' for column in _TABLE_COLUMNS[table])
            track = f"INSERT INTO history_pending VALUES ('{table}',NEW.rowid,rr_segment_bytes('{table}',{new_values})) ON CONFLICT (table_name,row_key) DO UPDATE SET record_bytes=excluded.record_bytes"
            changed = " OR ".join(f'NEW."{column}" IS NOT OLD."{column}"' for column in _TABLE_COLUMNS[table])  # as capture: an UPDATE that changes nothing is not a write
            count = f"INSERT INTO rr_row_inserts VALUES ('{table}',1) ON CONFLICT (table_name) DO UPDATE SET n=n+1"
            for operation, when, body in (("INSERT", "", f"{track}; {count}"), ("UPDATE", f" WHEN {changed}", track)):
                connection.execute(f'CREATE TEMP TRIGGER "rr_track_{table}_{operation}" AFTER {operation} ON main."{table}"{when} BEGIN {body}; END')
            connection.execute(f'CREATE TEMP TRIGGER "rr_track_{table}_DELETE" BEFORE DELETE ON main."{table}" BEGIN SELECT RAISE(ABORT,\'history_row_delete\'); END')
        connection.execute("CREATE TEMP TRIGGER rr_track_pending_insert AFTER INSERT ON main.history_pending BEGIN UPDATE history_open SET event_count=event_count+(NEW.table_name='financial_events'),byte_count=byte_count+NEW.record_bytes; END")
        connection.execute("CREATE TEMP TRIGGER rr_track_pending_update AFTER UPDATE ON main.history_pending BEGIN UPDATE history_open SET byte_count=byte_count+NEW.record_bytes-OLD.record_bytes; END")
        for table in _CAPTURED_TABLES:
            new_values = ",".join(f'NEW."{column}"' for column in self._table_columns[table])
            old_values = ",".join(f'OLD."{column}"' for column in self._table_columns[table])
            connection.execute(
                f"CREATE TEMP TRIGGER rr_capture_{table}_insert AFTER INSERT ON main.\"{table}\" BEGIN "
                f"INSERT INTO rr_captured_rows(image) VALUES (rr_captured_row('{table}',{new_values})); END"
            )
            connection.execute(
                f"CREATE TEMP TRIGGER rr_capture_{table}_update AFTER UPDATE ON main.\"{table}\" BEGIN "
                f"INSERT INTO rr_captured_rows(image) SELECT image FROM (SELECT rr_captured_row('{table}',{new_values},{old_values}) AS image) "
                f"WHERE image IS NOT NULL; END"
            )

    def _segment_record(self, table: str, values: Iterable[object]) -> dict[str, Any]:
        """One segment record: an event row, or a projection row's full image."""
        row = {column: self._export_value(value) for column, value in zip(_TABLE_COLUMNS[table], values, strict=True)}
        return row if table == "financial_events" else {"table": table, "row": row}

    def _track_all(self, connection: sqlite3.Connection) -> None:
        """Seal a store from before segments as one segment, inside the conversion transaction."""
        for table in ("financial_events", *_PROJECTION_TABLES):
            connection.executemany(
                "INSERT INTO history_pending VALUES (?,?,?)",
                ((table, row[0], len(_canonical(self._segment_record(table, tuple(row)[1:]))) + 1) for row in connection.execute(f'SELECT rowid,* FROM "{table}"').fetchall()),
            )
        connection.execute("UPDATE history_open SET event_count=(SELECT COUNT(*) FROM history_pending WHERE table_name='financial_events'),byte_count=(SELECT COALESCE(SUM(record_bytes),0) FROM history_pending)")
        self._seal_segment(connection, force=True)

    def _row_counts(self, connection: sqlite3.Connection, base: dict[str, int]) -> dict[str, int]:
        """Rows per history table now: the transaction's starting counts plus the rows it inserted (deletes abort)."""
        counts = dict(base)
        for table, inserted in connection.execute("SELECT table_name,n FROM temp.rr_row_inserts"):
            counts[table] += inserted
        return counts

    def _read_mark(self, connection: sqlite3.Connection) -> tuple[tuple[int, int, int], tuple[object, ...]]:
        """(data_version, device, file index) and the history mark, inside the caller's transaction (H1)."""
        history = tuple(connection.execute(_HISTORY_MARK).fetchone())
        try:
            stat = os.stat(self.path)
        except OSError:
            _fail(FinancialIntegrityError, "store_replaced")
        return (connection.execute("PRAGMA data_version").fetchone()[0], stat.st_dev, stat.st_ino), history

    def _adopt(self, connection: sqlite3.Connection) -> None:
        """Keep this connection as the writer (R1a), marked inside the transaction that verified or created the store."""
        self._install_capture_triggers(connection)
        mark, history = self._read_mark(connection)
        if self._rewound(history):
            _fail(FinancialIntegrityError, "store_replaced")
        self._mark, self._writer, self._row_cache, self._high = mark, connection, (history, _count_rows(connection)), history[2:]

    def _head_at(self, sequence: int) -> bytes | None:
        """The store's history head at ``sequence`` (0: its genesis), for the custody check."""
        with self._read_snapshot() as connection:
            row = connection.execute("SELECT head FROM financial_events WHERE event_sequence=?1 UNION ALL SELECT genesis_head FROM financial_identity WHERE ?1=0", (sequence,)).fetchone()
        return None if row is None else bytes(row[0])

    def resolve_custody(self, custody: Any, kind: str, *, actor_id: str, reason_ref: str, expect_sequence: int, expect_head: bytes) -> None:
        """An operator's custody act on this owner, opened without custody so its open verified the store in full:
        ``ADOPTED`` restarts a lost log, ``REWIND_ACCEPTED`` accepts a restored store. The operator states the
        restored (sequence, head); the signed record names them, the reason and the tail it lowers from. Never automatic."""
        _id(actor_id, "actor_id")
        _id(reason_ref, "reason_ref")
        with self._lock:
            if self._custody is not None or kind not in ("ADOPTED", "REWIND_ACCEPTED"):
                _fail(FinancialInputError, "custody_resolution")
            if self._high != (expect_sequence, expect_head):
                _fail(FinancialIntegrityError, "custody_expectation")
            custody.resolve(self.owner_id, kind, self.path, self._high, self._head_at, actor_id=actor_id, reason_ref=reason_ref)
            self._custody = custody

    def _rewound(self, history: tuple[object, ...]) -> bool:
        """A lower sequence than this owner last verified or committed, or that sequence with another head (III.6)."""
        return self._high is not None and (history[2] < self._high[0] or (history[2] == self._high[0] and history[3] != self._high[1]))

    def _discard_writer(self) -> None:
        writer, self._writer, self._mark, self._row_cache, self._refusal = self._writer, None, None, None, None
        if writer is not None:
            writer.close()

    def _begin(self, statement: str) -> sqlite3.Connection:
        """The writer inside ``statement`` at its marked point. SQLite moves data_version for every other connection's
        commit (a raw page edit moves nothing, and the writer's cache may keep the old pages: such an edit is seen at
        the next open or audit). A moved mark is verified again exactly as a fresh open verifies it. Another file,
        or a history behind the (sequence, head) this owner last verified or committed, is store_replaced, for as
        long as this object lives. If the history check refuses, the command still runs its own checks first on a
        connection that never commits, so a refusal they find keeps its code; otherwise the fresh open's refusal is
        raised before anything is reported or committed."""
        while True:
            if self._writer is None:
                try:
                    self._verify_open_identity(verify_history=True)
                except FinancialIntegrityError as refusal:
                    if not str(refusal).startswith("open_verification:"):  # identity, schema, triggers: as a fresh open
                        raise
                    high, connection = self._high, self._connect()
                    try:
                        self._adopt(connection)
                    except BaseException:
                        connection.close()
                        raise refusal
                    self._refusal, self._high = refusal, high  # an unverified store never moves the high-water
            self._writer.execute(statement)
            mark, history = self._read_mark(self._writer)
            if (mark, history) == (self._mark, self._row_cache[0]):
                return self._writer
            if mark[1:] != self._mark[1:] or self._rewound(history):
                _fail(FinancialIntegrityError, "store_replaced")
            self._discard_writer()

    def _seal_segment(self, connection: sqlite3.Connection, *, force: bool = False, rows: dict[str, int] | None = None) -> bytes | None:
        """Seal the open segment at a soft bound (or when forced); refuse a write past a hard bound."""
        opened = connection.execute("SELECT event_count,byte_count FROM history_open WHERE id=1").fetchone()
        if opened is None or {type(opened[0]), type(opened[1])} != {int}:
            _fail(FinancialIntegrityError, "history_segment_events")
        count, size = opened
        if count > _MAX_SEGMENT_EVENTS or size + _SEGMENT_FRAME_BYTES > _MAX_SEGMENT_BYTES:
            _fail(FinancialContinuityError, "history_segment_size")
        sealing = count > 0 and (force or count >= _SEAL_SEGMENT_EVENTS or size >= _SEAL_SEGMENT_BYTES)
        if sealing and rows is not None and rows != _count_rows(connection):  # each seal proves the cached counts exact
            _fail(FinancialIntegrityError, "row_cache_drift")
        touched = "SELECT table_name FROM temp.rr_row_inserts" if rows is not None else "SELECT DISTINCT table_name FROM history_pending"
        for (table,) in connection.execute(touched).fetchall():  # only a table this write inserted into can have grown (updates add no rows, deletes abort); the Checker reads at most Lean's maxRows per table
            cached = rows[table] if rows is not None else None
            if cached is None or cached >= _MAX_ROWS - _MAX_ROWS // 20:  # within 5% of the cap, counted exactly
                exact = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                if cached is not None and cached != exact:
                    _fail(FinancialIntegrityError, "row_cache_drift")
                cached = exact
            if cached > _MAX_ROWS:
                _fail(FinancialIntegrityError, "history_capacity")
        if not sealing:
            return None
        # The chain continues from the last sealed segment only if its stored seal still recomputes.
        last = connection.execute("SELECT * FROM history_segments ORDER BY segment_index DESC LIMIT 2").fetchall()
        index, first, previous = 0, 1, _ZERO_DIGEST
        if last:
            stored = tuple(last[0])
            if [type(value) for value in stored] != [int, int, int, bytes, bytes, bytes, bytes, str] or stored[3] != (last[1][6] if len(last) == 2 else _ZERO_DIGEST) or stored[5] != _digest(_SEGMENT_DOMAIN, b"rows", stored[7].encode()) or stored[6] != _digest(_SEGMENT_DOMAIN, b"seal", _canonical(_segment_seal(*stored[:6]))):
                _fail(FinancialIntegrityError, "history_segment_chain")
            index, first, previous = stored[0] + 1, stored[2] + 1, stored[6]
        meta = self._meta(connection)
        pending = connection.execute("SELECT COALESCE(SUM(table_name='financial_events'),0),COALESCE(SUM(record_bytes),0),COALESCE(SUM(record_bytes*(table_name='financial_events')),0) FROM history_pending").fetchone()
        if int(meta["sequence"]) - first + 1 != count or tuple(pending[:2]) != (count, size):
            _fail(FinancialIntegrityError, "history_segment_events")
        images = []
        for table, key in connection.execute("SELECT table_name,row_key FROM history_pending WHERE table_name<>'financial_events'").fetchall():
            images.append(_canonical(self._segment_record(table, tuple(connection.execute(f'SELECT * FROM "{table}" WHERE rowid=?', (key,)).fetchone()))))
        rows_json = b"[" + b",".join(sorted(images)) + b"]"
        if len(rows_json) + pending[2] + _SEGMENT_FRAME_BYTES > _MAX_SEGMENT_BYTES:  # measured as built, before it is stored
            _fail(FinancialContinuityError, "history_segment_size")
        seal = (index, first, int(meta["sequence"]), previous, bytes(meta["history_head"]), _digest(_SEGMENT_DOMAIN, b"rows", rows_json))
        digest = _digest(_SEGMENT_DOMAIN, b"seal", _canonical(_segment_seal(*seal)))
        connection.execute("INSERT INTO history_segments VALUES (?,?,?,?,?,?,?,?)", (*seal, digest, rows_json.decode("ascii")))
        connection.execute("DELETE FROM history_pending")
        connection.execute("UPDATE history_open SET event_count=0,byte_count=0")
        return digest

    def _derive_command_log(self, connection: sqlite3.Connection) -> None:
        """Rebuild the command log from history (restore; it is never exported)."""
        for event in connection.execute(
            "SELECT event_sequence,aggregate_id,kind,payload_json FROM financial_events ORDER BY event_sequence"
        ).fetchall():
            self._record_command(
                connection,
                sequence=int(event["event_sequence"]),
                kind=str(event["kind"]),
                aggregate_id=str(event["aggregate_id"]),
                payload=_stored_object(event["payload_json"], "command_event_payload"),
            )

    def _verify_open_identity(self, *, verify_history: bool) -> None:
        """On a new connection, which stays as the writer once the history is verified (R1a)."""
        no_migration = self.mode == "SHADOW" or self._existing_only
        self._discard_writer()
        connection = self._connect()
        try:
            if no_migration and connection.execute("PRAGMA journal_mode").fetchone()[0] != "wal":  # R0.5: a pre-WAL header changes only in a migrating open
                _fail(FinancialIntegrityError, "shadow_requires_migration")
            connection.execute("BEGIN IMMEDIATE")
            meta = _one(connection, "schema_meta", "SELECT * FROM financial_meta WHERE id=1")
            if (meta["schema_version"], meta["schema"]) != (_SCHEMA_VERSION, _SCHEMA):
                _fail(FinancialIntegrityError, "unsupported_store_version")
            migrated = False
            self._verify_meta_identity(connection, meta)
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if tables in (_TABLES, _TABLES | {"right_rail_continuity_admission"}):
                # A v8 store from before history segments: replayed, then its whole history opens the first segment.
                if no_migration:
                    _fail(FinancialIntegrityError, "shadow_requires_migration")
                migrated = True
                connection.execute("DROP TABLE IF EXISTS right_rail_continuity_admission")
                _execute_script(connection, _SEGMENT_SCHEMA)
                self._track_all(connection)
            elif tables != _TABLES | _SEGMENT_TABLES:
                _fail(FinancialIntegrityError, "schema_tables")
            if not no_migration:
                _install_private_index_set(connection)
            elif _private_index_set_version(connection) < (_PRIVATE_INDEX_SET_VERSION if self._existing_only else 1):  # never upgraded here: a read-only SHADOW may keep v1; an existing-only writer needs the current set
                _fail(FinancialIntegrityError, "shadow_requires_migration")
            _install_history_append_only(connection, read_only=no_migration)
            if verify_history or migrated:
                self._verify_history_in_transaction(connection)
                self._adopt(connection)
            connection.execute("COMMIT")
            if not no_migration and connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":  # only once verified
                _fail(FinancialIntegrityError, "journal_mode")
        except BaseException as error:
            self._discard_writer()
            connection.close()  # closing rolls back
            if isinstance(error, sqlite3.DatabaseError):
                _raise_if_busy(error)
                _fail(FinancialIntegrityError, "schema_read")
            raise
        if self._writer is None:  # a restore's unverified import check: its own checker runs next
            connection.close()

    def _verify_meta_identity(self, connection: sqlite3.Connection, meta: sqlite3.Row) -> None:
        """Bind persisted meta and identity rows to this Owner's config, mode, owner id and authority."""

        scope = self._scope_value()
        actual = (meta["schema_version"], meta["schema"], *(meta[key] for key in scope))
        if actual != (self.schema_version, self.schema, *scope.values()):
            _fail(FinancialIntegrityError, "schema_identity")
        if int(meta["dispatch_enabled"]) != 0 or int(meta["egress_enabled"]) != 0 or str(meta["mode"]) != self.mode:
            _fail(FinancialIntegrityError, "nonactivating_boundary")
        if str(meta["owner_id"]) != self.owner_id:
            _fail(FinancialIntegrityError, "owner_identity")
        authority = self.trusted_authority
        if (str(meta["trusted_authority_id"]), int(meta["trusted_authority_epoch"]),
                bytes(meta["trusted_authority_digest"])) != (
            authority.authority_id, authority.epoch, authority.digest
        ):
            _fail(FinancialAuthorityError, "trusted_authority_stale")
        identity_rows = connection.execute("SELECT * FROM financial_identity WHERE id=1").fetchall()
        if len(identity_rows) != 1:
            _fail(FinancialIntegrityError, "identity_cardinality")
        identity_row = identity_rows[0]
        identity = _identity_record(
            {column: identity_row[column] for column in self._table_columns["financial_identity"]},
        )
        if identity["bound_mode"] != str(meta["mode"]) or identity["bound_owner_id"] != str(meta["owner_id"]):
            _fail(FinancialIntegrityError, "identity_binding")
        if identity["provenance"] == "ROOT":
            expected_genesis = _digest(
                _GENESIS_DOMAIN,
                self.config.canonical_bytes,
                self.trusted_authority.digest,
                identity["identity_digest"],
            )
            if (
                identity["source_package_digest"] != _ZERO_DIGEST
                or identity["anchor_sequence"] != 0
                or identity["anchor_head"] != expected_genesis
                or identity["genesis_head"] != expected_genesis
            ):
                _fail(FinancialIntegrityError, "identity_genesis")
        else:
            if identity["source_package_digest"] == _ZERO_DIGEST or identity["anchor_sequence"] > int(meta["sequence"]):
                _fail(FinancialIntegrityError, "identity_anchor")
            if identity["anchor_sequence"] == 0:
                if identity["anchor_head"] != identity["genesis_head"]:
                    _fail(FinancialIntegrityError, "identity_anchor")
            else:
                anchor = connection.execute(
                    "SELECT head FROM financial_events WHERE event_sequence=?",
                    (identity["anchor_sequence"],),
                ).fetchone()
                if anchor is None or bytes(anchor["head"]) != identity["anchor_head"]:
                    _fail(FinancialIntegrityError, "identity_history_anchor")
        if int(meta["sequence"]) == 0:
            if bytes(meta["history_head"]) != identity["genesis_head"]:
                _fail(FinancialIntegrityError, "identity_history_head")
        else:
            first_event = connection.execute(
                "SELECT previous_head FROM financial_events WHERE event_sequence=1",
            ).fetchone()
            if first_event is None or bytes(first_event["previous_head"]) != identity["genesis_head"]:
                _fail(FinancialIntegrityError, "identity_history_genesis")

    @staticmethod
    def _verify_funding_projection(connection: sqlite3.Connection) -> None:
        """Check current funding leaves against receipt and event facts, without replaying history."""
        drift = connection.execute(
            "SELECT 1 FROM program_funding_projection AS p "
            "LEFT JOIN program_funding_receipts AS r ON r.receipt_id=p.receipt_id "
            "LEFT JOIN program_funding_receipts AS child ON child.supersedes_receipt_id=p.receipt_id "
            "LEFT JOIN financial_events AS e ON e.aggregate_type='PROGRAM_FUNDING_RECEIPT' AND e.aggregate_id=p.receipt_id "
            "WHERE r.receipt_id IS NULL OR child.rowid IS NOT NULL OR e.aggregate_id IS NULL "
            "OR p.source_record_ref IS NOT r.source_record_ref OR p.amount_cents IS NOT r.amount_cents "
            "OR p.event_at_ms IS NOT r.event_at_ms OR p.receipt_digest IS NOT r.receipt_digest "
            "OR p.revision IS NOT e.after_revision OR e.before_revision IS NOT p.revision-1 "
            "OR e.committed_at_ms IS NOT r.recorded_at_ms OR json_extract(e.payload_json,'$.amount_cents') IS NOT r.amount_cents "
            "OR json_extract(e.payload_json,'$.receipt_digest') IS NOT hex(r.receipt_digest) "
            "OR e.kind IS NOT CASE WHEN r.supersedes_receipt_id IS NULL THEN 'FUNDING_RECEIPT_RECORDED' "
            "ELSE 'FUNDING_RECEIPT_SUPERSEDED' END LIMIT 1"
        ).fetchone()
        roots = connection.execute(
            "SELECT 1 FROM program_funding_receipts AS r WHERE r.supersedes_receipt_id IS NULL "
            "GROUP BY r.source_record_ref HAVING COUNT(*) != 1 OR NOT EXISTS "
            "(SELECT 1 FROM program_funding_projection AS p WHERE p.source_record_ref=r.source_record_ref) LIMIT 1"
        ).fetchone()
        counts = connection.execute(
            "SELECT (SELECT COUNT(*) FROM program_funding_receipts WHERE supersedes_receipt_id IS NULL), "
            "(SELECT COUNT(*) FROM program_funding_projection)"
        ).fetchone()
        if drift is not None or roots is not None or counts[0] != counts[1]:
            _fail(FinancialIntegrityError, "funding_projection_drift")

    @contextmanager
    def _write(self, *, before_commit=None, conclude=None) -> Iterator[sqlite3.Connection]:
        """One atomic command; inside ``run_batch`` the batch owns the connection, BEGIN, COMMIT and ROLLBACK,
        while each command still seals as it would alone, so a batch's segments equal its commands' run singly."""
        batch = getattr(self._batch, "connection", None)
        began = batch is None
        with self._lock if began else nullcontext():
            outer_now, self._batch.now = getattr(self._batch, "now", None), -1  # this command's clock is unread (_now)
            if collect := began and gc.isenabled(): gc.disable()  # a write makes millions of short-lived objects; the cycle collector's passes over the live rows cost ~10% of a full file's lock
            try:
                if began and self._custody is not None:
                    self._custody.settle(self.owner_id)  # an owed custody MARK lands first, or nothing more is written
                connection = self._begin("BEGIN IMMEDIATE") if began else batch
                if began:
                    self._verify_funding_projection(connection)
                    self._batch.rows = self._row_cache[1]
                    self._batch.evaluated = set()  # obligations Lean evaluated in this write
                yield connection
                if began:
                    self._verify_funding_projection(connection)
                rows = self._row_counts(connection, self._batch.rows)
                self._seal_segment(connection, rows=rows)
                if connection.execute("SELECT 1 FROM temp.rr_captured_rows").fetchone() is not None:
                    _fail(FinancialIntegrityError, "captured_rows_without_event")  # refused, never stranded
                if began:
                    if _CHECK_ROW_CACHE and rows != _count_rows(connection):
                        raise AssertionError(f"row_count_cache: {rows} != {_count_rows(connection)}")
                    after = (tuple(connection.execute(_HISTORY_MARK).fetchone()), rows)
                    done = before_commit(connection) if before_commit is not None else None  # the obligations the cash-file checker verified, on this same state
                    if self._batch.evaluated:  # the very set it verified needs only this Owner's own schema and meta check
                        self._verify_before_commit(connection, "evaluation", *(() if self._batch.evaluated == done else sorted(self._batch.evaluated)))
                    if self._refusal is not None:
                        self._seal_segment(connection, force=True)  # its seal-time checks speak too (history_segment_chain)
                        raise self._refusal
                    conclude and conclude()  # a cash-file preview reports only after the check above, then rolls back
                    connection.execute("DELETE FROM temp.rr_row_inserts")  # the next write counts its own
                    connection.execute("COMMIT")
                    self._row_cache, self._high = after, after[0][2:]
                    if self._custody is not None:
                        self._custody.mark(self.owner_id, self._high)  # only after COMMIT, so custody never names an uncommitted head
            except BaseException as error:
                if began:  # R1a: a failed write (a proven drift included) is never reused; the next one verifies in full. A stale refusal changed nothing: the next begin's mark check still guards it
                    connection.execute("ROLLBACK") if type(error) is FinancialStaleError else self._discard_writer()
                _raise_if_busy(error)
                raise
            finally:
                collect and gc.enable()
                self._batch.now = outer_now
                if began:
                    self._batch.rows = None

    def _verify_before_commit(self, connection: sqlite3.Connection, label: str, *obligation_ids: str) -> None:
        """The independent checker recomputes what Lean decided from the exact rows written, before COMMIT."""

        from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_obligation_connection

        try:
            verify_obligation_connection(connection, *obligation_ids, **self._checker_expectations())
        except IndependentFinancialError as error:
            _fail(FinancialIntegrityError, f"{label}_verification:{error}")

    def run_batch(self, commands: list[tuple[str, Mapping[str, Any]]], *, cash_file_context=None):
        """Up to 1,000 commands in one transaction, each run exactly as its method alone (same checks,
        history, retries). All or nothing: the first failure rolls the whole batch back and is raised
        with a ``batch_index=<i>`` note (Art. III.2, III.5). In an absorbed cash file (intake facts given) an input,
        conflict or revision refusal holds only its row (and its item's later rows), the file may carry no row, and the
        file's one INTAKE event lands last; any other cash file is atomic."""
        if type(commands) is not list or not (cash_file_context is None) <= len(commands) <= 1_000 or any(type(entry) is not tuple or len(entry) != 2 or entry[0] not in _BATCH_COMMANDS or not isinstance(entry[1], Mapping) for entry in commands):
            _fail(FinancialInputError, "batch_commands")
        check = None
        results = []
        if cash_file_context is not None:
            from app.right_rail_financial_cash_file_independent import CashFileCheck
            if getattr(self._batch, "connection", None) is not None:
                _fail(FinancialInputError, "cash_file_nested_batch")
            check = CashFileCheck(commands, cash_file_context)
            commands = check.commands
        with self._write(before_commit=(lambda connection: check.finish(connection, results)) if check else None, conclude=check.conclude if check else None) as connection:
            outcomes = check.begin(connection) if check else [None] * len(commands)
            self._batch.connection = connection
            absorbing = check is not None and check.intake is not None
            held = set()  # a cash file's items with a held row: their later rows assumed it (docs/CORE_REDESIGN.md "Rows")
            try:
                for index, ((name, arguments), outcome) in enumerate(zip(commands, outcomes)):
                    if check and outcome is None and arguments["item_id"] in held:
                        outcome = {"status": "HELD", "payment_id": arguments["payment_id"], "reason": "depends_on_held"}
                    elif outcome is None:
                        absorbing and connection.execute("SAVEPOINT rr_row")  # D2: a refused cash row rolls back alone
                        try:
                            answer = getattr(self, name)(**arguments)
                            outcome = {"status": answer["status"], "payment_id": answer["payment_id"], "reason": None} if check else answer
                        except BaseException as error:
                            if not (absorbing and isinstance(error, (FinancialInputError, FinancialConflictError, FinancialRevisionError))):
                                error.add_note(f"batch_index={index}")
                                raise
                            connection.execute("ROLLBACK TO rr_row")  # this row's writes, temp logs included
                            outcome = {"status": "HELD", "payment_id": arguments["payment_id"], "reason": str(error)}
                        absorbing and connection.execute("RELEASE rr_row")
                    if check and outcome["status"] == "HELD":
                        held.add(arguments["item_id"])
                    results.append(outcome)
                if absorbing:
                    self._append_event(connection, aggregate_type="INTAKE", aggregate_id=check.intake["source_sha256"], kind="INTAKE_RECEIVED", before_revision=0, after_revision=0,
                                       payload=check.intake_payload(results), committed_at_ms=self._now())
            finally:
                self._batch.connection = None
        return check.receipt if check else results

    @contextmanager
    def _read_snapshot(self, *, _connection: sqlite3.Connection | None = None) -> Iterator[sqlite3.Connection]:
        """Read a multi-query view from one committed SQLite snapshot."""
        if _connection is not None:
            if not isinstance(_connection, sqlite3.Connection) or not _connection.in_transaction:
                _fail(FinancialIntegrityError, "read_snapshot_required")
            yield _connection
            return
        with closing(self._connect()) as connection:  # closing ends the read; nothing to commit
            try:
                connection.execute("BEGIN")
                yield connection
            except sqlite3.OperationalError as error:
                _raise_if_busy(error)
                raise

    def _now(self) -> int:
        """The owner clock, read once per command: inside a ``_write`` every call returns its first reading,
        so an evidence row's received_at_ms is its event's committed_at_ms (checker replay:evidence-received-at)."""
        now = getattr(self._batch, "now", None)
        if now is not None and now >= 0:
            return now
        value = _time(self.clock.now_ms(), "clock")
        if now is not None:
            self._batch.now = value
        return value

    def _scope_period(self, period_id: str) -> None:
        _id(period_id, "period_id")
        if period_id in _WILDCARD_PERIODS or self.config.period_id in _WILDCARD_PERIODS or period_id != self.config.period_id:
            _fail(FinancialIntegrityError, "period_scope")

    def _meta(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = _one(connection, "meta_missing", "SELECT * FROM financial_meta WHERE id=1")
        return row

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        aggregate_type: str,
        aggregate_id: str,
        kind: str,
        before_revision: int,
        after_revision: int,
        payload: Mapping[str, Any],
        committed_at_ms: int,
    ) -> bytes:
        _kind(aggregate_type, "aggregate_type")
        _id(aggregate_id, "aggregate_id")
        _kind(kind, "event_kind")
        for value, label in (
            (before_revision, "event_before_revision"),
            (after_revision, "event_after_revision"),
            (committed_at_ms, "event_committed_at"),
        ):
            if type(value) is not int or value < 0 or value >= 2**63:
                _fail(FinancialIntegrityError, label)
        event_payload = dict(payload)
        if aggregate_type == "OBLIGATION" and "evaluation_id" in event_payload:
            evaluation_id = _id(event_payload["evaluation_id"], "event_evaluation_id")
            evaluation = connection.execute(
                "SELECT input_snapshot_digest,result_digest,receipt_digest FROM evaluations WHERE evaluation_id=? AND obligation_id=?",
                (evaluation_id, aggregate_id),
            ).fetchone()
            if evaluation is None:
                _fail(FinancialIntegrityError, "event_evaluation_missing")
            event_payload.update(
                {
                    "evaluation_input_digest": _hex(bytes(evaluation["input_snapshot_digest"])),
                    "evaluation_result_digest": _hex(bytes(evaluation["result_digest"])),
                    "evaluation_receipt_digest": _hex(bytes(evaluation["receipt_digest"])),
                }
            )
        captured = connection.execute("SELECT image FROM temp.rr_captured_rows ORDER BY rowid").fetchall()
        if captured:
            event_payload["rows"] = [json.loads(row[0]) for row in captured]
            connection.execute("DELETE FROM temp.rr_captured_rows")
        payload_bytes = _canonical(event_payload)
        payload_digest = _digest(_EVENT_DOMAIN, payload_bytes)
        meta = self._meta(connection)
        # Lean's maxRows/maxRevision (Types.lean): the checker refuses a history or revision past them.
        if int(meta["sequence"]) >= _MAX_ROWS or after_revision > _MAX_ROWS:
            _fail(FinancialIntegrityError, "history_capacity")
        sequence = int(meta["sequence"]) + 1
        if (last := connection.execute("SELECT committed_at_ms FROM financial_events WHERE event_sequence=?", (sequence - 1,)).fetchone()) and committed_at_ms < last[0]:
            _fail(FinancialIntegrityError, "event_commit_order")  # checker history:commit-order: a clock behind its history writes nothing
        if connection.execute("SELECT 1 FROM financial_events WHERE event_sequence>=?", (sequence,)).fetchone() is not None:
            _fail(FinancialIntegrityError, "history_sequence")  # an event past the meta sequence was written outside this Owner
        previous_head = bytes(meta["history_head"])
        header = b"".join(
            value.to_bytes(8, "big")
            for value in (before_revision, after_revision, committed_at_ms)
        )
        event_id = _digest(
            _EVENT_DOMAIN,
            sequence.to_bytes(8, "big"),
            aggregate_type.encode("ascii"),
            aggregate_id.encode("ascii"),
            kind.encode("ascii"),
            header,
            payload_digest,
        )
        head = _digest(_HEAD_DOMAIN, previous_head, event_id, header, payload_digest)
        connection.execute(
            "INSERT INTO financial_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (sequence, event_id, aggregate_type, aggregate_id, kind, before_revision, after_revision, payload_bytes.decode("ascii"), payload_digest, previous_head, head, committed_at_ms),
        )
        connection.execute("UPDATE financial_meta SET sequence=?,history_head=? WHERE id=1", (sequence, head))
        self._record_command(connection, sequence=sequence, kind=kind, aggregate_id=aggregate_id, payload=event_payload)
        return event_id

    def _record_command(
        self,
        connection: sqlite3.Connection,
        *,
        sequence: int,
        kind: str,
        aggregate_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Record the accepted request behind one command event (``_COMMAND_EVENTS``)."""

        command = _COMMAND_EVENTS.get(kind)
        if command is None:
            return
        command_kind, key_field = command
        key = aggregate_id if key_field is None else payload.get(key_field)
        if type(key) is not str:
            _fail(FinancialIntegrityError, "command_key")
        rows = connection.execute(_COMMAND_REQUEST_SQL[command_kind], (key,)).fetchall()
        if len(rows) != 1:
            _fail(FinancialIntegrityError, "command_request_source")
        request: dict[str, Any] = {"command": command_kind, "key": key}
        for field in rows[0].keys():
            value = rows[0][field]
            request[field] = _hex(bytes(value)) if type(value) is bytes else value
        command_id = f"{command_kind}:{key}"
        if connection.execute("SELECT 1 FROM commands WHERE command_id=?", (command_id,)).fetchone() is not None:
            _fail(FinancialIntegrityError, "command_duplicate")
        request_json = _canonical(request)
        connection.execute(
            "INSERT INTO commands VALUES (?,?,?,?,?)",
            (command_id, command_kind, request_json.decode("ascii"), _digest(_COMMAND_DOMAIN, request_json), sequence),
        )

    def _replayed_command(
        self,
        connection: sqlite3.Connection,
        kind: str,
        key: str,
        request: Mapping[str, Any],
        conflict_code: str,
    ) -> bool:
        """The one retry rule: True if ``kind:key`` is logged with every field (only optional ones may be None); False if new. ``expected_revision`` guards a first recording only; a retry of support, reversal, offset, report or acknowledgment ignores it."""

        row = connection.execute("SELECT request_json FROM commands WHERE command_id=?", (f"{kind}:{key}",)).fetchone()
        if row is None:
            return False
        logged = _stored_object(row[0], "command_request")
        if any(logged.get(field) != value and not (value is None and field in _OPTIONAL_REQUEST_FIELDS) for field, value in request.items()):
            _fail(FinancialConflictError, conflict_code)
        return True

    def _assert_actionable(self) -> None:
        if self.mode == "SHADOW":
            _fail(FinancialDispatchError, "shadow_owner_read_only")

    def _get_obligation_row(self, connection: sqlite3.Connection, item_id: str) -> sqlite3.Row:
        _id(item_id, "item_id")
        row = _one(connection, "obligation_missing", "SELECT * FROM obligations WHERE item_id=? AND period_id=?", (item_id, self.config.period_id))
        return row

    def _population_binding_for_obligation(
        self,
        connection: sqlite3.Connection,
        obligation: sqlite3.Row,
    ) -> dict[str, Any]:
        """Reconstruct the published v7 manifest revision for one obligation."""

        population_id = _id(str(obligation["population_id"]), "population_id")
        population = connection.execute(
            "SELECT * FROM population_imports WHERE population_id=?",
            (population_id,),
        ).fetchone()
        if population is None:
            _fail(FinancialIntegrityError, "population_manifest_binding_missing")
        manifest, manifest_row = self._bound_population_manifest(connection, population, published=True)
        actual_members = self._population_member_ids(connection, population_id)
        if (
            actual_members != manifest.member_ids
            or str(obligation["item_id"]) not in actual_members
        ):
            _fail(FinancialIntegrityError, "population_manifest_membership")
        return {
            "population_id": population_id,
            "status": "PUBLISHED",
            "completeness": "EXACT",
            "source_complete": True,
            "manifest_id": manifest.manifest_id,
            "manifest_version": manifest.manifest_version,
            "manifest_digest": _hex(bytes(manifest_row["manifest_digest"])),
            "member_id": str(obligation["item_id"]),
            "member_count": len(manifest.member_ids),
            "member_digest": _hex(bytes(manifest_row["member_digest"])),
        }

    def _control_pack_for_obligation(
        self,
        connection: sqlite3.Connection,
        obligation_id: str,
    ) -> tuple[ControlPack, str, str]:
        row = connection.execute(
            """
            SELECT cp.*
            FROM obligations o
            JOIN population_imports pi ON pi.population_id=o.population_id
            JOIN control_packs cp ON cp.pack_id=pi.pack_id
            WHERE o.obligation_id=?
            """,
            (obligation_id,),
        ).fetchone()
        if row is None or str(row["status"]) != "APPROVED":
            _fail(FinancialIntegrityError, "control_pack_missing")
        key = tuple(row)  # built and checked once per owner for each exact row; any changed column is a new key, rebuilt and re-checked
        if key not in self._packs:
            pack = _control_pack_from_row(row)
            if bytes(row["pack_digest"]) != pack.digest:
                _fail(FinancialIntegrityError, "control_pack_digest")
            self._packs[key] = (pack, *_control_pack_policy(calculation_rule_id=pack.calculation_rule_id, adjustment_rule_id=pack.adjustment_rule_id, authorized_roles=pack.authorized_roles, expected_tests=pack.expected_tests))
        self._scope_pack(self._packs[key][0])
        return self._packs[key]

    def _insert_evidence(self, connection: sqlite3.Connection, evidence: EvidenceRecord) -> str:
        existing = connection.execute("SELECT record_digest,received_at_ms FROM evidence WHERE evidence_id=?", (evidence.evidence_id,)).fetchone()
        if existing is not None:  # a retry restates the fact; its received time stays the first recording's
            if evidence.event_at_ms <= existing[1] and bytes(existing[0]) == replace(evidence, received_at_ms=existing[1]).record_digest:
                return "DUPLICATE"
            _fail(FinancialConflictError, "evidence_identity_conflict")
        connection.execute(
            "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence.evidence_id, evidence.item_id, evidence.kind, evidence.common_origin_id, evidence.source_id, evidence.source_version, evidence.local_ref, evidence.applicable_at_ms, evidence.event_at_ms, evidence.received_at_ms, evidence.content_digest, evidence.record_digest, evidence.amount_cents, evidence.reversal_of, evidence.supersedes),
        )
        return "INSERTED"

    def _recompute_and_record(
        self,
        connection: sqlite3.Connection,
        obligation_id: str,
        *,
        kind: str,
        payload: Mapping[str, Any],
        now_ms: int,
        decided: Any = None,
    ) -> dict[str, Any]:
        """Recompute one obligation and append its event, bound to the new evaluation."""

        before, after, evaluation = self._recompute_obligation(connection, obligation_id, now_ms=now_ms, decided=decided)
        self._append_event(
            connection,
            aggregate_type="OBLIGATION",
            aggregate_id=obligation_id,
            kind=kind,
            before_revision=before,
            after_revision=after,
            payload={**payload, "evaluation_id": evaluation["evaluation_id"]},
            committed_at_ms=now_ms,
        )
        return evaluation

    def _recompute_obligation(self, connection: sqlite3.Connection, obligation_id: str, *, now_ms: int, decided: Any = None) -> tuple[int, int, dict[str, Any]]:
        """Lean ``evaluate`` decides; this only binds its declared result to the three writes (V.1)."""

        from app import right_rail_financial_engine as financial_engine
        from app import right_rail_financial_semantic_adapter as semantic

        pack, _calculation, _adjustment = self._control_pack_for_obligation(connection, obligation_id)
        try:
            decided = decided or financial_engine.evaluate_live(  # M3: a payment command arrives with its Lean decision
                connection,
                obligation_id=obligation_id,
                authority_context=semantic.TrustedAuthorityContext.from_authority(self.trusted_authority),
                evaluation_time_ms=now_ms,
                verification={"scope": self._scope_value(), "owner_id": self.owner_id, "mode": self.mode},
            )
        except (FinancialError, financial_engine.FinancialEngineError) as error:
            _fail(FinancialIntegrityError, f"lean_evaluation:{error}")
        self._batch.evaluated.add(obligation_id)
        evaluation_id = f"evaluation:{obligation_id}:r{decided.after_revision}"
        result = _decided_evaluation(decided, evaluation_id, obligation_id, decided.after_revision)
        connection.execute("UPDATE cases SET status=?,updated_at_ms=? WHERE obligation_id=?", (decided.case_status, now_ms, obligation_id))
        stored_evaluation = self._insert_evaluation(
            connection,
            result=result,
            pack=pack,
            evidence_ids=decided.evidence_ids,
            authority_epoch=decided.authority_epoch,
            authority_digest=decided.authority_digest,
        )
        updated = connection.execute(
            "UPDATE obligations SET revision=?,claimed_adjustment_cents=?,lawful_adjustment_cents=?,received_cash_cents=?,shortfall_cents=?,overage_cents=?,cash_satisfied=?,amount_satisfied=?,timely=?,verification_status=?,case_status=?,delivery_status=?,current_evaluation_id=?,updated_at_ms=? WHERE obligation_id=? AND revision=?",
            (
                decided.after_revision, *(result[field] for field in _PROJECTION_FIELDS if field != "reporting_complete"),
                evaluation_id, now_ms, obligation_id, decided.before_revision,
            ),
        )
        if updated.rowcount != 1:
            _fail(FinancialRevisionError, "obligation_revision_conflict")
        return decided.before_revision, decided.after_revision, stored_evaluation

    def _scope_pack(self, pack: ControlPack) -> None:
        if type(pack) is not ControlPack:
            _fail(FinancialInputError, "control_pack_type")
        if (pack.state_id, pack.deployment_id, pack.program_id) != (self.config.state_id, self.config.deployment_id, self.config.program_id):
            _fail(FinancialIntegrityError, "control_pack_scope")
        self._scope_period(pack.period_id)

    def publish_control_pack(self, pack: ControlPack) -> dict[str, Any]:
        """Publish one approved, versioned rule pack in the owner database."""
        self._assert_actionable()
        self._scope_pack(pack)
        _control_pack_policy(
            calculation_rule_id=pack.calculation_rule_id,
            adjustment_rule_id=pack.adjustment_rule_id,
            authorized_roles=pack.authorized_roles,
            expected_tests=pack.expected_tests,
        )
        with self._write() as connection:
            if self._replayed_command(connection, "CONTROL_PACK", pack.pack_id, {"pack_digest": _hex(pack.digest)}, "control_pack_identity_conflict"):
                return {"status": "DUPLICATE", "pack_id": pack.pack_id, "digest": _hex(pack.digest)}
            for row in connection.execute("SELECT version,effective_start_ms,effective_end_ms FROM control_packs WHERE program_id=? AND period_id=? AND status='APPROVED'", (pack.program_id, pack.period_id)):
                if int(row[0]) == pack.version or max(pack.effective_start_ms, int(row[1])) < min(pack.effective_end_ms, int(row[2])):
                    _fail(FinancialConflictError, "control_pack_effective_overlap")
            connection.execute(
                "INSERT INTO control_packs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pack.pack_id, pack.state_id, pack.deployment_id, pack.program_id, pack.period_id, pack.version, _values_json(pack.source_refs), pack.effective_start_ms, pack.effective_end_ms, pack.recorded_at_ms, pack.approved_at_ms, pack.calculation_rule_id, pack.adjustment_rule_id, _values_json(pack.authorized_roles), _values_json(pack.expected_tests), pack.digest, "APPROVED"),
            )
            at_ms = self._now()
            self._append_event(connection, aggregate_type="CONTROL_PACK", aggregate_id=pack.pack_id, kind="CONTROL_PACK_PUBLISHED", before_revision=0, after_revision=1, payload={"pack_id": pack.pack_id, "version": pack.version, "period_id": pack.period_id, "digest": _hex(pack.digest)}, committed_at_ms=at_ms)
            return {"status": "PUBLISHED", "pack_id": pack.pack_id, "version": pack.version, "digest": _hex(pack.digest)}

    def _load_population_manifest(
        self,
        connection: sqlite3.Connection,
        manifest_id: str,
    ) -> tuple[PopulationManifest, sqlite3.Row]:
        row = connection.execute(
            "SELECT * FROM population_manifests WHERE manifest_id=?",
            (manifest_id,),
        ).fetchone()
        if row is None:
            _fail(FinancialIntegrityError, "population_manifest_missing")
        try:
            inclusion_rules = _stored_values(row["inclusion_rules_json"], "population_manifest_integrity")
            member_rows = connection.execute(
                "SELECT position,member_id FROM population_manifest_members WHERE manifest_id=? ORDER BY position",
                (manifest_id,),
            ).fetchall()
            manifest = PopulationManifest(
                manifest_id=str(row["manifest_id"]),
                manifest_version=int(row["manifest_version"]),
                state_id=str(row["state_id"]),
                deployment_id=str(row["deployment_id"]),
                program_id=str(row["program_id"]),
                period_id=str(row["period_id"]),
                currency=str(row["currency"]),
                pack_id=str(row["pack_id"]),
                cutoff_ms=int(row["cutoff_ms"]),
                inclusion_rules=inclusion_rules,
                source_owner_id=str(row["source_owner_id"]),
                authority_id=str(row["authority_id"]),
                authority_epoch=int(row["authority_epoch"]),
                authority_digest=bytes(row["authority_digest"]),
                approved_by=str(row["approved_by"]),
                approval_ref=str(row["approval_ref"]),
                source_id=str(row["source_id"]),
                source_version=str(row["source_version"]),
                source_digest=bytes(row["source_digest"]),
                member_ids=tuple(str(member["member_id"]) for member in member_rows),
                supersedes_manifest_id=None
                if row["supersedes_manifest_id"] is None
                else str(row["supersedes_manifest_id"]),
                supersedes_digest=None
                if row["supersedes_digest"] is None
                else bytes(row["supersedes_digest"]),
            )
        except (FinancialError, TypeError, ValueError, OverflowError):
            _fail(FinancialIntegrityError, "population_manifest_integrity")
        try:
            valid_persisted_manifest = (
                str(row["contract"]) == _POPULATION_MANIFEST_CONTRACT
                and len(member_rows) == int(row["member_count"])
                and all(int(member["position"]) == index for index, member in enumerate(member_rows))
                and bytes(row["member_digest"]) == manifest.member_digest
                and bytes(row["manifest_digest"]) == manifest.digest
            )
        except (TypeError, ValueError, OverflowError):
            _fail(FinancialIntegrityError, "population_manifest_integrity")
        if not valid_persisted_manifest:
            _fail(FinancialIntegrityError, "population_manifest_integrity")
        if (
            manifest.authority_id != self.trusted_authority.authority_id
            or manifest.authority_epoch != self.trusted_authority.epoch
            or manifest.authority_digest != self.trusted_authority.digest
        ):
            _fail(FinancialIntegrityError, "population_manifest_authority")
        try:
            self.trusted_authority.require(manifest.approved_by, "FINANCE_DECISION")
        except FinancialAuthorityError:
            _fail(FinancialIntegrityError, "population_manifest_approver")
        return manifest, row

    @staticmethod
    def _require_manifest_pack(connection: sqlite3.Connection, manifest: PopulationManifest) -> None:
        """The manifest's approved control pack must cover its scope and cutoff."""

        pack = connection.execute(
            "SELECT * FROM control_packs WHERE pack_id=? AND status='APPROVED'",
            (manifest.pack_id,),
        ).fetchone()
        if pack is None:
            _fail(FinancialIntegrityError, "control_pack_missing")
        if (
            tuple(str(pack[key]) for key in ("state_id", "deployment_id", "program_id", "period_id"))
            != (manifest.state_id, manifest.deployment_id, manifest.program_id, manifest.period_id)
            or not int(pack["effective_start_ms"]) <= manifest.cutoff_ms < int(pack["effective_end_ms"])
        ):
            _fail(FinancialIntegrityError, "population_manifest_pack_scope")

    @staticmethod
    def _manifest_head_rows(
        connection: sqlite3.Connection,
        manifest: PopulationManifest,
    ) -> tuple[sqlite3.Row | None, sqlite3.Row | None]:
        """Return the (head, highest registered version) rows for the manifest's source key."""

        head = connection.execute(
            "SELECT manifest_id,manifest_version,manifest_digest FROM population_manifest_heads "
            "WHERE state_id=? AND deployment_id=? AND program_id=? AND period_id=? AND pack_id=? AND cutoff_ms=? AND source_owner_id=?",
            (manifest.state_id, manifest.deployment_id, manifest.program_id, manifest.period_id, manifest.pack_id, manifest.cutoff_ms, manifest.source_owner_id),
        ).fetchone()
        latest = connection.execute(
            "SELECT manifest_id,manifest_version,manifest_digest FROM population_manifests "
            "WHERE state_id=? AND deployment_id=? AND program_id=? AND period_id=? AND currency=? AND pack_id=? AND cutoff_ms=? AND source_owner_id=? "
            "ORDER BY manifest_version DESC LIMIT 1",
            (manifest.state_id, manifest.deployment_id, manifest.program_id, manifest.period_id, manifest.currency, manifest.pack_id, manifest.cutoff_ms, manifest.source_owner_id),
        ).fetchone()
        return head, latest

    @staticmethod
    def _population_member_ids(connection: sqlite3.Connection, population_id: str) -> tuple[str, ...]:
        return tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT item_id FROM population_items WHERE population_id=? ORDER BY item_id",
                (population_id,),
            )
        )

    def _bound_population_manifest(
        self,
        connection: sqlite3.Connection,
        population: sqlite3.Row,
        *,
        published: bool = False,
    ) -> tuple[PopulationManifest, sqlite3.Row]:
        """Validate the current manifest bound to one population import row; ``published`` also requires a complete, published import."""

        binding = connection.execute(
            "SELECT manifest_id,manifest_version,manifest_digest FROM population_manifest_bindings WHERE population_id=?",
            (str(population["population_id"]),),
        ).fetchone()
        if binding is None:
            _fail(FinancialIntegrityError, "population_manifest_binding_missing")
        if published and (
            str(population["status"]) != "PUBLISHED"
            or int(population["source_complete"]) != 1
            or int(population["imported_count"]) != int(population["expected_count"])
            or int(population["validated_count"]) != int(population["expected_count"])
        ):
            _fail(FinancialIntegrityError, "population_manifest_incomplete")
        rules = _stored_values(population["inclusion_rules_json"], "population_manifest_integrity")
        if published and any(type(value) is not str for value in rules):
            _fail(FinancialIntegrityError, "population_manifest_integrity")
        manifest, manifest_row = self._validate_population_manifest(
            connection,
            manifest_id=str(binding["manifest_id"]),
            pack_id=str(population["pack_id"]),
            cutoff_ms=int(population["cutoff_ms"]),
            inclusion_rules=rules,
            expected_count=int(population["expected_count"]),
        )
        if int(binding["manifest_version"]) != manifest.manifest_version or bytes(binding["manifest_digest"]) != manifest.digest:
            _fail(FinancialIntegrityError, "population_manifest_binding")
        return manifest, manifest_row

    def _validate_population_manifest(
        self,
        connection: sqlite3.Connection,
        *,
        manifest_id: str,
        pack_id: str,
        cutoff_ms: int,
        inclusion_rules: tuple[str, ...],
        expected_count: int,
    ) -> tuple[PopulationManifest, sqlite3.Row]:
        manifest, row = self._load_population_manifest(connection, manifest_id)
        if (
            _attrs(manifest, *_SCOPE_KEYS) != _attrs(self.config, *_SCOPE_KEYS)
            or manifest.pack_id != pack_id
            or manifest.cutoff_ms != cutoff_ms
            or manifest.inclusion_rules != inclusion_rules
        ):
            _fail(FinancialIntegrityError, "population_manifest_scope")
        if expected_count != len(manifest.member_ids):
            _fail(FinancialIntegrityError, "population_manifest_count")
        self._require_manifest_pack(connection, manifest)
        head, latest = self._manifest_head_rows(connection, manifest)
        if head is None or latest is None or tuple(head) != tuple(latest):
            _fail(FinancialIntegrityError, "population_manifest_head")
        if (
            str(head["manifest_id"]) != manifest.manifest_id
            or int(head["manifest_version"]) != manifest.manifest_version
            or bytes(head["manifest_digest"]) != manifest.digest
        ):
            _fail(FinancialConflictError, "population_manifest_stale")
        return manifest, row

    def register_population_manifest(self, manifest: PopulationManifest) -> dict[str, Any]:
        """Record an immutable source roster receipt or an explicit supersession."""

        self._assert_actionable()
        if type(manifest) is not PopulationManifest:
            _fail(FinancialInputError, "population_manifest_type")
        if _attrs(manifest, *_SCOPE_KEYS) != _attrs(self.config, *_SCOPE_KEYS):
            _fail(FinancialInputError, "population_manifest_scope")
        authority = self.trusted_authority
        if (manifest.authority_id, manifest.authority_epoch, manifest.authority_digest) != (authority.authority_id, authority.epoch, authority.digest):
            _fail(FinancialAuthorityError, "population_manifest_authority")
        authority.require(manifest.approved_by, "FINANCE_DECISION")
        encoded_rules = _values_json(manifest.inclusion_rules)
        manifest_digest = manifest.digest
        member_digest = manifest.member_digest
        receipt = {
            "manifest_id": manifest.manifest_id,
            "manifest_version": manifest.manifest_version,
            "manifest_digest": _hex(manifest_digest),
            "member_count": len(manifest.member_ids),
        }
        scope_key = (
            manifest.state_id, manifest.deployment_id, manifest.program_id, manifest.period_id,
            manifest.pack_id, manifest.cutoff_ms, manifest.source_owner_id,
        )
        with self._write() as connection:
            self._require_manifest_pack(connection, manifest)
            head, latest = self._manifest_head_rows(connection, manifest)
            if (head is None) != (latest is None) or (head is not None and tuple(head) != tuple(latest)):
                _fail(FinancialIntegrityError, "population_manifest_head")
            if self._replayed_command(connection, "POPULATION_MANIFEST", manifest.manifest_id, {"manifest_digest": _hex(manifest_digest)}, "population_manifest_identity_conflict"):
                stored_manifest, _stored_row = self._load_population_manifest(connection, manifest.manifest_id)
                if stored_manifest.member_ids != manifest.member_ids:
                    _fail(FinancialIntegrityError, "population_manifest_integrity")
                return {"status": "DUPLICATE", **receipt}
            if head is None:
                if manifest.manifest_version != 1 or manifest.supersedes_manifest_id is not None:
                    _fail(FinancialConflictError, "population_manifest_supersedes_missing")
                before_version = 0
            else:
                prior_id = str(head["manifest_id"])
                prior_digest = bytes(head["manifest_digest"])
                if (
                    manifest.supersedes_manifest_id != prior_id
                    or manifest.supersedes_digest != prior_digest
                    or manifest.manifest_version != int(head["manifest_version"]) + 1
                ):
                    _fail(FinancialConflictError, "population_manifest_supersession_conflict")
                published = connection.execute(
                    "SELECT 1 FROM population_manifest_bindings b JOIN population_imports p USING(population_id) "
                    "WHERE b.manifest_id=? AND p.status='PUBLISHED' LIMIT 1",
                    (prior_id,),
                ).fetchone()
                if published is not None:
                    _fail(FinancialConflictError, "population_manifest_supersede_after_publish")
                before_version = int(head["manifest_version"])
            now_ms = self._now()
            connection.execute(
                "INSERT INTO population_manifests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    manifest.manifest_id, _POPULATION_MANIFEST_CONTRACT, manifest.manifest_version,
                    manifest.state_id, manifest.deployment_id, manifest.program_id, manifest.period_id,
                    manifest.currency, manifest.pack_id, manifest.cutoff_ms, encoded_rules,
                    manifest.source_owner_id, manifest.authority_id, manifest.authority_epoch,
                    manifest.authority_digest, manifest.approved_by, manifest.approval_ref,
                    manifest.source_id, manifest.source_version, manifest.source_digest,
                    len(manifest.member_ids), member_digest, manifest.supersedes_manifest_id,
                    manifest.supersedes_digest, manifest_digest, now_ms,
                ),
            )
            connection.executemany(
                "INSERT INTO population_manifest_members VALUES (?,?,?)",
                ((manifest.manifest_id, index, member_id) for index, member_id in enumerate(manifest.member_ids)),
            )
            if head is None:
                connection.execute(
                    "INSERT INTO population_manifest_heads VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (*scope_key[:4], manifest.currency, *scope_key[4:], manifest.manifest_id, manifest.manifest_version, manifest_digest, now_ms),
                )
                kind = "POPULATION_MANIFEST_REGISTERED"
            else:
                connection.execute(
                    "UPDATE population_manifest_heads SET manifest_id=?,manifest_version=?,manifest_digest=?,updated_at_ms=? "
                    "WHERE state_id=? AND deployment_id=? AND program_id=? AND period_id=? AND pack_id=? AND cutoff_ms=? AND source_owner_id=?",
                    (manifest.manifest_id, manifest.manifest_version, manifest_digest, now_ms, *scope_key),
                )
                kind = "POPULATION_MANIFEST_SUPERSEDED"
            self._append_event(
                connection,
                aggregate_type="POPULATION_MANIFEST",
                aggregate_id=manifest.manifest_id,
                kind=kind,
                before_revision=before_version,
                after_revision=manifest.manifest_version,
                payload={
                    "contract": _POPULATION_MANIFEST_CONTRACT,
                    "manifest_id": manifest.manifest_id,
                    "manifest_version": manifest.manifest_version,
                    "manifest_digest": _hex(manifest_digest),
                    "member_digest": _hex(member_digest),
                    "member_count": len(manifest.member_ids),
                    "supersedes_manifest_id": manifest.supersedes_manifest_id,
                    "supersedes_digest": None if manifest.supersedes_digest is None else _hex(manifest.supersedes_digest),
                },
                committed_at_ms=now_ms,
            )
            return {"status": "REGISTERED" if head is None else "SUPERSEDED", **receipt}

    def _bind_population_manifest(self, connection: sqlite3.Connection, *, population_id: str, manifest_id: str, **identity: Any) -> tuple[PopulationManifest, sqlite3.Row]:
        """``identity`` is the import's pack_id, cutoff_ms, inclusion_rules and expected_count."""
        manifest, row = self._validate_population_manifest(connection, manifest_id=manifest_id, **identity)
        existing = connection.execute(
            "SELECT manifest_id,manifest_version,manifest_digest FROM population_manifest_bindings WHERE population_id=?",
            (population_id,),
        ).fetchone()
        if existing is not None:
            if (
                str(existing["manifest_id"]) != manifest_id
                or int(existing["manifest_version"]) != manifest.manifest_version
                or bytes(existing["manifest_digest"]) != manifest.digest
            ):
                _fail(FinancialConflictError, "population_manifest_binding_conflict")
            return manifest, row
        try:
            connection.execute(
                "INSERT INTO population_manifest_bindings VALUES (?,?,?,?)",
                (population_id, manifest_id, manifest.manifest_version, manifest.digest),
            )
        except sqlite3.IntegrityError:
            _fail(FinancialConflictError, "population_manifest_already_bound")
        return manifest, row

    def _ensure_population_import(self, connection: sqlite3.Connection, *, population_id: str, pack_id: str, cutoff_ms: int, inclusion_rules: tuple[str, ...], expected_count: int, now_ms: int, create: bool) -> tuple[sqlite3.Row, bool, sqlite3.Row]:
        """Return the staged import row, whether this call inserted it, and its approved control pack.

        Only ``stage_population``'s opening transaction may create the row
        (``create=True``); it appends the matching POPULATION_IMPORT_OPENED
        event in that same transaction (Article III.2).
        """
        pack = _one(connection, "control_pack_missing", "SELECT * FROM control_packs WHERE pack_id=? AND status='APPROVED'", (pack_id,))
        existing = connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
        encoded_rules = _values_json(inclusion_rules)
        if existing is not None:
            if (str(existing["pack_id"]), int(existing["cutoff_ms"]), str(existing["inclusion_rules_json"]), int(existing["expected_count"])) != (pack_id, cutoff_ms, encoded_rules, expected_count):
                _fail(FinancialConflictError, "population_import_identity_conflict")
            if str(existing["status"]) == "PUBLISHED":
                _fail(FinancialConflictError, "population_already_published")
            imported = existing["imported_count"]
            if type(imported) is not int or imported < 0 or imported != connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0]:
                _fail(FinancialIntegrityError, "population_manifest_imported_count")
            return existing, False, pack
        if not create:
            _fail(FinancialIntegrityError, "population_import_missing")
        connection.execute(
            "INSERT INTO population_imports VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (population_id, pack_id, cutoff_ms, encoded_rules, expected_count, 0, 0, 0, None, "STAGED", now_ms, now_ms),
        )
        return connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone(), True, pack

    def _stage_population_chunk(self, *, population_id: str, manifest_id: str, identity: dict[str, Any], chunk: tuple[PopulationItem, ...]) -> None:
        if not chunk:
            return
        with self._write() as connection:
            now_ms = self._now()
            population, _created, pack = self._ensure_population_import(connection, population_id=population_id, **identity, now_ms=now_ms, create=False)
            manifest, manifest_row = self._bind_population_manifest(connection, population_id=population_id, manifest_id=manifest_id, **identity)
            manifest_members = set(manifest.member_ids)
            current_count = population["imported_count"]  # its item count (_ensure_population_import)
            seen: dict[str, tuple[str, int, int, str]] = {}
            new_items: list[PopulationItem] = []
            for item in chunk:
                if item.population_id != population_id:
                    _fail(FinancialInputError, "population_item_id")
                if item.due_at_ms < int(pack["effective_start_ms"]):  # item 4: nothing falls due before the pack that governs it takes effect
                    _fail(FinancialInputError, "population_item_due_before_pack")
                if item.item_id not in manifest_members:
                    _fail(FinancialIntegrityError, "population_manifest_extra_member")
                expected = (item.display_label, item.owed_cents, item.due_at_ms, item.currency)
                prior = seen.get(item.item_id)
                if prior is not None:
                    _fail(FinancialIntegrityError, "population_manifest_duplicate_member")
                seen[item.item_id] = expected
                existing = connection.execute("SELECT display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? AND item_id=?", (population_id, item.item_id)).fetchone()
                if existing is not None:
                    if tuple(existing) != expected:
                        _fail(FinancialConflictError, "population_item_conflict")
                    continue
                new_items.append(item)
            if new_items and str(population["status"]) != "STAGED":
                _fail(FinancialConflictError, "population_not_staged")
            if current_count + len(new_items) > identity["expected_count"]:
                _fail(FinancialIntegrityError, "population_count_exceeded")
            if not new_items:
                return
            for item in new_items:
                connection.execute("INSERT INTO population_items VALUES (?,?,?,?,?,?)", (population_id, item.item_id, item.display_label, item.owed_cents, item.due_at_ms, item.currency))
            count = int(connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0])
            connection.execute("UPDATE population_imports SET imported_count=?,updated_at_ms=? WHERE population_id=?", (count, now_ms, population_id))
            self._append_event(
                connection,
                aggregate_type="POPULATION",
                aggregate_id=population_id,
                kind="POPULATION_STAGED",
                before_revision=current_count,
                after_revision=count,
                payload={
                    "population_id": population_id,
                    "imported_count": count,
                    "chunk_count": len(new_items),
                    **_manifest_event_fields(manifest, manifest_row),
                },
                committed_at_ms=now_ms,
            )

    def stage_population(
        self,
        *,
        population_id: str,
        manifest_id: str | None = None,
        pack_id: str,
        cutoff_ms: int,
        inclusion_rules: tuple[str, ...],
        expected_count: int,
        items: Iterable[PopulationItem],
        chunk_size: int = 256,
    ) -> dict[str, Any]:
        """Stream a population into a staged import; publish is a separate gate."""
        self._assert_actionable()
        _id(population_id, "population_id")
        if manifest_id is None:
            _fail(FinancialInputError, "population_manifest_required")
        _id(manifest_id, "population_manifest_id")
        _id(pack_id, "pack_id")
        _time(cutoff_ms, "population_cutoff")
        if type(inclusion_rules) is not tuple or not inclusion_rules:
            _fail(FinancialInputError, "population_inclusion_rules")
        for rule in inclusion_rules:
            _text(rule, "population_inclusion_rule")
        if type(expected_count) is not int or not 1 <= expected_count <= _MAX_ROWS:
            _fail(FinancialInputError, "population_expected_count")
        if type(chunk_size) is not int or not 1 <= chunk_size <= 1000:
            _fail(FinancialInputError, "population_chunk_size")
        iterator = iter(items)
        identity = {"pack_id": pack_id, "cutoff_ms": cutoff_ms, "inclusion_rules": inclusion_rules, "expected_count": expected_count}
        with self._write() as connection:
            self._validate_population_manifest(connection, manifest_id=manifest_id, **identity)
            opened_at_ms = self._now()
            population, created, _pack = self._ensure_population_import(connection, population_id=population_id, **identity, now_ms=opened_at_ms, create=True)
            manifest, manifest_row = self._bind_population_manifest(connection, population_id=population_id, manifest_id=manifest_id, **identity)
            if created:
                # Article III.2: the staged import row and its manifest binding
                # commit together with their history event, exactly once.
                self._append_event(
                    connection,
                    aggregate_type="POPULATION",
                    aggregate_id=population_id,
                    kind="POPULATION_IMPORT_OPENED",
                    before_revision=0,
                    after_revision=0,
                    payload={
                        "population_id": population_id,
                        "staging_digest": _hex(
                            _population_staging_digest(
                                population_id=population_id,
                                pack_id=str(population["pack_id"]),
                                cutoff_ms=int(population["cutoff_ms"]),
                                inclusion_rules_json=str(population["inclusion_rules_json"]),
                                expected_count=int(population["expected_count"]),
                                created_at_ms=int(population["created_at_ms"]),
                            )
                        ),
                        **_manifest_event_fields(manifest, manifest_row),
                    },
                    committed_at_ms=opened_at_ms,
                )
        chunk: list[PopulationItem] = []
        input_limit = min(_MAX_ROWS, expected_count + _MAX_DUPLICATE_INPUTS)
        consumed = 0
        seen_input_ids: set[str] = set()
        for item in iterator:
            consumed += 1
            if consumed > input_limit:
                _fail(FinancialIntegrityError, "population_input_limit")
            if type(item) is not PopulationItem:
                _fail(FinancialInputError, "population_item_type")
            if item.item_id in seen_input_ids:
                _fail(FinancialIntegrityError, "population_manifest_duplicate_member")
            seen_input_ids.add(item.item_id)
            chunk.append(item)
            if len(chunk) >= chunk_size:
                self._stage_population_chunk(population_id=population_id, manifest_id=manifest_id, identity=identity, chunk=tuple(chunk))
                chunk.clear()
        if chunk:
            self._stage_population_chunk(population_id=population_id, manifest_id=manifest_id, identity=identity, chunk=tuple(chunk))
        with self._write() as connection:
            manifest, manifest_row = self._validate_population_manifest(connection, manifest_id=manifest_id, **identity)
            binding = connection.execute(
                "SELECT manifest_id,manifest_version,manifest_digest FROM population_manifest_bindings WHERE population_id=?",
                (population_id,),
            ).fetchone()
            if binding is None or str(binding["manifest_id"]) != manifest_id or bytes(binding["manifest_digest"]) != manifest.digest:
                _fail(FinancialConflictError, "population_manifest_binding_conflict")
            row = _one(connection, "population_import_missing", "SELECT expected_count,imported_count,source_complete FROM population_imports WHERE population_id=?", (population_id,))
            stored_members = self._population_member_ids(connection, population_id)
            persisted_imported_count = row["imported_count"]
            if (
                type(persisted_imported_count) is not int
                or persisted_imported_count < 0
                or len(stored_members) != persisted_imported_count
            ):
                _fail(FinancialIntegrityError, "population_manifest_imported_count")
            if stored_members == manifest.member_ids and int(row["source_complete"]) == 0:
                now_ms = self._now()
                connection.execute("UPDATE population_imports SET source_complete=1,updated_at_ms=? WHERE population_id=?", (now_ms, population_id))
                self._append_event(
                    connection,
                    aggregate_type="POPULATION",
                    aggregate_id=population_id,
                    kind="POPULATION_SOURCE_COMPLETED",
                    before_revision=0,
                    after_revision=int(row["imported_count"]),
                    payload={
                        "population_id": population_id,
                        "imported_count": int(row["imported_count"]),
                        "expected_count": int(row["expected_count"]),
                        **_manifest_event_fields(manifest, manifest_row),
                    },
                    committed_at_ms=now_ms,
                )
        with self._read_snapshot() as connection:
            row = _one(connection, "population_import_missing", "SELECT imported_count,source_complete,status FROM population_imports WHERE population_id=?", (population_id,))
            return {"status": str(row[2]), "population_id": population_id, "imported_count": int(row[0]), "expected_count": expected_count, "source_complete": bool(row[1])}

    def validate_population(self, population_id: str) -> dict[str, Any]:
        self._assert_actionable()
        _id(population_id, "population_id")
        with self._write() as connection:
            row = _one(connection, "population_missing", "SELECT * FROM population_imports WHERE population_id=?", (population_id,))
            manifest, manifest_row = self._bound_population_manifest(connection, row)
            if int(row["source_complete"]) != 1:
                _fail(FinancialIntegrityError, "population_source_incomplete")
            count = int(connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0])
            stored_members = self._population_member_ids(connection, population_id)
            if (
                count != int(row["imported_count"])
                or count != int(row["expected_count"])
                or stored_members != manifest.member_ids
            ):
                _fail(FinancialIntegrityError, "population_incomplete")
            digest = _population_validation_digest(connection.execute("SELECT item_id,display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? ORDER BY item_id", (population_id,)))
            now_ms = self._now()
            connection.execute("UPDATE population_imports SET imported_count=?,validated_count=?,validation_digest=?,status='VALIDATED',updated_at_ms=? WHERE population_id=?", (count, count, digest, now_ms, population_id))
            self._append_event(
                connection,
                aggregate_type="POPULATION",
                aggregate_id=population_id,
                kind="POPULATION_VALIDATED",
                before_revision=0,
                after_revision=count,
                payload={
                    "population_id": population_id,
                    "validated_count": count,
                    "validation_digest": _hex(digest),
                    **_manifest_event_fields(manifest, manifest_row),
                },
                committed_at_ms=now_ms,
            )
            return {
                "status": "VALIDATED",
                "population_id": population_id,
                "validated_count": count,
                "validation_digest": _hex(digest),
                "manifest_id": manifest.manifest_id,
                "manifest_version": manifest.manifest_version,
                "manifest_digest": _hex(manifest.digest),
            }

    def population_status(
        self,
        population_id: str,
        *,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        """Expose bounded completeness facts without returning roster members."""

        _id(population_id, "population_id")
        with self._read_snapshot(_connection=_connection) as connection:
            row = connection.execute(
                "SELECT * FROM population_imports WHERE population_id=?",
                (population_id,),
            ).fetchone()
            if row is None:
                _fail(FinancialIntegrityError, "population_missing")
            base = {
                "population_id": population_id,
                "status": str(row["status"]),
                **_cols(row, int, "imported_count", "expected_count", "validated_count"),
            }
            binding = connection.execute(
                "SELECT manifest_id,manifest_version,manifest_digest FROM population_manifest_bindings WHERE population_id=?",
                (population_id,),
            ).fetchone()
            if binding is None:
                return {
                    **base,
                    "manifest_status": "MISSING",
                    "completeness": "UNVERIFIED",
                    "source_complete": False,
                    "manifest_version": None,
                    "manifest_digest": None,
                }
            manifest, manifest_row = self._load_population_manifest(connection, str(binding["manifest_id"]))
            if int(binding["manifest_version"]) != manifest.manifest_version or bytes(binding["manifest_digest"]) != manifest.digest:
                _fail(FinancialIntegrityError, "population_manifest_binding")
            head, latest = self._manifest_head_rows(connection, manifest)
            if (
                head is None
                or latest is None
                or (head["manifest_id"], head["manifest_digest"]) != (latest["manifest_id"], latest["manifest_digest"])
            ):
                _fail(FinancialIntegrityError, "population_manifest_head")
            current = (
                head is not None
                and str(head["manifest_id"]) == manifest.manifest_id
                and bytes(head["manifest_digest"]) == manifest.digest
            )
            actual_members = self._population_member_ids(connection, population_id)
            if len(actual_members) != int(row["imported_count"]):
                _fail(FinancialIntegrityError, "population_manifest_imported_count")
            exact = actual_members == manifest.member_ids
            complete = (
                current
                and exact
                and int(row["source_complete"]) == 1
                and int(row["imported_count"]) == len(manifest.member_ids)
                and int(row["expected_count"]) == len(manifest.member_ids)
            )
            return {
                **base,
                "manifest_status": "CURRENT" if current else "SUPERSEDED",
                "completeness": "EXACT" if complete else ("STALE" if not current else "INCOMPLETE"),
                "source_complete": complete,
                "manifest_version": manifest.manifest_version,
                "manifest_digest": _hex(bytes(manifest_row["manifest_digest"])),
            }

    def _scope_value(self) -> dict[str, str]:
        return _attrs(self.config, *_SCOPE_KEYS)

    def _evaluation_input_snapshot(
        self,
        connection: sqlite3.Connection,
        *,
        obligation_id: str,
        pre_revision: int,
    ) -> dict[str, Any]:
        obligation = connection.execute(
            "SELECT obligation_id,item_id,revision,rule_version,owed_cents,due_at_ms,reporting_complete FROM obligations WHERE obligation_id=?",
            (obligation_id,),
        ).fetchone()
        if obligation is None:
            _fail(FinancialIntegrityError, "evaluation_input_obligation_missing")
        item_id = str(obligation["item_id"])
        if int(obligation["revision"]) != pre_revision:
            _fail(FinancialRevisionError, "evaluation_input_revision")
        return {
            "pre_revision": pre_revision,
            "obligation": {
                "obligation_id": str(obligation["obligation_id"]),
                "item_id": item_id,
                **_cols(obligation, int, "revision", "rule_version", "owed_cents", "due_at_ms", "reporting_complete"),
            },
            "evidence": [
                {
                    "evidence_id": str(row["evidence_id"]),
                    "record_digest": _hex(bytes(row["record_digest"])),
                    "event_at_ms": int(row["event_at_ms"]),
                    "received_at_ms": int(row["received_at_ms"]),
                }
                for row in connection.execute(
                    "SELECT evidence_id,record_digest,event_at_ms,received_at_ms FROM evidence WHERE item_id=? ORDER BY evidence_id",
                    (item_id,),
                )
            ],
            "payments": [
                {
                    "payment_id": str(row["payment_id"]),
                    **_cols(row, int, "amount_cents", "event_at_ms", "active"),
                }
                for row in connection.execute(
                    "SELECT payment_id,amount_cents,event_at_ms,active FROM payments WHERE obligation_id=? ORDER BY payment_id",
                    (obligation_id,),
                )
            ],
            "claims": [
                {
                    "claim_id": str(row["claim_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "status": str(row["status"]),
                }
                for row in connection.execute(
                    "SELECT claim_id,amount_cents,status FROM claimed_adjustments WHERE obligation_id=? ORDER BY claim_id",
                    (obligation_id,),
                )
            ],
            "determinations": [
                {
                    "determination_id": str(row["determination_id"]),
                    "decision": str(row["decision"]),
                    "amount_cents": int(row["amount_cents"]),
                    "decided_at_ms": int(row["decided_at_ms"]),
                }
                for row in connection.execute(
                    "SELECT determination_id,decision,amount_cents,decided_at_ms FROM determinations WHERE obligation_id=? ORDER BY determination_id",
                    (obligation_id,),
                )
            ],
            "cases": [
                {"case_id": str(row["case_id"]), "status": str(row["status"])}
                for row in connection.execute(
                    "SELECT case_id,status FROM cases WHERE obligation_id=? ORDER BY case_id",
                    (obligation_id,),
                )
            ],
            "actions": [
                {
                    "action_id": str(row["action_id"]),
                    "status": str(row["status"]),
                    "created_at_ms": int(row["created_at_ms"]),
                }
                for row in connection.execute(
                    "SELECT action_id,status,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id",
                    (obligation_id,),
                )
            ],
            "conflicts": [
                str(row["conflict_id"])
                for row in connection.execute(
                    "SELECT conflict_id FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id",
                    (obligation_id,),
                )
            ],
        }

    def _insert_evaluation(
        self,
        connection: sqlite3.Connection,
        *,
        result: Mapping[str, Any],
        pack: ControlPack,
        evidence_ids: Iterable[str] | None = None,
        evidence_bindings: list[dict[str, str]] | None = None,
        authority_epoch: int,
        authority_digest: bytes,
    ) -> dict[str, Any]:
        if (evidence_ids is None) == (evidence_bindings is None):
            _fail(FinancialIntegrityError, "evaluation_evidence_source")
        result_body = _evaluation_result_body(result)
        result_digest = _digest(_EVALUATION_RESULT_DOMAIN, _canonical(result_body))
        stored_result = {**result_body, "result_digest": _hex(result_digest)}
        result_revision = int(result["revision"])
        pre_revision = result_revision if result_revision == 0 else result_revision - 1
        input_snapshot = self._evaluation_input_snapshot(
            connection,
            obligation_id=str(result["obligation_id"]),
            pre_revision=pre_revision,
        )
        if evidence_bindings is None:  # batch-frames-v1 D4: the rows the snapshot just read, not a second query
            ordered = list(evidence_ids)
            if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
                _fail(FinancialIntegrityError, "evaluation_evidence_order")
            digests = {row["evidence_id"]: row["record_digest"] for row in input_snapshot["evidence"]}
            if not digests.keys() >= set(ordered):
                _fail(FinancialIntegrityError, "evaluation_evidence_missing")
            evidence_bindings = [{"evidence_id": evidence_id, "record_digest": digests[evidence_id]} for evidence_id in ordered]
        input_snapshot_bytes = _canonical(input_snapshot)
        input_snapshot_digest = _digest(_EVALUATION_INPUT_DOMAIN, input_snapshot_bytes)
        receipt_body = _evaluation_receipt_body(
            result=stored_result,
            scope=self._scope_value(),
            control_pack_id=pack.pack_id,
            control_pack_version=pack.version,
            control_pack_digest=pack.digest,
            evidence_bindings=evidence_bindings,
            authority_id=str(result["authority_id"]),
            authority_epoch=authority_epoch,
            authority_digest=authority_digest,
            input_snapshot_digest=input_snapshot_digest,
            result_digest=result_digest,
        )
        receipt_digest = _digest(_EVALUATION_RECEIPT_DOMAIN, _canonical(receipt_body))
        values: dict[str, Any] = {
            **stored_result,
            "evidence_ids_json": _canonical({"evidence_ids": list(result["evidence_ids"])}).decode("ascii"),
            "contract_version": _EVALUATION_RECEIPT_CONTRACT,
            "scope_json": _canonical(self._scope_value()).decode("ascii"),
            "control_pack_id": pack.pack_id,
            "control_pack_version": pack.version,
            "control_pack_digest": pack.digest,
            "authority_epoch": authority_epoch,
            "authority_digest": authority_digest,
            "evidence_bindings_json": _canonical({"bindings": evidence_bindings}).decode("ascii"),
            "input_snapshot_json": input_snapshot_bytes.decode("ascii"),
            "input_snapshot_digest": input_snapshot_digest,
            "receipt_digest": receipt_digest,
        }
        values["result_digest"] = result_digest
        self._insert_row(connection, "evaluations", values)
        return {
            **stored_result,
            "receipt_digest": _hex(receipt_digest),
            "evaluation_result_digest": _hex(result_digest),
            "input_snapshot_digest": _hex(input_snapshot_digest),
        }

    def _insert_initial_evaluation(self, connection: sqlite3.Connection, *, obligation_id: str, owed_cents: int, rule_version: int, pack: ControlPack, now_ms: int) -> dict[str, Any]:
        result = {"evaluation_id": f"evaluation:{obligation_id}:r0", "obligation_id": obligation_id, "revision": 0, "rule_version": rule_version, "evidence_ids": [], "authority_id": self.trusted_authority.authority_id, "evaluated_at_ms": now_ms, "owed_cents": owed_cents, "claimed_adjustment_cents": 0, "lawful_adjustment_cents": 0, "received_cash_cents": 0, "shortfall_cents": owed_cents, "overage_cents": 0, "cash_satisfied": 0, "amount_satisfied": 0, "timely": 0, "reporting_complete": 0, "verification_status": "MISSING_EVIDENCE", "case_status": "OPEN", "delivery_status": "NONE"}
        return self._insert_evaluation(
            connection,
            result=result,
            pack=pack,
            evidence_ids=[],
            authority_epoch=self.trusted_authority.epoch,
            authority_digest=self.trusted_authority.digest,
        )

    @staticmethod
    def _obligation_id(item_id: str, period_id: str) -> str:
        suffix = period_id
        marker = "period-"
        if marker in period_id:
            suffix = marker + period_id.rsplit(marker, 1)[1]
        return f"obligation:{item_id}:{suffix}"

    def _ensure_case(self, connection: sqlite3.Connection, *, obligation_id: str, reason: str, owner: str, due_at_ms: int, status: str, now_ms: int) -> None:
        case_id = f"case:{obligation_id}"
        existing = connection.execute("SELECT status FROM cases WHERE case_id=?", (case_id,)).fetchone()
        conditions = _canonical({"amount_satisfied": True, "reporting_complete": True, "delivery_acknowledged_or_not_required": True}).decode("ascii")
        if existing is None:
            connection.execute("INSERT INTO cases VALUES (?,?,?,?,?,?,?, ?,?)", (case_id, obligation_id, reason, "PROGRAM_ACCOUNTABILITY", owner, due_at_ms, conditions, status, now_ms))
        elif existing[0] != "CORRECTION_REQUIRED":  # an outstanding correction keeps its case, owner and due date
            connection.execute("UPDATE cases SET reason=?,next_action_owner=?,due_at_ms=?,status=?,updated_at_ms=? WHERE case_id=?", (reason, owner, due_at_ms, status, now_ms, case_id))

    def publish_population(self, population_id: str) -> dict[str, Any]:
        """Publish only a fully validated population and create obligations atomically."""
        self._assert_actionable()
        _id(population_id, "population_id")
        with self._write() as connection:
            import_row = connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
            if import_row is None or str(import_row["status"]) != "VALIDATED" or int(import_row["source_complete"]) != 1:
                _fail(FinancialIntegrityError, "population_not_validated")
            manifest, manifest_row = self._bound_population_manifest(connection, import_row)
            if connection.execute("SELECT 1 FROM obligations WHERE population_id=? LIMIT 1", (population_id,)).fetchone() is not None:
                _fail(FinancialConflictError, "population_already_published")
            pack = _one(connection, "control_pack_missing", "SELECT * FROM control_packs WHERE pack_id=?", (import_row["pack_id"],))
            now_ms = self._now()
            items = connection.execute("SELECT item_id,display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? ORDER BY item_id", (population_id,)).fetchall()
            stored_members = tuple(str(item[0]) for item in items)
            if (
                stored_members != manifest.member_ids
                or len(items) != len(manifest.member_ids)
                or int(import_row["imported_count"]) != len(items)
                or int(import_row["validated_count"]) != len(items)
            ):
                _fail(FinancialIntegrityError, "population_manifest_incomplete")
            if import_row["validation_digest"] is None or bytes(import_row["validation_digest"]) != _population_validation_digest(items):
                _fail(FinancialIntegrityError, "population_validation_changed")
            control_pack = _control_pack_from_row(pack)
            initial_evaluation_bindings: list[dict[str, str]] = []
            for item_id, _label, owed_cents, due_at_ms, currency in items:
                obligation_id = self._obligation_id(str(item_id), str(pack["period_id"]))
                connection.execute("INSERT INTO obligations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (obligation_id, population_id, str(item_id), str(pack["period_id"]), str(currency), int(owed_cents), int(due_at_ms), int(pack["version"]), 0, 0, 0, 0, int(owed_cents), 0, 0, 0, 0, 0, "MISSING_EVIDENCE", "OPEN", "NONE", f"evaluation:{obligation_id}:r0", now_ms))
                self._ensure_case(connection, obligation_id=obligation_id, reason="INITIAL_ACCOUNTABILITY", owner="CASE_OWNER", due_at_ms=int(due_at_ms), status="OPEN", now_ms=now_ms)
                initial_evaluation = self._insert_initial_evaluation(
                    connection,
                    obligation_id=obligation_id,
                    owed_cents=int(owed_cents),
                    rule_version=int(pack["version"]),
                    pack=control_pack,
                    now_ms=now_ms,
                )
                initial_evaluation_bindings.append(
                    {
                        "evaluation_id": str(initial_evaluation["evaluation_id"]),
                        "input_snapshot_digest": str(initial_evaluation["input_snapshot_digest"]),
                        "result_digest": str(initial_evaluation["evaluation_result_digest"]),
                        "receipt_digest": str(initial_evaluation["receipt_digest"]),
                    }
                )
            connection.execute("UPDATE population_imports SET status='PUBLISHED',updated_at_ms=? WHERE population_id=?", (now_ms, population_id))
            self._append_event(
                connection,
                aggregate_type="POPULATION",
                aggregate_id=population_id,
                kind="POPULATION_PUBLISHED",
                before_revision=0,
                after_revision=len(items),
                payload={
                    "population_id": population_id,
                    "item_count": len(items),
                    "pack_id": str(import_row["pack_id"]),
                    "pack_version": int(pack["version"]),
                    "evaluation_count": len(initial_evaluation_bindings),
                    "evaluation_binding_digest": _hex(_evaluation_binding_digest(initial_evaluation_bindings)),
                    **_manifest_event_fields(manifest, manifest_row),
                },
                committed_at_ms=now_ms,
            )
            return {
                "status": "PUBLISHED",
                "population_id": population_id,
                "item_count": len(items),
                "pack_id": str(import_row["pack_id"]),
                "pack_version": int(pack["version"]),
                "manifest_id": manifest.manifest_id,
                "manifest_version": manifest.manifest_version,
                "manifest_digest": _hex(manifest.digest),
            }

    def _new_evidence(
        self,
        *,
        evidence_id: str,
        item_id: str,
        kind: str,
        common_origin_id: str,
        source_id: str,
        source_version: str,
        local_ref: str,
        applicable_at_ms: int,
        event_at_ms: int,
        received_at_ms: int,
        amount_cents: int | None = None,
        reversal_of: str | None = None,
        supersedes: str | None = None,
    ) -> EvidenceRecord:
        content_digest = _digest(_EVIDENCE_DOMAIN, _canonical({"source_id": source_id, "source_version": source_version, "local_ref": local_ref, "common_origin_id": common_origin_id, "kind": kind}))
        return EvidenceRecord(evidence_id, item_id, kind, common_origin_id, source_id, source_version, local_ref, applicable_at_ms, event_at_ms, received_at_ms, content_digest, amount_cents, reversal_of, supersedes)

    def _check_revision(self, row: sqlite3.Row, expected_revision: int | None) -> None:
        if expected_revision is not None and (type(expected_revision) is not int or expected_revision != int(row["revision"])):
            _fail(FinancialRevisionError, "obligation_revision_conflict")

    def _decide_payment(self, connection: sqlite3.Connection, obligation: sqlite3.Row, expected_revision: int | None, command: dict[str, Any]) -> dict[str, Any]:
        """M3: Lean decides one payment command (BLFPAY01); this writes exactly the rows it names (V.1)."""

        from app import right_rail_financial_engine as financial_engine
        from app import right_rail_financial_semantic_adapter as semantic

        if expected_revision is not None and (type(expected_revision) is not int or not 0 <= expected_revision < 1 << 63):
            _fail(FinancialRevisionError, "obligation_revision_conflict")
        obligation_id, now = str(obligation["obligation_id"]), self._now()
        asked = max(now, int(obligation["updated_at_ms"]))  # D4: a clock behind the last update is asked at that update, and only an exact retry is answered
        try:
            out = financial_engine.decide_payment_live(
                connection, obligation_id=obligation_id, authority_context=semantic.TrustedAuthorityContext.from_authority(self.trusted_authority), now_ms=asked,
                verification={"scope": self._scope_value(), "owner_id": self.owner_id, "mode": self.mode}, expected_revision=expected_revision,
                command=command, receipts=_payment_receipts(connection, obligation_id))
        except (FinancialError, financial_engine.FinancialEngineError) as error:
            _fail(FinancialIntegrityError, f"lean_payment:{error}")
        if asked > now and out.status != "DUPLICATE":  # a DUPLICATE writes nothing; any other answer fails closed as before
            _fail(FinancialIntegrityError, "lean_payment:obligation_after_evaluation")
        if out.reason is not None:
            _fail(*_PAYMENT_REFUSALS[out.reason])
        if out.evidence is not None:
            self._insert_evidence(connection, self._new_evidence(**out.evidence))
        if out.status == "RECORDED":
            connection.execute("INSERT INTO payments VALUES (:payment_id,:obligation_id,:item_id,:evidence_id,:common_origin_id,:amount_cents,:event_at_ms,:active,:reversed_by_evidence_id)", out.payment_row)
        elif out.status == "REVERSED":
            if connection.execute("UPDATE payments SET active=0,reversed_by_evidence_id=:reversed_by_evidence_id WHERE payment_id=:payment_id AND obligation_id=:obligation_id AND active=1", out.payment_row).rowcount != 1:
                _fail(FinancialIntegrityError, "payment_reversal_rows")
        if out.conflict_row is not None:
            connection.execute("INSERT INTO financial_conflicts VALUES (:conflict_id,:obligation_id,:common_origin_id,:existing_payment_id,:candidate_evidence_id,:existing_amount_cents,:candidate_amount_cents,:reason,:visible_at_ms)", out.conflict_row)
        if out.decided is not None:
            self._recompute_and_record(connection, obligation_id, kind=out.event_kind, payload=out.event_payload, now_ms=now, decided=out.decided)
        elif out.event_kind is not None:  # a confirmation of a recorded origin: an event, no new revision
            revision = int(obligation["revision"])
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=obligation_id, kind=out.event_kind, before_revision=revision, after_revision=revision, payload=out.event_payload, committed_at_ms=now)
        return out.answer(self._current_projection(connection, obligation_id))

    def _projection_for_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            **_cols(row, str, "obligation_id", "item_id", "population_id", "period_id", "currency"),
            **_cols(row, int, "revision", "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents"),
            **_cols(row, bool, "cash_satisfied", "amount_satisfied", "timely", "reporting_complete"),
            **_cols(row, str, "verification_status", "case_status", "delivery_status"),
            "current_evaluation_id": _opt(row["current_evaluation_id"], str),
            "due_at_ms": int(row["due_at_ms"]),
        }

    def _obligation_by_id(self, connection: sqlite3.Connection, obligation_id: str) -> sqlite3.Row:
        row = _one(connection, "obligation_missing", "SELECT * FROM obligations WHERE obligation_id=?", (obligation_id,))
        return row

    def _current_projection(self, connection: sqlite3.Connection, obligation_id: str) -> dict[str, Any]:
        return self._projection_for_row(self._obligation_by_id(connection, obligation_id))

    def record_support_evidence(
        self,
        *,
        item_id: str,
        evidence_id: str,
        common_origin_id: str,
        source_id: str = "synthetic-source",
        source_version: str = "fixture-v1",
        local_ref: str | None = None,
        applicable_at_ms: int = 1,
        event_at_ms: int = 1,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        """Received time is the owner clock, never the caller's; event_at_ms is when the document is dated. A retry ignores expected_revision."""
        self._assert_actionable()
        with self._write() as connection:
            evidence = self._new_evidence(evidence_id=evidence_id, item_id=item_id, kind="SUPPORT", common_origin_id=common_origin_id, source_id=source_id, source_version=source_version, local_ref=local_ref or f"support:{evidence_id}", applicable_at_ms=applicable_at_ms, event_at_ms=event_at_ms, received_at_ms=self._now())
            obligation = self._get_obligation_row(connection, item_id)
            status = self._insert_evidence(connection, evidence)
            if status == "DUPLICATE":
                return {"status": "DUPLICATE", **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)  # after the retry test (III.3); a stale write rolls the insert back
            self._recompute_and_record(connection, str(obligation["obligation_id"]), kind="SUPPORT_EVIDENCE_RECORDED", payload={"evidence_id": evidence_id, "record_digest": _hex(evidence.record_digest)}, now_ms=self._now())
            return {"status": "RECORDED", **self._current_projection(connection, str(obligation["obligation_id"]))}

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
        pays_action_id: str | None = None,
    ) -> dict[str, Any]:
        """Record one payment once by common origin; conflicts never mutate cash. A payment answering
        a correction request names it (pays_action_id) and never pays more than the request leaves unpaid."""
        self._assert_actionable()
        _id(payment_id, "payment_id")
        if pays_action_id is not None:
            _id(pays_action_id, "pays_action_id")
        _cents(amount_cents, "payment_amount", nonnegative=True)
        _id(item_id, "item_id")
        _id(common_origin_id, "common_origin_id")
        _id(source_id, "source_id")
        _id(evidence_id, "evidence_id")
        _id(source_version, "source_version")
        if local_ref:
            _id(local_ref, "local_ref")
        with self._write() as connection:
            return self._decide_payment(connection, self._get_obligation_row(connection, item_id), expected_revision, {
                "kind": "record", "payment_id": payment_id, "evidence_id": evidence_id, "common_origin_id": common_origin_id, "source_id": source_id,
                "source_version": source_version, "local_ref": local_ref or None, "amount_cents": amount_cents, "event_at_ms": event_at_ms, "pays_action_id": pays_action_id})

    def reverse_payment(
        self,
        *,
        item_id: str,
        payment_id: str,
        evidence_id: str,
        common_origin_id: str | None = None,
        event_at_ms: int | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        _id(payment_id, "payment_id")
        _id(evidence_id, "evidence_id")
        with self._write() as connection:
            return self._decide_payment(connection, self._get_obligation_row(connection, item_id), expected_revision, {
                "kind": "reverse", "payment_id": payment_id, "evidence_id": evidence_id, "common_origin_id": common_origin_id or None, "event_at_ms": event_at_ms})

    def record_offset_claim(
        self,
        *,
        item_id: str,
        claim_id: str,
        amount_cents: int,
        evidence_id: str,
        owner_role: str = "CASE_OWNER",
        deadline_ms: int,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        _id(claim_id, "claim_id")
        _cents(amount_cents, "offset_amount", nonnegative=True)
        if amount_cents == 0:
            _fail(FinancialInputError, "offset_amount_zero")
        _role(owner_role, "offset_owner_role")
        _time(deadline_ms, "offset_deadline")
        with self._write() as connection:
            now_ms = self._now()
            evidence = self._new_evidence(evidence_id=evidence_id, item_id=item_id, kind="OFFSET_CLAIM", common_origin_id=claim_id, source_id="synthetic-offset-source", source_version="fixture-v1", local_ref=f"offset:{claim_id}", applicable_at_ms=now_ms, event_at_ms=now_ms, received_at_ms=now_ms, amount_cents=amount_cents)
            obligation = self._get_obligation_row(connection, item_id)
            pack, _calculation, _adjustment = self._control_pack_for_obligation(connection, str(obligation["obligation_id"]))
            if owner_role not in pack.authorized_roles:
                _fail(FinancialAuthorityError, "control_pack_owner_role_not_authorized")
            request = {"item_id": item_id, "evidence_id": evidence_id, "amount_cents": amount_cents, "owner_role": owner_role, "deadline_ms": deadline_ms}
            if self._replayed_command(connection, "OFFSET_CLAIM", claim_id, request, "offset_claim_identity_conflict"):
                return {"status": "DUPLICATE", "claim_id": claim_id, **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)
            evidence_status = self._insert_evidence(connection, evidence)
            if evidence_status == "DUPLICATE":
                _fail(FinancialConflictError, "offset_evidence_reused")
            connection.execute("INSERT INTO claimed_adjustments VALUES (?,?,?,?,?,?,?,?,?)", (claim_id, obligation["obligation_id"], evidence_id, amount_cents, owner_role, deadline_ms, "CLAIMED", now_ms, now_ms))
            self._ensure_case(connection, obligation_id=str(obligation["obligation_id"]), reason="UNSUPPORTED_OFFSET", owner=owner_role, due_at_ms=deadline_ms, status="OPEN", now_ms=now_ms)
            self._recompute_and_record(connection, str(obligation["obligation_id"]), kind="OFFSET_CLAIMED", payload={"claim_id": claim_id, "evidence_id": evidence_id, "amount_cents": amount_cents}, now_ms=now_ms)
            return {"status": "CLAIMED", "claim_id": claim_id, **self._current_projection(connection, str(obligation["obligation_id"]))}

    def retry_action(self, action_id: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Retry a state-owned action without permitting payload replacement."""
        self._assert_actionable()
        _id(action_id, "action_id")
        if payload is not None and not isinstance(payload, Mapping):
            _fail(FinancialInputError, "action_payload")
        with self._write() as connection:
            action = _one(connection, "action_missing", "SELECT * FROM actions WHERE action_id=?", (action_id,))
            stored_payload = _stored_object(action["payload_json"], "action_payload_integrity")
            if payload is not None and _canonical(dict(payload)) != _canonical(stored_payload):
                _fail(FinancialConflictError, "action_payload_immutable")
            return {"status": "DUPLICATE", "action_id": action_id, **self._current_projection(connection, str(action["obligation_id"]))}

    def _authority_action(self, connection: sqlite3.Connection, obligation_id: str, actor_id: str, actor_role: str) -> ControlPack:
        self.trusted_authority.require(actor_id, actor_role)
        pack, _calculation, _adjustment = self._control_pack_for_obligation(connection, obligation_id)
        if actor_role not in pack.authorized_roles: _fail(FinancialAuthorityError, "control_pack_actor_role_not_authorized")
        return pack

    def _validate_evaluation_reference(
        self,
        connection: sqlite3.Connection,
        obligation: sqlite3.Row,
        *,
        claim_evidence_id: str,
        evaluation_id: str | None,
        evaluation_result_digest: str | bytes | None,
        expected_revision: int | None,
        decision_time: int,
    ) -> tuple[sqlite3.Row, dict[str, Any], bytes]:
        if evaluation_id is None or evaluation_result_digest is None:
            _fail(FinancialInputError, "evaluation_reference_required")
        if type(expected_revision) is not int:
            _fail(FinancialInputError, "expected_revision_required")
        _id(evaluation_id, "evaluation_id")
        provided_digest = _digest_input(evaluation_result_digest, "evaluation_result_digest")
        if expected_revision != int(obligation["revision"]):
            _fail(FinancialRevisionError, "obligation_revision_conflict")
        if str(obligation["current_evaluation_id"]) != evaluation_id:
            _fail(FinancialRevisionError, "evaluation_revision_conflict")
        row = _one(connection, "evaluation_reference_missing", "SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?", (evaluation_id, obligation["obligation_id"]))
        if int(row["revision"]) != expected_revision or bytes(row["result_digest"]) != provided_digest:
            _fail(FinancialRevisionError, "evaluation_reference_conflict")
        receipt = self._evaluation_receipt_for_row(connection, row)
        if receipt["result_digest"] != _hex(provided_digest) or int(receipt["revision"]) != expected_revision:
            _fail(FinancialRevisionError, "evaluation_reference_conflict")
        if claim_evidence_id not in receipt["evidence_ids"]:
            _fail(FinancialIntegrityError, "evaluation_evidence_coverage")
        if int(receipt["evaluated_at_ms"]) > decision_time:
            _fail(FinancialIntegrityError, "evaluation_chronology")
        for key in (
            "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents",
            "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely",
            "reporting_complete", "verification_status", "case_status", "delivery_status",
        ):
            if receipt[key] != obligation[key]:
                _fail(FinancialRevisionError, "evaluation_projection_conflict")
        consumed = connection.execute("SELECT determination_id FROM determinations WHERE input_evaluation_id=?", (evaluation_id,)).fetchone()
        if consumed is not None:
            _fail(FinancialConflictError, "evaluation_already_consumed")
        return row, receipt, provided_digest

    def _validate_staff_correction_binding(
        self,
        connection: sqlite3.Connection,
        *,
        binding: Mapping[str, Any],
        item_id: str,
        obligation: sqlite3.Row,
        action_id: str,
        expected_revision: int | None,
        evaluation_id: str | None,
        evaluation_result_digest: str | bytes | None,
        duplicate: bool,
    ) -> None:
        """Bind a staff correction to the displayed verified Owner snapshot."""

        def malformed() -> None:
            _fail(FinancialInputError, "staff_command_binding")

        def conflict() -> None:
            if duplicate:
                _fail(FinancialConflictError, "determination_request_conflict")
            _fail(FinancialRevisionError, "obligation_revision_conflict")

        if type(binding) is not dict or set(binding) != {
            "contract", "snapshot", "item_binding", "authority", "input",
        } or binding.get("contract") != "RR/FINANCIAL/STAFF-COMMAND-BINDING/v2":
            malformed()
        snapshot = binding["snapshot"]
        if not _shaped(snapshot, _STAFF_SNAPSHOT_SHAPE):
            malformed()
        if snapshot["snapshot_id"] != _staff_snapshot_id({key: value for key, value in snapshot.items() if key != "snapshot_id"}):
            conflict()
        item_binding, authority, input_binding = binding["item_binding"], binding["authority"], binding["input"]
        if not (_shaped(item_binding, _STAFF_ITEM_BINDING_SHAPE) and _shaped(authority, _STAFF_AUTHORITY_SHAPE) and _shaped(input_binding, _STAFF_INPUT_SHAPE)):
            malformed()
        if (
            expected_revision is None
            or evaluation_id is None
            or evaluation_result_digest is None
            or item_binding["item_id"] != item_id
            or item_binding["obligation_id"] != str(obligation["obligation_id"])
            or item_binding["revision"] != expected_revision
            or item_binding["evaluation_id"] != evaluation_id
            or item_binding["evaluation_result_digest"] != _hex(_digest_input(evaluation_result_digest, "evaluation_result_digest"))
            or input_binding["evaluation_id"] != evaluation_id
            or input_binding["evaluation_result_digest"] != item_binding["evaluation_result_digest"]
        ):
            conflict()

        evaluation = connection.execute(
            "SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?",
            (evaluation_id, obligation["obligation_id"]),
        ).fetchone()
        if evaluation is None:
            conflict()
        result_hex = _hex(bytes(evaluation["result_digest"]))
        expected_item_binding = {
            "item_id": item_id,
            "obligation_id": str(obligation["obligation_id"]),
            "revision": int(evaluation["revision"]),
            "evaluation_id": str(evaluation["evaluation_id"]),
            "evaluation_result_digest": result_hex,
            "control_pack_id": str(evaluation["control_pack_id"]),
            "control_pack_version": int(evaluation["control_pack_version"]),
            "control_pack_digest": _hex(bytes(evaluation["control_pack_digest"])),
        }
        expected_authority = _row_authority(evaluation)
        expected_input = {"evaluation_id": str(evaluation["evaluation_id"]), "evaluation_result_digest": result_hex, "receipt_digest": _hex(bytes(evaluation["receipt_digest"]))}
        if item_binding != expected_item_binding or authority != expected_authority or input_binding != expected_input:
            conflict()

        meta = self._meta(connection)
        expected_snapshot = {
            "schema": str(meta["schema"]),
            "schema_version": int(meta["schema_version"]),
            "scope": self._scope_value(),
            "mode": str(meta["mode"]),
            "owner_id": str(meta["owner_id"]),
            "continuity_epoch": int(meta["continuity_epoch"]),
        }
        if any(snapshot[key] != value for key, value in expected_snapshot.items()):
            conflict()

        if duplicate:
            determination = connection.execute(
                "SELECT expected_revision,input_evaluation_id,input_evaluation_result_digest "
                "FROM determinations WHERE determination_id=?",
                (f"determination:{action_id}",),
            ).fetchone()
            if (
                determination is None
                or int(determination["expected_revision"]) != expected_revision
                or str(determination["input_evaluation_id"]) != evaluation_id
                or bytes(determination["input_evaluation_result_digest"])
                != _digest_input(evaluation_result_digest, "evaluation_result_digest")
            ):
                conflict()
            events = connection.execute(
                "SELECT event_sequence,before_revision,previous_head,payload_json FROM financial_events "
                "WHERE aggregate_type='OBLIGATION' AND aggregate_id=? "
                "AND kind='OFFSET_REJECTED_CORRECTION_AUTHORIZED' ORDER BY event_sequence DESC",
                (obligation["obligation_id"],),
            ).fetchall()
            for event in events:
                event_payload = _stored_object(event["payload_json"], "staff_command_binding_event")
                if event_payload.get("action_id") == action_id:
                    # The event's own ``evaluation_id`` is the result evaluation
                    # the transition created; the reviewed input evaluation is
                    # recorded in ``correction_followup.input_evaluation``.
                    followup = event_payload.get("correction_followup")
                    input_evaluation = followup.get("input_evaluation") if type(followup) is dict else None
                    if (
                        int(event["event_sequence"]) == snapshot["sequence"] + 1
                        and int(event["before_revision"]) == expected_revision
                        and bytes(event["previous_head"]).hex().upper() == snapshot["history_head"]
                        and type(input_evaluation) is dict
                        and input_evaluation.get("evaluation_id") == evaluation_id
                        and input_evaluation.get("result_digest")
                        == _hex(_digest_input(evaluation_result_digest, "evaluation_result_digest"))
                        and event_payload.get("determination_id") == f"determination:{action_id}"
                    ):
                        return
                    break
            conflict()

        meta_sequence = int(meta["sequence"])
        meta_head = _hex(bytes(meta["history_head"]))
        if snapshot["sequence"] != meta_sequence or snapshot["history_head"] != meta_head:
            _fail(FinancialRevisionError, "obligation_revision_conflict")

    def _duplicate_action_or_conflict(
        self,
        connection: sqlite3.Connection,
        *,
        action: sqlite3.Row,
        obligation: sqlite3.Row,
        claim_id: str,
        actor_id: str,
        actor_role: str,
        decision: str,
        evaluation_id: str | None,
        evaluation_result_digest: str | bytes | None,
        expected_revision: int | None,
        decision_at_ms: int | None,
    ) -> dict[str, Any]:
        if expected_revision is not None and type(expected_revision) is not int:
            _fail(FinancialInputError, "expected_revision")
        if decision_at_ms is not None:
            _time(decision_at_ms, "decision_time")
        request = {
            "item_id": str(obligation["item_id"]),
            "claim_id": claim_id,
            "decision": decision,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "evaluation_id": evaluation_id,
            "evaluation_result_digest": None if evaluation_result_digest is None else _hex(_digest_input(evaluation_result_digest, "evaluation_result_digest")),
            "expected_revision": expected_revision,
            "decided_at_ms": decision_at_ms,
        }
        if not self._replayed_command(connection, "OFFSET_DECISION", str(action["action_id"]), request, "determination_request_conflict"):
            _fail(FinancialConflictError, "determination_request_conflict")
        authority = connection.execute("SELECT authority_id,authority_epoch,authority_digest FROM determinations WHERE determination_id=?", (action["determination_id"],)).fetchone()
        if (str(authority[0]), int(authority[1]), bytes(authority[2])) != (self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest):
            _fail(FinancialAuthorityError, "determination_authority_stale")
        return {"status": "DUPLICATE", "action_id": str(action["action_id"]), "determination_id": str(action["determination_id"]), **self._projection_for_row(obligation)}

    def _insert_row(self, connection: sqlite3.Connection, table: str, values: Mapping[str, Any]) -> None:
        columns = self._table_columns[table]
        connection.execute(
            f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            tuple(values[column] for column in columns),
        )

    def _apply_accepted_correction_transition(
        self,
        connection: sqlite3.Connection,
        *,
        offset: bool,
        obligation: sqlite3.Row,
        claim: sqlite3.Row,
        command: Mapping[str, Any],
        input_receipt: Mapping[str, Any],
        input_result_digest: bytes,
        pack: ControlPack,
        query_observations: Mapping[str, Mapping[str, Any]],
        current_event_sequence: int,
        previous_history_head: bytes,
        transition_result: Mapping[str, Any],
        financial_engine: Any,
        semantic: Any,
        snapshot: Any,
    ) -> dict[str, Any]:
        """Bind and atomically apply one accepted Engine offset or correction delta.

        ``decode_correction_transition_result`` already enforces the result's
        internal consistency (effect order, explanation, action/outbox/case/event
        shape and cross-field equalities). This method binds the result to what
        only the Owner knows: the command, trusted authority, control pack,
        claim row, read set, history position and scope. Before COMMIT the
        independent checker recomputes the written evaluation from exact rows.
        """

        def require_binding(condition: bool, code: str) -> None:
            if not condition:
                _fail(FinancialIntegrityError, code)

        mutation = transition_result["mutation"]
        decision = "OFFSET_AUTHORIZED" if offset else "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
        action_kind = "OFFSET_AUTHORIZATION" if offset else "CORRECTION_PAYMENT_REQUEST"
        dependencies = mutation["dependencies"]
        determination = mutation["determination"]
        action = mutation["action"]
        case_delta = mutation["case_delta"]
        case_record = case_delta["record"]
        event = mutation["event"]
        followups = mutation["followups"]
        financial_result = mutation["resulting_result"]
        expected_revision = int(command["expected_revision"])
        resulting_revision = expected_revision + 1
        action_id = str(command["action_id"])
        determination_id = f"determination:{action_id}"
        obligation_id = str(obligation["obligation_id"])
        evaluation_id = f"evaluation:{obligation_id}:r{resulting_revision}"
        mutation_time = max(int(command["decision_at_ms"]), int(command["owner_now_ms"]))
        evidence_bindings = list(input_receipt["evidence_bindings"])
        evidence_bindings_wire = [
            {
                "evidence_id": str(binding["evidence_id"]),
                "record_digest": bytes.fromhex(str(binding["record_digest"])),
            }
            for binding in evidence_bindings
        ]
        control_pack = input_receipt["control_pack"]
        authority = self.trusted_authority
        authority_fields = {"authority_id": authority.authority_id, "authority_epoch": authority.epoch, "authority_digest": authority.digest}

        require_binding(transition_result["action_id"] == action_id and mutation["transition"] == decision, "correction_result_identity")
        require_binding(
            all(dependencies[key] == value for key, value in authority_fields.items())
            and dependencies["control_pack_id"] == pack.pack_id == control_pack["pack_id"]
            and dependencies["control_pack_version"] == pack.version == control_pack["version"]
            and dependencies["control_pack_digest"] == pack.digest == bytes.fromhex(control_pack["digest"])
            and dependencies["input_evaluation_id"] == str(command["evaluation_id"])
            and dependencies["input_evaluation_result_digest"] == input_result_digest
            and dependencies["input_evaluation_revision"] == expected_revision
            and dependencies["input_evaluation_evaluated_at_ms"] == input_receipt["evaluated_at_ms"]
            and dependencies["input_evaluation_snapshot_digest"]
            == bytes.fromhex(str(input_receipt["input_snapshot_digest"]))
            and dependencies["input_shortfall_cents"] == int(input_receipt["shortfall_cents"])
            and dependencies["decision_at_ms"] == command["decision_at_ms"]
            and dependencies["owner_now_ms"] == command["owner_now_ms"]
            and dependencies["current_event_sequence"] == current_event_sequence
            and dependencies["previous_history_head"] == previous_history_head,
            "correction_dependency_binding",
        )
        expected_claim = {
            **_cols(claim, str, "claim_id", "obligation_id", "evidence_id"),
            "amount_cents": int(claim["amount_cents"]),
            "owner_role": str(claim["owner_role"]),
            "deadline_at_ms": int(claim["deadline_ms"]),
            "status": str(claim["status"]),
        }
        require_binding(
            dependencies["claim_before"] == expected_claim
            and determination["obligation_id"] == obligation_id
            and determination["actor_id"] == command["actor_id"]
            and determination["actor_role"] == command["actor_role"]
            and all(determination[key] == value for key, value in authority_fields.items())
            and determination["expected_revision"] == expected_revision
            and determination["decided_at_ms"] == command["decision_at_ms"],
            "correction_determination_binding",
        )
        require_binding(dependencies["supporting_evidence"] == evidence_bindings_wire and dependencies["query_observations"] == query_observations, "correction_read_set_binding")
        require_binding(
            action["obligation_id"] == obligation_id and action["currency"] == self.config.currency,
            "correction_action_binding",
        )
        action_amount = int(action["amount_cents"])

        determination_fields = {
            "determination_id": determination_id,
            "obligation_id": obligation_id,
            **_cols(command, str, "claim_id", "actor_id", "actor_role"),
            **authority_fields,
            "decision": decision,
            "amount_cents": expected_claim["amount_cents"],
            "expected_revision": expected_revision,
            "resulting_revision": resulting_revision,
            "decided_at_ms": int(command["decision_at_ms"]),
            "input_evaluation_id": str(command["evaluation_id"]),
            "input_evaluation_result_digest": input_result_digest,
        }
        determination_payload = _determination_digest_payload(action_id=action_id, kind=action_kind, supporting_evidence=evidence_bindings, **determination_fields)
        expected_determination_digest = _digest(_ACTION_DOMAIN, _canonical(determination_payload))
        action_payload = {
            "action_id": action_id,
            "amount_cents": action_amount,
            "claim_id": str(command["claim_id"]),
            "currency": self.config.currency,
            "determination_id": determination_id,
            "dispatch": "SYNTHETIC_RECORD_ONLY",
            "input_evaluation_id": str(command["evaluation_id"]),
            "input_evaluation_result_digest": _hex(input_result_digest),
            "kind": action_kind,
            "obligation_id": obligation_id,
            "revision": resulting_revision,
        }
        action_payload_digest = _digest(_ACTION_DOMAIN, _canonical(action_payload))
        require_binding(action["payload_digest"] == action_payload_digest, "correction_digest_binding")
        action_idempotency_key = _digest(_IDEMPOTENCY_DOMAIN, action_id.encode("ascii"))
        prior_case = connection.execute(
            "SELECT * FROM cases WHERE case_id=? AND obligation_id=?",
            (case_record["case_id"], obligation_id),
        ).fetchone()
        require_binding((prior_case is None) is case_delta["inserted"], "correction_case_inserted_binding")

        self._insert_row(connection, "determinations", {
            **determination_fields,
            "supporting_evidence_json": _canonical({"bindings": evidence_bindings}).decode("ascii"),
            "determination_digest": expected_determination_digest,
        })
        changed_claim = connection.execute(
            "UPDATE claimed_adjustments SET status=?,updated_at_ms=? "
            "WHERE claim_id=? AND obligation_id=? AND status='CLAIMED'",
            ("AUTHORIZED" if offset else "REJECTED", mutation_time, str(command["claim_id"]), obligation_id),
        )
        require_binding(changed_claim.rowcount == 1, "correction_claim_update")

        case_values = {
            "case_id": str(case_record["case_id"]),
            "obligation_id": obligation_id,
            "reason": str(case_record["reason"]),
            "contractual_accountability": str(case_delta["contractual_accountability"]),
            "next_action_owner": str(case_record["next_action_owner"]),
            "due_at_ms": int(case_record["due_at_ms"]),
            "completion_conditions_json": _canonical(
                {key: case_delta[f"completion_conditions_{key}"] for key in ("amount_satisfied", "reporting_complete", "delivery_acknowledged_or_not_required")}
            ).decode("ascii"),
            "status": str(case_record["status"]),
            "updated_at_ms": mutation_time,
        }
        if prior_case is None:
            self._insert_row(connection, "cases", case_values)
        else:
            connection.execute(
                "UPDATE cases SET reason=?,contractual_accountability=?,next_action_owner=?,due_at_ms=?,"
                "completion_conditions_json=?,status=?,updated_at_ms=? WHERE case_id=? AND obligation_id=?",
                (
                    *(case_values[key] for key in ("reason", "contractual_accountability", "next_action_owner", "due_at_ms", "completion_conditions_json", "status")),
                    mutation_time, case_values["case_id"], obligation_id,
                ),
            )
        connection.execute(
            "UPDATE cases SET status=?,updated_at_ms=? WHERE obligation_id=?",
            (financial_result.case_status, mutation_time, obligation_id),
        )

        self._insert_row(connection, "actions", {
            "action_id": action_id,
            "obligation_id": obligation_id,
            "determination_id": determination_id,
            "kind": action_kind,
            "status": "READY",
            "revision": resulting_revision,
            "payload_json": _canonical(action_payload).decode("ascii"),
            "payload_digest": action_payload_digest,
            "idempotency_key": action_idempotency_key,
            "created_at_ms": mutation_time,
        })
        self._insert_row(connection, "action_outbox", {
            "action_id": action_id,
            "status": "READY",
            "attempt": 0,
            "payload_digest": action_payload_digest,
            "acknowledgment_ref": None,
            "updated_at_ms": mutation_time,
        })
        try:  # Lean's declared post-state (input and result context, at mutation time) is the one these writes produced.
            authority_context = semantic.TrustedAuthorityContext.from_authority(authority)
            semantic.bind_resulting_state(
                connection, snapshot, authority_context=authority_context, evaluation_time_ms=mutation_time, mutation=mutation,
            )
            lean = financial_engine.evaluate_live(
                connection, obligation_id=obligation_id, authority_context=authority_context, evaluation_time_ms=mutation_time,
                verification={"scope": self._scope_value(), "owner_id": self.owner_id, "mode": self.mode},
            )
            if lean.completion_at_ms != financial_result.completion_at_ms:
                _fail(FinancialIntegrityError, "correction_post_state:result_completion")
        except (semantic.SemanticAdapterError, financial_engine.FinancialEngineError) as error:
            _fail(FinancialIntegrityError, f"correction_post_state:{error}")

        result = _decided_evaluation(financial_result, evaluation_id, obligation_id, resulting_revision)
        evaluation_receipt = self._insert_evaluation(
            connection,
            result=result,
            pack=pack,
            evidence_bindings=evidence_bindings,
            authority_epoch=authority.epoch,
            authority_digest=authority.digest,
        )
        projection_update = connection.execute(
            "UPDATE obligations SET revision=?,claimed_adjustment_cents=?,lawful_adjustment_cents=?,"
            "received_cash_cents=?,shortfall_cents=?,overage_cents=?,cash_satisfied=?,amount_satisfied=?,"
            "timely=?,reporting_complete=?,verification_status=?,case_status=?,delivery_status=?,"
            "current_evaluation_id=?,updated_at_ms=? "
            "WHERE obligation_id=? AND revision=? AND current_evaluation_id=?",
            (
                resulting_revision, *(result[field] for field in _PROJECTION_FIELDS),
                evaluation_id, mutation_time, obligation_id, expected_revision, str(command["evaluation_id"]),
            ),
        )
        require_binding(projection_update.rowcount == 1, "correction_projection_update")

        payload = {"action_id": action_id, "amount_cents": expected_claim["amount_cents"], "determination_id": determination_id, "evaluation_id": evaluation_id}
        if offset:
            payload["artifact"] = {"sha256": _hex(financial_engine.EVALUATOR_ARTIFACT_SHA256)}
        else:
            query_observations_wire = {
                key: {
                    **dict(value),
                    "version_head": _hex(bytes(value["version_head"])),
                }
                for key, value in dependencies["query_observations"].items()
            }
            payload["correction_followup"] = {
                "contract": _CORRECTION_FOLLOWUP_CONTRACT,
                "work_id": action_id,
                "determination_id": determination_id,
                "source": dict(followups),
                "artifact": {
                    "contract": str(dependencies["artifact_contract"]),
                    "version": int(dependencies["artifact_version"]),
                    "sha256": _hex(financial_engine.EVALUATOR_ARTIFACT_SHA256),
                },
                "control_pack": {**_attrs(pack, "pack_id", "version"), "digest": _hex(pack.digest)},
                "authority": _authority_ref(authority),
                "input_evaluation": {
                    "evaluation_id": str(input_receipt["evaluation_id"]),
                    "revision": int(input_receipt["revision"]),
                    "result_digest": _hex(input_result_digest),
                    "receipt_digest": str(input_receipt["receipt_digest"]),
                },
                "result_evaluation": {
                    "evaluation_id": str(evaluation_receipt["evaluation_id"]),
                    "revision": int(evaluation_receipt["revision"]),
                    "result_digest": str(evaluation_receipt["evaluation_result_digest"]),
                    "receipt_digest": str(evaluation_receipt["receipt_digest"]),
                },
                "determination_digest": _hex(expected_determination_digest),
                "case_status": str(case_record["status"]),
                "action_status": "READY",
                "outbox_status": "READY",
                "supporting_evidence": [_cols(value, str, "evidence_id", "record_digest") for value in evidence_bindings],
                "dependency_families": list(_CORRECTION_FOLLOWUP_DEPENDENCIES),
                "read_observations": query_observations_wire,
                "outputs": ["MIRROR_EXPLANATION", "STATE_REPORT", "CORPORATE_SUPPORT"],
            }
        self._append_event(
            connection,
            **_cols(event, str, "aggregate_type", "aggregate_id", "kind"),
            **_cols(event, int, "before_revision", "after_revision"),
            payload=payload,
            committed_at_ms=int(event["committed_at_ms"]),
        )
        self._verify_before_commit(connection, "correction", obligation_id)
        return {
            "status": "AUTHORIZED" if offset else "CORRECTION_AUTHORIZED",
            "action_id": action_id,
            "determination_id": determination_id,
            **self._current_projection(connection, obligation_id),
        }

    def _claim_decision_inputs(
        self,
        connection: sqlite3.Connection,
        obligation: sqlite3.Row,
        *,
        claim_id: str,
        actor_id: str,
        actor_role: str,
        decision_at_ms: int | None,
        decision_time_required: bool,
        evaluation_id: str | None,
        evaluation_result_digest: str | bytes | None,
        expected_revision: int | None,
    ) -> tuple[sqlite3.Row, int, dict[str, Any], bytes]:
        """Authority, claim lookup, decision time and current-evaluation reference for both served decisions."""
        self._authority_action(connection, str(obligation["obligation_id"]), actor_id, actor_role)
        claim = _one(connection, "offset_claim_missing", "SELECT * FROM claimed_adjustments WHERE claim_id=? AND obligation_id=?", (claim_id, obligation["obligation_id"]))
        if decision_at_ms is None and decision_time_required:
            _fail(FinancialInputError, "decision_time_required")
        decision_time = self._now() if decision_at_ms is None else _time(decision_at_ms, "decision_time")
        if decision_time > self._now():  # a future decision would hold the clock ahead of every later write
            _fail(FinancialInputError, "decision_time_future")
        _evaluation_row, evaluation_receipt, input_result_digest = self._validate_evaluation_reference(
            connection,
            obligation,
            claim_evidence_id=str(claim["evidence_id"]),
            evaluation_id=evaluation_id,
            evaluation_result_digest=evaluation_result_digest,
            expected_revision=expected_revision,
            decision_time=decision_time,
        )
        return claim, decision_time, evaluation_receipt, input_result_digest

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
        self._assert_actionable()
        action_ref = action_id or f"action:offset:{claim_id}"
        _id(action_ref, "action_id")
        request = {"claim_id": claim_id, "actor_id": actor_id, "actor_role": actor_role, "expected_revision": expected_revision, "decision_at_ms": decision_at_ms, "evaluation_id": evaluation_id, "evaluation_result_digest": evaluation_result_digest}
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            existing_action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_ref,)).fetchone()
            if existing_action is not None:
                return self._duplicate_action_or_conflict(connection, action=existing_action, obligation=obligation, decision="OFFSET_AUTHORIZED", **request)
            return self._served_decision(connection, obligation, offset=True, item_id=item_id, action_ref=action_ref, **request)

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
        self._assert_actionable()
        action_ref = action_id or f"action:correction:{claim_id}"
        _id(action_ref, "action_id")
        request = {"claim_id": claim_id, "actor_id": actor_id, "actor_role": actor_role, "expected_revision": expected_revision, "decision_at_ms": decision_at_ms, "evaluation_id": evaluation_id, "evaluation_result_digest": evaluation_result_digest}
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            existing_action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_ref,)).fetchone()
            if staff_read_binding is not None:
                self._validate_staff_correction_binding(
                    connection,
                    binding=staff_read_binding,
                    item_id=item_id,
                    obligation=obligation,
                    action_id=action_ref,
                    expected_revision=expected_revision,
                    evaluation_id=evaluation_id,
                    evaluation_result_digest=evaluation_result_digest,
                    duplicate=existing_action is not None,
                )
            if existing_action is not None:
                if (
                    evaluation_id is None
                    or evaluation_result_digest is None
                    or expected_revision is None
                    or decision_at_ms is None
                    or str(existing_action["determination_id"]) != f"determination:{action_ref}"
                ):
                    _fail(FinancialConflictError, "determination_request_conflict")
                return self._duplicate_action_or_conflict(connection, action=existing_action, obligation=obligation, decision="OFFSET_REJECTED_CORRECTION_AUTHORIZED", **request)
            return self._served_decision(connection, obligation, offset=False, item_id=item_id, action_ref=action_ref, **request)

    def _served_decision(
        self,
        connection: sqlite3.Connection,
        obligation: sqlite3.Row,
        *,
        offset: bool,
        item_id: str,
        claim_id: str,
        action_ref: str,
        actor_id: str,
        actor_role: str,
        expected_revision: int | None,
        decision_at_ms: int | None,
        evaluation_id: str | None,
        evaluation_result_digest: str | bytes | None,
    ) -> dict[str, Any]:
        """The pinned worker decides an offset authorization, or its rejection with a correction; the owner binds and applies its answer."""
        claim, decision_time, evaluation_receipt, input_result_digest = self._claim_decision_inputs(
            connection,
            obligation,
            claim_id=claim_id,
            actor_id=actor_id,
            actor_role=actor_role,
            decision_at_ms=decision_at_ms,
            decision_time_required=not offset,
            evaluation_id=evaluation_id,
            evaluation_result_digest=evaluation_result_digest,
            expected_revision=expected_revision,
        )
        deterministic_determination_id = f"determination:{action_ref}"
        from app import right_rail_financial_engine as financial_engine
        from app import right_rail_financial_semantic_adapter as semantic

        try:
            owner_now_ms = self._now()
            snapshot = semantic.build_locked_semantic_snapshot(
                connection,
                obligation_id=str(obligation["obligation_id"]),
                authority_context=semantic.TrustedAuthorityContext.from_authority(self.trusted_authority),
                evaluation_time_ms=owner_now_ms,
                expected_config=self.config,
                expected_scope=self._scope_value(),
                expected_mode=self.mode,
                expected_owner_id=self.owner_id,
            )
            pack, _calculation_rule, _adjustment_rule = self._control_pack_for_obligation(
                connection,
                str(obligation["obligation_id"]),
            )
            meta = self._meta(connection)
            current_event_sequence = int(meta["sequence"])
            previous_history_head = bytes(meta["history_head"])
            input_evaluation_id = str(evaluation_receipt["evaluation_id"])
            lookups = [
                (name, predicate, subject, column, connection.execute(sql, (subject,)).fetchall())
                for name, predicate, subject, column, sql in (
                    ("action_id", "ACTION_ID", action_ref, "action_id", "SELECT action_id FROM actions WHERE action_id=?"),
                    ("determination_id", "DETERMINATION_ID", deterministic_determination_id, "determination_id", "SELECT determination_id FROM determinations WHERE determination_id=?"),
                    ("evaluation_consumed", "EVALUATION_CONSUMED", input_evaluation_id, "determination_id", "SELECT determination_id FROM determinations WHERE input_evaluation_id=?"),
                )
            ]
            if any(len(rows) > 1 for *_, rows in lookups):
                _fail(FinancialIntegrityError, "correction_query_cardinality")
            query_observations = {
                name: {
                    "predicate": predicate, "subject": subject, "complete": True, "match_count": len(rows),
                    "result_identity": None if not rows else str(rows[0][column]),
                    "version_sequence": current_event_sequence, "version_head": previous_history_head,
                }
                for name, predicate, subject, column, rows in lookups
            }
            if any(rows for *_, rows in lookups):
                _fail(FinancialConflictError, "determination_request_conflict")
            command = {
                "item_id": item_id,
                "claim_id": claim_id,
                "action_id": action_ref,
                "actor_id": actor_id,
                "actor_role": actor_role,
                "current_authority_id": self.trusted_authority.authority_id,
                "current_authority_epoch": self.trusted_authority.epoch,
                "current_authority_digest": self.trusted_authority.digest,
                "expected_revision": expected_revision,
                "evaluation_id": input_evaluation_id,
                "evaluation_result_digest": input_result_digest,
                "decision_at_ms": decision_time,
                "owner_now_ms": owner_now_ms,
            }
            request = financial_engine.encode_correction_transition_request(
                snapshot=snapshot,
                command=command,
                action_lookup={"kind": "absent"},
                query_observations=query_observations,
                current_event_sequence=current_event_sequence,
                previous_history_head=previous_history_head,
                payment_links=[{"payment_id": p, "action_id": a} for p, _r, a in _payment_receipts(connection, str(obligation["obligation_id"])) if a is not None],
            )
            transition_result = (financial_engine.run_offset_authorization_v1 if offset else financial_engine.run_correction_transition_v1)(request=request)
        except financial_engine.FinancialEngineError:
            _fail(FinancialIntegrityError, "correction_transition_failed")
        except semantic.SemanticAdapterError:
            _fail(FinancialIntegrityError, "correction_snapshot_invalid")

        if transition_result["status"] == "REJECTED":
            rejected_errors: dict[str, tuple[type[FinancialError], str]] = {
                "INVALID_REQUEST": (FinancialInputError, "correction_request_invalid"),
                "INVALID_INPUT": (FinancialIntegrityError, "correction_input_invalid"),
                "SHADOW_READ_ONLY": (FinancialDispatchError, "shadow_owner_read_only"),
                "SCOPE_MISMATCH": (FinancialIntegrityError, "correction_scope_mismatch"),
                "AUTHORITY_STALE": (FinancialAuthorityError, "determination_authority_stale"),
                "ACTOR_UNAUTHORIZED": (FinancialAuthorityError, "authority_actor_not_authorized"),
                "CONTROL_PACK_REJECTED": (FinancialIntegrityError, "control_pack_not_approved"),
                "REVISION_CONFLICT": (FinancialRevisionError, "obligation_revision_conflict"),
                "EVALUATION_CONFLICT": (FinancialRevisionError, "evaluation_revision_conflict"),
                "EVALUATION_CONSUMED": (FinancialConflictError, "evaluation_already_consumed"),
                "EVIDENCE_COVERAGE": (FinancialIntegrityError, "evaluation_evidence_coverage"),
                "CLAIM_MISSING": (FinancialIntegrityError, "offset_claim_missing"),
                "CLAIM_NOT_CLAIMED": (FinancialConflictError, "offset_claim_not_claimed"),
                "ACTION_CONFLICT": (FinancialConflictError, "determination_request_conflict"),
                "DETERMINATION_CONFLICT": (FinancialConflictError, "determination_request_conflict"),
                "CHRONOLOGY": (FinancialIntegrityError, "evaluation_chronology"),
                "QUERY_OBSERVATION_INVALID": (FinancialIntegrityError, "correction_read_set_invalid"),
                "INPUT_SNAPSHOT_MISSING": (FinancialIntegrityError, "correction_input_snapshot_missing"),
                "NO_SHORTFALL": (FinancialConflictError, "correction_no_shortfall"),
                "NO_REQUESTABLE_BALANCE": (FinancialConflictError, "correction_no_requestable_balance"),
                "CAPACITY": (FinancialIntegrityError, "history_capacity"),
                "DECISION_BACKDATED_PAST_DUE": (FinancialInputError, "decision_time_backdated_past_due"),
                "CLAIM_EXCEEDS_SHORTFALL": (FinancialConflictError, "offset_exceeds_shortfall"),
                "DECISION_BEFORE_PACK_EFFECTIVE": (FinancialIntegrityError, "control_pack_not_effective"),
            }
            error_type, error_code = rejected_errors.get(
                str(transition_result["reject_reason"]),
                (FinancialIntegrityError, "correction_transition_rejected"),
            )
            _fail(error_type, error_code)
        if transition_result["status"] != "ACCEPTED":
            _fail(FinancialIntegrityError, "correction_duplicate_without_action")
        return self._apply_accepted_correction_transition(
            connection,
            offset=offset,
            obligation=obligation,
            claim=claim,
            command=command,
            input_receipt=evaluation_receipt,
            input_result_digest=input_result_digest,
            pack=pack,
            query_observations=query_observations,
            current_event_sequence=current_event_sequence,
            previous_history_head=previous_history_head,
            transition_result=transition_result,
            financial_engine=financial_engine,
            semantic=semantic,
            snapshot=snapshot,
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
        """Record a local acknowledgment; it never creates cash evidence."""
        self._assert_actionable()
        _id(action_id, "action_id")
        _id(acknowledgment_ref, "acknowledgment_ref")
        with self._write() as connection:
            action = _one(connection, "action_missing", "SELECT * FROM actions WHERE action_id=?", (action_id,))
            obligation = self._obligation_by_id(connection, str(action["obligation_id"]))
            self._authority_action(connection, str(obligation["obligation_id"]), actor_id, actor_role)
            if connection.execute("SELECT 1 FROM determinations WHERE determination_id=? AND actor_id=?", (action["determination_id"], actor_id)).fetchone():
                _fail(FinancialAuthorityError, "acknowledger_is_authorizer")
            outbox = _one(connection, "action_outbox_missing", "SELECT * FROM action_outbox WHERE action_id=?", (action_id,))
            if self._replayed_command(connection, "ACTION_ACKNOWLEDGMENT", action_id, {"acknowledgment_ref": acknowledgment_ref}, "acknowledgment_conflict"):
                return {"status": "DUPLICATE", "action_id": action_id, **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)
            if str(action["status"]) != "READY":
                _fail(FinancialConflictError, "action_not_acknowledgeable")
            connection.execute("UPDATE actions SET status='ACKNOWLEDGED' WHERE action_id=? AND status='READY'", (action_id,))
            connection.execute("UPDATE action_outbox SET status='ACKNOWLEDGED',attempt=attempt+1,acknowledgment_ref=?,updated_at_ms=? WHERE action_id=? AND status='READY'", (acknowledgment_ref, self._now(), action_id))
            self._recompute_and_record(connection, str(action["obligation_id"]), kind="ACTION_ACKNOWLEDGED", payload={"action_id": action_id, "acknowledgment_ref": acknowledgment_ref, "cash_mutation": False}, now_ms=self._now())
            return {"status": "ACKNOWLEDGED", "action_id": action_id, **self._current_projection(connection, str(action["obligation_id"]))}

    def record_followthrough_decision(
        self,
        *,
        item_id: str,
        decision_id: str,
        act: str,
        reason_code: str | None = None,
        owner_id: str | None = None,
        suggestion: Mapping[str, object] | None = None,
        actor_id: str,
        actor_role: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """An official's follow-through act (assign an owner, or close with a reason), with any AI or contractor
        suggestion recorded beside it, never as evidence; money is unchanged."""
        self._assert_actionable()
        _id(decision_id, "decision_id")
        _followthrough_shape(act, reason_code, owner_id)
        if actor_role not in ("CASE_OWNER", "FINANCE_DECISION"):
            _fail(FinancialAuthorityError, "followthrough_actor_role")
        if suggestion is not None:
            code = "followthrough_suggestion"
            if type(suggestion) is not dict or set(suggestion) != {"source_id", "source_ref", "source_sha256", "suggested_at_ms", "act", "reason_code", "owner_id"}:
                _fail(FinancialInputError, code)
            _id(suggestion["source_id"], code), _id(suggestion["source_ref"], code), _time(suggestion["suggested_at_ms"], code)
            if type(suggestion["source_sha256"]) is not str or _UPPER_HEX64.fullmatch(suggestion["source_sha256"]) is None:
                _fail(FinancialInputError, code)
            _followthrough_shape(suggestion["act"], suggestion["reason_code"], suggestion["owner_id"], code)
        if type(expected_revision) is not int:
            _fail(FinancialInputError, "expected_revision_required")
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            obligation_id = str(obligation["obligation_id"])
            self._authority_action(connection, obligation_id, actor_id, actor_role)
            now = self._now()
            if suggestion is not None and suggestion["suggested_at_ms"] > now:
                _fail(FinancialInputError, "followthrough_suggestion_time")
            payload = {
                "decision_id": decision_id, "item_id": item_id, "act": act, "reason_code": reason_code, "owner_id": owner_id,
                "suggestion": None if suggestion is None else dict(suggestion), "actor_id": actor_id, "actor_role": actor_role,
                "authority_id": self.trusted_authority.authority_id, "authority_epoch": self.trusted_authority.epoch,
                "authority_digest": _hex(self.trusted_authority.digest),
            }
            digest = _hex(_digest(_EVENT_DOMAIN, _canonical(payload)))
            if self._replayed_command(connection, "FOLLOWTHROUGH_DECISION", decision_id, {"payload_digest": digest}, "followthrough_decision_conflict"):
                return {"status": "DUPLICATE", "decision_id": decision_id, **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)
            revision = int(obligation["revision"])
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=obligation_id, kind="FOLLOWTHROUGH_DECIDED",
                               before_revision=revision, after_revision=revision, payload=payload, committed_at_ms=now)
            from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_followthrough_connection

            try:  # before COMMIT: the checker runs every rule it applies to this kind on open
                verify_followthrough_connection(connection, obligation_id, decision_id, **self._checker_expectations())
            except IndependentFinancialError as error:
                _fail(FinancialIntegrityError, f"followthrough_verification:{error}")
            return {"status": "RECORDED", "decision_id": decision_id, **self._projection_for_row(obligation)}

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
        """Record the report that a later reporting correction may supersede."""
        return self._record_report(
            item_id=item_id, report_id=report_id, evidence_id=evidence_id, actor_id=actor_id,
            actor_role=actor_role, expected_revision=expected_revision, event_at_ms=event_at_ms,
            correction=False, supersedes=None,
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
        return self._record_report(
            item_id=item_id, report_id=report_id, evidence_id=evidence_id, actor_id=actor_id,
            actor_role=actor_role, expected_revision=expected_revision, event_at_ms=event_at_ms,
            correction=True, supersedes=supersedes,
        )

    def _record_report(
        self,
        *,
        item_id: str,
        report_id: str,
        evidence_id: str | None,
        actor_id: str,
        actor_role: str,
        expected_revision: int | None,
        event_at_ms: int | None,
        correction: bool,
        supersedes: str | None,
    ) -> dict[str, Any]:
        """One path for original reports and bound reporting corrections."""
        self._assert_actionable()
        _id(report_id, "report_id")
        evidence_ref = evidence_id or f"evidence:report:{report_id}"
        _id(evidence_ref, "evidence_id")
        if correction:
            if supersedes is None:
                _fail(FinancialIntegrityError, "report_supersedes_required")
            _id(supersedes, "supersedes")
        requested_event_time = None if event_at_ms is None else _time(event_at_ms, "reporting_event")
        evidence_fields: dict[str, Any] = {
            "evidence_id": evidence_ref,
            "item_id": item_id,
            "kind": "REPORT_CORRECTION" if correction else "REPORT",
            "common_origin_id": report_id,
            "source_id": "synthetic-report-source",
            "source_version": "fixture-v1",
            "local_ref": f"report:{report_id}",
        }
        if correction:
            evidence_fields["supersedes"] = supersedes
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            obligation_id = str(obligation["obligation_id"])
            self._authority_action(connection, obligation_id, actor_id, actor_role)
            existing = connection.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_ref,)).fetchone()
            if existing is not None:
                duplicate_event_time = int(existing["event_at_ms"]) if requested_event_time is None else requested_event_time
                try:
                    duplicate_candidate = self._new_evidence(
                        **evidence_fields,
                        applicable_at_ms=duplicate_event_time,
                        event_at_ms=duplicate_event_time,
                        received_at_ms=int(existing["received_at_ms"]),
                    )
                except FinancialError:
                    _fail(FinancialConflictError, "evidence_identity_conflict")
                if duplicate_candidate.record_digest != bytes(existing["record_digest"]):
                    _fail(FinancialConflictError, "evidence_identity_conflict")
                return {"status": "DUPLICATE", "report_id": report_id, **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)
            event_time = self._now() if requested_event_time is None else requested_event_time
            evidence = self._new_evidence(
                **evidence_fields,
                applicable_at_ms=event_time,
                event_at_ms=event_time,
                received_at_ms=self._now(),
            )
            if correction:
                prior = _one(connection, "report_supersedes_missing", "SELECT * FROM evidence WHERE evidence_id=?", (supersedes,))
                if str(prior["item_id"]) != item_id:
                    _fail(FinancialIntegrityError, "report_supersedes_item")
                if str(prior["kind"]) not in {"REPORT", "REPORT_CORRECTION"}:
                    _fail(FinancialIntegrityError, "report_supersedes_kind")
                if int(prior["event_at_ms"]) >= event_time:
                    _fail(FinancialIntegrityError, "report_supersedes_chronology")
                if connection.execute("SELECT 1 FROM evidence WHERE supersedes=? LIMIT 1", (supersedes,)).fetchone() is not None:
                    _fail(FinancialConflictError, "report_supersedes_already_superseded")
            if self._insert_evidence(connection, evidence) != "INSERTED":
                _fail(FinancialIntegrityError, "reporting_evidence_insert")
            connection.execute("UPDATE obligations SET reporting_complete=1 WHERE obligation_id=?", (obligation_id,))
            self._recompute_and_record(
                connection,
                obligation_id,
                kind="REPORTING_CORRECTION_RECORDED" if correction else "REPORTING_EVIDENCE_RECORDED",
                payload={"report_id": report_id, "evidence_id": evidence.evidence_id, "cash_mutation": False},
                now_ms=self._now(),
            )
            return {"status": "RECORDED", "report_id": report_id, **self._current_projection(connection, obligation_id)}

    def evaluate_obligation(self, item_id: str, *, expected_revision: int | None = None) -> dict[str, Any]:
        self._assert_actionable()
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            self._check_revision(obligation, expected_revision)
            now_ms = self._now()
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=now_ms)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="EVALUATION_RECORDED", before_revision=before, after_revision=after, payload={"evaluation_id": evaluation["evaluation_id"], "evidence_ids": evaluation["evidence_ids"]}, committed_at_ms=now_ms)
            return {"status": "EVALUATED", "evaluation_receipt": self._evaluation_receipt_for_row(connection, connection.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (evaluation["evaluation_id"],)).fetchone()), **self._current_projection(connection, str(obligation["obligation_id"]))}

    def _evaluation_receipt_for_row(self, connection: sqlite3.Connection, row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            _fail(FinancialIntegrityError, "evaluation_missing")
        try:
            evidence_ids_value = json.loads(str(row["evidence_ids_json"]))
            bindings_value = json.loads(str(row["evidence_bindings_json"]))
            scope = json.loads(str(row["scope_json"]))
            input_snapshot = json.loads(str(row["input_snapshot_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            _fail(FinancialIntegrityError, "evaluation_reference_malformed")
        if not isinstance(evidence_ids_value, dict) or set(evidence_ids_value) != {"evidence_ids"} or not isinstance(evidence_ids_value["evidence_ids"], list):
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        evidence_ids = evidence_ids_value["evidence_ids"]
        if any(type(value) is not str for value in evidence_ids) or evidence_ids != sorted(evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        if not isinstance(bindings_value, dict) or set(bindings_value) != {"bindings"} or not isinstance(bindings_value["bindings"], list):
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        bindings = bindings_value["bindings"]
        if any(type(value) is not dict or set(value) != {"evidence_id", "record_digest"} for value in bindings):
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        if [value["evidence_id"] for value in bindings] != evidence_ids:
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        for binding in bindings:
            if type(binding["evidence_id"]) is not str or type(binding["record_digest"]) is not str:
                _fail(FinancialIntegrityError, "evaluation_evidence_binding")
            record = connection.execute("SELECT record_digest FROM evidence WHERE evidence_id=?", (binding["evidence_id"],)).fetchone()
            if record is None or _hex(bytes(record[0])) != binding["record_digest"]:
                _fail(FinancialIntegrityError, "evaluation_evidence_binding")
            _digest_input(binding["record_digest"], "evaluation_evidence_binding")
        if not isinstance(scope, dict) or set(scope) != set(self._scope_value()) or scope != self._scope_value():
            _fail(FinancialIntegrityError, "evaluation_scope_binding")
        if not isinstance(input_snapshot, dict) or type(input_snapshot.get("pre_revision")) is not int:
            _fail(FinancialIntegrityError, "evaluation_input_snapshot")
        expected_pre_revision = int(row["revision"]) if int(row["revision"]) == 0 else int(row["revision"]) - 1
        if input_snapshot["pre_revision"] != expected_pre_revision:
            _fail(FinancialIntegrityError, "evaluation_input_revision")
        input_snapshot_digest = bytes(row["input_snapshot_digest"])
        if input_snapshot_digest != _digest(_EVALUATION_INPUT_DOMAIN, _canonical(input_snapshot)):
            _fail(FinancialIntegrityError, "evaluation_input_digest")
        obligation = _one(connection, "evaluation_obligation_missing", "SELECT * FROM obligations WHERE obligation_id=?", (row["obligation_id"],))
        pack, _calculation, _adjustment = self._control_pack_for_obligation(connection, str(obligation["obligation_id"]))
        if str(row["control_pack_id"]) != pack.pack_id or int(row["control_pack_version"]) != pack.version or bytes(row["control_pack_digest"]) != pack.digest:
            _fail(FinancialIntegrityError, "evaluation_control_pack_binding")
        authority_digest = bytes(row["authority_digest"])
        if (str(row["authority_id"]), int(row["authority_epoch"]), authority_digest) != (self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest):
            _fail(FinancialAuthorityError, "evaluation_authority_stale")
        result = {
            "evaluation_id": str(row["evaluation_id"]),
            "obligation_id": str(row["obligation_id"]),
            "revision": int(row["revision"]),
            "rule_version": int(row["rule_version"]),
            "evidence_ids": evidence_ids,
            "authority_id": str(row["authority_id"]),
            **_cols(row, int, "evaluated_at_ms", "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely", "reporting_complete"),
            **_cols(row, str, "verification_status", "case_status", "delivery_status"),
        }
        result_digest = bytes(row["result_digest"])
        if result_digest != _digest(_EVALUATION_RESULT_DOMAIN, _canonical(_evaluation_result_body(result))):
            _fail(FinancialIntegrityError, "evaluation_result_digest")
        receipt_body = _evaluation_receipt_body(
            result={**result, "result_digest": _hex(result_digest)},
            scope=scope,
            control_pack_id=pack.pack_id,
            control_pack_version=pack.version,
            control_pack_digest=pack.digest,
            evidence_bindings=bindings,
            authority_id=str(row["authority_id"]),
            authority_epoch=int(row["authority_epoch"]),
            authority_digest=authority_digest,
            input_snapshot_digest=input_snapshot_digest,
            result_digest=result_digest,
        )
        receipt_digest = _digest(_EVALUATION_RECEIPT_DOMAIN, _canonical(receipt_body))
        if bytes(row["receipt_digest"]) != receipt_digest or str(row["contract_version"]) != _EVALUATION_RECEIPT_CONTRACT:
            _fail(FinancialIntegrityError, "evaluation_receipt_digest")
        return {**receipt_body, "receipt_digest": _hex(receipt_digest), "evaluation_result_digest": _hex(result_digest)}

    def current_evaluation_receipt(self, item_id: str) -> dict[str, Any]:
        """Read the current persisted evaluation reference without advancing state."""

        with self._read_snapshot() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            evaluation_id = obligation["current_evaluation_id"]
            if evaluation_id is None:
                _fail(FinancialIntegrityError, "evaluation_missing")
            row = connection.execute("SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?", (evaluation_id, obligation["obligation_id"])).fetchone()
            receipt = self._evaluation_receipt_for_row(connection, row)
            if int(receipt["revision"]) != int(obligation["revision"]):
                _fail(FinancialRevisionError, "evaluation_revision_binding")
            return receipt

    def decision_package(
        self,
        item_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        expected_evaluation_id: str | None = None,
        expected_evaluation_result_digest: str | bytes | None = None,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        """Return one bounded, read-only decision view from a single DB snapshot."""

        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or not 0 <= offset <= _MAX_ROWS:
            _fail(FinancialInputError, "decision_package_page")
        if (expected_evaluation_id is None) != (expected_evaluation_result_digest is None):
            _fail(FinancialInputError, "evaluation_reference_required")
        expected_digest = None
        if expected_evaluation_id is not None:
            _id(expected_evaluation_id, "evaluation_id")
            expected_digest = _digest_input(expected_evaluation_result_digest, "evaluation_result_digest")

        with self._read_snapshot(_connection=_connection) as connection:
            obligation = self._get_obligation_row(connection, item_id)
            obligation_id = str(obligation["obligation_id"])
            evaluation_id = obligation["current_evaluation_id"]
            if evaluation_id is None:
                _fail(FinancialIntegrityError, "evaluation_missing")
            evaluation_row = connection.execute(
                "SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?",
                (evaluation_id, obligation_id),
            ).fetchone()
            receipt = self._evaluation_receipt_for_row(connection, evaluation_row)
            if int(receipt["revision"]) != int(obligation["revision"]):
                _fail(FinancialRevisionError, "evaluation_revision_binding")
            if expected_evaluation_id is not None and receipt["evaluation_id"] != expected_evaluation_id:
                _fail(FinancialRevisionError, "evaluation_revision_conflict")
            if expected_digest is not None and bytes.fromhex(str(receipt["result_digest"])) != expected_digest:
                _fail(FinancialRevisionError, "evaluation_reference_conflict")

            pack, _calculation_rule, _adjustment_rule = self._control_pack_for_obligation(connection, obligation_id)
            population_binding = self._population_binding_for_obligation(connection, obligation)

            def page(
                select_sql: str,
                count_sql: str,
                args: tuple[Any, ...],
                project: Any,
            ) -> dict[str, Any]:
                total = int(connection.execute(count_sql, args).fetchone()[0])
                rows = connection.execute(f"{select_sql} LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
                items = [project(row) for row in rows]
                next_offset = offset + len(items) if offset + len(items) < total else None
                return {
                    "offset": offset,
                    "limit": limit,
                    "count": len(items),
                    "total": total,
                    "next_offset": next_offset,
                    "items": items,
                }

            def evidence_ref(row: sqlite3.Row) -> dict[str, Any]:
                return {
                    **_cols(row, str, "evidence_id", "item_id", "kind", "common_origin_id", "source_id", "source_version", "local_ref"),
                    **_cols(row, int, "applicable_at_ms", "event_at_ms", "received_at_ms"),
                    "amount_cents": _opt(row["amount_cents"], int),
                    "reversal_of": _opt(row["reversal_of"], str),
                    "supersedes": _opt(row["supersedes"], str),
                    "record_digest": _hex(bytes(row["record_digest"])),
                    "obligation_id": obligation_id,
                }

            def case_ref(row: sqlite3.Row) -> dict[str, Any]:
                conditions = _stored_object(row["completion_conditions_json"], "decision_package_case")
                required_conditions = {
                    "amount_satisfied",
                    "delivery_acknowledged_or_not_required",
                    "reporting_complete",
                }
                if set(conditions) != required_conditions or any(type(conditions[key]) is not bool for key in required_conditions):
                    _fail(FinancialIntegrityError, "decision_package_case")
                return {
                    "case_id": str(row["case_id"]),
                    "obligation_id": obligation_id,
                    **_cols(row, str, "reason", "contractual_accountability", "next_action_owner"),
                    "due_at_ms": int(row["due_at_ms"]),
                    "completion_conditions": {key: conditions[key] for key in sorted(conditions)},
                    "status": str(row["status"]),
                    "updated_at_ms": int(row["updated_at_ms"]),
                }

            def payment_ref(row: sqlite3.Row) -> dict[str, Any]:
                return {
                    "payment_id": str(row["payment_id"]),
                    "obligation_id": obligation_id,
                    **_cols(row, str, "evidence_id", "common_origin_id"),
                    **_cols(row, int, "amount_cents", "event_at_ms"),
                    "active": bool(row["active"]),
                    "reversed_by_evidence_id": _opt(row["reversed_by_evidence_id"], str),
                }

            def claim_ref(row: sqlite3.Row) -> dict[str, Any]:
                return {
                    "claim_id": str(row["claim_id"]),
                    "obligation_id": obligation_id,
                    "evidence_id": str(row["evidence_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "owner_role": str(row["owner_role"]),
                    "deadline_ms": int(row["deadline_ms"]),
                    "status": str(row["status"]),
                    **_cols(row, int, "created_at_ms", "updated_at_ms"),
                }

            def determination_ref(row: sqlite3.Row) -> dict[str, Any]:
                supporting = _stored_object(row["supporting_evidence_json"], "decision_package_determination")
                bindings = supporting.get("bindings") if set(supporting) == {"bindings"} else None
                if type(bindings) is not list or any(not _shaped(value, {"evidence_id": _is_str, "record_digest": _is_str}) for value in bindings):
                    _fail(FinancialIntegrityError, "decision_package_determination")
                return {
                    "determination_id": str(row["determination_id"]),
                    "obligation_id": obligation_id,
                    "claim_id": _opt(row["claim_id"], str),
                    **_cols(row, str, "actor_id", "actor_role"),
                    "authority": _row_authority(row),
                    "decision": str(row["decision"]),
                    "amount_cents": int(row["amount_cents"]),
                    "supporting_evidence": [_cols(value, str, "evidence_id", "record_digest") for value in bindings],
                    **_cols(row, int, "expected_revision", "resulting_revision", "decided_at_ms"),
                    "determination_digest": _hex(bytes(row["determination_digest"])),
                    "input_evaluation_id": str(row["input_evaluation_id"]),
                    "input_evaluation_result_digest": _hex(bytes(row["input_evaluation_result_digest"])),
                }

            action_fields = (
                "action", "action_id", "obligation_id", "determination_id", "kind", "claim_id",
                "amount_cents", "currency", "revision", "input_evaluation_id",
                "input_evaluation_result_digest", "dispatch",
            )

            open_cents = _open_requests(connection, obligation_id, int(obligation["shortfall_cents"]))

            def action_ref(row: sqlite3.Row) -> dict[str, Any]:
                payload = _stored_object(row["payload_json"], "decision_package_action")
                payload_fields: dict[str, Any] = {}
                for key in action_fields:
                    if key not in payload:
                        continue
                    value = payload[key]
                    if value is not None and type(value) not in {str, int, bool}:
                        _fail(FinancialIntegrityError, "decision_package_action")
                    payload_fields[key] = value
                return {
                    "action_id": str(row["action_id"]),
                    "obligation_id": obligation_id,
                    **_cols(row, str, "determination_id", "kind", "status"),
                    "revision": int(row["revision"]),
                    "payload_digest": _hex(bytes(row["payload_digest"])),
                    "payload_fields": payload_fields,
                    "open_cents": open_cents.get(str(row["action_id"]), 0 if row["kind"] == "CORRECTION_PAYMENT_REQUEST" else None),
                    "created_at_ms": int(row["created_at_ms"]),
                    "acknowledgment": {
                        "status": str(row["outbox_status"]),
                        "reference": _opt(row["acknowledgment_ref"], str),
                        "attempt": int(row["attempt"]),
                        "updated_at_ms": int(row["outbox_updated_at_ms"]),
                        "cash_effect_cents": 0,
                    },
                }

            def conflict_ref(row: sqlite3.Row) -> dict[str, Any]:
                return {
                    "conflict_id": str(row["conflict_id"]),
                    "obligation_id": obligation_id,
                    "common_origin_id": str(row["common_origin_id"]),
                    "existing_payment_id": _opt(row["existing_payment_id"], str),
                    "candidate_evidence_id": str(row["candidate_evidence_id"]),
                    **{key: _opt(row[key], int) for key in ("existing_amount_cents", "candidate_amount_cents")},
                    "reason": str(row["reason"]),
                    "visible_at_ms": int(row["visible_at_ms"]),
                }

            def owned_page(table: str, key: str, project: Any) -> dict[str, Any]:
                return page(f"SELECT * FROM {table} WHERE obligation_id=? ORDER BY {key}", f"SELECT COUNT(*) FROM {table} WHERE obligation_id=?", (obligation_id,), project)

            def latest(sql: str, project: Any) -> dict[str, Any] | None:
                return _opt(connection.execute(sql, (obligation_id,)).fetchone(), project)

            evidence_select = "SELECT evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,amount_cents,reversal_of,supersedes,record_digest FROM evidence WHERE item_id=?"
            reports_only = " AND kind IN ('REPORT','REPORT_CORRECTION')"
            item_args = (str(obligation["item_id"]),)
            action_query = """
                SELECT a.*,o.status AS outbox_status,o.attempt,o.acknowledgment_ref,
                       o.updated_at_ms AS outbox_updated_at_ms
                FROM actions a JOIN action_outbox o ON o.action_id=a.action_id
                WHERE a.obligation_id=? ORDER BY a.action_id
            """
            case_page = owned_page("cases", "case_id", case_ref)
            evidence_page = page(f"{evidence_select} ORDER BY evidence_id", "SELECT COUNT(*) FROM evidence WHERE item_id=?", item_args, evidence_ref)
            payment_page = owned_page("payments", "payment_id", payment_ref)
            claim_page = owned_page("claimed_adjustments", "claim_id", claim_ref)
            determination_page = owned_page("determinations", "determination_id", determination_ref)
            action_page = page(action_query, "SELECT COUNT(*) FROM actions WHERE obligation_id=?", (obligation_id,), action_ref)
            conflict_page = owned_page("financial_conflicts", "conflict_id", conflict_ref)
            reporting_page = page(f"{evidence_select}{reports_only} ORDER BY evidence_id", f"SELECT COUNT(*) FROM evidence WHERE item_id=?{reports_only}", item_args, evidence_ref)

            current_case = latest("SELECT * FROM cases WHERE obligation_id=? ORDER BY case_id DESC LIMIT 1", case_ref)
            current_action = latest(f"{action_query.rsplit('ORDER BY', 1)[0]}ORDER BY a.revision DESC,a.action_id DESC LIMIT 1", action_ref)
            current_determination = latest("SELECT * FROM determinations WHERE obligation_id=? ORDER BY resulting_revision DESC,determination_id DESC LIMIT 1", determination_ref)

            def rows(sql: str) -> list[sqlite3.Row]:
                return connection.execute(sql, (obligation_id,)).fetchall()

            active_payment_count = int(rows("SELECT COUNT(*) FROM payments WHERE obligation_id=? AND active=1")[0][0])
            active_payment_rows = rows("SELECT amount_cents FROM payments WHERE obligation_id=? AND active=1 ORDER BY payment_id")
            authorized_claim_count = int(rows("SELECT COUNT(*) FROM claimed_adjustments WHERE obligation_id=? AND status='AUTHORIZED'")[0][0])
            adjustment_rows = rows("SELECT amount_cents,status FROM claimed_adjustments WHERE obligation_id=? AND status IN ('CLAIMED','AUTHORIZED') ORDER BY claim_id")
            conflict_count = int(rows("SELECT COUNT(*) FROM financial_conflicts WHERE obligation_id=?")[0][0])
            report_count = int(reporting_page["total"])
            active_payment_ids = [row["evidence_id"] for row in payment_page["items"] if row["active"]]
            authorized_evidence_ids = [row["evidence_id"] for row in claim_page["items"] if row["status"] == "AUTHORIZED"]
            reporting_evidence_ids = [row["evidence_id"] for row in reporting_page["items"]]
            payment_references_complete = offset == 0 and payment_page["next_offset"] is None
            claim_references_complete = offset == 0 and claim_page["next_offset"] is None
            reporting_references_complete = offset == 0 and reporting_page["next_offset"] is None

            active_payment_cents = _sum_cents(int(row["amount_cents"]) for row in active_payment_rows)
            claimed_adjustment_cents = _sum_cents(int(row["amount_cents"]) for row in adjustment_rows)
            lawful_adjustment_cents = _sum_cents(
                int(row["amount_cents"]) for row in adjustment_rows if str(row["status"]) == "AUTHORIZED"
            )
            payment_support = (
                "SUPPORTED" if active_payment_count and active_payment_cents == int(obligation["received_cash_cents"])
                else "NO_LINKED_EVIDENCE" if not active_payment_count and int(obligation["received_cash_cents"]) == 0
                else "CONFLICTED"
            )
            adjustment_support = (
                "SUPPORTED"
                if (authorized_claim_count or adjustment_rows)
                and claimed_adjustment_cents == int(obligation["claimed_adjustment_cents"])
                and lawful_adjustment_cents == int(obligation["lawful_adjustment_cents"])
                else "NO_LINKED_EVIDENCE"
                if not adjustment_rows and int(obligation["claimed_adjustment_cents"]) == 0 and int(obligation["lawful_adjustment_cents"]) == 0
                else "CONFLICTED"
            )
            reporting_support = (
                "SUPPORTED" if bool(obligation["reporting_complete"]) and report_count
                else "UNKNOWN" if bool(obligation["reporting_complete"])
                else "CONFLICTED" if report_count
                else "NOT_SATISFIED"
            )
            if current_action is None:
                delivery_support = "UNKNOWN"
            elif current_action["status"] == "ACKNOWLEDGED" and current_action["acknowledgment"]["reference"] is not None:
                delivery_support = "SUPPORTED"
            else:
                delivery_support = "NOT_SATISFIED"

            amount_evidence_ids = sorted(set(active_payment_ids + authorized_evidence_ids))
            amount_satisfied = bool(obligation["amount_satisfied"])
            if payment_support == "CONFLICTED" or adjustment_support == "CONFLICTED":
                amount_support = "CONFLICTED"
            elif amount_satisfied and not active_payment_count and not authorized_claim_count:
                amount_support = "UNKNOWN"
            elif str(obligation["verification_status"]) == "CONFLICT_VISIBLE":
                amount_support = "CONFLICTED"
            else:
                amount_support = "SUPPORTED" if active_payment_count or authorized_claim_count else "NO_LINKED_EVIDENCE"

            requirements = {
                "amount_satisfied": "SUPPORTED" if amount_satisfied and amount_support == "SUPPORTED" else (
                    "NOT_SATISFIED" if not amount_satisfied and amount_support != "CONFLICTED"
                    else "CONFLICTED" if amount_support == "CONFLICTED" else "UNKNOWN"
                ),
                "delivery_acknowledged_or_not_required": "UNKNOWN" if current_action is None else "NOT_SATISFIED" if any(open_cents.get(a, 1) > 0 for (a,) in connection.execute("SELECT action_id FROM actions WHERE obligation_id=? AND status='READY'", (obligation_id,))) else "SUPPORTED",  # every READY action that still asks (a request with open > 0; any other kind, default 1) waits on delivery
                "reporting_complete": reporting_support,
            }
            missing_requirements = sorted(key for key, value in requirements.items() if value != "SUPPORTED")
            observed_case_status = None if current_case is None else current_case["status"]
            # The stored case condition allows acknowledgment or an explicit
            # not-required state, but this schema has no durable not-required
            # marker. An absent action therefore stays UNKNOWN in this view.
            if observed_case_status != "RESOLVED":
                resolution_assessment = "NOT_RESOLVED"
            elif conflict_count or amount_support == "CONFLICTED" or reporting_support == "CONFLICTED":
                resolution_assessment = "CONFLICTED"
            elif any(value == "NOT_SATISFIED" for value in requirements.values()):
                resolution_assessment = "UNSUPPORTED"
            elif missing_requirements:
                resolution_assessment = "UNKNOWN"
            else:
                resolution_assessment = "SUPPORTED"

            package = {
                "contract": _DECISION_PACKAGE_CONTRACT,
                "scope": self._scope_value(),
                "obligation": self._projection_for_row(obligation),
                "population_binding": population_binding,
                "evaluation_receipt": receipt,
                "control_pack": {
                    **_attrs(pack, "pack_id", "version"),
                    "digest": _hex(pack.digest),
                    **_attrs(pack, "calculation_rule_id", "adjustment_rule_id"),
                    "source_refs": list(pack.source_refs),
                    "authorized_roles": list(pack.authorized_roles),
                    **_attrs(pack, "effective_start_ms", "effective_end_ms", "recorded_at_ms", "approved_at_ms"),
                },
                "case": current_case,
                "current_determination": current_determination,
                "current_action": current_action,
                "cash": {
                    "recorded_received_cash_cents": int(obligation["received_cash_cents"]),
                    "cash_satisfied": bool(obligation["cash_satisfied"]),
                    "claimed_adjustment_cents": int(obligation["claimed_adjustment_cents"]),
                    "lawful_adjustment_cents": int(obligation["lawful_adjustment_cents"]),
                    "amount_satisfied": bool(obligation["amount_satisfied"]),
                    "shortfall_cents": int(obligation["shortfall_cents"]),
                    "overage_cents": int(obligation["overage_cents"]),
                    "active_payment_count": active_payment_count,
                    "authorized_adjustment_count": authorized_claim_count,
                },
                "reporting": {
                    "complete": bool(obligation["reporting_complete"]),
                    "evidence_count": report_count,
                },
                "references": {
                    "cases": case_page,
                    "evidence": evidence_page,
                    "payments": payment_page,
                    "claims": claim_page,
                    "determinations": determination_page,
                    "actions": action_page,
                    "conflicts": conflict_page,
                    "reporting_evidence": reporting_page,
                },
                "conclusions": {
                    "cash_satisfaction": {
                        "result": "SATISFIED" if bool(obligation["cash_satisfied"]) else "NOT_SATISFIED",
                        "evidence_status": payment_support,
                        "recorded_received_cash_cents": int(obligation["received_cash_cents"]),
                        "required_cents": int(obligation["owed_cents"]),
                        "missing_cents": max(int(obligation["owed_cents"]) - int(obligation["received_cash_cents"]), 0),
                        "supporting_evidence_ids": active_payment_ids,
                        "supporting_references_complete": payment_references_complete,
                    },
                    "amount_satisfaction": {
                        "result": "SATISFIED" if amount_satisfied else "NOT_SATISFIED",
                        "evidence_status": amount_support,
                        "supporting_evidence_ids": amount_evidence_ids,
                        "supporting_references_complete": payment_references_complete and claim_references_complete,
                    },
                    "reporting_completion": {
                        "result": reporting_support,
                        "supporting_evidence_ids": reporting_evidence_ids,
                        "supporting_references_complete": reporting_references_complete,
                    },
                    "action_acknowledgment": {
                        "result": delivery_support,
                        "action_id": None if current_action is None else current_action["action_id"],
                        "reference": None if current_action is None else current_action["acknowledgment"]["reference"],
                        "cash_effect_cents": 0,
                    },
                    "case_resolution": {
                        "case_id": None if current_case is None else current_case["case_id"],
                        "obligation_id": obligation_id,
                        "observed_status": observed_case_status,
                        "assessment": resolution_assessment,
                        "required_conditions": requirements,
                        "missing_requirements": missing_requirements,
                        "supporting_evidence_ids": sorted(set(amount_evidence_ids + reporting_evidence_ids)),
                        "supporting_references_complete": payment_references_complete and claim_references_complete and reporting_references_complete,
                        "conflict_count": conflict_count,
                        "conflict_ids": [row["conflict_id"] for row in conflict_page["items"]],
                    },
                },
            }
            if len(_canonical(package)) > _MAX_DECISION_PACKAGE_BYTES:
                _fail(FinancialIntegrityError, "decision_package_size")
            return package

    def _correction_followup_status(
        self,
        connection: sqlite3.Connection,
        package: Mapping[str, Any],
        item_id: str,
        sequence: int,
        followup: Any,
        artifact: Any,
    ) -> tuple[str, list[str]]:
        """Derive which dependency keys of one committed correction moved, from its stored basis and later history.

        REOPENED iff a later event touches a key and re-reading that key at head gives a different value.
        An unknown event kind, stored family or engine, or a moved key no later event explains, is REVIEW_REQUIRED.
        """

        try:
            if (
                artifact is None
                or followup["contract"] != _CORRECTION_FOLLOWUP_CONTRACT
                or followup["dependency_families"] != list(_CORRECTION_FOLLOWUP_DEPENDENCIES)
            ):
                return "REVIEW_REQUIRED", []
            obligation_id, work_id = package["obligation"]["obligation_id"], followup["work_id"]
            pack, authority, determination = followup["control_pack"], followup["authority"], package["current_determination"]
            delivery = connection.execute(
                "SELECT a.status,o.status FROM actions a JOIN action_outbox o USING(action_id) WHERE a.action_id=?", (work_id,)
            ).fetchone()
            moved = {
                key
                for key, value_moved in (
                    (("RULE", f"RULE({pack['pack_id']})"), {k: package["control_pack"][k] for k in pack} != pack),
                    (("AUTHORITY", f"AUTHORITY({authority['authority_id']})"), package["evaluation_receipt"]["authority"] != authority),
                    (
                        ("DETERMINATION", f"COLLECTION(DETERMINATION, {obligation_id})"),
                        (determination["determination_id"], determination["determination_digest"])
                        != (followup["determination_id"], followup["determination_digest"]),
                    ),
                    (
                        ("DELIVERY_REJECTED", f"COLLECTION(DELIVERY_REJECTED, {work_id})"),
                        delivery is None or not {*delivery} <= {"READY", "ACKNOWLEDGED"},
                    ),
                )
                if value_moved
            }
            bound = {value["evidence_id"] for value in followup["supporting_evidence"]}
            for evidence_id, kind in connection.execute(  # not new facts: the payment this correction requested, and a
                # re-sent confirmation that made no payment or conflict of its own (the checker binds the label)
                "SELECT e.evidence_id,e.kind FROM evidence e WHERE e.item_id=:item AND NOT (e.kind='PAYMENT_CONFIRMATION' AND ("
                "EXISTS (SELECT 1 FROM payments p JOIN financial_events f ON json_extract(f.payload_json,'$.payment_id')=p.payment_id "
                "WHERE p.evidence_id=e.evidence_id AND f.aggregate_type='OBLIGATION' AND f.aggregate_id=:obligation "
                "AND f.kind='PAYMENT_RECEIVED' AND json_extract(f.payload_json,'$.pays_action_id')=:work) "
                "OR NOT EXISTS (SELECT 1 FROM payments WHERE evidence_id=e.evidence_id) "
                "AND NOT EXISTS (SELECT 1 FROM financial_conflicts WHERE candidate_evidence_id=e.evidence_id) "
                "AND EXISTS (SELECT 1 FROM financial_events f WHERE f.aggregate_type='OBLIGATION' AND f.aggregate_id=:obligation "
                "AND f.kind='PAYMENT_DUPLICATE_EVIDENCE' AND json_extract(f.payload_json,'$.candidate_evidence_id')=e.evidence_id)))",
                {"item": item_id, "obligation": obligation_id, "work": work_id},
            ):
                if evidence_id not in bound:
                    family = _EVIDENCE_COLLECTION[kind]
                    moved.add((family, f"COLLECTION({family}, {item_id})"))
            touched: set[str] = set()
            for kind, foreign in connection.execute(
                "SELECT DISTINCT kind,aggregate_type='OBLIGATION' AND aggregate_id<>? FROM financial_events WHERE event_sequence>?",
                (obligation_id, sequence),
            ):
                families = _FOLLOWUP_TOUCHES[kind]
                if not foreign:
                    touched.update(families)
        except (KeyError, TypeError):
            return "REVIEW_REQUIRED", []
        if any(family not in touched for family, _ in moved):
            return "REVIEW_REQUIRED", []
        changed = sorted(key for _, key in moved)
        return ("REOPENED" if changed else "CURRENT"), changed

    def correction_followup_outputs(self, item_id: str, action_id: str) -> dict[str, Any]:
        """Read deterministic Mirror, report, and recipient-safe support views for one accepted correction."""

        _id(action_id, "action_id")
        from app import right_rail_financial_engine as financial_engine

        with self._read_snapshot() as connection:
            package = self.decision_package(item_id, _connection=connection)
            found = [
                (int(row["event_sequence"]), payload.get("correction_followup"))
                for row in connection.execute(
                    "SELECT event_sequence,payload_json FROM financial_events WHERE aggregate_type='OBLIGATION' "
                    "AND aggregate_id=? AND kind='OFFSET_REJECTED_CORRECTION_AUTHORIZED' ORDER BY event_sequence",
                    (package["obligation"]["obligation_id"],),
                )
                if (payload := _stored_object(row["payload_json"], "correction_followup_event")).get("action_id") == action_id
            ]
            if len(found) != 1:
                _fail(FinancialIntegrityError, "correction_followup_duplicate" if found else "correction_followup_missing")
            sequence, followup = found[0]
            accepted_basis = None
            if type(followup) is dict:
                accepted_basis = {
                    key: followup[key]
                    for key in (
                        "artifact", "control_pack", "authority", "input_evaluation",
                        "result_evaluation", "dependency_families",
                    )
                    if key in followup
                }
            artifact = accepted_basis.get("artifact") if type(accepted_basis) is dict else None
            if (
                type(artifact) is not dict
                or set(artifact) != {"contract", "version", "sha256"}
                or artifact.get("contract") != financial_engine.CORRECTION_TRANSITION_OPERATION
                or type(artifact.get("version")) is not int
                or artifact.get("version") != 1
                or not _known_correction_engine(artifact.get("sha256"))
            ):
                artifact = None
            status, changed = self._correction_followup_status(connection, package, item_id, sequence, followup, artifact)
        view = {
            "followup_status": status,
            "changed_dependencies": changed,
            "source_event_sequence": sequence,
            "accepted_basis": accepted_basis,
            "current_basis": {
                "obligation_revision": package["obligation"]["revision"],
                **{key: package[key] for key in ("evaluation_receipt", "control_pack", "current_determination", "current_action", "case")},
            },
            "decision_package": package,
        }
        explanation = {"contract": "RR/FINANCIAL/CORRECTION-EXPLANATION/v1", "transition": "OFFSET_REJECTED_CORRECTION_AUTHORIZED", **view}
        report = {"contract": "RR/FINANCIAL/CORRECTION-REPORT/v1", **view}
        failure_stage, error_class = {
            "CURRENT": ("NONE", "NONE"),
            "REOPENED": ("FOLLOWUP_RECONCILIATION", "STALE_DEPENDENCY"),
            "REVIEW_REQUIRED": ("FOLLOWUP_RECONCILIATION", "UNSUPPORTED_DEPENDENCY"),
        }[status]
        pack = accepted_basis.get("control_pack") if type(accepted_basis) is dict else None
        support = {
            "contract": "RR/FINANCIAL/CORPORATE-SUPPORT/v2", "status": status, "component": "FINANCIAL_CORRECTION",
            "software_version": "NONE",  # no commit or kit digest is bound to a running owner
            "rule_version": {key: pack.get(key) for key in ("pack_id", "version", "digest")} if type(pack) is dict else "NONE",
            "adapter_versions": {"population": _POPULATION_MANIFEST_CONTRACT, "trust_graph_source_profile": "NONE"},
            "artifact": artifact, "failure_stage": failure_stage, "error_class": error_class, "work_ref_count": int(status != "CURRENT"),
            "reproduction": dict(financial_engine.CORRECTION_TRANSITION_REPRODUCTION)
            if artifact and artifact["sha256"] == _hex(financial_engine.EVALUATOR_ARTIFACT_SHA256) else "NONE",
        }
        result = {
            "followup_status": status,
            "work_id": action_id,
            "source_event_sequence": sequence,
            "mirror_explanation": explanation,
            "state_report": report,
            "corporate_support": support,
        }
        if len(_canonical(result)) > _MAX_CORRECTION_FOLLOWUP_BYTES:
            _fail(FinancialIntegrityError, "correction_followup_size")
        return result

    def drain_correction_followups(
        self,
        *,
        after_event_sequence: int = 0,
        limit: int = 25,
    ) -> dict[str, Any]:
        """Read a bounded, repeatable page of event-backed correction follow-up work."""

        if type(after_event_sequence) is not int or not 0 <= after_event_sequence < 2**63:
            _fail(FinancialInputError, "correction_followup_cursor")
        if type(limit) is not int or not 1 <= limit <= 100:
            _fail(FinancialInputError, "correction_followup_limit")
        with self._read_snapshot() as connection:
            events = connection.execute(
                "SELECT event_sequence,aggregate_id,payload_json FROM financial_events "
                "WHERE aggregate_type='OBLIGATION' AND kind='OFFSET_REJECTED_CORRECTION_AUTHORIZED' "
                "AND event_sequence>? ORDER BY event_sequence LIMIT ?",
                (after_event_sequence, limit + 1),
            ).fetchall()
            has_more = len(events) > limit
            selected = events[:limit]
            requests: list[tuple[int, str, str]] = []
            for event in selected:
                payload = _stored_object(event["payload_json"], "correction_followup_event")
                if type(payload.get("action_id")) is not str:
                    _fail(FinancialIntegrityError, "correction_followup_event")
                item = connection.execute(
                    "SELECT item_id FROM obligations WHERE obligation_id=?",
                    (str(event["aggregate_id"]),),
                ).fetchone()
                if item is None:
                    _fail(FinancialIntegrityError, "correction_followup_obligation")
                requests.append((int(event["event_sequence"]), str(item["item_id"]), str(payload["action_id"])))
        items: list[dict[str, Any]] = []
        next_sequence = after_event_sequence
        for index, (sequence, item_id, action_id) in enumerate(requests):
            item = self.correction_followup_outputs(item_id, action_id)
            candidate_items = [*items, item]
            candidate_sequence = sequence
            candidate_has_more = has_more or index + 1 < len(requests)
            candidate = {
                "contract": "RR/FINANCIAL/CORRECTION-FOLLOWUP-DRAIN/v1",
                "items": candidate_items,
                "count": len(candidate_items),
                "after_event_sequence": after_event_sequence,
                "next_after_event_sequence": candidate_sequence,
                "has_more": candidate_has_more,
                "skipped": {"count": 0, "reasons": {}},
            }
            if len(_canonical(candidate)) > _MAX_CORRECTION_FOLLOWUP_PAGE_BYTES:
                if not items:
                    _fail(FinancialIntegrityError, "correction_followup_page_size")
                has_more = True
                break
            items.append(item)
            next_sequence = sequence
            has_more = candidate_has_more
        return {
            "contract": "RR/FINANCIAL/CORRECTION-FOLLOWUP-DRAIN/v1",
            "items": items,
            "count": len(items),
            "after_event_sequence": after_event_sequence,
            "next_after_event_sequence": next_sequence,
            "has_more": has_more or len(items) < len(requests),
            "skipped": {"count": 0, "reasons": {}},
        }

    def _dict_rows(self, connection: sqlite3.Connection, query: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        return [dict(row) for row in connection.execute(query, args).fetchall()]

    @staticmethod
    def _funding_row_value(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "receipt_id": str(row["receipt_id"]),
            "source_record_ref": str(row["source_record_ref"]),
            "amount_cents": int(row["amount_cents"]),
            "confirmation_class": str(row["confirmation_class"]),
            "evidence_status": str(row["evidence_status"]),
            "event_at_ms": int(row["event_at_ms"]),
            "recorded_at_ms": int(row["recorded_at_ms"]),
            "supersedes_receipt_id": row["supersedes_receipt_id"],
            "receipt_digest": _hex(bytes(row["receipt_digest"])),
        }

    def program_funding_summary(self) -> dict[str, Any]:
        """Return the separate, versioned program-funding evidence projection."""

        with self._read_snapshot() as connection:
            self._verify_funding_projection(connection)
            projections = list(
                connection.execute(
                    "SELECT p.*,r.confirmation_class,r.evidence_status,r.recorded_at_ms,r.supersedes_receipt_id "
                    "FROM program_funding_projection AS p "
                    "JOIN program_funding_receipts AS r ON r.receipt_id=p.receipt_id "
                    "ORDER BY p.source_record_ref"
                )
            )
            history = list(
                connection.execute(
                    "SELECT * FROM program_funding_receipts ORDER BY recorded_at_ms,receipt_id"
                )
            )
            total = 0
            for row in projections:
                total = _add(total, int(row["amount_cents"]))
            return {
                "schema": _PROGRAM_FUNDING_RECEIPT_SCHEMA,
                "scope": self._scope_value(),
                "reported_funding_cents": total,
                "current_receipt_count": len(projections),
                "historical_receipt_count": len(history),
                "confirmation_class": _PROGRAM_FUNDING_CONFIRMATION_CLASS,
                "evidence_status": _PROGRAM_FUNDING_EVIDENCE_STATUS,
                "current_receipts": [self._funding_row_value(row) for row in projections],
                "receipt_history": [self._funding_row_value(row) for row in history],
                "money_movement_effect": False,
                "recipient_cash_effect": False,
                "payment_authorization_effect": False,
            }

    def _record_program_funding_receipt_in_transaction(
        self,
        connection: sqlite3.Connection,
        receipt: ProgramFundingReceipt,
    ) -> tuple[str, dict[str, Any]]:
        """Persist one validated, scoped receipt while the caller holds BEGIN IMMEDIATE."""

        receipt_digest = receipt.digest
        if self._replayed_command(connection, "FUNDING_RECEIPT", receipt.receipt_id, {"receipt_digest": _hex(receipt_digest)}, "program_funding_receipt_identity_conflict"):
            existing = connection.execute("SELECT * FROM program_funding_receipts WHERE receipt_id=?", (receipt.receipt_id,)).fetchone()
            return "DUPLICATE", self._funding_row_value(existing)

        current = connection.execute(
            "SELECT * FROM program_funding_projection WHERE source_record_ref=?",
            (receipt.source_record_ref,),
        ).fetchone()
        parent: sqlite3.Row | None = None
        before_revision = 0
        if receipt.supersedes_receipt_id is None:
            if current is not None:
                _fail(FinancialConflictError, "program_funding_supersession_required")
        else:
            parent = connection.execute(
                "SELECT * FROM program_funding_receipts WHERE receipt_id=?",
                (receipt.supersedes_receipt_id,),
            ).fetchone()
            if parent is None:
                _fail(FinancialConflictError, "program_funding_supersession_missing")
            if (
                str(parent["source_record_ref"]) != receipt.source_record_ref
                or current is None
                or str(current["receipt_id"]) != receipt.supersedes_receipt_id
            ):
                _fail(FinancialConflictError, "program_funding_supersession_stale")
            before_revision = int(current["revision"])

        other_current_total = 0
        for projection in connection.execute(
            "SELECT source_record_ref,amount_cents FROM program_funding_projection"
        ):
            if str(projection["source_record_ref"]) == receipt.source_record_ref:
                continue
            amount_cents = projection["amount_cents"]
            if type(amount_cents) is not int or not 0 <= amount_cents <= _MAX_CENTS:
                _fail(FinancialIntegrityError, "program_funding_projection_amount")
            other_current_total = _add(other_current_total, amount_cents)
        if receipt.amount_cents > _MAX_CENTS - other_current_total:
            _fail(FinancialInputError, "program_funding_total_cents")

        recorded_at_ms = self._now()
        if parent is not None and recorded_at_ms < int(parent["recorded_at_ms"]):
            _fail(FinancialInputError, "program_funding_supersession_chronology")

        next_revision = before_revision + 1
        record = receipt.as_record()
        self._insert_row(
            connection, "program_funding_receipts",
            {**record, "recorded_at_ms": recorded_at_ms, "receipt_digest": receipt_digest},
        )
        connection.execute(
            "INSERT INTO program_funding_projection "
            "(source_record_ref,receipt_id,amount_cents,event_at_ms,revision,receipt_digest) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(source_record_ref) DO UPDATE SET "
            "receipt_id=excluded.receipt_id,amount_cents=excluded.amount_cents,"
            "event_at_ms=excluded.event_at_ms,revision=excluded.revision,receipt_digest=excluded.receipt_digest",
            (
                receipt.source_record_ref,
                receipt.receipt_id,
                receipt.amount_cents,
                receipt.event_at_ms,
                next_revision,
                receipt_digest,
            ),
        )
        self._append_event(
            connection,
            aggregate_type="PROGRAM_FUNDING_RECEIPT",
            aggregate_id=receipt.receipt_id,
            kind="FUNDING_RECEIPT_SUPERSEDED" if receipt.supersedes_receipt_id is not None else "FUNDING_RECEIPT_RECORDED",
            before_revision=before_revision,
            after_revision=next_revision,
            payload={
                **record,
                "recorded_at_ms": recorded_at_ms,
                "receipt_digest": _hex(receipt_digest),
                "projection_revision": next_revision,
            },
            committed_at_ms=recorded_at_ms,
        )
        persisted = connection.execute(
            "SELECT * FROM program_funding_receipts WHERE receipt_id=?",
            (receipt.receipt_id,),
        ).fetchone()
        if persisted is None:
            _fail(FinancialIntegrityError, "program_funding_receipt_missing")
        return "RECORDED", self._funding_row_value(persisted)

    def record_program_funding_receipt(self, receipt: ProgramFundingReceipt) -> dict[str, Any]:
        """Record synthetic program-funding evidence without changing obligations or cash."""

        self._assert_actionable()
        if type(receipt) is not ProgramFundingReceipt:
            _fail(FinancialInputError, "program_funding_receipt_type")
        if any(getattr(receipt, key) != value for key, value in self._scope_value().items()):
            _fail(FinancialInputError, "program_funding_scope")
        with self._write() as connection:
            result_status, result_receipt = self._record_program_funding_receipt_in_transaction(
                connection,
                receipt,
            )
        return {
            "status": result_status,
            "receipt": result_receipt,
            "program_funding": self.program_funding_summary(),
        }

    def summary(self, *, _connection: sqlite3.Connection | None = None) -> dict[str, Any]:
        with self._read_snapshot(_connection=_connection) as connection:
            meta = self._meta(connection)
            totals = connection.execute("SELECT COUNT(*),COALESCE(SUM(owed_cents),0),COALESCE(SUM(received_cash_cents),0),COALESCE(SUM(lawful_adjustment_cents),0),COALESCE(SUM(shortfall_cents),0) FROM obligations").fetchone()
            return {
                "schema": self.schema,
                **_cols(meta, str, *_SCOPE_KEYS),
                "sequence": int(meta["sequence"]),
                "population_count": int(connection.execute("SELECT COUNT(*) FROM population_imports WHERE status='PUBLISHED'").fetchone()[0]),
                "obligation_count": int(totals[0]),
                "owed_cents": int(totals[1]),
                "received_cash_cents": int(totals[2]),
                "lawful_adjustment_cents": int(totals[3]),
                "shortfall_cents": int(totals[4]),
                "open_count": int(connection.execute("SELECT COUNT(*) FROM obligations WHERE amount_satisfied=0").fetchone()[0]),
                "cash_satisfied_count": int(connection.execute("SELECT COUNT(*) FROM obligations WHERE cash_satisfied=1").fetchone()[0]),
                "amount_satisfied_count": int(connection.execute("SELECT COUNT(*) FROM obligations WHERE amount_satisfied=1").fetchone()[0]),
                "dispatch_enabled": False,
                "egress_enabled": False,
                "production_usable": False,
                "activation": False,
                "proof_suite_id": None,
            }

    def list_obligations(
        self,
        *,
        status: str = "OPEN",
        limit: int = 100,
        offset: int = 0,
        _connection: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        if status not in _OBLIGATION_STATUS_CLAUSES:
            _fail(FinancialInputError, "obligation_status")
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= _MAX_ROWS:
            _fail(FinancialInputError, "obligation_page")
        with self._read_snapshot(_connection=_connection) as connection:
            return [self._projection_for_row(row) for row in connection.execute(f"SELECT * FROM obligations WHERE {_OBLIGATION_STATUS_CLAUSES[status]} ORDER BY obligation_id LIMIT ? OFFSET ?", (limit, offset)).fetchall()]

    def obligation_detail(
        self,
        item_id: str,
        *,
        limit: int = 100,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= 200:
            _fail(FinancialInputError, "detail_limit")
        with self._read_snapshot(_connection=_connection) as connection:
            obligation = self._get_obligation_row(connection, item_id)
            obligation_id = str(obligation["obligation_id"])
            result = self._projection_for_row(obligation)
            result["evidence"] = self._dict_rows(connection, "SELECT evidence_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,amount_cents,reversal_of,supersedes,record_digest FROM evidence WHERE item_id=? ORDER BY evidence_id LIMIT ?", (item_id, limit))
            result["payments"] = self._dict_rows(connection, "SELECT payment_id,evidence_id,common_origin_id,amount_cents,event_at_ms,active,reversed_by_evidence_id FROM payments WHERE obligation_id=? ORDER BY payment_id LIMIT ?", (obligation_id, limit))
            result["cases"] = self._dict_rows(connection, "SELECT case_id,reason,contractual_accountability,next_action_owner,due_at_ms,completion_conditions_json,status,updated_at_ms FROM cases WHERE obligation_id=? ORDER BY case_id LIMIT ?", (obligation_id, limit))
            result["determinations"] = self._dict_rows(connection, "SELECT determination_id,claim_id,actor_id,actor_role,authority_id,authority_epoch,authority_digest,decision,amount_cents,supporting_evidence_json,expected_revision,resulting_revision,decided_at_ms,determination_digest,input_evaluation_id,input_evaluation_result_digest FROM determinations WHERE obligation_id=? ORDER BY determination_id LIMIT ?", (obligation_id, limit))
            result["actions"] = self._dict_rows(connection, "SELECT action_id,determination_id,kind,status,revision,payload_digest,idempotency_key,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id LIMIT ?", (obligation_id, limit))
            result["conflicts"] = self._dict_rows(connection, "SELECT conflict_id,common_origin_id,existing_payment_id,candidate_evidence_id,existing_amount_cents,candidate_amount_cents,reason,visible_at_ms FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id LIMIT ?", (obligation_id, limit))
            result["evaluations"] = self._dict_rows(connection, "SELECT evaluation_id,revision,rule_version,evidence_ids_json,authority_id,authority_epoch,authority_digest,evaluated_at_ms,owed_cents,claimed_adjustment_cents,lawful_adjustment_cents,received_cash_cents,shortfall_cents,overage_cents,cash_satisfied,amount_satisfied,timely,reporting_complete,verification_status,case_status,delivery_status,result_digest,contract_version,scope_json,control_pack_id,control_pack_version,control_pack_digest,evidence_bindings_json,input_snapshot_json,input_snapshot_digest,receipt_digest FROM evaluations WHERE obligation_id=? ORDER BY revision LIMIT ?", (obligation_id, limit))
            return result

    def history(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        _connection: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or not 0 <= offset <= _MAX_ROWS:
            _fail(FinancialInputError, "history_page")
        with self._read_snapshot(_connection=_connection) as connection:
            return self._dict_rows(connection, "SELECT event_sequence,event_id,aggregate_type,aggregate_id,kind,before_revision,after_revision,payload_json,payload_digest,previous_head,head,committed_at_ms FROM financial_events ORDER BY event_sequence LIMIT ? OFFSET ?", (limit, offset))

    def intake_records(self, sha: str | None = None) -> list[dict[str, Any]]:
        """Every stored intake record (or the one raw file `sha`'s), oldest first: (aggregate_id = raw file SHA-256, committed_at_ms, payload_json)."""
        with self._read_snapshot() as connection:
            return self._dict_rows(connection, "SELECT aggregate_id,committed_at_ms,payload_json FROM financial_events WHERE aggregate_type='INTAKE'" + ("" if sha is None else " AND aggregate_id=?") + " ORDER BY event_sequence", () if sha is None else (sha,))

    def _obligation_timeline(self, connection: sqlite3.Connection, obligation_id: str, limit: int) -> dict[str, Any]:
        """The newest ``limit`` OBLIGATION events for one obligation, oldest first."""

        total = int(connection.execute(
            "SELECT COUNT(*) FROM financial_events WHERE aggregate_type='OBLIGATION' AND aggregate_id=?",
            (obligation_id,),
        ).fetchone()[0])
        rows = self._dict_rows(
            connection,
            "SELECT event_sequence,event_id,aggregate_type,aggregate_id,kind,before_revision,after_revision,payload_json,payload_digest,previous_head,head,committed_at_ms FROM financial_events WHERE aggregate_type='OBLIGATION' AND aggregate_id=? ORDER BY event_sequence DESC LIMIT ?",
            (obligation_id, limit),
        )
        rows.reverse()
        return {"limit": limit, "total_count": total, "truncated": total > limit, "items": rows}

    def read_verified_staff_snapshot(self, query: Mapping[str, Any]) -> dict[str, Any]:
        """Read one bounded staff view and independently verify the same SQLite snapshot."""

        if not isinstance(query, Mapping):
            _fail(FinancialInputError, "staff_read_query")
        query_value = dict(query)
        resource = query_value.get("resource")
        workspace = resource == _STAFF_WORKSPACE_QUERY
        fields = ("resource", "item_id", "population_id", "status", "limit", "offset", "detail_limit", "history_limit") if workspace else ("resource", "item_id", "limit", "offset")
        if not (workspace or resource == _STAFF_DECISION_PACKAGE_QUERY) or set(query_value) != set(fields):
            _fail(FinancialInputError, "staff_read_query")
        query_value = {key: query_value[key] for key in fields}
        item_id = _id(query_value["item_id"], "item_id")
        population_id = _id(query_value["population_id"], "population_id") if workspace else None
        status, detail_limit, history_limit = (query_value[key] for key in ("status", "detail_limit", "history_limit")) if workspace else (None, None, 200)
        limit, offset = query_value["limit"], query_value["offset"]
        if (
            workspace and status not in _OBLIGATION_STATUS_CLAUSES
            or type(limit) is not int or not 1 <= limit <= (100 if workspace else 200)
            or type(offset) is not int or not 0 <= offset <= _MAX_ROWS
            or workspace and (type(detail_limit) is not int or not 1 <= detail_limit <= 200 or type(history_limit) is not int or not 1 <= history_limit <= 200)
        ):
            _fail(FinancialInputError, "staff_read_query")

        statement_counts = {"owner": 0, "independent_verifier": 0}
        phase = ["owner"]

        def count_read_statement(statement: str) -> None:
            words = statement.lstrip().split(None, 1)
            if words and words[0].upper() in {"SELECT", "WITH", "PRAGMA"}:
                statement_counts[phase[0]] += 1

        started_ns = time.perf_counter_ns()
        with self._read_snapshot() as connection:
            connection.set_trace_callback(count_read_statement)
            meta = self._meta(connection)
            snapshot_fields = {
                "schema": str(meta["schema"]),
                "schema_version": int(meta["schema_version"]),
                "scope": _cols(meta, str, *_SCOPE_KEYS),
                "mode": str(meta["mode"]),
                "owner_id": str(meta["owner_id"]),
                "continuity_epoch": int(meta["continuity_epoch"]),
                "sequence": int(meta["sequence"]),
                "history_head": _hex(bytes(meta["history_head"])),
            }
            snapshot_fields["snapshot_id"] = _staff_snapshot_id(snapshot_fields)

            if workspace:
                summary = self.summary(_connection=connection)
                population = self.population_status(population_id, _connection=connection)
                items = self.list_obligations(
                    status=status,
                    limit=limit,
                    offset=offset,
                    _connection=connection,
                )
                total_count = int(connection.execute(
                    f"SELECT COUNT(*) FROM obligations WHERE {_OBLIGATION_STATUS_CLAUSES[status]}"
                ).fetchone()[0])
                next_offset = offset + len(items) if offset + len(items) < total_count else None
                detail = self.obligation_detail(item_id, limit=detail_limit, _connection=connection)
                package = self.decision_package(
                    item_id,
                    limit=100,
                    offset=0,
                    _connection=connection,
                )
                resources: dict[str, Any] = {
                    "summary": summary,
                    "population": population,
                    "items_page": {
                        "status": status,
                        "limit": limit,
                        "offset": offset,
                        "total_count": total_count,
                        "next_offset": next_offset,
                        "items": items,
                    },
                    "detail": detail,
                    "decision_package": package,
                    "timeline": self._obligation_timeline(connection, str(detail["obligation_id"]), history_limit),
                }
                item_ids = sorted({str(row["item_id"]) for row in items} | {item_id})
            else:
                package = self.decision_package(
                    item_id,
                    limit=limit,
                    offset=offset,
                    _connection=connection,
                )
                resources = {
                    "decision_package": package,
                    "timeline": self._obligation_timeline(
                        connection, str(package["obligation"]["obligation_id"]), history_limit
                    ),
                }
                item_ids = [item_id]

            if not item_ids or len(set(item_ids)) != len(item_ids):
                _fail(FinancialIntegrityError, "staff_snapshot_items")
            placeholders = ",".join("?" for _ in item_ids)
            support_counts = {
                str(row["item_id"]): int(row["support_count"])
                for row in connection.execute(
                    f"SELECT item_id,COUNT(*) AS support_count FROM evidence WHERE kind='SUPPORT' AND item_id IN ({placeholders}) GROUP BY item_id",
                    tuple(item_ids),
                ).fetchall()
            }
            resources["support_counts"] = {item_id: support_counts.get(item_id, 0) for item_id in item_ids}
            binding_rows = connection.execute(
                "SELECT o.item_id,o.obligation_id,o.revision,o.current_evaluation_id,"
                "e.revision AS evaluation_revision,e.result_digest,e.control_pack_id,"
                "e.control_pack_version,e.control_pack_digest "
                "FROM obligations o JOIN evaluations e ON e.evaluation_id=o.current_evaluation_id "
                f"AND e.obligation_id=o.obligation_id WHERE o.item_id IN ({placeholders}) ORDER BY o.item_id",
                tuple(item_ids),
            ).fetchall()
            if len(binding_rows) != len(item_ids):
                _fail(FinancialIntegrityError, "staff_snapshot_evaluation_binding")
            item_bindings: list[dict[str, Any]] = []
            for row in binding_rows:
                if (
                    row["current_evaluation_id"] is None
                    or int(row["evaluation_revision"]) != int(row["revision"])
                    or any(row[key] is None for key in ("result_digest", "control_pack_id", "control_pack_version", "control_pack_digest"))
                    or len(result_digest := bytes(row["result_digest"])) != 64
                    or len(pack_digest := bytes(row["control_pack_digest"])) != 64
                ):
                    _fail(FinancialIntegrityError, "staff_snapshot_evaluation_binding")
                item_bindings.append(
                    {
                        **_cols(row, str, "item_id", "obligation_id"),
                        "revision": int(row["revision"]),
                        "evaluation_id": str(row["current_evaluation_id"]),
                        "evaluation_result_digest": _hex(result_digest),
                        "control_pack_id": str(row["control_pack_id"]),
                        "control_pack_version": int(row["control_pack_version"]),
                        "control_pack_digest": _hex(pack_digest),
                    }
                )
            verifier_started_ns = time.perf_counter_ns()
            phase[0] = "independent_verifier"
            from app.right_rail_financial_owner_independent import verify_database_connection

            verification = verify_database_connection(connection, **self._checker_expectations())
            verifier_microseconds = (time.perf_counter_ns() - verifier_started_ns) // 1_000
            if any(verification.get(key) != snapshot_fields[key] for key in ("owner_id", "schema", "schema_version", "scope", "mode", "continuity_epoch", "sequence", "history_head")):
                _fail(FinancialIntegrityError, "staff_snapshot_verification_binding")
            if workspace and int(summary["sequence"]) != snapshot_fields["sequence"]:
                _fail(FinancialIntegrityError, "staff_snapshot_sequence_binding")
            bundle = {
                "contract": _VERIFIED_STAFF_SNAPSHOT_CONTRACT,
                "query": query_value,
                "snapshot": snapshot_fields,
                "resources": resources,
                "item_bindings": item_bindings,
                "verification": verification,
                "read_cost": {
                    "owner_connection_acquisitions": 1,
                    "independent_verifier_connection_acquisitions": 0,
                    "owner_read_statement_count": statement_counts["owner"],
                    "independent_verifier_statement_count": statement_counts["independent_verifier"],
                    "independent_verifier_microseconds": verifier_microseconds,
                },
            }
        bundle["read_cost"]["snapshot_transaction_microseconds"] = (
            time.perf_counter_ns() - started_ns
        ) // 1_000
        return bundle

    def action_payload(self, action_id: str) -> dict[str, Any]:
        _id(action_id, "action_id")
        with self._read_snapshot() as connection:
            row = _one(connection, "action_missing", "SELECT payload_json,payload_digest FROM actions WHERE action_id=?", (action_id,))
            return {"action_id": action_id, "payload": _stored_object(row[0], "action_payload_integrity"), "payload_digest": _hex(bytes(row[1]))}

    @staticmethod
    def _export_value(value: Any) -> Any:
        if type(value) is bytes:
            return {"hex": _hex(value)}
        if value is None or type(value) in {str, int, float, bool}:
            return value
        _fail(FinancialContinuityError, "continuity_value")

    @staticmethod
    def _import_value(value: Any) -> Any:
        if type(value) is dict and set(value) == {"hex"} and type(value["hex"]) is str:
            try:
                raw = bytes.fromhex(value["hex"])
            except ValueError:
                _fail(FinancialContinuityError, "continuity_hex")
            return raw
        if value is None or type(value) in {str, int, float, bool}:
            return value
        _fail(FinancialContinuityError, "continuity_value")

    @classmethod
    def validate_continuity_package(cls, package_bytes: bytes) -> dict[str, Any]:
        if type(package_bytes) is not bytes or not package_bytes or len(package_bytes) > _MAX_PACKAGE_BYTES:
            _fail(FinancialContinuityError, "continuity_package_size")
        try:
            package = json.loads(package_bytes.decode("ascii"), parse_constant=lambda _: None, parse_float=lambda t: None if abs(float(t)) == float("inf") else float(t))  # NaN, Infinity and 1e999 become null, so the canonical comparison below refuses them
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail(FinancialContinuityError, "continuity_package_json")
        if type(package) is not dict or _canonical(package) != package_bytes:
            _fail(FinancialContinuityError, "continuity_package_canonical")
        required = {
            "schema", "version", "scope", "authority", "continuity_epoch", "sequence",
            "history_head", "dispatch_enabled", "egress_enabled", "mode", "tables",
            "package_digest",
        }
        if set(package) != required:
            _fail(FinancialContinuityError, "continuity_package_shape")
        package_version = package["version"]
        # The Owner restores Continuity v8 only; every other version fails closed here.
        if type(package_version) is not int or package_version != _SCHEMA_VERSION:
            _fail(FinancialContinuityError, "continuity_package_schema")
        if package["schema"] != _CONTINUITY_SCHEMA:
            _fail(FinancialContinuityError, "continuity_package_schema")
        scope = package["scope"]
        if type(scope) is not dict or set(scope) != set(_SCOPE_KEYS):
            _fail(FinancialContinuityError, "continuity_package_scope")
        for key in _SCOPE_KEYS[:4]:
            _id(scope[key], f"continuity_scope_{key}")
        if scope["currency"] != _CURRENCY:
            _fail(FinancialContinuityError, "continuity_scope_currency")
        authority = package["authority"]
        if type(authority) is not dict or set(authority) != {"authority_id", "epoch", "digest"}:
            _fail(FinancialContinuityError, "continuity_package_authority")
        _id(authority["authority_id"], "continuity_authority_id")
        if type(authority["epoch"]) is not int or authority["epoch"] < 1:
            _fail(FinancialContinuityError, "continuity_authority_epoch")
        try:
            authority_digest = bytes.fromhex(str(authority["digest"]))
        except (TypeError, ValueError):
            _fail(FinancialContinuityError, "continuity_authority_digest")
        if type(authority["digest"]) is not str or len(authority_digest) != 64:
            _fail(FinancialContinuityError, "continuity_authority_digest")
        if type(package["continuity_epoch"]) is not int or package["continuity_epoch"] < 1:
            _fail(FinancialContinuityError, "continuity_package_epoch")
        if type(package["sequence"]) is not int or not 0 <= package["sequence"] <= _MAX_ROWS:
            _fail(FinancialContinuityError, "continuity_package_sequence")
        for field in ("history_head", "package_digest"):
            value = package[field]
            if type(value) is not str or re.fullmatch(r"[0-9A-Fa-f]{128}", value) is None:
                _fail(FinancialContinuityError, f"continuity_{field}")
        if package["dispatch_enabled"] is not False or package["egress_enabled"] is not False or package["mode"] not in _MODES:
            _fail(FinancialContinuityError, "continuity_package_binding")
        tables = package["tables"]
        if type(tables) is not dict or set(tables) != _PACKAGE_TABLES:
            _fail(FinancialContinuityError, "continuity_package_tables")
        for table in sorted(_PACKAGE_TABLES):
            rows = tables[table]
            if type(rows) is not list or len(rows) > _MAX_ROWS:
                _fail(FinancialContinuityError, "continuity_package_rows")
            expected_columns = set(_TABLE_COLUMNS[table])
            for row in rows:
                if type(row) is not dict or set(row) != expected_columns:
                    _fail(FinancialContinuityError, "continuity_package_row")
                for value in row.values():
                    cls._import_value(value)
        identity_rows = tables["financial_identity"]
        if len(identity_rows) != 1:
            _fail(FinancialContinuityError, "continuity_identity_cardinality")
        identity_raw = {column: cls._import_value(identity_rows[0][column]) for column in _TABLE_COLUMNS["financial_identity"]}
        identity = _identity_record(identity_raw, error_type=FinancialContinuityError, code_prefix="continuity_identity")
        if identity["id"] != 1:
            _fail(FinancialContinuityError, "continuity_identity_id")
        meta_rows = tables["financial_meta"]
        if len(meta_rows) != 1:
            _fail(FinancialContinuityError, "continuity_meta_rows")
        meta_row = {column: cls._import_value(meta_rows[0][column]) for column in _TABLE_COLUMNS["financial_meta"]}
        expected_meta = {
            "schema_version": _SCHEMA_VERSION,
            "schema": _SCHEMA,
            **scope,
            "sequence": package["sequence"],
            "history_head": bytes.fromhex(str(package["history_head"])),
            "continuity_epoch": package["continuity_epoch"],
            "dispatch_enabled": 0,
            "egress_enabled": 0,
            "trusted_authority_id": authority["authority_id"],
            "trusted_authority_epoch": authority["epoch"],
            "trusted_authority_digest": authority_digest,
            "mode": package["mode"],
        }
        for key, expected_value in expected_meta.items():
            if meta_row.get(key) != expected_value:
                _fail(FinancialContinuityError, "continuity_meta_binding")
        if identity["bound_mode"] != package["mode"] or identity["bound_mode"] != meta_row["mode"] or identity["bound_owner_id"] != meta_row["owner_id"]:
            _fail(FinancialContinuityError, "continuity_identity_binding")
        if identity["provenance"] == "ROOT":
            expected_genesis = _digest(_GENESIS_DOMAIN, _canonical(scope), authority_digest, identity["identity_digest"])
            if identity["source_package_digest"] != _ZERO_DIGEST or identity["anchor_sequence"] != 0 or identity["anchor_head"] != expected_genesis or identity["genesis_head"] != expected_genesis:
                _fail(FinancialContinuityError, "continuity_identity_genesis")
        else:
            if identity["source_package_digest"] == _ZERO_DIGEST or identity["anchor_sequence"] > package["sequence"]:
                _fail(FinancialContinuityError, "continuity_identity_anchor")
            if identity["anchor_sequence"] == 0:
                if identity["anchor_head"] != identity["genesis_head"]:
                    _fail(FinancialContinuityError, "continuity_identity_anchor")
            else:
                anchor_row = next((row for row in tables["financial_events"] if row["event_sequence"] == identity["anchor_sequence"]), None)
                if anchor_row is None or cls._import_value(anchor_row["head"]) != identity["anchor_head"]:
                    _fail(FinancialContinuityError, "continuity_identity_history_anchor")
        digest = package["package_digest"]
        body = dict(package)
        del body["package_digest"]
        expected = _hex(_digest(_CONTINUITY_DOMAIN, _canonical(body)))
        if digest != expected:
            _fail(FinancialContinuityError, "continuity_package_digest")
        return package

    def _continuity_package_body(
        self,
        connection: sqlite3.Connection,
        exported_rows: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        meta = self._meta(connection)
        if int(meta["dispatch_enabled"]) != 0 or int(meta["egress_enabled"]) != 0:
            _fail(FinancialContinuityError, "continuity_dispatch_boundary")
        return {
            "schema": self.continuity_schema,
            "version": self.schema_version,
            "scope": self._scope_value(),
            "authority": _authority_ref(self.trusted_authority),
            "continuity_epoch": int(meta["continuity_epoch"]),
            "sequence": int(meta["sequence"]),
            "history_head": _hex(bytes(meta["history_head"])),
            "dispatch_enabled": False,
            "egress_enabled": False,
            "mode": str(meta["mode"]),
            "tables": exported_rows,
        }

    def _continuity_package_bytes(self, connection: sqlite3.Connection) -> bytes:
        """Serialize the exact bounded Continuity package from this connection."""
        # Refused before any row is loaded when the event payloads alone exceed the cap.
        if connection.execute("SELECT COALESCE(SUM(length(payload_json)),0) FROM financial_events").fetchone()[0] > _MAX_PACKAGE_BYTES:
            _fail(FinancialContinuityError, "continuity_package_size")
        exported_rows: dict[str, list[dict[str, Any]]] = {}
        for table in sorted(self._tables):
            columns = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))
            if columns != self._table_columns[table]:
                _fail(FinancialContinuityError, "continuity_schema_columns")
            rows: list[dict[str, Any]] = []
            for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid"):  # every package table is a rowid table; history replays in event order
                rows.append({column: self._export_value(row[column]) for column in columns})
            if len(rows) > _MAX_ROWS:
                _fail(FinancialContinuityError, "continuity_row_cap")
            exported_rows[table] = rows
        body = self._continuity_package_body(connection, exported_rows)
        package = {**body, "package_digest": _hex(_digest(_CONTINUITY_DOMAIN, _canonical(body)))}
        encoded = _canonical(package)
        if len(encoded) > _MAX_PACKAGE_BYTES:
            _fail(FinancialContinuityError, "continuity_package_size")
        return encoded

    def export_continuity(self) -> bytes:
        """Export only bounded, allowlisted responsibility state, from history a full verification covers (R1a, M5)."""
        with self._lock:
            try:
                package = self._continuity_package_bytes(self._begin("BEGIN"))
                if self._refusal is not None:
                    raise self._refusal
                self._writer.execute("ROLLBACK")
                return package
            except BaseException as error:
                self._discard_writer()
                _raise_if_busy(error)
                raise

    def export_history(self, directory: Path) -> bytes:
        """Export all history as sealed segments and a manifest (docs/CORE_REDESIGN.md "History segments").

        The manifest is read in the sealing transaction; sealed segments are append-only,
        so their files may be written after it. A segment file already in ``directory``
        is never rewritten, only compared byte for byte (IX.3); ``manifest.json`` is replaced only by a
        later export of the same history: a cash file's baseline is these exact bytes (III.3).
        """
        with self._write() as connection:
            self._seal_segment(connection, force=True)
            rows = {table: self._segment_record(table, tuple(connection.execute(f"SELECT * FROM {table}").fetchone()))["row"] for table in ("financial_identity", "financial_meta")}
            count, last = connection.execute("SELECT COUNT(*),(SELECT segment_digest FROM history_segments ORDER BY segment_index DESC LIMIT 1) FROM history_segments").fetchone()
        body = {"format": _SEGMENT_FORMAT, "identity": rows["financial_identity"], "meta": rows["financial_meta"], "segment_count": count, "last_segment_digest": _hex(_ZERO_DIGEST if last is None else bytes(last))}
        manifest = _canonical({**body, "manifest_digest": _hex(_digest(_SEGMENT_DOMAIN, b"manifest", _canonical(body)))})
        directory.mkdir(exist_ok=True)
        target = directory / "manifest.json"
        with self._read_snapshot() as connection:
            segments = connection.execute("SELECT * FROM history_segments WHERE segment_index<? ORDER BY segment_index", (count,)).fetchall()
            if target.exists():
                try:  # an older manifest of this identity whose last segment is this store's segment at that index
                    old = json.loads(target.read_bytes())
                    replaceable = old["identity"] == body["identity"] and old["segment_count"] >= 0 and old["last_segment_digest"] == (_hex(bytes(segments[old["segment_count"] - 1]["segment_digest"])) if old["segment_count"] else _hex(_ZERO_DIGEST))
                except (ValueError, KeyError, TypeError, IndexError):
                    replaceable = False
                if not replaceable and target.read_bytes() != manifest:
                    _fail(FinancialContinuityError, "history_export_mismatch")
            for segment in segments:
                events = connection.execute("SELECT * FROM financial_events WHERE event_sequence BETWEEN ? AND ? ORDER BY event_sequence", (segment["first_sequence"], segment["last_sequence"]))
                data = _canonical({"events": [self._segment_record("financial_events", tuple(row)) for row in events], "rows": json.loads(segment["rows_json"]), "seal": _segment_seal(*tuple(segment)[:6]), "segment_digest": _hex(bytes(segment["segment_digest"])), "signature": None})
                path = directory / f"segment-{segment['segment_index']:08d}.json"
                if not path.exists():
                    _replace_file(path, data)
                else:
                    with path.open("rb") as handle:
                        if handle.read(len(data) + 1) != data:
                            _fail(FinancialContinuityError, "history_export_mismatch")
        if not target.exists() or target.read_bytes() != manifest:
            _replace_file(target, manifest)
        return manifest

    def _replay_segment(self, connection: sqlite3.Connection, path: Path) -> None:
        """Apply one checked segment's events and final row images, then reseal it; the seal must match."""
        with path.open("rb") as handle:
            segment = json.loads(handle.read(_MAX_SEGMENT_BYTES + 1))
        columns = _TABLE_COLUMNS["financial_events"]
        connection.executemany(f"INSERT INTO financial_events ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", ([self._import_value(event[column]) for column in columns] for event in segment["events"]))
        keys = {table: [str(info[1]) for info in sorted(connection.execute(f"PRAGMA table_info({table})"), key=lambda info: info[5]) if info[5]] for table in _PROJECTION_TABLES}
        for record in segment["rows"]:
            table, values = record["table"], {column: self._import_value(record["row"][column]) for column in _TABLE_COLUMNS[record["table"]]}
            where, key = " AND ".join(f"{column}=?" for column in keys[table]), [values[column] for column in keys[table]]
            current = connection.execute(f"SELECT * FROM {table} WHERE {where}", key).fetchone()
            if current is None:
                connection.execute(f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", list(values.values()))
            elif changed := [column for column in values if current[column] != values[column]]:
                connection.execute(f"UPDATE {table} SET {','.join(f'{column}=?' for column in changed)} WHERE {where}", [values[column] for column in changed] + key)
            connection.execute(f"INSERT OR IGNORE INTO history_pending SELECT ?,rowid,? FROM {table} WHERE {where}", [table, len(_canonical(record)) + 1, *key])
        last = segment["events"][-1]
        connection.execute("UPDATE financial_meta SET sequence=?,history_head=? WHERE id=1", (last["event_sequence"], self._import_value(last["head"])))
        connection.execute("DELETE FROM temp.rr_captured_rows")
        if self._seal_segment(connection, force=True) != bytes.fromhex(segment["segment_digest"]):
            _fail(FinancialContinuityError, "history_replay_mismatch")

    @classmethod
    def restore_continuity(
        cls,
        *,
        package_bytes: bytes | None = None,
        history: Path | None = None,
        recovered_path: Path,
        trusted_authority: SyntheticTrustedAuthority | None,
        clock: FinancialClock | None = None,
        restore_mode: str = "SHADOW",
    ) -> "FinancialOwner":
        """Restore into a new SHADOW or explicitly approved TEST owner, from a package or by replaying a history export."""
        from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_database, verify_history_export

        sidecar_paths = (Path(f"{recovered_path}-wal"), Path(f"{recovered_path}-shm")) if isinstance(recovered_path, Path) else ()
        occupied = lambda path: path.exists() or path.is_symlink()
        if not isinstance(recovered_path, Path) or any(occupied(path) for path in (recovered_path, *sidecar_paths)) or not recovered_path.parent.is_dir():
            _fail(FinancialContinuityError, "continuity_destination")
        if restore_mode not in {"SHADOW", "TEST"}:
            _fail(FinancialContinuityError, "continuity_restore_mode")
        if history is None:
            package = cls.validate_continuity_package(package_bytes)
        elif package_bytes is not None:
            _fail(FinancialContinuityError, "continuity_source")
        if trusted_authority is None or type(trusted_authority) is not SyntheticTrustedAuthority:
            _fail(FinancialAuthorityError, "trusted_authority_required")
        if history is not None:
            try:
                package = verify_history_export(history, expected_authority=_checker_authority(trusted_authority))
            except IndependentFinancialError as error:
                _fail(FinancialContinuityError, f"history_export:{error}")
        authority = package["authority"]
        if (str(authority.get("authority_id")), int(authority.get("epoch", 0)), str(authority.get("digest"))) != (trusted_authority.authority_id, trusted_authority.epoch, _hex(trusted_authority.digest)):
            _fail(FinancialAuthorityError, "continuity_authority_mismatch")
        config = FinancialOwnerConfig(**_cols(package["scope"], str, *_SCOPE_KEYS))
        restored_owner_id = _SHADOW_OWNER_ID if restore_mode == "SHADOW" else _TEST_OWNER_ID
        source_identity_rows = package["tables"]["financial_identity"]
        if len(source_identity_rows) != 1:
            _fail(FinancialContinuityError, "continuity_identity_rows")
        source_identity = _identity_record(
            {column: cls._import_value(source_identity_rows[0][column]) for column in _TABLE_COLUMNS["financial_identity"]},
            error_type=FinancialContinuityError,
            code_prefix="continuity_identity",
        )
        identity_contract = {
            "id": 1,
            "schema_version": _SCHEMA_VERSION,
            "provenance": "CONTINUITY_RESTORE",
            "bound_mode": restore_mode,
            "bound_owner_id": restored_owner_id,
            "anchor_sequence": int(package["sequence"]),
            "anchor_head": bytes.fromhex(str(package["history_head"])),
            "genesis_head": bytes(source_identity["genesis_head"]),
            "source_package_digest": bytes.fromhex(str(package["package_digest"])),
            "identity_digest": _identity_digest(
                provenance="CONTINUITY_RESTORE",
                bound_mode=restore_mode,
                bound_owner_id=restored_owner_id,
                anchor_sequence=int(package["sequence"]),
                source_package_digest=bytes.fromhex(str(package["package_digest"])),
            ),
        }
        owner: FinancialOwner | None = None
        attempt_directory: Path | None = None
        attempt_path: Path | None = None
        published = False
        attempt_identity: tuple[int, int] | None = None
        published_identity: tuple[int, int] | None = None
        cleanup_failures: list[str] = []

        def cleanup_path(path: Path) -> None:
            try:
                if occupied(path):
                    path.unlink()
            except OSError as cleanup_error:
                cleanup_failures.append(f"{path}:{cleanup_error.__class__.__name__}")

        def cleanup_attempt() -> None:
            for path in () if attempt_path is None else (attempt_path, Path(f"{attempt_path}-wal"), Path(f"{attempt_path}-shm")):
                cleanup_path(path)
            if attempt_directory is not None:
                try:
                    attempt_directory.rmdir()
                except FileNotFoundError:
                    pass
                except OSError as cleanup_error:
                    cleanup_failures.append(f"{attempt_directory}:{cleanup_error.__class__.__name__}")

        def cleanup_published_destination() -> None:
            if not published or published_identity is None:
                return
            try:
                current = recovered_path.stat()
                if (int(current.st_dev), int(current.st_ino)) == published_identity:
                    recovered_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                cleanup_failures.append(f"{recovered_path}:{cleanup_error.__class__.__name__}")

        try:
            try:
                attempt_directory = Path(tempfile.mkdtemp(prefix=f".{recovered_path.name}.restore-", dir=str(recovered_path.parent)))
            except OSError:
                _fail(FinancialContinuityError, "continuity_destination")
            attempt_path = attempt_directory / "owner.sqlite"
            owner = cls._open_restore_destination(
                path=attempt_path,
                config=config,
                trusted_authority=trusted_authority,
                clock=clock,
                mode=restore_mode,
                owner_id=restored_owner_id,
                identity_contract=identity_contract,
                )
            insertion_order = (
                "control_packs", "population_imports", "population_items", "obligations", "evidence",
                "payments", "claimed_adjustments", "cases", "determinations", "actions", "action_outbox",
                "financial_events", "financial_conflicts", "evaluations", "program_funding_receipts",
                "program_funding_projection", "population_manifests", "population_manifest_members",
                "population_manifest_heads", "population_manifest_bindings",
            )
            with owner._write() as connection:
                for table in insertion_order if history is None else ():
                    connection.execute(f"DELETE FROM {table}")
                for index in range(int(package["segment_count"]) if history is not None else 0):
                    owner._replay_segment(connection, history / f"segment-{index:08d}.json")
                meta_rows = package["tables"]["financial_meta"]
                if len(meta_rows) != 1:
                    _fail(FinancialContinuityError, "continuity_meta_rows")
                meta_columns = owner._table_columns["financial_meta"]
                meta_values = [owner._import_value(meta_rows[0][column]) for column in meta_columns]
                overrides = {"mode": restore_mode, "dispatch_enabled": 0, "egress_enabled": 0, "owner_id": restored_owner_id}
                meta_values = [overrides.get(column, value) for column, value in zip(meta_columns, meta_values)]
                assignments = ",".join(f"{column}=?" for column in meta_columns)
                connection.execute(f"UPDATE financial_meta SET {assignments} WHERE id=1", tuple(meta_values))
                for table in insertion_order if history is None else ():
                    columns = owner._table_columns[table]
                    rows = package["tables"][table]
                    placeholders = ",".join("?" for _ in columns)
                    for raw_row in rows:
                        values = [owner._import_value(raw_row[column]) for column in columns]
                        connection.execute(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})", tuple(values))
                connection.execute("DELETE FROM temp.rr_captured_rows")  # the imported history already carries them
                owner._derive_command_log(connection)
            # The restore-source verification below is strictly stronger than the open replay.
            owner._verify_open_identity(verify_history=False)
            verify_database(
                owner.path,
                expected_config=config,
                expected_authority=_checker_authority(trusted_authority),
                expected_mode=restore_mode,
                expected_owner_id=restored_owner_id,
                expected_continuity_epoch=int(package["continuity_epoch"]),
                restore_source_package=package_bytes,
            )
            if history is not None:
                verify_history_export(history, expected_authority=_checker_authority(trusted_authority), restored=owner.path)
            owner.close()
            with closing(owner._connect()) as connection:  # WAL: only the main file is published
                if tuple(connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()) != (0, 0, 0):
                    _fail(FinancialContinuityError, "continuity_restore_checkpoint")
            attempt_stat = attempt_path.stat()
            attempt_identity = (int(attempt_stat.st_dev), int(attempt_stat.st_ino))
            if any(occupied(path) for path in sidecar_paths):
                _fail(FinancialContinuityError, "continuity_destination")
            try:
                os.link(attempt_path, recovered_path)
            except FileExistsError:
                _fail(FinancialContinuityError, "continuity_destination")
            except OSError:
                _fail(FinancialContinuityError, "continuity_destination_claim")
            published = True
            published_identity = attempt_identity
            try:
                published_stat = recovered_path.stat()
            except OSError:
                _fail(FinancialContinuityError, "continuity_destination_claim")
            if (int(published_stat.st_dev), int(published_stat.st_ino)) != attempt_identity:
                _fail(FinancialContinuityError, "continuity_destination")
            if any(occupied(path) for path in sidecar_paths):
                _fail(FinancialContinuityError, "continuity_destination")
            cleanup_attempt()
            if cleanup_failures:
                cleanup_published_destination()
                _fail(FinancialContinuityError, "continuity_restore_cleanup")
            owner.path = recovered_path
        except Exception as error:
            if owner is not None:
                owner.close()
            cleanup_published_destination()
            cleanup_attempt()
            if cleanup_failures:
                _fail(FinancialContinuityError, "continuity_restore_cleanup")
            if error.__class__.__module__ == "app.right_rail_financial_owner_independent":
                _fail(FinancialContinuityError, "continuity_restore_integrity")
            raise
        if owner is None:
            _fail(FinancialContinuityError, "continuity_restore_owner")
        return owner

    def _checker_expectations(self) -> dict[str, Any]:
        """This Owner's trusted identity, as the independent checker expects it."""

        return {
            "expected_config": {**self._scope_value(), "schema_version": self.schema_version},
            "expected_authority": _checker_authority(self.trusted_authority),
            "expected_mode": self.mode,
            "expected_owner_id": self.owner_id,
        }

    def verify_integrity(self) -> dict[str, Any]:
        from app.right_rail_financial_owner_independent import verify_database

        return verify_database(self.path, **self._checker_expectations())

    def dispatch_outbox(self, *_args: Any, **_kwargs: Any) -> None:
        _fail(FinancialDispatchError, "dispatch_disabled")

    def close(self) -> None:
        with self._lock:
            self._discard_writer()
            if self._custody is not None:
                self._custody.close(self.owner_id, self._high)  # a signed ANCHOR at the last verified or committed state

    def __enter__(self) -> "FinancialOwner":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
