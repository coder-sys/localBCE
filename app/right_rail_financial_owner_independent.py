"""Independent, read-only checker for the synthetic RightRail financial owner.

This module deliberately does not import the production owner.  It owns a
second copy of the versioned database grammar, digest domains, identity
bindings, and projection equations.  It never repairs a database and opens
database paths read-only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
from typing import Any, NoReturn
from urllib.parse import quote


class IndependentFinancialError(RuntimeError):
    """Raised for every malformed, stale, rebound, or inconsistent owner DB."""


def _fail(code: str, caught: BaseException | None = None) -> NoReturn:
    # Only the checker's own caught read error can be a lock: another connection's lock is retryable, never a finding.
    if isinstance(caught, sqlite3.OperationalError) and getattr(caught, "sqlite_errorcode", 0) & 0xFF in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
        code = "database:busy"
    error = IndependentFinancialError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


# Stores and packages are verified at v8 only; every other version fails closed.
SCHEMA_VERSION = 8
SCHEMA = "RR/FINANCIAL/OWNER/v8"
CONTINUITY_SCHEMA = "RR/FINANCIAL/CONTINUITY/v8"
DECISION_PACKAGE_CONTRACT = "RR/FINANCIAL/DECISION-PACKAGE/v2"
POPULATION_MANIFEST_CONTRACT = "RR/FINANCIAL/POPULATION-MANIFEST/v1"
CURRENCY = "USD"
MAX_CENTS = (1 << 63) - 1
MAX_ROWS = 10_000
MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_DECISION_PACKAGE_BYTES = MAX_PACKAGE_BYTES - 512
MAX_DECISION_PACKAGE_DEPTH = 32
MAX_JSON_BYTES = 1 * 1024 * 1024
MAX_PACKAGE_NODES = 250_000
SEGMENT_FORMAT = "RR/GATE/SEGMENT/v1"  # docs/CORE_REDESIGN.md "History segments"
SEGMENT_DOMAIN = b"RR/GATE/SEGMENT/v1\x00"
MAX_SEGMENT_BYTES = 2 * MAX_PACKAGE_BYTES
SEAL_SEGMENT_EVENTS, SEAL_SEGMENT_BYTES = 4096, MAX_PACKAGE_BYTES // 2  # every Owner write leaves the open segment below both
PRIVATE_INDEX_DEFS_V1 = {  # name -> (table, key columns); each is exactly CREATE INDEX name ON table(columns)
    "rr_financial_v1_evidence_item_id": ("evidence", ("item_id", "evidence_id")),
    "rr_financial_v1_claims_obligation_id": ("claimed_adjustments", ("obligation_id", "claim_id")),
    "rr_financial_v1_cases_obligation_id": ("cases", ("obligation_id", "case_id")),
    "rr_financial_v1_actions_obligation_id": ("actions", ("obligation_id", "action_id")),
    "rr_financial_v1_conflicts_obligation_id": ("financial_conflicts", ("obligation_id", "conflict_id")),
    "rr_financial_v1_evaluations_obligation_revision": ("evaluations", ("obligation_id", "revision")),
    "rr_financial_v1_determinations_obligation_id": ("determinations", ("obligation_id", "determination_id")),
}
PRIVATE_INDEX_DEFS = {  # user_version -> its exact index set; the Owner upgrades 1 to 2 on open
    1: PRIVATE_INDEX_DEFS_V1,
    2: {**PRIVATE_INDEX_DEFS_V1, "rr_financial_v2_events_aggregate_kind": ("financial_events", ("aggregate_type", "aggregate_id", "kind"))},
}
CORRECTION_FOLLOWUP_CONTRACT = "RR/FINANCIAL/CORRECTION-FOLLOWUP/v1"
CORRECTION_TRANSITION_OPERATION = "RR/FINANCIAL/CORRECTION-TRANSITION/v1"
CORRECTION_TRANSITION_ARTIFACT_SHA256 = "1A7A18333726484A0737DA7B005EC699F73E99EA0CFACFB409B000F964BED3AF"
RETIRED_PINS_PATH = Path(__file__).resolve().parent.parent / "artifacts" / "engine-correction" / "RETIRED_PINS"
RETIRED_PINS_SHA256 = "d0c3aa9e493e6adf6af590fdd1c32b99eb85bf1c6d52b73f3fca1dab46f1dc3b"


# What a correction requests, by the rule of the engine that decided it: (claim, input shortfall,
# what earlier correction requests on the obligation still ask for, less what was paid against them) -> amount.
_CORRECTION_AMOUNT_RULES = {
    "correction-rule-v1": lambda claim, shortfall, unpaid: claim,  # E911: the whole claim
    "b2-v1": lambda claim, shortfall, unpaid: min(claim, shortfall),  # 88D8: the unpaid balance
    "h1-v1": lambda claim, shortfall, unpaid: min(claim, max(shortfall - unpaid, 0)),  # current: not yet requested
}


def correction_engines() -> dict[str, tuple[int, str]]:
    """Every engine committed correction history may name -> (generation, amount rule). Retired engines are
    valid for history, never for new work; generation is registry order and the current pin is newest
    (append-only, digest-pinned; line = sha, date, retiring commit, rule, reason). A malformed registry refuses."""
    try:
        registry = RETIRED_PINS_PATH.read_bytes()
    except OSError:
        registry = b""
    if hashlib.sha256(registry).hexdigest() != RETIRED_PINS_SHA256:
        _fail("history:correction-retired-pins")
    engines: dict[str, tuple[int, str]] = {}
    try:
        for line in registry.decode("ascii").splitlines():
            sha, _date, _commit, rule, _reason = line.split("\t")
            if re.fullmatch("[0-9A-F]{64}", sha) is None or rule not in _CORRECTION_AMOUNT_RULES or sha in engines or sha == CORRECTION_TRANSITION_ARTIFACT_SHA256:
                raise ValueError(sha)
            engines[sha] = (len(engines), rule)
    except ValueError:
        _fail("history:correction-retired-pins")
    engines[CORRECTION_TRANSITION_ARTIFACT_SHA256] = (len(engines), "h1-v1")
    return engines


CORRECTION_FOLLOWUP_DEPENDENCIES = [
    "OBLIGATION_REVISION",
    "CURRENT_EVALUATION_RECEIPT",
    "CONTROL_PACK",
    "TRUSTED_AUTHORITY",
    "SUPPORTING_EVIDENCE",
    "CURRENT_DETERMINATION",
    "ACTION_DELIVERY",
]
CORRECTION_FOLLOWUP_READ_OBSERVATIONS = {
    "action_id": ("ACTION_ID", "action_id"),
    "determination_id": ("DETERMINATION_ID", "determination_id"),
    "evaluation_consumed": ("EVALUATION_CONSUMED", "input_evaluation_id"),
}

EVENT_DOMAIN = b"RR/FINANCIAL/EVENT/v2\x00"
HEAD_DOMAIN = b"RR/FINANCIAL/HEAD/v2\x00"
GENESIS_DOMAIN = b"RR/FINANCIAL/GENESIS/v7\x00"
EVIDENCE_DOMAIN = b"RR/FINANCIAL/EVIDENCE/v1\x00"
ACTION_DOMAIN = b"RR/FINANCIAL/ACTION/v1\x00"
IDEMPOTENCY_DOMAIN = b"RR/FINANCIAL/IDEMPOTENCY/v1\x00"
EVALUATION_RESULT_DOMAIN = b"RR/FINANCIAL/EVALUATION/v5\x00"
EVALUATION_INPUT_DOMAIN = b"RR/FINANCIAL/EVALUATION-INPUT/v1\x00"
EVALUATION_EVENT_DOMAIN = b"RR/FINANCIAL/EVALUATION-EVENT/v1\x00"
EVALUATION_RECEIPT_DOMAIN = b"RR/FINANCIAL/EVALUATION-RECEIPT/v1\x00"
CONTINUITY_DOMAIN = b"RR/FINANCIAL/CONTINUITY/v8\x00"
COMMAND_DOMAIN = b"RR/FINANCIAL/COMMAND/v1\x00"
POPULATION_MANIFEST_DOMAIN = b"RR/FINANCIAL/POPULATION-MANIFEST/v1\x00"
POPULATION_MANIFEST_MEMBERS_DOMAIN = b"RR/FINANCIAL/POPULATION-MANIFEST-MEMBERS/v1\x00"
POPULATION_STAGING_DOMAIN = b"RR/FINANCIAL/POPULATION-STAGING/v1\x00"
PROGRAM_FUNDING_RECEIPT_DOMAIN = b"RR/FINANCIAL/PROGRAM-FUNDING-RECEIPT/v1\x00"
PROGRAM_FUNDING_RECEIPT_SCHEMA = "RR/FINANCIAL/PROGRAM-FUNDING-RECEIPT/v1"
PROGRAM_FUNDING_CONFIRMATION_CLASS = "STATE_PAYMENT_RECORD"
PROGRAM_FUNDING_EVIDENCE_STATUS = "SYNTHETIC_UNAPPROVED"
IDENTITY_DOMAIN = b"RR/FINANCIAL/IDENTITY/v1\x00"
EVALUATION_RECEIPT_CONTRACT = "RR/FINANCIAL/EVALUATION-RECEIPT/v1"
ZERO_DIGEST = b"\x00" * 64
TEST_OWNER_ID = "continuity-test-owner-v1"
SHADOW_OWNER_ID = "continuity-shadow-owner-v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ROLE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_KIND = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_HEX128 = re.compile(r"[0-9A-Fa-f]{128}\Z")


# The names, order, declared SQLite types, and primary-key positions are
# independently frozen here.  They are intentionally not imported from the
# owner module.
def _parse_table_specs(specs: dict[str, str]) -> dict[str, tuple[tuple[str, str, int], ...]]:
    """Expand ``"T name@pk ..."`` column specs (I=INTEGER, T=TEXT, B=BLOB)."""

    types = {"I": "INTEGER", "T": "TEXT", "B": "BLOB"}
    result: dict[str, tuple[tuple[str, str, int], ...]] = {}
    for table, text in specs.items():
        tokens = text.split()
        columns = []
        for index in range(0, len(tokens), 2):
            name, _, pk = tokens[index + 1].partition("@")
            columns.append((name, types[tokens[index]], int(pk or 0)))
        result[table] = tuple(columns)
    return result


_TABLE_DEFS: dict[str, tuple[tuple[str, str, int], ...]] = _parse_table_specs({
    "financial_identity": (
        "I id@1 I schema_version T provenance T bound_mode T bound_owner_id I anchor_sequence "
        "B anchor_head B genesis_head B source_package_digest B identity_digest"
    ),
    "financial_meta": (
        "I id@1 I schema_version T schema T state_id T deployment_id T program_id T period_id T currency "
        "I sequence B history_head I continuity_epoch I dispatch_enabled I egress_enabled "
        "T trusted_authority_id I trusted_authority_epoch B trusted_authority_digest T mode T owner_id"
    ),
    "control_packs": (
        "T pack_id@1 T state_id T deployment_id T program_id T period_id I version T source_refs_json "
        "I effective_start_ms I effective_end_ms I recorded_at_ms I approved_at_ms T calculation_rule_id "
        "T adjustment_rule_id T authorized_roles_json T expected_tests_json B pack_digest T status"
    ),
    "population_imports": (
        "T population_id@1 T pack_id I cutoff_ms T inclusion_rules_json I expected_count "
        "I source_complete I imported_count I validated_count B validation_digest T status "
        "I created_at_ms I updated_at_ms"
    ),
    "population_items": "T population_id@1 T item_id@2 T display_label I owed_cents I due_at_ms T currency",
    "obligations": (
        "T obligation_id@1 T population_id T item_id T period_id T currency I owed_cents I due_at_ms "
        "I rule_version I revision I claimed_adjustment_cents I lawful_adjustment_cents "
        "I received_cash_cents I shortfall_cents I overage_cents I cash_satisfied I amount_satisfied "
        "I timely I reporting_complete T verification_status T case_status T delivery_status "
        "T current_evaluation_id I updated_at_ms"
    ),
    "evidence": (
        "T evidence_id@1 T item_id T kind T common_origin_id T source_id T source_version T local_ref "
        "I applicable_at_ms I event_at_ms I received_at_ms B content_digest B record_digest "
        "I amount_cents T reversal_of T supersedes"
    ),
    "payments": (
        "T payment_id@1 T obligation_id T item_id T evidence_id T common_origin_id I amount_cents "
        "I event_at_ms I active T reversed_by_evidence_id"
    ),
    "claimed_adjustments": (
        "T claim_id@1 T obligation_id T evidence_id I amount_cents T owner_role I deadline_ms T status "
        "I created_at_ms I updated_at_ms"
    ),
    "cases": (
        "T case_id@1 T obligation_id T reason T contractual_accountability T next_action_owner "
        "I due_at_ms T completion_conditions_json T status I updated_at_ms"
    ),
    "determinations": (
        "T determination_id@1 T obligation_id T claim_id T actor_id T actor_role T authority_id "
        "I authority_epoch B authority_digest T decision I amount_cents T supporting_evidence_json "
        "I expected_revision I resulting_revision I decided_at_ms B determination_digest "
        "T input_evaluation_id B input_evaluation_result_digest"
    ),
    "actions": (
        "T action_id@1 T obligation_id T determination_id T kind T status I revision T payload_json "
        "B payload_digest B idempotency_key I created_at_ms"
    ),
    "action_outbox": "T action_id@1 T status I attempt B payload_digest T acknowledgment_ref I updated_at_ms",
    "financial_events": (
        "I event_sequence@1 B event_id T aggregate_type T aggregate_id T kind I before_revision "
        "I after_revision T payload_json B payload_digest B previous_head B head I committed_at_ms"
    ),
    "financial_conflicts": (
        "T conflict_id@1 T obligation_id T common_origin_id T existing_payment_id T candidate_evidence_id "
        "I existing_amount_cents I candidate_amount_cents T reason I visible_at_ms"
    ),
    "evaluations": (
        "T evaluation_id@1 T obligation_id I revision I rule_version T evidence_ids_json T authority_id "
        "I evaluated_at_ms I owed_cents I claimed_adjustment_cents I lawful_adjustment_cents "
        "I received_cash_cents I shortfall_cents I overage_cents I cash_satisfied I amount_satisfied "
        "I timely I reporting_complete T verification_status T case_status T delivery_status "
        "B result_digest T contract_version T scope_json T control_pack_id I control_pack_version "
        "B control_pack_digest I authority_epoch B authority_digest T evidence_bindings_json "
        "T input_snapshot_json B input_snapshot_digest B receipt_digest"
    ),
    "program_funding_receipts": (
        "T receipt_id@1 T state_id T deployment_id T program_id T period_id T currency "
        "T source_record_ref I amount_cents T confirmation_class T evidence_status I event_at_ms "
        "I recorded_at_ms T supersedes_receipt_id B receipt_digest"
    ),
    "program_funding_projection": "T source_record_ref@1 T receipt_id I amount_cents I event_at_ms I revision B receipt_digest",
    "population_manifests": (
        "T manifest_id@1 T contract I manifest_version T state_id T deployment_id T program_id "
        "T period_id T currency T pack_id I cutoff_ms T inclusion_rules_json T source_owner_id "
        "T authority_id I authority_epoch B authority_digest T approved_by T approval_ref T source_id "
        "T source_version B source_digest I member_count B member_digest T supersedes_manifest_id "
        "B supersedes_digest B manifest_digest I registered_at_ms"
    ),
    "population_manifest_members": "T manifest_id@1 I position@2 T member_id",
    "population_manifest_heads": (
        "T state_id@1 T deployment_id@2 T program_id@3 T period_id@4 T currency T pack_id@5 I cutoff_ms@6 "
        "T source_owner_id@7 T manifest_id I manifest_version B manifest_digest I updated_at_ms"
    ),
    "population_manifest_bindings": "T population_id@1 T manifest_id I manifest_version B manifest_digest",
    "commands": "T command_id@1 T kind T request_json B request_digest I event_sequence",
})

TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    table: tuple(column[0] for column in definition)
    for table, definition in _TABLE_DEFS.items()
}
TABLES = frozenset(_TABLE_DEFS)
PACKAGE_TABLES = TABLES - {"commands"}  # the command log is derived from history, never exported
PROJECTION_TABLES = PACKAGE_TABLES - {"financial_events", "financial_identity", "financial_meta"}
_HISTORY_TABLE_DEFS = _parse_table_specs({
    "history_segments": "I segment_index@1 I first_sequence I last_sequence B previous_digest B event_head B projection_root B segment_digest T rows_json",
    "history_pending": "T table_name@1 I row_key@2 I record_bytes",
    "history_open": "I id@1 I event_count I byte_count",
})
# Rows whose every write the next event carries in ``rows``; they must equal replay of the chain.
CAPTURED_TABLES = ("action_outbox", "cases", "claimed_adjustments", "evidence", "financial_conflicts")

# Package versions: (continuity schema, owner schema, digest domain).
_PACKAGE_FORMATS: dict[int, tuple[str, str, bytes]] = {
    8: (CONTINUITY_SCHEMA, SCHEMA, CONTINUITY_DOMAIN),
}

# Declared foreign keys, frozen here independently: "child,cols>parent.cols".
_FOREIGN_KEY_DEFS: dict[str, frozenset[tuple[tuple[str, ...], str, tuple[str, ...]]]] = {
    table: frozenset(
        (tuple(child.split(",")), parent.partition(".")[0], tuple(parent.partition(".")[2].split(",")))
        for child, _, parent in (entry.partition(">") for entry in spec.split())
    )
    for table, spec in {
        "population_imports": "pack_id>control_packs.pack_id",
        "population_items": "population_id>population_imports.population_id",
        "obligations": (
            "population_id,item_id>population_items.population_id,item_id "
            "current_evaluation_id>evaluations.evaluation_id"
        ),
        "evidence": "reversal_of>payments.payment_id supersedes>evidence.evidence_id",
        "payments": (
            "obligation_id>obligations.obligation_id evidence_id>evidence.evidence_id "
            "reversed_by_evidence_id>evidence.evidence_id"
        ),
        "claimed_adjustments": "obligation_id>obligations.obligation_id evidence_id>evidence.evidence_id",
        "cases": "obligation_id>obligations.obligation_id",
        "determinations": (
            "obligation_id>obligations.obligation_id claim_id>claimed_adjustments.claim_id "
            "input_evaluation_id>evaluations.evaluation_id"
        ),
        "actions": "obligation_id>obligations.obligation_id determination_id>determinations.determination_id",
        "action_outbox": "action_id>actions.action_id",
        "financial_conflicts": (
            "obligation_id>obligations.obligation_id existing_payment_id>payments.payment_id "
            "candidate_evidence_id>evidence.evidence_id"
        ),
        "evaluations": "obligation_id>obligations.obligation_id control_pack_id>control_packs.pack_id",
        "program_funding_receipts": "supersedes_receipt_id>program_funding_receipts.receipt_id",
        "program_funding_projection": "receipt_id>program_funding_receipts.receipt_id",
        "population_manifests": "pack_id>control_packs.pack_id supersedes_manifest_id>population_manifests.manifest_id",
        "population_manifest_members": "manifest_id>population_manifests.manifest_id",
        "population_manifest_heads": "pack_id>control_packs.pack_id manifest_id>population_manifests.manifest_id",
        "population_manifest_bindings": (
            "population_id>population_imports.population_id manifest_id>population_manifests.manifest_id"
        ),
        "commands": "event_sequence>financial_events.event_sequence",
    }.items()
}

# Command log, per request kind: the events it produced; the payload field naming
# its key (None: the event's aggregate id); the rows it wrote ("alias=table.column",
# matched to the key or to "<alias.column" of an earlier row); its request fields
# ("[name=]alias.column").
_COMMAND_SOURCES: dict[str, tuple[str, str | None, str, str]] = {
    "CONTROL_PACK": ("CONTROL_PACK_PUBLISHED", None, "r=control_packs.pack_id", "r.pack_digest"),
    "POPULATION_MANIFEST": (
        "POPULATION_MANIFEST_REGISTERED POPULATION_MANIFEST_SUPERSEDED", None,
        "r=population_manifests.manifest_id", "r.manifest_digest",
    ),
    "FUNDING_RECEIPT": (
        "FUNDING_RECEIPT_RECORDED FUNDING_RECEIPT_SUPERSEDED", None,
        "r=program_funding_receipts.receipt_id", "r.receipt_digest",
    ),
    "SUPPORT_EVIDENCE": ("SUPPORT_EVIDENCE_RECORDED", "evidence_id", "r=evidence.evidence_id", "r.item_id r.record_digest"),
    "REPORT": (
        "REPORTING_EVIDENCE_RECORDED REPORTING_CORRECTION_RECORDED", "evidence_id",
        "r=evidence.evidence_id", "r.item_id r.record_digest",
    ),
    "PAYMENT_REVERSAL": (
        "PAYMENT_REVERSED", "evidence_id",
        "r=evidence.evidence_id", "r.item_id payment_id=r.reversal_of r.record_digest",
    ),
    "PAYMENT": (
        "PAYMENT_RECEIVED", "payment_id",
        "r=payments.payment_id e=evidence.evidence_id<r.evidence_id",
        "r.item_id r.evidence_id r.common_origin_id r.amount_cents r.event_at_ms e.source_id e.source_version e.local_ref",
    ),
    "OFFSET_CLAIM": (
        "OFFSET_CLAIMED", "claim_id",
        "r=claimed_adjustments.claim_id o=obligations.obligation_id<r.obligation_id",
        "o.item_id r.evidence_id r.amount_cents r.owner_role r.deadline_ms",
    ),
    "OFFSET_DECISION": (
        "OFFSET_AUTHORIZED OFFSET_REJECTED_CORRECTION_AUTHORIZED", "action_id",
        "r=actions.action_id d=determinations.determination_id<r.determination_id o=obligations.obligation_id<r.obligation_id",
        "o.item_id d.claim_id d.decision d.actor_id d.actor_role d.expected_revision d.decided_at_ms "
        "evaluation_id=d.input_evaluation_id evaluation_result_digest=d.input_evaluation_result_digest",
    ),
    "ACTION_ACKNOWLEDGMENT": ("ACTION_ACKNOWLEDGED", "action_id", "r=action_outbox.action_id", "r.acknowledgment_ref"),
}
_COMMAND_EVENT_KINDS = {event: kind for kind, spec in _COMMAND_SOURCES.items() for event in spec[0].split()}

_TRIGGER_DEFS = {
    "action_payload_immutable": "CREATE TRIGGER action_payload_immutable BEFORE UPDATE OF action_id,obligation_id,determination_id,kind,revision,payload_json,payload_digest,idempotency_key,created_at_ms ON actions BEGIN SELECT RAISE(ABORT,'action_payload_immutable'); END",
    "action_outbox_payload_immutable": "CREATE TRIGGER action_outbox_payload_immutable BEFORE UPDATE OF action_id,payload_digest ON action_outbox BEGIN SELECT RAISE(ABORT,'action_outbox_payload_immutable'); END",
    "evidence_record_immutable": "CREATE TRIGGER evidence_record_immutable BEFORE UPDATE OF evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,content_digest,record_digest,amount_cents,reversal_of,supersedes ON evidence BEGIN SELECT RAISE(ABORT,'evidence_record_immutable'); END",
    "financial_identity_insert_immutable": "CREATE TRIGGER financial_identity_insert_immutable BEFORE INSERT ON financial_identity WHEN EXISTS (SELECT 1 FROM financial_identity) BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END",
    "financial_identity_update_immutable": "CREATE TRIGGER financial_identity_update_immutable BEFORE UPDATE OF schema_version,provenance,bound_mode,bound_owner_id,anchor_sequence,anchor_head,genesis_head,source_package_digest,identity_digest ON financial_identity BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END",
    "financial_event_update_immutable": "CREATE TRIGGER financial_event_update_immutable BEFORE UPDATE ON financial_events BEGIN SELECT RAISE(ABORT,'financial_event_immutable'); END",
    "financial_event_delete_immutable": "CREATE TRIGGER financial_event_delete_immutable BEFORE DELETE ON financial_events BEGIN SELECT RAISE(ABORT,'financial_event_immutable'); END",
    "financial_identity_delete_immutable": "CREATE TRIGGER financial_identity_delete_immutable BEFORE DELETE ON financial_identity BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END",
    "program_funding_receipt_update_immutable": "CREATE TRIGGER program_funding_receipt_update_immutable BEFORE UPDATE ON program_funding_receipts BEGIN SELECT RAISE(ABORT,'program_funding_receipt_immutable'); END",
    "program_funding_receipt_delete_immutable": "CREATE TRIGGER program_funding_receipt_delete_immutable BEFORE DELETE ON program_funding_receipts BEGIN SELECT RAISE(ABORT,'program_funding_receipt_immutable'); END",
    "population_manifest_update_immutable": "CREATE TRIGGER population_manifest_update_immutable BEFORE UPDATE ON population_manifests BEGIN SELECT RAISE(ABORT,'population_manifest_immutable'); END",
    "population_manifest_delete_immutable": "CREATE TRIGGER population_manifest_delete_immutable BEFORE DELETE ON population_manifests BEGIN SELECT RAISE(ABORT,'population_manifest_immutable'); END",
    "population_manifest_member_update_immutable": "CREATE TRIGGER population_manifest_member_update_immutable BEFORE UPDATE ON population_manifest_members BEGIN SELECT RAISE(ABORT,'population_manifest_member_immutable'); END",
    "population_manifest_member_delete_immutable": "CREATE TRIGGER population_manifest_member_delete_immutable BEFORE DELETE ON population_manifest_members BEGIN SELECT RAISE(ABORT,'population_manifest_member_immutable'); END",
    "population_manifest_binding_update_immutable": "CREATE TRIGGER population_manifest_binding_update_immutable BEFORE UPDATE ON population_manifest_bindings BEGIN SELECT RAISE(ABORT,'population_manifest_binding_immutable'); END",
    "population_manifest_binding_delete_immutable": "CREATE TRIGGER population_manifest_binding_delete_immutable BEFORE DELETE ON population_manifest_bindings BEGIN SELECT RAISE(ABORT,'population_manifest_binding_immutable'); END",
    "command_update_immutable": "CREATE TRIGGER command_update_immutable BEFORE UPDATE ON commands BEGIN SELECT RAISE(ABORT,'command_immutable'); END",
    "command_delete_immutable": "CREATE TRIGGER command_delete_immutable BEFORE DELETE ON commands BEGIN SELECT RAISE(ABORT,'command_immutable'); END",
    "history_segment_update_immutable": "CREATE TRIGGER history_segment_update_immutable BEFORE UPDATE ON history_segments BEGIN SELECT RAISE(ABORT,'history_segment_immutable'); END",
    "history_segment_delete_immutable": "CREATE TRIGGER history_segment_delete_immutable BEFORE DELETE ON history_segments BEGIN SELECT RAISE(ABORT,'history_segment_immutable'); END",
}

_EVENT_KINDS = {
    "CONTROL_PACK": {"CONTROL_PACK_PUBLISHED"},
    "POPULATION": {
        "POPULATION_IMPORT_OPENED",
        "POPULATION_STAGED",
        "POPULATION_SOURCE_COMPLETED",
        "POPULATION_VALIDATED",
        "POPULATION_PUBLISHED",
    },
    "POPULATION_MANIFEST": {"POPULATION_MANIFEST_REGISTERED", "POPULATION_MANIFEST_SUPERSEDED"},
    "PROGRAM_FUNDING_RECEIPT": {"FUNDING_RECEIPT_RECORDED", "FUNDING_RECEIPT_SUPERSEDED"},
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
_PAYMENT_EVIDENCE_KINDS = {"PAYMENT_CONFIRMATION"}
_WILDCARD_PERIODS = {"PROGRAM", "ALL"}
_CONTROL_PACK_ALLOWED_ROLES = {"FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"}
_CONTROL_PACK_REQUIRED_ROLES = {"FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER"}
_CONTROL_PACK_POLICIES = {
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
_CASE_STATUSES = {"OPEN", "AUTHORIZED", "CORRECTION_REQUIRED", "ACTIONED", "RESOLVED"}
_DELIVERY_STATUSES = {"NONE", "READY", "ACKNOWLEDGED", "CANCELLED"}
_EVALUATION_VERIFICATION = {"MISSING_EVIDENCE", "SUPPORTED", "CONFLICT_VISIBLE"}
_ACTION_KINDS = {"OFFSET_AUTHORIZATION", "CORRECTION_PAYMENT_REQUEST"}
_ACTION_STATUSES = {"READY", "ACKNOWLEDGED"}  # v2 never cancels an action
_CLAIM_STATUSES = {"CLAIMED", "AUTHORIZED", "REJECTED"}


def _canonical(value: object, code: str = "canonical") -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError, UnicodeError):
        _fail(f"{code}:canonical")


def _snapshot_decision_package_input(value: object) -> dict[str, object]:
    """Bound and detach caller input before opening the owner database."""

    if type(value) is not dict:
        _fail("decision-package:object")
    encoded_bytes = 0
    nodes = 0
    active_containers: set[int] = set()

    def add_size(size: int) -> None:
        nonlocal encoded_bytes
        encoded_bytes += size
        if encoded_bytes > MAX_DECISION_PACKAGE_BYTES:
            _fail("decision-package:input-limit")

    def add_json_string(text: str) -> None:
        if type(text) is not str:
            _fail("decision-package:input")
        size = 2
        for character in text:
            point = ord(character)
            if point in {0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x22, 0x5C}:
                size += 2
            elif point < 0x20:
                size += 6
            elif point <= 0x7E:
                size += 1
            elif point <= 0xFFFF:
                size += 6
            else:
                size += 12
            if encoded_bytes + size > MAX_DECISION_PACKAGE_BYTES:
                _fail("decision-package:input-limit")
        add_size(size)

    def clone(current: object, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_PACKAGE_NODES or depth > MAX_DECISION_PACKAGE_DEPTH:
            _fail("decision-package:input-limit")
        if current is None:
            add_size(4)
            return None
        if type(current) is bool:
            add_size(4 if current else 5)
            return current
        if type(current) is int:
            if current < -(1 << 63) or current > MAX_CENTS:
                _fail("decision-package:input-limit")
            add_size(len(str(current)))
            return current
        if type(current) is float:
            if not math.isfinite(current):
                _fail("decision-package:input")
            try:
                encoded = json.dumps(
                    current,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("ascii")
            except (TypeError, ValueError, UnicodeError):
                _fail("decision-package:input")
            add_size(len(encoded))
            return current
        if type(current) is str:
            add_json_string(current)
            return current
        if type(current) not in {dict, list, tuple}:
            _fail("decision-package:input")
        identity = id(current)
        if identity in active_containers:
            _fail("decision-package:input-limit")
        active_containers.add(identity)
        try:
            if type(current) is dict:
                result: dict[str, object] = {}
                add_size(1)
                item_count = 0
                try:
                    for key, child in current.items():
                        if type(key) is not str:
                            _fail("decision-package:input")
                        if item_count:
                            add_size(1)
                        item_count += 1
                        add_json_string(key)
                        add_size(1)
                        result[key] = clone(child, depth + 1)
                except IndependentFinancialError:
                    raise
                except RuntimeError:
                    _fail("decision-package:input")
                add_size(1)
                return result
            result_items: list[object] = []
            add_size(1)
            item_count = 0
            try:
                for child in current:
                    if item_count:
                        add_size(1)
                    item_count += 1
                    result_items.append(clone(child, depth + 1))
            except IndependentFinancialError:
                raise
            except RuntimeError:
                _fail("decision-package:input")
            add_size(1)
            return tuple(result_items) if type(current) is tuple else result_items
        finally:
            active_containers.remove(identity)

    snapshot = clone(value, 0)
    assert type(snapshot) is dict
    return snapshot


def _digest(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes:
        _fail("digest:domain")
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes:
            _fail("digest:part")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _group(rows: Iterable[sqlite3.Row], *columns: str) -> dict[object, list[sqlite3.Row]]:
    """Rows by their raw column values, in row order: a dict lookup equal to filtering every row with ==."""
    groups: dict[object, list[sqlite3.Row]] = {}
    for row in rows:
        groups.setdefault(tuple(row[column] for column in columns) if len(columns) > 1 else row[columns[0]], []).append(row)
    return groups


def _duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("json:duplicate-key")
        result[key] = value
    return result


def _parse_json(raw: object, code: str, *, max_bytes: int = MAX_JSON_BYTES) -> object:
    if type(raw) is not str:
        _fail(f"{code}:type")
    try:
        encoded = raw.encode("ascii")
    except UnicodeEncodeError:
        _fail(f"{code}:ascii")
    if not encoded or len(encoded) > max_bytes:
        _fail(f"{code}:bytes")
    try:
        value = json.loads(
            encoded.decode("ascii"),
            object_pairs_hook=_duplicate_pairs,
            parse_constant=lambda _value: _fail(f"{code}:constant"),
        )
    except IndependentFinancialError:
        raise
    except (RecursionError, TypeError, UnicodeDecodeError, ValueError):
        _fail(f"{code}:parse")
    if _canonical(value, code) != encoded:
        _fail(f"{code}:noncanonical")
    return value


def _check_json_shape(value: object, code: str) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_PACKAGE_NODES or depth > 32:
            _fail(f"{code}:bounds")
        if isinstance(current, dict):
            for key, child in current.items():
                if type(key) is not str:
                    _fail(f"{code}:key")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _id(value: object, code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(code)
    return value


def _role(value: object, code: str) -> str:
    if type(value) is not str or _ROLE.fullmatch(value) is None:
        _fail(code)
    return value


def _kind(value: object, code: str) -> str:
    if type(value) is not str or _KIND.fullmatch(value) is None:
        _fail(code)
    return value


def _text(value: object, code: str, *, max_bytes: int = 512) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(code)
    try:
        if len(value.encode("utf-8")) > max_bytes:
            _fail(code)
    except UnicodeEncodeError:
        _fail(code)
    return value


def _integer(value: object, code: str, *, minimum: int = 0, maximum: int = MAX_CENTS) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _fail(code)
    return value


def _cents(value: object, code: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    return _integer(value, code, minimum=minimum, maximum=MAX_CENTS)


def _add_cents(left: int, right: int, code: str = "projection:cents-overflow") -> int:
    if type(left) is not int or type(right) is not int:
        _fail(f"{code}:type")
    value = left + right
    if value < -MAX_CENTS or value > MAX_CENTS:
        _fail(code)
    return value


def _sum_cents(values: Any, code: str) -> int:
    total = 0
    for value in values:
        total = _add_cents(total, _cents(value, f"{code}:value"), f"{code}:overflow")
    return total


def _time(value: object, code: str) -> int:
    return _integer(value, code, minimum=0, maximum=(1 << 63) - 1)


def _flag(value: object, code: str) -> int:
    if type(value) is not int or value not in (0, 1):
        _fail(code)
    return value


def _blob64(value: object, code: str) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        _fail(code)
    return bytes(value)


def _event_header(before_revision: int, after_revision: int, committed_at_ms: int, code: str = "history:event-header") -> bytes:
    before = _integer(before_revision, f"{code}:before", maximum=MAX_CENTS)
    after = _integer(after_revision, f"{code}:after", maximum=MAX_CENTS)
    committed = _time(committed_at_ms, f"{code}:committed")
    return b"".join(value.to_bytes(8, "big") for value in (before, after, committed))


def _hex_digest(value: object, code: str) -> bytes:
    if type(value) is bytes:
        return _blob64(value, code)
    if type(value) is not str or _HEX128.fullmatch(value) is None:
        _fail(code)
    try:
        return bytes.fromhex(value)
    except ValueError:
        _fail(code)


def _identity_digest(
    *,
    provenance: str,
    bound_mode: str,
    bound_owner_id: str,
    anchor_sequence: int,
    source_package_digest: bytes,
) -> bytes:
    if provenance not in {"ROOT", "CONTINUITY_RESTORE"}:
        _fail("identity:provenance")
    if bound_mode not in {"LIVE", "SHADOW", "TEST"}:
        _fail("identity:mode")
    _id(bound_owner_id, "identity:owner")
    _integer(anchor_sequence, "identity:anchor-sequence", maximum=MAX_ROWS)
    source_digest = _blob64(source_package_digest, "identity:source-package-digest")
    return _digest(
        IDENTITY_DOMAIN,
        _canonical(
            {
                "anchor_sequence": anchor_sequence,
                "bound_mode": bound_mode,
                "bound_owner_id": bound_owner_id,
                "provenance": provenance,
                "source_package_digest": source_digest.hex().upper(),
            },
            "identity:digest-input",
        ),
    )


def _identity_record(
    value: Mapping[str, object],
    code_prefix: str = "identity",
    schema_version: int = SCHEMA_VERSION,
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(TABLE_COLUMNS["financial_identity"]):
        _fail(f"{code_prefix}:shape")
    if value["id"] != 1 or value["schema_version"] != schema_version:
        _fail(f"{code_prefix}:schema")
    provenance = value["provenance"]
    bound_mode = value["bound_mode"]
    bound_owner_id = _id(value["bound_owner_id"], f"{code_prefix}:owner")
    if provenance not in {"ROOT", "CONTINUITY_RESTORE"}:
        _fail(f"{code_prefix}:provenance")
    if bound_mode not in {"LIVE", "SHADOW", "TEST"}:
        _fail(f"{code_prefix}:mode")
    if provenance == "CONTINUITY_RESTORE":
        if bound_mode == "LIVE":
            _fail(f"{code_prefix}:restore-live")
        expected_owner_id = SHADOW_OWNER_ID if bound_mode == "SHADOW" else TEST_OWNER_ID
        if bound_owner_id != expected_owner_id:
            _fail(f"{code_prefix}:restore-owner")
    anchor_sequence = _integer(value["anchor_sequence"], f"{code_prefix}:anchor-sequence", maximum=MAX_ROWS)
    anchor_head = _blob64(value["anchor_head"], f"{code_prefix}:anchor-head")
    genesis_head = _blob64(value["genesis_head"], f"{code_prefix}:genesis-head")
    source_package_digest = _blob64(value["source_package_digest"], f"{code_prefix}:source-package-digest")
    identity_digest = _blob64(value["identity_digest"], f"{code_prefix}:digest")
    if identity_digest != _identity_digest(
        provenance=provenance,
        bound_mode=bound_mode,
        bound_owner_id=bound_owner_id,
        anchor_sequence=anchor_sequence,
        source_package_digest=source_package_digest,
    ):
        _fail(f"{code_prefix}:digest")
    return {
        "id": 1,
        "schema_version": schema_version,
        "provenance": provenance,
        "bound_mode": bound_mode,
        "bound_owner_id": bound_owner_id,
        "anchor_sequence": anchor_sequence,
        "anchor_head": anchor_head,
        "genesis_head": genesis_head,
        "source_package_digest": source_package_digest,
        "identity_digest": identity_digest,
    }


def _normal_sql(value: object) -> str:
    if type(value) is not str:
        _fail("schema:sql")
    return re.sub(r"\s+", " ", value.strip()).rstrip(";").lower()


def _verify_private_index_schema(connection: sqlite3.Connection) -> None:
    version_row = connection.execute("PRAGMA user_version").fetchone()
    version = version_row[0] if version_row is not None else None
    if type(version) is not int or version not in PRIVATE_INDEX_DEFS:
        _fail("schema:private-index-version")
    defs = PRIVATE_INDEX_DEFS[version]
    actual = {
        str(row[0]): row[1]
        for row in connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if set(actual) != set(defs):
        _fail("schema:private-indexes")
    for name, (table, columns) in defs.items():
        if _normal_sql(actual[name]) != _normal_sql(f"CREATE INDEX {name} ON {table}({','.join(columns)})"):
            _fail(f"schema:private-index:{name}")
        listed = [
            row
            for row in connection.execute(f'PRAGMA index_list("{table}")')
            if str(row[1]) == name
        ]
        if len(listed) != 1 or int(listed[0][2]) != 0 or str(listed[0][3]) != "c" or int(listed[0][4]) != 0:
            _fail(f"schema:private-index:{name}")
        key_parts = tuple(
            (str(row[2]), int(row[3]), str(row[4]).upper())
            for row in connection.execute(f'PRAGMA index_xinfo("{name}")')
            if int(row[5]) == 1
        )
        if key_parts != tuple((column, 0, "BINARY") for column in columns):
            _fail(f"schema:private-index:{name}")


def _field(value: object, name: str) -> object:
    if isinstance(value, Mapping):
        if name in value:
            return value[name]
        _fail(f"identity:missing-{name}")
    if hasattr(value, name):
        return getattr(value, name)
    _fail(f"identity:missing-{name}")


def _actor_roles(value: object) -> dict[str, frozenset[str]] | None:
    if isinstance(value, Mapping):
        actors = value.get("actors")
    else:
        actors = getattr(value, "actors", None)
    if actors is None:
        return None
    if type(actors) not in (tuple, list) or not actors:
        _fail("identity:actors")
    result: dict[str, frozenset[str]] = {}
    for actor in actors:
        actor_id = _id(_field(actor, "actor_id"), "identity:actor-id")
        roles_value = _field(actor, "roles")
        if type(roles_value) not in (tuple, list) or not roles_value:
            _fail("identity:actor-roles")
        roles = frozenset(_role(role, "identity:actor-role") for role in roles_value)
        if actor_id in result or len(roles) != len(roles_value):
            _fail("identity:actor-duplicate")
        result[actor_id] = roles
    return result


def _roster_authority_digest(authority_id: str, authority_epoch: int, value: object) -> bytes:
    """Recompute the synthetic authority digest from a supplied, already-parsed roster."""

    actors = value.get("actors") if isinstance(value, Mapping) else getattr(value, "actors", None)
    if type(actors) not in (tuple, list) or not actors:
        _fail("identity:actors")
    authority = {
        "authority_id": authority_id,
        "epoch": authority_epoch,
        "actors": [
            {"actor_id": _field(actor, "actor_id"), "roles": list(_field(actor, "roles"))}
            for actor in actors
        ],
        "synthetic_only": True,
    }
    return _digest(EVIDENCE_DOMAIN, _canonical(authority, "identity:authority-roster"))


def _identity(
    *,
    expected_config: object | None,
    expected_scope: object | None,
    expected_authority: object | None,
    expected_mode: str | None,
    expected_owner_id: str | None,
    expected_continuity_epoch: int | None,
) -> dict[str, object]:
    scope_source = expected_scope if expected_scope is not None else expected_config
    if scope_source is None:
        _fail("identity:scope-required")
    scope = {
        "state_id": _id(_field(scope_source, "state_id"), "identity:state-id"),
        "deployment_id": _id(_field(scope_source, "deployment_id"), "identity:deployment-id"),
        "program_id": _id(_field(scope_source, "program_id"), "identity:program-id"),
        "period_id": _id(_field(scope_source, "period_id"), "identity:period-id"),
        "currency": _field(scope_source, "currency"),
    }
    if scope["currency"] != CURRENCY:
        _fail("identity:currency")
    if scope["period_id"] in _WILDCARD_PERIODS:
        _fail("identity:period-scope")
    authority_source = expected_authority
    if authority_source is None and expected_config is not None:
        if isinstance(expected_config, Mapping):
            authority_source = expected_config if "authority_id" in expected_config else None
        elif hasattr(expected_config, "authority_id"):
            authority_source = expected_config
    # Every verification (database or continuity package) needs caller-supplied
    # trusted authority with its digest-bound roster. There is no built-in
    # default authority and no path that trusts the authority a package or
    # database names for itself (Articles V.2, XI.10).
    if authority_source is None:
        _fail("identity:authority-required")
    authority_id = _id(_field(authority_source, "authority_id"), "identity:authority-id")
    authority_epoch = _integer(_field(authority_source, "epoch"), "identity:authority-epoch", minimum=1, maximum=MAX_CENTS)
    authority_digest = _hex_digest(_field(authority_source, "digest"), "identity:authority-digest")
    actors = _actor_roles(authority_source)
    if actors is None:
        _fail("identity:authority-roster-required")
    if _roster_authority_digest(authority_id, authority_epoch, authority_source) != authority_digest:
        _fail("identity:authority-roster-digest")
    mode = expected_mode
    if mode is None and expected_config is not None and hasattr(expected_config, "mode"):
        mode = getattr(expected_config, "mode")
    if mode is not None and mode not in {"LIVE", "SHADOW", "TEST"}:
        _fail("identity:mode")
    owner_id = expected_owner_id
    if owner_id is None and expected_config is not None and hasattr(expected_config, "owner_id"):
        owner_id = getattr(expected_config, "owner_id")
    if owner_id is not None:
        owner_id = _id(owner_id, "identity:owner-id")
    epoch = expected_continuity_epoch
    if epoch is None and expected_config is not None and hasattr(expected_config, "continuity_epoch"):
        epoch = getattr(expected_config, "continuity_epoch")
    if epoch is not None:
        epoch = _integer(epoch, "identity:continuity-epoch", minimum=1, maximum=MAX_CENTS)
    schema_version = None
    if expected_config is not None:
        if isinstance(expected_config, Mapping) and "schema_version" in expected_config:
            schema_version = _integer(expected_config["schema_version"], "identity:schema-version", minimum=SCHEMA_VERSION, maximum=SCHEMA_VERSION)
        elif hasattr(expected_config, "schema_version"):
            schema_version = _integer(getattr(expected_config, "schema_version"), "identity:schema-version", minimum=SCHEMA_VERSION, maximum=SCHEMA_VERSION)
    return {
        "scope": scope,
        "authority_source": authority_source,
        "authority_id": authority_id,
        "authority_epoch": authority_epoch,
        "authority_digest": authority_digest,
        "actors": actors,
        "mode": mode,
        "owner_id": owner_id,
        "continuity_epoch": epoch,
        "schema_version": schema_version,
    }


def _open_readonly(path: str | Path) -> sqlite3.Connection:
    if not isinstance(path, (str, Path)):
        _fail("database:path")
    target = Path(path)
    try:
        if target.is_symlink() or not target.is_file():
            _fail("database:path")
        if target.stat().st_size <= 0:
            _fail("database:byte-cap")
        uri = "file:" + quote(target.resolve().as_posix(), safe="/:") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
    except IndependentFinancialError:
        raise
    except (OSError, sqlite3.Error, ValueError) as error:
        _fail("database:open", error)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
    except sqlite3.Error as error:
        connection.close()
        _fail("database:query-only", error)
    return connection


def _verify_schema(connection: sqlite3.Connection) -> int:
    try:
        meta = connection.execute("SELECT schema_version,schema FROM financial_meta WHERE id=1").fetchone()
        if meta is None or type(meta["schema_version"]) is not int:
            _fail("schema:version")
        schema_version = int(meta["schema_version"])
        if schema_version != SCHEMA_VERSION or meta["schema"] != SCHEMA:
            _fail("schema:version")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != TABLES | set(_HISTORY_TABLE_DEFS):
            _fail("schema:tables")
        for table, definition in {**_TABLE_DEFS, **_HISTORY_TABLE_DEFS}.items():
            actual = tuple(
                (str(row[1]), str(row[2]).upper(), int(row[5]))
                for row in connection.execute(f"PRAGMA table_info({table})")
            )
            if actual != tuple(definition):
                _fail(f"schema:columns:{table}")
        triggers = {
            str(row[0]): str(row[1])
            for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")
        }
        if set(triggers) != set(_TRIGGER_DEFS):
            _fail("schema:triggers")
        for name, expected in _TRIGGER_DEFS.items():
            if _normal_sql(triggers[name]) != _normal_sql(expected):
                _fail(f"schema:trigger:{name}")
        for table in sorted(TABLES):
            sql = _normal_sql(connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0])
            references = sql.count("references ")  # every one deferred: PRAGMA foreign_key_list cannot show it
            deferred = references == len(re.findall(r"references \w+ ?\([^)]*\) deferrable initially deferred", sql))
            declared: dict[int, list[sqlite3.Row]] = {}
            for row in connection.execute(f"PRAGMA foreign_key_list({table})"):
                if (str(row[5]).upper(), str(row[6]).upper(), str(row[7]).upper()) != ("NO ACTION", "NO ACTION", "NONE"):
                    _fail(f"schema:foreign-keys:{table}")
                declared.setdefault(int(row[0]), []).append(row)
            actual_keys = {
                (
                    tuple(str(row[3]) for row in sorted(rows, key=lambda row: int(row[1]))),
                    str(rows[0][2]),
                    tuple(str(row[4]) for row in sorted(rows, key=lambda row: int(row[1]))),
                )
                for rows in declared.values()
            }
            if not deferred or len(actual_keys) != len(declared) or references != len(declared) or actual_keys != _FOREIGN_KEY_DEFS.get(table, frozenset()):
                _fail(f"schema:foreign-keys:{table}")
        _verify_private_index_schema(connection)
        return schema_version
    except IndependentFinancialError:
        raise
    except sqlite3.Error as error:
        _fail("schema:read", error)


def _bounded_rows(connection: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    try:
        if int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) > MAX_ROWS:
            _fail(f"rows:cap:{table}")
        return list(connection.execute(f"SELECT * FROM {table}"))
    except IndependentFinancialError:
        raise
    except sqlite3.Error as error:
        _fail(f"rows:read:{table}", error)


def _verify_meta(connection: sqlite3.Connection, identity: dict[str, object], schema_version: int) -> dict[str, object]:
    try:
        if int(connection.execute("SELECT COUNT(*) FROM financial_meta").fetchone()[0]) != 1:
            _fail("meta:cardinality")
        row = connection.execute("SELECT * FROM financial_meta WHERE id=1").fetchone()
    except (sqlite3.Error, TypeError, ValueError) as error:
        _fail("meta:read", error)
    if row is None:
        _fail("meta:missing")
    if row["id"] != 1 or row["schema_version"] != SCHEMA_VERSION or row["schema"] != SCHEMA:
        _fail("meta:schema")
    if identity["schema_version"] is not None and identity["schema_version"] != schema_version:
        _fail("meta:schema-version-binding")
    scope = identity["scope"]
    assert isinstance(scope, dict)
    for key in ("state_id", "deployment_id", "program_id", "period_id", "currency"):
        _text(row[key], f"meta:{key}")
        if row[key] != scope[key]:
            _fail(f"meta:scope:{key}")
    sequence = _integer(row["sequence"], "meta:sequence", maximum=MAX_ROWS)
    history_head = _blob64(row["history_head"], "meta:history-head")
    continuity_epoch = _integer(row["continuity_epoch"], "meta:continuity-epoch", minimum=1, maximum=1)  # no writer advances it
    if _flag(row["dispatch_enabled"], "meta:dispatch") != 0 or _flag(row["egress_enabled"], "meta:egress") != 0:
        _fail("meta:nonactivating")
    mode = row["mode"]
    if mode not in {"LIVE", "SHADOW", "TEST"}:
        _fail("meta:mode")
    if identity["mode"] is not None and mode != identity["mode"]:
        _fail("meta:mode-binding")
    owner_id = _id(row["owner_id"], "meta:owner-id")
    if identity["owner_id"] is not None and owner_id != identity["owner_id"]:
        _fail("meta:owner-binding")
    authority_id = _id(row["trusted_authority_id"], "meta:authority-id")
    authority_epoch = _integer(row["trusted_authority_epoch"], "meta:authority-epoch", minimum=1, maximum=MAX_CENTS)
    authority_digest = _blob64(row["trusted_authority_digest"], "meta:authority-digest")
    if (authority_id, authority_epoch, authority_digest) != (
        identity["authority_id"],
        identity["authority_epoch"],
        identity["authority_digest"],
    ):
        _fail("meta:authority-binding")
    if identity["continuity_epoch"] is not None and continuity_epoch != identity["continuity_epoch"]:
        _fail("meta:continuity-epoch")
    try:
        if int(connection.execute("SELECT COUNT(*) FROM financial_identity").fetchone()[0]) != 1:
            _fail("identity:cardinality")
        identity_row = connection.execute("SELECT * FROM financial_identity WHERE id=1").fetchone()
    except (sqlite3.Error, TypeError, ValueError) as error:
        _fail("identity:read", error)
    if identity_row is None:
        _fail("identity:missing")
    identity_contract = _identity_record(
        {column: identity_row[column] for column in TABLE_COLUMNS["financial_identity"]},
    )
    if identity_contract["bound_mode"] != mode or identity_contract["bound_owner_id"] != owner_id:
        _fail("identity:meta-binding")
    scope_bytes = _canonical(scope, "meta:scope")
    if identity_contract["provenance"] == "ROOT":
        expected_genesis = _digest(GENESIS_DOMAIN, scope_bytes, authority_digest, identity_contract["identity_digest"])
        if identity_contract["source_package_digest"] != ZERO_DIGEST or identity_contract["anchor_sequence"] != 0 or identity_contract["anchor_head"] != expected_genesis or identity_contract["genesis_head"] != expected_genesis:
            _fail("identity:genesis")
    else:
        if identity_contract["source_package_digest"] == ZERO_DIGEST or identity_contract["anchor_sequence"] > sequence:
            _fail("identity:anchor")
        if identity_contract["anchor_sequence"] == 0 and identity_contract["anchor_head"] != identity_contract["genesis_head"]:
            _fail("identity:anchor")
    genesis = identity_contract["genesis_head"]
    if sequence == 0 and history_head != genesis:
        _fail("identity:history-head")
    return {
        "row": row,
        "sequence": sequence,
        "history_head": history_head,
        "genesis": genesis,
        "identity": identity_contract,
        "continuity_epoch": continuity_epoch,
        "mode": mode,
        "owner_id": owner_id,
        "authority_id": authority_id,
        "authority_epoch": authority_epoch,
        "authority_digest": authority_digest,
        "scope": scope,
        "schema_version": schema_version,
    }


def _verify_event(row: Mapping[str, object], index: int, previous: bytes) -> bytes:
    """Recompute one event's id and head from its predecessor's head; return the head."""
    if row["event_sequence"] != index:
        _fail("history:sequence")
    event_id = _blob64(row["event_id"], "history:event-id")
    aggregate_type = _kind(row["aggregate_type"], "history:aggregate-type")
    aggregate_id = _id(row["aggregate_id"], "history:aggregate-id")
    kind = _kind(row["kind"], "history:event-kind")
    if aggregate_type not in _EVENT_KINDS or kind not in _EVENT_KINDS[aggregate_type]:
        _fail("history:event-kind")
    before = _integer(row["before_revision"], "history:before-revision")
    after = _integer(row["after_revision"], "history:after-revision")
    if after < before:
        _fail("history:revision-order")
    payload_raw = row["payload_json"]
    payload = _parse_json(payload_raw, "history:payload", max_bytes=MAX_PACKAGE_BYTES)  # rows can outgrow 1 MiB; the package cap bounds them
    if not isinstance(payload, dict):
        _fail("history:payload-object")
    payload_bytes = _canonical(payload, "history:payload")
    payload_digest = _blob64(row["payload_digest"], "history:payload-digest")
    expected_payload_digest = _digest(EVENT_DOMAIN, payload_bytes)
    if payload_digest != expected_payload_digest:
        _fail("history:payload-digest")
    committed_at_ms = _time(row["committed_at_ms"], "history:committed-at")
    header = _event_header(before, after, committed_at_ms)
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
        _fail("history:event-id")
    previous_head = _blob64(row["previous_head"], "history:previous-head")
    head = _blob64(row["head"], "history:head")
    if previous_head != previous:
        _fail("history:predecessor")
    expected_head = _digest(HEAD_DOMAIN, previous_head, event_id, header, payload_digest)
    if head != expected_head:
        _fail("history:head")
    return head


def _verify_events(connection: sqlite3.Connection, meta: dict[str, object]) -> list[sqlite3.Row]:
    rows = list(connection.execute("SELECT * FROM financial_events ORDER BY event_sequence"))
    if len(rows) > MAX_ROWS:
        _fail("history:row-cap")
    expected_sequence = int(meta["sequence"])
    if len(rows) != expected_sequence:
        _fail("history:sequence-count")
    previous = meta["genesis"]
    assert isinstance(previous, bytes)
    for index, row in enumerate(rows, start=1):
        previous = _verify_event(row, index, previous)
    if previous != meta["history_head"]:
        _fail("history:meta-head")
    identity = meta["identity"]
    assert isinstance(identity, dict)
    anchor_sequence = int(identity["anchor_sequence"])
    if anchor_sequence > 0:
        if anchor_sequence > len(rows) or bytes(rows[anchor_sequence - 1]["head"]) != identity["anchor_head"]:
            _fail("identity:history-anchor")
    return rows


def _verify_history_tables(connection: sqlite3.Connection, events: list[sqlite3.Row]) -> None:
    """Recompute every sealed segment's seal and chain from the event rows, then the open segment's tracking."""
    previous, sealed = ZERO_DIGEST, 0
    for index, row in enumerate(connection.execute("SELECT * FROM history_segments ORDER BY segment_index")):
        code, first = f"history-segments:{index}", sealed + 1
        sealed = _integer(row["last_sequence"], f"{code}:last", minimum=first, maximum=min(len(events), sealed + MAX_ROWS))
        if row["segment_index"] != index or row["first_sequence"] != first or len(row["rows_json"]) > MAX_SEGMENT_BYTES:
            _fail(f"{code}:shape")
        stored = {"previous_digest": previous, "event_head": bytes(events[sealed - 1]["head"]), "projection_root": _digest(SEGMENT_DOMAIN, b"rows", row["rows_json"].encode())}
        if any(row[key] != value for key, value in stored.items()):
            _fail(f"{code}:seal")
        previous = _digest(SEGMENT_DOMAIN, b"seal", _canonical({"format": SEGMENT_FORMAT, "segment_index": index, "first_sequence": first, "last_sequence": sealed, "event_count": sealed - first + 1, **{key: value.hex().upper() for key, value in stored.items()}}))
        if row["segment_digest"] != previous:
            _fail(f"{code}:digest")
    touched = set()  # every captured-table write since the last seal is carried in an open event's rows
    for event in events[sealed:]:
        for image in _parse_json(event["payload_json"], "replay:payload", max_bytes=MAX_PACKAGE_BYTES).get("rows") or ():
            touched.add((image["table"], image["row"][TABLE_COLUMNS[image["table"]][0]] if "row" in image else image["key"]))
    pending = connection.execute("SELECT table_name,row_key,record_bytes FROM history_pending").fetchall()
    for table, key, size in pending:  # each record size is recomputed from its row, never trusted
        row = connection.execute(f'SELECT * FROM "{table}" WHERE rowid=?', (key,)).fetchone() if table in PROJECTION_TABLES | {"financial_events"} and type(key) is int else None
        if row is None or size != _record_bytes(table, row):
            _fail("history-pending:row")
        if table in CAPTURED_TABLES:
            touched.symmetric_difference_update({(table, row[TABLE_COLUMNS[table][0]])})
    count, size = len(events) - sealed, sum(row[2] for row in pending)
    if touched or [tuple(row) for row in connection.execute("SELECT id,event_count,byte_count FROM history_open")] != [(1, count, size)] or count >= SEAL_SEGMENT_EVENTS or size >= SEAL_SEGMENT_BYTES or sorted(key for table, key, _ in pending if table == "financial_events") != list(range(sealed + 1, len(events) + 1)):
        _fail("history-open:counts")


def _record_bytes(table: str, row: sqlite3.Row) -> int:
    """The Owner's record size: the canonical export of an event, or of a table's row with its name, plus a separator."""
    record = {column: {"hex": row[column].hex().upper()} if type(row[column]) is bytes else row[column] for column in TABLE_COLUMNS[table]}
    return len(_canonical(record if table == "financial_events" else {"table": table, "row": record})) + 1


def _verify_replayed_rows(connection: sqlite3.Connection, events: list[sqlite3.Row]) -> None:
    """Replay every event's ``rows`` and require the result exactly."""

    state: dict[str, dict[str, dict[str, object]]] = {table: {} for table in CAPTURED_TABLES}
    acknowledged: dict[object, object] = {}  # every history names the accepted reference
    for event in events:
        payload = _parse_json(event["payload_json"], "replay:payload", max_bytes=MAX_PACKAGE_BYTES)
        images = payload.get("rows")
        if event["kind"] == "ACTION_ACKNOWLEDGED":
            acknowledged[payload.get("action_id")] = payload.get("acknowledgment_ref")
        if images is None:
            continue
        if not isinstance(images, list) or not images:
            _fail("replay:rows")
        for image in images:
            table = image.get("table") if isinstance(image, dict) else None
            if table not in state:
                _fail("replay:image")
            columns = TABLE_COLUMNS[table]
            rows = state[table]
            row, key, changes = image.get("row"), image.get("key"), image.get("set")
            if set(image) == {"table", "row"} and isinstance(row, dict) and set(row) == set(columns) and type(row[columns[0]]) is str and row[columns[0]] not in rows:
                rows[row[columns[0]]] = {column: _package_import_value(row[column], f"replay:{table}") for column in columns}
            elif set(image) == {"table", "key", "set"} and type(key) is str and key in rows and isinstance(changes, dict) and changes and set(changes) <= set(columns[1:]):
                rows[key].update({column: _package_import_value(value, f"replay:{table}") for column, value in changes.items()})
            else:
                _fail(f"replay:image:{table}")
    for table in CAPTURED_TABLES:
        if {str(row[0]): dict(row) for row in _bounded_rows(connection, table)} != state[table]:
            _fail(f"replay:{table}")
    if {row["action_id"]: row["acknowledgment_ref"] for row in _bounded_rows(connection, "action_outbox") if row["acknowledgment_ref"] is not None} != acknowledged:
        _fail("replay:acknowledgment")


def _verify_correction_followup_records(
    events: Iterable[Mapping[str, object]],
    *,
    evaluations: Mapping[str, Mapping[str, object]],
    determinations: Mapping[str, Mapping[str, object]],
    actions: Mapping[str, Mapping[str, object]],
    cases: Mapping[str, Mapping[str, object]],
    packs: Mapping[str, Mapping[str, object]],
) -> None:
    """Independently bind durable correction work to its committed source rows."""

    seen_work_ids: set[str] = set()
    for event_value in events:
        event = dict(event_value)
        if (
            event.get("aggregate_type") != "OBLIGATION"
            or event.get("kind") != "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
        ):
            continue
        payload = _parse_json(event.get("payload_json"), "history:correction-followup-payload")
        if not isinstance(payload, dict):
            _fail("history:correction-followup-payload")
        if "correction_followup" not in payload:
            continue
        followup = payload["correction_followup"]
        if not isinstance(followup, dict) or set(followup) != {
            "contract", "work_id", "determination_id", "source", "artifact", "control_pack", "authority",
            "input_evaluation", "result_evaluation", "determination_digest", "case_status",
            "action_status", "outbox_status", "supporting_evidence",
            "dependency_families", "read_observations", "outputs",
        }:
            _fail("history:correction-followup-shape")
        if followup["contract"] != CORRECTION_FOLLOWUP_CONTRACT:
            _fail("history:correction-followup-contract")
        work_id = _id(followup["work_id"], "history:correction-followup-work-id")
        if work_id in seen_work_ids:
            _fail("history:correction-followup-duplicate")
        seen_work_ids.add(work_id)
        action_id = _id(payload.get("action_id"), "history:correction-followup-action-id")
        determination_id = _id(payload.get("determination_id"), "history:correction-followup-determination-id")
        result_evaluation_id = _id(payload.get("evaluation_id"), "history:correction-followup-result-evaluation")
        event_sequence = _integer(event.get("event_sequence"), "history:correction-followup-sequence", minimum=1, maximum=MAX_ROWS)
        aggregate_id = _id(event.get("aggregate_id"), "history:correction-followup-obligation")
        if work_id != action_id or followup.get("determination_id") != determination_id:
            _fail("history:correction-followup-work-binding")
        source = followup["source"]
        if not isinstance(source, dict) or set(source) != {
            "action_id", "outbox_action_id", "case_id", "resulting_evaluation_id", "event_sequence",
        }:
            _fail("history:correction-followup-source")
        case_id = _id(source["case_id"], "history:correction-followup-case-id")
        if source != {
            "action_id": action_id,
            "outbox_action_id": action_id,
            "case_id": case_id,
            "resulting_evaluation_id": result_evaluation_id,
            "event_sequence": event_sequence,
        }:
            _fail("history:correction-followup-source-binding")
        if (
            _integer(event.get("after_revision"), "history:correction-followup-revision", maximum=MAX_ROWS)
            != _integer(followup.get("result_evaluation", {}).get("revision") if isinstance(followup.get("result_evaluation"), dict) else None, "history:correction-followup-result-revision", maximum=MAX_ROWS)
        ):
            _fail("history:correction-followup-revision-binding")

        artifact = followup["artifact"]
        if not isinstance(artifact, dict) or set(artifact) != {"contract", "version", "sha256"}:
            _fail("history:correction-followup-artifact")
        if (
            artifact["contract"] != CORRECTION_TRANSITION_OPERATION
            or _integer(artifact["version"], "history:correction-followup-artifact-version", minimum=1, maximum=MAX_ROWS) != 1
            or str(artifact["sha256"]) not in correction_engines()
        ):
            _fail("history:correction-followup-artifact-binding")

        control_pack = followup["control_pack"]
        if not isinstance(control_pack, dict) or set(control_pack) != {"pack_id", "version", "digest"}:
            _fail("history:correction-followup-control-pack")
        pack_id = _id(control_pack["pack_id"], "history:correction-followup-pack-id")
        pack = packs.get(pack_id)
        if pack is None or (
            _integer(control_pack["version"], "history:correction-followup-pack-version", minimum=1, maximum=MAX_ROWS)
            != _integer(pack.get("version"), "history:correction-followup-stored-pack-version", minimum=1, maximum=MAX_ROWS)
            or _hex_digest(control_pack["digest"], "history:correction-followup-pack-digest")
            != _blob64(pack.get("pack_digest"), "history:correction-followup-stored-pack-digest")
        ):
            _fail("history:correction-followup-pack-binding")

        result_evaluation = followup["result_evaluation"]
        if not isinstance(result_evaluation, dict) or set(result_evaluation) != {
            "evaluation_id", "revision", "result_digest", "receipt_digest",
        }:
            _fail("history:correction-followup-result-evaluation")
        result_row = evaluations.get(result_evaluation_id)
        if result_row is None:
            _fail("history:correction-followup-result-missing")
        if (
            result_evaluation["evaluation_id"] != result_evaluation_id
            or _integer(result_evaluation["revision"], "history:correction-followup-result-revision", maximum=MAX_ROWS)
            != _integer(result_row.get("revision"), "history:correction-followup-stored-result-revision", maximum=MAX_ROWS)
            or _hex_digest(result_evaluation["result_digest"], "history:correction-followup-result-digest")
            != _blob64(result_row.get("result_digest"), "history:correction-followup-stored-result-digest")
            or _hex_digest(result_evaluation["receipt_digest"], "history:correction-followup-receipt-digest")
            != _blob64(result_row.get("receipt_digest"), "history:correction-followup-stored-receipt-digest")
            or result_row.get("obligation_id") != aggregate_id
            or result_row.get("control_pack_id") != pack_id
            or _integer(result_row.get("control_pack_version"), "history:correction-followup-eval-pack-version", minimum=1, maximum=MAX_ROWS)
            != control_pack["version"]
            or _blob64(result_row.get("control_pack_digest"), "history:correction-followup-eval-pack-digest")
            != _hex_digest(control_pack["digest"], "history:correction-followup-pack-digest")
        ):
            _fail("history:correction-followup-result-binding")
        if (
            payload.get("evaluation_input_digest") != bytes(result_row["input_snapshot_digest"]).hex().upper()
            or payload.get("evaluation_result_digest") != bytes(result_row["result_digest"]).hex().upper()
            or payload.get("evaluation_receipt_digest") != bytes(result_row["receipt_digest"]).hex().upper()
        ):
            _fail("history:correction-followup-event-evaluation")

        authority = followup["authority"]
        if not isinstance(authority, dict) or set(authority) != {"authority_id", "epoch", "digest"}:
            _fail("history:correction-followup-authority")
        if (
            authority["authority_id"] != result_row.get("authority_id")
            or _integer(authority["epoch"], "history:correction-followup-authority-epoch", minimum=1, maximum=MAX_CENTS)
            != _integer(result_row.get("authority_epoch"), "history:correction-followup-stored-authority-epoch", minimum=1, maximum=MAX_CENTS)
            or _hex_digest(authority["digest"], "history:correction-followup-authority-digest")
            != _blob64(result_row.get("authority_digest"), "history:correction-followup-stored-authority-digest")
        ):
            _fail("history:correction-followup-authority-binding")

        input_evaluation = followup["input_evaluation"]
        if not isinstance(input_evaluation, dict) or set(input_evaluation) != {
            "evaluation_id", "revision", "result_digest", "receipt_digest",
        }:
            _fail("history:correction-followup-input-evaluation")
        input_evaluation_id = _id(input_evaluation["evaluation_id"], "history:correction-followup-input-id")
        input_row = evaluations.get(input_evaluation_id)
        determination = determinations.get(determination_id)
        action = actions.get(action_id)
        case = cases.get(case_id)
        if input_row is None or determination is None or action is None or case is None:
            _fail("history:correction-followup-result-rows")
        if (
            _integer(input_evaluation["revision"], "history:correction-followup-input-revision", maximum=MAX_ROWS)
            != _integer(input_row.get("revision"), "history:correction-followup-stored-input-revision", maximum=MAX_ROWS)
            or _hex_digest(input_evaluation["result_digest"], "history:correction-followup-input-digest")
            != _blob64(input_row.get("result_digest"), "history:correction-followup-stored-input-digest")
            or _hex_digest(input_evaluation["receipt_digest"], "history:correction-followup-input-receipt")
            != _blob64(input_row.get("receipt_digest"), "history:correction-followup-stored-input-receipt")
            or determination.get("obligation_id") != aggregate_id
            or determination.get("decision") != "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
            or determination.get("input_evaluation_id") != input_evaluation_id
            or _blob64(determination.get("input_evaluation_result_digest"), "history:correction-followup-determination-eval-digest")
            != _hex_digest(input_evaluation["result_digest"], "history:correction-followup-input-digest")
            or action.get("obligation_id") != aggregate_id
            or action.get("determination_id") != determination_id
            or action.get("kind") != "CORRECTION_PAYMENT_REQUEST"
            or _hex_digest(followup.get("determination_digest"), "history:correction-followup-determination-digest")
            != _blob64(determination.get("determination_digest"), "history:correction-followup-stored-determination-digest")
            or followup.get("case_status") != result_row.get("case_status")
            or followup.get("action_status") != "READY"
            or followup.get("outbox_status") != "READY"
            or case.get("obligation_id") != aggregate_id
        ):
            _fail("history:correction-followup-input-binding")
        try:
            evidence_value = json.loads(str(result_row["evidence_bindings_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            _fail("history:correction-followup-evidence")
        if not isinstance(evidence_value, dict) or set(evidence_value) != {"bindings"} or followup["supporting_evidence"] != evidence_value["bindings"]:
            _fail("history:correction-followup-evidence-binding")

        if followup["dependency_families"] != CORRECTION_FOLLOWUP_DEPENDENCIES:
            _fail("history:correction-followup-dependencies")
        if followup["outputs"] != ["MIRROR_EXPLANATION", "STATE_REPORT", "CORPORATE_SUPPORT"]:
            _fail("history:correction-followup-outputs")
        observations = followup["read_observations"]
        if not isinstance(observations, dict) or set(observations) != set(CORRECTION_FOLLOWUP_READ_OBSERVATIONS):
            _fail("history:correction-followup-observations")
        previous_head = _blob64(event.get("previous_head"), "history:correction-followup-previous-head").hex().upper()
        for key, (predicate, subject_key) in CORRECTION_FOLLOWUP_READ_OBSERVATIONS.items():
            observation = observations[key]
            if not isinstance(observation, dict) or set(observation) != {
                "predicate", "subject", "complete", "match_count", "result_identity",
                "version_sequence", "version_head",
            }:
                _fail("history:correction-followup-observation-shape")
            expected_subject = input_evaluation_id if subject_key == "input_evaluation_id" else action_id if subject_key == "action_id" else determination_id
            if (
                observation["predicate"] != predicate
                or observation["subject"] != expected_subject
                or observation["complete"] is not True
                or observation["match_count"] != 0
                or observation["result_identity"] is not None
                or observation["version_sequence"] != event_sequence - 1
                or observation["version_head"] != previous_head
            ):
                _fail("history:correction-followup-observation-binding")


def _verify_program_funding_rows(
    receipt_rows: list[Mapping[str, object]],
    projection_rows: list[Mapping[str, object]],
    events: list[Mapping[str, object]],
    scope: Mapping[str, object],
) -> tuple[dict[str, object], set[str]]:
    """Reconstruct funding leaves, projection, and bound history events."""

    receipts: dict[str, dict[str, object]] = {}
    grouped: dict[str, list[str]] = {}
    for index, row in enumerate(receipt_rows):
        receipt_id = _id(row["receipt_id"], f"funding:receipt:{index}:id")
        if receipt_id in receipts:
            _fail("funding:receipt-duplicate")
        row_scope = {
            key: _text(row[key], f"funding:receipt:{index}:{key}")
            for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")
        }
        if row_scope != dict(scope):
            _fail("funding:scope")
        if row_scope["currency"] != CURRENCY or row_scope["period_id"] in _WILDCARD_PERIODS:
            _fail("funding:scope")
        source_ref = _id(row["source_record_ref"], f"funding:receipt:{index}:source-ref")
        amount = _integer(row["amount_cents"], f"funding:receipt:{index}:amount", minimum=1, maximum=MAX_CENTS)
        confirmation_class = _text(row["confirmation_class"], f"funding:receipt:{index}:class")
        evidence_status = _text(row["evidence_status"], f"funding:receipt:{index}:status")
        if confirmation_class != PROGRAM_FUNDING_CONFIRMATION_CLASS or evidence_status != PROGRAM_FUNDING_EVIDENCE_STATUS:
            _fail("funding:unapproved-source-class")
        event_at_ms = _time(row["event_at_ms"], f"funding:receipt:{index}:event-time")
        recorded_at_ms = _time(row["recorded_at_ms"], f"funding:receipt:{index}:recorded-time")
        supersedes = row["supersedes_receipt_id"]
        if supersedes is not None:
            supersedes = _id(supersedes, f"funding:receipt:{index}:supersedes")
        record = {
            "schema": PROGRAM_FUNDING_RECEIPT_SCHEMA,
            "receipt_id": receipt_id,
            "state_id": row_scope["state_id"],
            "deployment_id": row_scope["deployment_id"],
            "program_id": row_scope["program_id"],
            "period_id": row_scope["period_id"],
            "currency": row_scope["currency"],
            "source_record_ref": source_ref,
            "amount_cents": amount,
            "confirmation_class": confirmation_class,
            "evidence_status": evidence_status,
            "event_at_ms": event_at_ms,
            "supersedes_receipt_id": supersedes,
        }
        expected_digest = _digest(
            PROGRAM_FUNDING_RECEIPT_DOMAIN,
            _canonical(record, f"funding:receipt:{index}:canonical"),
        )
        digest = _blob64(row["receipt_digest"], f"funding:receipt:{index}:digest")
        if digest != expected_digest:
            _fail("funding:receipt-digest")
        receipts[receipt_id] = {
            **record,
            "recorded_at_ms": recorded_at_ms,
            "receipt_digest": digest,
        }
        grouped.setdefault(source_ref, []).append(receipt_id)

    children: dict[str, str] = {}
    for receipt_id, receipt in receipts.items():
        parent_id = receipt["supersedes_receipt_id"]
        if parent_id is None:
            continue
        parent = receipts.get(str(parent_id))
        if parent is None:
            _fail("funding:supersession-missing")
        if parent["source_record_ref"] != receipt["source_record_ref"]:
            _fail("funding:supersession-scope")
        if int(receipt["recorded_at_ms"]) < int(parent["recorded_at_ms"]):
            _fail("funding:supersession-chronology")
        if str(parent_id) in children:
            _fail("funding:supersession-fork")
        children[str(parent_id)] = receipt_id

    events_by_id: dict[str, Mapping[str, object]] = {}
    funding_event_count = 0
    for event in events:
        if event["aggregate_type"] != "PROGRAM_FUNDING_RECEIPT":
            continue
        funding_event_count += 1
        receipt_id = _id(event["aggregate_id"], "funding:event:aggregate-id")
        if receipt_id in events_by_id:
            _fail("funding:event-duplicate")
        events_by_id[receipt_id] = event
    if funding_event_count != len(receipts) or set(events_by_id) != set(receipts):
        _fail("funding:event-count")

    projection_by_ref: dict[str, Mapping[str, object]] = {}
    for index, row in enumerate(projection_rows):
        source_ref = _id(row["source_record_ref"], f"funding:projection:{index}:source-ref")
        if source_ref in projection_by_ref:
            _fail("funding:projection-duplicate")
        projection_by_ref[source_ref] = row
    if set(projection_by_ref) != set(grouped):
        _fail("funding:projection-cardinality")

    leaves: list[tuple[str, dict[str, object], int]] = []
    visited: set[str] = set()
    for source_ref, ids in grouped.items():
        roots = [receipt_id for receipt_id in ids if receipts[receipt_id]["supersedes_receipt_id"] is None]
        if len(roots) != 1:
            _fail("funding:lineage-root")
        receipt_id = roots[0]
        revision = 0
        prior_sequence = 0
        lineage_seen: set[str] = set()
        while True:
            if receipt_id in lineage_seen:
                _fail("funding:lineage-cycle")
            lineage_seen.add(receipt_id)
            visited.add(receipt_id)
            revision += 1
            receipt = receipts[receipt_id]
            event = events_by_id[receipt_id]
            kind = "FUNDING_RECEIPT_SUPERSEDED" if receipt["supersedes_receipt_id"] is not None else "FUNDING_RECEIPT_RECORDED"
            if (
                event["aggregate_type"] != "PROGRAM_FUNDING_RECEIPT"
                or event["aggregate_id"] != receipt_id
                or event["kind"] != kind
                or _integer(event["before_revision"], "funding:event:before") != revision - 1
                or _integer(event["after_revision"], "funding:event:after") != revision
                or _time(event["committed_at_ms"], "funding:event:committed") != receipt["recorded_at_ms"]
            ):
                _fail("funding:event-binding")
            sequence = _integer(event["event_sequence"], "funding:event:sequence", minimum=1, maximum=MAX_ROWS)
            if sequence <= prior_sequence:
                _fail("funding:event-order")
            prior_sequence = sequence
            payload = _parse_json(event["payload_json"], "funding:event:payload")
            expected_payload = {
                key: value
                for key, value in receipt.items()
                if key not in {"receipt_digest"}
            }
            expected_payload["receipt_digest"] = bytes(receipt["receipt_digest"]).hex().upper()
            expected_payload["projection_revision"] = revision
            if payload != expected_payload:
                _fail("funding:event-payload")
            child_id = children.get(receipt_id)
            if child_id is None:
                leaves.append((source_ref, receipt, revision))
                break
            child_event = events_by_id.get(child_id)
            if child_event is None or int(child_event["event_sequence"]) <= sequence:
                _fail("funding:supersession-event-order")
            receipt_id = child_id
        if len(lineage_seen) != len(ids):
            _fail("funding:lineage-disconnected")
    if visited != set(receipts):
        _fail("funding:lineage-unreachable")

    total = 0
    for source_ref, receipt, revision in leaves:
        projection = projection_by_ref[source_ref]
        if (
            projection["receipt_id"] != receipt["receipt_id"]
            or _integer(projection["amount_cents"], "funding:projection:amount", minimum=1, maximum=MAX_CENTS) != receipt["amount_cents"]
            or _time(projection["event_at_ms"], "funding:projection:event-time") != receipt["event_at_ms"]
            or _integer(projection["revision"], "funding:projection:revision", minimum=1, maximum=MAX_ROWS) != revision
            or _blob64(projection["receipt_digest"], "funding:projection:digest") != receipt["receipt_digest"]
        ):
            _fail("funding:projection-reconstruction")
        total = _add_cents(total, int(receipt["amount_cents"]), "funding:total-overflow")
    return (
        {
            "schema": PROGRAM_FUNDING_RECEIPT_SCHEMA,
            "scope": dict(scope),
            "reported_funding_cents": total,
            "current_receipt_count": len(leaves),
            "historical_receipt_count": len(receipts),
            "confirmation_class": PROGRAM_FUNDING_CONFIRMATION_CLASS,
            "evidence_status": PROGRAM_FUNDING_EVIDENCE_STATUS,
            "money_movement_effect": False,
            "recipient_cash_effect": False,
            "payment_authorization_effect": False,
        },
        set(receipts),
    )


def _verify_program_funding(connection: sqlite3.Connection, meta: dict[str, object], events: list[sqlite3.Row]) -> tuple[dict[str, object], set[str]]:
    receipt_rows = _bounded_rows(connection, "program_funding_receipts")
    projection_rows = _bounded_rows(connection, "program_funding_projection")
    scope = meta["scope"]
    assert isinstance(scope, dict)
    return _verify_program_funding_rows(receipt_rows, projection_rows, events, scope)


def _values_json(raw: object, code: str) -> list[object]:
    value = _parse_json(raw, code)
    if not isinstance(value, dict) or set(value) != {"values"} or not isinstance(value["values"], list):
        _fail(f"{code}:values")
    return value["values"]


def _evidence_ids_json(raw: object, code: str) -> list[str]:
    value = _parse_json(raw, code)
    if not isinstance(value, dict) or set(value) != {"evidence_ids"} or not isinstance(value["evidence_ids"], list):
        _fail(f"{code}:shape")
    result = [_id(item, f"{code}:id") for item in value["evidence_ids"]]
    if result != sorted(result) or len(set(result)) != len(result):
        _fail(f"{code}:order")
    return result


def _control_pack_policy(
    calculation_rule_id: object,
    adjustment_rule_id: object,
    authorized_roles: list[str],
    expected_tests: list[str],
) -> tuple[str, str]:
    policy = _CONTROL_PACK_POLICIES.get((calculation_rule_id, adjustment_rule_id))
    if policy is None or tuple(expected_tests) != policy[0]:
        _fail("pack:policy")
    if not authorized_roles or len(set(authorized_roles)) != len(authorized_roles):
        _fail("pack:roles")
    if not set(authorized_roles) <= _CONTROL_PACK_ALLOWED_ROLES or not _CONTROL_PACK_REQUIRED_ROLES <= set(authorized_roles):
        _fail("pack:roles")
    return policy[1], policy[2]


def _verify_packs(connection: sqlite3.Connection, meta: dict[str, object]) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "control_packs")
    result: dict[str, sqlite3.Row] = {}
    scope = meta["scope"]
    assert isinstance(scope, dict)
    approved: list[sqlite3.Row] = []
    for row in rows:
        pack_id = _id(row["pack_id"], "pack:id")
        if pack_id in result:
            _fail("pack:duplicate")
        result[pack_id] = row
        for key in ("state_id", "deployment_id", "program_id", "period_id"):
            _id(row[key], f"pack:{key}")
            if row[key] != scope[key]:
                _fail(f"pack:scope:{key}")
        version = _integer(row["version"], "pack:version", minimum=1, maximum=MAX_ROWS)
        source_refs = _values_json(row["source_refs_json"], "pack:source-refs")
        authorized_roles = _values_json(row["authorized_roles_json"], "pack:roles")
        expected_tests = _values_json(row["expected_tests_json"], "pack:tests")
        if not source_refs or not authorized_roles or not expected_tests:
            _fail("pack:empty-list")
        for value in source_refs:
            _text(value, "pack:source-ref")
        for value in authorized_roles:
            _role(value, "pack:role")
        if len(set(authorized_roles)) != len(authorized_roles):
            _fail("pack:role-duplicate")
        for value in expected_tests:
            _text(value, "pack:test")
        _control_pack_policy(row["calculation_rule_id"], row["adjustment_rule_id"], authorized_roles, expected_tests)
        start = _time(row["effective_start_ms"], "pack:start")
        end = _time(row["effective_end_ms"], "pack:end")
        if start >= end:
            _fail("pack:period")
        recorded = _time(row["recorded_at_ms"], "pack:recorded")
        approved_at = _time(row["approved_at_ms"], "pack:approved")
        if approved_at < recorded:
            _fail("pack:chronology")
        _id(row["calculation_rule_id"], "pack:calculation-rule")
        _id(row["adjustment_rule_id"], "pack:adjustment-rule")
        pack_digest = _blob64(row["pack_digest"], "pack:digest")
        expected_digest = _digest(
            EVIDENCE_DOMAIN,
            _canonical(
                {
                    "pack_id": pack_id,
                    "state_id": row["state_id"],
                    "deployment_id": row["deployment_id"],
                    "program_id": row["program_id"],
                    "period_id": row["period_id"],
                    "version": version,
                    "source_refs": source_refs,
                    "effective_start_ms": start,
                    "effective_end_ms": end,
                    "recorded_at_ms": recorded,
                    "approved_at_ms": approved_at,
                    "calculation_rule_id": row["calculation_rule_id"],
                    "adjustment_rule_id": row["adjustment_rule_id"],
                    "authorized_roles": authorized_roles,
                    "expected_tests": expected_tests,
                },
                "pack:digest-input",
            ),
        )
        if pack_digest != expected_digest:
            _fail("pack:digest")
        if row["status"] not in {"APPROVED", "WITHDRAWN"}:
            _fail("pack:status")
        if row["status"] == "APPROVED":
            approved.append(row)
    for left_index, left in enumerate(approved):
        for right in approved[left_index + 1 :]:
            if left["program_id"] != right["program_id"] or left["period_id"] != right["period_id"]:
                continue
            if left["version"] == right["version"] or max(left["effective_start_ms"], right["effective_start_ms"]) < min(left["effective_end_ms"], right["effective_end_ms"]):
                _fail("pack:overlap")
    return result


def _verify_population_manifest_rows(
    *,
    manifest_rows: list[Mapping[str, object]],
    member_rows: list[Mapping[str, object]],
    head_rows: list[Mapping[str, object]],
    binding_rows: list[Mapping[str, object]],
    population_rows: list[Mapping[str, object]],
    item_rows: list[Mapping[str, object]],
    event_rows: list[Mapping[str, object]],
    packs: Mapping[str, Mapping[str, object]],
    scope: Mapping[str, object],
    authority_id: str,
    authority_epoch: int,
    authority_digest: bytes,
    actors: Mapping[str, frozenset[str]] | None,
) -> dict[str, object]:
    """Reconstruct manifest receipts, membership, supersession, and bindings."""

    manifests: dict[str, Mapping[str, object]] = {}
    members_by_manifest: dict[str, tuple[str, ...]] = {}
    if len(manifest_rows) > MAX_ROWS or len(member_rows) > MAX_ROWS or len(head_rows) > MAX_ROWS or len(binding_rows) > MAX_ROWS:
        _fail("population-manifest:row-cap")
    positions: dict[str, dict[int, str]] = {}
    for index, row in enumerate(manifest_rows):
        manifest_id = _id(row["manifest_id"], f"population-manifest:{index}:id")
        if manifest_id in manifests:
            _fail("population-manifest:duplicate")
        manifests[manifest_id] = row
        positions[manifest_id] = {}
    for index, row in enumerate(member_rows):
        manifest_id = _id(row["manifest_id"], f"population-manifest-member:{index}:manifest")
        position = _integer(row["position"], f"population-manifest-member:{index}:position", maximum=MAX_ROWS)
        member_id = _id(row["member_id"], f"population-manifest-member:{index}:id")
        if manifest_id not in manifests or position in positions[manifest_id]:
            _fail("population-manifest:member-reference")
        positions[manifest_id][position] = member_id

    manifest_keys: dict[tuple[object, ...], dict[int, str]] = {}
    children: dict[str, str] = {}
    children_by_scope: dict[tuple[object, ...], set[str]] = {}
    events_by_manifest: dict[str, Mapping[str, object]] = {}
    event_sequences: dict[str, int] = {}
    manifest_events = [row for row in event_rows if row["aggregate_type"] == "POPULATION_MANIFEST"]
    for event in manifest_events:
        event_manifest_id = _id(event["aggregate_id"], "population-manifest:event-id")
        if event_manifest_id in events_by_manifest:
            _fail("population-manifest:event-duplicate")
        events_by_manifest[event_manifest_id] = event
    for index, (manifest_id, row) in enumerate(manifests.items()):
        contract = row["contract"]
        if contract != POPULATION_MANIFEST_CONTRACT:
            _fail("population-manifest:contract")
        version = _integer(row["manifest_version"], f"population-manifest:{index}:version", minimum=1, maximum=MAX_ROWS)
        manifest_scope = {
            "state_id": _id(row["state_id"], f"population-manifest:{index}:state"),
            "deployment_id": _id(row["deployment_id"], f"population-manifest:{index}:deployment"),
            "program_id": _id(row["program_id"], f"population-manifest:{index}:program"),
            "period_id": _id(row["period_id"], f"population-manifest:{index}:period"),
            "currency": row["currency"],
        }
        if manifest_scope != dict(scope) or manifest_scope["currency"] != CURRENCY:
            _fail("population-manifest:scope")
        pack_id = _id(row["pack_id"], f"population-manifest:{index}:pack")
        pack = packs.get(pack_id)
        if pack is None or pack["status"] != "APPROVED":
            _fail("population-manifest:pack")
        if any(pack[key] != manifest_scope[key] for key in ("state_id", "deployment_id", "program_id", "period_id")):
            _fail("population-manifest:pack-scope")
        cutoff_ms = _time(row["cutoff_ms"], f"population-manifest:{index}:cutoff")
        pack_start = _time(pack["effective_start_ms"], f"population-manifest:{index}:pack-start")
        pack_end = _time(pack["effective_end_ms"], f"population-manifest:{index}:pack-end")
        if not pack_start <= cutoff_ms < pack_end:
            _fail("population-manifest:pack-cutoff")
        rules = _values_json(row["inclusion_rules_json"], f"population-manifest:{index}:rules")
        if not rules:
            _fail("population-manifest:rules")
        for rule in rules:
            _text(rule, f"population-manifest:{index}:rule")
        source_owner_id = _id(row["source_owner_id"], f"population-manifest:{index}:source-owner")
        row_authority_id = _id(row["authority_id"], f"population-manifest:{index}:authority")
        row_authority_epoch = _integer(row["authority_epoch"], f"population-manifest:{index}:authority-epoch", minimum=1, maximum=MAX_CENTS)
        row_authority_digest = _blob64(row["authority_digest"], f"population-manifest:{index}:authority-digest")
        if (row_authority_id, row_authority_epoch, row_authority_digest) != (authority_id, authority_epoch, authority_digest):
            _fail("population-manifest:authority")
        approved_by = _id(row["approved_by"], f"population-manifest:{index}:approver")
        if actors is None or "FINANCE_DECISION" not in actors.get(approved_by, frozenset()):
            _fail("population-manifest:approver")
        approval_ref = _id(row["approval_ref"], f"population-manifest:{index}:approval-ref")
        source_id = _id(row["source_id"], f"population-manifest:{index}:source")
        source_version = _text(row["source_version"], f"population-manifest:{index}:source-version")
        source_digest = _blob64(row["source_digest"], f"population-manifest:{index}:source-digest")
        member_count = _integer(row["member_count"], f"population-manifest:{index}:member-count", minimum=1, maximum=MAX_ROWS)
        indexed_members = positions[manifest_id]
        if sorted(indexed_members) != list(range(member_count)):
            _fail("population-manifest:member-position")
        member_ids = tuple(indexed_members[position] for position in range(member_count))
        if tuple(sorted(set(member_ids))) != member_ids:
            _fail("population-manifest:member-order")
        member_digest = _blob64(row["member_digest"], f"population-manifest:{index}:member-digest")
        expected_member_digest = _digest(
            POPULATION_MANIFEST_MEMBERS_DOMAIN,
            _canonical({"member_ids": list(member_ids)}, f"population-manifest:{index}:members-canonical"),
        )
        if member_digest != expected_member_digest:
            _fail("population-manifest:member-digest")
        parent_id = row["supersedes_manifest_id"]
        parent_digest_value = row["supersedes_digest"]
        parent_digest = None if parent_digest_value is None else _blob64(parent_digest_value, f"population-manifest:{index}:parent-digest")
        if (parent_id is None) != (parent_digest is None):
            _fail("population-manifest:parent-binding")
        source_key = (
            manifest_scope["state_id"], manifest_scope["deployment_id"], manifest_scope["program_id"],
            manifest_scope["period_id"], manifest_scope["currency"], pack_id, cutoff_ms, source_owner_id,
        )
        versions = manifest_keys.setdefault(source_key, {})
        if version in versions:
            _fail("population-manifest:version-duplicate")
        versions[version] = manifest_id
        if version == 1:
            if parent_id is not None:
                _fail("population-manifest:root-parent")
        else:
            parent_id = _id(parent_id, f"population-manifest:{index}:parent")
            parent = manifests.get(parent_id)
            if parent is None:
                _fail("population-manifest:parent-missing")
            parent_version = _integer(parent["manifest_version"], "population-manifest:parent-version", minimum=1, maximum=MAX_ROWS)
            parent_key = (
                parent["state_id"], parent["deployment_id"], parent["program_id"], parent["period_id"],
                parent["currency"], parent["pack_id"], parent["cutoff_ms"], parent["source_owner_id"],
            )
            if parent_key != source_key or parent_version + 1 != version or _blob64(parent["manifest_digest"], "population-manifest:parent-manifest-digest") != parent_digest:
                _fail("population-manifest:parent-binding")
            if parent_id in children:
                _fail("population-manifest:fork")
            children[parent_id] = manifest_id
            children_by_scope.setdefault(source_key, set()).add(parent_id)
        body = {
            "contract": POPULATION_MANIFEST_CONTRACT,
            "manifest_id": manifest_id,
            "manifest_version": version,
            "scope": manifest_scope,
            "pack_id": pack_id,
            "cutoff_ms": cutoff_ms,
            "inclusion_rules": rules,
            "source_owner_id": source_owner_id,
            "authority": {
                "authority_id": row_authority_id,
                "epoch": row_authority_epoch,
                "digest": row_authority_digest.hex().upper(),
            },
            "approved_by": approved_by,
            "approval_ref": approval_ref,
            "source": {"source_id": source_id, "version": source_version, "digest": source_digest.hex().upper()},
            "member_count": member_count,
            "member_ids": list(member_ids),
            "member_digest": member_digest.hex().upper(),
            "supersedes": None
            if parent_id is None
            else {"manifest_id": parent_id, "digest": parent_digest.hex().upper()},
        }
        manifest_digest = _blob64(row["manifest_digest"], f"population-manifest:{index}:digest")
        if manifest_digest != _digest(POPULATION_MANIFEST_DOMAIN, _canonical(body, f"population-manifest:{index}:canonical")):
            _fail("population-manifest:digest")
        registered_at = _time(row["registered_at_ms"], f"population-manifest:{index}:registered")
        members_by_manifest[manifest_id] = member_ids

        event = events_by_manifest.get(manifest_id)
        if event is None:
            _fail("population-manifest:event-count")
        event_sequence = _integer(
            event["event_sequence"],
            f"population-manifest:{index}:event-sequence",
            minimum=1,
            maximum=MAX_ROWS,
        )
        event_sequences[manifest_id] = event_sequence
        if parent_id is not None:
            parent_event = events_by_manifest.get(parent_id)
            if parent_event is None or event_sequence <= _integer(
                parent_event["event_sequence"],
                "population-manifest:parent-event-sequence",
                minimum=1,
                maximum=MAX_ROWS,
            ):
                _fail("population-manifest:event-lineage-order")
        event_kind = "POPULATION_MANIFEST_REGISTERED" if version == 1 else "POPULATION_MANIFEST_SUPERSEDED"
        before = 0 if version == 1 else version - 1
        expected_event_payload = {
            "contract": POPULATION_MANIFEST_CONTRACT,
            "manifest_id": manifest_id,
            "manifest_version": version,
            "manifest_digest": manifest_digest.hex().upper(),
            "member_digest": member_digest.hex().upper(),
            "member_count": member_count,
            "supersedes_manifest_id": parent_id,
            "supersedes_digest": None if parent_digest is None else parent_digest.hex().upper(),
        }
        payload = _parse_json(event["payload_json"], "population-manifest:event-payload")
        if (
            event["kind"] != event_kind
            or _integer(event["before_revision"], "population-manifest:event-before", maximum=MAX_ROWS) != before
            or _integer(event["after_revision"], "population-manifest:event-after", minimum=1, maximum=MAX_ROWS) != version
            or _time(event["committed_at_ms"], "population-manifest:event-committed") != registered_at
            or payload != expected_event_payload
        ):
            _fail("population-manifest:event-binding")
    if len(manifest_events) != len(manifests) or set(events_by_manifest) != set(manifests):
        _fail("population-manifest:event-cardinality")
    expected_heads: dict[tuple[object, ...], tuple[str, Mapping[str, object]]] = {}
    for source_key, version_map in manifest_keys.items():
        if sorted(version_map) != list(range(1, max(version_map) + 1)):
            _fail("population-manifest:version-sequence")
        leaf_ids = set(version_map.values()) - children_by_scope.get(source_key, set())
        if len(leaf_ids) != 1:
            _fail("population-manifest:head-lineage")
        head_id = next(iter(leaf_ids))
        expected_heads[source_key] = (head_id, manifests[head_id])
    actual_heads: dict[tuple[object, ...], Mapping[str, object]] = {}
    for index, row in enumerate(head_rows):
        key = (
            _id(row["state_id"], f"population-head:{index}:state"),
            _id(row["deployment_id"], f"population-head:{index}:deployment"),
            _id(row["program_id"], f"population-head:{index}:program"),
            _id(row["period_id"], f"population-head:{index}:period"),
            row["currency"],
            _id(row["pack_id"], f"population-head:{index}:pack"),
            _time(row["cutoff_ms"], f"population-head:{index}:cutoff"),
            _id(row["source_owner_id"], f"population-head:{index}:source-owner"),
        )
        if key in actual_heads:
            _fail("population-manifest:head-duplicate")
        actual_heads[key] = row
    if set(actual_heads) != set(expected_heads):
        _fail("population-manifest:head-cardinality")
    for key, (manifest_id, expected_row) in expected_heads.items():
        row = actual_heads[key]
        if (
            row["manifest_id"] != manifest_id
            or _integer(row["manifest_version"], "population-manifest:head-version", minimum=1, maximum=MAX_ROWS)
            != _integer(expected_row["manifest_version"], "population-manifest:expected-head-version", minimum=1, maximum=MAX_ROWS)
            or _blob64(row["manifest_digest"], "population-manifest:head-digest") != expected_row["manifest_digest"]
            or _time(row["updated_at_ms"], "population-manifest:head-updated") != expected_row["registered_at_ms"]
        ):
            _fail("population-manifest:head-binding")

    bindings: dict[str, Mapping[str, object]] = {}
    bound_manifests: set[str] = set()
    for index, row in enumerate(binding_rows):
        population_id = _id(row["population_id"], f"population-binding:{index}:population")
        manifest_id = _id(row["manifest_id"], f"population-binding:{index}:manifest")
        manifest = manifests.get(manifest_id)
        if population_id in bindings or manifest is None or manifest_id in bound_manifests:
            _fail("population-manifest:binding-duplicate")
        if (
            _integer(row["manifest_version"], "population-binding:version", minimum=1, maximum=MAX_ROWS) != manifest["manifest_version"]
            or _blob64(row["manifest_digest"], "population-binding:digest") != manifest["manifest_digest"]
        ):
            _fail("population-manifest:binding")
        bindings[population_id] = row
        bound_manifests.add(manifest_id)
    if len(bindings) != len(population_rows):
        _fail("population-manifest:population-binding-cardinality")
    imports_by_id = {_id(row["population_id"], "population-manifest:import-population"): row for row in population_rows}
    if set(bindings) != set(imports_by_id):
        _fail("population-manifest:population-binding-set")
    items_by_population: dict[str, set[str]] = {}
    for row in item_rows:
        population_id = _id(row["population_id"], "population-manifest:item-population")
        item_id = _id(row["item_id"], "population-manifest:item-id")
        if population_id not in imports_by_id or item_id in items_by_population.setdefault(population_id, set()):
            _fail("population-manifest:item-duplicate")
        items_by_population[population_id].add(item_id)
    for population_id, binding in bindings.items():
        manifest_id = str(binding["manifest_id"])
        manifest = manifests[manifest_id]
        population = imports_by_id[population_id]
        if (
            population["pack_id"] != manifest["pack_id"]
            or population["cutoff_ms"] != manifest["cutoff_ms"]
            or _values_json(population["inclusion_rules_json"], "population-manifest:import-rules") != _values_json(manifest["inclusion_rules_json"], "population-manifest:rules")
            or _integer(population["expected_count"], "population-manifest:expected-count", minimum=1, maximum=MAX_ROWS) != manifest["member_count"]
        ):
            _fail("population-manifest:import-binding")
        actual = items_by_population.get(population_id, set())
        expected = set(members_by_manifest[manifest_id])
        if not actual <= expected:
            _fail("population-manifest:extra-imported-member")
        if _integer(population["imported_count"], "population-manifest:imported-count", maximum=MAX_ROWS) != len(actual):
            _fail("population-manifest:imported-count")
        complete = _flag(population["source_complete"], "population-manifest:source-complete")
        status = population["status"]
        if complete == 1 and actual != expected:
            _fail("population-manifest:source-complete-members")
        if status in {"VALIDATED", "PUBLISHED"} and (complete != 1 or actual != expected):
            _fail("population-manifest:validated-members")
        source_key = (
            manifest["state_id"], manifest["deployment_id"], manifest["program_id"], manifest["period_id"],
            manifest["currency"], manifest["pack_id"], manifest["cutoff_ms"], manifest["source_owner_id"],
        )
        head = actual_heads.get(source_key)
        if status == "PUBLISHED" and (head is None or head["manifest_id"] != manifest_id):
            _fail("population-manifest:published-stale")
    return {
        "manifests": manifests,
        "members_by_manifest": members_by_manifest,
        "bindings": bindings,
        "heads": actual_heads,
        "event_sequences": event_sequences,
        "superseded_at": {
            parent_id: event_sequences[child_id]
            for parent_id, child_id in children.items()
        },
    }


def _verify_populations(
    connection: sqlite3.Connection,
    meta: dict[str, object],
    packs: dict[str, sqlite3.Row],
    manifest_state: Mapping[str, object],
) -> tuple[dict[str, sqlite3.Row], dict[str, sqlite3.Row]]:
    imports = _bounded_rows(connection, "population_imports")
    items = _bounded_rows(connection, "population_items")
    populations: dict[str, sqlite3.Row] = {}
    items_by_population: dict[str, list[sqlite3.Row]] = {}
    item_by_id: dict[str, sqlite3.Row] = {}
    scope = meta["scope"]
    assert isinstance(scope, dict)
    manifest_records = manifest_state["manifests"]
    manifest_members = manifest_state["members_by_manifest"]
    manifest_bindings = manifest_state["bindings"]
    if not (
        isinstance(manifest_records, dict)
        and isinstance(manifest_members, dict)
        and isinstance(manifest_bindings, dict)
    ):
        _fail("population:manifest-state")
    for row in imports:
        population_id = _id(row["population_id"], "population:id")
        if population_id in populations:
            _fail("population:duplicate")
        populations[population_id] = row
        pack_id = _id(row["pack_id"], "population:pack-id")
        pack = packs.get(pack_id)
        if pack is None or pack["status"] != "APPROVED":
            _fail("population:pack")
        _time(row["cutoff_ms"], "population:cutoff")
        rules = _values_json(row["inclusion_rules_json"], "population:rules")
        if not rules:
            _fail("population:rules-empty")
        for rule in rules:
            _text(rule, "population:rule")
        expected = _integer(row["expected_count"], "population:expected-count", minimum=1, maximum=MAX_ROWS)
        source_complete = _flag(row["source_complete"], "population:source-complete")
        imported = _integer(row["imported_count"], "population:imported-count", maximum=MAX_ROWS)
        validated = _integer(row["validated_count"], "population:validated-count", maximum=MAX_ROWS)
        status = row["status"]
        if status not in {"STAGED", "VALIDATED", "PUBLISHED"}:
            _fail("population:status")
        created = _time(row["created_at_ms"], "population:created")
        updated = _time(row["updated_at_ms"], "population:updated")
        if updated < created:
            _fail("population:chronology")
        if status == "STAGED" and validated != 0:
            _fail("population:staged-validation")
        if source_complete == 1 and imported != expected:
            _fail("population:source-count")
        if status in {"VALIDATED", "PUBLISHED"}:
            if source_complete != 1 or validated != imported or imported != expected:
                _fail("population:count")
            _blob64(row["validation_digest"], "population:validation-digest")
        elif row["validation_digest"] is not None:
            _fail("population:staged-digest")
        if imported > expected or validated > expected:
            _fail("population:count")
        binding = manifest_bindings.get(population_id)
        if binding is None:
            _fail("population:manifest-binding")
        manifest_id = str(binding["manifest_id"])
        manifest = manifest_records.get(manifest_id)
        if manifest is None:
            _fail("population:manifest-reference")
        if (
            row["pack_id"] != manifest["pack_id"]
            or row["cutoff_ms"] != manifest["cutoff_ms"]
            or expected != manifest["member_count"]
        ):
            _fail("population:manifest-binding")
        items_by_population[population_id] = []
        _ = scope
    for row in items:
        population_id = _id(row["population_id"], "item:population-id")
        item_id = _id(row["item_id"], "item:id")
        existing = item_by_id.get(item_id)
        if existing is not None:
            existing_population = populations[str(existing["population_id"])]
            current_population = populations[population_id]
            if str(existing["population_id"]) == population_id or (existing_population["status"] == "PUBLISHED" and current_population["status"] == "PUBLISHED"):
                _fail("item:duplicate")
        else:
            item_by_id[item_id] = row
        _text(row["display_label"], "item:label", max_bytes=128)
        _cents(row["owed_cents"], "item:owed", positive=True)
        _time(row["due_at_ms"], "item:due")
        if row["currency"] != scope["currency"]:
            _fail("item:currency")
        items_by_population[population_id].append(row)
    for population_id, row in populations.items():
        actual_items = items_by_population.get(population_id, [])
        if len(actual_items) != row["imported_count"]:
            _fail("population:imported-count")
        binding = manifest_bindings[population_id]
        expected_members = manifest_members[str(binding["manifest_id"])]
        actual_members = tuple(sorted(str(item["item_id"]) for item in actual_items))
        if not set(actual_members) <= set(expected_members):
            _fail("population:manifest-extra-member")
        if row["source_complete"] == 1 and actual_members != expected_members:
            _fail("population:manifest-completeness")
        if row["status"] in {"VALIDATED", "PUBLISHED"}:
            material = b"".join(
                _digest(
                    EVIDENCE_DOMAIN,
                    _canonical(
                        {
                            "item_id": item["item_id"],
                            "display_label": item["display_label"],
                            "owed_cents": item["owed_cents"],
                            "due_at_ms": item["due_at_ms"],
                            "currency": item["currency"],
                        },
                        "population:item-digest-input",
                    ),
                )
                for item in sorted(actual_items, key=lambda item: item["item_id"])
            )
            expected_digest = _digest(EVIDENCE_DOMAIN, material)
            if bytes(row["validation_digest"]) != expected_digest:
                _fail("population:validation-digest")
    return populations, item_by_id


def _verify_obligations(
    connection: sqlite3.Connection,
    meta: dict[str, object],
    populations: dict[str, sqlite3.Row],
    items: dict[str, sqlite3.Row],
    packs: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "obligations")
    obligations: dict[str, sqlite3.Row] = {}
    by_item: dict[str, sqlite3.Row] = {}
    for row in rows:
        obligation_id = _id(row["obligation_id"], "obligation:id")
        if obligation_id in obligations:
            _fail("obligation:duplicate")
        obligations[obligation_id] = row
        population_id = _id(row["population_id"], "obligation:population-id")
        population = populations.get(population_id)
        if population is None or population["status"] != "PUBLISHED":
            _fail("obligation:population")
        item_id = _id(row["item_id"], "obligation:item-id")
        item = items.get(item_id)
        if item is None or item["population_id"] != population_id:
            _fail("obligation:item")
        if item_id in by_item:
            _fail("obligation:item-duplicate")
        by_item[item_id] = row
        pack = packs[str(population["pack_id"])]
        period_id = _id(pack["period_id"], "obligation:period")
        suffix = period_id
        marker = "period-"
        if marker in period_id:
            suffix = marker + period_id.rsplit(marker, 1)[1]
        if obligation_id != f"obligation:{item_id}:{suffix}":
            _fail("obligation:id-binding")
        if row["period_id"] != pack["period_id"] or row["currency"] != meta["scope"]["currency"]:
            _fail("obligation:scope")
        if row["owed_cents"] != item["owed_cents"] or row["due_at_ms"] != item["due_at_ms"]:
            _fail("obligation:source-binding")
        _cents(row["owed_cents"], "obligation:owed", positive=True)
        _time(row["due_at_ms"], "obligation:due")
        _integer(row["rule_version"], "obligation:rule-version", minimum=1, maximum=MAX_ROWS)
        if row["rule_version"] != pack["version"]:
            _fail("obligation:rule-binding")
        _integer(row["revision"], "obligation:revision", maximum=MAX_ROWS)
        for key in ("claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents"):
            _cents(row[key], f"obligation:{key}")
        for key in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
            _flag(row[key], f"obligation:{key}")
        if row["verification_status"] not in _EVALUATION_VERIFICATION:
            _fail("obligation:verification")
        if row["case_status"] not in _CASE_STATUSES:
            _fail("obligation:case")
        if row["delivery_status"] not in _DELIVERY_STATUSES:
            _fail("obligation:delivery")
        if row["current_evaluation_id"] is not None:
            _id(row["current_evaluation_id"], "obligation:evaluation-id")
        _time(row["updated_at_ms"], "obligation:updated")
    for population_id, population in populations.items():
        if population["status"] == "PUBLISHED":
            for item_id, item in items.items():
                if item["population_id"] == population_id and item_id not in by_item:
                    _fail("obligation:missing")
    return obligations


def _verify_population_history(
    events: list[Mapping[str, object]],
    populations: dict[str, sqlite3.Row],
    packs: dict[str, sqlite3.Row],
    manifest_state: Mapping[str, object],
) -> None:
    """Reconstruct each population's lifecycle from ordered history events."""

    by_population: dict[str, list[sqlite3.Row]] = {population_id: [] for population_id in populations}
    for event in events:
        if event["aggregate_type"] != "POPULATION":
            continue
        population_id = str(event["aggregate_id"])
        if population_id not in populations:
            _fail("history:population-reference")
        by_population[population_id].append(event)

    bindings = manifest_state.get("bindings")
    manifests = manifest_state.get("manifests")
    event_sequences = manifest_state.get("event_sequences")
    superseded_at = manifest_state.get("superseded_at")
    # A typed failure, not an ``assert``: the check must hold under ``python -O`` too.
    if not (
        isinstance(bindings, dict)
        and isinstance(manifests, dict)
        and isinstance(event_sequences, dict)
        and isinstance(superseded_at, dict)
    ):
        _fail("history:population-manifest-state")
    last_committed_at: dict[str, int | None] = {}
    for population_id, population in populations.items():
        expected = _integer(population["expected_count"], "history:population-expected", minimum=1, maximum=MAX_ROWS)
        binding = bindings.get(population_id)
        if binding is None:
            _fail("history:population-manifest-binding")
        manifest_id = str(binding["manifest_id"])
        manifest = manifests.get(manifest_id)
        if manifest is None:
            _fail("history:population-manifest-reference")
        manifest_event_sequence = event_sequences.get(manifest_id)
        if type(manifest_event_sequence) is not int:
            _fail("history:population-manifest-event")
        superseded_sequence = superseded_at.get(manifest_id)
        manifest_fields: dict[str, object] = {
            "manifest_id": manifest_id,
            "manifest_version": int(manifest["manifest_version"]),
            "manifest_digest": _blob64(manifest["manifest_digest"], "history:population-manifest-digest").hex().upper(),
            "member_digest": _blob64(manifest["member_digest"], "history:population-member-digest").hex().upper(),
        }
        imported = 0
        opened = False
        source_completed = False
        validated = False
        published = False
        previous_committed_at: int | None = None
        for event in by_population[population_id]:
            event_sequence = _integer(
                event["event_sequence"],
                "history:population-event-sequence",
                minimum=1,
                maximum=MAX_ROWS,
            )
            if event_sequence <= manifest_event_sequence:
                _fail("history:population-manifest-order")
            if (
                superseded_sequence is not None
                and event_sequence >= _integer(
                    superseded_sequence,
                    "history:population-superseded-sequence",
                    minimum=1,
                    maximum=MAX_ROWS,
                )
            ):
                _fail("history:population-manifest-stale-event")
            committed_at = _time(event["committed_at_ms"], "history:population-committed-at")
            if previous_committed_at is not None and committed_at < previous_committed_at:
                _fail("history:population-chronology")
            previous_committed_at = committed_at
            before = _integer(event["before_revision"], "history:population-before", maximum=MAX_ROWS)
            after = _integer(event["after_revision"], "history:population-after", maximum=MAX_ROWS)
            payload = _parse_json(event["payload_json"], "history:population-payload", max_bytes=MAX_PACKAGE_BYTES)
            if not isinstance(payload, dict):
                _fail("history:population-payload")
            payload.pop("rows", None)  # the rows it wrote, checked by replay
            kind = str(event["kind"])
            if kind != "POPULATION_IMPORT_OPENED" and not opened:
                _fail("history:population-open-order")
            if kind == "POPULATION_IMPORT_OPENED":
                # Staging is recorded exactly once, before any import, completion,
                # validation or publication event for the same population.
                if opened:
                    _fail("history:population-open-duplicate")
                if imported or source_completed or validated or published:
                    _fail("history:population-open-order")
                if set(payload) != {"population_id", "staging_digest"} | set(manifest_fields):
                    _fail("history:population-open-payload")
                if any(payload.get(key) != value for key, value in manifest_fields.items()):
                    _fail("history:population-open-manifest")
                if payload["population_id"] != population_id:
                    _fail("history:population-open-population")
                if before != 0 or after != 0:
                    _fail("history:population-open-revision")
                expected_staging_digest = _digest(
                    POPULATION_STAGING_DOMAIN,
                    _canonical(
                        {
                            "population_id": population_id,
                            "pack_id": _id(population["pack_id"], "history:population-open-pack"),
                            "cutoff_ms": _time(population["cutoff_ms"], "history:population-open-cutoff"),
                            "inclusion_rules_json": _text(
                                population["inclusion_rules_json"],
                                "history:population-open-rules",
                                max_bytes=MAX_JSON_BYTES,
                            ),
                            "expected_count": expected,
                            "created_at_ms": _time(population["created_at_ms"], "history:population-open-created"),
                        },
                        "history:population-open-staging",
                    ),
                )
                if _hex_digest(payload["staging_digest"], "history:population-open-staging-digest") != expected_staging_digest:
                    _fail("history:population-open-staging-digest")
                opened = True
                continue

            if kind == "POPULATION_STAGED":
                if source_completed or validated or published:
                    _fail("history:population-stage-order")
                stage_fields = {"population_id", "imported_count", "chunk_count"} | set(manifest_fields)
                if set(payload) != stage_fields:
                    _fail("history:population-stage-payload")
                if any(payload.get(key) != value for key, value in manifest_fields.items()):
                    _fail("history:population-stage-manifest")
                if payload["population_id"] != population_id:
                    _fail("history:population-stage-population")
                count = _integer(payload["imported_count"], "history:population-stage-imported", maximum=MAX_ROWS)
                chunk_count = _integer(payload["chunk_count"], "history:population-stage-chunk", minimum=1, maximum=MAX_ROWS)
                if before != imported or after != count or count != imported + chunk_count:
                    _fail("history:population-stage-revision")
                if count > expected:
                    _fail("history:population-stage-count")
                imported = count
                continue

            if kind == "POPULATION_SOURCE_COMPLETED":
                if source_completed:
                    _fail("history:population-completion-duplicate")
                if validated or published:
                    _fail("history:population-completion-order")
                completion_fields = {"population_id", "imported_count", "expected_count"} | set(manifest_fields)
                if set(payload) != completion_fields:
                    _fail("history:population-completion-payload")
                if any(payload.get(key) != value for key, value in manifest_fields.items()):
                    _fail("history:population-completion-manifest")
                if payload["population_id"] != population_id:
                    _fail("history:population-completion-population")
                completed_imported = _integer(payload["imported_count"], "history:population-completion-imported", maximum=MAX_ROWS)
                completed_expected = _integer(payload["expected_count"], "history:population-completion-expected", minimum=1, maximum=MAX_ROWS)
                if before != 0 or after != completed_imported:
                    _fail("history:population-completion-revision")
                if _flag(population["source_complete"], "population:source-complete") != 1 or completed_imported != expected or completed_expected != expected:
                    _fail("history:population-completion-binding")
                source_completed = True
                continue

            if kind == "POPULATION_VALIDATED":
                if not source_completed:
                    _fail("history:population-completion-order")
                if validated or published:
                    _fail("history:population-validation-order")
                validation_fields = {"population_id", "validated_count", "validation_digest"} | set(manifest_fields)
                if set(payload) != validation_fields:
                    _fail("history:population-validation-payload")
                if any(payload.get(key) != value for key, value in manifest_fields.items()):
                    _fail("history:population-validation-manifest")
                if payload["population_id"] != population_id:
                    _fail("history:population-validation-population")
                validated_count = _integer(payload["validated_count"], "history:population-validation-count", minimum=1, maximum=MAX_ROWS)
                validation_digest = _hex_digest(payload["validation_digest"], "history:population-validation-digest")
                if before != 0 or after != validated_count:
                    _fail("history:population-validation-revision")
                if validated_count != expected or validated_count != imported:
                    _fail("history:population-validation-binding")
                if population["status"] not in {"VALIDATED", "PUBLISHED"} or population["validated_count"] != validated_count or bytes(population["validation_digest"]) != validation_digest:
                    _fail("history:population-validation-binding")
                validated = True
                continue

            if kind == "POPULATION_PUBLISHED":
                if not validated:
                    _fail("history:population-validation-order")
                if published:
                    _fail("history:population-publication-duplicate")
                publication_fields = {"population_id", "item_count", "pack_id", "pack_version", "evaluation_count", "evaluation_binding_digest"} | set(manifest_fields)
                if set(payload) != publication_fields:
                    _fail("history:population-publication-payload")
                if any(payload.get(key) != value for key, value in manifest_fields.items()):
                    _fail("history:population-publication-manifest")
                if payload["population_id"] != population_id:
                    _fail("history:population-publication-population")
                item_count = _integer(payload["item_count"], "history:population-publication-count", minimum=1, maximum=MAX_ROWS)
                pack_id = _id(payload["pack_id"], "history:population-publication-pack")
                pack_version = _integer(payload["pack_version"], "history:population-publication-version", minimum=1, maximum=MAX_ROWS)
                pack = packs.get(str(population["pack_id"]))
                if pack is None or pack_id != str(population["pack_id"]) or pack_version != int(pack["version"]):
                    _fail("history:population-publication-binding")
                evaluation_count = _integer(payload["evaluation_count"], "history:population-publication-evaluation-count", minimum=1, maximum=MAX_ROWS)
                _hex_digest(payload["evaluation_binding_digest"], "history:population-publication-evaluation-digest")
                if before != 0 or after != item_count or item_count != expected or item_count != imported or evaluation_count != item_count or population["status"] != "PUBLISHED":
                    _fail("history:population-publication-binding")
                published = True

        if not opened:
            _fail("history:population-open-missing")
        persisted_imported = _integer(population["imported_count"], "history:population-imported", maximum=MAX_ROWS)
        if imported != persisted_imported:
            _fail("history:population-imported-binding")
        source_complete = _flag(population["source_complete"], "population:source-complete")
        if source_completed and imported != expected:
            _fail("history:population-completion-binding")
        if source_complete == 1 and not source_completed:
            _fail("history:population-completion-missing")
        if source_complete == 0 and source_completed:
            _fail("history:population-completion-unexpected")
        status = str(population["status"])
        if status == "STAGED":
            if validated or published:
                _fail("history:population-status-order")
        elif status == "VALIDATED":
            if not validated or published:
                _fail("history:population-status-order")
        elif status == "PUBLISHED":
            if not validated or not published:
                _fail("history:population-status-order")
        last_committed_at[population_id] = previous_committed_at
    if any(populations[population_id]["updated_at_ms"] != at for population_id, at in last_committed_at.items()):
        _fail("history:population-updated-at")


def _verify_evidence(
    connection: sqlite3.Connection,
    items: dict[str, sqlite3.Row],
    obligations: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "evidence")
    evidence: dict[str, sqlite3.Row] = {}
    obligation_items = {str(item["item_id"]) for item in obligations.values()}
    for row in rows:
        evidence_id = _id(row["evidence_id"], "evidence:id")
        if evidence_id in evidence:
            _fail("evidence:duplicate")
        evidence[evidence_id] = row
        item_id = _id(row["item_id"], "evidence:item")
        if item_id not in items or item_id not in obligation_items:
            _fail("evidence:item-binding")
        _kind(row["kind"], "evidence:kind")
        _id(row["common_origin_id"], "evidence:common-origin")
        _id(row["source_id"], "evidence:source-id")
        _id(row["source_version"], "evidence:source-version")
        _id(row["local_ref"], "evidence:local-ref")
        applicable = _time(row["applicable_at_ms"], "evidence:applicable")
        event = _time(row["event_at_ms"], "evidence:event")
        received = _time(row["received_at_ms"], "evidence:received")
        if event > received:
            _fail("evidence:chronology")
        content_digest = _blob64(row["content_digest"], "evidence:content-digest")
        record_digest = _blob64(row["record_digest"], "evidence:record-digest")
        amount = row["amount_cents"]
        if amount is not None:
            _cents(amount, "evidence:amount")
        reversal = row["reversal_of"]
        supersedes = row["supersedes"]
        if reversal is not None:
            _id(reversal, "evidence:reversal")
        if supersedes is not None:
            _id(supersedes, "evidence:supersedes")
        expected_content = _digest(
            EVIDENCE_DOMAIN,
            _canonical(
                {
                    "source_id": row["source_id"],
                    "source_version": row["source_version"],
                    "local_ref": row["local_ref"],
                    "common_origin_id": row["common_origin_id"],
                    "kind": row["kind"],
                },
                "evidence:content-input",
            ),
        )
        if content_digest != expected_content:
            _fail("evidence:content-digest")
        expected_record = _digest(
            EVIDENCE_DOMAIN,
            _canonical(
                {
                    "evidence_id": evidence_id,
                    "item_id": item_id,
                    "kind": row["kind"],
                    "common_origin_id": row["common_origin_id"],
                    "source_id": row["source_id"],
                    "source_version": row["source_version"],
                    "local_ref": row["local_ref"],
                    "applicable_at_ms": applicable,
                    "event_at_ms": event,
                    "received_at_ms": received,
                    "content_digest": content_digest.hex().upper(),
                    "amount_cents": amount,
                    "reversal_of": reversal,
                    "supersedes": supersedes,
                },
                "evidence:record-input",
            ),
        )
        if record_digest != expected_record:
            _fail("evidence:record-digest")
    successor_by_target: dict[str, str] = {}
    for row in evidence.values():
        if row["kind"] != "REPORT_CORRECTION" or row["supersedes"] is None:
            continue
        target = str(row["supersedes"])
        successor = str(row["evidence_id"])
        prior_successor = successor_by_target.get(target)
        if prior_successor is not None and prior_successor != successor:
            _fail("evidence:report-supersedes-fork")
        successor_by_target[target] = successor
    for row in evidence.values():
        kind = str(row["kind"])
        supersedes = row["supersedes"]
        if kind == "REPORT" and supersedes is not None:
            _fail("evidence:report-supersedes")
        if kind != "REPORT_CORRECTION":
            continue
        if supersedes is None:
            _fail("evidence:report-supersedes-required")
        prior = evidence[str(supersedes)]
        if prior["item_id"] != row["item_id"]:
            _fail("evidence:report-supersedes-item")
        if prior["kind"] not in {"REPORT", "REPORT_CORRECTION"}:
            _fail("evidence:report-supersedes-kind")
        if int(prior["event_at_ms"]) >= int(row["event_at_ms"]):
            _fail("evidence:report-supersedes-chronology")
    return evidence


def _verify_payments(
    connection: sqlite3.Connection,
    obligations: dict[str, sqlite3.Row],
    items: dict[str, sqlite3.Row],
    evidence: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "payments")
    payments: dict[str, sqlite3.Row] = {}
    origins: set[tuple[str, str]] = set()
    for row in rows:
        payment_id = _id(row["payment_id"], "payment:id")
        if payment_id in payments:
            _fail("payment:duplicate")
        payments[payment_id] = row
        obligation_id = _id(row["obligation_id"], "payment:obligation")
        obligation = obligations.get(obligation_id)
        if obligation is None or row["item_id"] != obligation["item_id"] or row["item_id"] not in items:
            _fail("payment:obligation")
        item_id = _id(row["item_id"], "payment:item")
        common_origin_id = _id(row["common_origin_id"], "payment:common-origin")
        pair = (obligation_id, common_origin_id)
        if pair in origins:
            _fail("payment:common-origin-duplicate")
        origins.add(pair)
        evidence_id = _id(row["evidence_id"], "payment:evidence")
        ev = evidence.get(evidence_id)
        if ev is None or ev["item_id"] != item_id or ev["kind"] not in _PAYMENT_EVIDENCE_KINDS or ev["common_origin_id"] != common_origin_id or ev["amount_cents"] != row["amount_cents"] or ev["event_at_ms"] != row["event_at_ms"]:
            _fail("payment:evidence")
        _cents(row["amount_cents"], "payment:amount", positive=True)
        _time(row["event_at_ms"], "payment:event")
        _flag(row["active"], "payment:active")
        reversed_by = row["reversed_by_evidence_id"]
        if row["active"] == 1 and reversed_by is not None:
            _fail("payment:active-reversal")
        if row["active"] == 0:
            if reversed_by is None:
                _fail("payment:inactive-reversal")
            _id(reversed_by, "payment:reversed-by")
    for row in rows:
        reversed_by = row["reversed_by_evidence_id"]
        if reversed_by is None:
            continue
        reversal = evidence.get(str(reversed_by))
        if reversal is None or reversal["kind"] != "PAYMENT_REVERSAL" or reversal["item_id"] != row["item_id"] or reversal["reversal_of"] != row["payment_id"] or reversal["amount_cents"] != row["amount_cents"]:
            _fail("payment:reversal-binding")
    for ev in evidence.values():
        if ev["kind"] == "PAYMENT_REVERSAL":
            reversal_of = ev["reversal_of"]
            if reversal_of is None or reversal_of not in payments:
                _fail("payment:orphan-reversal")
    return payments


def _verify_adjustments(
    connection: sqlite3.Connection,
    obligations: dict[str, sqlite3.Row],
    evidence: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "claimed_adjustments")
    claims: dict[str, sqlite3.Row] = {}
    acts: dict[str, list[tuple[str, int]]] = {}
    for act in _claim_acts(connection):
        acts.setdefault(str(act[2]), []).append((str(act[1]), act[3]))
    used_evidence: set[str] = set()
    for row in rows:
        claim_id = _id(row["claim_id"], "claim:id")
        if claim_id in claims:
            _fail("claim:duplicate")
        claims[claim_id] = row
        obligation_id = _id(row["obligation_id"], "claim:obligation")
        evidence_id = _id(row["evidence_id"], "claim:evidence")
        ev = evidence.get(evidence_id)
        if ev is None or ev["kind"] != "OFFSET_CLAIM" or ev["item_id"] != obligations[obligation_id]["item_id"] or ev["common_origin_id"] != claim_id or ev["amount_cents"] != row["amount_cents"]:
            _fail("claim:evidence")
        if evidence_id in used_evidence:
            _fail("claim:evidence-duplicate")
        used_evidence.add(evidence_id)
        _cents(row["amount_cents"], "claim:amount", positive=True)
        if _role(row["owner_role"], "claim:owner") not in _CONTROL_PACK_ALLOWED_ROLES:
            _fail("claim:owner")
        _time(row["deadline_ms"], "claim:deadline")
        if row["status"] not in _CLAIM_STATUSES:
            _fail("claim:status")
        history = acts.get(claim_id, [])
        if [kind for kind, _ in history] != _CLAIM_ACTS[row["status"]] or (row["created_at_ms"], row["updated_at_ms"]) != (history[0][1], history[-1][1]):
            _fail("claim:chronology")
    return claims


# A claim's own events, in order, for each claim status.
_CLAIM_ACTS = {"CLAIMED": ["OFFSET_CLAIMED"], "AUTHORIZED": ["OFFSET_CLAIMED", "OFFSET_AUTHORIZED"], "REJECTED": ["OFFSET_CLAIMED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED"]}
_CASE_ACTS = {"OFFSET_CLAIMED": "UNSUPPORTED_OFFSET", "OFFSET_AUTHORIZED": "OFFSET_AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED": "CORRECTION_REQUIRED"}
_CASE_CONDITIONS = '{"amount_satisfied":true,"delivery_acknowledged_or_not_required":true,"reporting_complete":true}'


def _claim_acts(connection: sqlite3.Connection, obligation_id: str | None = None) -> list[sqlite3.Row]:
    """Claim and decision events in history order: (obligation_id, kind, claim_id, committed_at_ms, prior case status)."""

    sql = (
        "SELECT e.aggregate_id,e.kind,COALESCE(json_extract(e.payload_json,'$.claim_id'),d.claim_id),e.committed_at_ms,p.case_status FROM financial_events e "
        "LEFT JOIN determinations d ON d.determination_id=json_extract(e.payload_json,'$.determination_id') "
        "LEFT JOIN evaluations p ON p.evaluation_id='evaluation:'||e.aggregate_id||':r'||e.before_revision "
        "WHERE e.aggregate_type='OBLIGATION' AND e.kind IN ('OFFSET_CLAIMED','OFFSET_AUTHORIZED','OFFSET_REJECTED_CORRECTION_AUTHORIZED')"
    )
    if obligation_id is None:
        return connection.execute(sql + " ORDER BY e.event_sequence").fetchall()
    return connection.execute(sql + " AND e.aggregate_id=? ORDER BY e.event_sequence", (obligation_id,)).fetchall()


def _verify_cases(connection: sqlite3.Connection, obligations: Mapping[str, Mapping[str, Any]], current: Mapping[str, Mapping[str, Any]], obligation_id: str | None = None) -> None:
    """Each obligation has one case, from its latest claim or decision (an outstanding correction outlasts later ones) and current evaluation."""

    acts = {str(act[0]): act for act in _claim_acts(connection, obligation_id) if act[4] != "CORRECTION_REQUIRED" or act[1] == "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}
    if obligation_id is None:
        rows = _bounded_rows(connection, "cases")
    else:
        rows = connection.execute("SELECT * FROM cases WHERE obligation_id=?", (obligation_id,)).fetchall()
    expected = set()
    for key, obligation in obligations.items():
        act = acts.get(key)
        claim = None if act is None else connection.execute("SELECT owner_role,deadline_ms FROM claimed_adjustments WHERE claim_id=? AND obligation_id=?", (act[2], key)).fetchone()
        if act is None:
            reason, owner, due = "INITIAL_ACCOUNTABILITY", "CASE_OWNER", obligation["due_at_ms"]
        elif claim is None:
            _fail("case:derived")
        else:
            reason, owner, due = _CASE_ACTS[act[1]], claim[0] if act[1] == "OFFSET_CLAIMED" else "CASE_OWNER", claim[1]
        expected.add((f"case:{key}", key, reason, "PROGRAM_ACCOUNTABILITY", owner, due, _CASE_CONDITIONS, current[key]["case_status"], current[key]["evaluated_at_ms"]))
    if len(rows) != len(expected) or {tuple(row) for row in rows} != expected:
        _fail("case:derived")


def _verify_determinations(
    connection: sqlite3.Connection,
    meta: dict[str, object],
    obligations: dict[str, sqlite3.Row],
    populations: dict[str, sqlite3.Row],
    packs: dict[str, sqlite3.Row],
    claims: dict[str, sqlite3.Row],
    evidence: dict[str, sqlite3.Row],
    evaluations: dict[str, list[sqlite3.Row]],
    *,
    actors: Mapping[str, frozenset[str]] | None,
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "determinations")
    result: dict[str, sqlite3.Row] = {}
    evaluations_by_id = {
        str(evaluation["evaluation_id"]): evaluation
        for history in evaluations.values()
        for evaluation in history
    }
    consumed_evaluations: set[str] = set()
    if not isinstance(actors, Mapping):
        _fail("determination:actor-roster")
    for row in rows:
        determination_id = _id(row["determination_id"], "determination:id")
        if determination_id in result:
            _fail("determination:duplicate")
        result[determination_id] = row
        obligation_id = _id(row["obligation_id"], "determination:obligation")
        claim_id = row["claim_id"]
        if claim_id is not None:
            claim_id = _id(claim_id, "determination:claim-id")
        actor_id = _id(row["actor_id"], "determination:actor")
        actor_role = _role(row["actor_role"], "determination:role")
        if actor_role not in actors.get(actor_id, frozenset()):
            _fail("determination:actor-role")
        obligation = obligations[obligation_id]
        population = populations[str(obligation["population_id"])]
        pack = packs[str(population["pack_id"])]
        authorized_roles = _values_json(pack["authorized_roles_json"], "pack:roles")
        if actor_role not in authorized_roles:
            _fail("determination:pack-role")
        authority_id = _id(row["authority_id"], "determination:authority-id")
        authority_epoch = _integer(row["authority_epoch"], "determination:authority-epoch", minimum=1, maximum=MAX_CENTS)
        authority_digest = _blob64(row["authority_digest"], "determination:authority-digest")
        if (authority_id, authority_epoch, authority_digest) != (meta["authority_id"], meta["authority_epoch"], meta["authority_digest"]):
            _fail("determination:authority")
        decision = row["decision"]
        if decision not in {"OFFSET_AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}:
            _fail("determination:decision")
        amount = _cents(row["amount_cents"], "determination:amount")
        expected_revision = _integer(row["expected_revision"], "determination:expected-revision")
        resulting_revision = _integer(row["resulting_revision"], "determination:resulting-revision")
        if resulting_revision != expected_revision + 1:
            _fail("determination:revision")
        input_evaluation_id = _id(row["input_evaluation_id"], "determination:evaluation-id")
        if input_evaluation_id in consumed_evaluations:
            _fail("determination:evaluation-duplicate")
        consumed_evaluations.add(input_evaluation_id)
        input_evaluation = evaluations_by_id.get(input_evaluation_id)
        if input_evaluation is None or input_evaluation["obligation_id"] != obligation_id or int(input_evaluation["revision"]) != expected_revision:
            _fail("determination:evaluation-binding")
        input_result_digest = _blob64(row["input_evaluation_result_digest"], "determination:evaluation-digest")
        if input_result_digest != bytes(input_evaluation["result_digest"]):
            _fail("determination:evaluation-digest")
        supporting = _evaluation_bindings_json(row["supporting_evidence_json"], "determination:evidence")
        if claim_id is None or len(supporting) != len(_evidence_ids_json(input_evaluation["evidence_ids_json"], "determination:evaluation-evidence")):
            _fail("determination:evidence-binding")
        supporting_ids = [binding["evidence_id"] for binding in supporting]
        if str(claims[str(claim_id)]["evidence_id"]) not in supporting_ids:
            _fail("determination:evidence-binding")
        for binding in supporting:
            if binding["evidence_id"] not in evidence or binding["record_digest"] != bytes(evidence[binding["evidence_id"]]["record_digest"]).hex().upper():
                _fail("determination:evidence-binding")
        claim = claims[str(claim_id)]
        if amount != claim["amount_cents"] or (decision == "OFFSET_AUTHORIZED" and claim["status"] != "AUTHORIZED") or (decision == "OFFSET_REJECTED_CORRECTION_AUTHORIZED" and claim["status"] != "REJECTED"):
            _fail("determination:claim-binding")
        decided = _time(row["decided_at_ms"], "determination:time")
        if int(input_evaluation["evaluated_at_ms"]) > decided:
            _fail("determination:evaluation-chronology")
        kind = "OFFSET_AUTHORIZATION" if decision == "OFFSET_AUTHORIZED" else "CORRECTION_PAYMENT_REQUEST"
        action_id = determination_id.removeprefix("determination:")
        if not action_id or determination_id != f"determination:{action_id}":
            _fail("determination:action-id")
        payload = {
            "action_id": action_id,
            "determination_id": determination_id,
            "obligation_id": obligation_id,
            "kind": kind,
            "claim_id": claim_id,
            "decision": decision,
            "amount_cents": amount,
            "input_evaluation_id": input_evaluation_id,
            "input_evaluation_result_digest": input_result_digest.hex().upper(),
            "actor_id": actor_id,
            "actor_role": actor_role,
            "authority_id": authority_id,
            "authority_epoch": authority_epoch,
            "authority_digest": authority_digest.hex().upper(),
            "supporting_evidence": supporting,
            "expected_revision": expected_revision,
            "resulting_revision": resulting_revision,
            "decided_at_ms": decided,
        }
        expected_digest = _digest(ACTION_DOMAIN, _canonical(payload, "determination:digest-input"))
        if _blob64(row["determination_digest"], "determination:digest") != expected_digest:
            _fail("determination:digest")
    return result


def _verify_actions(
    connection: sqlite3.Connection,
    meta: dict[str, object],
    evaluations: dict[str, list[sqlite3.Row]],
    claims: dict[str, sqlite3.Row],
    determinations: dict[str, sqlite3.Row],
    payments: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "actions")
    outbox_rows = _bounded_rows(connection, "action_outbox")
    outbox = {str(row["action_id"]): row for row in outbox_rows}
    acks = {str(row[0]): int(row[1]) for row in connection.execute("SELECT json_extract(payload_json,'$.action_id'),committed_at_ms FROM financial_events WHERE aggregate_type='OBLIGATION' AND kind='ACTION_ACKNOWLEDGED'")}
    registry = correction_engines()
    current = registry[CORRECTION_TRANSITION_ARTIFACT_SHA256]
    engines: dict[str, tuple[int, str]] = {}  # correction action -> the engine that decided it, by its decision event
    decided: dict[str, object] = {}  # correction action -> the amount its decision event records
    newest = 0
    for action_ref, sha, event_amount in connection.execute("SELECT json_extract(payload_json,'$.action_id'),json_extract(payload_json,'$.correction_followup.artifact.sha256'),json_extract(payload_json,'$.amount_cents') FROM financial_events WHERE aggregate_type='OBLIGATION' AND kind='OFFSET_REJECTED_CORRECTION_AUTHORIZED' ORDER BY event_sequence"):
        engines[action_ref] = engine = registry.get(sha, current)
        if engine[0] < newest:
            _fail("action:engine-order")  # a retired engine never decides after a newer one
        newest = engine[0]
        decided[action_ref] = event_amount
    reversed_at = dict(connection.execute("SELECT json_extract(payload_json,'$.payment_id'),after_revision FROM financial_events WHERE aggregate_type='OBLIGATION' AND kind='PAYMENT_REVERSED'").fetchall())
    links = connection.execute("SELECT aggregate_id,after_revision,json_extract(payload_json,'$.payment_id'),json_extract(payload_json,'$.pays_action_id') FROM financial_events WHERE aggregate_type='OBLIGATION' AND kind='PAYMENT_RECEIVED' AND json_extract(payload_json,'$.pays_action_id') IS NOT NULL").fetchall()
    linked: dict[object, list[tuple[int, object, int]]] = {}  # correction action -> (paid at, reversed at, cents)
    for _obligation, paid_revision, payment_id, action_ref in links:
        if payment_id not in payments:
            _fail("payment:link")
        linked.setdefault(action_ref, []).append((paid_revision, reversed_at.get(payment_id), payments[payment_id]["amount_cents"]))

    def paid_at(action_ref: object, revision: int) -> int:  # what linked payments had paid on the request when revision was decided
        return sum(cents for paid, reversed_revision, cents in linked.get(action_ref, ()) if paid < revision and (reversed_revision is None or reversed_revision >= revision))

    if len(outbox) != len(outbox_rows):
        _fail("outbox:duplicate")
    actions: dict[str, sqlite3.Row] = {}
    requests: dict[str, dict[str, int]] = {}  # per obligation, in revision order: correction request -> amount
    for row in sorted(rows, key=lambda row: (str(row["obligation_id"]), _integer(row["revision"], "action:revision"))):
        action_id = _id(row["action_id"], "action:id")
        if action_id in actions:
            _fail("action:duplicate")
        actions[action_id] = row
        obligation_id = _id(row["obligation_id"], "action:obligation")
        determination_id = _id(row["determination_id"], "action:determination")
        determination = determinations.get(determination_id)
        if determination is None or determination["obligation_id"] != obligation_id:
            _fail("action:determination")
        kind = _kind(row["kind"], "action:kind")
        if kind not in _ACTION_KINDS:
            _fail("action:kind")
        expected_kind = "OFFSET_AUTHORIZATION" if determination["decision"] == "OFFSET_AUTHORIZED" else "CORRECTION_PAYMENT_REQUEST"
        if kind != expected_kind:
            _fail("action:decision-binding")
        if row["status"] not in _ACTION_STATUSES:
            _fail("action:status")
        revision = _integer(row["revision"], "action:revision")
        if revision != determination["resulting_revision"]:
            _fail("action:revision-binding")
        payload = _parse_json(row["payload_json"], "action:payload")
        if not isinstance(payload, dict):
            _fail("action:payload-object")
        claim_id = determination["claim_id"]
        amount = requestable = claims[str(claim_id)]["amount_cents"]
        if kind == "CORRECTION_PAYMENT_REQUEST":  # the input evaluation's unpaid balance, by the deciding engine's rule
            if decided.get(action_id) != amount:
                _fail("action:event-amount")  # the decision event records the rejected claim
            shortfall = _cents(next((e["shortfall_cents"] for e in evaluations.get(obligation_id, ()) if e["evaluation_id"] == determination["input_evaluation_id"]), None), "action:input-shortfall", positive=True)
            earlier = requests.setdefault(obligation_id, {})
            unpaid = sum(max(cents - paid_at(ref, revision), 0) for ref, cents in earlier.items())
            requestable = max(shortfall - unpaid, 0)
            amount = earlier[action_id] = _CORRECTION_AMOUNT_RULES[engines.get(action_id, current)[1]](amount, shortfall, unpaid)
        expected_payload = {
            "action_id": action_id,
            "obligation_id": obligation_id,
            "determination_id": determination_id,
            "kind": kind,
            "claim_id": claim_id,
            "amount_cents": amount,
            "currency": meta["scope"]["currency"],
            "revision": revision,
            "input_evaluation_id": determination["input_evaluation_id"],
            "input_evaluation_result_digest": bytes(determination["input_evaluation_result_digest"]).hex().upper(),
            "dispatch": "SYNTHETIC_RECORD_ONLY",
        }
        if payload != expected_payload:
            _fail("action:payload-binding")
        if amount > requestable:
            _fail("action:requestable")  # whatever engine decided it, never more than earlier requests leave unpaid
        payload_bytes = _canonical(payload, "action:payload")
        payload_digest = _blob64(row["payload_digest"], "action:payload-digest")
        if payload_digest != _digest(ACTION_DOMAIN, payload_bytes):
            _fail("action:payload-digest")
        if _blob64(row["idempotency_key"], "action:idempotency") != _digest(IDEMPOTENCY_DOMAIN, action_id.encode("ascii")):
            _fail("action:idempotency")
        created = _time(row["created_at_ms"], "action:created")
        if created < determination["decided_at_ms"]:
            _fail("action:chronology")
        box = outbox.get(action_id)
        if box is None:
            _fail("outbox:missing")
        if box["status"] != row["status"] or _blob64(box["payload_digest"], "outbox:payload-digest") != payload_digest:
            _fail("outbox:binding")
        acknowledgment = box["acknowledgment_ref"]
        updated = _time(box["updated_at_ms"], "outbox:updated")
        if row["status"] == "READY" and (acknowledgment is not None or box["attempt"] != 0 or updated != created or action_id in acks):
            _fail("outbox:ready")
        if row["status"] == "ACKNOWLEDGED":
            _id(acknowledgment, "outbox:ack")
            if box["attempt"] != 1 or updated > acks.get(action_id, -1):
                _fail("outbox:acknowledged")
    if set(outbox) != set(actions):
        _fail("outbox:orphan")
    for obligation_id, paid_revision, payment_id, action_ref in links:  # a payment pays an earlier request, never past it
        request = requests.get(obligation_id, {}).get(action_ref)
        if request is None or actions[action_ref]["revision"] >= paid_revision or paid_at(action_ref, paid_revision) + payments[payment_id]["amount_cents"] > request:
            _fail("payment:link")
    return actions


def _verify_conflicts(
    connection: sqlite3.Connection,
    obligations: dict[str, sqlite3.Row],
    evidence: dict[str, sqlite3.Row],
    payments: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "financial_conflicts")
    conflicts: dict[str, sqlite3.Row] = {}
    visible = {str(row[0]): int(row[1]) for row in connection.execute("SELECT json_extract(payload_json,'$.conflict_id'),committed_at_ms FROM financial_events WHERE aggregate_type='OBLIGATION' AND kind='PAYMENT_CONFLICT_VISIBLE'")}
    keys: set[tuple[str, str, str]] = set()
    for row in rows:
        conflict_id = _id(row["conflict_id"], "conflict:id")
        if conflict_id in conflicts:
            _fail("conflict:duplicate")
        conflicts[conflict_id] = row
        obligation_id = _id(row["obligation_id"], "conflict:obligation")
        common_origin_id = _id(row["common_origin_id"], "conflict:common-origin")
        candidate_id = _id(row["candidate_evidence_id"], "conflict:candidate")
        candidate = evidence.get(candidate_id)
        if candidate is None or candidate["kind"] != "PAYMENT_CONFIRMATION" or candidate["common_origin_id"] != common_origin_id:
            _fail("conflict:candidate")
        existing_id = row["existing_payment_id"]
        if existing_id is None or str(existing_id) not in payments:
            _fail("conflict:existing-payment")
        existing = payments[str(existing_id)]
        if existing["obligation_id"] != obligation_id or existing["common_origin_id"] != common_origin_id:
            _fail("conflict:existing-binding")
        _cents(row["existing_amount_cents"], "conflict:existing-amount", positive=True)
        _cents(row["candidate_amount_cents"], "conflict:candidate-amount", positive=True)
        if row["existing_amount_cents"] != existing["amount_cents"] or row["candidate_amount_cents"] != candidate["amount_cents"] or row["existing_amount_cents"] == row["candidate_amount_cents"]:
            _fail("conflict:amount")
        if row["reason"] != "CONFLICTING_COMMON_ORIGIN_AMOUNT":
            _fail("conflict:reason")
        if not candidate["received_at_ms"] <= _time(row["visible_at_ms"], "conflict:visible") <= visible.get(conflict_id, -1):
            _fail("conflict:visible")
        key = (obligation_id, common_origin_id, candidate_id)
        if key in keys:
            _fail("conflict:key")
        keys.add(key)
    # Every payment confirmation that is not the persisted payment itself must
    # be either an equal duplicate or an explicitly visible amount conflict.
    obligations_by_item, payments_by_origin = _group(obligations.values(), "item_id"), _group(payments.values(), "obligation_id", "common_origin_id")
    for candidate_id, candidate in evidence.items():
        if candidate["kind"] != "PAYMENT_CONFIRMATION":
            continue
        obligation = obligations_by_item.get(candidate["item_id"], [None])[0]
        if obligation is None:
            _fail("conflict:orphan-confirmation")
        matching = payments_by_origin.get((obligation["obligation_id"], candidate["common_origin_id"]), [])
        if not matching:
            _fail("conflict:unaccounted-confirmation")
        payment = matching[0]
        if payment["evidence_id"] == candidate_id:
            continue
        candidate_key = (str(obligation["obligation_id"]), str(candidate["common_origin_id"]), candidate_id)
        if candidate["amount_cents"] == payment["amount_cents"]:
            if candidate_key in keys:
                _fail("conflict:equal-amount-conflict")
        elif candidate_key not in keys:
            _fail("conflict:missing")
    return conflicts


def _verify_duplicate_evidence(connection: sqlite3.Connection) -> None:
    """A DUPLICATE label names a confirmation on its obligation's item with no payment or conflict of its own that
    repeats the named payment of that obligation (same origin, amount); a forged one would hide a new payment."""
    if connection.execute(
        "SELECT 1 FROM financial_events f WHERE f.kind='PAYMENT_DUPLICATE_EVIDENCE' AND NOT EXISTS (SELECT 1 FROM evidence e "
        "JOIN obligations o ON o.item_id=e.item_id JOIN payments p ON p.obligation_id=o.obligation_id "
        "WHERE f.aggregate_type='OBLIGATION' AND o.obligation_id=f.aggregate_id AND e.kind='PAYMENT_CONFIRMATION' "
        "AND e.evidence_id=json_extract(f.payload_json,'$.candidate_evidence_id') "
        "AND p.payment_id=json_extract(f.payload_json,'$.existing_payment_id') "
        "AND p.common_origin_id=json_extract(f.payload_json,'$.common_origin_id') "
        "AND e.common_origin_id=p.common_origin_id AND e.amount_cents=p.amount_cents "
        "AND NOT EXISTS (SELECT 1 FROM payments WHERE evidence_id=e.evidence_id) "
        "AND NOT EXISTS (SELECT 1 FROM financial_conflicts WHERE candidate_evidence_id=e.evidence_id))"
    ).fetchone() is not None:
        _fail("duplicate-evidence:binding")


def _evaluation_bindings_json(raw: object, code: str) -> list[dict[str, str]]:
    value = _parse_json(raw, code)
    if not isinstance(value, dict) or set(value) != {"bindings"} or not isinstance(value["bindings"], list):
        _fail(f"{code}:shape")
    result: list[dict[str, str]] = []
    for binding in value["bindings"]:
        if not isinstance(binding, dict) or set(binding) != {"evidence_id", "record_digest"}:
            _fail(f"{code}:binding")
        result.append({"evidence_id": _id(binding["evidence_id"], f"{code}:id"), "record_digest": _hex_digest(binding["record_digest"], f"{code}:digest").hex().upper()})
    ids = [binding["evidence_id"] for binding in result]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        _fail(f"{code}:order")
    return result


def _evaluation_result(row: sqlite3.Row, evidence_ids: list[str]) -> dict[str, object]:
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


def _evaluation_receipt_body(
    *,
    row: sqlite3.Row,
    evidence_ids: list[str],
    evidence_bindings: list[dict[str, str]],
    scope: dict[str, object],
    control_pack_id: str,
    control_pack_version: int,
    control_pack_digest: bytes,
    authority_epoch: int,
    authority_digest: bytes,
    input_snapshot_digest: bytes,
) -> dict[str, object]:
    result = _evaluation_result(row, evidence_ids)
    return {
        "contract_version": EVALUATION_RECEIPT_CONTRACT,
        "scope": dict(scope),
        "evaluation_id": row["evaluation_id"],
        "obligation_id": row["obligation_id"],
        "revision": row["revision"],
        "control_pack": {
            "pack_id": control_pack_id,
            "version": control_pack_version,
            "digest": control_pack_digest.hex().upper(),
        },
        "evidence_bindings": evidence_bindings,
        "input_snapshot_digest": input_snapshot_digest.hex().upper(),
        "authority": {
            "authority_id": row["authority_id"],
            "epoch": authority_epoch,
            "digest": authority_digest.hex().upper(),
        },
        **result,
        "result_digest": _blob64(row["result_digest"], "evaluation:result-digest").hex().upper(),
    }


def _evaluation_binding_digest(bindings: list[dict[str, str]]) -> bytes:
    ordered = sorted(
        (
            {
                "evaluation_id": str(binding["evaluation_id"]),
                "input_snapshot_digest": str(binding["input_snapshot_digest"]),
                "result_digest": str(binding["result_digest"]),
                "receipt_digest": str(binding["receipt_digest"]),
            }
            for binding in bindings
        ),
        key=lambda binding: binding["evaluation_id"],
    )
    return _digest(EVALUATION_EVENT_DOMAIN, _canonical({"evaluations": ordered}, "evaluation:event-input"))


def _evaluation_input_snapshot(raw: object, code: str) -> dict[str, object]:
    value = _parse_json(raw, code)
    required = {"pre_revision", "obligation", "evidence", "payments", "claims", "determinations", "cases", "actions", "conflicts"}
    if not isinstance(value, dict) or set(value) != required:
        _fail(f"{code}:shape")
    pre_revision = _integer(value["pre_revision"], f"{code}:pre-revision", maximum=MAX_ROWS)
    obligation_raw = value["obligation"]
    if not isinstance(obligation_raw, dict) or set(obligation_raw) != {"obligation_id", "item_id", "revision", "rule_version", "owed_cents", "due_at_ms", "reporting_complete"}:
        _fail(f"{code}:obligation")
    obligation = {
        "obligation_id": _id(obligation_raw["obligation_id"], f"{code}:obligation-id"),
        "item_id": _id(obligation_raw["item_id"], f"{code}:item-id"),
        "revision": _integer(obligation_raw["revision"], f"{code}:revision", maximum=MAX_ROWS),
        "rule_version": _integer(obligation_raw["rule_version"], f"{code}:rule-version", minimum=1, maximum=MAX_ROWS),
        "owed_cents": _cents(obligation_raw["owed_cents"], f"{code}:owed", positive=True),
        "due_at_ms": _time(obligation_raw["due_at_ms"], f"{code}:due"),
        "reporting_complete": _flag(obligation_raw["reporting_complete"], f"{code}:reporting"),
    }
    if obligation["revision"] != pre_revision:
        _fail(f"{code}:revision")

    def ordered_rows(raw_rows: object, keys: set[str], name: str, identifier: str) -> list[dict[str, object]]:
        if not isinstance(raw_rows, list):
            _fail(f"{code}:{name}")
        rows: list[dict[str, object]] = []
        previous: str | None = None
        for raw_row in raw_rows:
            if not isinstance(raw_row, dict) or set(raw_row) != keys:
                _fail(f"{code}:{name}")
            current = _id(raw_row[identifier], f"{code}:{name}-id")
            if previous is not None and current <= previous:
                _fail(f"{code}:{name}-order")
            previous = current
            rows.append(dict(raw_row))
        return rows

    evidence: list[dict[str, object]] = []
    previous_evidence: str | None = None
    if not isinstance(value["evidence"], list):
        _fail(f"{code}:evidence")
    for raw_evidence in value["evidence"]:
        if not isinstance(raw_evidence, dict) or set(raw_evidence) != {"evidence_id", "record_digest", "event_at_ms", "received_at_ms"}:
            _fail(f"{code}:evidence")
        evidence_id = _id(raw_evidence["evidence_id"], f"{code}:evidence-id")
        if previous_evidence is not None and evidence_id <= previous_evidence:
            _fail(f"{code}:evidence-order")
        previous_evidence = evidence_id
        event_at_ms = _time(raw_evidence["event_at_ms"], f"{code}:evidence-event")
        received_at_ms = _time(raw_evidence["received_at_ms"], f"{code}:evidence-received")
        if event_at_ms > received_at_ms:
            _fail(f"{code}:evidence-chronology")
        evidence.append({"evidence_id": evidence_id, "record_digest": _hex_digest(raw_evidence["record_digest"], f"{code}:evidence-digest").hex().upper(), "event_at_ms": event_at_ms, "received_at_ms": received_at_ms})

    payments = ordered_rows(value["payments"], {"payment_id", "amount_cents", "event_at_ms", "active"}, "payments", "payment_id")
    for payment in payments:
        payment["amount_cents"] = _cents(payment["amount_cents"], f"{code}:payment-amount", positive=True)
        payment["event_at_ms"] = _time(payment["event_at_ms"], f"{code}:payment-event")
        payment["active"] = _flag(payment["active"], f"{code}:payment-active")
    claims = ordered_rows(value["claims"], {"claim_id", "amount_cents", "status"}, "claims", "claim_id")
    for claim in claims:
        claim["amount_cents"] = _cents(claim["amount_cents"], f"{code}:claim-amount", positive=True)
        if claim["status"] not in {"CLAIMED", "AUTHORIZED", "REJECTED"}:
            _fail(f"{code}:claim-status")
    determinations = ordered_rows(value["determinations"], {"determination_id", "decision", "amount_cents", "decided_at_ms"}, "determinations", "determination_id")
    for determination in determinations:
        if determination["decision"] not in {"OFFSET_AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}:
            _fail(f"{code}:determination-decision")
        determination["amount_cents"] = _cents(determination["amount_cents"], f"{code}:determination-amount")
        determination["decided_at_ms"] = _time(determination["decided_at_ms"], f"{code}:determination-time")
    cases = ordered_rows(value["cases"], {"case_id", "status"}, "cases", "case_id")
    for case in cases:
        if case["status"] not in _CASE_STATUSES:
            _fail(f"{code}:case-status")
    actions = ordered_rows(value["actions"], {"action_id", "status", "created_at_ms"}, "actions", "action_id")
    for action in actions:
        if action["status"] not in _ACTION_STATUSES:
            _fail(f"{code}:action-status")
        action["created_at_ms"] = _time(action["created_at_ms"], f"{code}:action-created")
    conflicts = value["conflicts"]
    if not isinstance(conflicts, list):
        _fail(f"{code}:conflicts")
    normalized_conflicts: list[str] = []
    previous_conflict: str | None = None
    for conflict in conflicts:
        conflict_id = _id(conflict, f"{code}:conflict-id")
        if previous_conflict is not None and conflict_id <= previous_conflict:
            _fail(f"{code}:conflict-order")
        previous_conflict = conflict_id
        normalized_conflicts.append(conflict_id)
    return {
        "pre_revision": pre_revision,
        "obligation": obligation,
        "evidence": evidence,
        "payments": payments,
        "claims": claims,
        "determinations": determinations,
        "cases": cases,
        "actions": actions,
        "conflicts": normalized_conflicts,
    }


# The case status an evaluation starts from is set by the history that produced it, never
# read back from the stored case (a correction writes Lean's answer there): publishing and a
# claim open the case, a decision latches its own status, and any other evaluation continues
# the previous evaluation's status. An outstanding correction outlasts a later claim or decision.
_CASE_LATCHES = {"OFFSET_CLAIMED": "OPEN", "OFFSET_AUTHORIZED": "AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED": "CORRECTION_REQUIRED"}


def _evaluation_event_kinds(connection: sqlite3.Connection, obligation_id: str | None = None) -> dict[str, str]:
    """evaluation_id -> the kind of the obligation event that produced it."""
    sql = "SELECT json_extract(payload_json,'$.evaluation_id'),kind FROM financial_events WHERE aggregate_type='OBLIGATION'"
    rows = connection.execute(sql) if obligation_id is None else connection.execute(sql + " AND aggregate_id=?", (obligation_id,))
    return {str(row[0]): str(row[1]) for row in rows if row[0] is not None}


def _evaluation_projection_from_input(
    snapshot: dict[str, object],
    *,
    evaluation: sqlite3.Row,
    action_revisions: dict[str, int],
    latch: str,
) -> dict[str, object]:
    obligation = snapshot["obligation"]
    assert isinstance(obligation, dict)
    evidence = snapshot["evidence"]
    payments = snapshot["payments"]
    claims = snapshot["claims"]
    determinations = snapshot["determinations"]
    actions = snapshot["actions"]
    conflicts = snapshot["conflicts"]
    assert isinstance(evidence, list) and isinstance(payments, list) and isinstance(claims, list)
    assert isinstance(determinations, list) and isinstance(actions, list) and isinstance(conflicts, list)
    cash = _sum_cents((int(row["amount_cents"]) for row in payments if row["active"] == 1), "evaluation-input:cash")
    claimed = _sum_cents((int(row["amount_cents"]) for row in claims if row["status"] in {"CLAIMED", "AUTHORIZED"}), "evaluation-input:claimed")
    lawful = _sum_cents((int(row["amount_cents"]) for row in claims if row["status"] == "AUTHORIZED"), "evaluation-input:lawful")
    total = _add_cents(cash, lawful, "evaluation-input:total")
    owed = int(obligation["owed_cents"])
    shortfall = max(owed - total, 0)
    overage = max(total - owed, 0)
    entries = [
        (int(row["decided_at_ms"]), int(row["amount_cents"]))
        for row in determinations
        if row["decision"] == "OFFSET_AUTHORIZED"
    ]
    entries.extend(
        (int(row["event_at_ms"]), int(row["amount_cents"]))
        for row in payments
        if row["active"] == 1
    )
    completion: int | None = None
    running_total = 0
    for at_ms, amount in sorted(entries, key=lambda value: (value[0], value[1])):
        running_total = _add_cents(running_total, amount, "evaluation-input:completion")
        if running_total >= owed:
            completion = at_ms
            break
    if completion is None and _add_cents(lawful, cash, "evaluation-input:completion-total") >= owed and entries:
        completion = max(value[0] for value in entries)
    amount_satisfied = int(total >= owed)
    cash_satisfied = int(cash >= owed)
    if amount_satisfied and int(obligation["reporting_complete"]):
        case_status = "RESOLVED"
    elif amount_satisfied:
        case_status = "ACTIONED"
    elif latch in {"CORRECTION_REQUIRED", "AUTHORIZED"}:
        case_status = latch
    else:
        case_status = "OPEN"
    delivery = "NONE" if not actions else str(
        max(actions, key=lambda row: (action_revisions[str(row["action_id"])], str(row["action_id"])))["status"]
    )
    return {
        "revision": int(evaluation["revision"]),
        "rule_version": int(obligation["rule_version"]),
        "evidence_ids": [str(row["evidence_id"]) for row in evidence],
        "owed_cents": owed,
        "claimed_adjustment_cents": claimed,
        "lawful_adjustment_cents": lawful,
        "received_cash_cents": cash,
        "shortfall_cents": shortfall,
        "overage_cents": overage,
        "cash_satisfied": cash_satisfied,
        "amount_satisfied": amount_satisfied,
        "timely": int(completion is not None and completion <= int(obligation["due_at_ms"])),
        "reporting_complete": int(obligation["reporting_complete"]),
        "verification_status": "CONFLICT_VISIBLE" if conflicts else ("SUPPORTED" if evidence else "MISSING_EVIDENCE"),
        "case_status": case_status,
        "delivery_status": delivery,
    }


def _verify_evaluations(
    connection: sqlite3.Connection,
    meta: dict[str, object],
    obligations: dict[str, sqlite3.Row],
    populations: dict[str, sqlite3.Row],
    packs: dict[str, sqlite3.Row],
    evidence: dict[str, sqlite3.Row],
) -> dict[str, list[sqlite3.Row]]:
    by_obligation: dict[str, list[sqlite3.Row]] = {}
    event_kinds = _evaluation_event_kinds(connection)
    for row in _bounded_rows(connection, "evaluations"):
        obligation_id, _snapshot = _verify_evaluation_row(connection, meta, row, obligations, populations, packs, evidence, event_kinds)
        by_obligation.setdefault(obligation_id, []).append(row)
    for obligation_id, obligation in obligations.items():
        values = sorted(by_obligation.get(obligation_id, []), key=lambda row: row["revision"])
        if [row["revision"] for row in values] != list(range(int(obligation["revision"]) + 1)):
            _fail("evaluation:revision-chain")
        if not values:
            _fail("evaluation:missing")
        initial = values[0]
        if initial["owed_cents"] != obligation["owed_cents"] or initial["claimed_adjustment_cents"] != 0 or initial["lawful_adjustment_cents"] != 0 or initial["received_cash_cents"] != 0 or initial["shortfall_cents"] != obligation["owed_cents"] or initial["overage_cents"] != 0 or initial["cash_satisfied"] != 0 or initial["amount_satisfied"] != 0 or initial["timely"] != 0 or initial["reporting_complete"] != 0 or initial["verification_status"] != "MISSING_EVIDENCE" or initial["case_status"] != "OPEN" or initial["delivery_status"] != "NONE":
            _fail("evaluation:initial")
    return by_obligation


def _verify_evaluation_row(
    connection: sqlite3.Connection,
    meta: dict[str, object],
    row: sqlite3.Row,
    obligations: Mapping[str, sqlite3.Row],
    populations: Mapping[str, sqlite3.Row],
    packs: Mapping[str, sqlite3.Row],
    evidence: Mapping[str, sqlite3.Row],
    event_kinds: Mapping[str, str],
) -> tuple[str, dict[str, object]]:
    """One evaluation receipt: its input binds to the rows it names and recomputes to its values."""
    evaluation_id = _id(row["evaluation_id"], "evaluation:id")
    obligation_id = _id(row["obligation_id"], "evaluation:obligation")
    obligation = obligations[obligation_id]
    revision = _integer(row["revision"], "evaluation:revision")
    if evaluation_id != f"evaluation:{obligation_id}:r{revision}":
        _fail("evaluation:id-binding")
    if row["rule_version"] != obligation["rule_version"]:
        _fail("evaluation:rule")
    population = populations.get(str(obligation["population_id"]))
    if population is None:
        _fail("evaluation:population")
    pack = packs.get(str(population["pack_id"]))
    if pack is None or row["control_pack_id"] != pack["pack_id"] or row["control_pack_version"] != pack["version"] or _blob64(row["control_pack_digest"], "evaluation:pack-digest") != bytes(pack["pack_digest"]):
        _fail("evaluation:control-pack")
    if row["contract_version"] != EVALUATION_RECEIPT_CONTRACT:
        _fail("evaluation:contract")
    scope = _parse_json(row["scope_json"], "evaluation:scope")
    if not isinstance(scope, dict) or scope != meta["scope"]:
        _fail("evaluation:scope")
    evidence_ids = _evidence_ids_json(row["evidence_ids_json"], "evaluation:evidence")
    for evidence_id in evidence_ids:
        if evidence_id not in evidence or evidence[evidence_id]["item_id"] != obligation["item_id"]:
            _fail("evaluation:evidence-binding")
    evidence_bindings = _evaluation_bindings_json(row["evidence_bindings_json"], "evaluation:evidence-bindings")
    if [binding["evidence_id"] for binding in evidence_bindings] != evidence_ids:
        _fail("evaluation:evidence-bindings")
    for binding in evidence_bindings:
        if binding["record_digest"] != bytes(evidence[binding["evidence_id"]]["record_digest"]).hex().upper():
            _fail("evaluation:evidence-bindings")
    authority_id = _id(row["authority_id"], "evaluation:authority-id")
    authority_epoch = _integer(row["authority_epoch"], "evaluation:authority-epoch", minimum=1, maximum=MAX_CENTS)
    authority_digest = _blob64(row["authority_digest"], "evaluation:authority-digest")
    if (authority_id, authority_epoch, authority_digest) != (meta["authority_id"], meta["authority_epoch"], meta["authority_digest"]):
        _fail("evaluation:authority")
    evaluated_at_ms = _time(row["evaluated_at_ms"], "evaluation:time")
    snapshot = _evaluation_input_snapshot(row["input_snapshot_json"], "evaluation:input")
    input_snapshot_digest = _blob64(row["input_snapshot_digest"], "evaluation:input-digest")
    if input_snapshot_digest != _digest(EVALUATION_INPUT_DOMAIN, _canonical(snapshot, "evaluation:input-digest-input")):
        _fail("evaluation:input-digest")
    snapshot_obligation = snapshot["obligation"]
    assert isinstance(snapshot_obligation, dict)
    expected_pre_revision = revision if revision == 0 else revision - 1
    if snapshot["pre_revision"] != expected_pre_revision or snapshot_obligation["obligation_id"] != obligation_id or snapshot_obligation["item_id"] != obligation["item_id"] or snapshot_obligation["rule_version"] != obligation["rule_version"] or snapshot_obligation["owed_cents"] != obligation["owed_cents"] or snapshot_obligation["due_at_ms"] != obligation["due_at_ms"]:
        _fail("evaluation:input-binding")
    snapshot_evidence = snapshot["evidence"]
    assert isinstance(snapshot_evidence, list)
    if [str(item["evidence_id"]) for item in snapshot_evidence] != evidence_ids:
        _fail("evaluation:input-evidence")
    for item in snapshot_evidence:
        evidence_row = evidence.get(str(item["evidence_id"]))
        if evidence_row is None or evidence_row["item_id"] != obligation["item_id"] or str(item["record_digest"]) != bytes(evidence_row["record_digest"]).hex().upper() or int(item["event_at_ms"]) != int(evidence_row["event_at_ms"]) or int(item["received_at_ms"]) != int(evidence_row["received_at_ms"]):
            _fail("evaluation:input-evidence")
        if int(item["received_at_ms"]) > evaluated_at_ms:
            _fail("evaluation:evidence-chronology")
    for item in snapshot["payments"]:
        payment = connection.execute("SELECT obligation_id,amount_cents,event_at_ms FROM payments WHERE payment_id=?", (item["payment_id"],)).fetchone()
        if payment is None or payment["obligation_id"] != obligation_id or int(payment["amount_cents"]) != int(item["amount_cents"]) or int(payment["event_at_ms"]) != int(item["event_at_ms"]):
            _fail("evaluation:input-payment")
    for item in snapshot["claims"]:
        claim = connection.execute("SELECT obligation_id,amount_cents FROM claimed_adjustments WHERE claim_id=?", (item["claim_id"],)).fetchone()
        if claim is None or claim["obligation_id"] != obligation_id or int(claim["amount_cents"]) != int(item["amount_cents"]):
            _fail("evaluation:input-claim")
    for item in snapshot["determinations"]:
        determination = connection.execute("SELECT obligation_id,decision,amount_cents,decided_at_ms FROM determinations WHERE determination_id=?", (item["determination_id"],)).fetchone()
        if determination is None or determination["obligation_id"] != obligation_id or determination["decision"] != item["decision"] or int(determination["amount_cents"]) != int(item["amount_cents"]) or int(determination["decided_at_ms"]) != int(item["decided_at_ms"]):
            _fail("evaluation:input-determination")
    for item in snapshot["cases"]:
        case = connection.execute("SELECT obligation_id FROM cases WHERE case_id=?", (item["case_id"],)).fetchone()
        if case is None or case["obligation_id"] != obligation_id:
            _fail("evaluation:input-case")
    snapshot_action_revisions: dict[str, int] = {}
    for item in snapshot["actions"]:
        action = connection.execute("SELECT obligation_id,created_at_ms,revision FROM actions WHERE action_id=?", (item["action_id"],)).fetchone()
        if action is None or action["obligation_id"] != obligation_id or int(action["created_at_ms"]) != int(item["created_at_ms"]):
            _fail("evaluation:input-action")
        snapshot_action_revisions[str(item["action_id"])] = _integer(
            action["revision"], "evaluation:input-action-revision"
        )
    for conflict_id in snapshot["conflicts"]:
        conflict = connection.execute("SELECT obligation_id FROM financial_conflicts WHERE conflict_id=?", (conflict_id,)).fetchone()
        if conflict is None or conflict["obligation_id"] != obligation_id:
            _fail("evaluation:input-conflict")
    latch = "OPEN" if revision == 0 else _CASE_LATCHES.get(event_kinds.get(evaluation_id, ""))
    if revision and latch != "CORRECTION_REQUIRED":
        previous = connection.execute("SELECT case_status FROM evaluations WHERE evaluation_id=?", (f"evaluation:{obligation_id}:r{revision - 1}",)).fetchone()
        if previous is None:
            _fail("evaluation:revision-chain")
        latch = str(previous[0]) if latch is None or previous[0] == "CORRECTION_REQUIRED" else latch
    input_projection = _evaluation_projection_from_input(
        snapshot,
        evaluation=row,
        action_revisions=snapshot_action_revisions,
        latch=latch,
    )
    if evidence_ids != input_projection["evidence_ids"]:
        _fail("evaluation:input-projection:evidence_ids")
    for key in ("revision", "rule_version", "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely", "reporting_complete", "verification_status", "case_status", "delivery_status"):
        if row[key] != input_projection[key]:
            _fail(f"evaluation:input-projection:{key}")
    for key in ("owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents"):
        _cents(row[key], f"evaluation:{key}")
    for key in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
        _flag(row[key], f"evaluation:{key}")
    if row["verification_status"] not in _EVALUATION_VERIFICATION or row["case_status"] not in _CASE_STATUSES or row["delivery_status"] not in _DELIVERY_STATUSES:
        _fail("evaluation:status")
    expected_digest = _digest(EVALUATION_RESULT_DOMAIN, _canonical(_evaluation_result(row, evidence_ids), "evaluation:digest-input"))
    if _blob64(row["result_digest"], "evaluation:digest") != expected_digest:
        _fail("evaluation:digest")
    receipt_body = _evaluation_receipt_body(
        row=row,
        evidence_ids=evidence_ids,
        evidence_bindings=evidence_bindings,
        scope=scope,
        control_pack_id=str(pack["pack_id"]),
        control_pack_version=int(pack["version"]),
        control_pack_digest=bytes(pack["pack_digest"]),
        authority_epoch=authority_epoch,
        authority_digest=authority_digest,
        input_snapshot_digest=input_snapshot_digest,
    )
    if _blob64(row["receipt_digest"], "evaluation:receipt-digest") != _digest(EVALUATION_RECEIPT_DOMAIN, _canonical(receipt_body, "evaluation:receipt-input")):
        _fail("evaluation:receipt-digest")
    return obligation_id, snapshot


# The obligation's rows as an evaluation input names them, read now (same order and form).
_EXACT_INPUT_SQL = {
    "evidence": "SELECT evidence_id,record_digest,event_at_ms,received_at_ms FROM evidence WHERE item_id=? ORDER BY evidence_id",
    "payments": "SELECT payment_id,amount_cents,event_at_ms,active FROM payments WHERE obligation_id=? ORDER BY payment_id",
    "claims": "SELECT claim_id,amount_cents,status FROM claimed_adjustments WHERE obligation_id=? ORDER BY claim_id",
    "determinations": "SELECT determination_id,decision,amount_cents,decided_at_ms FROM determinations WHERE obligation_id=? ORDER BY determination_id",
    "actions": "SELECT action_id,status,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id",
    "conflicts": "SELECT conflict_id FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id",
}


def _verify_exact_input(connection: sqlite3.Connection, obligation: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    """The current evaluation saw exactly the obligation's rows as they are now; a repeated payment
    confirmation its own event names is stored without a new evaluation (it changes no value)."""
    current: dict[str, object] = {
        "pre_revision": snapshot["pre_revision"],
        "obligation": {**{key: obligation[key] for key in ("obligation_id", "item_id", "rule_version", "owed_cents", "due_at_ms", "reporting_complete")}, "revision": snapshot["pre_revision"]},
    }
    repeats = {str(row[0]) for row in connection.execute("SELECT json_extract(payload_json,'$.candidate_evidence_id') FROM financial_events WHERE aggregate_type='OBLIGATION' AND kind='PAYMENT_DUPLICATE_EVIDENCE' AND aggregate_id=?", (obligation["obligation_id"],))}
    for key, sql in _EXACT_INPUT_SQL.items():
        values = [dict(value) for value in connection.execute(sql, (obligation["item_id" if key == "evidence" else "obligation_id"],))]
        for value in values:
            if "record_digest" in value:
                value["record_digest"] = bytes(value["record_digest"]).hex().upper()
        if key == "evidence":
            values = [value for value in values if value in snapshot["evidence"] or value["evidence_id"] not in repeats]
        current[key] = [value["conflict_id"] for value in values] if key == "conflicts" else values
    for key, value in current.items():
        if snapshot[key] != value:
            _fail(f"obligation:exact-input:{key}")


def verify_obligation_connection(connection: sqlite3.Connection, obligation_id: str, **expected: Any) -> dict[str, object]:
    """Per-obligation mode, run before COMMIT: the current evaluation was computed
    from exactly the obligation's rows as they are now, recomputes to its values,
    and the obligation's projection equals it. Takes verify_database's expected_*
    keywords; the whole-database mode stays the open and audit check."""

    keys = ("expected_config", "expected_scope", "expected_authority", "expected_mode", "expected_owner_id", "expected_continuity_epoch")
    if not isinstance(connection, sqlite3.Connection):
        _fail("database:connection")
    if not set(expected) <= set(keys):
        _fail("identity:expectation")
    identity = _identity(**{key: expected.get(key) for key in keys})

    def check() -> dict[str, object]:
        meta = _verify_meta(connection, identity, _verify_schema(connection))
        obligation = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (_id(obligation_id, "obligation:id"),)).fetchone()
        if obligation is None:
            _fail("obligation:missing")
        row = connection.execute("SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?", (obligation["current_evaluation_id"], obligation_id)).fetchone()
        if row is None:
            _fail("obligation:current-evaluation")
        population = connection.execute("SELECT * FROM population_imports WHERE population_id=?", (obligation["population_id"],)).fetchone()
        populations = {} if population is None else {str(population["population_id"]): population}
        pack = None if population is None else connection.execute("SELECT * FROM control_packs WHERE pack_id=?", (population["pack_id"],)).fetchone()
        packs = {} if pack is None else {str(pack["pack_id"]): pack}
        evidence = {str(value["evidence_id"]): value for value in connection.execute("SELECT * FROM evidence WHERE item_id=?", (obligation["item_id"],))}
        _, snapshot = _verify_evaluation_row(connection, meta, row, {obligation_id: obligation}, populations, packs, evidence, _evaluation_event_kinds(connection, obligation_id))
        _verify_exact_input(connection, obligation, snapshot)
        _verify_cases(connection, {obligation_id: obligation}, {obligation_id: row}, obligation_id)
        for key in ("revision", "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely", "reporting_complete", "verification_status", "case_status", "delivery_status"):
            if obligation[key] != row[key]:
                _fail(f"obligation:projection:{key}")
        if obligation["updated_at_ms"] != row["evaluated_at_ms"]:
            _fail("obligation:projection:updated_at_ms")
        return {"obligation_id": obligation_id, "revision": int(row["revision"]), "evaluation_id": str(row["evaluation_id"]), "result_digest": bytes(row["result_digest"]).hex().upper()}

    return _mapped(check)


def _verify_evaluation_history_events(
    events: list[sqlite3.Row],
    populations: dict[str, sqlite3.Row],
    obligations: dict[str, sqlite3.Row],
    evaluations: dict[str, list[sqlite3.Row]],
) -> None:
    evaluations_by_id = {
        str(row["evaluation_id"]): row
        for history in evaluations.values()
        for row in history
    }
    seen: set[str] = set()
    for event in events:
        payload = _parse_json(event["payload_json"], "history:evaluation-payload")
        if not isinstance(payload, dict):
            _fail("history:evaluation-payload")
        if event["aggregate_type"] == "POPULATION" and event["kind"] == "POPULATION_PUBLISHED":
            population_id = str(event["aggregate_id"])
            expected_bindings = [
                {
                    "evaluation_id": str(row["evaluation_id"]),
                    "input_snapshot_digest": _blob64(row["input_snapshot_digest"], "history:evaluation-input-digest").hex().upper(),
                    "result_digest": _blob64(row["result_digest"], "history:evaluation-result-digest").hex().upper(),
                    "receipt_digest": _blob64(row["receipt_digest"], "history:evaluation-receipt-digest").hex().upper(),
                }
                for obligation_id, history in evaluations.items()
                if str(obligations[obligation_id]["population_id"]) == population_id
                for row in history
                if int(row["revision"]) == 0
            ]
            expected_digest = _evaluation_binding_digest(expected_bindings)
            if _integer(payload["evaluation_count"], "history:population-evaluation-count", minimum=0, maximum=MAX_ROWS) != len(expected_bindings) or _hex_digest(payload["evaluation_binding_digest"], "history:population-evaluation-digest") != expected_digest:
                _fail("history:evaluation-binding")
            for binding in expected_bindings:
                evaluation_id = binding["evaluation_id"]
                if evaluation_id in seen:
                    _fail("history:evaluation-duplicate")
                seen.add(evaluation_id)
            continue
        if event["aggregate_type"] != "OBLIGATION" or "evaluation_id" not in payload:
            continue
        required = {"evaluation_id", "evaluation_input_digest", "evaluation_result_digest", "evaluation_receipt_digest"}
        if not required <= set(payload):
            _fail("history:evaluation-binding")
        evaluation_id = _id(payload["evaluation_id"], "history:evaluation-id")
        row = evaluations_by_id.get(evaluation_id)
        if row is None or str(row["obligation_id"]) != str(event["aggregate_id"]):
            _fail("history:evaluation-binding")
        if int(row["revision"]) != int(event["after_revision"]):
            _fail("history:evaluation-binding")
        expected = {
            "evaluation_input_digest": _blob64(row["input_snapshot_digest"], "history:evaluation-input-digest").hex().upper(),
            "evaluation_result_digest": _blob64(row["result_digest"], "history:evaluation-result-digest").hex().upper(),
            "evaluation_receipt_digest": _blob64(row["receipt_digest"], "history:evaluation-receipt-digest").hex().upper(),
        }
        if any(str(payload[key]) != value for key, value in expected.items()):
            _fail("history:evaluation-binding")
        if evaluation_id in seen:
            _fail("history:evaluation-duplicate")
        seen.add(evaluation_id)
    if seen != set(evaluations_by_id):
        _fail("history:evaluation-missing")


def _completion_time(
    obligation: sqlite3.Row,
    payments: list[sqlite3.Row],
    determinations: list[sqlite3.Row],
) -> int | None:
    entries: list[tuple[int, int]] = [
        (int(row["decided_at_ms"]), int(row["amount_cents"]))
        for row in determinations
        if row["decision"] == "OFFSET_AUTHORIZED"
    ]
    entries.extend(
        (int(row["event_at_ms"]), int(row["amount_cents"]))
        for row in payments
        if row["active"] == 1
    )
    total = 0
    for at_ms, amount in sorted(entries, key=lambda value: (value[0], value[1])):
        total = _add_cents(total, amount, "projection:completion-overflow")
        if total >= obligation["owed_cents"]:
            return at_ms
    lawful = _sum_cents(
        [int(row["amount_cents"]) for row in determinations if row["decision"] == "OFFSET_AUTHORIZED"],
        "projection:lawful",
    )
    cash = _sum_cents([int(row["amount_cents"]) for row in payments if row["active"] == 1], "projection:cash")
    if _add_cents(lawful, cash, "projection:completion-total") >= obligation["owed_cents"] and entries:
        return max(value[0] for value in entries)
    return None


def _verify_projections(
    meta: dict[str, object],
    obligations: dict[str, sqlite3.Row],
    populations: dict[str, sqlite3.Row],
    packs: dict[str, sqlite3.Row],
    evidence: dict[str, sqlite3.Row],
    payments: dict[str, sqlite3.Row],
    claims: dict[str, sqlite3.Row],
    determinations: dict[str, sqlite3.Row],
    actions: dict[str, sqlite3.Row],
    conflicts: dict[str, sqlite3.Row],
    evaluations: dict[str, list[sqlite3.Row]],
) -> tuple[dict[str, dict[str, object]], dict[str, int]]:
    projections: dict[str, dict[str, object]] = {}
    totals = {"owed_cents": 0, "received_cash_cents": 0, "lawful_adjustment_cents": 0, "shortfall_cents": 0}
    determinations_by_obligation: dict[str, list[sqlite3.Row]] = {}
    for row in determinations.values():
        determinations_by_obligation.setdefault(str(row["obligation_id"]), []).append(row)
    payments_by, claims_by, evidence_by, conflicts_by, actions_by = (_group(rows.values(), column) for rows, column in (
        (payments, "obligation_id"), (claims, "obligation_id"), (evidence, "item_id"), (conflicts, "obligation_id"), (actions, "obligation_id")))
    for obligation_id, obligation in obligations.items():
        population = populations[str(obligation["population_id"])]
        pack = packs[str(population["pack_id"])]
        authorized_roles = _values_json(pack["authorized_roles_json"], "pack:roles")
        calculation, adjustment = _control_pack_policy(pack["calculation_rule_id"], pack["adjustment_rule_id"], authorized_roles, _values_json(pack["expected_tests_json"], "pack:tests"))
        if calculation != "PER_RECIPIENT" or adjustment != "AUTHORIZED_OFFSET":
            _fail("projection:policy")
        active_payments = [row for row in payments_by.get(obligation_id, []) if row["active"] == 1]
        obligation_claims = claims_by.get(obligation_id, [])
        cash = _sum_cents([int(row["amount_cents"]) for row in active_payments], "projection:cash")
        claimed = _sum_cents([int(row["amount_cents"]) for row in obligation_claims if row["status"] in {"CLAIMED", "AUTHORIZED"}], "projection:claimed")
        lawful = _sum_cents([int(row["amount_cents"]) for row in obligation_claims if row["status"] == "AUTHORIZED"], "projection:lawful")
        total = _add_cents(cash, lawful, "projection:total")
        owed = int(obligation["owed_cents"])
        shortfall = max(owed - total, 0)
        overage = max(total - owed, 0)
        evidence_count = len(evidence_by.get(obligation["item_id"], []))
        conflict_count = len(conflicts_by.get(obligation_id, []))
        verification = "CONFLICT_VISIBLE" if conflict_count else ("SUPPORTED" if evidence_count else "MISSING_EVIDENCE")
        completion = _completion_time(obligation, active_payments, determinations_by_obligation.get(obligation_id, []))
        timely = int(completion is not None and completion <= obligation["due_at_ms"])
        amount_satisfied = int(total >= owed)
        cash_satisfied = int(cash >= owed)
        reporting_complete = int(obligation["reporting_complete"])
        action_rows = actions_by.get(obligation_id, [])
        delivery = "NONE" if not action_rows else str(
            max(action_rows, key=lambda row: (row["revision"], row["action_id"]))["status"]
        )
        current = max(evaluations.get(obligation_id, []), key=lambda row: row["revision"])
        expected = {
            "revision": obligation["revision"],
            "owed_cents": owed,
            "claimed_adjustment_cents": claimed,
            "lawful_adjustment_cents": lawful,
            "received_cash_cents": cash,
            "shortfall_cents": shortfall,
            "overage_cents": overage,
            "cash_satisfied": cash_satisfied,
            "amount_satisfied": amount_satisfied,
            "timely": timely,
            "reporting_complete": reporting_complete,
            "verification_status": verification,
            "case_status": current["case_status"],
            "delivery_status": delivery,
            "current_evaluation_id": obligation["current_evaluation_id"],
        }
        for key, value in expected.items():
            if obligation[key] != value:
                _fail(f"projection:{key}")
        if obligation["current_evaluation_id"] != current["evaluation_id"] or current["revision"] != obligation["revision"]:
            _fail("projection:current-evaluation")
        if obligation["updated_at_ms"] != current["evaluated_at_ms"]:
            _fail("projection:updated-at")
        for key in (
            "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents",
            "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely",
            "reporting_complete", "verification_status", "case_status", "delivery_status",
        ):
            if current[key] != expected[key]:
                _fail(f"projection:evaluation:{key}")
        projection = {
            "obligation_id": obligation_id,
            "item_id": obligation["item_id"],
            "population_id": obligation["population_id"],
            **expected,
            "due_at_ms": obligation["due_at_ms"],
        }
        projections[obligation_id] = projection
        for key, value in (("owed_cents", owed), ("received_cash_cents", cash), ("lawful_adjustment_cents", lawful), ("shortfall_cents", shortfall)):
            totals[key] = _add_cents(totals[key], value, f"projection:total:{key}")
    return projections, totals


def _verify_event_references(
    events: list[sqlite3.Row],
    packs: dict[str, sqlite3.Row],
    populations: dict[str, sqlite3.Row],
    obligations: dict[str, sqlite3.Row],
    funding_receipt_ids: set[str],
    manifest_ids: set[str],
) -> None:
    for row in events:
        aggregate_type = row["aggregate_type"]
        aggregate_id = row["aggregate_id"]
        if aggregate_type == "CONTROL_PACK" and aggregate_id not in packs:
            _fail("history:pack-reference")
        if aggregate_type == "POPULATION" and aggregate_id not in populations:
            _fail("history:population-reference")
        if aggregate_type == "POPULATION_MANIFEST" and aggregate_id not in manifest_ids:
            _fail("history:population-manifest-reference")
        if aggregate_type == "OBLIGATION" and aggregate_id not in obligations:
            _fail("history:obligation-reference")
        if aggregate_type == "PROGRAM_FUNDING_RECEIPT" and aggregate_id not in funding_receipt_ids:
            _fail("history:funding-reference")


def _package_payload_without_digest(value: Mapping[str, object]) -> dict[str, object]:
    if "package_digest" not in value:
        _fail("continuity:digest-field")
    payload = dict(value)
    del payload["package_digest"]
    return payload


def continuity_package_digest(payload: Mapping[str, object]) -> str:
    """Return the independent digest for a package payload without its digest."""

    if not isinstance(payload, Mapping):
        _fail("continuity:payload")
    if "package_digest" in payload:
        _fail("continuity:digest-field")
    package_format = _PACKAGE_FORMATS.get(payload.get("version")) if type(payload.get("version")) is int else None
    domain = CONTINUITY_DOMAIN if package_format is None else package_format[2]
    return _digest(domain, _canonical(dict(payload), "continuity:digest-input")).hex().upper()


def _verify_commands(rows: Mapping[str, Sequence[Mapping[str, object]]], code: str) -> None:
    """Recompute the command log from the history and the rows each request wrote."""

    indexes: dict[tuple[str, str], dict[object, Mapping[str, object]]] = {}
    expected: dict[str, tuple[str, str, bytes, int]] = {}
    for event in sorted(rows["financial_events"], key=lambda event: int(event["event_sequence"])):
        kind = _COMMAND_EVENT_KINDS.get(str(event["kind"]))
        if kind is None:
            continue
        _events, field, joins, columns = _COMMAND_SOURCES[kind]
        if field is None:
            key = event["aggregate_id"]
        else:
            payload = _parse_json(event["payload_json"], f"{code}:event-payload")
            key = payload.get(field) if isinstance(payload, dict) else None
        if type(key) is not str:
            _fail(f"{code}:key")
        found: dict[str, Mapping[str, object]] = {}
        for join in joins.split():
            alias, _, target = join.partition("=")
            source, _, via = target.partition("<")
            table, _, column = source.partition(".")
            if (table, column) not in indexes:
                indexes[(table, column)] = {row[column]: row for row in rows[table]}
            via_alias, _, via_column = via.partition(".")
            row = indexes[(table, column)].get(found[via_alias][via_column] if via else key)
            if row is None:
                _fail(f"{code}:source")
            found[alias] = row
        fields: dict[str, object] = {}
        for entry in columns.split():
            name, _, source = entry.rpartition("=")
            alias, _, column = source.partition(".")
            value = found[alias][column]
            fields[name or column] = value.hex().upper() if type(value) is bytes else value
        command_id = f"{kind}:{key}"
        if command_id in expected:
            _fail(f"{code}:duplicate")
        request_json = _canonical({"command": kind, "key": key, **fields}, f"{code}:request")
        expected[command_id] = (kind, request_json.decode("ascii"), _digest(COMMAND_DOMAIN, request_json), int(event["event_sequence"]))
    actual: dict[object, tuple[object, object, object, object]] = {}
    for command in rows["commands"]:
        if command["command_id"] in actual:
            _fail(f"{code}:duplicate")
        actual[command["command_id"]] = (command["kind"], command["request_json"], command["request_digest"], command["event_sequence"])
    if actual != expected:
        _fail(f"{code}:mismatch")


def _package_import_value(value: object, code: str) -> object:
    """Decode the owner's bounded JSON representation of one SQLite value."""

    if type(value) is dict:
        if set(value) != {"hex"} or type(value["hex"]) is not str:
            _fail(f"{code}:hex")
        encoded = value["hex"]
        if len(encoded) % 2 or re.fullmatch(r"[0-9A-Fa-f]*", encoded) is None:
            _fail(f"{code}:hex")
        try:
            return bytes.fromhex(encoded)
        except ValueError:
            _fail(f"{code}:hex")
    if value is None or type(value) in {str, int, float, bool}:
        return value
    _fail(f"{code}:value")


def _verify_package_rows(raw_rows: object, table: str) -> list[dict[str, object]]:
    if not isinstance(raw_rows, list) or len(raw_rows) > MAX_ROWS:
        _fail(f"continuity:rows:{table}")
    definition = _TABLE_DEFS[table]
    columns = TABLE_COLUMNS[table]
    decoded_rows: list[dict[str, object]] = []
    for row_index, raw_row in enumerate(raw_rows):
        if type(raw_row) is not dict or set(raw_row) != set(columns):
            _fail(f"continuity:row:{table}:{row_index}")
        decoded: dict[str, object] = {}
        for column, declared_type, _primary_key in definition:
            item = _package_import_value(raw_row[column], f"continuity:{table}:{column}")
            if item is not None:
                if declared_type == "INTEGER" and type(item) is not int:
                    _fail(f"continuity:{table}:{column}:integer")
                if declared_type == "TEXT" and type(item) is not str:
                    _fail(f"continuity:{table}:{column}:text")
                if declared_type == "BLOB" and type(item) is not bytes:
                    _fail(f"continuity:{table}:{column}:blob")
            decoded[column] = item
        decoded_rows.append(decoded)
    return decoded_rows


def _snapshot_row_key(row: Mapping[str, object], table: str) -> tuple[object, ...]:
    primary_columns = [column for column, _declared_type, primary in _TABLE_DEFS[table] if primary]
    return tuple(row[column] for column in primary_columns)


def _database_snapshot_rows(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    snapshot: dict[str, list[dict[str, object]]] = {}
    for table in PACKAGE_TABLES:
        rows = _bounded_rows(connection, table)
        snapshot[table] = [
            {column: row[column] for column in TABLE_COLUMNS[table]}
            for row in rows
        ]
    return snapshot


def _verify_current_snapshot(
    connection: sqlite3.Connection,
    package_rows: dict[str, list[dict[str, object]]],
) -> None:
    """Bind a current-snapshot package to every allowlisted row in this database."""

    database_rows = _database_snapshot_rows(connection)
    for table in PACKAGE_TABLES:
        package_sorted = sorted(package_rows[table], key=lambda row: _snapshot_row_key(row, table))
        database_sorted = sorted(database_rows[table], key=lambda row: _snapshot_row_key(row, table))
        if package_sorted != database_sorted:
            _fail("continuity:current-snapshot-mismatch")


def _verify_restore_source_binding(
    meta: dict[str, object],
    package_result: dict[str, object],
    package_rows: dict[str, list[dict[str, object]]],
) -> None:
    """Bind a restore-source package to the persisted target restore contract."""

    identity = meta["identity"]
    assert isinstance(identity, dict)
    if identity["provenance"] != "CONTINUITY_RESTORE":
        _fail("continuity:restore-source-provenance")
    package_digest = package_result["package_digest"]
    assert isinstance(package_digest, str)
    if identity["source_package_digest"] != bytes.fromhex(package_digest):
        _fail("continuity:restore-source-digest")
    if identity["anchor_sequence"] != package_result["sequence"]:
        _fail("continuity:restore-source-sequence")
    if identity["anchor_head"] != bytes.fromhex(str(package_result["history_head"])):
        _fail("continuity:restore-source-head")
    source_identity = package_rows["financial_identity"]
    if len(source_identity) != 1 or source_identity[0]["genesis_head"] != identity["genesis_head"]:
        _fail("continuity:restore-source-genesis")


def _read_json(path: Path, code: str, max_bytes: int) -> object:
    try:
        with path.open("rb") as handle:
            return _parse_json(handle.read(max_bytes + 1).decode("latin-1"), code, max_bytes=max_bytes)
    except OSError:
        _fail(f"{code}:read")


def verify_history_export(directory: str | Path, *, expected_authority: object, expected_scope: object | None = None, restored: str | Path | None = None) -> dict[str, object]:
    """Replay-verify a history export (manifest, chained segments); bind a database ``restored`` from it to its final images."""
    return _mapped(lambda: _verify_history_export(Path(directory), expected_authority, expected_scope, restored))


def _verify_history_export(directory: Path, expected_authority: object, expected_scope: object | None, restored: str | Path | None) -> dict[str, object]:
    manifest = _read_json(directory / "manifest.json", "history:manifest", MAX_JSON_BYTES)
    if not isinstance(manifest, dict) or set(manifest) != {"format", "identity", "meta", "segment_count", "last_segment_digest", "manifest_digest"} or manifest["format"] != SEGMENT_FORMAT:
        _fail("history:manifest")
    body = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest["manifest_digest"] != _digest(SEGMENT_DOMAIN, b"manifest", _canonical(body)).hex().upper():
        _fail("history:manifest-digest")
    meta = _verify_package_rows([manifest["meta"]], "financial_meta")[0]
    identity = _identity_record(_verify_package_rows([manifest["identity"]], "financial_identity")[0], "history:identity")
    scope = {key: meta[key] for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")}
    expected = _identity(expected_config=None, expected_scope=scope if expected_scope is None else expected_scope, expected_authority=expected_authority, expected_mode=None, expected_owner_id=None, expected_continuity_epoch=None)
    authority = (meta["trusted_authority_id"], meta["trusted_authority_epoch"], meta["trusted_authority_digest"])
    if meta["id"] != 1 or meta["schema_version"] != SCHEMA_VERSION or meta["schema"] != SCHEMA or scope != expected["scope"] or authority != (expected["authority_id"], expected["authority_epoch"], expected["authority_digest"]):
        _fail("history:meta")
    if identity["provenance"] == "ROOT" and identity["genesis_head"] != _digest(GENESIS_DOMAIN, _canonical(scope), expected["authority_digest"], identity["identity_digest"]):
        _fail("history:identity-genesis")
    if identity["anchor_sequence"] == 0 and identity["anchor_head"] != identity["genesis_head"]:
        _fail("history:identity-anchor")
    count = _integer(manifest["segment_count"], "history:segment-count", maximum=MAX_ROWS)
    previous, head, sequence = ZERO_DIGEST, identity["genesis_head"], 0
    images: dict[tuple[str, tuple[object, ...]], dict[str, object]] = {}
    for index in range(count):
        code = f"history:segment:{index}"
        segment = _read_json(directory / f"segment-{index:08d}.json", code, MAX_SEGMENT_BYTES)
        if not isinstance(segment, dict) or set(segment) != {"events", "rows", "seal", "segment_digest", "signature"} or segment["signature"] is not None or not isinstance(segment["rows"], list):
            _fail(f"{code}:shape")
        first = sequence + 1
        for event in _verify_package_rows(segment["events"], "financial_events"):
            sequence += 1
            if sequence > MAX_ROWS:
                _fail("history:row-cap")
            head = _verify_event(event, sequence, head)
            if sequence == identity["anchor_sequence"] and head != identity["anchor_head"]:
                _fail("history:identity-anchor")
        segment_images: dict[tuple[str, tuple[object, ...]], dict[str, object]] = {}
        for record in segment["rows"]:
            if not isinstance(record, dict) or set(record) != {"table", "row"} or record["table"] not in PROJECTION_TABLES:
                _fail(f"{code}:record")
            row = _verify_package_rows([record["row"]], record["table"])[0]
            segment_images[(record["table"], _snapshot_row_key(row, record["table"]))] = row
        records = [_canonical(record) for record in segment["rows"]]
        if sequence < first or records != sorted(records) or len(segment_images) != len(records):  # sorted, one image per row
            _fail(f"{code}:records")
        images.update(segment_images)
        seal = {"format": SEGMENT_FORMAT, "segment_index": index, "first_sequence": first, "last_sequence": sequence, "event_count": sequence - first + 1, "previous_digest": previous.hex().upper(), "event_head": head.hex().upper(), "projection_root": _digest(SEGMENT_DOMAIN, b"rows", _canonical(segment["rows"])).hex().upper()}
        if _canonical(segment["seal"]) != _canonical(seal):
            _fail(f"{code}:seal")
        previous = _digest(SEGMENT_DOMAIN, b"seal", _canonical(seal))
        if segment["segment_digest"] != previous.hex().upper():
            _fail(f"{code}:digest")
    if manifest["last_segment_digest"] != previous.hex().upper() or (meta["sequence"], meta["history_head"]) != (sequence, head) or identity["anchor_sequence"] > sequence:
        _fail("history:manifest-binding")
    result: dict[str, object] = {  # shaped like a verified package, for restore
        "scope": scope, "authority": {"authority_id": authority[0], "epoch": authority[1], "digest": expected["authority_digest"].hex().upper()},
        "continuity_epoch": meta["continuity_epoch"], "sequence": sequence, "history_head": head.hex().upper(), "package_digest": manifest["manifest_digest"],
        "segment_count": count, "tables": {"financial_identity": [manifest["identity"]], "financial_meta": [manifest["meta"]]},
    }
    if restored is not None:
        connection = _open_readonly(restored)
        try:
            target = _identity_record(dict(connection.execute("SELECT * FROM financial_identity").fetchone()))
            _verify_restore_source_binding({"identity": target}, result, {"financial_identity": [identity]})
            if tuple(connection.execute("SELECT sequence,history_head FROM financial_meta").fetchone()) != (sequence, head):
                _fail("history:restored-head")
            for table in sorted(PROJECTION_TABLES):
                for row in connection.execute(f"SELECT * FROM {table}"):
                    decoded = {column: row[column] for column in TABLE_COLUMNS[table]}
                    if images.pop((table, _snapshot_row_key(decoded, table)), None) != decoded:
                        _fail(f"history:restored-row:{table}")
            if images:
                _fail("history:restored-missing-row")
        finally:
            connection.close()
    return result


def verify_continuity_package(
    raw: bytes,
    *,
    expected_config: object | None = None,
    expected_scope: object | None = None,
    expected_schema_version: int | None = None,
    expected_authority: object | None = None,
    expected_sequence: int | None = None,
    expected_history_head: bytes | str | None = None,
    expected_continuity_epoch: int | None = None,
    _include_rows: bool = False,
) -> dict[str, object]:
    """Verify the bounded canonical continuity package grammar and digest."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_PACKAGE_BYTES:
        _fail("continuity:byte-cap")
    identity = _identity(
        expected_config=expected_config,
        expected_scope=expected_scope,
        expected_authority=expected_authority,
        expected_mode=None,
        expected_owner_id=None,
        expected_continuity_epoch=expected_continuity_epoch,
    )
    try:
        raw_text = raw.decode("ascii")
    except UnicodeDecodeError:
        _fail("continuity:ascii")
    value = _parse_json(raw_text, "continuity:package", max_bytes=MAX_PACKAGE_BYTES)
    if not isinstance(value, dict):
        _fail("continuity:object")
    _check_json_shape(value, "continuity:shape")
    required = {
        "schema", "version", "scope", "authority", "continuity_epoch", "sequence",
        "history_head", "dispatch_enabled", "egress_enabled", "mode", "tables", "package_digest",
    }
    if set(value) != required:
        _fail("continuity:keys")
    package_version = value["version"]
    # Continuity v8 only; every other package version fails closed here.
    package_format = _PACKAGE_FORMATS.get(package_version) if type(package_version) is int else None
    if package_format is None or value["schema"] != package_format[0]:
        _fail("continuity:schema")
    package_schema, owner_schema, _domain = package_format
    if expected_schema_version is not None and package_version != _integer(expected_schema_version, "continuity:expected-schema-version", minimum=min(_PACKAGE_FORMATS), maximum=SCHEMA_VERSION):
        _fail("continuity:schema-version-binding")
    if identity["schema_version"] is not None and identity["schema_version"] != package_version:
        _fail("continuity:schema-version-binding")
    scope = value["scope"]
    if not isinstance(scope, dict) or set(scope) != {"state_id", "deployment_id", "program_id", "period_id", "currency"}:
        _fail("continuity:scope")
    expected_scope_value = identity["scope"]
    assert isinstance(expected_scope_value, dict)
    for key, expected in expected_scope_value.items():
        if scope[key] != expected:
            _fail(f"continuity:scope:{key}")
    for key in ("state_id", "deployment_id", "program_id", "period_id"):
        _id(scope[key], f"continuity:scope:{key}")
    if scope["currency"] != CURRENCY:
        _fail("continuity:scope:currency")
    authority = value["authority"]
    if not isinstance(authority, dict) or set(authority) != {"authority_id", "epoch", "digest"}:
        _fail("continuity:authority")
    authority_id = _id(authority["authority_id"], "continuity:authority-id")
    authority_epoch = _integer(authority["epoch"], "continuity:authority-epoch", minimum=1, maximum=MAX_CENTS)
    authority_digest = _hex_digest(authority["digest"], "continuity:authority-digest")
    if (authority_id, authority_epoch) != (identity["authority_id"], identity["authority_epoch"]):
        _fail("continuity:authority")
    if authority_digest != identity["authority_digest"]:
        _fail("continuity:authority-digest")
    epoch = _integer(value["continuity_epoch"], "continuity:epoch", minimum=1, maximum=MAX_CENTS)
    sequence = _integer(value["sequence"], "continuity:sequence", maximum=MAX_ROWS)
    history_head = _hex_digest(value["history_head"], "continuity:history-head")
    mode = value["mode"]
    if mode not in {"LIVE", "SHADOW", "TEST"} or value["dispatch_enabled"] is not False or value["egress_enabled"] is not False:
        _fail("continuity:nonactivating")
    if expected_sequence is not None and sequence != _integer(expected_sequence, "continuity:expected-sequence", maximum=MAX_ROWS):
        _fail("continuity:sequence-binding")
    if expected_history_head is not None and history_head != _hex_digest(expected_history_head, "continuity:expected-head"):
        _fail("continuity:head-binding")
    if expected_continuity_epoch is not None and epoch != _integer(expected_continuity_epoch, "continuity:expected-epoch", minimum=1, maximum=MAX_CENTS):
        _fail("continuity:epoch-binding")
    tables = value["tables"]
    if not isinstance(tables, dict) or set(tables) != PACKAGE_TABLES:
        _fail("continuity:tables")
    counts: dict[str, int] = {}
    decoded_rows: dict[str, list[dict[str, object]]] = {}
    for table in PACKAGE_TABLES:
        decoded_rows[table] = _verify_package_rows(tables[table], table)
        counts[table] = len(decoded_rows[table])
    if counts["financial_meta"] != 1:
        _fail("continuity:meta-cardinality")
    meta = decoded_rows["financial_meta"][0]
    if meta["id"] != 1 or meta["schema_version"] != package_version or meta["schema"] != owner_schema:
        _fail("continuity:meta-schema")
    for key, expected in scope.items():
        if meta[key] != expected:
            _fail(f"continuity:meta-scope:{key}")
    if meta["mode"] != mode or _flag(meta["dispatch_enabled"], "continuity:meta-dispatch") != 0 or _flag(meta["egress_enabled"], "continuity:meta-egress") != 0:
        _fail("continuity:meta-nonactivating")
    _id(meta["owner_id"], "continuity:meta-owner")
    meta_authority = (
        _id(meta["trusted_authority_id"], "continuity:meta-authority-id"),
        _integer(meta["trusted_authority_epoch"], "continuity:meta-authority-epoch", minimum=1, maximum=MAX_CENTS),
        _blob64(meta["trusted_authority_digest"], "continuity:meta-authority-digest"),
    )
    if meta_authority != (authority_id, authority_epoch, authority_digest):
        _fail("continuity:meta-authority")
    if _integer(meta["sequence"], "continuity:meta-sequence", maximum=MAX_ROWS) != sequence:
        _fail("continuity:meta-sequence")
    if _blob64(meta["history_head"], "continuity:meta-history-head") != history_head:
        _fail("continuity:meta-history-head")
    if _integer(meta["continuity_epoch"], "continuity:meta-epoch", minimum=1, maximum=MAX_CENTS) != epoch:
        _fail("continuity:meta-epoch")
    if counts["financial_identity"] != 1:
        _fail("continuity:identity-cardinality")
    identity_contract = _identity_record(
        decoded_rows["financial_identity"][0],
        "continuity:identity",
        package_version,
    )
    if identity_contract["bound_mode"] != mode or identity_contract["bound_owner_id"] != meta["owner_id"]:
        _fail("continuity:identity-binding")
    if identity_contract["provenance"] == "ROOT":
        expected_genesis = _digest(GENESIS_DOMAIN, _canonical(scope, "continuity:scope"), authority_digest, identity_contract["identity_digest"])
        if identity_contract["source_package_digest"] != ZERO_DIGEST or identity_contract["anchor_sequence"] != 0 or identity_contract["anchor_head"] != expected_genesis or identity_contract["genesis_head"] != expected_genesis:
            _fail("continuity:identity-genesis")
    else:
        if identity_contract["source_package_digest"] == ZERO_DIGEST or identity_contract["anchor_sequence"] > sequence:
            _fail("continuity:identity-anchor")
        if identity_contract["anchor_sequence"] == 0 and identity_contract["anchor_head"] != identity_contract["genesis_head"]:
            _fail("continuity:identity-anchor")
        if identity_contract["anchor_sequence"] > 0:
            anchor_row = next((row for row in decoded_rows["financial_events"] if row["event_sequence"] == identity_contract["anchor_sequence"]), None)
            if anchor_row is None or anchor_row["head"] != identity_contract["anchor_head"]:
                _fail("continuity:identity-history-anchor")
    payload = _package_payload_without_digest(value)
    expected_digest = continuity_package_digest(payload)
    package_digest = value["package_digest"]
    if type(package_digest) is not str or package_digest != package_digest.upper() or _HEX128.fullmatch(package_digest) is None or package_digest != expected_digest:
        _fail("continuity:package-digest")
    _verify_correction_followup_records(
        decoded_rows["financial_events"],
        evaluations={str(row["evaluation_id"]): row for row in decoded_rows["evaluations"]},
        determinations={str(row["determination_id"]): row for row in decoded_rows["determinations"]},
        actions={str(row["action_id"]): row for row in decoded_rows["actions"]},
        cases={str(row["case_id"]): row for row in decoded_rows["cases"]},
        packs={str(row["pack_id"]): row for row in decoded_rows["control_packs"]},
    )
    package_packs = {
        _id(row["pack_id"], "continuity:manifest-pack-id"): row
        for row in decoded_rows["control_packs"]
    }
    manifest_state = _verify_population_manifest_rows(
        manifest_rows=decoded_rows["population_manifests"],
        member_rows=decoded_rows["population_manifest_members"],
        head_rows=decoded_rows["population_manifest_heads"],
        binding_rows=decoded_rows["population_manifest_bindings"],
        population_rows=decoded_rows["population_imports"],
        item_rows=decoded_rows["population_items"],
        event_rows=decoded_rows["financial_events"],
        packs=package_packs,
        scope=scope,
        authority_id=authority_id,
        authority_epoch=authority_epoch,
        authority_digest=authority_digest,
        actors=identity.get("actors"),
    )
    package_populations = {
        str(row["population_id"]): row for row in decoded_rows["population_imports"]
    }
    _verify_population_history(
        decoded_rows["financial_events"],
        package_populations,
        package_packs,
        manifest_state,
    )
    result: dict[str, object] = {
        "schema": package_schema,
        "version": package_version,
        "scope": dict(scope),
        "authority": {"authority_id": authority_id, "epoch": authority_epoch, "digest": authority_digest.hex().upper()},
        "continuity_epoch": epoch,
        "sequence": sequence,
        "history_head": history_head.hex().upper(),
        "table_counts": counts,
        "package_digest": package_digest,
    }
    funding, _receipt_ids = _verify_program_funding_rows(
        decoded_rows["program_funding_receipts"],
        decoded_rows["program_funding_projection"],
        decoded_rows["financial_events"],
        scope,
    )
    result["program_funding"] = funding
    if _include_rows:
        result["_decoded_rows"] = decoded_rows
    return result


def _verify_connection(
    connection: sqlite3.Connection,
    *,
    identity: dict[str, object],
    current_snapshot_package: bytes | None,
    restore_source_package: bytes | None,
) -> dict[str, object]:
    schema_version = _verify_schema(connection)
    # Whole-store mode only: the lookups below trust index contents the Owner wrote, so every index entry must match its row.
    if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
        _fail("schema:index-integrity")
    try:
        orphan = connection.execute("PRAGMA foreign_key_check").fetchone()
    except sqlite3.Error as error:
        _fail("foreign-keys:read", error)
    if orphan is not None:
        _fail(f"foreign-keys:{orphan[0]}")
    meta = _verify_meta(connection, identity, schema_version)
    events = _verify_events(connection, meta)
    packs = _verify_packs(connection, meta)
    manifest_state = _verify_population_manifest_rows(
        manifest_rows=[dict(row) for row in _bounded_rows(connection, "population_manifests")],
        member_rows=[dict(row) for row in _bounded_rows(connection, "population_manifest_members")],
        head_rows=[dict(row) for row in _bounded_rows(connection, "population_manifest_heads")],
        binding_rows=[dict(row) for row in _bounded_rows(connection, "population_manifest_bindings")],
        population_rows=[dict(row) for row in _bounded_rows(connection, "population_imports")],
        item_rows=[dict(row) for row in _bounded_rows(connection, "population_items")],
        event_rows=[dict(row) for row in events],
        packs={pack_id: dict(row) for pack_id, row in packs.items()},
        scope=meta["scope"],
        authority_id=str(meta["authority_id"]),
        authority_epoch=int(meta["authority_epoch"]),
        authority_digest=bytes(meta["authority_digest"]),
        actors=identity.get("actors"),
    )
    populations, items = _verify_populations(connection, meta, packs, manifest_state)
    _verify_population_history([dict(row) for row in events], populations, packs, manifest_state)
    obligations = _verify_obligations(connection, meta, populations, items, packs)
    evidence = _verify_evidence(connection, items, obligations)
    payments = _verify_payments(connection, obligations, items, evidence)
    claims = _verify_adjustments(connection, obligations, evidence)
    evaluations = _verify_evaluations(connection, meta, obligations, populations, packs, evidence)
    current = {key: max(history, key=lambda row: row["revision"]) for key, history in evaluations.items()}
    _verify_cases(connection, obligations, current)
    _verify_evaluation_history_events(events, populations, obligations, evaluations)
    determinations = _verify_determinations(
        connection,
        meta,
        obligations,
        populations,
        packs,
        claims,
        evidence,
        evaluations,
        actors=identity["actors"],
    )
    actions = _verify_actions(connection, meta, evaluations, claims, determinations, payments)
    conflicts = _verify_conflicts(connection, obligations, evidence, payments)
    _verify_duplicate_evidence(connection)
    funding, funding_receipt_ids = _verify_program_funding(connection, meta, events)
    manifest_records = manifest_state["manifests"]
    assert isinstance(manifest_records, dict)
    _verify_event_references(events, packs, populations, obligations, funding_receipt_ids, set(manifest_records))
    projections, totals = _verify_projections(meta, obligations, populations, packs, evidence, payments, claims, determinations, actions, conflicts, evaluations)
    for key, obligation in obligations.items():
        _verify_exact_input(connection, obligation, _evaluation_input_snapshot(current[key]["input_snapshot_json"], "evaluation:input"))
    _verify_replayed_rows(connection, events)  # after the specific checks, so their diagnoses come first
    _verify_history_tables(connection, events)  # bookkeeping last: a replay finding is the sharper diagnosis
    package_result: dict[str, object] | None = None
    if current_snapshot_package is not None and restore_source_package is not None:
        _fail("continuity:duplicate-input")
    if current_snapshot_package is not None:
        package_result = verify_continuity_package(
            current_snapshot_package,
            expected_scope=meta["scope"],
            expected_schema_version=schema_version,
            expected_authority=identity["authority_source"],
            expected_sequence=meta["sequence"],
            expected_history_head=meta["history_head"],
            expected_continuity_epoch=meta["continuity_epoch"],
            _include_rows=True,
        )
        package_rows = package_result.pop("_decoded_rows")
        if not isinstance(package_rows, dict):
            _fail("continuity:decoded-rows")
        _verify_current_snapshot(connection, package_rows)
        package_result["role"] = "current_snapshot"
    elif restore_source_package is not None:
        package_result = verify_continuity_package(
            restore_source_package,
            expected_scope=meta["scope"],
            expected_schema_version=schema_version,
            expected_authority=identity["authority_source"],
            expected_continuity_epoch=meta["continuity_epoch"],
            _include_rows=True,
        )
        package_rows = package_result.pop("_decoded_rows")
        if not isinstance(package_rows, dict):
            _fail("continuity:decoded-rows")
        _verify_restore_source_binding(meta, package_result, package_rows)
        package_result["role"] = "restore_source"
    _verify_correction_followup_records(
        events,
        evaluations={str(row["evaluation_id"]): dict(row) for row in _bounded_rows(connection, "evaluations")},
        determinations={str(row["determination_id"]): dict(row) for row in _bounded_rows(connection, "determinations")},
        actions={str(row["action_id"]): dict(row) for row in _bounded_rows(connection, "actions")},
        cases={str(row["case_id"]): dict(row) for row in _bounded_rows(connection, "cases")},
        packs={str(row["pack_id"]): dict(row) for row in _bounded_rows(connection, "control_packs")},
    )
    _verify_commands(
        {table: [dict(row) for row in _bounded_rows(connection, table)] for table in sorted(TABLES)},
        "commands",
    )
    result = {
        "schema": SCHEMA,
        "schema_version": schema_version,
        "scope": dict(meta["scope"]),
        "authority": {
            "authority_id": meta["authority_id"],
            "epoch": meta["authority_epoch"],
            "digest": meta["authority_digest"].hex().upper(),
        },
        "mode": meta["mode"],
        "owner_id": meta["owner_id"],
        "continuity_epoch": meta["continuity_epoch"],
        "sequence": meta["sequence"],
        "history_head": meta["history_head"].hex().upper(),
        "counts": {
            "events": len(events),
            "packs": len(packs),
            "populations": len(populations),
            "items": len(items),
            "obligations": len(obligations),
            "evidence": len(evidence),
            "payments": len(payments),
            "claims": len(claims),
            "determinations": len(determinations),
            "actions": len(actions),
            "conflicts": len(conflicts),
            "evaluations": sum(len(rows) for rows in evaluations.values()),
        },
        "totals": totals,
        "obligations": projections,
        "continuity": package_result,
        "program_funding": funding,
    }
    return result


def _verify_mapped(
    connection: sqlite3.Connection,
    identity: dict[str, object],
    current_snapshot_package: bytes | None,
    restore_source_package: bytes | None,
) -> dict[str, object]:
    return _mapped(lambda: _verify_connection(
        connection,
        identity=identity,
        current_snapshot_package=current_snapshot_package,
        restore_source_package=restore_source_package,
    ))


def _mapped(check: Any) -> dict[str, object]:
    try:
        return check()
    except IndependentFinancialError:
        raise
    except (sqlite3.Error, KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError) as error:
        _fail("database:malformed", error)


def verify_database(
    path: str | Path,
    *,
    expected_config: object | None = None,
    expected_scope: object | None = None,
    expected_authority: object | None = None,
    expected_mode: str | None = None,
    expected_owner_id: str | None = None,
    expected_continuity_epoch: int | None = None,
    current_snapshot_package: bytes | None = None,
    restore_source_package: bytes | None = None,
) -> dict[str, object]:
    """Read and independently verify one financial-owner SQLite database.

    A supplied package must be named as either the current database snapshot or
    the source package used to create a continuity-restored database.
    """

    if current_snapshot_package is not None and restore_source_package is not None:
        _fail("continuity:duplicate-input")
    identity = _identity(
        expected_config=expected_config,
        expected_scope=expected_scope,
        expected_authority=expected_authority,
        expected_mode=expected_mode,
        expected_owner_id=expected_owner_id,
        expected_continuity_epoch=expected_continuity_epoch,
    )
    connection = _open_readonly(path)
    check = lambda: _verify_mapped(connection, identity, current_snapshot_package, restore_source_package)  # noqa: E731
    data_version = lambda: _mapped(lambda: connection.execute("PRAGMA data_version").fetchone()[0])  # noqa: E731
    try:
        # Unlocked, each read sees the latest commit, so a commit landing mid-check can mix two states. A check the
        # store sat still for keeps its verdict; a mixed pass with no finding is busy (retry). A mixed pass with a
        # finding is judged again on one snapshot, so a tamper never looks retryable; writers wait meanwhile.
        version = data_version()
        try:
            result = check()
        except IndependentFinancialError as finding:
            if str(finding) == "database:busy" or data_version() == version:
                raise
            _mapped(lambda: (connection.execute("BEGIN"), connection.execute("SELECT 1 FROM financial_meta").fetchone()))
            try:
                return check()
            finally:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
        if data_version() != version:
            _fail("database:busy")
        return result
    finally:
        connection.close()


def verify_database_connection(
    connection: sqlite3.Connection,
    *,
    expected_config: object | None = None,
    expected_scope: object | None = None,
    expected_authority: object | None = None,
    expected_mode: str | None = None,
    expected_owner_id: str | None = None,
    expected_continuity_epoch: int | None = None,
    current_snapshot_package: bytes | None = None,
    restore_source_package: bytes | None = None,
) -> dict[str, object]:
    """Verify an already-open connection without taking ownership of it."""

    if not isinstance(connection, sqlite3.Connection):
        _fail("database:connection")
    if current_snapshot_package is not None and restore_source_package is not None:
        _fail("continuity:duplicate-input")
    identity = _identity(
        expected_config=expected_config,
        expected_scope=expected_scope,
        expected_authority=expected_authority,
        expected_mode=expected_mode,
        expected_owner_id=expected_owner_id,
        expected_continuity_epoch=expected_continuity_epoch,
    )
    return _verify_mapped(connection, identity, current_snapshot_package, restore_source_package)


def verify_decision_package(
    path: str | Path,
    item_id: str,
    package: object,
    *,
    expected_config: object | None = None,
    expected_scope: object | None = None,
    expected_authority: object | None = None,
    expected_mode: str | None = None,
    expected_owner_id: str | None = None,
) -> dict[str, object]:
    """Reconstruct and verify an owner decision package from durable rows.

    This checker does not import or call the financial owner. It first verifies
    the complete owner database, then rebuilds the package's receipt, pages,
    links, and conclusions from the same read-only SQLite snapshot.
    """

    _id(item_id, "decision-package:item")
    package = _snapshot_decision_package_input(package)
    connection = _open_readonly(path)
    try:
        try:
            connection.execute("BEGIN")
            verified = verify_database_connection(
                connection,
                expected_config=expected_config,
                expected_scope=expected_scope,
                expected_authority=expected_authority,
                expected_mode=expected_mode,
                expected_owner_id=expected_owner_id,
            )
            scope = dict(verified["scope"])
            obligations = connection.execute(
                "SELECT * FROM obligations WHERE item_id=? ORDER BY obligation_id",
                (item_id,),
            ).fetchall()
            if len(obligations) != 1:
                _fail("decision-package:obligation")
            obligation = obligations[0]
            obligation_id = str(obligation["obligation_id"])
            expected_obligation = {
                "obligation_id": obligation_id,
                "item_id": str(obligation["item_id"]),
                "population_id": str(obligation["population_id"]),
                "period_id": str(obligation["period_id"]),
                "currency": str(obligation["currency"]),
                "revision": int(obligation["revision"]),
                "owed_cents": int(obligation["owed_cents"]),
                "claimed_adjustment_cents": int(obligation["claimed_adjustment_cents"]),
                "lawful_adjustment_cents": int(obligation["lawful_adjustment_cents"]),
                "received_cash_cents": int(obligation["received_cash_cents"]),
                "shortfall_cents": int(obligation["shortfall_cents"]),
                "overage_cents": int(obligation["overage_cents"]),
                "cash_satisfied": bool(obligation["cash_satisfied"]),
                "amount_satisfied": bool(obligation["amount_satisfied"]),
                "timely": bool(obligation["timely"]),
                "reporting_complete": bool(obligation["reporting_complete"]),
                "verification_status": str(obligation["verification_status"]),
                "case_status": str(obligation["case_status"]),
                "delivery_status": str(obligation["delivery_status"]),
                "current_evaluation_id": None if obligation["current_evaluation_id"] is None else str(obligation["current_evaluation_id"]),
                "due_at_ms": int(obligation["due_at_ms"]),
            }
            population_id = _id(obligation["population_id"], "decision-package:population-id")
            population_row = connection.execute(
                """
                SELECT p.status,p.source_complete,p.expected_count,p.imported_count,p.validated_count,
                       b.manifest_id,b.manifest_version AS binding_version,
                       b.manifest_digest AS binding_digest,
                       m.manifest_version AS manifest_version,m.manifest_digest,
                       m.member_digest,m.member_count
                FROM population_imports p
                JOIN population_manifest_bindings b USING(population_id)
                JOIN population_manifests m USING(manifest_id)
                JOIN population_items i ON i.population_id=p.population_id
                WHERE p.population_id=? AND i.item_id=?
                """,
                (population_id, str(obligation["item_id"])),
            ).fetchone()
            if population_row is None:
                _fail("decision-package:population-binding")
            expected_count = _integer(population_row["expected_count"], "decision-package:population-expected", minimum=1, maximum=MAX_ROWS)
            imported_count = _integer(population_row["imported_count"], "decision-package:population-imported", maximum=MAX_ROWS)
            validated_count = _integer(population_row["validated_count"], "decision-package:population-validated", maximum=MAX_ROWS)
            if (
                population_row["status"] != "PUBLISHED"
                or _flag(population_row["source_complete"], "decision-package:population-source-complete") != 1
                or imported_count != expected_count
                or validated_count != expected_count
            ):
                _fail("decision-package:population-incomplete")
            manifest_id = _id(population_row["manifest_id"], "decision-package:manifest-id")
            manifest_version = _integer(population_row["manifest_version"], "decision-package:manifest-version", minimum=1, maximum=MAX_ROWS)
            if _integer(population_row["binding_version"], "decision-package:binding-version", minimum=1, maximum=MAX_ROWS) != manifest_version:
                _fail("decision-package:population-binding")
            manifest_digest = _blob64(population_row["manifest_digest"], "decision-package:manifest-digest")
            if _blob64(population_row["binding_digest"], "decision-package:binding-digest") != manifest_digest:
                _fail("decision-package:population-binding")
            member_digest = _blob64(population_row["member_digest"], "decision-package:member-digest")
            member_count = _integer(population_row["member_count"], "decision-package:member-count", minimum=1, maximum=MAX_ROWS)
            if member_count != expected_count:
                _fail("decision-package:population-binding")
            imported_members = tuple(
                _id(row["item_id"], "decision-package:population-member")
                for row in connection.execute(
                    "SELECT item_id FROM population_items WHERE population_id=? ORDER BY item_id",
                    (population_id,),
                )
            )
            manifest_members = tuple(
                _id(row["member_id"], "decision-package:manifest-member")
                for row in connection.execute(
                    "SELECT member_id FROM population_manifest_members WHERE manifest_id=? ORDER BY position",
                    (manifest_id,),
                )
            )
            if (
                imported_members != manifest_members
                or len(imported_members) != member_count
                or str(obligation["item_id"]) not in imported_members
            ):
                _fail("decision-package:population-membership")
            population_binding = {
                "population_id": population_id,
                "status": "PUBLISHED",
                "completeness": "EXACT",
                "source_complete": True,
                "manifest_id": manifest_id,
                "manifest_version": manifest_version,
                "manifest_digest": manifest_digest.hex().upper(),
                "member_id": str(obligation["item_id"]),
                "member_count": member_count,
                "member_digest": member_digest.hex().upper(),
            }
            if obligation["current_evaluation_id"] is None:
                _fail("decision-package:evaluation")
            evaluation = connection.execute(
                "SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?",
                (obligation["current_evaluation_id"], obligation_id),
            ).fetchone()
            if evaluation is None:
                _fail("decision-package:evaluation")
            evidence_ids = _evidence_ids_json(evaluation["evidence_ids_json"], "decision-package:evidence")
            evidence_bindings = _evaluation_bindings_json(evaluation["evidence_bindings_json"], "decision-package:bindings")
            evaluation_scope = _parse_json(evaluation["scope_json"], "decision-package:scope")
            if not isinstance(evaluation_scope, dict):
                _fail("decision-package:scope")
            input_digest = _blob64(evaluation["input_snapshot_digest"], "decision-package:input-digest")
            pack_row = connection.execute(
                """
                SELECT cp.* FROM control_packs cp
                JOIN population_imports pi ON pi.pack_id=cp.pack_id
                WHERE pi.population_id=?
                """,
                (obligation["population_id"],),
            ).fetchone()
            if pack_row is None:
                _fail("decision-package:control-pack")
            authority_digest = _blob64(evaluation["authority_digest"], "decision-package:authority-digest")
            expected_receipt_body = _evaluation_receipt_body(
                row=evaluation,
                evidence_ids=evidence_ids,
                evidence_bindings=evidence_bindings,
                scope=evaluation_scope,
                control_pack_id=str(pack_row["pack_id"]),
                control_pack_version=int(pack_row["version"]),
                control_pack_digest=_blob64(pack_row["pack_digest"], "decision-package:pack-digest"),
                authority_epoch=int(evaluation["authority_epoch"]),
                authority_digest=authority_digest,
                input_snapshot_digest=input_digest,
            )
            expected_receipt = {
                **expected_receipt_body,
                "receipt_digest": _blob64(evaluation["receipt_digest"], "decision-package:receipt-digest").hex().upper(),
                "evaluation_result_digest": _blob64(evaluation["result_digest"], "decision-package:result-digest").hex().upper(),
            }

            references = package.get("references")
            if type(references) is not dict or type(references.get("evidence")) is not dict:
                _fail("decision-package:references")
            page_limit = references["evidence"].get("limit")
            page_offset = references["evidence"].get("offset")
            if type(page_limit) is not int or not 1 <= page_limit <= 200 or type(page_offset) is not int or not 0 <= page_offset <= MAX_ROWS:
                _fail("decision-package:page-bounds")

            def build_page(
                name: str,
                select_sql: str,
                count_sql: str,
                args: tuple[object, ...],
                project: object,
            ) -> dict[str, object]:
                total = int(connection.execute(count_sql, args).fetchone()[0])
                rows = connection.execute(select_sql + " LIMIT ? OFFSET ?", (*args, page_limit, page_offset)).fetchall()
                items = [project(row) for row in rows]  # type: ignore[operator]
                next_offset = page_offset + len(items) if page_offset + len(items) < total else None
                result = {
                    "offset": page_offset,
                    "limit": page_limit,
                    "count": len(items),
                    "total": total,
                    "next_offset": next_offset,
                    "items": items,
                }
                actual = references.get(name)
                if _canonical(actual, f"decision-package:{name}") != _canonical(result, f"decision-package:{name}:expected"):
                    _fail(f"decision-package:{name}")
                return result

            def project_evidence(row: sqlite3.Row) -> dict[str, object]:
                return {
                    "evidence_id": str(row["evidence_id"]),
                    "item_id": str(row["item_id"]),
                    "kind": str(row["kind"]),
                    "common_origin_id": str(row["common_origin_id"]),
                    "source_id": str(row["source_id"]),
                    "source_version": str(row["source_version"]),
                    "local_ref": str(row["local_ref"]),
                    "applicable_at_ms": int(row["applicable_at_ms"]),
                    "event_at_ms": int(row["event_at_ms"]),
                    "received_at_ms": int(row["received_at_ms"]),
                    "amount_cents": None if row["amount_cents"] is None else int(row["amount_cents"]),
                    "reversal_of": None if row["reversal_of"] is None else str(row["reversal_of"]),
                    "supersedes": None if row["supersedes"] is None else str(row["supersedes"]),
                    "record_digest": _blob64(row["record_digest"], "decision-package:evidence-record").hex().upper(),
                    "obligation_id": obligation_id,
                }

            def project_case(row: sqlite3.Row) -> dict[str, object]:
                conditions = _parse_json(row["completion_conditions_json"], "decision-package:case-conditions")
                if not isinstance(conditions, dict):
                    _fail("decision-package:case-conditions")
                return {
                    "case_id": str(row["case_id"]),
                    "obligation_id": obligation_id,
                    "reason": str(row["reason"]),
                    "contractual_accountability": str(row["contractual_accountability"]),
                    "next_action_owner": str(row["next_action_owner"]),
                    "due_at_ms": int(row["due_at_ms"]),
                    "completion_conditions": {key: bool(conditions[key]) for key in sorted(conditions)},
                    "status": str(row["status"]),
                    "updated_at_ms": int(row["updated_at_ms"]),
                }

            def project_payment(row: sqlite3.Row) -> dict[str, object]:
                return {
                    "payment_id": str(row["payment_id"]),
                    "obligation_id": obligation_id,
                    "evidence_id": str(row["evidence_id"]),
                    "common_origin_id": str(row["common_origin_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "event_at_ms": int(row["event_at_ms"]),
                    "active": bool(row["active"]),
                    "reversed_by_evidence_id": None if row["reversed_by_evidence_id"] is None else str(row["reversed_by_evidence_id"]),
                }

            def project_claim(row: sqlite3.Row) -> dict[str, object]:
                return {
                    "claim_id": str(row["claim_id"]),
                    "obligation_id": obligation_id,
                    "evidence_id": str(row["evidence_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "owner_role": str(row["owner_role"]),
                    "deadline_ms": int(row["deadline_ms"]),
                    "status": str(row["status"]),
                    "created_at_ms": int(row["created_at_ms"]),
                    "updated_at_ms": int(row["updated_at_ms"]),
                }

            def project_determination(row: sqlite3.Row) -> dict[str, object]:
                supporting = _evaluation_bindings_json(row["supporting_evidence_json"], "decision-package:determination-evidence")
                return {
                    "determination_id": str(row["determination_id"]),
                    "obligation_id": obligation_id,
                    "claim_id": None if row["claim_id"] is None else str(row["claim_id"]),
                    "actor_id": str(row["actor_id"]),
                    "actor_role": str(row["actor_role"]),
                    "authority": {
                        "authority_id": str(row["authority_id"]),
                        "epoch": int(row["authority_epoch"]),
                        "digest": _blob64(row["authority_digest"], "decision-package:determination-authority").hex().upper(),
                    },
                    "decision": str(row["decision"]),
                    "amount_cents": int(row["amount_cents"]),
                    "supporting_evidence": supporting,
                    "expected_revision": int(row["expected_revision"]),
                    "resulting_revision": int(row["resulting_revision"]),
                    "decided_at_ms": int(row["decided_at_ms"]),
                    "determination_digest": _blob64(row["determination_digest"], "decision-package:determination-digest").hex().upper(),
                    "input_evaluation_id": str(row["input_evaluation_id"]),
                    "input_evaluation_result_digest": _blob64(row["input_evaluation_result_digest"], "decision-package:determination-evaluation").hex().upper(),
                }

            action_fields = (
                "action", "action_id", "obligation_id", "determination_id", "kind", "claim_id",
                "amount_cents", "currency", "revision", "input_evaluation_id",
                "input_evaluation_result_digest", "dispatch",
            )

            def project_action(row: sqlite3.Row) -> dict[str, object]:
                payload = _parse_json(row["payload_json"], "decision-package:action-payload")
                if not isinstance(payload, dict):
                    _fail("decision-package:action-payload")
                return {
                    "action_id": str(row["action_id"]),
                    "obligation_id": obligation_id,
                    "determination_id": str(row["determination_id"]),
                    "kind": str(row["kind"]),
                    "status": str(row["status"]),
                    "revision": int(row["revision"]),
                    "payload_digest": _blob64(row["payload_digest"], "decision-package:action-digest").hex().upper(),
                    "payload_fields": {key: payload[key] for key in action_fields if key in payload},
                    "created_at_ms": int(row["created_at_ms"]),
                    "acknowledgment": {
                        "status": str(row["outbox_status"]),
                        "reference": None if row["acknowledgment_ref"] is None else str(row["acknowledgment_ref"]),
                        "attempt": int(row["attempt"]),
                        "updated_at_ms": int(row["outbox_updated_at_ms"]),
                        "cash_effect_cents": 0,
                    },
                }

            def project_conflict(row: sqlite3.Row) -> dict[str, object]:
                return {
                    "conflict_id": str(row["conflict_id"]),
                    "obligation_id": obligation_id,
                    "common_origin_id": str(row["common_origin_id"]),
                    "existing_payment_id": None if row["existing_payment_id"] is None else str(row["existing_payment_id"]),
                    "candidate_evidence_id": str(row["candidate_evidence_id"]),
                    "existing_amount_cents": None if row["existing_amount_cents"] is None else int(row["existing_amount_cents"]),
                    "candidate_amount_cents": None if row["candidate_amount_cents"] is None else int(row["candidate_amount_cents"]),
                    "reason": str(row["reason"]),
                    "visible_at_ms": int(row["visible_at_ms"]),
                }

            case_page = build_page("cases", "SELECT * FROM cases WHERE obligation_id=? ORDER BY case_id", "SELECT COUNT(*) FROM cases WHERE obligation_id=?", (obligation_id,), project_case)
            evidence_select = "SELECT evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,amount_cents,reversal_of,supersedes,record_digest FROM evidence WHERE item_id=? ORDER BY evidence_id"
            evidence_page = build_page("evidence", evidence_select, "SELECT COUNT(*) FROM evidence WHERE item_id=?", (item_id,), project_evidence)
            payment_page = build_page("payments", "SELECT * FROM payments WHERE obligation_id=? ORDER BY payment_id", "SELECT COUNT(*) FROM payments WHERE obligation_id=?", (obligation_id,), project_payment)
            claim_page = build_page("claims", "SELECT * FROM claimed_adjustments WHERE obligation_id=? ORDER BY claim_id", "SELECT COUNT(*) FROM claimed_adjustments WHERE obligation_id=?", (obligation_id,), project_claim)
            determination_page = build_page("determinations", "SELECT * FROM determinations WHERE obligation_id=? ORDER BY determination_id", "SELECT COUNT(*) FROM determinations WHERE obligation_id=?", (obligation_id,), project_determination)
            action_base = "SELECT a.*,o.status AS outbox_status,o.attempt,o.acknowledgment_ref,o.updated_at_ms AS outbox_updated_at_ms FROM actions a JOIN action_outbox o ON o.action_id=a.action_id WHERE a.obligation_id=?"
            action_page = build_page("actions", action_base + " ORDER BY a.action_id", "SELECT COUNT(*) FROM actions WHERE obligation_id=?", (obligation_id,), project_action)
            conflict_page = build_page("conflicts", "SELECT * FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id", "SELECT COUNT(*) FROM financial_conflicts WHERE obligation_id=?", (obligation_id,), project_conflict)
            report_select = "SELECT evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,amount_cents,reversal_of,supersedes,record_digest FROM evidence WHERE item_id=? AND kind IN ('REPORT','REPORT_CORRECTION') ORDER BY evidence_id"
            reporting_page = build_page("reporting_evidence", report_select, "SELECT COUNT(*) FROM evidence WHERE item_id=? AND kind IN ('REPORT','REPORT_CORRECTION')", (item_id,), project_evidence)

            case_row = connection.execute("SELECT * FROM cases WHERE obligation_id=? ORDER BY case_id DESC LIMIT 1", (obligation_id,)).fetchone()
            current_case = None if case_row is None else project_case(case_row)
            action_row = connection.execute(action_base + " ORDER BY a.revision DESC,a.action_id DESC LIMIT 1", (obligation_id,)).fetchone()
            current_action = None if action_row is None else project_action(action_row)
            determination_row = connection.execute("SELECT * FROM determinations WHERE obligation_id=? ORDER BY resulting_revision DESC,determination_id DESC LIMIT 1", (obligation_id,)).fetchone()
            current_determination = None if determination_row is None else project_determination(determination_row)

            pack_scope = {"state_id": str(pack_row["state_id"]), "deployment_id": str(pack_row["deployment_id"]), "program_id": str(pack_row["program_id"]), "period_id": str(pack_row["period_id"])}
            source_refs = _parse_json(pack_row["source_refs_json"], "decision-package:pack-source-refs")
            authorized_roles = _parse_json(pack_row["authorized_roles_json"], "decision-package:pack-roles")
            if not isinstance(source_refs, dict) or set(source_refs) != {"values"} or not isinstance(authorized_roles, dict) or set(authorized_roles) != {"values"}:
                _fail("decision-package:control-pack")
            expected_pack = {
                "pack_id": str(pack_row["pack_id"]),
                "version": int(pack_row["version"]),
                "digest": _blob64(pack_row["pack_digest"], "decision-package:pack-digest").hex().upper(),
                "calculation_rule_id": str(pack_row["calculation_rule_id"]),
                "adjustment_rule_id": str(pack_row["adjustment_rule_id"]),
                "source_refs": list(source_refs["values"]),
                "authorized_roles": list(authorized_roles["values"]),
                "effective_start_ms": int(pack_row["effective_start_ms"]),
                "effective_end_ms": int(pack_row["effective_end_ms"]),
                "recorded_at_ms": int(pack_row["recorded_at_ms"]),
                "approved_at_ms": int(pack_row["approved_at_ms"]),
            }
            if pack_scope != {key: scope[key] for key in pack_scope}:
                _fail("decision-package:control-pack-scope")

            active_payment_count = int(connection.execute("SELECT COUNT(*) FROM payments WHERE obligation_id=? AND active=1", (obligation_id,)).fetchone()[0])
            authorized_claim_count = int(connection.execute("SELECT COUNT(*) FROM claimed_adjustments WHERE obligation_id=? AND status='AUTHORIZED'", (obligation_id,)).fetchone()[0])
            conflict_count = int(connection.execute("SELECT COUNT(*) FROM financial_conflicts WHERE obligation_id=?", (obligation_id,)).fetchone()[0])
            report_count = int(reporting_page["total"])
            active_payment_cents = _sum_cents(
                [int(row[0]) for row in connection.execute("SELECT amount_cents FROM payments WHERE obligation_id=? AND active=1 ORDER BY payment_id", (obligation_id,))],
                "decision-package:cash-support",
            )
            adjustment_rows = connection.execute(
                "SELECT amount_cents,status FROM claimed_adjustments WHERE obligation_id=? AND status IN ('CLAIMED','AUTHORIZED') ORDER BY claim_id",
                (obligation_id,),
            ).fetchall()
            claimed_adjustment_cents = _sum_cents([int(row["amount_cents"]) for row in adjustment_rows], "decision-package:claimed-support")
            lawful_adjustment_cents = _sum_cents([int(row["amount_cents"]) for row in adjustment_rows if row["status"] == "AUTHORIZED"], "decision-package:lawful-support")
            active_payment_ids = [str(row["evidence_id"]) for row in payment_page["items"] if row["active"]]
            authorized_evidence_ids = [str(row["evidence_id"]) for row in claim_page["items"] if row["status"] == "AUTHORIZED"]
            reporting_evidence_ids = [str(row["evidence_id"]) for row in reporting_page["items"]]
            payment_references_complete = page_offset == 0 and payment_page["next_offset"] is None
            claim_references_complete = page_offset == 0 and claim_page["next_offset"] is None
            reporting_references_complete = page_offset == 0 and reporting_page["next_offset"] is None
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
                amount_support = "SUPPORTED" if amount_evidence_ids else "NO_LINKED_EVIDENCE"
            requirements = {
                "amount_satisfied": "SUPPORTED" if amount_satisfied and amount_support == "SUPPORTED" else (
                    "NOT_SATISFIED" if not amount_satisfied and amount_support != "CONFLICTED"
                    else "CONFLICTED" if amount_support == "CONFLICTED" else "UNKNOWN"
                ),
                "delivery_acknowledged_or_not_required": delivery_support,
                "reporting_complete": reporting_support,
            }
            missing_requirements = sorted(key for key, value in requirements.items() if value != "SUPPORTED")
            observed_case_status = None if current_case is None else current_case["status"]
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

            expected_package = {
                "contract": DECISION_PACKAGE_CONTRACT,
                "scope": scope,
                "obligation": expected_obligation,
                "population_binding": population_binding,
                "evaluation_receipt": expected_receipt,
                "control_pack": expected_pack,
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
                "reporting": {"complete": bool(obligation["reporting_complete"]), "evidence_count": report_count},
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
                        "conflict_ids": [str(row["conflict_id"]) for row in conflict_page["items"]],
                    },
                },
            }
            if _canonical(package, "decision-package:actual") != _canonical(expected_package, "decision-package:expected"):
                _fail("decision-package:mismatch")
            connection.execute("COMMIT")
            return {
                "integrity": "VERIFIED",
                "obligation_id": obligation_id,
                "evaluation_id": str(evaluation["evaluation_id"]),
                "revision": int(evaluation["revision"]),
                "case_status": observed_case_status,
            }
        except IndependentFinancialError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except (sqlite3.Error, KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError) as error:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            _fail("decision-package:malformed", error)
    finally:
        connection.close()
