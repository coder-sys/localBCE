"""Independent, read-only checker for the synthetic RightRail financial owner.

This module deliberately does not import the production owner.  It owns a
second copy of the versioned database grammar, digest domains, identity
bindings, and projection equations.  It never repairs a database and opens
database paths read-only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, NoReturn
from urllib.parse import quote


class IndependentFinancialError(RuntimeError):
    """Raised for every malformed, stale, rebound, or inconsistent owner DB."""


# Friendly aliases keep the boundary usable without coupling callers to one
# historical exception spelling.
FinancialIndependentError = IndependentFinancialError
FinancialVerificationError = IndependentFinancialError


def _fail(code: str) -> NoReturn:
    error = IndependentFinancialError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


SCHEMA_VERSION = 5
SCHEMA = "RR/FINANCIAL/OWNER/v5"
CONTINUITY_SCHEMA = "RR/FINANCIAL/CONTINUITY/v5"
CURRENCY = "USD"
MAX_CENTS = (1 << 63) - 1
MAX_ROWS = 10_000
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 1 * 1024 * 1024
MAX_PACKAGE_NODES = 250_000

EVENT_DOMAIN = b"RR/FINANCIAL/EVENT/v2\x00"
HEAD_DOMAIN = b"RR/FINANCIAL/HEAD/v2\x00"
GENESIS_DOMAIN = b"RR/FINANCIAL/GENESIS/v5\x00"
EVIDENCE_DOMAIN = b"RR/FINANCIAL/EVIDENCE/v1\x00"
ACTION_DOMAIN = b"RR/FINANCIAL/ACTION/v1\x00"
IDEMPOTENCY_DOMAIN = b"RR/FINANCIAL/IDEMPOTENCY/v1\x00"
EVALUATION_RESULT_DOMAIN = b"RR/FINANCIAL/EVALUATION/v5\x00"
EVALUATION_INPUT_DOMAIN = b"RR/FINANCIAL/EVALUATION-INPUT/v1\x00"
EVALUATION_EVENT_DOMAIN = b"RR/FINANCIAL/EVALUATION-EVENT/v1\x00"
EVALUATION_RECEIPT_DOMAIN = b"RR/FINANCIAL/EVALUATION-RECEIPT/v1\x00"
CONTINUITY_DOMAIN = b"RR/FINANCIAL/CONTINUITY/v5\x00"
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
_TABLE_DEFS: dict[str, tuple[tuple[str, str, int], ...]] = {
    "financial_identity": (
        ("id", "INTEGER", 1),
        ("schema_version", "INTEGER", 0),
        ("provenance", "TEXT", 0),
        ("bound_mode", "TEXT", 0),
        ("bound_owner_id", "TEXT", 0),
        ("anchor_sequence", "INTEGER", 0),
        ("anchor_head", "BLOB", 0),
        ("genesis_head", "BLOB", 0),
        ("source_package_digest", "BLOB", 0),
        ("identity_digest", "BLOB", 0),
    ),
    "financial_meta": (
        ("id", "INTEGER", 1),
        ("schema_version", "INTEGER", 0),
        ("schema", "TEXT", 0),
        ("state_id", "TEXT", 0),
        ("deployment_id", "TEXT", 0),
        ("program_id", "TEXT", 0),
        ("period_id", "TEXT", 0),
        ("currency", "TEXT", 0),
        ("sequence", "INTEGER", 0),
        ("history_head", "BLOB", 0),
        ("continuity_epoch", "INTEGER", 0),
        ("dispatch_enabled", "INTEGER", 0),
        ("egress_enabled", "INTEGER", 0),
        ("trusted_authority_id", "TEXT", 0),
        ("trusted_authority_epoch", "INTEGER", 0),
        ("trusted_authority_digest", "BLOB", 0),
        ("mode", "TEXT", 0),
        ("owner_id", "TEXT", 0),
    ),
    "control_packs": (
        ("pack_id", "TEXT", 1),
        ("state_id", "TEXT", 0),
        ("deployment_id", "TEXT", 0),
        ("program_id", "TEXT", 0),
        ("period_id", "TEXT", 0),
        ("version", "INTEGER", 0),
        ("source_refs_json", "TEXT", 0),
        ("effective_start_ms", "INTEGER", 0),
        ("effective_end_ms", "INTEGER", 0),
        ("recorded_at_ms", "INTEGER", 0),
        ("approved_at_ms", "INTEGER", 0),
        ("calculation_rule_id", "TEXT", 0),
        ("adjustment_rule_id", "TEXT", 0),
        ("authorized_roles_json", "TEXT", 0),
        ("expected_tests_json", "TEXT", 0),
        ("pack_digest", "BLOB", 0),
        ("status", "TEXT", 0),
    ),
    "population_imports": (
        ("population_id", "TEXT", 1),
        ("pack_id", "TEXT", 0),
        ("cutoff_ms", "INTEGER", 0),
        ("inclusion_rules_json", "TEXT", 0),
        ("expected_count", "INTEGER", 0),
        ("source_complete", "INTEGER", 0),
        ("imported_count", "INTEGER", 0),
        ("validated_count", "INTEGER", 0),
        ("validation_digest", "BLOB", 0),
        ("status", "TEXT", 0),
        ("created_at_ms", "INTEGER", 0),
        ("updated_at_ms", "INTEGER", 0),
    ),
    "population_items": (
        ("population_id", "TEXT", 1),
        ("item_id", "TEXT", 2),
        ("display_label", "TEXT", 0),
        ("owed_cents", "INTEGER", 0),
        ("due_at_ms", "INTEGER", 0),
        ("currency", "TEXT", 0),
    ),
    "obligations": (
        ("obligation_id", "TEXT", 1),
        ("population_id", "TEXT", 0),
        ("item_id", "TEXT", 0),
        ("period_id", "TEXT", 0),
        ("currency", "TEXT", 0),
        ("owed_cents", "INTEGER", 0),
        ("due_at_ms", "INTEGER", 0),
        ("rule_version", "INTEGER", 0),
        ("revision", "INTEGER", 0),
        ("claimed_adjustment_cents", "INTEGER", 0),
        ("lawful_adjustment_cents", "INTEGER", 0),
        ("received_cash_cents", "INTEGER", 0),
        ("shortfall_cents", "INTEGER", 0),
        ("overage_cents", "INTEGER", 0),
        ("cash_satisfied", "INTEGER", 0),
        ("amount_satisfied", "INTEGER", 0),
        ("timely", "INTEGER", 0),
        ("reporting_complete", "INTEGER", 0),
        ("verification_status", "TEXT", 0),
        ("case_status", "TEXT", 0),
        ("delivery_status", "TEXT", 0),
        ("current_evaluation_id", "TEXT", 0),
        ("updated_at_ms", "INTEGER", 0),
    ),
    "evidence": (
        ("evidence_id", "TEXT", 1),
        ("item_id", "TEXT", 0),
        ("kind", "TEXT", 0),
        ("common_origin_id", "TEXT", 0),
        ("source_id", "TEXT", 0),
        ("source_version", "TEXT", 0),
        ("local_ref", "TEXT", 0),
        ("applicable_at_ms", "INTEGER", 0),
        ("event_at_ms", "INTEGER", 0),
        ("received_at_ms", "INTEGER", 0),
        ("content_digest", "BLOB", 0),
        ("record_digest", "BLOB", 0),
        ("amount_cents", "INTEGER", 0),
        ("reversal_of", "TEXT", 0),
        ("supersedes", "TEXT", 0),
    ),
    "payments": (
        ("payment_id", "TEXT", 1),
        ("obligation_id", "TEXT", 0),
        ("item_id", "TEXT", 0),
        ("evidence_id", "TEXT", 0),
        ("common_origin_id", "TEXT", 0),
        ("amount_cents", "INTEGER", 0),
        ("event_at_ms", "INTEGER", 0),
        ("active", "INTEGER", 0),
        ("reversed_by_evidence_id", "TEXT", 0),
    ),
    "claimed_adjustments": (
        ("claim_id", "TEXT", 1),
        ("obligation_id", "TEXT", 0),
        ("evidence_id", "TEXT", 0),
        ("amount_cents", "INTEGER", 0),
        ("owner_role", "TEXT", 0),
        ("deadline_ms", "INTEGER", 0),
        ("status", "TEXT", 0),
        ("created_at_ms", "INTEGER", 0),
        ("updated_at_ms", "INTEGER", 0),
    ),
    "cases": (
        ("case_id", "TEXT", 1),
        ("obligation_id", "TEXT", 0),
        ("reason", "TEXT", 0),
        ("contractual_accountability", "TEXT", 0),
        ("next_action_owner", "TEXT", 0),
        ("due_at_ms", "INTEGER", 0),
        ("completion_conditions_json", "TEXT", 0),
        ("status", "TEXT", 0),
        ("updated_at_ms", "INTEGER", 0),
    ),
    "determinations": (
        ("determination_id", "TEXT", 1),
        ("obligation_id", "TEXT", 0),
        ("claim_id", "TEXT", 0),
        ("actor_id", "TEXT", 0),
        ("actor_role", "TEXT", 0),
        ("authority_id", "TEXT", 0),
        ("authority_epoch", "INTEGER", 0),
        ("authority_digest", "BLOB", 0),
        ("decision", "TEXT", 0),
        ("amount_cents", "INTEGER", 0),
        ("supporting_evidence_json", "TEXT", 0),
        ("expected_revision", "INTEGER", 0),
        ("resulting_revision", "INTEGER", 0),
        ("decided_at_ms", "INTEGER", 0),
        ("determination_digest", "BLOB", 0),
        ("input_evaluation_id", "TEXT", 0),
        ("input_evaluation_result_digest", "BLOB", 0),
    ),
    "actions": (
        ("action_id", "TEXT", 1),
        ("obligation_id", "TEXT", 0),
        ("determination_id", "TEXT", 0),
        ("kind", "TEXT", 0),
        ("status", "TEXT", 0),
        ("revision", "INTEGER", 0),
        ("payload_json", "TEXT", 0),
        ("payload_digest", "BLOB", 0),
        ("idempotency_key", "BLOB", 0),
        ("created_at_ms", "INTEGER", 0),
    ),
    "action_outbox": (
        ("action_id", "TEXT", 1),
        ("status", "TEXT", 0),
        ("attempt", "INTEGER", 0),
        ("payload_digest", "BLOB", 0),
        ("acknowledgment_ref", "TEXT", 0),
        ("updated_at_ms", "INTEGER", 0),
    ),
    "financial_events": (
        ("event_sequence", "INTEGER", 1),
        ("event_id", "BLOB", 0),
        ("aggregate_type", "TEXT", 0),
        ("aggregate_id", "TEXT", 0),
        ("kind", "TEXT", 0),
        ("before_revision", "INTEGER", 0),
        ("after_revision", "INTEGER", 0),
        ("payload_json", "TEXT", 0),
        ("payload_digest", "BLOB", 0),
        ("previous_head", "BLOB", 0),
        ("head", "BLOB", 0),
        ("committed_at_ms", "INTEGER", 0),
    ),
    "financial_conflicts": (
        ("conflict_id", "TEXT", 1),
        ("obligation_id", "TEXT", 0),
        ("common_origin_id", "TEXT", 0),
        ("existing_payment_id", "TEXT", 0),
        ("candidate_evidence_id", "TEXT", 0),
        ("existing_amount_cents", "INTEGER", 0),
        ("candidate_amount_cents", "INTEGER", 0),
        ("reason", "TEXT", 0),
        ("visible_at_ms", "INTEGER", 0),
    ),
    "evaluations": (
        ("evaluation_id", "TEXT", 1),
        ("obligation_id", "TEXT", 0),
        ("revision", "INTEGER", 0),
        ("rule_version", "INTEGER", 0),
        ("evidence_ids_json", "TEXT", 0),
        ("authority_id", "TEXT", 0),
        ("evaluated_at_ms", "INTEGER", 0),
        ("owed_cents", "INTEGER", 0),
        ("claimed_adjustment_cents", "INTEGER", 0),
        ("lawful_adjustment_cents", "INTEGER", 0),
        ("received_cash_cents", "INTEGER", 0),
        ("shortfall_cents", "INTEGER", 0),
        ("overage_cents", "INTEGER", 0),
        ("cash_satisfied", "INTEGER", 0),
        ("amount_satisfied", "INTEGER", 0),
        ("timely", "INTEGER", 0),
        ("reporting_complete", "INTEGER", 0),
        ("verification_status", "TEXT", 0),
        ("case_status", "TEXT", 0),
        ("delivery_status", "TEXT", 0),
        ("result_digest", "BLOB", 0),
        ("contract_version", "TEXT", 0),
        ("scope_json", "TEXT", 0),
        ("control_pack_id", "TEXT", 0),
        ("control_pack_version", "INTEGER", 0),
        ("control_pack_digest", "BLOB", 0),
        ("authority_epoch", "INTEGER", 0),
        ("authority_digest", "BLOB", 0),
        ("evidence_bindings_json", "TEXT", 0),
        ("input_snapshot_json", "TEXT", 0),
        ("input_snapshot_digest", "BLOB", 0),
        ("receipt_digest", "BLOB", 0),
    ),
}

TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    table: tuple(column[0] for column in definition)
    for table, definition in _TABLE_DEFS.items()
}
TABLES = frozenset(_TABLE_DEFS)

_TRIGGER_DEFS = {
    "action_payload_immutable": "CREATE TRIGGER action_payload_immutable BEFORE UPDATE OF action_id,obligation_id,determination_id,kind,revision,payload_json,payload_digest,idempotency_key,created_at_ms ON actions BEGIN SELECT RAISE(ABORT,'action_payload_immutable'); END",
    "action_outbox_payload_immutable": "CREATE TRIGGER action_outbox_payload_immutable BEFORE UPDATE OF action_id,payload_digest ON action_outbox BEGIN SELECT RAISE(ABORT,'action_outbox_payload_immutable'); END",
    "evidence_record_immutable": "CREATE TRIGGER evidence_record_immutable BEFORE UPDATE OF evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,content_digest,record_digest,amount_cents,reversal_of,supersedes ON evidence BEGIN SELECT RAISE(ABORT,'evidence_record_immutable'); END",
    "financial_identity_insert_immutable": "CREATE TRIGGER financial_identity_insert_immutable BEFORE INSERT ON financial_identity WHEN EXISTS (SELECT 1 FROM financial_identity) BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END",
    "financial_identity_update_immutable": "CREATE TRIGGER financial_identity_update_immutable BEFORE UPDATE OF schema_version,provenance,bound_mode,bound_owner_id,anchor_sequence,anchor_head,genesis_head,source_package_digest,identity_digest ON financial_identity BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END",
    "financial_identity_delete_immutable": "CREATE TRIGGER financial_identity_delete_immutable BEFORE DELETE ON financial_identity BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END",
}

_EVENT_KINDS = {
    "CONTROL_PACK": {"CONTROL_PACK_PUBLISHED"},
    "POPULATION": {"POPULATION_STAGED", "POPULATION_SOURCE_COMPLETED", "POPULATION_VALIDATED", "POPULATION_PUBLISHED"},
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
_ACTION_STATUSES = {"READY", "ACKNOWLEDGED", "CANCELLED"}
_CLAIM_STATUSES = {"CLAIMED", "AUTHORIZED", "REJECTED"}


@dataclass(frozen=True, slots=True)
class ExpectedFinancialIdentity:
    """External binding required before a database can be accepted."""

    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    authority_id: str = "synthetic-authority-v1"
    authority_epoch: int = 1
    authority_digest: bytes | str | None = None
    currency: str = CURRENCY
    mode: str | None = None
    owner_id: str | None = None
    continuity_epoch: int | None = None


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


def _identity_record(value: Mapping[str, object], code_prefix: str = "identity") -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(TABLE_COLUMNS["financial_identity"]):
        _fail(f"{code_prefix}:shape")
    if value["id"] != 1 or value["schema_version"] != SCHEMA_VERSION:
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
        "schema_version": SCHEMA_VERSION,
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


def _field(value: object, name: str, *aliases: str) -> object:
    names = (name, *aliases)
    if isinstance(value, Mapping):
        for candidate in names:
            if candidate in value:
                return value[candidate]
        _fail(f"identity:missing-{name}")
    for candidate in names:
        if hasattr(value, candidate):
            return getattr(value, candidate)
    _fail(f"identity:missing-{name}")


def _default_authority_digest() -> bytes:
    authority = {
        "authority_id": "synthetic-authority-v1",
        "epoch": 1,
        "actors": [
            {"actor_id": "synthetic-official", "roles": ["FINANCE_DECISION", "CASE_OWNER"]},
            {"actor_id": "synthetic-reporter", "roles": ["REPORTING_EDITOR"]},
            {"actor_id": "synthetic-receiver", "roles": ["RECEIVER"]},
        ],
        "synthetic_only": True,
    }
    return _digest(EVIDENCE_DOMAIN, _canonical(authority))


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
    if authority_source is None:
        authority_id = "synthetic-authority-v1"
        authority_epoch = 1
        authority_digest = _default_authority_digest()
        actors = {
            "synthetic-official": frozenset({"FINANCE_DECISION", "CASE_OWNER"}),
            "synthetic-reporter": frozenset({"REPORTING_EDITOR"}),
            "synthetic-receiver": frozenset({"RECEIVER"}),
        }
    else:
        authority_id = _id(_field(authority_source, "authority_id"), "identity:authority-id")
        authority_epoch = _integer(_field(authority_source, "authority_epoch", "epoch"), "identity:authority-epoch", minimum=1, maximum=MAX_CENTS)
        raw_digest = None
        if isinstance(authority_source, Mapping):
            raw_digest = authority_source.get("authority_digest", authority_source.get("digest"))
        else:
            raw_digest = getattr(authority_source, "authority_digest", getattr(authority_source, "digest", None))
        if raw_digest is None and authority_id == "synthetic-authority-v1" and authority_epoch == 1:
            authority_digest = _default_authority_digest()
        else:
            authority_digest = _hex_digest(raw_digest, "identity:authority-digest")
        actors = _actor_roles(authority_source)
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
    return {
        "scope": scope,
        "authority_id": authority_id,
        "authority_epoch": authority_epoch,
        "authority_digest": authority_digest,
        "actors": actors,
        "mode": mode,
        "owner_id": owner_id,
        "continuity_epoch": epoch,
    }


def _open_readonly(path: str | Path) -> sqlite3.Connection:
    if not isinstance(path, (str, Path)):
        _fail("database:path")
    target = Path(path)
    try:
        if target.is_symlink() or not target.is_file():
            _fail("database:path")
        if target.stat().st_size <= 0 or target.stat().st_size > MAX_DATABASE_BYTES:
            _fail("database:byte-cap")
        uri = "file:" + quote(target.resolve().as_posix(), safe="/:") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
    except IndependentFinancialError:
        raise
    except (OSError, sqlite3.Error, ValueError):
        _fail("database:open")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
    except sqlite3.Error:
        connection.close()
        _fail("database:query-only")
    return connection


def _verify_schema(connection: sqlite3.Connection) -> None:
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != TABLES:
            _fail("schema:tables")
        for table, definition in _TABLE_DEFS.items():
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
    except IndependentFinancialError:
        raise
    except sqlite3.Error:
        _fail("schema:read")


def _bounded_rows(connection: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    try:
        count = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        if count > MAX_ROWS:
            _fail(f"rows:cap:{table}")
        return list(connection.execute(f"SELECT * FROM {table}"))
    except IndependentFinancialError:
        raise
    except sqlite3.Error:
        _fail(f"rows:read:{table}")


def _verify_meta(connection: sqlite3.Connection, identity: dict[str, object]) -> dict[str, object]:
    try:
        if int(connection.execute("SELECT COUNT(*) FROM financial_meta").fetchone()[0]) != 1:
            _fail("meta:cardinality")
        row = connection.execute("SELECT * FROM financial_meta WHERE id=1").fetchone()
    except (sqlite3.Error, TypeError, ValueError):
        _fail("meta:read")
    if row is None:
        _fail("meta:missing")
    if row["id"] != 1 or row["schema_version"] != SCHEMA_VERSION or row["schema"] != SCHEMA:
        _fail("meta:schema")
    scope = identity["scope"]
    assert isinstance(scope, dict)
    for key in ("state_id", "deployment_id", "program_id", "period_id", "currency"):
        _text(row[key], f"meta:{key}")
        if row[key] != scope[key]:
            _fail(f"meta:scope:{key}")
    sequence = _integer(row["sequence"], "meta:sequence", maximum=MAX_ROWS)
    history_head = _blob64(row["history_head"], "meta:history-head")
    continuity_epoch = _integer(row["continuity_epoch"], "meta:continuity-epoch", minimum=1, maximum=MAX_CENTS)
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
    except (sqlite3.Error, TypeError, ValueError):
        _fail("identity:read")
    if identity_row is None:
        _fail("identity:missing")
    identity_contract = _identity_record(
        {column: identity_row[column] for column in TABLE_COLUMNS["financial_identity"]}
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
    }


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
        payload = _parse_json(payload_raw, "history:payload")
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
        previous = head
    if previous != meta["history_head"]:
        _fail("history:meta-head")
    identity = meta["identity"]
    assert isinstance(identity, dict)
    anchor_sequence = int(identity["anchor_sequence"])
    if anchor_sequence > 0:
        if anchor_sequence > len(rows) or bytes(rows[anchor_sequence - 1]["head"]) != identity["anchor_head"]:
            _fail("identity:history-anchor")
    return rows


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


def _verify_populations(
    connection: sqlite3.Connection,
    meta: dict[str, object],
    packs: dict[str, sqlite3.Row],
) -> tuple[dict[str, sqlite3.Row], dict[str, sqlite3.Row]]:
    imports = _bounded_rows(connection, "population_imports")
    items = _bounded_rows(connection, "population_items")
    populations: dict[str, sqlite3.Row] = {}
    items_by_population: dict[str, list[sqlite3.Row]] = {}
    item_by_id: dict[str, sqlite3.Row] = {}
    scope = meta["scope"]
    assert isinstance(scope, dict)
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
        items_by_population[population_id] = []
        _ = scope
    for row in items:
        population_id = _id(row["population_id"], "item:population-id")
        if population_id not in populations:
            _fail("item:population")
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
    events: list[sqlite3.Row],
    populations: dict[str, sqlite3.Row],
    packs: dict[str, sqlite3.Row],
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

    for population_id, population in populations.items():
        expected = _integer(population["expected_count"], "history:population-expected", minimum=1, maximum=MAX_ROWS)
        imported = 0
        source_completed = False
        validated = False
        published = False
        previous_committed_at: int | None = None
        for event in by_population[population_id]:
            committed_at = _time(event["committed_at_ms"], "history:population-committed-at")
            if previous_committed_at is not None and committed_at < previous_committed_at:
                _fail("history:population-chronology")
            previous_committed_at = committed_at
            before = _integer(event["before_revision"], "history:population-before", maximum=MAX_ROWS)
            after = _integer(event["after_revision"], "history:population-after", maximum=MAX_ROWS)
            payload = _parse_json(event["payload_json"], "history:population-payload")
            if not isinstance(payload, dict):
                _fail("history:population-payload")
            kind = str(event["kind"])
            if kind == "POPULATION_STAGED":
                if source_completed or validated or published:
                    _fail("history:population-stage-order")
                if set(payload) != {"population_id", "imported_count", "chunk_count"}:
                    _fail("history:population-stage-payload")
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
                if set(payload) != {"population_id", "imported_count", "expected_count"}:
                    _fail("history:population-completion-payload")
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
                if set(payload) != {"population_id", "validated_count", "validation_digest"}:
                    _fail("history:population-validation-payload")
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
                if set(payload) != {"population_id", "item_count", "pack_id", "pack_version", "evaluation_count", "evaluation_binding_digest"}:
                    _fail("history:population-publication-payload")
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


def _verify_evidence(
    connection: sqlite3.Connection,
    items: dict[str, sqlite3.Row],
    obligations: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "evidence")
    evidence: dict[str, sqlite3.Row] = {}
    for row in rows:
        evidence_id = _id(row["evidence_id"], "evidence:id")
        if evidence_id in evidence:
            _fail("evidence:duplicate")
        evidence[evidence_id] = row
        item_id = _id(row["item_id"], "evidence:item")
        if item_id not in items or item_id not in {str(item["item_id"]) for item in obligations.values()}:
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
        prior = evidence.get(str(supersedes))
        if prior is None:
            _fail("evidence:report-supersedes-missing")
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
    used_evidence: set[str] = set()
    for row in rows:
        claim_id = _id(row["claim_id"], "claim:id")
        if claim_id in claims:
            _fail("claim:duplicate")
        claims[claim_id] = row
        obligation_id = _id(row["obligation_id"], "claim:obligation")
        if obligation_id not in obligations:
            _fail("claim:obligation")
        evidence_id = _id(row["evidence_id"], "claim:evidence")
        ev = evidence.get(evidence_id)
        if ev is None or ev["kind"] != "OFFSET_CLAIM" or ev["item_id"] != obligations[obligation_id]["item_id"] or ev["common_origin_id"] != claim_id or ev["amount_cents"] != row["amount_cents"]:
            _fail("claim:evidence")
        if evidence_id in used_evidence:
            _fail("claim:evidence-duplicate")
        used_evidence.add(evidence_id)
        _cents(row["amount_cents"], "claim:amount", positive=True)
        _role(row["owner_role"], "claim:owner")
        _time(row["deadline_ms"], "claim:deadline")
        if row["status"] not in _CLAIM_STATUSES:
            _fail("claim:status")
        created = _time(row["created_at_ms"], "claim:created")
        updated = _time(row["updated_at_ms"], "claim:updated")
        if updated < created:
            _fail("claim:chronology")
    return claims


def _verify_cases(connection: sqlite3.Connection, obligations: dict[str, sqlite3.Row]) -> dict[str, list[sqlite3.Row]]:
    rows = _bounded_rows(connection, "cases")
    cases: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        case_id = _id(row["case_id"], "case:id")
        obligation_id = _id(row["obligation_id"], "case:obligation")
        if obligation_id not in obligations:
            _fail("case:orphan")
        _text(row["reason"], "case:reason")
        _text(row["contractual_accountability"], "case:accountability")
        _role(row["next_action_owner"], "case:owner")
        _time(row["due_at_ms"], "case:due")
        conditions = _parse_json(row["completion_conditions_json"], "case:conditions")
        if conditions != {"amount_satisfied": True, "delivery_acknowledged_or_not_required": True, "reporting_complete": True}:
            _fail("case:conditions")
        if row["status"] not in _CASE_STATUSES:
            _fail("case:status")
        _time(row["updated_at_ms"], "case:updated")
        cases.setdefault(obligation_id, []).append(row)
        _ = case_id
    return cases


def _verify_determinations(
    connection: sqlite3.Connection,
    meta: dict[str, object],
    obligations: dict[str, sqlite3.Row],
    populations: dict[str, sqlite3.Row],
    packs: dict[str, sqlite3.Row],
    claims: dict[str, sqlite3.Row],
    evidence: dict[str, sqlite3.Row],
    evaluations: dict[str, list[sqlite3.Row]],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "determinations")
    result: dict[str, sqlite3.Row] = {}
    evaluations_by_id = {
        str(evaluation["evaluation_id"]): evaluation
        for history in evaluations.values()
        for evaluation in history
    }
    consumed_evaluations: set[str] = set()
    actor_roles = meta.get("actors")
    for row in rows:
        determination_id = _id(row["determination_id"], "determination:id")
        if determination_id in result:
            _fail("determination:duplicate")
        result[determination_id] = row
        obligation_id = _id(row["obligation_id"], "determination:obligation")
        if obligation_id not in obligations:
            _fail("determination:obligation")
        claim_id = row["claim_id"]
        if claim_id is not None:
            claim_id = _id(claim_id, "determination:claim-id")
            if claim_id not in claims:
                _fail("determination:claim")
        actor_id = _id(row["actor_id"], "determination:actor")
        actor_role = _role(row["actor_role"], "determination:role")
        if isinstance(actor_roles, dict) and actor_id in actor_roles and actor_role not in actor_roles[actor_id]:
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
        if claim_id is None or len(supporting) != len(_evidence_ids_json(input_evaluation["evidence_ids_json"], "determination:evaluation-evidence")) or claim_id not in claims:
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
    obligations: dict[str, sqlite3.Row],
    claims: dict[str, sqlite3.Row],
    determinations: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "actions")
    outbox_rows = _bounded_rows(connection, "action_outbox")
    outbox = {str(row["action_id"]): row for row in outbox_rows}
    if len(outbox) != len(outbox_rows):
        _fail("outbox:duplicate")
    actions: dict[str, sqlite3.Row] = {}
    for row in rows:
        action_id = _id(row["action_id"], "action:id")
        if action_id in actions:
            _fail("action:duplicate")
        actions[action_id] = row
        obligation_id = _id(row["obligation_id"], "action:obligation")
        if obligation_id not in obligations:
            _fail("action:obligation")
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
        claim = claims.get(str(claim_id)) if claim_id is not None else None
        if claim is None:
            _fail("action:claim")
        expected_payload = {
            "action_id": action_id,
            "obligation_id": obligation_id,
            "determination_id": determination_id,
            "kind": kind,
            "claim_id": claim_id,
            "amount_cents": claim["amount_cents"],
            "currency": meta["scope"]["currency"],
            "revision": revision,
            "input_evaluation_id": determination["input_evaluation_id"],
            "input_evaluation_result_digest": bytes(determination["input_evaluation_result_digest"]).hex().upper(),
            "dispatch": "SYNTHETIC_RECORD_ONLY",
        }
        if payload != expected_payload:
            _fail("action:payload-binding")
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
        _integer(box["attempt"], "outbox:attempt")
        acknowledgment = box["acknowledgment_ref"]
        if row["status"] == "READY" and acknowledgment is not None:
            _fail("outbox:ready-ack")
        if row["status"] == "ACKNOWLEDGED":
            if acknowledgment is None:
                _fail("outbox:ack-missing")
            _id(acknowledgment, "outbox:ack")
            if box["attempt"] < 1:
                _fail("outbox:ack-attempt")
        _time(box["updated_at_ms"], "outbox:updated")
    if set(outbox) != set(actions):
        _fail("outbox:orphan")
    return actions


def _verify_conflicts(
    connection: sqlite3.Connection,
    obligations: dict[str, sqlite3.Row],
    evidence: dict[str, sqlite3.Row],
    payments: dict[str, sqlite3.Row],
) -> dict[str, sqlite3.Row]:
    rows = _bounded_rows(connection, "financial_conflicts")
    conflicts: dict[str, sqlite3.Row] = {}
    keys: set[tuple[str, str, str]] = set()
    for row in rows:
        conflict_id = _id(row["conflict_id"], "conflict:id")
        if conflict_id in conflicts:
            _fail("conflict:duplicate")
        conflicts[conflict_id] = row
        obligation_id = _id(row["obligation_id"], "conflict:obligation")
        if obligation_id not in obligations:
            _fail("conflict:obligation")
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
        _time(row["visible_at_ms"], "conflict:visible")
        key = (obligation_id, common_origin_id, candidate_id)
        if key in keys:
            _fail("conflict:key")
        keys.add(key)
    # Every payment confirmation that is not the persisted payment itself must
    # be either an equal duplicate or an explicitly visible amount conflict.
    for candidate_id, candidate in evidence.items():
        if candidate["kind"] != "PAYMENT_CONFIRMATION":
            continue
        obligation = next((row for row in obligations.values() if row["item_id"] == candidate["item_id"]), None)
        if obligation is None:
            _fail("conflict:orphan-confirmation")
        matching = [row for row in payments.values() if row["obligation_id"] == obligation["obligation_id"] and row["common_origin_id"] == candidate["common_origin_id"]]
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


def _evaluation_projection_from_input(snapshot: dict[str, object], *, evaluation: sqlite3.Row) -> dict[str, object]:
    obligation = snapshot["obligation"]
    assert isinstance(obligation, dict)
    evidence = snapshot["evidence"]
    payments = snapshot["payments"]
    claims = snapshot["claims"]
    determinations = snapshot["determinations"]
    cases = snapshot["cases"]
    actions = snapshot["actions"]
    conflicts = snapshot["conflicts"]
    assert isinstance(evidence, list) and isinstance(payments, list) and isinstance(claims, list)
    assert isinstance(determinations, list) and isinstance(cases, list) and isinstance(actions, list) and isinstance(conflicts, list)
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
    prior_case = "OPEN" if not cases else str(max(cases, key=lambda row: str(row["case_id"]))["status"])
    if amount_satisfied and int(obligation["reporting_complete"]):
        case_status = "RESOLVED"
    elif amount_satisfied:
        case_status = "ACTIONED"
    elif prior_case in {"CORRECTION_REQUIRED", "AUTHORIZED"}:
        case_status = prior_case
    else:
        case_status = "OPEN"
    delivery = "NONE" if not actions else str(max(actions, key=lambda row: (int(row["created_at_ms"]), str(row["action_id"])))["status"])
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
    rows = _bounded_rows(connection, "evaluations")
    by_obligation: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        evaluation_id = _id(row["evaluation_id"], "evaluation:id")
        obligation_id = _id(row["obligation_id"], "evaluation:obligation")
        obligation = obligations.get(obligation_id)
        if obligation is None:
            _fail("evaluation:orphan")
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
        for item in snapshot["actions"]:
            action = connection.execute("SELECT obligation_id,created_at_ms FROM actions WHERE action_id=?", (item["action_id"],)).fetchone()
            if action is None or action["obligation_id"] != obligation_id or int(action["created_at_ms"]) != int(item["created_at_ms"]):
                _fail("evaluation:input-action")
        for conflict_id in snapshot["conflicts"]:
            conflict = connection.execute("SELECT obligation_id FROM financial_conflicts WHERE conflict_id=?", (conflict_id,)).fetchone()
            if conflict is None or conflict["obligation_id"] != obligation_id:
                _fail("evaluation:input-conflict")
        input_projection = _evaluation_projection_from_input(snapshot, evaluation=row)
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
    cases: dict[str, list[sqlite3.Row]],
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
    for obligation_id, obligation in obligations.items():
        population = populations[str(obligation["population_id"])]
        pack = packs[str(population["pack_id"])]
        authorized_roles = _values_json(pack["authorized_roles_json"], "pack:roles")
        calculation, adjustment = _control_pack_policy(pack["calculation_rule_id"], pack["adjustment_rule_id"], authorized_roles, _values_json(pack["expected_tests_json"], "pack:tests"))
        if calculation != "PER_RECIPIENT" or adjustment != "AUTHORIZED_OFFSET":
            _fail("projection:policy")
        active_payments = [row for row in payments.values() if row["obligation_id"] == obligation_id and row["active"] == 1]
        obligation_claims = [row for row in claims.values() if row["obligation_id"] == obligation_id]
        cash = _sum_cents([int(row["amount_cents"]) for row in active_payments], "projection:cash")
        claimed = _sum_cents([int(row["amount_cents"]) for row in obligation_claims if row["status"] in {"CLAIMED", "AUTHORIZED"}], "projection:claimed")
        lawful = _sum_cents([int(row["amount_cents"]) for row in obligation_claims if row["status"] == "AUTHORIZED"], "projection:lawful")
        total = _add_cents(cash, lawful, "projection:total")
        owed = int(obligation["owed_cents"])
        shortfall = max(owed - total, 0)
        overage = max(total - owed, 0)
        item_evidence = [row for row in evidence.values() if row["item_id"] == obligation["item_id"]]
        evidence_count = len(item_evidence)
        conflict_count = sum(1 for row in conflicts.values() if row["obligation_id"] == obligation_id)
        verification = "CONFLICT_VISIBLE" if conflict_count else ("SUPPORTED" if evidence_count else "MISSING_EVIDENCE")
        completion = _completion_time(obligation, active_payments, determinations_by_obligation.get(obligation_id, []))
        timely = int(completion is not None and completion <= obligation["due_at_ms"])
        amount_satisfied = int(total >= owed)
        cash_satisfied = int(cash >= owed)
        reporting_complete = int(obligation["reporting_complete"])
        action_rows = [row for row in actions.values() if row["obligation_id"] == obligation_id]
        delivery = "NONE" if not action_rows else str(max(action_rows, key=lambda row: (row["created_at_ms"], row["action_id"]))["status"])
        case_rows = cases.get(obligation_id, [])
        prior_case = "OPEN" if not case_rows else str(max(case_rows, key=lambda row: row["case_id"])["status"])
        if amount_satisfied and reporting_complete:
            case_status = "RESOLVED"
        elif amount_satisfied:
            case_status = "ACTIONED"
        elif prior_case in {"CORRECTION_REQUIRED", "AUTHORIZED"}:
            case_status = prior_case
        else:
            case_status = "OPEN"
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
            "case_status": case_status,
            "delivery_status": delivery,
            "current_evaluation_id": obligation["current_evaluation_id"],
        }
        for key, value in expected.items():
            if obligation[key] != value:
                _fail(f"projection:{key}")
        history = evaluations.get(obligation_id, [])
        current = max(history, key=lambda row: row["revision"])
        if obligation["current_evaluation_id"] != current["evaluation_id"] or current["revision"] != obligation["revision"]:
            _fail("projection:current-evaluation")
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
) -> None:
    for row in events:
        aggregate_type = row["aggregate_type"]
        aggregate_id = row["aggregate_id"]
        if aggregate_type == "CONTROL_PACK" and aggregate_id not in packs:
            _fail("history:pack-reference")
        if aggregate_type == "POPULATION" and aggregate_id not in populations:
            _fail("history:population-reference")
        if aggregate_type == "OBLIGATION" and aggregate_id not in obligations:
            _fail("history:obligation-reference")


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
    return _digest(CONTINUITY_DOMAIN, _canonical(dict(payload), "continuity:digest-input")).hex().upper()


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
    for table in TABLES:
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
    for table in TABLES:
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


def verify_continuity_package(
    raw: bytes,
    *,
    expected_config: object | None = None,
    expected_scope: object | None = None,
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
    if value["schema"] != CONTINUITY_SCHEMA or value["version"] != 5:
        _fail("continuity:schema")
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
    if not isinstance(tables, dict) or set(tables) != TABLES:
        _fail("continuity:tables")
    counts: dict[str, int] = {}
    decoded_rows: dict[str, list[dict[str, object]]] = {}
    for table in TABLES:
        decoded_rows[table] = _verify_package_rows(tables[table], table)
        counts[table] = len(decoded_rows[table])
    if counts["financial_meta"] != 1:
        _fail("continuity:meta-cardinality")
    meta = decoded_rows["financial_meta"][0]
    if meta["id"] != 1 or meta["schema_version"] != SCHEMA_VERSION or meta["schema"] != SCHEMA:
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
    identity_contract = _identity_record(decoded_rows["financial_identity"][0], "continuity:identity")
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
    result: dict[str, object] = {
        "schema": CONTINUITY_SCHEMA,
        "scope": dict(scope),
        "authority": {"authority_id": authority_id, "epoch": authority_epoch, "digest": authority_digest.hex().upper()},
        "continuity_epoch": epoch,
        "sequence": sequence,
        "history_head": history_head.hex().upper(),
        "table_counts": counts,
        "package_digest": package_digest,
    }
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
    _verify_schema(connection)
    meta = _verify_meta(connection, identity)
    events = _verify_events(connection, meta)
    packs = _verify_packs(connection, meta)
    populations, items = _verify_populations(connection, meta, packs)
    _verify_population_history(events, populations, packs)
    obligations = _verify_obligations(connection, meta, populations, items, packs)
    evidence = _verify_evidence(connection, items, obligations)
    payments = _verify_payments(connection, obligations, items, evidence)
    claims = _verify_adjustments(connection, obligations, evidence)
    cases = _verify_cases(connection, obligations)
    evaluations = _verify_evaluations(connection, meta, obligations, populations, packs, evidence)
    _verify_evaluation_history_events(events, populations, obligations, evaluations)
    determinations = _verify_determinations(connection, meta, obligations, populations, packs, claims, evidence, evaluations)
    actions = _verify_actions(connection, meta, obligations, claims, determinations)
    conflicts = _verify_conflicts(connection, obligations, evidence, payments)
    _verify_event_references(events, packs, populations, obligations)
    projections, totals = _verify_projections(meta, obligations, populations, packs, evidence, payments, claims, cases, determinations, actions, conflicts, evaluations)
    package_result: dict[str, object] | None = None
    if current_snapshot_package is not None and restore_source_package is not None:
        _fail("continuity:duplicate-input")
    if current_snapshot_package is not None:
        package_result = verify_continuity_package(
            current_snapshot_package,
            expected_scope=meta["scope"],
            expected_authority={
                "authority_id": meta["authority_id"],
                "epoch": meta["authority_epoch"],
                "digest": meta["authority_digest"],
            },
            expected_sequence=meta["sequence"],
            expected_history_head=meta["history_head"],
            expected_continuity_epoch=meta["continuity_epoch"],
            _include_rows=True,
        )
        package_rows = package_result.pop("_decoded_rows")
        assert isinstance(package_rows, dict)
        _verify_current_snapshot(connection, package_rows)
        package_result["role"] = "current_snapshot"
    elif restore_source_package is not None:
        package_result = verify_continuity_package(
            restore_source_package,
            expected_scope=meta["scope"],
            expected_authority={
                "authority_id": meta["authority_id"],
                "epoch": meta["authority_epoch"],
                "digest": meta["authority_digest"],
            },
            expected_continuity_epoch=meta["continuity_epoch"],
            _include_rows=True,
        )
        package_rows = package_result.pop("_decoded_rows")
        assert isinstance(package_rows, dict)
        _verify_restore_source_binding(meta, package_result, package_rows)
        package_result["role"] = "restore_source"
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
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
    }


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
    try:
        try:
            return _verify_connection(
                connection,
                identity=identity,
                current_snapshot_package=current_snapshot_package,
                restore_source_package=restore_source_package,
            )
        except IndependentFinancialError:
            raise
        except (sqlite3.Error, KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError):
            _fail("database:malformed")
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
    try:
        return _verify_connection(
            connection,
            identity=identity,
            current_snapshot_package=current_snapshot_package,
            restore_source_package=restore_source_package,
        )
    except IndependentFinancialError:
        raise
    except (sqlite3.Error, KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError):
        _fail("database:malformed")


verify = verify_database
verify_continuity = verify_continuity_package
