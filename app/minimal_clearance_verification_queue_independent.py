"""Independent reconstruction of the durable Queue V10 image.

This module intentionally does not import the queue writer.  It checks the
clean-break schema, exact guard identity, immutable batch/member image,
reservation and lifecycle chains, bounded zero-PHI codes, and reconstructs a
complete VERIFIED batch from the batch owner plus its ordered members.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any, Final, Mapping


class IndependentQueueError(RuntimeError):
    pass


SCHEMA_VERSION: Final[int] = 10
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/v10"
_MATERIAL: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v9\x00"
_ADMISSION_CAP: Final[int] = 4_500_000_000
_DATABASE_PAGE_SIZE: Final[int] = 4096
_DATABASE_MAX_PAGE_COUNT: Final[int] = 32768
_DATABASE_CAP: Final[int] = _DATABASE_PAGE_SIZE * _DATABASE_MAX_PAGE_COUNT
_COUNT: Final[int] = 100
_PROOF_ATTEMPTS_PER_BATCH: Final[int] = 101
_PROOF_ATTEMPTS_CAP: Final[int] = 2**32
_MAX_WINDOW: Final[int] = 3_600_000
_MAX_EPOCH: Final[int] = 2**64 - 1
_MAX_RECEIPT: Final[int] = 16 * 1024
_MAX_EVENT: Final[int] = 4096
_STATEMENT_BYTES: Final[int] = 304
_STATEMENT_ENCODING_VERSION: Final[int] = 2
_MAGIC: Final[bytes] = b"BL-R100-STMT-V2\x00"
_CIRCUIT: Final[bytes] = bytes.fromhex(
    "A85A1A5F4AD3E9B777E5F9043F8B43F5C0018F8A6AAB51359AEDFE1264091C0C"
    "0F973C9D4E3BF9064383F0DB9BEB2606BAD62B92677DB0588006475236BD83CF"
)
_PROFILE: Final[bytes] = bytes.fromhex(
    "609A2A9D66E3D2E3332E86DE5BE4720699C1ADE901C62E6954715ABD1CF64E19"
    "7F315A32EEB972DEADAEDAB4D4E8882E00AE9EA9EE23575CDED3498429A802DF"
)
_PROFILE_EPOCH: Final[int] = 9
_PROFILE_TOKEN: Final[str] = "BLIND-ZKBPP-CUNRUH-RANGE100-V9"
_SOURCE_AUTH_PROFILE: Final[str] = "BLIND-MLDSA87-SOURCE-AUTH-V1-R100-V9-UNQUALIFIED"
_DIRECTIVES: Final[list[str]] = ["CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"]
_BATCH_LEAF: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-LEAF/v9\x00"
_BATCH_ROOT: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-ROOT/v9\x00"
_GENESIS: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/GENESIS/v9\x00"
_EVENT: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/EVENT/v9\x00"
_HEAD: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/HEAD/v9\x00"
_MEMBER_SET: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MEMBER-SET/v9\x00"
_COMPOSITION_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v4"
_COMPOSITION_MATERIAL: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/MATERIAL/v4\x00"
_COMPOSITION_GENESIS: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/GENESIS/v4\x00"
_COMPOSITION_EVENT: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/EVENT/v4\x00"
_COMPOSITION_HEAD: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/HEAD/v4\x00"
_COMPOSITION_STATE: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/STATE/v4\x00"
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_FORBIDDEN_CODE_WORDS = (
    "provider", "patient", "member", "claim", "identity", "digest", "path", "log",
    "stdout", "stderr", "credential", "secret",
)
_FORBIDDEN_BYTES = (
    "raw_proof", "raw_signature", "public_key", "stable_fingerprint", "acceptance_bytes",
)
_ALLOWED_CODES = frozenset({
    "accepted", "rejected", "proof_or_source_not_accepted", "fresh_handoff_required",
    "validity_expired", "lease_expired", "verifier_timeout", "verifier_transport",
    "verifier_stream_not_consumed", "verifier_result_mismatch", "verifier_result_unknown_field",
    "verifier_result_shape", "verifier_result_flags", "verifier_key_epoch", "verifier_result_code",
    "proof_handoff_stream", "proof_handoff_length", "proof_handoff_oversize", "proof_handoff_empty",
    "proof_handoff_closed", "proof_handoff_bytes", "batch_binding", "batch_unknown", "queue_capacity",
    "computational_budget_exhausted", "queue_database_bounds", "queue_schema_unsupported",
    "queue_profile_mismatch", "queue_config_encoding", "queue_config_binding", "queue_integrity_failed",
    "startup_recovery", "runtime_startup", "completion_not_live", "completion_lease_fence", "completion_status",
    "completion_acceptance", "batch_required", "queue_closed", "runtime_closed", "runtime_scope",
    "runtime_already_owned", "runtime_configuration", "queue_parent", "queue_owner_required", "queue_configuration",
    "queue_integer", "queue_batch_shape", "queue_batch_order", "queue_batch_requires_100", "batch_window_mismatch",
    "source_key_epoch", "queue_profile_invalid", "queue_profile_epoch", "queue_profile_version", "queue_capacity_invalid",
    "qualification_flags_invalid", "validity_window_invalid", "validity_window_too_long", "queue_randomness", "template_shape",
    "assertion_identifier_invalid", "assertion_identifier_forbidden", "assertion_version_invalid", "state_profile_version_invalid",
    "state_profile_version_forbidden", "source_registry_root", "qualification_flag_invalid", "batch_position_invalid",
    "batch_root", "batch_statement", "batch_identity", "statement_binding", "statement_length", "statement_window",
    "session_ref", "admission_seq", "attempt_missing", "attempt_status", "attempt_chain",
    "proof_attempt_ledger", "receipt_cap", "receipt_bounds", "receipt_encoding", "receipt_keys", "receipt_flags",
    "receipt_acceptance", "receipt_batch_id", "receipt_statement", "receipt_root", "receipt_source_profile",
    "receipt_source_epoch", "receipt_result_code", "receipt_error", "flags_bounds", "flags_encoding", "flags_shape",
    "event_fields", "event_bounds", "handoff_not_consumed", "runtime_backend_unqualified", "runtime_result", "runtime_max_batches",
})

_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": ("id", "schema_version", "queue_id", "config_json", "config_digest", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "page_size", "max_page_count", "journal_mode", "synchronous", "head_root", "next_transition_seq", "next_admission_seq", "nonterminal_count", "live_lease_count", "proof_attempts_used", "proof_attempts_cap", "next_attempt_seq"),
    "queue_batches": ("batch_id", "batch_root", "session_ref", "proof_statement", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "approved_source_registry_root", "qualification_flags", "identity_digest", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "queue_members": ("batch_id", "batch_position", "operation_ref", "admission_seq"),
    "queue_leases": ("batch_id", "worker_id", "token_digest", "attempt", "claim_sequence", "leased_ms", "expires_ms"),
    "queue_attempts": ("attempt_id", "batch_id", "reservation_before", "reservation_after", "proof_attempts", "source_key_epoch", "status", "reserved_ms", "closed_ms", "result_code"),
    "queue_results": ("batch_id", "terminal_status", "receipt_id", "receipt_bytes", "proof_accepted", "source_authenticated", "proof_statement", "batch_root", "source_auth_profile", "source_key_epoch", "result_code", "qualification_flags", "completed_ms", "attempt", "error_code"),
    "queue_transitions": ("sequence", "transition_kind", "batch_id", "before_root", "after_root", "event_bytes", "event_digest"),
    "composition_meta": ("id", "schema_version", "config_json", "config_digest", "event_head", "next_event_sequence", "state_profile_identity", "state_id", "state_bytes", "state_epoch", "state_sequence", "state_continuity_root", "state_audit_head", "state_clearance_root", "state_clearance_count", "payment_root", "active_dispatch_count"),
    "composition_transactions": ("transaction_id", "operation_ref", "status", "proof_accepted", "policy_result", "effective_directive", "disposition_id", "state_profile_identity", "state_before_id", "state_after_id", "sequence_before", "sequence_after", "state_receipt_bytes", "state_receipt_digest", "error_code", "created_ms", "updated_ms"),
    "composition_events": ("sequence", "operation_ref", "event_kind", "before_state", "after_state", "payload", "event_digest", "event_root", "at_ms"),
    "composition_outbox": ("operation_ref", "effective_directive", "status", "attempt", "worker_id", "lease_token", "lease_expires_ms", "updated_ms"),
}
_TABLES = frozenset(_TABLE_COLUMNS)
_TABLE_SCHEMA_SQL: Final[dict[str, str]] = {
    "queue_metadata": "CREATE TABLE queue_metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, queue_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), admission_cap_bytes INTEGER NOT NULL, process_tree_peak_cap_bytes INTEGER NOT NULL, active_process_limit INTEGER NOT NULL, page_size INTEGER NOT NULL CHECK(page_size=4096), max_page_count INTEGER NOT NULL CHECK(max_page_count=32768), journal_mode TEXT NOT NULL CHECK(journal_mode='delete'), synchronous INTEGER NOT NULL CHECK(synchronous=2), head_root BLOB NOT NULL CHECK(length(head_root)=64), next_transition_seq INTEGER NOT NULL, next_admission_seq INTEGER NOT NULL, nonterminal_count INTEGER NOT NULL, live_lease_count INTEGER NOT NULL, proof_attempts_used INTEGER NOT NULL, proof_attempts_cap INTEGER NOT NULL CHECK(proof_attempts_cap=4294967296), next_attempt_seq INTEGER NOT NULL)",
    "queue_batches": "CREATE TABLE queue_batches (batch_id BLOB PRIMARY KEY CHECK(length(batch_id)=32), batch_root BLOB NOT NULL CHECK(length(batch_root)=64), session_ref BLOB NOT NULL CHECK(length(session_ref)=64), proof_statement BLOB NOT NULL CHECK(length(proof_statement)=304), assertion_identifier TEXT NOT NULL, assertion_version INTEGER NOT NULL, state_profile_version TEXT NOT NULL, valid_from_ms INTEGER NOT NULL, valid_until_ms INTEGER NOT NULL, approved_source_registry_root BLOB, qualification_flags BLOB NOT NULL, identity_digest BLOB NOT NULL CHECK(length(identity_digest)=64), status TEXT NOT NULL CHECK(status IN ('AWAITING_HANDOFF','QUEUED','LEASED','VERIFIED','REJECTED','HELD')), admission_seq INTEGER NOT NULL UNIQUE CHECK(admission_seq>=1), attempt INTEGER NOT NULL CHECK(attempt IN (0,1)), next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT, CHECK(approved_source_registry_root IS NULL OR length(approved_source_registry_root)=64), CHECK(valid_from_ms<valid_until_ms))",
    "queue_members": "CREATE TABLE queue_members (batch_id BLOB NOT NULL REFERENCES queue_batches(batch_id), batch_position INTEGER NOT NULL CHECK(batch_position BETWEEN 0 AND 99), operation_ref BLOB NOT NULL CHECK(length(operation_ref)=32), admission_seq INTEGER NOT NULL CHECK(admission_seq>=1), PRIMARY KEY(batch_id,batch_position), UNIQUE(operation_ref), UNIQUE(admission_seq))",
    "queue_leases": "CREATE TABLE queue_leases (batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), worker_id TEXT NOT NULL, token_digest BLOB NOT NULL CHECK(length(token_digest)=64), attempt INTEGER NOT NULL CHECK(attempt=1), claim_sequence INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL CHECK(expires_ms>leased_ms))",
    "queue_attempts": "CREATE TABLE queue_attempts (attempt_id INTEGER PRIMARY KEY, batch_id BLOB NOT NULL UNIQUE REFERENCES queue_batches(batch_id), reservation_before INTEGER NOT NULL CHECK(reservation_before>=0), reservation_after INTEGER NOT NULL CHECK(reservation_after>reservation_before), proof_attempts INTEGER NOT NULL CHECK(proof_attempts=101), source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8), status TEXT NOT NULL CHECK(status IN ('RESERVED','ACCEPTED','REJECTED','HELD')), reserved_ms INTEGER NOT NULL, closed_ms INTEGER, result_code TEXT)",
    "queue_results": "CREATE TABLE queue_results (batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), terminal_status TEXT NOT NULL CHECK(terminal_status IN ('VERIFIED','REJECTED','HELD')), receipt_id BLOB NOT NULL CHECK(length(receipt_id)=32), receipt_bytes BLOB NOT NULL, proof_accepted INTEGER NOT NULL CHECK(proof_accepted IN (0,1)), source_authenticated INTEGER NOT NULL CHECK(source_authenticated IN (0,1)), proof_statement BLOB NOT NULL CHECK(length(proof_statement)=304), batch_root BLOB NOT NULL CHECK(length(batch_root)=64), source_auth_profile TEXT NOT NULL, source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8), result_code TEXT NOT NULL, qualification_flags BLOB NOT NULL, completed_ms INTEGER NOT NULL, attempt INTEGER NOT NULL CHECK(attempt IN (0,1)), error_code TEXT)",
    "queue_transitions": "CREATE TABLE queue_transitions (sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, batch_id BLOB NOT NULL REFERENCES queue_batches(batch_id), before_root BLOB NOT NULL CHECK(length(before_root)=64), after_root BLOB NOT NULL CHECK(length(after_root)=64), event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL CHECK(length(event_digest)=64))",
    "composition_meta": "CREATE TABLE composition_meta (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL CHECK(schema_version=4), config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), event_head BLOB NOT NULL CHECK(length(event_head)=64), next_event_sequence INTEGER NOT NULL CHECK(next_event_sequence>=0), state_profile_identity BLOB, state_id BLOB, state_bytes BLOB, state_epoch INTEGER, state_sequence INTEGER, state_continuity_root BLOB, state_audit_head BLOB, state_clearance_root BLOB, state_clearance_count INTEGER, payment_root BLOB NOT NULL CHECK(length(payment_root)=64), active_dispatch_count INTEGER NOT NULL CHECK(active_dispatch_count>=0))",
    "composition_transactions": "CREATE TABLE composition_transactions (transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id)=64), operation_ref BLOB NOT NULL UNIQUE CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), status TEXT NOT NULL CHECK(status IN ('APPLIED','HELD')), proof_accepted INTEGER NOT NULL CHECK(proof_accepted IN (0,1)), policy_result TEXT NOT NULL CHECK(policy_result IN ('PASS','MISSING','AMBIGUOUS','FAIL')), effective_directive TEXT NOT NULL CHECK(effective_directive IN ('CLEAR','HOLD','HUMAN_REVIEW','BLOCK','EXCEPTION_APPROVED')), disposition_id BLOB NOT NULL CHECK(length(disposition_id)=64), state_profile_identity BLOB NOT NULL CHECK(length(state_profile_identity)=64), state_before_id BLOB NOT NULL CHECK(length(state_before_id)=64), state_after_id BLOB NOT NULL CHECK(length(state_after_id)=64), sequence_before INTEGER NOT NULL, sequence_after INTEGER NOT NULL, state_receipt_bytes BLOB, state_receipt_digest BLOB, error_code TEXT, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL)",
    "composition_events": "CREATE TABLE composition_events (sequence INTEGER PRIMARY KEY CHECK(sequence>=1), operation_ref BLOB NOT NULL CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), event_kind TEXT NOT NULL CHECK(event_kind IN ('APPLIED','HELD','DISPATCH_LEASED','ACKNOWLEDGED','DELIVERY_UNCONFIRMED','LEASE_EXPIRED')), before_state TEXT NOT NULL, after_state TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=4096), event_digest BLOB NOT NULL UNIQUE CHECK(length(event_digest)=64), event_root BLOB NOT NULL CHECK(length(event_root)=64), at_ms INTEGER NOT NULL)",
    "composition_outbox": "CREATE TABLE composition_outbox (operation_ref BLOB PRIMARY KEY CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), effective_directive TEXT NOT NULL CHECK(effective_directive IN ('CLEAR','HOLD','HUMAN_REVIEW','BLOCK','EXCEPTION_APPROVED')), status TEXT NOT NULL CHECK(status IN ('READY','LEASED','ACKNOWLEDGED','DELIVERY_UNCONFIRMED')), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 3), worker_id TEXT, lease_token BLOB, lease_expires_ms INTEGER, updated_ms INTEGER NOT NULL)",
}
_STATUSES = frozenset(("AWAITING_HANDOFF", "QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"))
_TERMINAL = frozenset(("VERIFIED", "REJECTED", "HELD"))
_TRIGGER_DEFS: Final[tuple[tuple[str, str], ...]] = (
    ("queue_batches_identity_guard", "CREATE TRIGGER queue_batches_identity_guard BEFORE UPDATE OF batch_id,batch_root,session_ref,proof_statement,assertion_identifier,assertion_version,state_profile_version,valid_from_ms,valid_until_ms,approved_source_registry_root,qualification_flags,identity_digest,admission_seq,created_ms ON queue_batches BEGIN SELECT RAISE(ABORT,'queue_batch_identity_guard'); END"),
    ("queue_batches_no_delete", "CREATE TRIGGER queue_batches_no_delete BEFORE DELETE ON queue_batches BEGIN SELECT RAISE(ABORT,'queue_batch_delete_guard'); END"),
    ("queue_members_no_update", "CREATE TRIGGER queue_members_no_update BEFORE UPDATE ON queue_members BEGIN SELECT RAISE(ABORT,'queue_member_update_guard'); END"),
    ("queue_members_no_delete", "CREATE TRIGGER queue_members_no_delete BEFORE DELETE ON queue_members BEGIN SELECT RAISE(ABORT,'queue_member_delete_guard'); END"),
    ("queue_results_no_update", "CREATE TRIGGER queue_results_no_update BEFORE UPDATE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_result_update_guard'); END"),
    ("queue_results_no_delete", "CREATE TRIGGER queue_results_no_delete BEFORE DELETE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_result_delete_guard'); END"),
    ("queue_transitions_no_update", "CREATE TRIGGER queue_transitions_no_update BEFORE UPDATE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transition_update_guard'); END"),
    ("queue_transitions_no_delete", "CREATE TRIGGER queue_transitions_no_delete BEFORE DELETE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transition_delete_guard'); END"),
    ("queue_attempts_transition_guard", "CREATE TRIGGER queue_attempts_transition_guard BEFORE UPDATE ON queue_attempts WHEN NOT (OLD.status='RESERVED' AND NEW.status IN ('ACCEPTED','REJECTED','HELD') AND OLD.attempt_id=NEW.attempt_id AND OLD.batch_id=NEW.batch_id AND OLD.reservation_before=NEW.reservation_before AND OLD.reservation_after=NEW.reservation_after AND OLD.proof_attempts=NEW.proof_attempts AND OLD.source_key_epoch=NEW.source_key_epoch AND OLD.reserved_ms=NEW.reserved_ms AND NEW.closed_ms IS NOT NULL AND (OLD.result_code IS NULL OR NEW.result_code=OLD.result_code OR NEW.result_code IS NOT NULL)) BEGIN SELECT RAISE(ABORT,'queue_attempt_transition_guard'); END"),
    ("queue_attempts_no_delete", "CREATE TRIGGER queue_attempts_no_delete BEFORE DELETE ON queue_attempts BEGIN SELECT RAISE(ABORT,'queue_attempt_delete_guard'); END"),
    ("queue_metadata_config_guard", "CREATE TRIGGER queue_metadata_config_guard BEFORE UPDATE OF schema_version,queue_id,config_json,config_digest,admission_cap_bytes,process_tree_peak_cap_bytes,active_process_limit,page_size,max_page_count,journal_mode,synchronous,proof_attempts_cap ON queue_metadata BEGIN SELECT RAISE(ABORT,'queue_metadata_config_guard'); END"),
    ("composition_transactions_no_delete", "CREATE TRIGGER composition_transactions_no_delete BEFORE DELETE ON composition_transactions BEGIN SELECT RAISE(ABORT,'composition_append_only'); END"),
    ("composition_events_no_update", "CREATE TRIGGER composition_events_no_update BEFORE UPDATE ON composition_events BEGIN SELECT RAISE(ABORT,'composition_append_only'); END"),
    ("composition_events_no_delete", "CREATE TRIGGER composition_events_no_delete BEFORE DELETE ON composition_events BEGIN SELECT RAISE(ABORT,'composition_append_only'); END"),
)


def _fail(code: str) -> None:
    error = IndependentQueueError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            _fail("binding_type")
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("json")


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _fail("integer")
    return value.to_bytes(8, "big")


def _u64le(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _fail("integer")
    return value.to_bytes(8, "little")


def _blob(value: object, size: int, code: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _fail(code)
    return value


def _db_bytes(value: object, code: str) -> bytes:
    if type(value) is not bytes:
        _fail(code)
    return value


def _epoch(value: object, code: str) -> int:
    raw = _db_bytes(value, code)
    if len(raw) != 8:
        _fail(code)
    return int.from_bytes(raw, "big")


def _token(value: object, code: str, maximum: int = 128) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _SAFE_TOKEN.fullmatch(value) is None:
        _fail(code)
    if any(word in value.lower() for word in _FORBIDDEN_CODE_WORDS):
        _fail(f"{code}_forbidden")
    return value


def _code(value: object, code: str = "code") -> str:
    if type(value) is not str or _SAFE_CODE.fullmatch(value) is None or value not in _ALLOWED_CODES or any(word in value.lower() for word in _FORBIDDEN_CODE_WORDS):
        _fail(code)
    return value


def _parse_flags(raw: bytes) -> tuple[str, ...]:
    if type(raw) is not bytes or len(raw) > 4096:
        _fail("flags_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("flags_encoding")
    if type(value) is not dict or set(value) != {"qualification_flags"} or type(value["qualification_flags"]) is not list:
        _fail("flags_shape")
    flags = tuple(value["qualification_flags"])
    if len(flags) > 32 or tuple(sorted(flags)) != flags or len(set(flags)) != len(flags):
        _fail("flags_shape")
    for flag in flags:
        _token(flag, "flag", 96)
    if raw != _json_bytes({"qualification_flags": list(flags)}):
        _fail("flags_encoding")
    return flags


def _parse_hex(value: object, size: int, code: str) -> bytes:
    if type(value) is not str or value != value.upper() or re.fullmatch(rf"[0-9A-F]{{{size * 2}}}\Z", value) is None:
        _fail(code)
    try:
        return bytes.fromhex(value)
    except ValueError:
        _fail(code)


def _parse_config(raw: bytes, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("config_encoding")
    required = {"schema_version", "handoff_protocol", "queue_id", "capacity", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "database_page_size", "database_max_page_count", "database_journal_mode", "database_synchronous", "proof_attempts_cap", "profile_version", "profile_digest", "profile_epoch", "source_auth_profile", "source_key_epoch", "qualification_flags", "directives", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required:
        _fail("config_shape")
    if value["schema_version"] != SCHEMA_VERSION or value["handoff_protocol"] != "BATCH_ISSUE_THEN_HANDOFF_V1":
        _fail("config_shape")
    if type(value["capacity"]) is not int or not 100 <= value["capacity"] <= 512:
        _fail("config_capacity")
    if value["admission_cap_bytes"] != _ADMISSION_CAP or type(value["process_tree_peak_cap_bytes"]) is not int or not 0 < value["process_tree_peak_cap_bytes"] < 5_000_000_000 or value["active_process_limit"] != 1:
        _fail("config_limits")
    if value["database_page_size"] != _DATABASE_PAGE_SIZE or value["database_max_page_count"] != _DATABASE_MAX_PAGE_COUNT or value["database_journal_mode"] != "delete" or value["database_synchronous"] != 2 or value["proof_attempts_cap"] != _PROOF_ATTEMPTS_CAP:
        _fail("config_database")
    _token(value["queue_id"], "config_queue_id", 96)
    if value["profile_version"] != _PROFILE_TOKEN or _parse_hex(value["profile_digest"], 64, "config_profile_digest") != _PROFILE:
        _fail("config_profile")
    if type(value["profile_epoch"]) is not int or value["profile_epoch"] != _PROFILE_EPOCH:
        _fail("config_profile_epoch")
    if value["source_auth_profile"] != _SOURCE_AUTH_PROFILE:
        _fail("config_source_profile")
    if type(value["source_key_epoch"]) is not int or not 1 <= value["source_key_epoch"] <= _MAX_EPOCH:
        _fail("config_source_epoch")
    flags = value["qualification_flags"]
    if type(flags) is not list or len(flags) > 32 or tuple(sorted(flags)) != tuple(flags) or len(set(flags)) != len(flags):
        _fail("config_flags")
    for flag in flags:
        _token(flag, "config_flag", 96)
    if value["directives"] != _DIRECTIVES or value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("config_nonactivation")
    if expected_config is not None and value != dict(expected_config):
        _fail("config_binding")
    return value


def _template_bytes(row: tuple[Any, ...]) -> bytes:
    if len(row) != len(_TABLE_COLUMNS["queue_batches"]):
        _fail("batch_shape")
    if type(row[4]) is not str or type(row[5]) is not int or type(row[6]) is not str or type(row[7]) is not int or type(row[8]) is not int or type(row[10]) is not bytes:
        _fail("batch_template")
    root = None if row[9] is None else _hex(_blob(_db_bytes(row[9], "registry_root"), 64, "registry_root"))
    return _json_bytes({"assertion_identifier": row[4], "assertion_version": row[5], "state_profile_version": row[6], "valid_from_ms": row[7], "valid_until_ms": row[8], "approved_source_registry_root": root, "qualification_flags": list(_parse_flags(row[10]))})


def _expected_batch_root(owner: tuple[Any, ...], members: tuple[tuple[Any, ...], ...]) -> bytes:
    if len(members) != _COUNT:
        _fail("batch_member_count")
    ordered = tuple(sorted(members, key=lambda row: int(row[1])))
    if tuple(int(row[1]) for row in ordered) != tuple(range(_COUNT)):
        _fail("batch_positions")
    leaves = tuple(_sha(_BATCH_LEAF, _u64(int(row[1])), _blob(_db_bytes(row[2], "operation_ref"), 32, "operation_ref"), _template_bytes(owner)) for row in ordered)
    return _sha(_BATCH_ROOT, _u64(_COUNT), b"".join(leaves))


def _build_statement(*, batch_root: bytes, session_ref: bytes, valid_from_ms: int, valid_until_ms: int) -> bytes:
    _blob(batch_root, 64, "batch_root")
    if batch_root == bytes(64):
        _fail("batch_root")
    _blob(session_ref, 64, "session_ref")
    if session_ref == bytes(64):
        _fail("session_ref")
    if type(valid_from_ms) is not int or type(valid_until_ms) is not int or not 0 <= valid_from_ms < valid_until_ms or valid_until_ms - valid_from_ms > _MAX_WINDOW:
        _fail("statement_window")
    statement = _MAGIC + _STATEMENT_ENCODING_VERSION.to_bytes(2, "little") + _STATEMENT_BYTES.to_bytes(2, "little") + session_ref + batch_root + _PROFILE_EPOCH.to_bytes(4, "little") + (1).to_bytes(1, "little") + bytes(3) + (1).to_bytes(4, "little") + _u64le(valid_from_ms) + _u64le(valid_until_ms) + _CIRCUIT + _PROFILE
    if len(statement) != _STATEMENT_BYTES:
        _fail("statement_length")
    return statement


def _parse_statement(statement: bytes, *, batch_root: bytes, session_ref: bytes, valid_from_ms: int, valid_until_ms: int) -> None:
    if type(statement) is not bytes or len(statement) != _STATEMENT_BYTES or statement[:16] != _MAGIC or statement[16:18] != _STATEMENT_ENCODING_VERSION.to_bytes(2, "little") or statement[18:20] != _STATEMENT_BYTES.to_bytes(2, "little"):
        _fail("statement_shape")
    if statement != _build_statement(batch_root=batch_root, session_ref=session_ref, valid_from_ms=valid_from_ms, valid_until_ms=valid_until_ms):
        _fail("statement_binding")


def _identity_digest(batch: tuple[Any, ...], members: tuple[tuple[Any, ...], ...], config: Mapping[str, Any]) -> bytes:
    refs = b"".join(_u64(int(row[1])) + _blob(_db_bytes(row[2], "operation_ref"), 32, "operation_ref") for row in sorted(members, key=lambda row: int(row[1])))
    return _sha(b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-IDENTITY/v9\x00", _blob(_db_bytes(batch[0], "batch_id"), 32, "batch_id"), _blob(_db_bytes(batch[1], "batch_root"), 64, "batch_root"), _blob(_db_bytes(batch[2], "session_ref"), 64, "session_ref"), _blob(_db_bytes(batch[3], "proof_statement"), _STATEMENT_BYTES, "proof_statement"), _template_bytes(batch), _u64(_COUNT), refs, _u64(int(batch[7])), _u64(int(batch[8])), str(config["source_auth_profile"]).encode("ascii"), _u64(int(config["source_key_epoch"])))


@dataclass(frozen=True, slots=True)
class IndependentVerifiedQueueJob:
    queue_id: str
    config_digest: bytes
    operation_ref: bytes
    status: str
    proof_accepted: bool
    attempt: int
    receipt_bytes: bytes = field(repr=False)
    receipt_id: bytes
    assertion_identifier: str
    assertion_version: int
    state_profile_version: str
    valid_from_ms: int
    valid_until_ms: int
    batch_position: int
    batch_root: bytes | None
    approved_source_registry_root: bytes | None
    verifier_profile_version: str
    outcome_code: str
    qualification_flags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IndependentBatchAcceptance:
    pre_head_root: bytes
    post_head_root: bytes
    config_digest: bytes
    operation_ids: tuple[bytes, ...]
    member_set_digest: bytes
    batch_id: bytes
    accepted_count: int
    pre_transition_count: int = 0


@dataclass(frozen=True, slots=True)
class IndependentVerifiedQueueBatch:
    batch: IndependentBatchAcceptance
    jobs: tuple[IndependentVerifiedQueueJob, ...]


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall())


def _normalize_schema_sql(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value.strip()).lower()
    return re.sub(r"\(\s+", "(", re.sub(r"\s+\)", ")", normalized))


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT:
        _fail("receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("receipt_encoding")
    required = {"schema", "batch_id", "proof_accepted", "source_authenticated", "proof_statement", "batch_root", "source_auth_profile", "source_key_epoch", "result_code", "qualification_flags", "error_code", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required or raw != _json_bytes(value) or value["schema"] != _SCHEMA:
        _fail("receipt_keys")
    if value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("receipt_nonactivation")
    if type(value["proof_accepted"]) is not bool or type(value["source_authenticated"]) is not bool:
        _fail("receipt_acceptance")
    _parse_hex(value["batch_id"], 32, "receipt_batch_id")
    _parse_hex(value["proof_statement"], _STATEMENT_BYTES, "receipt_statement")
    _parse_hex(value["batch_root"], 64, "receipt_root")
    _token(value["source_auth_profile"], "receipt_source_profile", 96)
    if type(value["source_key_epoch"]) is not int or not 1 <= value["source_key_epoch"] <= _MAX_EPOCH:
        _fail("receipt_source_epoch")
    _code(value["result_code"], "receipt_result_code")
    flags = tuple(value["qualification_flags"]) if type(value["qualification_flags"]) is list else value["qualification_flags"]
    _parse_flags(_json_bytes({"qualification_flags": list(flags)}))
    if value["error_code"] is not None:
        _code(value["error_code"], "receipt_error_code")
    return value


def _forbidden_bytes(blobs: tuple[bytes, ...]) -> None:
    for blob in blobs:
        lowered = blob.lower()
        if any(word.encode("ascii") in lowered for word in _FORBIDDEN_BYTES):
            _fail("forbidden_durable_data")


def _verify_lifecycle(events: list[dict[str, Any]], status: str, attempt: int) -> None:
    if not events or events[0]["kind"] != "BATCH_ISSUED" or events[0]["status"] != "AWAITING_HANDOFF" or events[0]["attempt"] != 0 or events[0]["error_code"] is not None or events[0].get("member_count") != _COUNT or "identity_digest" not in events[0]:
        _fail("lifecycle_issue")
    if status == "AWAITING_HANDOFF":
        if len(events) != 1:
            _fail("lifecycle_awaiting")
        return
    if status == "HELD" and len(events) == 2 and events[1]["kind"] == "BATCH_HELD" and events[1]["status"] == "HELD" and events[1]["attempt"] == 0:
        return
    if len(events) < 2 or events[1]["kind"] != "HANDOFF_SUBMITTED" or events[1]["status"] != "QUEUED" or events[1]["attempt"] != 0 or events[1]["error_code"] is not None:
        _fail("lifecycle_handoff")
    if status == "QUEUED":
        if len(events) != 2:
            _fail("lifecycle_queue")
        return
    if len(events) < 3 or events[2]["kind"] != "ATTEMPT_RESERVED" or events[2]["status"] != "LEASED" or events[2]["attempt"] != 1 or events[2]["error_code"] is not None:
        _fail("lifecycle_reservation")
    if status == "LEASED":
        if len(events) != 3 or attempt != 1:
            _fail("lifecycle_leased")
        return
    if attempt != 1 or len(events) != 4:
        _fail("lifecycle_terminal")
    terminal = events[3]
    if status in {"VERIFIED", "REJECTED"}:
        if terminal["kind"] != "BATCH_COMPLETED" or terminal["status"] != status or terminal["attempt"] != 1:
            _fail("lifecycle_completion")
    elif status == "HELD":
        if terminal["kind"] not in {"BATCH_HELD", "BATCH_COMPLETED"} or terminal["status"] != "HELD" or terminal["attempt"] != 1:
            _fail("lifecycle_held")
    else:
        _fail("lifecycle_status")


def _verify_composition(connection: sqlite3.Connection, *, config: Mapping[str, Any], queue_config_digest: bytes, batch_map: Mapping[bytes, tuple[Any, ...]], member_groups: Mapping[bytes, list[tuple[Any, ...]]]) -> dict[str, Any]:
    meta = connection.execute("SELECT * FROM composition_meta WHERE id=1").fetchone()
    if meta is None or int(meta[1]) != 4 or type(meta[2]) is not bytes or type(meta[3]) is not bytes or len(meta[3]) != 64:
        _fail("composition_metadata")
    try:
        composition_config = json.loads(bytes(meta[2]).decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("composition_config")
    if type(composition_config) is not dict or bytes(meta[3]) != _sha(_COMPOSITION_MATERIAL, bytes(meta[2])) or composition_config.get("schema_version") != 4 or composition_config.get("queue_id") != config["queue_id"] or composition_config.get("queue_config_digest") != _hex(queue_config_digest) or composition_config.get("proof_suite_id") is not None or composition_config.get("production_usable") is not False or composition_config.get("activation") is not False:
        _fail("composition_config")
    tx_rows = [tuple(row) for row in connection.execute("SELECT * FROM composition_transactions ORDER BY operation_ref").fetchall()]
    event_rows = [tuple(row) for row in connection.execute("SELECT * FROM composition_events ORDER BY sequence").fetchall()]
    outbox_rows = [tuple(row) for row in connection.execute("SELECT * FROM composition_outbox ORDER BY operation_ref").fetchall()]
    tx_map: dict[bytes, tuple[Any, ...]] = {}
    for row in tx_rows:
        ref = _blob(_db_bytes(row[1], "composition_operation_ref"), 32, "composition_operation_ref")
        if ref in tx_map or _blob(_db_bytes(row[0], "composition_transaction_id"), 64, "composition_transaction_id") == bytes(64) or str(row[2]) != "APPLIED" or int(row[3]) != 1 or str(row[4]) not in {"PASS", "MISSING", "AMBIGUOUS", "FAIL"} or str(row[5]) not in {"CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"}:
            _fail("composition_transaction")
        for index in (6, 7, 8, 9, 13):
            if row[index] is not None:
                _blob(_db_bytes(row[index], "composition_transaction_binding"), 64, "composition_transaction_binding")
        if row[12] is None or row[13] is None or bytes(row[13]) != _sha(_COMPOSITION_STATE, bytes(row[12])) or int(row[11]) != int(row[10]) + 1:
            _fail("composition_transaction")
        tx_map[ref] = row
    outbox_map: dict[bytes, tuple[Any, ...]] = {}
    for row in outbox_rows:
        ref = _blob(_db_bytes(row[0], "composition_outbox_ref"), 32, "composition_outbox_ref")
        if ref in outbox_map or str(row[1]) not in {"CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"} or str(row[2]) not in {"READY", "LEASED", "ACKNOWLEDGED", "DELIVERY_UNCONFIRMED"} or type(row[3]) is not int or not 0 <= int(row[3]) <= 3:
            _fail("composition_outbox")
        if str(row[2]) == "READY" and any(row[index] is not None for index in (4, 5, 6)):
            _fail("composition_outbox")
        outbox_map[ref] = row
    applied_events: dict[bytes, list[tuple[Any, ...]]] = {}
    expected_head = _sha(_COMPOSITION_GENESIS, bytes(meta[3]))
    for index, row in enumerate(event_rows, start=1):
        sequence, ref_raw, kind, before, after, payload_raw, event_digest, event_root, at_ms = row
        ref = _blob(_db_bytes(ref_raw, "composition_event_ref"), 32, "composition_event_ref")
        if int(sequence) != index or type(kind) is not str or kind not in {"APPLIED", "HELD", "DISPATCH_LEASED", "ACKNOWLEDGED", "DELIVERY_UNCONFIRMED", "LEASE_EXPIRED"} or type(before) is not str or type(after) is not str or type(payload_raw) is not bytes or len(payload_raw) > 4096 or int(at_ms) < 0:
            _fail("composition_event")
        try:
            payload = json.loads(bytes(payload_raw).decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("composition_event")
        if kind == "APPLIED":
            expected = {"operation_ref", "proof_accepted", "policy_result", "effective_directive", "state_receipt_digest", "sequence_before", "sequence_after"}
            if type(payload) is not dict or set(payload) != expected or payload.get("operation_ref") != _hex(ref) or payload.get("proof_accepted") is not True or payload.get("policy_result") not in {"PASS", "MISSING", "AMBIGUOUS", "FAIL"} or payload.get("effective_directive") not in {"CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"} or type(payload.get("state_receipt_digest")) is not str or re.fullmatch(r"[0-9A-F]{128}\Z", payload["state_receipt_digest"]) is None or type(payload.get("sequence_before")) is not int or type(payload.get("sequence_after")) is not int or payload["sequence_after"] != payload["sequence_before"] + 1 or before != "NONE" or after != "READY":
                _fail("composition_event")
            applied_events.setdefault(ref, []).append(row)
        event = {"schema": _COMPOSITION_SCHEMA, "sequence": int(sequence), "operation_ref": _hex(ref), "event_kind": kind, "before_state": before, "after_state": after, "payload": payload, "at_ms": int(at_ms)}
        raw = _json_bytes(event)
        digest = _sha(_COMPOSITION_EVENT, _u64(int(sequence)), raw)
        root = _sha(_COMPOSITION_HEAD, expected_head, _u64(int(sequence)), digest)
        if bytes(event_digest) != digest or bytes(event_root) != root:
            _fail("composition_event_chain")
        expected_head = root
    if any(len(events) != 1 for events in applied_events.values()) or bytes(meta[4]) != expected_head or int(meta[5]) != len(event_rows) or set(tx_map) != set(outbox_map) or set(tx_map) != set(applied_events):
        _fail("composition_head")
    verified_refs: set[bytes] = set()
    for batch_id, batch in batch_map.items():
        refs = {bytes(row[2]) for row in member_groups[batch_id]}
        if str(batch[12]) == "VERIFIED":
            if len(refs) != _COUNT or not refs.issubset(tx_map):
                _fail("composition_batch_complete")
            verified_refs.update(refs)
        elif refs & set(tx_map):
            _fail("composition_nonaccepted")
    if set(tx_map) != verified_refs:
        _fail("composition_batch_complete")
    return {"meta": tuple(meta), "transactions": tx_rows, "events": event_rows, "outbox": outbox_rows}


def _verify_connection(connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        # SQLite exposes max_page_count as a connection setting on some
        # Windows builds; re-assert it on every reconnect before checking the
        # effective value and the durable metadata cap.
        connection.execute("PRAGMA page_size=4096")
        connection.execute("PRAGMA max_page_count=32768")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        checks = {"foreign_keys": int(connection.execute("PRAGMA foreign_keys").fetchone()[0]), "page_size": int(connection.execute("PRAGMA page_size").fetchone()[0]), "max_page_count": int(connection.execute("PRAGMA max_page_count").fetchone()[0]), "journal_mode": str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(), "synchronous": int(connection.execute("PRAGMA synchronous").fetchone()[0])}
    except sqlite3.Error:
        _fail("database_pragmas")
    if checks != {"foreign_keys": 1, "page_size": _DATABASE_PAGE_SIZE, "max_page_count": _DATABASE_MAX_PAGE_COUNT, "journal_mode": "delete", "synchronous": 2}:
        _fail("database_pragmas")
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != _TABLES or any(_columns(connection, table) != _TABLE_COLUMNS[table] for table in _TABLES):
        _fail("schema")
    table_sql = {str(row[0]): str(row[1]) for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if set(table_sql) != _TABLES or any(_normalize_schema_sql(table_sql[name]) != _normalize_schema_sql(_TABLE_SCHEMA_SQL[name]) for name in _TABLES):
        _fail("schema")
    triggers = {str(row[0]): str(row[1]) for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
    if set(triggers) != {name for name, _ in _TRIGGER_DEFS}:
        _fail("schema_triggers")
    for name, expected in _TRIGGER_DEFS:
        if re.sub(r"\s+", " ", triggers[name].strip()).lower() != re.sub(r"\s+", " ", expected.strip()).lower():
            _fail("schema_triggers")
    meta = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
    if meta is None or len(meta) != len(_TABLE_COLUMNS["queue_metadata"]):
        _fail("metadata")
    if int(meta[1]) != SCHEMA_VERSION or int(meta[5]) != _ADMISSION_CAP or not 0 < int(meta[6]) < 5_000_000_000 or int(meta[7]) != 1 or int(meta[8]) != _DATABASE_PAGE_SIZE or int(meta[9]) != _DATABASE_MAX_PAGE_COUNT or str(meta[10]).lower() != "delete" or int(meta[11]) != 2 or int(meta[18]) != _PROOF_ATTEMPTS_CAP or int(meta[19]) < 0:
        _fail("metadata")
    config_raw = _db_bytes(meta[3], "config")
    config = _parse_config(config_raw, expected_config)
    config_digest = _sha(_MATERIAL, config_raw)
    # QueueConfig.digest is material(config_json); profile_digest is distinct.
    if _db_bytes(meta[4], "config_digest") != config_digest:
        _fail("config_digest")
    if _parse_hex(config["profile_digest"], 64, "profile_digest") != _PROFILE:
        _fail("config_profile_digest")
    _forbidden_bytes((config_raw,))
    batch_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_batches ORDER BY admission_seq").fetchall()]
    member_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_members ORDER BY admission_seq").fetchall()]
    lease_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_leases").fetchall()]
    attempt_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_attempts ORDER BY attempt_id").fetchall()]
    result_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_results").fetchall()]
    transition_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_transitions ORDER BY sequence").fetchall()]
    if len(lease_rows) > 1 or len(member_rows) != len(batch_rows) * _COUNT:
        _fail("batch_cardinality")
    batch_map = {_blob(_db_bytes(row[0], "batch_id"), 32, "batch_id"): row for row in batch_rows}
    if len(batch_map) != len(batch_rows) or tuple(int(row[13]) for row in batch_rows) != tuple(range(1, len(batch_rows) + 1)):
        _fail("batch_order")
    member_groups: dict[bytes, list[tuple[Any, ...]]] = {batch_id: [] for batch_id in batch_map}
    status_counts = {status: 0 for status in _STATUSES}
    for row in member_rows:
        batch_id = _blob(_db_bytes(row[0], "member_batch"), 32, "member_batch")
        if type(row[0]) is not bytes or type(row[1]) is not int or not 0 <= row[1] < _COUNT or type(row[2]) is not bytes or type(row[3]) is not int or row[3] < 1 or batch_id not in batch_map:
            _fail("member_binding")
        ref = _blob(_db_bytes(row[2], "operation_ref"), 32, "operation_ref")
        member_groups[batch_id].append(row)
    all_refs = [bytes(row[2]) for row in member_rows]
    if len(set(all_refs)) != len(all_refs) or len({int(row[3]) for row in member_rows}) != len(member_rows):
        _fail("member_binding")
    for batch_id, row in batch_map.items():
        group = tuple(member_groups[batch_id])
        if len(group) != _COUNT or tuple(sorted(int(item[1]) for item in group)) != tuple(range(_COUNT)) or len({bytes(item[2]) for item in group}) != _COUNT:
            _fail("batch_members")
        expected_admission = {(int(row[13]) - 1) * _COUNT + position + 1 for position in range(_COUNT)}
        if {int(item[3]) for item in group} != expected_admission:
            _fail("member_binding")
        root = _blob(_db_bytes(row[1], "batch_root"), 64, "batch_root")
        _blob(_db_bytes(row[2], "session_ref"), 64, "session_ref")
        if _db_bytes(row[2], "session_ref") == bytes(64):
            _fail("session_ref")
        if _expected_batch_root(row, group) != root:
            _fail("batch_root_binding")
        if type(row[12]) is not str or row[12] not in _STATUSES or type(row[14]) is not int or row[14] not in (0, 1):
            _fail("batch_status")
        _token(row[4], "batch_assertion", 96)
        if type(row[5]) is not int or not 1 <= int(row[5]) <= 2**31 or type(row[6]) is not str:
            _fail("batch_template")
        _token(row[6], "batch_profile", 96)
        if type(row[7]) is not int or type(row[8]) is not int or not 0 <= int(row[7]) < int(row[8]) or int(row[8]) - int(row[7]) > _MAX_WINDOW:
            _fail("batch_window")
        if row[9] is not None:
            _blob(_db_bytes(row[9], "registry_root"), 64, "registry_root")
        flags = _parse_flags(_db_bytes(row[10], "flags"))
        _blob(_db_bytes(row[11], "identity_digest"), 64, "identity_digest")
        if _db_bytes(row[11], "identity_digest") != _identity_digest(row, group, config):
            _fail("batch_identity")
        _parse_statement(_db_bytes(row[3], "proof_statement"), batch_root=root, session_ref=_blob(_db_bytes(row[2], "session_ref"), 64, "session_ref"), valid_from_ms=int(row[7]), valid_until_ms=int(row[8]))
        status_counts[str(row[12])] += 1
        _code(row[18], "batch_last_error") if row[18] is not None else None
        _forbidden_bytes((_db_bytes(row[10], "flags"), str(row[18]).encode("ascii") if row[18] is not None else b""))
    result_map = {_blob(_db_bytes(row[0], "result_batch_id"), 32, "result_batch_id"): row for row in result_rows}
    if len(result_map) != len(result_rows):
        _fail("result_duplicate")
    for batch_id, row in batch_map.items():
        status = str(row[12])
        result = result_map.get(batch_id)
        if (status in _TERMINAL and result is None) or (status not in _TERMINAL and result is not None):
            _fail("result_set")
        if result is not None:
            result_epoch = _epoch(result[9], "result_source_epoch")
            if type(result[1]) is not str or result[1] != status or type(result[13]) is not int or result[13] != row[14] or type(result[4]) is not int or result[4] not in (0, 1) or type(result[5]) is not int or result[5] not in (0, 1) or _db_bytes(result[6], "result_statement") != _db_bytes(row[3], "proof_statement") or _db_bytes(result[7], "result_root") != _db_bytes(row[1], "batch_root") or type(result[8]) is not str or result[8] != config["source_auth_profile"] or result_epoch != config["source_key_epoch"] or _parse_flags(_db_bytes(result[11], "result_flags")) != tuple(config["qualification_flags"]):
                _fail("result_binding")
            receipt = _parse_receipt(_db_bytes(result[3], "receipt"))
            if _parse_hex(receipt["batch_id"], 32, "receipt_batch_id") != batch_id or _parse_hex(receipt["proof_statement"], _STATEMENT_BYTES, "receipt_statement") != _db_bytes(row[3], "proof_statement") or _parse_hex(receipt["batch_root"], 64, "receipt_root") != _db_bytes(row[1], "batch_root") or receipt["source_auth_profile"] != config["source_auth_profile"] or int(receipt["source_key_epoch"]) != int(config["source_key_epoch"]):
                _fail("receipt_binding")
            if bool(result[4]) != bool(receipt["proof_accepted"]) or bool(result[5]) != bool(receipt["source_authenticated"]) or str(result[10]) != receipt["result_code"] or (None if result[14] is None else str(result[14])) != receipt["error_code"]:
                _fail("receipt_result_binding")
            _code(result[10], "result_code")
            if result[14] is not None:
                _code(result[14], "result_error_code")
            if status == "VERIFIED" and not (bool(result[4]) and bool(result[5]) and receipt["error_code"] is None):
                _fail("verified_acceptance")
            if status != "VERIFIED" and bool(result[4]) and bool(result[5]):
                _fail("terminal_acceptance")
            if status == "VERIFIED" and str(result[10]) != "accepted":
                _fail("verified_result_code")
            if status == "REJECTED" and str(result[10]) != "rejected":
                _fail("rejected_result_code")
            expected_receipt_id = _sha(_MATERIAL, b"receipt", batch_id, _u64(int(row[14])))[:32]
            if _db_bytes(result[2], "receipt_id") != expected_receipt_id:
                _fail("receipt_id")
            _forbidden_bytes((_db_bytes(result[3], "receipt"), str(result[10]).encode("ascii"), _db_bytes(result[11], "result_flags"), str(result[14]).encode("ascii") if result[14] is not None else b""))
    lease_map = {_blob(_db_bytes(row[0], "lease_batch_id"), 32, "lease_batch_id"): row for row in lease_rows}
    attempt_map = {_blob(_db_bytes(row[1], "attempt_batch_id"), 32, "attempt_batch_id"): row for row in attempt_rows}
    if len(attempt_map) != len(attempt_rows):
        _fail("attempt_duplicate")
    previous_after = 0
    for expected_id, row in enumerate(attempt_rows, start=1):
        batch_id = _blob(_db_bytes(row[1], "attempt_batch"), 32, "attempt_batch")
        before, after, proof_attempts = int(row[2]), int(row[3]), int(row[4])
        attempt_epoch = _epoch(row[5], "attempt_source_epoch")
        if int(row[0]) != expected_id or batch_id not in batch_map or before != previous_after or after != before + _PROOF_ATTEMPTS_PER_BATCH or proof_attempts != _PROOF_ATTEMPTS_PER_BATCH or not 1 <= attempt_epoch <= _MAX_EPOCH or str(row[6]) not in {"RESERVED", "ACCEPTED", "REJECTED", "HELD"} or int(row[7]) < 0 or (row[8] is not None and int(row[8]) < int(row[7])):
            _fail("attempt_chain")
        previous_after = after
        batch = batch_map[batch_id]
        if int(batch[14]) != 1 or attempt_epoch != int(config["source_key_epoch"]):
            _fail("attempt_binding")
        expected_status = {"LEASED": "RESERVED", "VERIFIED": "ACCEPTED", "REJECTED": "REJECTED", "HELD": "HELD"}.get(str(batch[12]))
        if expected_status is not None and str(row[6]) != expected_status:
            _fail("attempt_status")
        if row[9] is not None:
            _code(row[9], "attempt_result_code")
        result = result_map.get(batch_id)
        if result is not None and (result[10] is None or str(row[9]) != str(result[10])):
            _fail("attempt_result_binding")
    if int(meta[17]) != previous_after or int(meta[18]) != _PROOF_ATTEMPTS_CAP or int(meta[19]) != len(attempt_rows):
        _fail("attempt_ledger")
    for batch_id, row in batch_map.items():
        status = str(row[12])
        attempt = int(row[14])
        attempt_row = attempt_map.get(batch_id)
        if attempt == 0 and attempt_row is not None:
            _fail("attempt_unexpected")
        if attempt == 1 and attempt_row is None:
            _fail("attempt_missing")
        if status == "LEASED":
            lease = lease_map.get(batch_id)
            if lease is None or int(lease[3]) != 1 or type(lease[1]) is not str or len(_db_bytes(lease[2], "lease_digest")) != 64 or int(lease[6]) <= int(lease[5]):
                _fail("lease_binding")
            _token(lease[1], "lease_worker", 96)
        elif batch_id in lease_map:
            _fail("lease_status")
    if set(lease_map) != {batch_id for batch_id, row in batch_map.items() if str(row[12]) == "LEASED"}:
        _fail("lease_set")
    expected_nonterminal = sum(1 for row in batch_map.values() if str(row[12]) in {"AWAITING_HANDOFF", "QUEUED", "LEASED"})
    if int(meta[15]) != expected_nonterminal or int(meta[16]) != len(lease_rows):
        _fail("metadata_counts")
    expected_head = _sha(_GENESIS, str(config["queue_id"]).encode("ascii"), config_digest)
    events_by_batch: dict[bytes, list[dict[str, Any]]] = {batch_id: [] for batch_id in batch_map}
    for index, row in enumerate(transition_rows, start=1):
        batch_id = _blob(_db_bytes(row[2], "transition_batch"), 32, "transition_batch")
        if int(row[0]) != index or batch_id not in batch_map or _db_bytes(row[3], "transition_before") != expected_head or len(_db_bytes(row[5], "event")) > _MAX_EVENT:
            _fail("transition_chain")
        try:
            event = json.loads(_db_bytes(row[5], "event").decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("transition_encoding")
        if type(event) is not dict or _db_bytes(row[5], "event") != _json_bytes(event) or event.get("schema") != _SCHEMA or event.get("sequence") != index or event.get("batch_id") != _hex(batch_id) or event.get("kind") != str(row[1]) or event.get("status") not in _STATUSES or type(event.get("attempt")) is not int or not 0 <= event["attempt"] <= 1 or type(event.get("at_ms")) is not int or event["at_ms"] < 0:
            _fail("transition_binding")
        allowed = {"schema", "sequence", "kind", "batch_id", "status", "error_code", "attempt", "at_ms", "member_count", "reservation_before", "reservation_after", "receipt_id", "identity_digest"}
        if set(event) - allowed or event.get("member_count") != _COUNT:
            _fail("transition_fields")
        if event["error_code"] is not None:
            _code(event["error_code"], "event_error_code")
        if event["kind"] == "BATCH_ISSUED":
            if set(event) != {"schema", "sequence", "kind", "batch_id", "status", "error_code", "attempt", "at_ms", "member_count", "identity_digest"}:
                _fail("transition_fields")
            if event["identity_digest"] != _hex(batch_map[batch_id][11]):
                _fail("batch_identity")
        elif event["kind"] == "ATTEMPT_RESERVED":
            if set(event) != allowed - {"receipt_id", "identity_digest"} or type(event.get("reservation_before")) is not int or type(event.get("reservation_after")) is not int or event["reservation_after"] != event["reservation_before"] + _PROOF_ATTEMPTS_PER_BATCH:
                _fail("transition_reservation")
        elif set(event) != allowed - {"reservation_before", "reservation_after", "receipt_id", "identity_digest"}:
            _fail("transition_fields")
        digest = _sha(_EVENT, _u64(index), _db_bytes(row[5], "event"))
        after = _sha(_HEAD, expected_head, _u64(index), digest)
        if _db_bytes(row[6], "event_digest") != digest or _db_bytes(row[4], "transition_after") != after:
            _fail("transition_root")
        expected_head = after
        events_by_batch[batch_id].append(event)
        _forbidden_bytes((_db_bytes(row[5], "event"),))
    if _db_bytes(meta[12], "head_root") != expected_head or int(meta[13]) != len(transition_rows) or int(meta[14]) != len(batch_rows) * _COUNT:
        _fail("head_binding")
    for batch_id, row in batch_map.items():
        _verify_lifecycle(events_by_batch[batch_id], str(row[12]), int(row[14]))
    composition = _verify_composition(connection, config=config, queue_config_digest=config_digest, batch_map=batch_map, member_groups=member_groups)
    return {"schema": _SCHEMA, "config": config, "config_digest": config_digest, "meta": tuple(meta), "batches": batch_map, "members": member_groups, "results": result_map, "transitions": transition_rows, "events": events_by_batch, "composition": composition, "head_root": _db_bytes(meta[12], "head_root"), "status_counts": status_counts, "transition_count": len(transition_rows), "verified_batch_count": status_counts["VERIFIED"], "accepted_operation_count": status_counts["VERIFIED"] * _COUNT, "verified_count": status_counts["VERIFIED"], "proof_bytes_persisted": False, "path_custody": False, "proof_suite_id": None, "production_usable": False, "activation": False}


def _verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    try:
        if path.stat().st_size > _DATABASE_CAP:
            _fail("database_bounds")
        with closing(sqlite3.connect(str(path), timeout=5.0)) as connection:
            return _verify_connection(connection, expected_config=expected_config)
    except sqlite3.Error:
        _fail("database_sqlite")


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    verified = _verify_database(path, expected_config=expected_config)
    return {key: value for key, value in verified.items() if key not in {"config", "config_digest", "meta", "batches", "members", "results", "transitions", "events", "composition"}}


def _job_from_rows(config: Mapping[str, Any], config_digest: bytes, owner: tuple[Any, ...], member: tuple[Any, ...], result: tuple[Any, ...]) -> IndependentVerifiedQueueJob:
    receipt_raw = bytes(result[3])
    _parse_receipt(receipt_raw)
    return IndependentVerifiedQueueJob(str(config["queue_id"]), config_digest, bytes(member[2]), str(owner[12]), bool(result[4]), int(owner[14]), receipt_raw, bytes(result[2]), str(owner[4]), int(owner[5]), str(owner[6]), int(owner[7]), int(owner[8]), int(member[1]), None if owner[1] is None else bytes(owner[1]), None if owner[9] is None else bytes(owner[9]), str(config["profile_version"]), str(result[10]), tuple(_parse_flags(bytes(result[11]))))


def _empty_batch(config_digest: bytes, head_root: bytes, transition_count: int) -> IndependentVerifiedQueueBatch:
    return IndependentVerifiedQueueBatch(IndependentBatchAcceptance(bytes(64), head_root, config_digest, (), bytes(64), bytes(32), 0, transition_count), ())


def _promotion_batch(verified: dict[str, Any], batch_id: bytes) -> IndependentVerifiedQueueBatch:
    row = verified["batches"].get(batch_id)
    if row is None:
        _fail("batch_selector")
    if str(row[12]) != "VERIFIED":
        _fail("batch_incomplete")
    members = tuple(sorted(verified["members"][batch_id], key=lambda item: int(item[1])))
    result = verified["results"].get(batch_id)
    if len(members) != _COUNT or result is None or not bool(result[4]) or not bool(result[5]):
        _fail("batch_incomplete")
    config = verified["config"]
    jobs = tuple(_job_from_rows(config, verified["config_digest"], row, member, result) for member in members)
    refs = tuple(job.operation_ref for job in jobs)
    member_digest = _sha(_MEMBER_SET, _u64(_COUNT), b"".join(refs))
    events = verified["events"][batch_id]
    issued_sequence = next(event["sequence"] for event in events if event["kind"] == "BATCH_ISSUED")
    terminal_sequence = next(event["sequence"] for event in reversed(events) if event["kind"] in {"BATCH_COMPLETED", "BATCH_HELD"})
    before = bytes(verified["transitions"][int(issued_sequence) - 1][3])
    post = bytes(verified["transitions"][int(terminal_sequence) - 1][4])
    batch = IndependentBatchAcceptance(before, post, verified["config_digest"], refs, member_digest, batch_id, _COUNT, int(issued_sequence) - 1)
    return IndependentVerifiedQueueBatch(batch, jobs)


def read_verified_batch(path: Path, selector: bytes | None = None) -> IndependentVerifiedQueueBatch:
    verified = _verify_database(path)
    if selector is not None and (type(selector) is not bytes or len(selector) != 32):
        _fail("batch_selector")
    if selector is not None:
        return _promotion_batch(verified, selector)
    candidates = [(int(row[13]), batch_id) for batch_id, row in verified["batches"].items() if str(row[12]) == "VERIFIED" and bool(verified["results"].get(batch_id) and verified["results"][batch_id][4] and verified["results"][batch_id][5])]
    if not candidates:
        return _empty_batch(verified["config_digest"], verified["head_root"], verified["transition_count"])
    _admission, batch_id = min(candidates)
    return _promotion_batch(verified, batch_id)


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _DATABASE_CAP:
        _fail("export_bytes")
    with tempfile.TemporaryDirectory(prefix="bl-v9-export-") as directory:
        path = Path(directory) / "queue.sqlite"
        path.write_bytes(raw)
        return verify_database(path, expected_config=expected_config)


def restore_export_to_fresh_database(*, export_bytes: bytes, destination: Path, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if type(export_bytes) is not bytes or not export_bytes or len(export_bytes) > _DATABASE_CAP or not isinstance(destination, Path) or not destination.is_absolute() or not destination.parent.is_dir() or destination.exists():
        _fail("restore_path")
    destination.write_bytes(export_bytes)
    try:
        return verify_database(destination, expected_config=expected_config)
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise


__all__ = ("IndependentQueueError", "IndependentVerifiedQueueBatch", "IndependentVerifiedQueueJob", "IndependentBatchAcceptance", "read_verified_batch", "restore_export_to_fresh_database", "verify_database", "verify_export_bytes", "_parse_config")
