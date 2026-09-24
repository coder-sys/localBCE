"""Independent reconstruction of the durable Queue Profile 12 image.

This module intentionally does not import the queue writer.  It checks the
clean-break schema, exact guard identity, immutable batch/member image,
reservation and lifecycle chains, bounded zero-PHI codes, and reconstructs a
complete VERIFIED batch from the batch owner plus its ordered members.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from threading import get_ident
from types import MappingProxyType
from typing import Any, Final, Iterator, Mapping


class IndependentQueueError(RuntimeError):
    pass


SCHEMA_VERSION: Final[int] = 13
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/v13"
_ADMISSION_STATE_HANDOFF_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/ADMISSION-STATE-HANDOFF/v1"
_ADMISSION_STATE_HANDOFF_MAGIC: Final[bytes] = b"BLQST001"
_ADMISSION_STATE_HANDOFF_MAX: Final[int] = 64 * 1024
_MATERIAL: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v13\x00"
_ADMISSION_CAP: Final[int] = 4_500_000_000
_DATABASE_PAGE_SIZE: Final[int] = 4096
_DATABASE_MAX_PAGE_COUNT: Final[int] = 32768
_DATABASE_CAP: Final[int] = _DATABASE_PAGE_SIZE * _DATABASE_MAX_PAGE_COUNT
_COUNT: Final[int] = 100
_PROOF_ATTEMPTS_PER_BATCH: Final[int] = 101
_PROOF_ATTEMPTS_CAP: Final[int] = 2**32
_SOURCE_ADMISSION_RETRY_LIMIT: Final[int] = 4_096
_SOURCE_ADMISSION_A_UPPER: Final[int] = 1
_SOURCE_ADMISSION_S_UPPER: Final[int] = _SOURCE_ADMISSION_RETRY_LIMIT
_SOURCE_ADMISSION_M_UPPER: Final[int] = _COUNT
_SOURCE_ADMISSION_U_ISSUANCES: Final[int] = 1
_VERIFIER_LAUNCH_V_UPPER: Final[int] = 1
_SOURCE_REQUEST_MAGIC: Final[bytes] = b"DMSR0001"
_SOURCE_REQUEST_BYTES: Final[int] = 180
_SOURCE_REQUEST_DOMAIN: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/SOURCE-REQUEST/v1\x00"
_ISSUE_REQUEST_ID_BYTES: Final[int] = 32
_ISSUE_REQUEST_DOMAIN_V1: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/ISSUE-REQUEST-BATCH-ID/v1\x00"
_SOURCE_IDENTITY_PINS: Final[dict[str, tuple[int, bytes]]] = {
    "accepted": (275_968, bytes.fromhex("D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8")),
    "child-performance": (275_968, bytes.fromhex("E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9")),
}
_MAX_WINDOW: Final[int] = 3_600_000
_MAX_EPOCH: Final[int] = 2**64 - 1
_MAX_RECEIPT: Final[int] = 16 * 1024
_MAX_EVENT: Final[int] = 4096
_LEASE_MS: Final[int] = 60_000
_PUBLIC_COIN_BYTES: Final[int] = 96
_PROOF_CONTEXT_BYTES: Final[int] = 64
_PROFILE12_CONTEXT_PREIMAGE_BYTES: Final[int] = 405
_PROFILE12_CIRCUIT_PREIMAGE: Final[bytes] = (
    b"BL/DIRECT-MASK/CIRCUIT-ID/v1\x00" + b"SBA1-SRC-CMT-v1\x00" + (23).to_bytes(4, "little")
    + b"direct-mask-relation-v1"
    + b"".join(value.to_bytes(4, "little") for value in (256, 3, 33, 8, 248, 229, 125048, 172232, 0, 6, 512, 1))
)
if len(_PROFILE12_CIRCUIT_PREIMAGE) != 120:
    raise RuntimeError("profile12_circuit_preimage_length")
_CIRCUIT: Final[bytes] = hashlib.sha3_512(_PROFILE12_CIRCUIT_PREIMAGE).digest()
if _CIRCUIT.hex() != "01ee8be0a1b1bbb9957a9dcbfdc1f15f510226505a735d95f9b15e73de16161bf462522589824a3f0d0193d67aaf43c97736d24e4a00b9da655403cefd38f4a8":
    raise RuntimeError("profile12_circuit_fingerprint")
_PROFILE_TOKEN: Final[str] = "BLIND-DIRECT-MASK-FAEST256F-DEG3-V1"
_SOURCE_AUTH_PROFILE: Final[str] = "BLIND-MLDSA87-SOURCE-AUTH-DIRECT-MASK-V1-UNQUALIFIED"
_PROFILE12_PROFILE_PREIMAGE: Final[bytes] = (
    b"BL/DIRECT-MASK/QUEUE-PROFILE/v12\x00" + (12).to_bytes(4, "little")
    + len(_PROFILE_TOKEN.encode("ascii")).to_bytes(2, "little") + _PROFILE_TOKEN.encode("ascii")
    + len(_SOURCE_AUTH_PROFILE.encode("ascii")).to_bytes(2, "little") + _SOURCE_AUTH_PROFILE.encode("ascii")
    + _CIRCUIT + b"DMSP0001" + b"DMVI0001"
    + b"".join(value.to_bytes(4, "little") for value in (534370, 539013, 541781, 2592, 4627, 64, 96, 101))
    + (4294967296).to_bytes(8, "little")
)
if len(_PROFILE12_PROFILE_PREIMAGE) != 248:
    raise RuntimeError("profile12_profile_preimage_length")
_PROFILE: Final[bytes] = hashlib.sha3_512(_PROFILE12_PROFILE_PREIMAGE).digest()
if _PROFILE.hex() != "306885c3f4dba50a14bd7aa9e51ce90d4b29d750d813980ed801ba2aff0159e5b256385357219c1e848f55bff8c020d08c5c59f3b63bc5a3b32b388ff794023a":
    raise RuntimeError("profile12_profile_fingerprint")
_PROFILE_EPOCH: Final[int] = 12
_PROFILE12_CONTEXT_KAT: Final[bytes] = bytes.fromhex(
    "931fee1e981d0c844438d08662f6853cc62db7b6ac33a789b82032b33a764997"
    "677a505644a5e86085b871ac929c4c36667460883cf3d50b658dc50223c1417d"
)
_DIRECTIVES: Final[list[str]] = ["CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"]
_BATCH_LEAF: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-LEAF/v12\x00"
_BATCH_ROOT: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-ROOT/v12\x00"
_GENESIS: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/GENESIS/v13\x00"
_EVENT: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/EVENT/v13\x00"
_HEAD: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/HEAD/v13\x00"
_MEMBER_SET: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MEMBER-SET/v12\x00"
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
    "issue_request_id", "issue_request_template", "issue_request_conflict", "issue_request_transaction",
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
    "state_disposition", "state_control_set", "state_control_shape",
})
_HELD_DIRECT_CODES: Final[frozenset[str]] = frozenset(("batch_binding", "fresh_handoff_required", "validity_expired", "lease_expired"))
_HELD_PROCESS_ERRORS: Final[frozenset[str]] = frozenset((
    "verifier_stream_not_consumed", "verifier_result_unknown_field", "verifier_result_shape",
    "verifier_result_flags", "verifier_key_epoch", "verifier_result_code", "verifier_transport",
    "state_disposition", "state_control_set", "state_control_shape",
))
_HELD_PRELEASE_ERRORS: Final[frozenset[str]] = frozenset(("batch_binding", "fresh_handoff_required", "validity_expired"))
_HELD_STARTED_ERRORS: Final[frozenset[str]] = frozenset(("fresh_handoff_required", "validity_expired", "lease_expired")) | _HELD_PROCESS_ERRORS

_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": ("id", "schema_version", "queue_id", "config_json", "config_digest", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "page_size", "max_page_count", "journal_mode", "synchronous", "head_root", "next_transition_seq", "next_admission_seq", "nonterminal_count", "live_lease_count", "proof_attempts_used", "proof_attempts_cap", "next_attempt_seq", "source_a_used", "source_s_used", "source_m_used", "source_u_used", "verifier_v_used"),
    "queue_batches": ("batch_id", "batch_root", "session_ref", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "approved_source_registry_root", "qualification_flags", "identity_digest", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code", "public_coin"),
    "queue_members": ("batch_id", "batch_position", "operation_ref", "admission_seq"),
    "queue_leases": ("batch_id", "worker_id", "token_digest", "attempt", "claim_sequence", "leased_ms", "expires_ms"),
    "queue_attempts": ("attempt_id", "batch_id", "reservation_before", "reservation_after", "proof_attempts", "source_key_epoch", "status", "reserved_ms", "closed_ms", "result_code", "verifier_status", "verifier_v_upper"),
    "queue_source_admissions": ("batch_id", "profile_version", "profile_digest", "source_auth_profile", "source_key_epoch", "proof_context", "public_coin", "request_digest", "retry_limit", "source_configuration_digest", "source_identity_profile", "source_executable_size_bytes", "source_executable_sha256", "a_upper", "s_upper", "m_upper", "u_issuances", "source_status"),
    "queue_results": ("batch_id", "terminal_status", "receipt_id", "receipt_bytes", "proof_accepted", "source_authenticated", "batch_root", "source_auth_profile", "source_key_epoch", "result_code", "qualification_flags", "completed_ms", "attempt", "error_code"),
    "queue_transitions": ("sequence", "transition_kind", "batch_id", "before_root", "after_root", "event_bytes", "event_digest"),
    "composition_meta": ("id", "schema_version", "config_json", "config_digest", "event_head", "next_event_sequence", "state_profile_identity", "state_id", "state_bytes", "state_epoch", "state_sequence", "state_continuity_root", "state_audit_head", "state_clearance_root", "state_clearance_count", "payment_root", "active_dispatch_count"),
    "composition_transactions": ("transaction_id", "operation_ref", "status", "proof_accepted", "policy_result", "effective_directive", "disposition_id", "state_profile_identity", "state_before_id", "state_after_id", "sequence_before", "sequence_after", "state_receipt_bytes", "state_receipt_digest", "error_code", "created_ms", "updated_ms"),
    "composition_events": ("sequence", "operation_ref", "event_kind", "before_state", "after_state", "payload", "event_digest", "event_root", "at_ms"),
    "composition_outbox": ("operation_ref", "effective_directive", "status", "attempt", "worker_id", "lease_token", "lease_expires_ms", "updated_ms"),
}
_TABLES = frozenset(_TABLE_COLUMNS)
_TABLE_SCHEMA_SQL: Final[dict[str, str]] = {
    "queue_metadata": "CREATE TABLE queue_metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, queue_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), admission_cap_bytes INTEGER NOT NULL, process_tree_peak_cap_bytes INTEGER NOT NULL, active_process_limit INTEGER NOT NULL, page_size INTEGER NOT NULL CHECK(page_size=4096), max_page_count INTEGER NOT NULL CHECK(max_page_count=32768), journal_mode TEXT NOT NULL CHECK(journal_mode='delete'), synchronous INTEGER NOT NULL CHECK(synchronous=2), head_root BLOB NOT NULL CHECK(length(head_root)=64), next_transition_seq INTEGER NOT NULL, next_admission_seq INTEGER NOT NULL, nonterminal_count INTEGER NOT NULL, live_lease_count INTEGER NOT NULL, proof_attempts_used INTEGER NOT NULL, proof_attempts_cap INTEGER NOT NULL CHECK(proof_attempts_cap=4294967296), next_attempt_seq INTEGER NOT NULL, source_a_used INTEGER NOT NULL, source_s_used INTEGER NOT NULL, source_m_used INTEGER NOT NULL, source_u_used INTEGER NOT NULL, verifier_v_used INTEGER NOT NULL)",
    "queue_batches": "CREATE TABLE queue_batches (batch_id BLOB PRIMARY KEY CHECK(length(batch_id)=32), batch_root BLOB NOT NULL CHECK(length(batch_root)=64), session_ref BLOB NOT NULL CHECK(length(session_ref)=64), assertion_identifier TEXT NOT NULL, assertion_version INTEGER NOT NULL, state_profile_version TEXT NOT NULL, valid_from_ms INTEGER NOT NULL, valid_until_ms INTEGER NOT NULL, approved_source_registry_root BLOB, qualification_flags BLOB NOT NULL, identity_digest BLOB NOT NULL CHECK(length(identity_digest)=64), status TEXT NOT NULL CHECK(status IN ('AWAITING_HANDOFF','QUEUED','LEASED','VERIFIED','REJECTED','HELD')), admission_seq INTEGER NOT NULL UNIQUE CHECK(admission_seq>=1), attempt INTEGER NOT NULL CHECK(attempt IN (0,1)), next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT, public_coin BLOB NOT NULL CHECK(length(public_coin)=96), CHECK(approved_source_registry_root IS NULL OR length(approved_source_registry_root)=64), CHECK(valid_from_ms<valid_until_ms))",
    "queue_members": "CREATE TABLE queue_members (batch_id BLOB NOT NULL REFERENCES queue_batches(batch_id), batch_position INTEGER NOT NULL CHECK(batch_position BETWEEN 0 AND 99), operation_ref BLOB NOT NULL CHECK(length(operation_ref)=32), admission_seq INTEGER NOT NULL CHECK(admission_seq>=1), PRIMARY KEY(batch_id,batch_position), UNIQUE(operation_ref), UNIQUE(admission_seq))",
    "queue_leases": "CREATE TABLE queue_leases (batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), worker_id TEXT NOT NULL, token_digest BLOB NOT NULL CHECK(length(token_digest)=64), attempt INTEGER NOT NULL CHECK(attempt=1), claim_sequence INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL CHECK(expires_ms>leased_ms))",
    "queue_attempts": "CREATE TABLE queue_attempts (attempt_id INTEGER PRIMARY KEY, batch_id BLOB NOT NULL UNIQUE REFERENCES queue_batches(batch_id), reservation_before INTEGER NOT NULL CHECK(reservation_before>=0), reservation_after INTEGER NOT NULL CHECK(reservation_after>reservation_before), proof_attempts INTEGER NOT NULL CHECK(proof_attempts=101), source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8), status TEXT NOT NULL CHECK(status IN ('RESERVED','ACCEPTED','REJECTED','HELD')), reserved_ms INTEGER NOT NULL, closed_ms INTEGER, result_code TEXT, verifier_status TEXT NOT NULL CHECK(verifier_status IN ('UNRESERVED','STARTED','COMPLETED','UNKNOWN')), verifier_v_upper INTEGER NOT NULL CHECK(verifier_v_upper=1))",
    "queue_source_admissions": "CREATE TABLE queue_source_admissions (batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), profile_version TEXT NOT NULL, profile_digest BLOB NOT NULL CHECK(length(profile_digest)=64), source_auth_profile TEXT NOT NULL, source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8), proof_context BLOB NOT NULL CHECK(length(proof_context)=64), public_coin BLOB NOT NULL CHECK(length(public_coin)=96), request_digest BLOB NOT NULL CHECK(length(request_digest)=64), retry_limit INTEGER NOT NULL CHECK(retry_limit=4096), source_configuration_digest BLOB NOT NULL CHECK(length(source_configuration_digest)=64), source_identity_profile TEXT NOT NULL, source_executable_size_bytes INTEGER NOT NULL, source_executable_sha256 BLOB NOT NULL CHECK(length(source_executable_sha256)=32), a_upper INTEGER NOT NULL CHECK(a_upper=1), s_upper INTEGER NOT NULL CHECK(s_upper=4096), m_upper INTEGER NOT NULL CHECK(m_upper=100), u_issuances INTEGER NOT NULL CHECK(u_issuances=1), source_status TEXT NOT NULL CHECK(source_status IN ('AUTHORIZED','STARTED','COMPLETED','UNKNOWN')))",
    "queue_results": "CREATE TABLE queue_results (batch_id BLOB PRIMARY KEY REFERENCES queue_batches(batch_id), terminal_status TEXT NOT NULL CHECK(terminal_status IN ('VERIFIED','REJECTED','HELD')), receipt_id BLOB NOT NULL CHECK(length(receipt_id)=32), receipt_bytes BLOB NOT NULL, proof_accepted INTEGER NOT NULL CHECK(proof_accepted IN (0,1)), source_authenticated INTEGER NOT NULL CHECK(source_authenticated IN (0,1)), batch_root BLOB NOT NULL CHECK(length(batch_root)=64), source_auth_profile TEXT NOT NULL, source_key_epoch BLOB NOT NULL CHECK(length(source_key_epoch)=8), result_code TEXT NOT NULL, qualification_flags BLOB NOT NULL, completed_ms INTEGER NOT NULL, attempt INTEGER NOT NULL CHECK(attempt IN (0,1)), error_code TEXT)",
    "queue_transitions": "CREATE TABLE queue_transitions (sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, batch_id BLOB NOT NULL REFERENCES queue_batches(batch_id), before_root BLOB NOT NULL CHECK(length(before_root)=64), after_root BLOB NOT NULL CHECK(length(after_root)=64), event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL CHECK(length(event_digest)=64))",
    "composition_meta": "CREATE TABLE composition_meta (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL CHECK(schema_version=4), config_json BLOB NOT NULL, config_digest BLOB NOT NULL CHECK(length(config_digest)=64), event_head BLOB NOT NULL CHECK(length(event_head)=64), next_event_sequence INTEGER NOT NULL CHECK(next_event_sequence>=0), state_profile_identity BLOB, state_id BLOB, state_bytes BLOB, state_epoch INTEGER, state_sequence INTEGER, state_continuity_root BLOB, state_audit_head BLOB, state_clearance_root BLOB, state_clearance_count INTEGER, payment_root BLOB NOT NULL CHECK(length(payment_root)=64), active_dispatch_count INTEGER NOT NULL CHECK(active_dispatch_count>=0))",
    "composition_transactions": "CREATE TABLE composition_transactions (transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id)=64), operation_ref BLOB NOT NULL UNIQUE CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), status TEXT NOT NULL CHECK(status IN ('APPLIED','HELD')), proof_accepted INTEGER NOT NULL CHECK(proof_accepted IN (0,1)), policy_result TEXT NOT NULL CHECK(policy_result IN ('PASS','MISSING','AMBIGUOUS','FAIL')), effective_directive TEXT NOT NULL CHECK(effective_directive IN ('CLEAR','HOLD','HUMAN_REVIEW','BLOCK','EXCEPTION_APPROVED')), disposition_id BLOB NOT NULL CHECK(length(disposition_id)=64), state_profile_identity BLOB NOT NULL CHECK(length(state_profile_identity)=64), state_before_id BLOB NOT NULL CHECK(length(state_before_id)=64), state_after_id BLOB NOT NULL CHECK(length(state_after_id)=64), sequence_before INTEGER NOT NULL, sequence_after INTEGER NOT NULL, state_receipt_bytes BLOB, state_receipt_digest BLOB, error_code TEXT, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL)",
    "composition_events": "CREATE TABLE composition_events (sequence INTEGER PRIMARY KEY CHECK(sequence>=1), operation_ref BLOB NOT NULL CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), event_kind TEXT NOT NULL CHECK(event_kind IN ('APPLIED','HELD','DISPATCH_LEASED','ACKNOWLEDGED','DELIVERY_UNCONFIRMED','LEASE_EXPIRED')), before_state TEXT NOT NULL, after_state TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=4096), event_digest BLOB NOT NULL UNIQUE CHECK(length(event_digest)=64), event_root BLOB NOT NULL CHECK(length(event_root)=64), at_ms INTEGER NOT NULL)",
    "composition_outbox": "CREATE TABLE composition_outbox (operation_ref BLOB PRIMARY KEY CHECK(length(operation_ref)=32) REFERENCES queue_members(operation_ref), effective_directive TEXT NOT NULL CHECK(effective_directive IN ('CLEAR','HOLD','HUMAN_REVIEW','BLOCK','EXCEPTION_APPROVED')), status TEXT NOT NULL CHECK(status IN ('READY','LEASED','ACKNOWLEDGED','DELIVERY_UNCONFIRMED')), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 3), worker_id TEXT, lease_token BLOB, lease_expires_ms INTEGER, updated_ms INTEGER NOT NULL)",
}
_STATUSES = frozenset(("AWAITING_HANDOFF", "QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"))
_TERMINAL = frozenset(("VERIFIED", "REJECTED", "HELD"))
_SOURCE_STATUSES = frozenset(("AUTHORIZED", "STARTED", "COMPLETED", "UNKNOWN"))
_EVENT_KINDS = frozenset(("BATCH_ISSUED", "SOURCE_AUTHORIZED", "SOURCE_STARTED", "SOURCE_COMPLETED", "SOURCE_UNKNOWN", "HANDOFF_SUBMITTED", "VERIFICATION_STARTED", "VERIFIER_STARTED", "VERIFIER_COMPLETED", "VERIFIER_UNKNOWN", "BATCH_COMPLETED", "BATCH_HELD"))
_TRIGGER_DEFS: Final[tuple[tuple[str, str], ...]] = (
    ("queue_batches_identity_guard", "CREATE TRIGGER queue_batches_identity_guard BEFORE UPDATE OF batch_id,batch_root,session_ref,assertion_identifier,assertion_version,state_profile_version,valid_from_ms,valid_until_ms,approved_source_registry_root,qualification_flags,identity_digest,admission_seq,created_ms,public_coin ON queue_batches BEGIN SELECT RAISE(ABORT,'queue_batch_identity_guard'); END"),
    ("queue_batches_no_delete", "CREATE TRIGGER queue_batches_no_delete BEFORE DELETE ON queue_batches BEGIN SELECT RAISE(ABORT,'queue_batch_delete_guard'); END"),
    ("queue_members_no_update", "CREATE TRIGGER queue_members_no_update BEFORE UPDATE ON queue_members BEGIN SELECT RAISE(ABORT,'queue_member_update_guard'); END"),
    ("queue_members_no_delete", "CREATE TRIGGER queue_members_no_delete BEFORE DELETE ON queue_members BEGIN SELECT RAISE(ABORT,'queue_member_delete_guard'); END"),
    ("queue_results_no_update", "CREATE TRIGGER queue_results_no_update BEFORE UPDATE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_result_update_guard'); END"),
    ("queue_results_no_delete", "CREATE TRIGGER queue_results_no_delete BEFORE DELETE ON queue_results BEGIN SELECT RAISE(ABORT,'queue_result_delete_guard'); END"),
    ("queue_transitions_no_update", "CREATE TRIGGER queue_transitions_no_update BEFORE UPDATE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transition_update_guard'); END"),
    ("queue_transitions_no_delete", "CREATE TRIGGER queue_transitions_no_delete BEFORE DELETE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transition_delete_guard'); END"),
    ("queue_attempts_transition_guard", "CREATE TRIGGER queue_attempts_transition_guard BEFORE UPDATE ON queue_attempts WHEN NOT ((OLD.attempt_id=NEW.attempt_id AND OLD.batch_id=NEW.batch_id AND OLD.reservation_before=NEW.reservation_before AND OLD.reservation_after=NEW.reservation_after AND OLD.proof_attempts=NEW.proof_attempts AND OLD.source_key_epoch=NEW.source_key_epoch AND OLD.reserved_ms=NEW.reserved_ms AND OLD.verifier_v_upper=NEW.verifier_v_upper AND OLD.status='RESERVED' AND NEW.status='RESERVED' AND ((OLD.verifier_status='UNRESERVED' AND NEW.verifier_status='STARTED') OR (OLD.verifier_status='STARTED' AND NEW.verifier_status='UNKNOWN')) AND OLD.closed_ms IS NEW.closed_ms AND OLD.result_code IS NEW.result_code) OR (OLD.attempt_id=NEW.attempt_id AND OLD.batch_id=NEW.batch_id AND OLD.reservation_before=NEW.reservation_before AND OLD.reservation_after=NEW.reservation_after AND OLD.proof_attempts=NEW.proof_attempts AND OLD.source_key_epoch=NEW.source_key_epoch AND OLD.reserved_ms=NEW.reserved_ms AND OLD.verifier_v_upper=NEW.verifier_v_upper AND OLD.status='RESERVED' AND NEW.status IN ('ACCEPTED','REJECTED','HELD') AND NEW.closed_ms IS NOT NULL AND ((OLD.verifier_status='UNRESERVED' AND NEW.verifier_status='UNRESERVED') OR (OLD.verifier_status='STARTED' AND NEW.verifier_status IN ('COMPLETED','UNKNOWN')) OR (OLD.verifier_status='UNKNOWN' AND NEW.verifier_status='UNKNOWN')) AND (OLD.result_code IS NULL OR NEW.result_code=OLD.result_code OR NEW.result_code IS NOT NULL))) BEGIN SELECT RAISE(ABORT,'queue_attempt_transition_guard'); END"),
    ("queue_attempts_no_delete", "CREATE TRIGGER queue_attempts_no_delete BEFORE DELETE ON queue_attempts BEGIN SELECT RAISE(ABORT,'queue_attempt_delete_guard'); END"),
    ("queue_source_admissions_transition_guard", "CREATE TRIGGER queue_source_admissions_transition_guard BEFORE UPDATE ON queue_source_admissions WHEN NOT (OLD.batch_id=NEW.batch_id AND OLD.profile_version=NEW.profile_version AND OLD.profile_digest=NEW.profile_digest AND OLD.source_auth_profile=NEW.source_auth_profile AND OLD.source_key_epoch=NEW.source_key_epoch AND OLD.proof_context=NEW.proof_context AND OLD.public_coin=NEW.public_coin AND OLD.request_digest=NEW.request_digest AND OLD.retry_limit=NEW.retry_limit AND OLD.source_configuration_digest=NEW.source_configuration_digest AND OLD.source_identity_profile=NEW.source_identity_profile AND OLD.source_executable_size_bytes=NEW.source_executable_size_bytes AND OLD.source_executable_sha256=NEW.source_executable_sha256 AND OLD.a_upper=NEW.a_upper AND OLD.s_upper=NEW.s_upper AND OLD.m_upper=NEW.m_upper AND OLD.u_issuances=NEW.u_issuances AND ((OLD.source_status='AUTHORIZED' AND NEW.source_status IN ('STARTED','UNKNOWN')) OR (OLD.source_status='STARTED' AND NEW.source_status IN ('COMPLETED','UNKNOWN')))) BEGIN SELECT RAISE(ABORT,'queue_source_admission_transition_guard'); END"),
    ("queue_source_admissions_no_delete", "CREATE TRIGGER queue_source_admissions_no_delete BEFORE DELETE ON queue_source_admissions BEGIN SELECT RAISE(ABORT,'queue_source_admission_delete_guard'); END"),
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


def _strict_int(value: object, code: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    if type(value) is not int or (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        _fail(code)
    return value


def _schema_version_gate(connection: sqlite3.Connection) -> None:
    """Reject a non-Profile12 connection before any setting PRAGMA."""

    try:
        table = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='queue_metadata'"
        ).fetchone()
        if table is None or type(table[0]) is not str:
            _fail("queue_schema_unsupported")
        row = connection.execute("SELECT schema_version FROM queue_metadata WHERE id=1").fetchone()
        if row is None or type(row[0]) is not int or row[0] != SCHEMA_VERSION:
            _fail("queue_schema_unsupported")
    except IndependentQueueError:
        raise
    except sqlite3.Error:
        _fail("queue_schema_unsupported")


def _read_only_schema_gate(path: Path) -> None:
    """Reject a non-Profile12 file before any writable/PRAGMA connection work."""

    try:
        # The gate must not even acquire SQLite's shared-memory lock on a
        # retired WAL database: opening a normal read-only handle can rewrite
        # lock bytes in the -shm sidecar before the version rejection.  The
        # immutable handle reads only the database image needed for this
        # structural gate and performs no PRAGMA or writable work.
        uri = path.resolve().as_uri() + "?immutable=1"
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as connection:
            _schema_version_gate(connection)
    except IndependentQueueError:
        raise
    except (OSError, sqlite3.Error, ValueError):
        _fail("queue_schema_unsupported")


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


_SOURCE_CONFIGURATION_DOMAIN: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/SOURCE-CONFIG/v1\x00"


def _source_configuration_digest(*, identity_profile: str, executable_size_bytes: int, executable_sha256: bytes, retry_limit: int) -> bytes:
    _token(identity_profile, "source_identity_profile", 64)
    if type(executable_size_bytes) is not int or not 0 < executable_size_bytes < 5_000_000_000:
        _fail("source_executable_identity")
    _blob(executable_sha256, 32, "source_executable_identity")
    if type(retry_limit) is not int or retry_limit != _SOURCE_ADMISSION_RETRY_LIMIT:
        _fail("source_retry_policy")
    return _sha(_SOURCE_CONFIGURATION_DOMAIN, identity_profile.encode("ascii"), _u64le(executable_size_bytes), executable_sha256, _u64le(retry_limit))


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
    if any(type(flag) is not str for flag in flags):
        _fail("flags_shape")
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
    required = {"schema_version", "handoff_protocol", "queue_id", "capacity", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "database_page_size", "database_max_page_count", "database_journal_mode", "database_synchronous", "proof_attempts_cap", "public_coin_bytes", "proof_context_bytes", "profile12_context_preimage_bytes", "profile_version", "profile_digest", "profile_epoch", "source_auth_profile", "source_key_epoch", "qualification_flags", "directives", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required:
        _fail("config_shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION or type(value["handoff_protocol"]) is not str or value["handoff_protocol"] != "BATCH_ISSUE_THEN_HANDOFF_V1":
        _fail("config_shape")
    if type(value["capacity"]) is not int or not 100 <= value["capacity"] <= 512:
        _fail("config_capacity")
    if type(value["admission_cap_bytes"]) is not int or value["admission_cap_bytes"] != _ADMISSION_CAP or type(value["process_tree_peak_cap_bytes"]) is not int or not 0 < value["process_tree_peak_cap_bytes"] < 5_000_000_000 or type(value["active_process_limit"]) is not int or value["active_process_limit"] != 1:
        _fail("config_limits")
    if type(value["database_page_size"]) is not int or value["database_page_size"] != _DATABASE_PAGE_SIZE or type(value["database_max_page_count"]) is not int or value["database_max_page_count"] != _DATABASE_MAX_PAGE_COUNT or type(value["database_journal_mode"]) is not str or value["database_journal_mode"] != "delete" or type(value["database_synchronous"]) is not int or value["database_synchronous"] != 2 or type(value["proof_attempts_cap"]) is not int or value["proof_attempts_cap"] != _PROOF_ATTEMPTS_CAP or type(value["public_coin_bytes"]) is not int or value["public_coin_bytes"] != _PUBLIC_COIN_BYTES or type(value["proof_context_bytes"]) is not int or value["proof_context_bytes"] != _PROOF_CONTEXT_BYTES or type(value["profile12_context_preimage_bytes"]) is not int or value["profile12_context_preimage_bytes"] != _PROFILE12_CONTEXT_PREIMAGE_BYTES:
        _fail("config_database")
    _token(value["queue_id"], "config_queue_id", 96)
    if value["profile_version"] != _PROFILE_TOKEN or _parse_hex(value["profile_digest"], 64, "config_profile_digest") != _PROFILE:
        _fail("config_profile")
    if type(value["profile_epoch"]) is not int or value["profile_epoch"] != _PROFILE_EPOCH:
        _fail("config_profile_epoch")
    if type(value["source_auth_profile"]) is not str or value["source_auth_profile"] != _SOURCE_AUTH_PROFILE:
        _fail("config_source_profile")
    if type(value["source_key_epoch"]) is not int or not 1 <= value["source_key_epoch"] <= _MAX_EPOCH:
        _fail("config_source_epoch")
    flags = value["qualification_flags"]
    if type(flags) is not list or len(flags) > 32 or tuple(sorted(flags)) != tuple(flags) or len(set(flags)) != len(flags):
        _fail("config_flags")
    for flag in flags:
        _token(flag, "config_flag", 96)
    if type(value["directives"]) is not list or value["directives"] != _DIRECTIVES or value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("config_nonactivation")
    if expected_config is not None and value != dict(expected_config):
        _fail("config_binding")
    return value


def _template_bytes(row: tuple[Any, ...]) -> bytes:
    if len(row) != len(_TABLE_COLUMNS["queue_batches"]):
        _fail("batch_shape")
    if type(row[3]) is not str or type(row[4]) is not int or type(row[5]) is not str or type(row[6]) is not int or type(row[7]) is not int or type(row[9]) is not bytes:
        _fail("batch_template")
    root = None if row[8] is None else _hex(_blob(_db_bytes(row[8], "registry_root"), 64, "registry_root"))
    return _json_bytes({"assertion_identifier": row[3], "assertion_version": row[4], "state_profile_version": row[5], "valid_from_ms": row[6], "valid_until_ms": row[7], "approved_source_registry_root": root, "qualification_flags": list(_parse_flags(row[9]))})


def _expected_issue_template_bytes(value: Mapping[str, Any]) -> bytes:
    required = {
        "assertion_identifier", "assertion_version", "state_profile_version",
        "valid_from_ms", "valid_until_ms", "approved_source_registry_root",
        "qualification_flags",
    }
    if type(value) is not dict or set(value) != required:
        _fail("issue_request_template")
    if (
        type(value["assertion_identifier"]) is not str
        or type(value["assertion_version"]) is not int
        or type(value["state_profile_version"]) is not str
        or type(value["valid_from_ms"]) is not int
        or type(value["valid_until_ms"]) is not int
    ):
        _fail("issue_request_template")
    _token(value["assertion_identifier"], "issue_request_template", 96)
    _token(value["state_profile_version"], "issue_request_template", 96)
    if value["assertion_version"] < 1 or value["assertion_version"] > 2**31:
        _fail("issue_request_template")
    start = _strict_int(value["valid_from_ms"], "issue_request_template", minimum=0, maximum=_MAX_EPOCH)
    end = _strict_int(value["valid_until_ms"], "issue_request_template", minimum=0, maximum=_MAX_EPOCH)
    if not start < end or end - start > _MAX_WINDOW:
        _fail("issue_request_template")
    root = value["approved_source_registry_root"]
    if root is not None:
        if type(root) is not str or _hex(_parse_hex(root, 64, "issue_request_template")) != root:
            _fail("issue_request_template")
    flags = value["qualification_flags"]
    if type(flags) is not list or len(flags) > 32 or any(type(flag) is not str for flag in flags):
        _fail("issue_request_template")
    if tuple(sorted(flags)) != tuple(flags) or len(set(flags)) != len(flags):
        _fail("issue_request_template")
    for flag in flags:
        _token(flag, "issue_request_template", 96)
    try:
        return _json_bytes(value)
    except (TypeError, ValueError):
        _fail("issue_request_template")


def issue_request_batch_id_v1(*, queue_id: str, request_id: bytes) -> bytes:
    """Derive the schema-13 batch primary key for an opaque request ID v1."""

    if type(request_id) is not bytes or len(request_id) != _ISSUE_REQUEST_ID_BYTES:
        _fail("issue_request_id")
    if type(queue_id) is not str:
        _fail("issue_request_id")
    try:
        queue_id_bytes = queue_id.encode("ascii")
    except UnicodeEncodeError:
        _fail("issue_request_id")
    if not 1 <= len(queue_id_bytes) <= 128:
        _fail("issue_request_id")
    preimage = _ISSUE_REQUEST_DOMAIN_V1 + len(queue_id_bytes).to_bytes(8, "big") + queue_id_bytes + request_id
    return hashlib.sha3_256(preimage).digest()


def _expected_batch_root(owner: tuple[Any, ...], members: tuple[tuple[Any, ...], ...]) -> bytes:
    if len(members) != _COUNT:
        _fail("batch_member_count")
    ordered = tuple(sorted(members, key=lambda row: int(row[1])))
    if tuple(int(row[1]) for row in ordered) != tuple(range(_COUNT)):
        _fail("batch_positions")
    leaves = tuple(_sha(_BATCH_LEAF, _u64(int(row[1])), _blob(_db_bytes(row[2], "operation_ref"), 32, "operation_ref"), _template_bytes(owner)) for row in ordered)
    return _sha(_BATCH_ROOT, _u64(_COUNT), b"".join(leaves))


def _profile12_context(*, session_ref: bytes, batch_root: bytes, public_coin: bytes, valid_from_ms: int, valid_until_ms: int) -> bytes:
    _blob(session_ref, 64, "session_ref")
    if session_ref == bytes(64):
        _fail("session_ref")
    _blob(batch_root, 64, "batch_root")
    if batch_root == bytes(64):
        _fail("batch_root")
    _blob(public_coin, _PUBLIC_COIN_BYTES, "public_coin")
    if public_coin == bytes(_PUBLIC_COIN_BYTES):
        _fail("public_coin")
    if type(valid_from_ms) is not int or type(valid_until_ms) is not int or not 0 <= valid_from_ms < valid_until_ms or valid_until_ms - valid_from_ms > _MAX_WINDOW:
        _fail("statement_window")
    preimage = (b"BL/DIRECT-MASK/STATE-CONTEXT/v12\x00" + (12).to_bytes(4, "little") + session_ref + batch_root + public_coin + _u64le(valid_from_ms) + _u64le(valid_until_ms) + _CIRCUIT + _PROFILE)
    if len(preimage) != _PROFILE12_CONTEXT_PREIMAGE_BYTES:
        _fail("profile12_context")
    return hashlib.sha3_512(preimage).digest()


if _profile12_context(session_ref=bytes(range(64)), batch_root=bytes(range(64, 128)), public_coin=bytes(range(96)), valid_from_ms=6000, valid_until_ms=9000) != _PROFILE12_CONTEXT_KAT:
    raise RuntimeError("profile12_context_kat")


def _identity_digest(batch: tuple[Any, ...], members: tuple[tuple[Any, ...], ...], config: Mapping[str, Any]) -> bytes:
    refs = b"".join(_u64(int(row[1])) + _blob(_db_bytes(row[2], "operation_ref"), 32, "operation_ref") for row in sorted(members, key=lambda row: int(row[1])))
    root = _blob(_db_bytes(batch[1], "batch_root"), 64, "batch_root")
    session_ref = _blob(_db_bytes(batch[2], "session_ref"), 64, "session_ref")
    public_coin = _blob(_db_bytes(batch[18], "public_coin"), _PUBLIC_COIN_BYTES, "public_coin")
    if public_coin == bytes(_PUBLIC_COIN_BYTES):
        _fail("public_coin")
    context = _profile12_context(session_ref=session_ref, batch_root=root, public_coin=public_coin, valid_from_ms=int(batch[6]), valid_until_ms=int(batch[7]))
    return _sha(b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-IDENTITY/v12\x00", _blob(_db_bytes(batch[0], "batch_id"), 32, "batch_id"), root, session_ref, public_coin, context, _template_bytes(batch), _u64(_COUNT), refs, _u64(int(batch[6])), _u64(int(batch[7])), str(config["source_auth_profile"]).encode("ascii"), _u64(int(config["source_key_epoch"])))


def _expected_source_request_digest(batch: tuple[Any, ...], config: Mapping[str, Any]) -> bytes:
    public_coin = _blob(_db_bytes(batch[18], "source_public_coin"), _PUBLIC_COIN_BYTES, "source_public_coin")
    context = _profile12_context(
        session_ref=_blob(_db_bytes(batch[2], "session_ref"), 64, "source_session_ref"),
        batch_root=_blob(_db_bytes(batch[1], "batch_root"), 64, "source_batch_root"),
        public_coin=public_coin,
        valid_from_ms=_strict_int(batch[6], "source_window", minimum=0, maximum=_MAX_EPOCH),
        valid_until_ms=_strict_int(batch[7], "source_window", minimum=0, maximum=_MAX_EPOCH),
    )
    request = _SOURCE_REQUEST_MAGIC + _u64le(int(config["source_key_epoch"])) + _SOURCE_ADMISSION_RETRY_LIMIT.to_bytes(4, "little") + context + public_coin
    if len(request) != _SOURCE_REQUEST_BYTES:
        _fail("source_request_shape")
    return _sha(_SOURCE_REQUEST_DOMAIN, request)


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


@dataclass(frozen=True, slots=True)
class IndependentIssuedQueueRequest:
    request_version: int
    batch_id: bytes
    batch_root: bytes
    session_ref: bytes
    operation_refs: tuple[bytes, ...]
    public_coin: bytes
    proof_context: bytes
    identity_digest: bytes
    admission_seq: int
    status: str


@dataclass(frozen=True, slots=True)
class IndependentIssueRequestLookup:
    request_version: int
    config_digest: bytes
    meta: tuple[Any, ...] = field(repr=False)
    batch: IndependentIssuedQueueRequest | None = None


def parse_admission_state_handoff(raw: bytes) -> dict[str, Any]:
    """Decode the bounded canonical Queue-to-State v1 contract without trusting its sender."""

    if type(raw) is not bytes or not 12 <= len(raw) <= _ADMISSION_STATE_HANDOFF_MAX:
        _fail("state_handoff_bounds")
    if raw[:8] != _ADMISSION_STATE_HANDOFF_MAGIC:
        _fail("state_handoff_magic")
    payload_length = int.from_bytes(raw[8:12], "big")
    payload_raw = raw[12:]
    if payload_length != len(payload_raw):
        _fail("state_handoff_length")
    try:
        value = json.loads(payload_raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("state_handoff_encoding")
    required = {
        "schema", "queue_schema_version", "composition_schema_version", "profile_version",
        "profile_digest", "queue_id", "queue_config_digest", "composition_config_digest",
        "batch", "attempt", "events", "source", "attestation", "retry_policy",
        "terminal_result", "operations", "proof_suite_id", "production_usable", "activation",
    }
    if type(value) is not dict or set(value) != required or payload_raw != _json_bytes(value):
        _fail("state_handoff_shape")
    if (
        value["schema"] != _ADMISSION_STATE_HANDOFF_SCHEMA
        or _strict_int(value["queue_schema_version"], "state_handoff_version") != SCHEMA_VERSION
        or _strict_int(value["composition_schema_version"], "state_handoff_version") != 4
        or value["profile_version"] != _PROFILE_TOKEN
        or _parse_hex(value["profile_digest"], 64, "state_handoff_profile") != _PROFILE
        or value["proof_suite_id"] is not None
        or type(value["production_usable"]) is not bool or value["production_usable"] is not False
        or type(value["activation"]) is not bool or value["activation"] is not False
    ):
        _fail("state_handoff_version")
    _token(value["queue_id"], "state_handoff_queue_id", 96)
    queue_config_digest = _parse_hex(value["queue_config_digest"], 64, "state_handoff_queue_config")
    composition_config_digest = _parse_hex(value["composition_config_digest"], 64, "state_handoff_composition_config")

    batch = value["batch"]
    if type(batch) is not dict or set(batch) != {
        "batch_id", "batch_root", "identity_digest", "admission_seq", "template",
        "proof_context", "public_coin",
    }:
        _fail("state_handoff_batch")
    batch_id = _parse_hex(batch["batch_id"], 32, "state_handoff_batch_id")
    _parse_hex(batch["batch_root"], 64, "state_handoff_batch_root")
    _parse_hex(batch["identity_digest"], 64, "state_handoff_identity")
    admission_seq = _strict_int(batch["admission_seq"], "state_handoff_admission_seq", minimum=1)
    proof_context = _parse_hex(batch["proof_context"], _PROOF_CONTEXT_BYTES, "state_handoff_context")
    public_coin = _parse_hex(batch["public_coin"], _PUBLIC_COIN_BYTES, "state_handoff_coin")
    if public_coin == bytes(_PUBLIC_COIN_BYTES):
        _fail("state_handoff_coin")
    template = batch["template"]
    if type(template) is not dict or set(template) != {
        "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms",
        "valid_until_ms", "approved_source_registry_root", "qualification_flags",
    }:
        _fail("state_handoff_template")
    _token(template["assertion_identifier"], "state_handoff_assertion", 96)
    _strict_int(template["assertion_version"], "state_handoff_assertion_version", minimum=1, maximum=_MAX_EPOCH)
    if template["state_profile_version"] != _PROFILE_TOKEN:
        _fail("state_handoff_template")
    valid_from = _strict_int(template["valid_from_ms"], "state_handoff_window", minimum=0, maximum=_MAX_EPOCH)
    valid_until = _strict_int(template["valid_until_ms"], "state_handoff_window", minimum=0, maximum=_MAX_EPOCH)
    if valid_from >= valid_until or valid_until - valid_from > _MAX_WINDOW:
        _fail("state_handoff_window")
    registry_root = template["approved_source_registry_root"]
    if registry_root is not None:
        _parse_hex(registry_root, 64, "state_handoff_registry")
    flags = template["qualification_flags"]
    if type(flags) is not list or len(flags) > 32 or tuple(sorted(flags)) != tuple(flags) or len(set(flags)) != len(flags):
        _fail("state_handoff_flags")
    for flag in flags:
        _token(flag, "state_handoff_flag", 96)

    attempt = value["attempt"]
    if type(attempt) is not dict or set(attempt) != {
        "attempt_id", "attempt_number", "status", "proof_attempts", "reservation_before",
        "reservation_after", "source_key_epoch", "verifier_status", "verifier_v_upper",
    }:
        _fail("state_handoff_attempt")
    _strict_int(attempt["attempt_id"], "state_handoff_attempt_id", minimum=1)
    if (
        _strict_int(attempt["attempt_number"], "state_handoff_attempt_number") != 1
        or attempt["status"] != "ACCEPTED"
        or _strict_int(attempt["proof_attempts"], "state_handoff_proof_attempts") != _PROOF_ATTEMPTS_PER_BATCH
        or attempt["verifier_status"] != "COMPLETED"
        or _strict_int(attempt["verifier_v_upper"], "state_handoff_verifier_bound") != _VERIFIER_LAUNCH_V_UPPER
    ):
        _fail("state_handoff_attempt")
    reservation_before = _strict_int(attempt["reservation_before"], "state_handoff_reservation", minimum=0, maximum=_PROOF_ATTEMPTS_CAP)
    reservation_after = _strict_int(attempt["reservation_after"], "state_handoff_reservation", minimum=1, maximum=_PROOF_ATTEMPTS_CAP)
    if reservation_after - reservation_before != _PROOF_ATTEMPTS_PER_BATCH:
        _fail("state_handoff_reservation")
    source_key_epoch = _strict_int(attempt["source_key_epoch"], "state_handoff_source_epoch", minimum=1, maximum=_MAX_EPOCH)

    events = value["events"]
    expected_events = (
        ("HANDOFF_SUBMITTED", "QUEUED", 0),
        ("VERIFICATION_STARTED", "LEASED", 1),
        ("VERIFIER_STARTED", "LEASED", 1),
        ("VERIFIER_COMPLETED", "LEASED", 1),
        ("BATCH_COMPLETED", "VERIFIED", 1),
    )
    if type(events) is not list or len(events) != len(expected_events):
        _fail("state_handoff_events")
    previous_sequence = 0
    for index, (event, expected) in enumerate(zip(events, expected_events)):
        expected_keys = {"kind", "status", "attempt", "sequence", "event_digest"}
        if index == 1:
            expected_keys |= {"reservation_before", "reservation_after"}
        if type(event) is not dict or set(event) != expected_keys:
            _fail("state_handoff_events")
        kind, status, attempt_number = expected
        sequence = _strict_int(event["sequence"], "state_handoff_event_sequence", minimum=1)
        _parse_hex(event["event_digest"], 64, "state_handoff_event_digest")
        if event["kind"] != kind or event["status"] != status or _strict_int(event["attempt"], "state_handoff_event_attempt") != attempt_number or sequence <= previous_sequence:
            _fail("state_handoff_events")
        if index == 1 and (
            _strict_int(event["reservation_before"], "state_handoff_event_reservation", minimum=0) != reservation_before
            or _strict_int(event["reservation_after"], "state_handoff_event_reservation", minimum=1) != reservation_after
        ):
            _fail("state_handoff_events")
        previous_sequence = sequence

    source = value["source"]
    source_keys = {
        "status", "profile_version", "profile_digest", "source_auth_profile", "source_key_epoch",
        "request_digest", "retry_limit", "source_configuration_digest", "source_identity_profile",
        "source_executable_size_bytes", "source_executable_sha256",
    }
    if type(source) is not dict or set(source) != source_keys:
        _fail("state_handoff_source")
    if source["status"] == "ABSENT":
        if any(source[name] is not None for name in source_keys - {"status"}):
            _fail("state_handoff_source")
        source_retry_limit = None
    elif source["status"] == "COMPLETED":
        if (
            source["profile_version"] != _PROFILE_TOKEN
            or _parse_hex(source["profile_digest"], 64, "state_handoff_source_profile") != _PROFILE
            or source["source_auth_profile"] != _SOURCE_AUTH_PROFILE
            or _strict_int(source["source_key_epoch"], "state_handoff_source_epoch", minimum=1, maximum=_MAX_EPOCH) != source_key_epoch
        ):
            _fail("state_handoff_source")
        _parse_hex(source["request_digest"], 64, "state_handoff_source_request")
        source_retry_limit = _strict_int(source["retry_limit"], "state_handoff_source_retry", minimum=1)
        if source_retry_limit != _SOURCE_ADMISSION_RETRY_LIMIT:
            _fail("state_handoff_source_retry")
        _parse_hex(source["source_configuration_digest"], 64, "state_handoff_source_config")
        identity_profile = source["source_identity_profile"]
        _token(identity_profile, "state_handoff_source_identity", 96)
        exe_size = _strict_int(source["source_executable_size_bytes"], "state_handoff_source_executable", minimum=1)
        exe_sha256 = _parse_hex(source["source_executable_sha256"], 32, "state_handoff_source_executable")
        if _SOURCE_IDENTITY_PINS.get(identity_profile) != (exe_size, exe_sha256):
            _fail("state_handoff_source_executable")
    else:
        _fail("state_handoff_source")

    attestation = value["attestation"]
    if type(attestation) is not dict or set(attestation) != {
        "proof_accepted", "source_authenticated", "source_auth_profile", "source_key_epoch",
        "result_code", "qualification_flags",
    }:
        _fail("state_handoff_attestation")
    if (
        type(attestation["proof_accepted"]) is not bool or attestation["proof_accepted"] is not True
        or type(attestation["source_authenticated"]) is not bool or attestation["source_authenticated"] is not True
        or attestation["source_auth_profile"] != _SOURCE_AUTH_PROFILE
        or _strict_int(attestation["source_key_epoch"], "state_handoff_attestation_epoch", minimum=1, maximum=_MAX_EPOCH) != source_key_epoch
        or attestation["result_code"] != "accepted"
        or type(attestation["qualification_flags"]) is not list
        or tuple(attestation["qualification_flags"]) != tuple(flags)
    ):
        _fail("state_handoff_attestation")
    for flag in attestation["qualification_flags"]:
        _token(flag, "state_handoff_attestation_flag", 96)

    terminal_result = value["terminal_result"]
    if type(terminal_result) is not dict or set(terminal_result) != {
        "status", "attempt", "receipt_id", "receipt_sha256", "completed_ms", "error_code",
    }:
        _fail("state_handoff_terminal")
    if (
        terminal_result["status"] != "VERIFIED"
        or _strict_int(terminal_result["attempt"], "state_handoff_terminal_attempt") != 1
        or terminal_result["error_code"] is not None
    ):
        _fail("state_handoff_terminal")
    _parse_hex(terminal_result["receipt_id"], 32, "state_handoff_receipt_id")
    _parse_hex(terminal_result["receipt_sha256"], 32, "state_handoff_receipt_digest")
    _strict_int(terminal_result["completed_ms"], "state_handoff_completed_ms", minimum=0, maximum=_MAX_EPOCH)

    retry_policy = value["retry_policy"]
    if type(retry_policy) is not dict or set(retry_policy) != {
        "source_attempt_retry_limit", "queue_attempt_number", "state_outbox_initial_attempt",
        "state_outbox_retry_limit", "exact_postcommit_retry", "replay_policy",
    }:
        _fail("state_handoff_retry")
    if (
        retry_policy["source_attempt_retry_limit"] != source_retry_limit
        or _strict_int(retry_policy["queue_attempt_number"], "state_handoff_retry") != 1
        or _strict_int(retry_policy["state_outbox_initial_attempt"], "state_handoff_retry") != 0
        or _strict_int(retry_policy["state_outbox_retry_limit"], "state_handoff_retry") != 3
        or retry_policy["exact_postcommit_retry"] != "READ_DURABLE_RESULT"
        or retry_policy["replay_policy"] != "REJECT_STALE_OR_CONFLICTING"
    ):
        _fail("state_handoff_retry")

    operations = value["operations"]
    if type(operations) is not list or len(operations) != _COUNT:
        _fail("state_handoff_operations")
    operation_refs: list[bytes] = []
    for position, operation in enumerate(operations):
        if type(operation) is not dict or set(operation) != {
            "position", "operation_ref", "member_admission_seq", "outbox_correlation_id", "outbox_attempt",
        }:
            _fail("state_handoff_operations")
        if _strict_int(operation["position"], "state_handoff_position") != position:
            _fail("state_handoff_operations")
        ref = _parse_hex(operation["operation_ref"], 32, "state_handoff_operation_ref")
        if _parse_hex(operation["outbox_correlation_id"], 32, "state_handoff_outbox_ref") != ref:
            _fail("state_handoff_outbox_ref")
        expected_admission_seq = (admission_seq - 1) * _COUNT + position + 1
        if _strict_int(operation["member_admission_seq"], "state_handoff_member_admission_seq", minimum=1) != expected_admission_seq or _strict_int(operation["outbox_attempt"], "state_handoff_outbox_attempt") != 0:
            _fail("state_handoff_operations")
        operation_refs.append(ref)
    if len(set(operation_refs)) != _COUNT:
        _fail("state_handoff_replay")
    return value


def verify_admission_state_handoff(
    connection: sqlite3.Connection,
    raw: bytes,
    *,
    expected_config: Mapping[str, Any],
) -> tuple[IndependentVerifiedQueueJob, ...]:
    """Bind a decoded handoff to the same live Queue transaction and reject replay."""

    if not connection.in_transaction:
        _fail("state_handoff_transaction")
    value = parse_admission_state_handoff(raw)
    try:
        _schema_version_gate(connection)
    except IndependentQueueError:
        raise
    meta = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
    if meta is None or len(meta) != len(_TABLE_COLUMNS["queue_metadata"]):
        _fail("state_handoff_metadata")
    config_raw = _db_bytes(meta[3], "state_handoff_config")
    config = _parse_config(config_raw, expected_config)
    queue_config_digest = _sha(_MATERIAL, config_raw)
    if (
        type(meta[4]) is not bytes or bytes(meta[4]) != queue_config_digest
        or _strict_int(meta[1], "state_handoff_metadata") != SCHEMA_VERSION
        or value["queue_id"] != config["queue_id"]
        or _parse_hex(value["queue_config_digest"], 64, "state_handoff_config_digest") != queue_config_digest
        or value["profile_version"] != config["profile_version"]
        or _parse_hex(value["profile_digest"], 64, "state_handoff_profile") != _parse_hex(config["profile_digest"], 64, "state_handoff_profile")
    ):
        _fail("state_handoff_config_binding")

    composition_meta = connection.execute("SELECT * FROM composition_meta WHERE id=1").fetchone()
    if composition_meta is None or len(composition_meta) != len(_TABLE_COLUMNS["composition_meta"]) or _strict_int(composition_meta[1], "state_handoff_composition_schema") != 4:
        _fail("state_handoff_composition")
    composition_config_raw = _db_bytes(composition_meta[2], "state_handoff_composition_config")
    try:
        composition_config = json.loads(composition_config_raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("state_handoff_composition_config")
    composition_config_digest = _sha(_COMPOSITION_MATERIAL, composition_config_raw)
    if (
        type(composition_config) is not dict or composition_config_raw != _json_bytes(composition_config)
        or type(composition_meta[3]) is not bytes or bytes(composition_meta[3]) != composition_config_digest
        or _parse_hex(value["composition_config_digest"], 64, "state_handoff_composition_config") != composition_config_digest
        or composition_config.get("schema_version") != 4
        or composition_config.get("queue_id") != config["queue_id"]
        or composition_config.get("queue_config_digest") != _hex(queue_config_digest)
        or composition_config.get("max_attempts") != 3
        or composition_config.get("proof_suite_id") is not None
        or composition_config.get("production_usable") is not False
        or composition_config.get("activation") is not False
    ):
        _fail("state_handoff_composition_config")

    batch_value = value["batch"]
    batch_id = _parse_hex(batch_value["batch_id"], 32, "state_handoff_batch_id")
    batch_rows = connection.execute("SELECT * FROM queue_batches WHERE batch_id=?", (batch_id,)).fetchall()
    if len(batch_rows) != 1:
        _fail("state_handoff_batch")
    batch = tuple(batch_rows[0])
    template = batch_value["template"]
    flags = tuple(template["qualification_flags"])
    root = _parse_hex(batch_value["batch_root"], 64, "state_handoff_batch_root")
    identity = _parse_hex(batch_value["identity_digest"], 64, "state_handoff_identity")
    batch_public_coin = _blob(_db_bytes(batch[18], "state_handoff_coin"), _PUBLIC_COIN_BYTES, "state_handoff_coin")
    context = _profile12_context(
        session_ref=_blob(_db_bytes(batch[2], "state_handoff_session"), 64, "state_handoff_session"),
        batch_root=_blob(_db_bytes(batch[1], "state_handoff_batch_root"), 64, "state_handoff_batch_root"),
        public_coin=batch_public_coin,
        valid_from_ms=_strict_int(batch[6], "state_handoff_window", minimum=0, maximum=_MAX_EPOCH),
        valid_until_ms=_strict_int(batch[7], "state_handoff_window", minimum=0, maximum=_MAX_EPOCH),
    )
    if (
        str(batch[11]) != "VERIFIED" or _strict_int(batch[12], "state_handoff_admission_seq", minimum=1) != _strict_int(batch_value["admission_seq"], "state_handoff_admission_seq", minimum=1)
        or _strict_int(batch[13], "state_handoff_batch_attempt") != 1
        or (batch[8] is not None and type(batch[8]) is not bytes)
        or _db_bytes(batch[1], "state_handoff_batch_root") != root
        or _db_bytes(batch[10], "state_handoff_identity") != identity
        or batch[3] != template["assertion_identifier"] or batch[4] != template["assertion_version"]
        or batch[5] != template["state_profile_version"] or batch[6] != template["valid_from_ms"]
        or batch[7] != template["valid_until_ms"]
        or (None if batch[8] is None else _hex(_blob(_db_bytes(batch[8], "state_handoff_registry"), 64, "state_handoff_registry"))) != template["approved_source_registry_root"]
        or _parse_flags(_db_bytes(batch[9], "state_handoff_flags")) != tuple(template["qualification_flags"])
        or batch_public_coin != _parse_hex(batch_value["public_coin"], _PUBLIC_COIN_BYTES, "state_handoff_coin")
        or context != _parse_hex(batch_value["proof_context"], _PROOF_CONTEXT_BYTES, "state_handoff_context")
    ):
        _fail("state_handoff_batch_binding")

    members = [tuple(row) for row in connection.execute("SELECT * FROM queue_members WHERE batch_id=? ORDER BY batch_position", (batch_id,)).fetchall()]
    if len(members) != _COUNT or _expected_batch_root(batch, tuple(members)) != root or _identity_digest(batch, tuple(members), config) != identity:
        _fail("state_handoff_identity")
    operations = value["operations"]
    if any(
        type(member[0]) is not bytes or bytes(member[0]) != batch_id
        or _strict_int(member[1], "state_handoff_member_position") != position
        or _db_bytes(member[2], "state_handoff_member_ref") != _parse_hex(operation["operation_ref"], 32, "state_handoff_operation_ref")
        or _strict_int(member[3], "state_handoff_member_admission_seq", minimum=1) != _strict_int(operation["member_admission_seq"], "state_handoff_member_admission_seq", minimum=1)
        for position, (member, operation) in enumerate(zip(members, operations))
    ):
        _fail("state_handoff_identity")

    attempt_value = value["attempt"]
    source_key_epoch = _strict_int(attempt_value["source_key_epoch"], "state_handoff_source_epoch", minimum=1, maximum=_MAX_EPOCH)
    attempt_rows = connection.execute("SELECT * FROM queue_attempts WHERE batch_id=?", (batch_id,)).fetchall()
    if len(attempt_rows) != 1:
        _fail("state_handoff_attempt")
    attempt_row = tuple(attempt_rows[0])
    if (
        _strict_int(attempt_row[0], "state_handoff_attempt_id", minimum=1) != attempt_value["attempt_id"]
        or _db_bytes(attempt_row[1], "state_handoff_attempt_batch") != batch_id
        or _strict_int(attempt_row[2], "state_handoff_reservation", minimum=0) != attempt_value["reservation_before"]
        or _strict_int(attempt_row[3], "state_handoff_reservation", minimum=1) != attempt_value["reservation_after"]
        or _strict_int(attempt_row[4], "state_handoff_proof_attempts") != _PROOF_ATTEMPTS_PER_BATCH
        or _db_bytes(attempt_row[5], "state_handoff_source_epoch") != _u64(source_key_epoch)
        or str(attempt_row[6]) != "ACCEPTED" or attempt_row[8] is None
        or str(attempt_row[9]) != "accepted" or str(attempt_row[10]) != "COMPLETED"
        or _strict_int(attempt_row[11], "state_handoff_verifier_bound") != _VERIFIER_LAUNCH_V_UPPER
    ):
        _fail("state_handoff_attempt_binding")

    source_rows = connection.execute("SELECT * FROM queue_source_admissions WHERE batch_id=?", (batch_id,)).fetchall()
    source_value = value["source"]
    if not source_rows:
        if source_value["status"] != "ABSENT":
            _fail("state_handoff_source_binding")
    elif len(source_rows) == 1:
        source_row = tuple(source_rows[0])
        if (
            source_value["status"] != "COMPLETED" or str(source_row[17]) != "COMPLETED"
            or source_row[1] != source_value["profile_version"]
            or _db_bytes(source_row[2], "state_handoff_source_profile") != _parse_hex(source_value["profile_digest"], 64, "state_handoff_source_profile")
            or source_row[3] != source_value["source_auth_profile"]
            or _db_bytes(source_row[4], "state_handoff_source_epoch") != _u64(source_key_epoch)
            or _db_bytes(source_row[5], "state_handoff_source_context") != context
            or _db_bytes(source_row[6], "state_handoff_source_coin") != batch_public_coin
            or _db_bytes(source_row[7], "state_handoff_source_request") != _parse_hex(source_value["request_digest"], 64, "state_handoff_source_request")
            or _strict_int(source_row[8], "state_handoff_source_retry") != source_value["retry_limit"]
            or _db_bytes(source_row[9], "state_handoff_source_config") != _parse_hex(source_value["source_configuration_digest"], 64, "state_handoff_source_config")
            or source_row[10] != source_value["source_identity_profile"]
            or _strict_int(source_row[11], "state_handoff_source_executable") != source_value["source_executable_size_bytes"]
            or _db_bytes(source_row[12], "state_handoff_source_executable") != _parse_hex(source_value["source_executable_sha256"], 32, "state_handoff_source_executable")
        ):
            _fail("state_handoff_source_binding")
        if _expected_source_request_digest(batch, config) != _db_bytes(source_row[7], "state_handoff_source_request"):
            _fail("state_handoff_source_request")
        if _source_configuration_digest(
            identity_profile=str(source_row[10]),
            executable_size_bytes=_strict_int(source_row[11], "state_handoff_source_executable", minimum=1),
            executable_sha256=_blob(_db_bytes(source_row[12], "state_handoff_source_executable"), 32, "state_handoff_source_executable"),
            retry_limit=_strict_int(source_row[8], "state_handoff_source_retry", minimum=1),
        ) != _db_bytes(source_row[9], "state_handoff_source_config"):
            _fail("state_handoff_source_config")
    else:
        _fail("state_handoff_source_binding")

    result_rows = connection.execute("SELECT * FROM queue_results WHERE batch_id=?", (batch_id,)).fetchall()
    if len(result_rows) != 1:
        _fail("state_handoff_result")
    result = tuple(result_rows[0])
    receipt_raw = _db_bytes(result[3], "state_handoff_receipt")
    receipt = _parse_receipt(receipt_raw)
    if (
        str(result[1]) != "VERIFIED" or _db_bytes(result[0], "state_handoff_result_batch") != batch_id
        or _db_bytes(result[2], "state_handoff_receipt_id") != _parse_hex(value["terminal_result"]["receipt_id"], 32, "state_handoff_receipt_id")
        or hashlib.sha256(receipt_raw).hexdigest().upper() != value["terminal_result"]["receipt_sha256"]
        or type(result[4]) is not int or result[4] != 1 or type(result[5]) is not int or result[5] != 1
        or _db_bytes(result[6], "state_handoff_result_root") != root or result[7] != _SOURCE_AUTH_PROFILE
        or _db_bytes(result[8], "state_handoff_result_epoch") != _u64(source_key_epoch)
        or result[9] != "accepted" or _parse_flags(_db_bytes(result[10], "state_handoff_result_flags")) != tuple(flags)
        or _strict_int(result[11], "state_handoff_completed_ms", minimum=0) != value["terminal_result"]["completed_ms"]
        or _strict_int(result[12], "state_handoff_result_attempt") != 1 or result[13] is not None
        or receipt["batch_id"] != _hex(batch_id) or receipt["batch_root"] != _hex(root)
        or receipt["proof_accepted"] is not True or receipt["source_authenticated"] is not True
        or receipt["source_auth_profile"] != _SOURCE_AUTH_PROFILE or receipt["source_key_epoch"] != source_key_epoch
        or receipt["result_code"] != "accepted" or tuple(receipt["qualification_flags"]) != tuple(flags)
    ):
        _fail("state_handoff_result_binding")

    event_specs = value["events"]
    for descriptor in event_specs:
        rows = connection.execute(
            "SELECT sequence,before_root,after_root,event_bytes,event_digest FROM queue_transitions WHERE batch_id=? AND transition_kind=?",
            (batch_id, descriptor["kind"]),
        ).fetchall()
        if len(rows) != 1:
            _fail("state_handoff_events")
        sequence, before_root_raw, after_root_raw, event_raw, digest_raw = tuple(rows[0])
        sequence = _strict_int(sequence, "state_handoff_event_sequence", minimum=1)
        before_root = _blob(_db_bytes(before_root_raw, "state_handoff_event_root"), 64, "state_handoff_event_root")
        after_root = _blob(_db_bytes(after_root_raw, "state_handoff_event_root"), 64, "state_handoff_event_root")
        event_bytes = _db_bytes(event_raw, "state_handoff_event")
        digest = _blob(_db_bytes(digest_raw, "state_handoff_event_digest"), 64, "state_handoff_event_digest")
        try:
            event = json.loads(event_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("state_handoff_event_encoding")
        expected_event = {
            "schema": _SCHEMA,
            "sequence": sequence,
            "kind": descriptor["kind"],
            "batch_id": _hex(batch_id),
            "status": descriptor["status"],
            "error_code": None,
            "attempt": descriptor["attempt"],
        }
        expected_event_fields = {"schema", "sequence", "kind", "batch_id", "status", "error_code", "attempt", "at_ms", "member_count"}
        if descriptor["kind"] == "VERIFICATION_STARTED":
            expected_event.update({"reservation_before": attempt_value["reservation_before"], "reservation_after": attempt_value["reservation_after"]})
            expected_event_fields |= {"reservation_before", "reservation_after"}
        if (
            type(event) is not dict or set(event) != expected_event_fields
            or any(event.get(name) != expected for name, expected in expected_event.items())
            or _strict_int(event.get("at_ms"), "state_handoff_event_time", minimum=0) < 0
            or _strict_int(event.get("member_count"), "state_handoff_event_members") != _COUNT
            or event_bytes != _json_bytes(event)
            or sequence != descriptor["sequence"]
            or digest != _parse_hex(descriptor["event_digest"], 64, "state_handoff_event_digest")
            or digest != _sha(_EVENT, _u64(sequence), event_bytes)
            or after_root != _sha(_HEAD, before_root, _u64(sequence), digest)
        ):
            _fail("state_handoff_event_binding")
        if descriptor["kind"] == "BATCH_COMPLETED" and event["at_ms"] != value["terminal_result"]["completed_ms"]:
            _fail("state_handoff_event_binding")
        previous = connection.execute("SELECT after_root FROM queue_transitions WHERE sequence=?", (sequence - 1,)).fetchone()
        if sequence == 1:
            expected_before = _sha(_GENESIS, queue_config_digest)
        elif previous is None:
            _fail("state_handoff_event_chain")
        else:
            expected_before = _blob(_db_bytes(previous[0], "state_handoff_event_root"), 64, "state_handoff_event_root")
        if before_root != expected_before:
            _fail("state_handoff_event_chain")
    if event_specs[-1]["sequence"] > _strict_int(meta[13], "state_handoff_next_transition", minimum=1):
        _fail("state_handoff_event_sequence")

    operation_refs = tuple(_parse_hex(operation["operation_ref"], 32, "state_handoff_operation_ref") for operation in operations)
    placeholders = ",".join("?" for _ in operation_refs)
    for table in ("composition_transactions", "composition_events", "composition_outbox"):
        rows = connection.execute(f"SELECT operation_ref FROM {table} WHERE operation_ref IN ({placeholders})", operation_refs).fetchall()
        if rows:
            _fail("state_handoff_replay")

    return tuple(
        IndependentVerifiedQueueJob(
            config["queue_id"], queue_config_digest, ref, "VERIFIED", True, 1, b"", bytes(32),
            str(batch[3]), int(batch[4]), str(batch[5]), int(batch[6]), int(batch[7]), position,
            root, None if batch[8] is None else _blob(_db_bytes(batch[8], "state_handoff_registry"), 64, "state_handoff_registry"),
            config["profile_version"], "accepted", tuple(flags),
        )
        for position, ref in enumerate(operation_refs)
    )


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
    required = {"schema", "batch_id", "proof_accepted", "source_authenticated", "batch_root", "source_auth_profile", "source_key_epoch", "result_code", "qualification_flags", "error_code", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required or raw != _json_bytes(value) or value["schema"] != _SCHEMA:
        _fail("receipt_keys")
    if value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("receipt_nonactivation")
    if type(value["proof_accepted"]) is not bool or type(value["source_authenticated"]) is not bool:
        _fail("receipt_acceptance")
    _parse_hex(value["batch_id"], 32, "receipt_batch_id")
    _parse_hex(value["batch_root"], 64, "receipt_root")
    _token(value["source_auth_profile"], "receipt_source_profile", 96)
    if type(value["source_key_epoch"]) is not int or not 1 <= value["source_key_epoch"] <= _MAX_EPOCH:
        _fail("receipt_source_epoch")
    _code(value["result_code"], "receipt_result_code")
    if type(value["qualification_flags"]) is not list:
        _fail("receipt_flags")
    flags = tuple(value["qualification_flags"])
    if _parse_flags(_json_bytes({"qualification_flags": list(flags)})) != flags:
        _fail("receipt_flags")
    if value["error_code"] is not None:
        _code(value["error_code"], "receipt_error_code")
    return value


def _forbidden_bytes(blobs: tuple[bytes, ...]) -> None:
    for blob in blobs:
        lowered = blob.lower()
        if any(word.encode("ascii") in lowered for word in _FORBIDDEN_BYTES):
            _fail("forbidden_durable_data")


def _verify_lifecycle(events: list[dict[str, Any]], status: str, attempt: int, *, reservation_before: int, reservation_after: int) -> None:
    if type(attempt) is not int or status not in _STATUSES:
        _fail("lifecycle_status")
    if not events:
        _fail("lifecycle_issue")
    issued = events[0]
    if (
        issued["kind"] != "BATCH_ISSUED"
        or issued["status"] != "AWAITING_HANDOFF"
        or issued["attempt"] != 0
        or issued["error_code"] is not None
        or issued.get("member_count") != _COUNT
        or "identity_digest" not in issued
        or type(issued.get("reservation_before")) is not int
        or type(issued.get("reservation_after")) is not int
        or issued["reservation_before"] != reservation_before
        or issued["reservation_after"] != reservation_after
        or issued["reservation_after"] != issued["reservation_before"] + _PROOF_ATTEMPTS_PER_BATCH
    ):
        _fail("lifecycle_issue")

    def check_event(event: dict[str, Any], kind: str, expected_status: str, expected_attempt: int) -> None:
        if event["kind"] != kind or event["status"] != expected_status or event["attempt"] != expected_attempt or event["error_code"] is not None or event.get("member_count") != _COUNT:
            _fail("lifecycle_event")

    def check_terminal(event: dict[str, Any], kind: str, expected_status: str, expected_attempt: int) -> None:
        if event["kind"] != kind or event["status"] != expected_status or event["attempt"] != expected_attempt or event.get("member_count") != _COUNT:
            _fail("lifecycle_terminal")

    position = 1
    source_state: str | None = None
    if position < len(events) and events[position]["kind"].startswith("SOURCE_"):
        check_event(events[position], "SOURCE_AUTHORIZED", "AWAITING_HANDOFF", 0)
        source_state = "AUTHORIZED"
        position += 1
        if position < len(events) and events[position]["kind"] == "SOURCE_STARTED":
            check_event(events[position], "SOURCE_STARTED", "AWAITING_HANDOFF", 0)
            source_state = "STARTED"
            position += 1
        if position < len(events) and events[position]["kind"] in {"SOURCE_COMPLETED", "SOURCE_UNKNOWN"}:
            expected = events[position]["kind"]
            check_event(events[position], expected, "AWAITING_HANDOFF", 0)
            source_state = "COMPLETED" if expected == "SOURCE_COMPLETED" else "UNKNOWN"
            position += 1
        if position < len(events) and events[position]["kind"].startswith("SOURCE_"):
            _fail("lifecycle_source")

    if source_state == "UNKNOWN":
        if status != "HELD" or attempt != 0 or position >= len(events):
            _fail("lifecycle_source")
        check_terminal(events[position], "BATCH_HELD", "HELD", 0)
        if position + 1 != len(events):
            _fail("lifecycle_terminal")
        return
    if source_state in {"AUTHORIZED", "STARTED"}:
        if status != "AWAITING_HANDOFF" or attempt != 0 or position != len(events):
            _fail("lifecycle_source")
        return
    if status == "AWAITING_HANDOFF":
        if attempt != 0 or position != len(events):
            _fail("lifecycle_awaiting")
        return
    if position < len(events) and events[position]["kind"] == "BATCH_HELD":
        if status != "HELD" or attempt != 0:
            _fail("lifecycle_prelease")
        check_terminal(events[position], "BATCH_HELD", "HELD", 0)
        if position + 1 != len(events):
            _fail("lifecycle_terminal")
        return
    if position >= len(events) or events[position]["kind"] != "HANDOFF_SUBMITTED":
        _fail("lifecycle_handoff")
    check_event(events[position], "HANDOFF_SUBMITTED", "QUEUED", 0)
    position += 1
    if position < len(events) and events[position]["kind"] == "BATCH_HELD":
        if status != "HELD" or attempt != 0:
            _fail("lifecycle_prelease")
        check_terminal(events[position], "BATCH_HELD", "HELD", 0)
        if position + 1 != len(events):
            _fail("lifecycle_terminal")
        return
    if status == "QUEUED":
        if attempt != 0 or position != len(events):
            _fail("lifecycle_queue")
        return
    if position >= len(events) or events[position]["kind"] != "VERIFICATION_STARTED":
        _fail("lifecycle_verification_started")
    started = events[position]
    if (
        started["status"] != "LEASED"
        or started["attempt"] != 1
        or started["error_code"] is not None
        or type(started.get("reservation_before")) is not int
        or type(started.get("reservation_after")) is not int
        or started["reservation_before"] != reservation_before
        or started["reservation_after"] != reservation_after
        or started["reservation_after"] != started["reservation_before"] + _PROOF_ATTEMPTS_PER_BATCH
        or started.get("member_count") != _COUNT
    ):
        _fail("lifecycle_verification_started")
    position += 1
    verifier_state: str | None = None
    if position < len(events) and events[position]["kind"] == "VERIFIER_STARTED":
        check_event(events[position], "VERIFIER_STARTED", "LEASED", 1)
        verifier_state = "STARTED"
        position += 1
        if position < len(events) and events[position]["kind"] in {"VERIFIER_COMPLETED", "VERIFIER_UNKNOWN"}:
            expected = events[position]["kind"]
            check_event(events[position], expected, "LEASED", 1)
            verifier_state = "COMPLETED" if expected == "VERIFIER_COMPLETED" else "UNKNOWN"
            position += 1
    if position < len(events) and events[position]["kind"].startswith("VERIFIER_"):
        _fail("lifecycle_verifier")
    if status == "LEASED":
        if attempt != 1 or position != len(events) or verifier_state not in {None, "STARTED"}:
            _fail("lifecycle_leased")
        return
    if attempt != 1:
        _fail("lifecycle_terminal")
    if status in {"VERIFIED", "REJECTED"}:
        if verifier_state != "COMPLETED":
            _fail("lifecycle_verifier")
        expected_kind = "BATCH_COMPLETED"
        expected_status = status
    elif status == "HELD":
        if verifier_state not in {None, "UNKNOWN"}:
            _fail("lifecycle_verifier")
        expected_kind = "BATCH_HELD"
        expected_status = "HELD"
    else:
        _fail("lifecycle_status")
    if position >= len(events):
        _fail("lifecycle_terminal")
    check_terminal(events[position], expected_kind, expected_status, 1)
    if position + 1 != len(events):
        _fail("lifecycle_terminal")


def _verify_temporal_bindings(
    batch_id: bytes,
    batch: tuple[Any, ...],
    attempt_row: tuple[Any, ...],
    lease: tuple[Any, ...] | None,
    result: tuple[Any, ...] | None,
    events: list[dict[str, Any]],
) -> None:
    if not events:
        _fail("timestamp_binding")
    event_times = [_strict_int(event.get("at_ms"), "timestamp_binding", minimum=0, maximum=_MAX_EPOCH) for event in events]
    if any(later < earlier for earlier, later in zip(event_times, event_times[1:])):
        _fail("timestamp_binding")
    valid_from = _strict_int(batch[6], "validity_deadline", minimum=0, maximum=_MAX_EPOCH)
    valid_until = _strict_int(batch[7], "validity_deadline", minimum=0, maximum=_MAX_EPOCH)
    created = _strict_int(batch[15], "timestamp_binding", minimum=0, maximum=_MAX_EPOCH)
    updated = _strict_int(batch[16], "timestamp_binding", minimum=0, maximum=_MAX_EPOCH)
    next_eligible = _strict_int(batch[14], "timestamp_binding", minimum=0, maximum=_MAX_EPOCH)
    reserved = _strict_int(attempt_row[7], "timestamp_binding", minimum=0, maximum=_MAX_EPOCH)
    if event_times[0] != created or reserved != created:
        _fail("timestamp_binding")

    positions = {event["kind"]: index for index, event in enumerate(events)}
    handoff_time: int | None = None
    if "HANDOFF_SUBMITTED" in positions:
        handoff_index = positions["HANDOFF_SUBMITTED"]
        if handoff_index != max(index for index, event in enumerate(events) if event["kind"] == "HANDOFF_SUBMITTED"):
            _fail("timestamp_binding")
        handoff_time = event_times[handoff_index]
    expected_next_eligible = created if handoff_time is None else handoff_time
    if next_eligible != expected_next_eligible:
        _fail("next_eligible_binding")

    source_indices = [index for index, event in enumerate(events) if event["kind"].startswith("SOURCE_")]
    if source_indices:
        if source_indices[0] != 1 or any(index > (handoff_index - 1 if "HANDOFF_SUBMITTED" in positions else len(events) - 1) for index in source_indices):
            _fail("source_temporal_binding")
        source_kinds = [events[index]["kind"] for index in source_indices]
        if source_kinds not in (["SOURCE_AUTHORIZED"], ["SOURCE_AUTHORIZED", "SOURCE_STARTED"], ["SOURCE_AUTHORIZED", "SOURCE_COMPLETED"], ["SOURCE_AUTHORIZED", "SOURCE_STARTED", "SOURCE_COMPLETED"], ["SOURCE_AUTHORIZED", "SOURCE_UNKNOWN"], ["SOURCE_AUTHORIZED", "SOURCE_STARTED", "SOURCE_UNKNOWN"]):
            _fail("source_temporal_binding")
        for index in source_indices:
            if events[index]["status"] != "AWAITING_HANDOFF" or events[index]["attempt"] != 0:
                _fail("source_temporal_binding")
        if "SOURCE_STARTED" in positions:
            source_started_time = event_times[positions["SOURCE_STARTED"]]
            if not valid_from <= source_started_time < valid_until:
                _fail("validity_deadline")
        if "SOURCE_COMPLETED" in positions and "SOURCE_STARTED" in positions and event_times[positions["SOURCE_COMPLETED"]] < event_times[positions["SOURCE_STARTED"]]:
            _fail("source_temporal_binding")
        if "SOURCE_UNKNOWN" in positions and "SOURCE_STARTED" in positions and event_times[positions["SOURCE_UNKNOWN"]] < event_times[positions["SOURCE_STARTED"]]:
            _fail("source_temporal_binding")

    status = str(batch[11])
    started_time: int | None = None
    lease_deadline: int | None = None
    verification_index = positions.get("VERIFICATION_STARTED")
    if verification_index is not None:
        if "HANDOFF_SUBMITTED" not in positions or verification_index <= positions["HANDOFF_SUBMITTED"]:
            _fail("timestamp_binding")
        started_time = event_times[verification_index]
        if started_time > _MAX_EPOCH - _LEASE_MS or not valid_from <= started_time < valid_until:
            _fail("validity_deadline")
        lease_deadline = started_time + _LEASE_MS
        if status == "LEASED" and lease is None:
            _fail("lease_binding")
        if lease is not None and (
            _strict_int(lease[3], "lease_binding", minimum=0, maximum=1) != 1
            or _strict_int(lease[4], "lease_binding", minimum=0, maximum=_MAX_EPOCH) != _strict_int(events[verification_index]["sequence"], "lease_binding", minimum=0, maximum=_MAX_EPOCH)
            or _strict_int(lease[5], "lease_binding", minimum=0, maximum=_MAX_EPOCH) != started_time
            or _strict_int(lease[6], "lease_binding", minimum=0, maximum=_MAX_EPOCH) != lease_deadline
        ):
            _fail("lease_binding")
    elif lease is not None:
        _fail("lease_binding")

    verifier_indices = [index for index, event in enumerate(events) if event["kind"].startswith("VERIFIER_")]
    if verifier_indices:
        if verification_index is None or verifier_indices[0] != verification_index + 1:
            _fail("verifier_temporal_binding")
        terminal_index = min((index for index, event in enumerate(events) if event["kind"] in {"BATCH_COMPLETED", "BATCH_HELD"}), default=len(events))
        if any(index >= terminal_index for index in verifier_indices):
            _fail("verifier_temporal_binding")
        verifier_kinds = [events[index]["kind"] for index in verifier_indices]
        if verifier_kinds not in (["VERIFIER_STARTED"], ["VERIFIER_STARTED", "VERIFIER_COMPLETED"], ["VERIFIER_STARTED", "VERIFIER_UNKNOWN"]):
            _fail("verifier_temporal_binding")
        verifier_start_time = event_times[verifier_indices[0]]
        if started_time is None or verifier_start_time < started_time or lease_deadline is None or verifier_start_time >= lease_deadline:
            _fail("verifier_temporal_binding")
        if len(verifier_indices) == 2 and event_times[verifier_indices[1]] < verifier_start_time:
            _fail("verifier_temporal_binding")

    if status == "AWAITING_HANDOFF":
        if updated != created:
            _fail("timestamp_binding")
    elif status == "QUEUED":
        if handoff_time is None or updated != handoff_time:
            _fail("timestamp_binding")
    elif status == "LEASED":
        if started_time is None or updated != started_time:
            _fail("timestamp_binding")
    else:
        terminal_time = event_times[-1]
        if events[-1]["kind"] not in {"BATCH_COMPLETED", "BATCH_HELD"} or updated != terminal_time:
            _fail("timestamp_binding")
        if result is None or _strict_int(result[11], "timestamp_binding", minimum=0, maximum=_MAX_EPOCH) != terminal_time:
            _fail("result_timestamp_binding")
        if attempt_row[8] is None or _strict_int(attempt_row[8], "timestamp_binding", minimum=0, maximum=_MAX_EPOCH) != terminal_time:
            _fail("attempt_timestamp_binding")
        terminal_error = events[-1].get("error_code")
        if status in {"VERIFIED", "REJECTED"}:
            if started_time is None or not valid_from <= terminal_time < valid_until:
                _fail("validity_deadline")
            if lease_deadline is None or terminal_time >= lease_deadline:
                _fail("lease_deadline")
        elif status == "HELD":
            allowed_errors = _HELD_PRELEASE_ERRORS if started_time is None else _HELD_STARTED_ERRORS
            if terminal_error not in allowed_errors:
                _fail("terminal_error_binding")
            if started_time is None:
                if terminal_error == "validity_expired" and not (terminal_time < valid_from or terminal_time >= valid_until):
                    _fail("validity_deadline")
            elif terminal_error == "validity_expired":
                if not (terminal_time < valid_from or terminal_time >= valid_until):
                    _fail("validity_deadline")
            elif terminal_error == "lease_expired":
                if terminal_time < lease_deadline:
                    _fail("lease_deadline")
            elif terminal_error != "fresh_handoff_required" and not (valid_from <= terminal_time < valid_until and terminal_time < lease_deadline):
                _fail("lease_deadline")
    if status in {"AWAITING_HANDOFF", "QUEUED", "LEASED"} and (result is not None or attempt_row[8] is not None):
        _fail("timestamp_binding")


def _verify_terminal_bindings(
    batch: tuple[Any, ...],
    attempt_row: tuple[Any, ...],
    result: tuple[Any, ...] | None,
    events: list[dict[str, Any]],
) -> None:
    """Bind terminal status, error, receipt, and acceptance fields to the producer state machine."""

    status = str(batch[11])
    verifier_event_kinds = [event["kind"] for event in events if event["kind"].startswith("VERIFIER_")]
    if verifier_event_kinds not in ([], ["VERIFIER_STARTED"], ["VERIFIER_STARTED", "VERIFIER_COMPLETED"], ["VERIFIER_STARTED", "VERIFIER_UNKNOWN"]):
        _fail("verifier_status")
    verifier_status = str(attempt_row[10])
    expected_active_verifier_statuses = {"UNRESERVED", "STARTED"}
    if status in {"AWAITING_HANDOFF", "QUEUED", "LEASED"}:
        if batch[17] is not None or attempt_row[9] is not None:
            _fail("terminal_error_binding")
        if (status in {"AWAITING_HANDOFF", "QUEUED"} and verifier_status != "UNRESERVED") or (status == "LEASED" and verifier_status not in expected_active_verifier_statuses):
            _fail("verifier_status")
        return
    if result is None or not events:
        _fail("terminal_result_missing")
    receipt = _parse_receipt(_db_bytes(result[3], "receipt"))
    values = (batch[17], result[13], receipt["error_code"], events[-1].get("error_code"))
    if any(value is None for value in values) and status != "VERIFIED":
        _fail("terminal_error_binding")
    if not all(value == values[0] for value in values):
        _fail("terminal_error_binding")
    result_codes = (attempt_row[9], result[9], receipt["result_code"])
    if not all(code == result_codes[0] for code in result_codes):
        _fail("terminal_result_binding")
    proof_accepted = bool(result[4])
    source_authenticated = bool(result[5])
    if status == "VERIFIED":
        if values[0] is not None or str(attempt_row[6]) != "ACCEPTED" or str(attempt_row[9]) != "accepted" or str(result[9]) != "accepted" or not (proof_accepted and source_authenticated) or receipt["error_code"] is not None or receipt["result_code"] != "accepted" or verifier_event_kinds != ["VERIFIER_STARTED", "VERIFIER_COMPLETED"] or verifier_status != "COMPLETED":
            _fail("terminal_acceptance")
    elif status == "REJECTED":
        if values[0] is None or str(attempt_row[6]) != "REJECTED" or str(attempt_row[9]) != "rejected" or str(result[9]) != "rejected" or (proof_accepted and source_authenticated) or receipt["result_code"] != "rejected" or verifier_event_kinds != ["VERIFIER_STARTED", "VERIFIER_COMPLETED"] or verifier_status != "COMPLETED":
            _fail("terminal_rejection")
    elif status == "HELD":
        result_code = result_codes[0]
        error_code = values[0]
        if (
            error_code is None
            or result_code not in _HELD_DIRECT_CODES | {"fresh_handoff_required"}
            or not (
                result_code == error_code and result_code in _HELD_DIRECT_CODES
                or result_code == "fresh_handoff_required" and error_code in _HELD_PROCESS_ERRORS
            )
            or str(attempt_row[6]) != "HELD"
            or proof_accepted
            or source_authenticated
            or verifier_status != ("UNKNOWN" if verifier_event_kinds else "UNRESERVED")
        ):
            _fail("terminal_hold")
    else:
        _fail("terminal_status")


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
    for index in (0, 1, 5, 16):
        _strict_int(meta[index], "composition_numeric")
    if meta[14] is not None:
        _strict_int(meta[14], "composition_numeric")
    for row in tx_rows:
        for index in (3, 10, 11, 15, 16):
            _strict_int(row[index], "composition_numeric")
    for row in event_rows:
        _strict_int(row[0], "composition_numeric")
        _strict_int(row[8], "composition_numeric", minimum=0)
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
        if str(batch[11]) == "VERIFIED":
            if len(refs) != _COUNT or not refs.issubset(tx_map):
                _fail("composition_batch_complete")
            verified_refs.update(refs)
        elif refs & set(tx_map):
            _fail("composition_nonaccepted")
    if set(tx_map) != verified_refs:
        _fail("composition_batch_complete")
    return {"meta": tuple(meta), "transactions": tx_rows, "events": event_rows, "outbox": outbox_rows}


def _verify_connection(
    connection: sqlite3.Connection,
    *,
    expected_config: Mapping[str, Any] | None = None,
    configure_connection: bool = True,
) -> dict[str, Any]:
    # Composition and direct callers pass writable handles here.  Reject a
    # retired schema before any setting PRAGMA can touch that handle.
    _schema_version_gate(connection)
    try:
        if configure_connection:
            # Standalone verification establishes its connection-local limits
            # only after the exact schema/version gate has passed.
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA max_page_count=32768")
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
    if (
        _strict_int(meta[1], "metadata") != SCHEMA_VERSION
        or _strict_int(meta[5], "metadata") != _ADMISSION_CAP
        or not 0 < _strict_int(meta[6], "metadata") < 5_000_000_000
        or _strict_int(meta[7], "metadata") != 1
        or _strict_int(meta[8], "metadata") != _DATABASE_PAGE_SIZE
        or _strict_int(meta[9], "metadata") != _DATABASE_MAX_PAGE_COUNT
        or type(meta[10]) is not str or meta[10].lower() != "delete"
        or _strict_int(meta[11], "metadata") != 2
        or _strict_int(meta[18], "metadata") != _PROOF_ATTEMPTS_CAP
        or _strict_int(meta[19], "metadata", minimum=0) < 0
        or any(_strict_int(meta[index], "metadata", minimum=0, maximum=_PROOF_ATTEMPTS_CAP) < 0 for index in (20, 21, 22, 23, 24))
    ):
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
    source_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_source_admissions ORDER BY batch_id").fetchall()]
    result_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_results").fetchall()]
    transition_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_transitions ORDER BY sequence").fetchall()]
    for index in (0, 1, 5, 6, 7, 8, 9, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24):
        _strict_int(meta[index], "metadata")
    for row in batch_rows:
        for index in (4, 6, 7, 12, 13, 14, 15, 16):
            _strict_int(row[index], "batch_numeric")
    for row in member_rows:
        for index in (1, 3):
            _strict_int(row[index], "member_numeric")
    for row in lease_rows:
        for index in (3, 4, 5, 6):
            _strict_int(row[index], "lease_numeric")
    for row in attempt_rows:
        for index in (0, 2, 3, 4, 7, 11):
            _strict_int(row[index], "attempt_numeric")
        if row[8] is not None:
            _strict_int(row[8], "attempt_numeric")
    for row in source_rows:
        for index in (8, 11, 13, 14, 15, 16):
            _strict_int(row[index], "source_numeric")
    for row in result_rows:
        for index in (4, 5, 11, 12):
            _strict_int(row[index], "result_numeric")
    for row in transition_rows:
        _strict_int(row[0], "transition_numeric")
    if len(lease_rows) > 1 or len(member_rows) != len(batch_rows) * _COUNT:
        _fail("batch_cardinality")
    batch_map = {_blob(_db_bytes(row[0], "batch_id"), 32, "batch_id"): row for row in batch_rows}
    if len(batch_map) != len(batch_rows) or tuple(int(row[12]) for row in batch_rows) != tuple(range(1, len(batch_rows) + 1)):
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
        expected_admission = {(int(row[12]) - 1) * _COUNT + position + 1 for position in range(_COUNT)}
        if {int(item[3]) for item in group} != expected_admission:
            _fail("member_binding")
        root = _blob(_db_bytes(row[1], "batch_root"), 64, "batch_root")
        _blob(_db_bytes(row[2], "session_ref"), 64, "session_ref")
        if _db_bytes(row[2], "session_ref") == bytes(64):
            _fail("session_ref")
        if _expected_batch_root(row, group) != root:
            _fail("batch_root_binding")
        if type(row[11]) is not str or row[11] not in _STATUSES or type(row[13]) is not int or row[13] not in (0, 1):
            _fail("batch_status")
        _token(row[3], "batch_assertion", 96)
        if type(row[4]) is not int or not 1 <= int(row[4]) <= 2**31 or type(row[5]) is not str:
            _fail("batch_template")
        _token(row[5], "batch_profile", 96)
        if type(row[6]) is not int or type(row[7]) is not int or not 0 <= int(row[6]) < int(row[7]) or int(row[7]) - int(row[6]) > _MAX_WINDOW:
            _fail("batch_window")
        if row[8] is not None:
            _blob(_db_bytes(row[8], "registry_root"), 64, "registry_root")
        flags = _parse_flags(_db_bytes(row[9], "flags"))
        _blob(_db_bytes(row[10], "identity_digest"), 64, "identity_digest")
        if _db_bytes(row[10], "identity_digest") != _identity_digest(row, group, config):
            _fail("batch_identity")
        public_coin = _blob(_db_bytes(row[18], "public_coin"), _PUBLIC_COIN_BYTES, "public_coin")
        if public_coin == bytes(_PUBLIC_COIN_BYTES):
            _fail("public_coin")
        _profile12_context(session_ref=_blob(_db_bytes(row[2], "session_ref"), 64, "session_ref"), batch_root=root, public_coin=public_coin, valid_from_ms=int(row[6]), valid_until_ms=int(row[7]))
        status_counts[str(row[11])] += 1
        _code(row[17], "batch_last_error") if row[17] is not None else None
        _forbidden_bytes((_db_bytes(row[9], "flags"), str(row[17]).encode("ascii") if row[17] is not None else b""))
    source_map: dict[bytes, tuple[Any, ...]] = {}
    for source in source_rows:
        batch_id = _blob(_db_bytes(source[0], "source_batch_id"), 32, "source_batch_id")
        if batch_id in source_map or batch_id not in batch_map:
            _fail("source_batch_binding")
        batch = batch_map[batch_id]
        if _token(source[1], "source_profile_version", 96) != config["profile_version"]:
            _fail("source_profile_binding")
        if type(batch[5]) is not str or batch[5] != source[1]:
            _fail("source_profile_binding")
        if _blob(_db_bytes(source[2], "source_profile_digest"), 64, "source_profile_digest") != _parse_hex(config["profile_digest"], 64, "source_profile_digest"):
            _fail("source_profile_binding")
        if type(source[3]) is not str or source[3] != config["source_auth_profile"]:
            _fail("source_profile_binding")
        if _epoch(source[4], "source_key_epoch") != int(config["source_key_epoch"]):
            _fail("source_key_epoch")
        expected_context = _profile12_context(session_ref=_blob(_db_bytes(batch[2], "source_session_ref"), 64, "source_session_ref"), batch_root=_blob(_db_bytes(batch[1], "source_batch_root"), 64, "source_batch_root"), public_coin=_blob(_db_bytes(batch[18], "source_public_coin"), _PUBLIC_COIN_BYTES, "source_public_coin"), valid_from_ms=int(batch[6]), valid_until_ms=int(batch[7]))
        if _blob(_db_bytes(source[5], "source_context"), _PROOF_CONTEXT_BYTES, "source_context") != expected_context or _blob(_db_bytes(source[6], "source_public_coin"), _PUBLIC_COIN_BYTES, "source_public_coin") != _db_bytes(batch[18], "source_public_coin"):
            _fail("source_batch_binding")
        if _blob(_db_bytes(source[7], "source_request_digest"), 64, "source_request_digest") != _expected_source_request_digest(batch, config):
            _fail("source_request_binding")
        if _strict_int(source[8], "source_retry_policy") != _SOURCE_ADMISSION_RETRY_LIMIT:
            _fail("source_retry_policy")
        source_identity_profile = _token(source[10], "source_identity_profile", 64)
        pin = _SOURCE_IDENTITY_PINS.get(source_identity_profile)
        if pin is None or _strict_int(source[11], "source_executable_identity") != pin[0] or _blob(_db_bytes(source[12], "source_executable_identity"), 32, "source_executable_identity") != pin[1]:
            _fail("source_executable_identity")
        if _blob(_db_bytes(source[9], "source_configuration_digest"), 64, "source_configuration_digest") != _source_configuration_digest(identity_profile=source_identity_profile, executable_size_bytes=int(source[11]), executable_sha256=_db_bytes(source[12], "source_executable_identity"), retry_limit=int(source[8])):
            _fail("source_configuration_binding")
        if tuple(source[13:17]) != (_SOURCE_ADMISSION_A_UPPER, _SOURCE_ADMISSION_S_UPPER, _SOURCE_ADMISSION_M_UPPER, _SOURCE_ADMISSION_U_ISSUANCES):
            _fail("source_admission_bounds")
        if type(source[17]) is not str or source[17] not in _SOURCE_STATUSES:
            _fail("source_status")
        source_map[batch_id] = source
    if int(meta[20]) != sum(int(row[13]) for row in source_rows) or int(meta[21]) != sum(int(row[14]) for row in source_rows) or int(meta[22]) != sum(int(row[15]) for row in source_rows) or int(meta[23]) != len(batch_rows) or int(meta[24]) != sum(1 for row in attempt_rows if str(row[10]) != "UNRESERVED"):
        _fail("source_accounting")
    if len(source_rows) > len(batch_rows):
        _fail("source_cardinality")
    for batch_id, source in source_map.items():
        status = str(batch_map[batch_id][11])
        source_status = str(source[17])
        if source_status in {"AUTHORIZED", "STARTED"} and status != "AWAITING_HANDOFF":
            _fail("source_status_binding")
        if source_status == "UNKNOWN" and status != "HELD":
            _fail("source_status_binding")
        if source_status == "COMPLETED" and status not in _STATUSES:
            _fail("source_status_binding")
    result_map = {_blob(_db_bytes(row[0], "result_batch_id"), 32, "result_batch_id"): row for row in result_rows}
    if len(result_map) != len(result_rows):
        _fail("result_duplicate")
    if set(result_map) - set(batch_map):
        _fail("result_orphan")
    # Validate every result row, including rows that do not match a batch, so
    # an orphan cannot hide arbitrary receipt bytes behind the batch loop.
    for result in result_map.values():
        _parse_receipt(_db_bytes(result[3], "receipt"))
        _forbidden_bytes((_db_bytes(result[3], "receipt"),))
    attempt_batch_ids = {_blob(_db_bytes(row[1], "attempt_batch"), 32, "attempt_batch") for row in attempt_rows}
    if len(attempt_rows) != len(batch_rows) or attempt_batch_ids != set(batch_map):
        _fail("attempt_missing" if set(batch_map) - attempt_batch_ids else "attempt_orphan")
    lease_batch_ids = {_blob(_db_bytes(row[0], "lease_batch_id"), 32, "lease_batch_id") for row in lease_rows}
    expected_lease_ids = {batch_id for batch_id, row in batch_map.items() if row[11] == "LEASED"}
    if lease_batch_ids - set(batch_map):
        _fail("lease_orphan")
    if lease_batch_ids != expected_lease_ids:
        _fail("lease_binding")
    transition_batch_ids = {_blob(_db_bytes(row[2], "transition_batch"), 32, "transition_batch") for row in transition_rows}
    if transition_batch_ids - set(batch_map):
        _fail("transition_orphan")
    try:
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            _fail("foreign_key_check")
    except sqlite3.Error:
        _fail("foreign_key_check")
    for batch_id, row in batch_map.items():
        status = str(row[11])
        result = result_map.get(batch_id)
        if (status in _TERMINAL and result is None) or (status not in _TERMINAL and result is not None):
            _fail("result_set")
        if result is not None:
            result_epoch = _epoch(result[8], "result_source_epoch")
            if type(result[1]) is not str or result[1] != status or type(result[12]) is not int or result[12] != row[13] or type(result[4]) is not int or result[4] not in (0, 1) or type(result[5]) is not int or result[5] not in (0, 1) or _db_bytes(result[6], "result_root") != _db_bytes(row[1], "batch_root") or type(result[7]) is not str or result[7] != config["source_auth_profile"] or result_epoch != config["source_key_epoch"] or _parse_flags(_db_bytes(result[10], "result_flags")) != tuple(config["qualification_flags"]):
                _fail("result_binding")
            receipt = _parse_receipt(_db_bytes(result[3], "receipt"))
            if _parse_hex(receipt["batch_id"], 32, "receipt_batch_id") != batch_id or _parse_hex(receipt["batch_root"], 64, "receipt_root") != _db_bytes(row[1], "batch_root") or receipt["source_auth_profile"] != config["source_auth_profile"] or int(receipt["source_key_epoch"]) != int(config["source_key_epoch"]):
                _fail("receipt_binding")
            if type(receipt["qualification_flags"]) is not list or tuple(receipt["qualification_flags"]) != tuple(config["qualification_flags"]):
                _fail("receipt_flags")
            if bool(result[4]) != bool(receipt["proof_accepted"]) or bool(result[5]) != bool(receipt["source_authenticated"]) or str(result[9]) != receipt["result_code"] or (None if result[13] is None else str(result[13])) != receipt["error_code"]:
                _fail("receipt_result_binding")
            _code(result[9], "result_code")
            if result[13] is not None:
                _code(result[13], "result_error_code")
            if status == "VERIFIED" and not (bool(result[4]) and bool(result[5]) and receipt["error_code"] is None):
                _fail("verified_acceptance")
            if status != "VERIFIED" and bool(result[4]) and bool(result[5]):
                _fail("terminal_acceptance")
            if status == "VERIFIED" and str(result[9]) != "accepted":
                _fail("verified_result_code")
            if status == "REJECTED" and str(result[9]) != "rejected":
                _fail("rejected_result_code")
            expected_receipt_id = _sha(_MATERIAL, b"receipt", batch_id, _u64(int(row[13])))[:32]
            if _db_bytes(result[2], "receipt_id") != expected_receipt_id:
                _fail("receipt_id")
            _forbidden_bytes((_db_bytes(result[3], "receipt"), str(result[9]).encode("ascii"), _db_bytes(result[10], "result_flags"), str(result[13]).encode("ascii") if result[13] is not None else b""))
    lease_map = {_blob(_db_bytes(row[0], "lease_batch_id"), 32, "lease_batch_id"): row for row in lease_rows}
    attempt_map = {_blob(_db_bytes(row[1], "attempt_batch_id"), 32, "attempt_batch_id"): row for row in attempt_rows}
    if len(attempt_map) != len(attempt_rows):
        _fail("attempt_duplicate")
    previous_after = 0
    for expected_id, row in enumerate(attempt_rows, start=1):
        batch_id = _blob(_db_bytes(row[1], "attempt_batch"), 32, "attempt_batch")
        if type(row[0]) is not int or type(row[2]) is not int or type(row[3]) is not int or type(row[4]) is not int or type(row[7]) is not int or (row[8] is not None and type(row[8]) is not int):
            _fail("attempt_chain")
        before, after, proof_attempts = row[2], row[3], row[4]
        attempt_epoch = _epoch(row[5], "attempt_source_epoch")
        if int(row[0]) != expected_id or batch_id not in batch_map or before != previous_after or after != before + _PROOF_ATTEMPTS_PER_BATCH or proof_attempts != _PROOF_ATTEMPTS_PER_BATCH or not 1 <= attempt_epoch <= _MAX_EPOCH or str(row[6]) not in {"RESERVED", "ACCEPTED", "REJECTED", "HELD"} or int(row[7]) < 0 or (row[8] is not None and int(row[8]) < int(row[7])) or str(row[10]) not in {"UNRESERVED", "STARTED", "COMPLETED", "UNKNOWN"} or int(row[11]) != _VERIFIER_LAUNCH_V_UPPER:
            _fail("attempt_chain")
        previous_after = after
        batch = batch_map[batch_id]
        if int(batch[12]) != expected_id or attempt_epoch != int(config["source_key_epoch"]):
            _fail("attempt_binding")
        expected_status = {"AWAITING_HANDOFF": "RESERVED", "QUEUED": "RESERVED", "LEASED": "RESERVED", "VERIFIED": "ACCEPTED", "REJECTED": "REJECTED", "HELD": "HELD"}.get(str(batch[11]))
        if expected_status is not None and str(row[6]) != expected_status:
            _fail("attempt_status")
        if row[9] is not None:
            _code(row[9], "attempt_result_code")
        result = result_map.get(batch_id)
        if result is not None and (result[9] is None or str(row[9]) != str(result[9])):
            _fail("attempt_result_binding")
    if int(meta[17]) != previous_after or int(meta[18]) != _PROOF_ATTEMPTS_CAP or int(meta[19]) != len(attempt_rows):
        _fail("attempt_ledger")
    for batch_id, row in batch_map.items():
        status = str(row[11])
        attempt = int(row[13])
        attempt_row = attempt_map.get(batch_id)
        if attempt_row is None:
            _fail("attempt_missing")
        if status == "LEASED":
            lease = lease_map.get(batch_id)
            if lease is None or int(lease[3]) != 1 or type(lease[1]) is not str or len(_db_bytes(lease[2], "lease_digest")) != 64 or int(lease[6]) <= int(lease[5]):
                _fail("lease_binding")
            _token(lease[1], "lease_worker", 96)
        elif batch_id in lease_map:
            _fail("lease_status")
    if set(lease_map) != {batch_id for batch_id, row in batch_map.items() if str(row[11]) == "LEASED"}:
        _fail("lease_set")
    expected_nonterminal = sum(1 for row in batch_map.values() if str(row[11]) in {"AWAITING_HANDOFF", "QUEUED", "LEASED"})
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
        if type(event) is not dict or _db_bytes(row[5], "event") != _json_bytes(event) or event.get("schema") != _SCHEMA or type(event.get("sequence")) is not int or event.get("sequence") != index or event.get("batch_id") != _hex(batch_id) or event.get("kind") != str(row[1]) or event.get("kind") not in _EVENT_KINDS or event.get("status") not in _STATUSES or type(event.get("attempt")) is not int or not 0 <= event["attempt"] <= 1 or type(event.get("at_ms")) is not int or event["at_ms"] < 0:
            _fail("transition_binding")
        allowed = {"schema", "sequence", "kind", "batch_id", "status", "error_code", "attempt", "at_ms", "member_count", "reservation_before", "reservation_after", "receipt_id", "identity_digest"}
        if set(event) - allowed or event.get("member_count") != _COUNT:
            _fail("transition_fields")
        if event["error_code"] is not None:
            _code(event["error_code"], "event_error_code")
        if event["kind"] == "BATCH_ISSUED":
            if set(event) != {"schema", "sequence", "kind", "batch_id", "status", "error_code", "attempt", "at_ms", "member_count", "identity_digest", "reservation_before", "reservation_after"} or type(event.get("reservation_before")) is not int or type(event.get("reservation_after")) is not int or event["reservation_after"] != event["reservation_before"] + _PROOF_ATTEMPTS_PER_BATCH:
                _fail("transition_fields")
            if event["identity_digest"] != _hex(batch_map[batch_id][10]):
                _fail("batch_identity")
        elif event["kind"] == "VERIFICATION_STARTED":
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
    verifier_started_count = 0
    for batch_id, events in events_by_batch.items():
        source_kinds = [event["kind"] for event in events if event["kind"].startswith("SOURCE_")]
        source = source_map.get(batch_id)
        if source is None:
            if source_kinds:
                _fail("source_event_binding")
        else:
            expected_source_kinds = {
                "AUTHORIZED": ["SOURCE_AUTHORIZED"],
                "STARTED": ["SOURCE_AUTHORIZED", "SOURCE_STARTED"],
                "COMPLETED": ["SOURCE_AUTHORIZED", "SOURCE_STARTED", "SOURCE_COMPLETED"],
                "UNKNOWN": ["SOURCE_AUTHORIZED", "SOURCE_UNKNOWN"],
            }
            if str(source[17]) == "UNKNOWN" and source_kinds == ["SOURCE_AUTHORIZED", "SOURCE_STARTED", "SOURCE_UNKNOWN"]:
                pass
            elif source_kinds != expected_source_kinds.get(str(source[17])):
                _fail("source_event_binding")
        attempt_row = attempt_map.get(batch_id)
        if attempt_row is None:
            _fail("attempt_missing")
        verifier_kinds = [event["kind"] for event in events if event["kind"].startswith("VERIFIER_")]
        if verifier_kinds:
            verifier_started_count += verifier_kinds.count("VERIFIER_STARTED")
        expected_verifier_kinds = {
            "UNRESERVED": [],
            "STARTED": ["VERIFIER_STARTED"],
            "COMPLETED": ["VERIFIER_STARTED", "VERIFIER_COMPLETED"],
            "UNKNOWN": ["VERIFIER_STARTED", "VERIFIER_UNKNOWN"],
        }
        if verifier_kinds != expected_verifier_kinds.get(str(attempt_row[10])):
            _fail("verifier_event_binding")
    if verifier_started_count != int(meta[24]):
        _fail("verifier_accounting")
    expected_issue_order = [batch_id for batch_id, _row in sorted(batch_map.items(), key=lambda item: int(item[1][12]))]
    issue_records: list[tuple[int, bytes]] = []
    for batch_id, events in events_by_batch.items():
        issue_events = [event for event in events if event["kind"] == "BATCH_ISSUED"]
        if len(issue_events) != 1:
            _fail("issue_order")
        issue_records.append((_strict_int(issue_events[0]["sequence"], "issue_order", minimum=1, maximum=_MAX_EPOCH), batch_id))
    actual_issue_order = [batch_id for _sequence, batch_id in sorted(issue_records)]
    if actual_issue_order != expected_issue_order:
        _fail("issue_order")
    for batch_id, row in batch_map.items():
        attempt_row = attempt_map[batch_id]
        _verify_lifecycle(
            events_by_batch[batch_id],
            str(row[11]),
            int(row[13]),
            reservation_before=int(attempt_row[2]),
            reservation_after=int(attempt_row[3]),
        )
        _verify_temporal_bindings(
            batch_id,
            row,
            attempt_row,
            lease_map.get(batch_id),
            result_map.get(batch_id),
            events_by_batch[batch_id],
        )
        _verify_terminal_bindings(row, attempt_row, result_map.get(batch_id), events_by_batch[batch_id])
    composition = _verify_composition(connection, config=config, queue_config_digest=config_digest, batch_map=batch_map, member_groups=member_groups)
    return {"schema": _SCHEMA, "config": config, "config_digest": config_digest, "meta": tuple(meta), "batches": batch_map, "members": member_groups, "attempts": attempt_map, "leases": lease_map, "source_admissions": source_map, "results": result_map, "transitions": transition_rows, "events": events_by_batch, "composition": composition, "head_root": _db_bytes(meta[12], "head_root"), "status_counts": status_counts, "transition_count": len(transition_rows), "verified_batch_count": status_counts["VERIFIED"], "accepted_operation_count": status_counts["VERIFIED"] * _COUNT, "verified_count": status_counts["VERIFIED"], "source_admission_count": len(source_map), "source_accounting": {"a_used": int(meta[20]), "s_used": int(meta[21]), "m_used": int(meta[22]), "u_used": int(meta[23]), "v_used": int(meta[24])}, "proof_bytes_persisted": False, "path_custody": False, "proof_suite_id": None, "production_usable": False, "activation": False}


@dataclass(frozen=True, slots=True)
class _VerifiedLifecycleImage:
    connection: sqlite3.Connection
    owner_token: object
    transaction_token: object
    expected_config_bytes: bytes
    connection_fingerprint: tuple[Any, ...]
    thread_id: int
    verified: Mapping[str, Any]
    seal: object


@dataclass(frozen=True, slots=True)
class _LifecycleImageBinding:
    image: _VerifiedLifecycleImage
    connection: sqlite3.Connection
    owner_token: object
    transaction_token: object
    batch_id: bytes
    thread_id: int


_VERIFIED_LIFECYCLE_IMAGE_SEAL: Final[object] = object()
# The adapter's sole snapshot consumer is indirect. Bind the immutable image
# only for one synchronous Queue evaluation and reset it with the ContextVar
# token; any active but stale or mismatched binding fails closed.
_LIFECYCLE_IMAGE_CONTEXT: ContextVar[_LifecycleImageBinding | None] = ContextVar(
    "blind_ledger_queue_lifecycle_verified_image", default=None
)


def _freeze_verified_image(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_verified_image(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_verified_image(item) for item in value)
    if isinstance(value, bytearray):
        return bytes(value)
    return value


def _lifecycle_expected_config_bytes(expected_config: Mapping[str, Any] | None) -> bytes:
    if not isinstance(expected_config, Mapping):
        _fail("lifecycle_verified_image_config")
    try:
        return json.dumps(
            dict(expected_config),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        _fail("lifecycle_verified_image_config")


def _lifecycle_connection_fingerprint(connection: sqlite3.Connection) -> tuple[Any, ...]:
    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        _fail("lifecycle_verified_image_transaction")
    pragma_names = (
        "data_version",
        "schema_version",
        "user_version",
        "application_id",
        "foreign_keys",
        "page_size",
        "max_page_count",
        "journal_mode",
        "synchronous",
        "busy_timeout",
    )
    try:
        pragma_values: list[tuple[str, Any]] = []
        for name in pragma_names:
            row = connection.execute(f"PRAGMA {name}").fetchone()
            if row is None or len(row) != 1:
                _fail("lifecycle_verified_image_connection")
            value = row[0]
            pragma_values.append((name, str(value).lower() if name == "journal_mode" else value))
    except sqlite3.Error:
        _fail("lifecycle_verified_image_connection")
    checks = dict(pragma_values)
    if (
        type(checks["data_version"]) is not int
        or type(checks["schema_version"]) is not int
        or type(checks["user_version"]) is not int
        or type(checks["application_id"]) is not int
        or checks["foreign_keys"] != 1
        or checks["page_size"] != _DATABASE_PAGE_SIZE
        or checks["max_page_count"] != 32768
        or checks["journal_mode"] != "delete"
        or checks["synchronous"] != 2
        or checks["busy_timeout"] != 5000
    ):
        _fail("lifecycle_verified_image_connection")
    return (
        connection.total_changes,
        tuple(pragma_values),
        connection.row_factory,
        connection.text_factory,
        connection.isolation_level,
        getattr(connection, "autocommit", None),
    )


def _same_lifecycle_connection_fingerprint(
    left: tuple[Any, ...], right: tuple[Any, ...]
) -> bool:
    return (
        len(left) == len(right) == 6
        and left[:2] == right[:2]
        and left[2] is right[2]
        and left[3] is right[3]
        and left[4:] == right[4:]
    )


def _capture_verified_lifecycle_image(
    connection: sqlite3.Connection,
    *,
    expected_config: Mapping[str, Any],
    owner_token: object,
    transaction_token: object,
) -> _VerifiedLifecycleImage:
    if owner_token is None or transaction_token is None:
        _fail("lifecycle_verified_image_owner")
    before = _lifecycle_connection_fingerprint(connection)
    verified = _verify_connection(
        connection,
        expected_config=expected_config,
        configure_connection=False,
    )
    after = _lifecycle_connection_fingerprint(connection)
    if not _same_lifecycle_connection_fingerprint(before, after):
        _fail("lifecycle_verified_image_changed")
    return _VerifiedLifecycleImage(
        connection=connection,
        owner_token=owner_token,
        transaction_token=transaction_token,
        expected_config_bytes=_lifecycle_expected_config_bytes(expected_config),
        connection_fingerprint=after,
        thread_id=get_ident(),
        verified=_freeze_verified_image(verified),
        seal=_VERIFIED_LIFECYCLE_IMAGE_SEAL,
    )


def _assert_lifecycle_image_current(
    binding: _LifecycleImageBinding,
    *,
    connection: sqlite3.Connection,
    batch_id: bytes,
    expected_config: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    image = binding.image
    if (
        image.seal is not _VERIFIED_LIFECYCLE_IMAGE_SEAL
        or binding.connection is not connection
        or image.connection is not connection
        or binding.owner_token is not image.owner_token
        or binding.transaction_token is not image.transaction_token
        or binding.thread_id != get_ident()
        or image.thread_id != get_ident()
        or binding.batch_id != batch_id
        or _lifecycle_expected_config_bytes(expected_config) != image.expected_config_bytes
    ):
        _fail("lifecycle_verified_image_binding")
    if not _same_lifecycle_connection_fingerprint(
        _lifecycle_connection_fingerprint(connection), image.connection_fingerprint
    ):
        _fail("lifecycle_verified_image_stale")
    verified = image.verified
    cached_batch = verified["batches"].get(batch_id)
    if cached_batch is None:
        _fail("lifecycle_batch_unknown")
    try:
        current_batch = connection.execute(
            "SELECT * FROM queue_batches WHERE batch_id=?", (batch_id,)
        ).fetchone()
        current_members = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM queue_members WHERE batch_id=? ORDER BY batch_position",
                (batch_id,),
            ).fetchall()
        )
    except sqlite3.Error:
        _fail("lifecycle_database_sqlite")
    if current_batch is None or tuple(current_batch) != tuple(cached_batch):
        _fail("lifecycle_verified_image_batch")
    cached_members = verified["members"].get(batch_id)
    if cached_members is None:
        _fail("lifecycle_batch_members")
    expected_members = tuple(
        sorted((tuple(row) for row in cached_members), key=lambda row: int(row[1]))
    )
    if current_members != expected_members:
        _fail("lifecycle_verified_image_members")
    if not _same_lifecycle_connection_fingerprint(
        _lifecycle_connection_fingerprint(connection), image.connection_fingerprint
    ):
        _fail("lifecycle_verified_image_stale")
    return verified


@contextmanager
def _bind_verified_lifecycle_image(
    image: _VerifiedLifecycleImage,
    *,
    connection: sqlite3.Connection,
    owner_token: object,
    transaction_token: object,
    batch_id: bytes,
    expected_config: Mapping[str, Any],
) -> Iterator[None]:
    if not isinstance(image, _VerifiedLifecycleImage) or image.seal is not _VERIFIED_LIFECYCLE_IMAGE_SEAL:
        _fail("lifecycle_verified_image_type")
    if _LIFECYCLE_IMAGE_CONTEXT.get() is not None:
        _fail("lifecycle_verified_image_nested")
    binding = _LifecycleImageBinding(
        image=image,
        connection=connection,
        owner_token=owner_token,
        transaction_token=transaction_token,
        batch_id=batch_id,
        thread_id=get_ident(),
    )
    _assert_lifecycle_image_current(
        binding,
        connection=connection,
        batch_id=batch_id,
        expected_config=expected_config,
    )
    token = _LIFECYCLE_IMAGE_CONTEXT.set(binding)
    try:
        yield
        _assert_lifecycle_image_current(
            binding,
            connection=connection,
            batch_id=batch_id,
            expected_config=expected_config,
        )
    finally:
        _LIFECYCLE_IMAGE_CONTEXT.reset(token)


def _verified_image_for_lifecycle_snapshot(
    connection: sqlite3.Connection,
    *,
    batch_id: bytes,
    expected_config: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    binding = _LIFECYCLE_IMAGE_CONTEXT.get()
    if binding is None:
        return None
    return _assert_lifecycle_image_current(
        binding,
        connection=connection,
        batch_id=batch_id,
        expected_config=expected_config,
    )


def lifecycle_snapshot_from_connection(
    connection: sqlite3.Connection,
    *,
    batch_id: bytes,
    expected_config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a validated lifecycle input from the caller's active SQLite transaction.

    This helper never opens, closes, commits, rolls back, or writes to the supplied
    connection. Its caller must already hold the Queue owner lock and have begun
    the intended transaction; the SQLite API exposes only the active-transaction
    bit here, not the transaction's BEGIN mode or the external owner-lock state.
    """

    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        _fail("lifecycle_transaction_required")
    if type(batch_id) is not bytes or len(batch_id) != 32:
        _fail("lifecycle_batch_id")
    try:
        verified = _verified_image_for_lifecycle_snapshot(
            connection,
            batch_id=batch_id,
            expected_config=expected_config,
        )
        if verified is None:
            verified = _verify_connection(
                connection,
                expected_config=expected_config,
                configure_connection=False,
            )
        batch = verified["batches"].get(batch_id)
        members = verified["members"].get(batch_id)
        if batch is None or members is None:
            _fail("lifecycle_batch_unknown")
        ordered_members = tuple(sorted(members, key=lambda row: int(row[1])))
        if len(ordered_members) != _COUNT or tuple(int(row[1]) for row in ordered_members) != tuple(range(_COUNT)):
            _fail("lifecycle_batch_members")
        attempt = verified["attempts"].get(batch_id)
        lease = verified["leases"].get(batch_id)
        if attempt is None:
            _fail("lifecycle_attempt_or_lease")
        proof_context = _profile12_context(
            session_ref=_db_bytes(batch[2], "lifecycle_session_ref"),
            batch_root=_db_bytes(batch[1], "lifecycle_batch_root"),
            public_coin=_db_bytes(batch[18], "lifecycle_public_coin"),
            valid_from_ms=_strict_int(batch[6], "lifecycle_valid_from", minimum=0, maximum=_MAX_EPOCH),
            valid_until_ms=_strict_int(batch[7], "lifecycle_valid_until", minimum=0, maximum=_MAX_EPOCH),
        )
        return {
            "schema": verified["schema"],
            "config": verified["config"],
            "config_digest": verified["config_digest"],
            "proof_context": proof_context,
            "meta": verified["meta"],
            "batch": tuple(batch),
            "members": ordered_members,
            "source_admission": verified["source_admissions"].get(batch_id),
            "attempt": tuple(attempt),
            "lease": None if lease is None else tuple(lease),
            "result": verified["results"].get(batch_id),
            "events": tuple(verified["events"].get(batch_id, ())),
            "composition_meta": tuple(verified["composition"]["meta"]),
            "head_root": verified["head_root"],
            "transition_count": verified["transition_count"],
        }
    except sqlite3.Error:
        _fail("database_sqlite")


def _verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    try:
        if path.stat().st_size > _DATABASE_CAP:
            _fail("database_bounds")
        _read_only_schema_gate(path)
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5.0)) as connection:
            return _verify_connection(connection, expected_config=expected_config)
    except sqlite3.Error:
        _fail("database_sqlite")


def _resolve_issue_request_from_verified(
    verified: Mapping[str, Any],
    *,
    request_id: bytes,
    expected_template: Mapping[str, Any],
) -> IndependentIssueRequestLookup:
    template_bytes = _expected_issue_template_bytes(expected_template)
    queue_id = verified["config"].get("queue_id")
    batch_id = issue_request_batch_id_v1(queue_id=queue_id, request_id=request_id)
    row = verified["batches"].get(batch_id)
    if row is None:
        return IndependentIssueRequestLookup(
            1,
            bytes(verified["config_digest"]),
            tuple(verified["meta"]),
            None,
        )
    row = tuple(row)
    if _template_bytes(row) != template_bytes:
        _fail("issue_request_conflict")
    members = verified["members"].get(batch_id)
    if members is None:
        _fail("queue_integrity_failed")
    ordered = tuple(sorted((tuple(member) for member in members), key=lambda member: int(member[1])))
    if len(ordered) != _COUNT or tuple(int(member[1]) for member in ordered) != tuple(range(_COUNT)):
        _fail("queue_integrity_failed")
    refs = tuple(_blob(_db_bytes(member[2], "issue_request_operation_ref"), 32, "issue_request_operation_ref") for member in ordered)
    batch_root = _blob(_db_bytes(row[1], "issue_request_batch_root"), 64, "issue_request_batch_root")
    session_ref = _blob(_db_bytes(row[2], "issue_request_session_ref"), 64, "issue_request_session_ref")
    public_coin = _blob(_db_bytes(row[18], "issue_request_public_coin"), _PUBLIC_COIN_BYTES, "issue_request_public_coin")
    proof_context = _profile12_context(
        session_ref=session_ref,
        batch_root=batch_root,
        public_coin=public_coin,
        valid_from_ms=_strict_int(row[6], "issue_request_validity", minimum=0, maximum=_MAX_EPOCH),
        valid_until_ms=_strict_int(row[7], "issue_request_validity", minimum=0, maximum=_MAX_EPOCH),
    )
    resolved = IndependentIssuedQueueRequest(
        1,
        batch_id,
        batch_root,
        session_ref,
        refs,
        public_coin,
        proof_context,
        _blob(_db_bytes(row[10], "issue_request_identity"), 64, "issue_request_identity"),
        _strict_int(row[12], "issue_request_admission_seq", minimum=1),
        str(row[11]),
    )
    return IndependentIssueRequestLookup(
        1,
        bytes(verified["config_digest"]),
        tuple(verified["meta"]),
        resolved,
    )


def resolve_issue_request_from_connection(
    connection: sqlite3.Connection,
    *,
    request_id: bytes,
    expected_template: Mapping[str, Any],
    expected_config: Mapping[str, Any],
) -> IndependentIssueRequestLookup:
    """Independently resolve an issue request in its caller's active transaction."""

    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        _fail("issue_request_transaction")
    if not isinstance(expected_config, Mapping):
        _fail("config_binding")
    if type(request_id) is not bytes or len(request_id) != _ISSUE_REQUEST_ID_BYTES:
        _fail("issue_request_id")
    _expected_issue_template_bytes(expected_template)
    verified = _verify_connection(
        connection,
        expected_config=expected_config,
        configure_connection=False,
    )
    return _resolve_issue_request_from_verified(
        verified,
        request_id=request_id,
        expected_template=expected_template,
    )


def resolve_issue_request(
    path: Path,
    *,
    request_id: bytes,
    expected_template: Mapping[str, Any],
    expected_config: Mapping[str, Any],
) -> IndependentIssueRequestLookup:
    """Read-only independent lookup for a durable issue request v1."""

    if not isinstance(expected_config, Mapping):
        _fail("config_binding")
    if type(request_id) is not bytes or len(request_id) != _ISSUE_REQUEST_ID_BYTES:
        _fail("issue_request_id")
    _expected_issue_template_bytes(expected_template)
    verified = _verify_database(path, expected_config=expected_config)
    return _resolve_issue_request_from_verified(
        verified,
        request_id=request_id,
        expected_template=expected_template,
    )


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    verified = _verify_database(path, expected_config=expected_config)
    return {key: value for key, value in verified.items() if key not in {"config", "config_digest", "meta", "batches", "members", "attempts", "leases", "results", "transitions", "events", "composition"}}


def _job_from_rows(config: Mapping[str, Any], config_digest: bytes, owner: tuple[Any, ...], member: tuple[Any, ...], result: tuple[Any, ...]) -> IndependentVerifiedQueueJob:
    receipt_raw = bytes(result[3])
    _parse_receipt(receipt_raw)
    return IndependentVerifiedQueueJob(str(config["queue_id"]), config_digest, bytes(member[2]), str(owner[11]), bool(result[4]), int(owner[13]), receipt_raw, bytes(result[2]), str(owner[3]), int(owner[4]), str(owner[5]), int(owner[6]), int(owner[7]), int(member[1]), None if owner[1] is None else bytes(owner[1]), None if owner[8] is None else bytes(owner[8]), str(config["profile_version"]), str(result[9]), tuple(_parse_flags(bytes(result[10]))))


def _empty_batch(config_digest: bytes, head_root: bytes, transition_count: int) -> IndependentVerifiedQueueBatch:
    return IndependentVerifiedQueueBatch(IndependentBatchAcceptance(bytes(64), head_root, config_digest, (), bytes(64), bytes(32), 0, transition_count), ())


def _promotion_batch(verified: dict[str, Any], batch_id: bytes) -> IndependentVerifiedQueueBatch:
    row = verified["batches"].get(batch_id)
    if row is None:
        _fail("batch_selector")
    if str(row[11]) != "VERIFIED":
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
    candidates = [(int(row[12]), batch_id) for batch_id, row in verified["batches"].items() if str(row[11]) == "VERIFIED" and bool(verified["results"].get(batch_id) and verified["results"][batch_id][4] and verified["results"][batch_id][5])]
    if not candidates:
        return _empty_batch(verified["config_digest"], verified["head_root"], verified["transition_count"])
    _admission, batch_id = min(candidates)
    return _promotion_batch(verified, batch_id)


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _DATABASE_CAP:
        _fail("export_bytes")
    with tempfile.TemporaryDirectory(prefix="bl-v12-export-") as directory:
        path = Path(directory) / "queue.sqlite"
        path.write_bytes(raw)
        return verify_database(path, expected_config=expected_config)


def restore_export_to_fresh_database(*, export_bytes: bytes, destination: Path, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if type(export_bytes) is not bytes or not export_bytes or len(export_bytes) > _DATABASE_CAP or not isinstance(destination, Path) or not destination.is_absolute() or not destination.parent.is_dir() or destination.exists() or destination.is_symlink():
        _fail("restore_path")
    # Validate the complete export in a disposable read-only database before
    # creating the destination.  A malformed/old export must never leave a
    # destination artifact or overwrite a path that appeared during verify.
    verify_export_bytes(export_bytes, expected_config=expected_config)
    created_identity: tuple[int, int] | None = None
    try:
        with destination.open("xb") as output:
            stat_result = destination.stat()
            created_identity = (int(stat_result.st_dev), int(stat_result.st_ino))
            output.write(export_bytes)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        _fail("restore_path")
    except OSError:
        try:
            current = destination.stat()
            if created_identity == (int(current.st_dev), int(current.st_ino)) and not destination.is_symlink():
                destination.unlink()
        except OSError:
            pass
        _fail("restore_write")
    try:
        return verify_database(destination, expected_config=expected_config)
    except BaseException:
        try:
            current = destination.stat()
            if created_identity == (int(current.st_dev), int(current.st_ino)) and not destination.is_symlink():
                destination.unlink()
        except OSError:
            pass
        raise


__all__ = ("IndependentQueueError", "IndependentVerifiedQueueBatch", "IndependentVerifiedQueueJob", "IndependentBatchAcceptance", "IndependentIssuedQueueRequest", "IndependentIssueRequestLookup", "issue_request_batch_id_v1", "resolve_issue_request_from_connection", "resolve_issue_request", "parse_admission_state_handoff", "verify_admission_state_handoff", "read_verified_batch", "restore_export_to_fresh_database", "verify_database", "verify_export_bytes", "_parse_config")
