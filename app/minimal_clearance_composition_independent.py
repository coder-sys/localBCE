"""Independent reconstruction for the synthetic three-table composition V2."""

from __future__ import annotations

import hashlib
import json
import re
from functools import wraps
from pathlib import Path
import sqlite3
from typing import Any, Callable, Final, Mapping, NoReturn

from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes


class IndependentCompositionError(RuntimeError):
    pass


def _raise_fixed(code: str) -> NoReturn:
    error = IndependentCompositionError(code)
    try:
        raise error from None
    except IndependentCompositionError as clean:
        clean.__cause__ = None
        clean.__context__ = None
        raise


def _public(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except IndependentCompositionError as exc:
            exc.__cause__ = None
            exc.__context__ = None
            raise
        except Exception:
            _raise_fixed("independent_composition_error")
    return wrapped


_SCHEMA_VERSION: Final[int] = 3
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v3"
_HANDOFF_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/v2"
_ACK_MODE: Final[str] = "SYNTHETIC_ONLY"
_DIRECTIVES: Final[tuple[str, ...]] = ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED")
_DELIVERY_STATES: Final[frozenset[str]] = frozenset({"READY", "DISPATCH_LEASED", "DELIVERY_UNCONFIRMED", "RECONCILIATION_LEASED", "ACKNOWLEDGED", "DISPATCH_EXHAUSTED", "RECONCILIATION_EXHAUSTED"})
_EVENT_KINDS: Final[frozenset[str]] = frozenset({"APPLIED", "HELD", "DISPATCH_LEASED", "DISPATCH_RELEASED", "DELIVERY_UNCONFIRMED", "DISPATCH_LEASE_EXPIRED", "DISPATCH_EXHAUSTED", "RECONCILIATION_LEASED", "RECONCILIATION_INDETERMINATE", "RECONCILIATION_LEASE_EXPIRED", "RECONCILIATION_EXHAUSTED", "ACKNOWLEDGED", "ACKNOWLEDGED_BY_RECONCILIATION", "ACK_CONFLICT"})
_CONFIG_KEYS: Final[frozenset[str]] = frozenset({"schema_version", "composition_id", "queue_id", "queue_config_digest", "verifier_sha256", "receiver_identity", "receiver_epoch", "verifier_epoch", "capacity", "lease_seconds", "reconciliation_capacity", "reconciliation_lease_seconds", "max_attempts", "busy_timeout_ms", "ack_evidence_profile_digest", "directives", "proof_suite_id", "production_usable", "activation"})
_PAYLOAD_KEYS: Final[dict[str, frozenset[str]]] = {
    "APPLIED": frozenset({"operation_digest", "queue_view_digest", "acceptance_digest", "artifact_digest", "state_receipt_digest", "envelope_digest", "outbox_operation_id", "idempotency_key", "policy_result", "effective_directive", "payment_root_unchanged", "settlement_id", "settlement_domain", "exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until", "queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id", "batch_member_index", "batch_member_count"}),
    "HELD": frozenset({"acceptance_digest", "error_code"}),
    "DISPATCH_LEASED": frozenset({"attempt", "worker_id", "lease_token_digest", "lease_expires_ms"}),
    "DISPATCH_RELEASED": frozenset({"attempt", "error_code"}),
    "DELIVERY_UNCONFIRMED": frozenset({"attempt", "error_code"}),
    "DISPATCH_LEASE_EXPIRED": frozenset({"attempt", "error_code"}),
    "DISPATCH_EXHAUSTED": frozenset({"attempt", "error_code"}),
    "RECONCILIATION_LEASED": frozenset({"attempt", "worker_id", "lease_token_digest", "lease_expires_ms"}),
    "RECONCILIATION_INDETERMINATE": frozenset({"attempt", "error_code"}),
    "RECONCILIATION_LEASE_EXPIRED": frozenset({"attempt", "error_code"}),
    "RECONCILIATION_EXHAUSTED": frozenset({"attempt", "error_code"}),
    "ACKNOWLEDGED": frozenset({"ack_digest", "acknowledgment_id", "qualification_receipt_digest", "profile_digest", "policy_result", "effective_directive"}),
    "ACKNOWLEDGED_BY_RECONCILIATION": frozenset({"ack_digest", "acknowledgment_id", "qualification_receipt_digest", "profile_digest", "policy_result", "effective_directive"}),
    "ACK_CONFLICT": frozenset({"candidate_ack_digest", "stored_ack_digest", "error_code"}),
}
_MAX_RECEIPT = 16 * 1024
_MAX_ENVELOPE = 16 * 1024
_MAX_ACK = 4096
_MAX_ID = 128
_CAP_BYTES = 5_000_000_000
_ACTIVE_PROCESS_LIMIT = 1
_ZERO_SUITE = bytes(64)
_CIRCUIT_ID = bytes.fromhex("0f9fefb8cf05cc4e7a6b9657878c05a37034736d193272e14981f97fdd5a4275")
_TABLES: Final[tuple[str, ...]] = ("composition_meta", "composition_transactions", "composition_events")
_META_COLUMNS: Final[tuple[str, ...]] = ("id", "schema_version", "composition_id", "config_json", "config_digest", "state_profile_identity", "state_bytes", "event_head", "next_event_sequence", "active_dispatch_count", "active_reconciliation_count", "state_id", "state_epoch", "state_sequence", "state_continuity_root", "state_clearance_root", "state_clearance_count", "state_replay_root", "payment_root", "settled_batch_count", "state_binding", "audit_head", "last_operation_digest", "proof_suite_id", "production_usable", "activation")
_TX_COLUMNS: Final[tuple[str, ...]] = ("transaction_id", "queue_job_id", "queue_operation_id", "queue_view_bytes", "queue_view_digest", "acceptance_bytes", "acceptance_digest", "artifact_digest", "request_id", "attempt_id", "decision_id", "operation_digest", "disposition_id", "status", "state_receipt_bytes", "state_receipt_digest", "applied_sequence", "envelope_bytes", "envelope_digest", "outbox_operation_id", "idempotency_key", "delivery_status", "dispatch_attempt", "reconciliation_attempt", "lease_kind", "lease_worker_id", "lease_token", "lease_started_ms", "lease_expires_ms", "next_eligible_ms", "acknowledgment_bytes", "acknowledgment_digest", "acknowledgment_id", "acknowledged_ms", "ack_profile_digest", "qualification_receipt", "error_code", "created_ms", "updated_ms")
_EVENT_COLUMNS: Final[tuple[str, ...]] = ("global_sequence", "job_id", "job_sequence", "event_kind", "operation_id", "request_id", "transaction_id", "before_state", "after_state", "previous_root", "event_root", "event_bytes", "event_digest", "receipt_digest", "at_ms")
_SCHEMA_OBJECT_SHA256: Final[dict[tuple[str, str], str]] = {
    ("index", "composition_lease_expiry_idx"): "22881485D41757F0989C7FB42F63043D0F596728E2075C7771A7A3E96D4F9D1A",
    ("index", "composition_ready_idx"): "BDF45078607B4A6FEEE78673E8490E61B333821182F7B6F72B21E87755DC465F",
    ("index", "composition_reconcile_idx"): "2566A7AEFC866A2FE14D7293826050A055723521BDFDAF875946684679AC0754",
    ("table", "composition_events"): "F99CCD99DAA601CE9F1EE96986CB51AC1B07F50AD59C4DD10CC8D39E2C9B0014",
    ("table", "composition_meta"): "6EC7E493076005AC8BDC054FF2202A0CCE06484AD2B04006BC0B4A52BE95FA19",
    ("table", "composition_transactions"): "27FC4228A0B4FA9697A4BCCAF5A401540DA0C93962D8985A0319AB7B6E648EAA",
    ("trigger", "composition_events_no_delete"): "311496EA8CCAB27F13AFA94F612EDA9248FDD5050ED597420EF221EAF381A760",
    ("trigger", "composition_events_no_update"): "B76F1683E16695920BEF69F8017D452D4E50E687E4379E9BE4545C6F9ECB39C1",
    ("trigger", "composition_meta_guard"): "035BBCE8476619DD34BBDF4E144E4D37B46AEFD25A992C133960A0AEAA1B17E4",
    ("trigger", "composition_meta_no_delete"): "93A01AECF5249D5A7C4F6DCAE345485A4FC43D1EA018495C0E5E8B9DD5C36AAA",
    ("trigger", "composition_transactions_guard"): "3AC519524005E4FC0FDB87F49C26D320F901308926381F284C47CAC6A07A096F",
    ("trigger", "composition_transactions_no_delete"): "E3AC5B2BBF54FB86391D87632C3AF46ECF3217A248D67C2306D86C2E86B5D9F1",
}
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/MATERIAL/v3\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/GENESIS/v3\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/HEAD/v3\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/EVENT/v3\x00"
_STATE_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/PROOF-OPERATION/v1\x00"
_STATE_REPLAY = b"BL/MINIMAL-CLEARANCE/PROOF-REPLAY/v1\x00"
_STATE_CLEARANCE = b"BL/MINIMAL-CLEARANCE/CLEARANCE-ROOT/v1\x00"
_STATE_BINDING = b"BL/MINIMAL-CLEARANCE/STATE-BINDING/v1\x00"
_STATE_GENESIS = b"BL/MINIMAL-CLEARANCE/GENESIS/v1\x00"
_STATE_AUDIT_EVENT = b"BL/MINIMAL-CLEARANCE/AUDIT-EVENT/v1\x00"
_STATE_AUDIT_HEAD = b"BL/MINIMAL-CLEARANCE/AUDIT-HEAD/v1\x00"
_STATE_RECEIPT = b"BL/MINIMAL-CLEARANCE/RECEIPT/v1\x00"
_SETTLEMENT_REFERENCE = b"BL/NATIVE-V3/MINIMAL-SETTLEMENT-REFERENCE/v2\x00"
_STATE_IDENTITY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/STATE-STORE-IDENTITY/v1\x00"
_ENVELOPE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ENVELOPE/v2\x00"
_ACK = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK/v2\x00"
_ACK_PROFILE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-PROFILE/v2\x00"
_ACK_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-RECEIPT/v2\x00"
_OUTBOX_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-OPERATION/v2\x00"
_IDEMPOTENCY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-IDEMPOTENCY/v2\x00"
_QUEUE_VIEW_SCHEMA = "BL/NATIVE-V3/MINIMAL-CLEARANCE/QUEUE-VIEW/v2"
_COMPOSITION_BATCH = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/BATCH/v1\x00"
_QUEUE_BATCH = b"BL/NATIVE-V3/VERIFICATION-QUEUE/ACCEPT-BATCH/v6\x00"
_NO_EXCEPTION: Final[bytes] = b"\xe0" + bytes(63)


def _fail(code: str) -> NoReturn:
    _raise_fixed(code)


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(); digest.update(domain)
    for part in parts:
        if type(part) is not bytes: _fail("binding_type")
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try: return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError): _raise_fixed("json")


def _hex(raw: bytes) -> str: return raw.hex().upper()


def _blob(value: Any, size: int, label: str, nullable: bool = False) -> bytes | None:
    if value is None and nullable: return None
    if type(value) is not str: _fail(label)
    try: raw = bytes.fromhex(value)
    except ValueError: _raise_fixed(label)
    if len(raw) != size: _fail(label)
    return raw


def _u64(value: int) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**64: _fail("integer")
    return value.to_bytes(8, "big")


def _fixed_ascii(value: str) -> bytes:
    if type(value) is not str: _fail("identifier")
    try: encoded = value.encode("ascii")
    except UnicodeEncodeError: _raise_fixed("identifier_ascii")
    if len(encoded) > _MAX_ID: _fail("identifier_width")
    return len(encoded).to_bytes(2, "big") + encoded + bytes(_MAX_ID - len(encoded))


def _private_identity(label: str) -> bytes: return _sha(b"BL/NATIVE-V3/PRIVATE-ZK/IDENTITY/v1\x00", label.encode("ascii"))
_PRIVATE_CONTEXT = _private_identity("database-context.v1")
_PRIVATE_SCHEMA = _private_identity("database-schema.v1")
_PRIVATE_PROGRAM = _private_identity("database-program.v1")
_PRIVATE_MODE = _private_identity("mode.PRIVATE_ZK.v1")
_INITIAL_PAYMENT = _private_identity("payment-genesis.v1")
_INITIAL_CLEARANCE = _private_identity("clearance-genesis.v1")


def _profile_digest(statement: Any, verifier: bytes) -> bytes:
    return _sha(b"BL/NATIVE-V3/PRIVATE-ZK/PROFILE/v6\x00", _PRIVATE_MODE, _PRIVATE_CONTEXT, _PRIVATE_SCHEMA, _PRIVATE_PROGRAM, bytes(statement.get("proof_role")), bytes(statement.get("execution_context")), bytes(statement.get("source_registry_snapshot")), bytes(statement.get("source_profile")), bytes(statement.get("governance_snapshot")), bytes(statement.get("automatic_control_set")), bytes(statement.get("evaluator_id")), bytes(statement.get("schema_id")), bytes(statement.get("program_id")), bytes(statement.get("policy_id")), bytes(statement.get("rule_id")), _CIRCUIT_ID, verifier, _ZERO_SUITE, _u64(7))


def _state_identity(statement: Any, verifier: bytes) -> bytes:
    return _sha(_STATE_IDENTITY, _PRIVATE_CONTEXT, _PRIVATE_SCHEMA, _PRIVATE_PROGRAM, _PRIVATE_MODE, _CIRCUIT_ID, _profile_digest(statement, verifier), verifier)


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT: _fail("receipt_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed("receipt_encoding")
    required = {"operation_digest", "artifact_sha256", "artifact_digest", "statement_digest", "circuit_id", "bundle_id", "receipt_id", "join_id", "settlement_id", "settlement_domain", "request_id", "attempt_id", "decision_id", "sequence_before", "sequence_after", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "clearance_count_before", "clearance_count_after", "payment_root_before", "payment_root_after", "settled_batch_count_before", "settled_batch_count_after", "state_binding_after", "audit_head_after", "policy_result", "effective_directive", "exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until", "proof_session_accepted", "economic_mutation", "proof_suite_id", "queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id", "batch_member_index", "batch_member_count"}
    if type(value) is not dict or raw != _json_bytes(value) or set(value) != required: _fail("receipt_keys")
    for name in ("operation_digest", "artifact_digest", "statement_digest", "bundle_id", "receipt_id", "join_id", "settlement_id", "settlement_domain", "request_id", "attempt_id", "decision_id", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "payment_root_before", "payment_root_after", "state_binding_after", "audit_head_after", "exception_authorization_id", "exception_scope_id", "queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id"): _blob(value[name], 64, "receipt_" + name)
    _blob(value["artifact_sha256"], 32, "receipt_artifact_sha256"); _blob(value["circuit_id"], 32, "receipt_circuit")
    for name in ("sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after", "settled_batch_count_before", "settled_batch_count_after"):
        if type(value[name]) is not int or value[name] < 0: _fail("receipt_integer")
    if type(value["policy_result"]) is not int or not 1 <= value["policy_result"] <= 5 or type(value["effective_directive"]) is not int or not 1 <= value["effective_directive"] <= 5: _fail("receipt_directive")
    if type(value["exception_valid_from"]) is not int or value["exception_valid_from"] < 0 or type(value["exception_valid_until"]) is not int or value["exception_valid_until"] < 0: _fail("receipt_exception_interval")
    if type(value["batch_member_index"]) is not int or type(value["batch_member_count"]) is not int or not 1 <= value["batch_member_count"] <= 256 or not 0 <= value["batch_member_index"] < value["batch_member_count"]: _fail("receipt_batch")
    if int(value["effective_directive"]) != 5 and (value["exception_authorization_id"] != _hex(_NO_EXCEPTION) or value["exception_scope_id"] != _hex(_NO_EXCEPTION) or value["exception_valid_from"] != 0 or value["exception_valid_until"] != 0): _fail("receipt_exception_sentinel")
    if value["proof_session_accepted"] is not True or value["economic_mutation"] is not False or value["proof_suite_id"] is not None: _fail("receipt_nonactivation")
    return value


def _parse_envelope(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ENVELOPE: _fail("envelope_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed("envelope_encoding")
    keys = {"schema", "composition_config_digest", "composition_id_digest", "receiver_identity", "receiver_epoch", "verifier_epoch", "ack_evidence_profile_digest", "job_id_digest", "operation_id", "disposition_digest", "state_store_identity", "state_receipt_digest", "request_id", "attempt_id", "decision_id", "receipt_id", "settlement_id", "settlement_domain", "state_after_id", "state_binding_after", "audit_head_after", "policy_result", "effective_directive", "exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until", "proof_session_accepted", "proof_acceptance_is_clear", "payment_root_unchanged", "settled_batch_count_unchanged", "economic_mutation", "proof_suite_id"}
    if type(value) is not dict or set(value) != keys or raw != _json_bytes(value) or value["schema"] != _HANDOFF_SCHEMA: _fail("envelope_canonical")
    for name, size in (("composition_config_digest", 64), ("composition_id_digest", 64), ("receiver_identity", 32), ("ack_evidence_profile_digest", 64), ("job_id_digest", 64), ("operation_id", 64), ("disposition_digest", 64), ("state_store_identity", 64), ("state_receipt_digest", 64), ("request_id", 64), ("attempt_id", 64), ("decision_id", 64), ("receipt_id", 64), ("settlement_id", 64), ("settlement_domain", 64), ("state_after_id", 64), ("state_binding_after", 64), ("audit_head_after", 64), ("exception_authorization_id", 64), ("exception_scope_id", 64)): _blob(value[name], size, "envelope_" + name)
    for name in ("receiver_epoch", "verifier_epoch", "policy_result", "effective_directive"):
        if type(value[name]) is not int or value[name] < 1: _fail("envelope_integer")
    if type(value["exception_valid_from"]) is not int or value["exception_valid_from"] < 0 or type(value["exception_valid_until"]) is not int or value["exception_valid_until"] < 0: _fail("envelope_exception_interval")
    if int(value["effective_directive"]) != 5 and (value["exception_authorization_id"] != _hex(_NO_EXCEPTION) or value["exception_scope_id"] != _hex(_NO_EXCEPTION) or value["exception_valid_from"] != 0 or value["exception_valid_until"] != 0): _fail("envelope_exception_sentinel")
    if value["proof_session_accepted"] is not True or value["proof_acceptance_is_clear"] is not False or value["payment_root_unchanged"] is not True or value["settled_batch_count_unchanged"] is not True or value["economic_mutation"] is not False or value["proof_suite_id"] is not None: _fail("envelope_nonactivation")
    return value


def _parse_ack(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ACK: _fail("ack_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed("ack_encoding")
    keys = {"schema", "receiver_identity", "receiver_epoch", "verifier_identity", "verifier_epoch", "profile_digest", "idempotency_key", "envelope_digest", "effective_directive", "accepted_ms", "acknowledgment_id"}
    if type(value) is not dict or set(value) not in (keys, keys | {"policy_result"}) or raw != _json_bytes(value) or value["schema"] != _HANDOFF_SCHEMA: _fail("ack_canonical")
    _blob(value["receiver_identity"], 32, "ack_receiver"); _blob(value["verifier_identity"], 32, "ack_verifier"); _blob(value["profile_digest"], 64, "ack_profile"); _blob(value["idempotency_key"], 64, "ack_idempotency"); _blob(value["envelope_digest"], 64, "ack_envelope"); _blob(value["acknowledgment_id"], 64, "ack_id")
    if type(value["receiver_epoch"]) is not int or value["receiver_epoch"] < 1 or type(value["verifier_epoch"]) is not int or value["verifier_epoch"] < 1 or type(value["accepted_ms"]) is not int or value["accepted_ms"] < 0 or type(value["effective_directive"]) is not int or not 1 <= value["effective_directive"] <= 5: _fail("ack_values")
    if "policy_result" in value and (type(value["policy_result"]) is not int or not 1 <= value["policy_result"] <= 5): _fail("ack_policy")
    return value


def _parse_qualification(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT: _fail("qualification_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed("qualification_encoding")
    keys = {"schema_version", "mode", "profile_digest", "verifier_identity", "verifier_epoch", "receiver_identity", "receiver_epoch", "operation_id", "job_id_digest", "idempotency_key", "envelope_digest", "ack_digest", "acknowledgment_id", "policy_result", "effective_directive", "proof_suite_id", "production_usable", "activation", "attempt", "lease_kind", "lease_token_digest"}
    if type(value) is not dict or set(value) != keys or raw != _json_bytes(value) or value["schema_version"] != 2 or value["mode"] != _ACK_MODE: _fail("qualification_canonical")
    for name in ("profile_digest", "operation_id", "job_id_digest", "idempotency_key", "envelope_digest", "ack_digest", "acknowledgment_id", "lease_token_digest"): _blob(value[name], 64, "qualification_" + name)
    _blob(value["verifier_identity"], 32, "qualification_verifier"); _blob(value["receiver_identity"], 32, "qualification_receiver")
    for name in ("verifier_epoch", "receiver_epoch", "policy_result", "effective_directive", "attempt"):
        if type(value[name]) is not int or not 1 <= value[name] <= 2**63: _fail("qualification_integer")
    if value["lease_kind"] not in ("DISPATCH", "RECONCILIATION"): _fail("qualification_lease_kind")
    if value["policy_result"] > 5 or value["effective_directive"] > 5 or value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False: _fail("qualification_nonactivation")
    return value


def _parse_queue_view(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw: _fail("queue_view_bounds")
    try: value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed("queue_view_encoding")
    keys = {"schema", "queue_id", "config_digest", "verifier_sha256", "job_id", "operation_id", "attempt", "artifact_bytes", "artifact_sha256", "artifact_sha3_512", "circuit_id", "peak_job_commit_bytes", "cap_bytes", "cap_enforced", "active_process_limit", "timed_out", "exit_code", "queue_batch_id", "queue_batch_member_set_digest", "queue_batch_pre_head_root", "queue_batch_post_head_root", "queue_batch_pre_transition_count", "queue_batch_member_index", "queue_batch_member_count", "composition_batch_id"}
    if type(value) is not dict or set(value) != keys or raw != _json_bytes(value) or value["schema"] != _QUEUE_VIEW_SCHEMA: _fail("queue_view_schema")
    for name, size in (("config_digest", 64), ("verifier_sha256", 32), ("operation_id", 64), ("artifact_sha256", 32), ("artifact_sha3_512", 64), ("circuit_id", 32)): _blob(value[name], size, "queue_view_" + name)
    for name in ("queue_batch_id", "queue_batch_member_set_digest", "queue_batch_pre_head_root", "queue_batch_post_head_root", "composition_batch_id"): _blob(value[name], 64, "queue_view_" + name)
    for name in ("queue_id", "job_id"):
        if type(value[name]) is not str or not 0 < len(value[name]) <= _MAX_ID: _fail("queue_view_identifier")
    if type(value["attempt"]) is not int or value["attempt"] < 1 or type(value["artifact_bytes"]) is not int or value["artifact_bytes"] <= 0 or type(value["peak_job_commit_bytes"]) is not int or not 0 <= value["peak_job_commit_bytes"] <= _CAP_BYTES or value["cap_bytes"] != _CAP_BYTES or value["cap_enforced"] is not True or value["active_process_limit"] != _ACTIVE_PROCESS_LIMIT or value["timed_out"] is not False or value["exit_code"] != 0: _fail("queue_view_containment")
    if type(value["queue_batch_pre_transition_count"]) is not int or value["queue_batch_pre_transition_count"] < 0 or type(value["queue_batch_member_index"]) is not int or not 0 <= value["queue_batch_member_index"] < 256 or type(value["queue_batch_member_count"]) is not int or not 1 <= value["queue_batch_member_count"] <= 256 or value["queue_batch_member_index"] >= value["queue_batch_member_count"]: _fail("queue_view_batch")
    return value


def _composition_batch_id(config_digest: bytes, view: Mapping[str, Any], operation_ids: tuple[bytes, ...]) -> bytes:
    if len(operation_ids) != int(view["queue_batch_member_count"]): _fail("composition_batch_members")
    return _sha(_COMPOSITION_BATCH, config_digest, bytes.fromhex(str(view["queue_batch_id"])), bytes.fromhex(str(view["queue_batch_member_set_digest"])), bytes.fromhex(str(view["queue_batch_pre_head_root"])), bytes.fromhex(str(view["queue_batch_post_head_root"])), _u64(int(view["queue_batch_pre_transition_count"])), _u64(int(view["queue_batch_member_count"])), b"".join(operation_ids))


def _verify_config(config: Any) -> tuple[bytes, bytes]:
    if type(config) is not dict or set(config) != _CONFIG_KEYS or config.get("schema_version") != _SCHEMA_VERSION or config.get("proof_suite_id") is not None or config.get("production_usable") is not False or config.get("activation") is not False or tuple(config.get("directives", ())) != _DIRECTIVES: _fail("config")
    for name in ("queue_id", "composition_id"):
        if type(config.get(name)) is not str or not 1 <= len(config[name]) <= _MAX_ID or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for char in config[name]): _fail("config_identifier")
    try:
        canonical = _json_bytes(config); digest = _sha(_MATERIAL, canonical); queue_digest = bytes.fromhex(str(config["queue_config_digest"])); verifier = bytes.fromhex(str(config["verifier_sha256"])); receiver = bytes.fromhex(str(config["receiver_identity"])); profile = bytes.fromhex(str(config["ack_evidence_profile_digest"]))
    except (KeyError, ValueError): _raise_fixed("config_fields")
    if len(queue_digest) != 64 or len(verifier) != 32 or len(receiver) != 32 or len(profile) != 64: _fail("config_width")
    if type(config.get("receiver_epoch")) is not int or not 1 <= config["receiver_epoch"] < 2**63 or type(config.get("verifier_epoch")) is not int or not 1 <= config["verifier_epoch"] < 2**63: _fail("config_epoch")
    for name, maximum in (("capacity", 10_000), ("reconciliation_capacity", 10_000), ("lease_seconds", 3_600), ("reconciliation_lease_seconds", 3_600)):
        if type(config.get(name)) is not int or not 1 <= config[name] <= maximum: _fail("config_capacity")
    if config.get("max_attempts") != 3 or config.get("busy_timeout_ms") != 5_000: _fail("config_fixed")
    expected_profile = _sha(_ACK_PROFILE, _json_bytes({"schema_version": 2, "mode": _ACK_MODE, "verifier_identity": _hex(verifier), "verifier_epoch": int(config["verifier_epoch"]), "receiver_identity": _hex(receiver), "receiver_epoch": int(config["receiver_epoch"]), "proof_suite_id": None, "production_usable": False, "activation": False}))
    if profile != expected_profile: _fail("config_profile")
    return digest, profile


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall())


def _schema_inventory(connection: sqlite3.Connection) -> None:
    actual: dict[tuple[str, str], str] = {}
    for kind, name, sql in connection.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"):
        if type(sql) is not str: _fail("schema_sql")
        normalized = re.sub(r"\s+", " ", sql.strip().lower()).encode("utf-8")
        actual[(str(kind), str(name))] = hashlib.sha256(normalized).hexdigest().upper()
    if actual != _SCHEMA_OBJECT_SHA256: _fail("database_inventory")


def _state_expected(statement: Any, verifier: bytes) -> tuple[Any, ...]:
    continuity, audit = bytes(statement.state("before_continuity_root")), bytes(statement.state("before_audit_head"))
    clearance, replay = _sha(_STATE_GENESIS, statement.state_before_id, _INITIAL_CLEARANCE), _sha(_STATE_GENESIS, statement.attempt_id, statement.request_id)
    predecessor = bytes(statement.get("predecessor_state_bytes"))
    binding = _sha(_STATE_BINDING, predecessor, statement.state_before_id, _u64(statement.epoch), _u64(statement.sequence_before), continuity, clearance, replay, _INITIAL_PAYMENT, _u64(0), verifier, _profile_digest(statement, verifier))
    return (bytes(statement.state_before_id), int(statement.epoch), int(statement.sequence_before), continuity, clearance, int(statement.state("clearance_count_before")), replay, _INITIAL_PAYMENT, 0, binding, audit, None)


def _exception_fields(acceptance: Any) -> tuple[bytes, bytes, int, int]:
    statement = acceptance.statement
    if int(acceptance.effective_directive) != 5:
        return _NO_EXCEPTION, _NO_EXCEPTION, 0, 0
    authorization, scope = bytes(statement.get("exception_id")), bytes(statement.get("exception_scope_id"))
    valid_from, valid_until = int(statement.state("exception_valid_from")), int(statement.state("exception_valid_until"))
    if authorization == _NO_EXCEPTION or scope == _NO_EXCEPTION or not valid_from < valid_until: _fail("exception_authorization")
    return authorization, scope, valid_from, valid_until


def _expected_audit(previous: bytes, decision_id: bytes, effective: int) -> bytes:
    return _sha(b"BL/NATIVE-V3/MINIMAL-AUDIT-HEAD/v1\x00", previous, decision_id, bytes((effective,)))


def _event_error(value: Any) -> None:
    if type(value) is not str or not 1 <= len(value) <= 96 or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in value): _fail("event_error_code")


def _event_payload(kind: str, payload: Any, tx: tuple[Any, ...], config: Mapping[str, Any], profile: bytes) -> None:
    if type(payload) is not dict or set(payload) != _PAYLOAD_KEYS[kind]: _fail("event_payload")
    if kind == "APPLIED":
        for name in ("operation_digest", "queue_view_digest", "acceptance_digest", "artifact_digest", "state_receipt_digest", "envelope_digest", "outbox_operation_id", "idempotency_key", "settlement_id", "settlement_domain", "exception_authorization_id", "exception_scope_id", "queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id"): _blob(payload[name], 64, "event_" + name)
        for name in ("policy_result", "effective_directive"):
            if type(payload[name]) is not int or not 1 <= payload[name] <= 5: _fail("event_directive")
        if type(payload["batch_member_index"]) is not int or type(payload["batch_member_count"]) is not int or not 1 <= payload["batch_member_count"] <= 256 or not 0 <= payload["batch_member_index"] < payload["batch_member_count"]: _fail("event_batch")
        if payload["payment_root_unchanged"] is not True: _fail("event_economic")
        receipt = _parse_receipt(bytes(tx[14]))
        if payload["operation_digest"] != _hex(bytes(tx[11])) or payload["queue_view_digest"] != _hex(bytes(tx[4])) or payload["acceptance_digest"] != _hex(bytes(tx[6])) or payload["artifact_digest"] != _hex(bytes(tx[7])) or payload["state_receipt_digest"] != _hex(bytes(tx[15])) or payload["envelope_digest"] != _hex(bytes(tx[18])) or payload["outbox_operation_id"] != _hex(bytes(tx[19])) or payload["idempotency_key"] != _hex(bytes(tx[20])) or payload["settlement_id"] != receipt["settlement_id"] or payload["settlement_domain"] != receipt["settlement_domain"] or payload["policy_result"] != int(receipt["policy_result"]) or payload["effective_directive"] != int(receipt["effective_directive"]) or any(payload[name] != receipt[name] for name in ("queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id", "batch_member_index", "batch_member_count")): _fail("applied_event_binding")
        for name in ("exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until"):
            if payload[name] != receipt[name]: _fail("applied_exception_binding")
    elif kind == "HELD":
        _blob(payload["acceptance_digest"], 64, "event_acceptance_digest"); _event_error(payload["error_code"])
        if payload["acceptance_digest"] != _hex(bytes(tx[6])) or tx[13] != "HELD": _fail("held_event_binding")
    elif kind in {"DISPATCH_LEASED", "RECONCILIATION_LEASED"}:
        if type(payload["attempt"]) is not int or not 1 <= payload["attempt"] <= 2**63 or type(payload["worker_id"]) is not str or not 1 <= len(payload["worker_id"]) <= _MAX_ID or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for char in payload["worker_id"]): _fail("lease_event_binding")
        _blob(payload["lease_token_digest"], 64, "event_lease_token_digest")
        if type(payload["lease_expires_ms"]) is not int or payload["lease_expires_ms"] < 1 or payload["attempt"] > int(tx[22] if kind == "DISPATCH_LEASED" else tx[23]): _fail("lease_event_binding")
    elif kind in {"DISPATCH_RELEASED", "DELIVERY_UNCONFIRMED", "DISPATCH_LEASE_EXPIRED", "DISPATCH_EXHAUSTED", "RECONCILIATION_INDETERMINATE", "RECONCILIATION_LEASE_EXPIRED", "RECONCILIATION_EXHAUSTED"}:
        if type(payload["attempt"]) is not int or not 1 <= payload["attempt"] <= 2**63 or payload["attempt"] > int(tx[22] if kind.startswith("DISPATCH") or kind == "DELIVERY_UNCONFIRMED" else tx[23]): _fail("lease_event_binding")
        _event_error(payload["error_code"])
    elif kind in {"ACKNOWLEDGED", "ACKNOWLEDGED_BY_RECONCILIATION"}:
        _blob(payload["ack_digest"], 64, "event_ack_digest"); _blob(payload["qualification_receipt_digest"], 64, "event_qualification_digest"); _blob(payload["profile_digest"], 64, "event_profile_digest")
        if type(payload["acknowledgment_id"]) is not str or len(payload["acknowledgment_id"]) != 128 or type(payload["policy_result"]) is not int or not 1 <= payload["policy_result"] <= 5 or type(payload["effective_directive"]) is not int or not 1 <= payload["effective_directive"] <= 5: _fail("ack_event_binding")
        receipt = _parse_receipt(bytes(tx[14]))
        if tx[21] != "ACKNOWLEDGED" or payload["ack_digest"] != _hex(bytes(tx[31])) or payload["acknowledgment_id"] != str(tx[32]) or payload["profile_digest"] != _hex(profile) or payload["qualification_receipt_digest"] != _hex(_sha(_MATERIAL, bytes(tx[35]))) or payload["policy_result"] != int(receipt["policy_result"]) or payload["effective_directive"] != int(receipt["effective_directive"]): _fail("ack_event_binding")
    elif kind == "ACK_CONFLICT":
        _blob(payload["candidate_ack_digest"], 64, "event_candidate_ack_digest"); _blob(payload["stored_ack_digest"], 64, "event_stored_ack_digest"); _event_error(payload["error_code"])
        if payload["stored_ack_digest"] != _hex(bytes(tx[31])) or payload["candidate_ack_digest"] == payload["stored_ack_digest"] or payload["error_code"] != "ack_conflict" or tx[21] != "ACKNOWLEDGED": _fail("ack_conflict_event")


def _verify_rows(connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    names = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if names != set(_TABLES): _fail("database_tables")
    indexes = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")}
    triggers = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    if indexes != {"composition_ready_idx", "composition_reconcile_idx", "composition_lease_expiry_idx"} or triggers != {"composition_meta_no_delete", "composition_meta_guard", "composition_transactions_no_delete", "composition_transactions_guard", "composition_events_no_update", "composition_events_no_delete"}: _fail("database_inventory")
    _schema_inventory(connection)
    if _columns(connection, "composition_meta") != _META_COLUMNS or _columns(connection, "composition_transactions") != _TX_COLUMNS or _columns(connection, "composition_events") != _EVENT_COLUMNS: _fail("declared_schema")
    meta = connection.execute("SELECT * FROM composition_meta WHERE id=1").fetchone()
    if meta is None or len(meta) != len(_META_COLUMNS): _fail("meta_missing")
    meta = tuple(meta); config_raw = bytes(meta[3])
    try: config = json.loads(config_raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed("config_encoding")
    if raw := _json_bytes(config):
        if raw != config_raw: _fail("config_canonical")
    config_digest, profile = _verify_config(config)
    if expected_config is not None and _json_bytes(config) != _json_bytes(dict(expected_config)): _fail("config_substitution")
    if int(meta[1]) != _SCHEMA_VERSION or bytes(meta[4]) != config_digest or str(meta[2]) != config["composition_id"] or meta[23] is not None or meta[24] != 0 or meta[25] != 0: _fail("meta_binding")
    if type(meta[7]) is not bytes or len(meta[7]) != 64 or type(meta[8]) is not int or meta[8] < 0: _fail("meta_head")
    state = meta[11:23]
    if meta[11] is None and any(x is not None for x in state): _fail("state_partial")
    if meta[11] is not None and any(x is None for x in meta[11:22]): _fail("state_partial")
    if meta[11] is not None and (bytes(meta[18]) != _INITIAL_PAYMENT or int(meta[19]) != 0): _fail("economic_sentinel")
    for index, size in ((5, 64), (7, 64), (14, 64), (15, 64), (17, 64), (18, 64), (20, 64), (21, 64), (22, 64)):
        if meta[index] is not None and (type(meta[index]) is not bytes or len(meta[index]) != size): _fail("meta_blob")
    if meta[6] is not None and (type(meta[6]) is not bytes or len(meta[6]) != 1686): _fail("meta_state_bytes")
    tx_rows = [tuple(row) for row in connection.execute("SELECT * FROM composition_transactions ORDER BY created_ms,queue_job_id").fetchall()]
    event_rows = [tuple(row) for row in connection.execute("SELECT * FROM composition_events ORDER BY global_sequence").fetchall()]
    by_id = {bytes(row[0]): row for row in tx_rows}
    if len(by_id) != len(tx_rows): _fail("transaction_identity")
    applied = [row for row in tx_rows if row[13] == "APPLIED"]
    ordered_tx_rows = sorted(tx_rows, key=lambda row: (0 if row[13] == "APPLIED" else 1, -1 if row[16] is None else int(row[16]), str(row[1])))
    current: tuple[Any, ...] | None = None
    current_state_bytes: bytes | None = None
    batch_groups: dict[bytes, list[tuple[int, bytes, dict[str, Any], tuple[Any, ...]]]] = {}
    applied_sequence = 0
    for tx in ordered_tx_rows:
        if len(tx) != len(_TX_COLUMNS): _fail("transaction_shape")
        if type(tx[1]) is not str or not tx[1] or type(tx[2]) is not bytes or len(tx[2]) != 64 or type(tx[3]) is not bytes or type(tx[5]) is not bytes: _fail("transaction_identity")
        view = _parse_queue_view(bytes(tx[3]))
        if view["job_id"] != tx[1] or bytes.fromhex(view["operation_id"]) != bytes(tx[2]) or bytes(tx[4]) != _sha(_MATERIAL, b"queue-view", bytes(tx[3])): _fail("queue_view_binding")
        batch_groups.setdefault(bytes.fromhex(str(view["composition_batch_id"])), []).append((int(view["queue_batch_member_index"]), bytes(tx[2]), view, tx))
        try: acceptance = parse_acceptance_bytes(bytes(tx[5]))
        except Exception: _raise_fixed("acceptance_binding")
        if bytes(tx[6]) != _sha(_MATERIAL, b"acceptance", bytes(tx[5])) or acceptance.artifact_digest != bytes(tx[7]) or acceptance.artifact_sha256 != bytes.fromhex(str(view["artifact_sha256"])) or acceptance.artifact_digest != bytes.fromhex(str(view["artifact_sha3_512"])) or acceptance.circuit_id != bytes.fromhex(str(view["circuit_id"])) or int(view["artifact_bytes"]) != int(acceptance.artifact_bytes) or bytes(tx[8]) != acceptance.statement.request_id or bytes(tx[9]) != acceptance.statement.attempt_id or bytes(tx[10]) != acceptance.statement.decision_id: _fail("transaction_acceptance")
        operation_digest = _sha(_STATE_OPERATION, bytes(tx[5]), bytes(acceptance.statement.state_before_id), bytes(acceptance.statement.attempt_id), bytes.fromhex(str(config["verifier_sha256"])))
        if bytes(tx[11]) != operation_digest or bytes(tx[12]) != _sha(_MATERIAL, b"disposition", str(tx[1]).encode("ascii"), bytes(tx[2]), bytes(tx[6])) or bytes(tx[0]) != _sha(_MATERIAL, b"transaction", bytes(tx[12])): _fail("transaction_operation")
        if tx[13] not in {"HELD", "APPLIED"}: _fail("transaction_status")
        if tx[13] == "HELD":
            if any(tx[index] is not None for index in (14, 15, 16, 17, 18, 19, 20, 21, 24, 25, 26, 27, 28, 30, 31, 32, 33, 34, 35)) or tx[22] != 0 or tx[23] != 0: _fail("held_shape")
            continue
        if any(tx[index] is None for index in (14, 15, 16, 17, 18, 19, 20, 21, 29, 37, 38)) or tx[21] not in _DELIVERY_STATES: _fail("applied_shape")
        receipt = _parse_receipt(bytes(tx[14]))
        exception_fields = _exception_fields(acceptance)
        settlement_domain = bytes(acceptance.statement.get("settlement_domain"))
        expected_settlement = _sha(_SETTLEMENT_REFERENCE, settlement_domain, bytes((int(acceptance.effective_directive),)), bytes(acceptance.statement.decision_id), bytes(acceptance.statement.state_after_id), bytes(acceptance.statement.state("authorized_payment_commitment")))
        if bytes(tx[15]) != _sha(_STATE_RECEIPT, bytes(tx[14])) or bytes.fromhex(receipt["operation_digest"]) != bytes(tx[11]) or bytes.fromhex(receipt["artifact_digest"]) != bytes(tx[7]) or bytes.fromhex(receipt["request_id"]) != bytes(tx[8]) or bytes.fromhex(receipt["attempt_id"]) != bytes(tx[9]) or bytes.fromhex(receipt["decision_id"]) != bytes(tx[10]) or bytes.fromhex(receipt["settlement_domain"]) != settlement_domain or bytes.fromhex(receipt["settlement_id"]) != expected_settlement or (bytes.fromhex(receipt["exception_authorization_id"]), bytes.fromhex(receipt["exception_scope_id"]), int(receipt["exception_valid_from"]), int(receipt["exception_valid_until"])) != exception_fields or receipt["queue_batch_id"] != view["queue_batch_id"] or receipt["queue_batch_member_set_digest"] != view["queue_batch_member_set_digest"] or receipt["composition_batch_id"] != view["composition_batch_id"] or receipt["batch_member_index"] != view["queue_batch_member_index"] or receipt["batch_member_count"] != view["queue_batch_member_count"]: _fail("receipt_binding")
        predecessor = bytes(acceptance.statement.get("predecessor_state_bytes"))
        if current is None:
            current = _state_expected(acceptance.statement, bytes.fromhex(str(config["verifier_sha256"])))
            current_state_bytes = predecessor
        if current_state_bytes != predecessor: _fail("state_predecessor_bytes")
        if current[0] != bytes.fromhex(receipt["state_before_id"]) or current[2] != int(receipt["sequence_before"]) or current[4] != bytes.fromhex(receipt["clearance_root_before"]) or current[5] != int(receipt["clearance_count_before"]): _fail("state_before")
        sequence_after = int(current[2]) + 1
        if int(receipt["sequence_after"]) != sequence_after: _fail("receipt_sequence")
        advanced = int(acceptance.statement.directive) in (1, 5)
        clearance_after = _sha(_STATE_CLEARANCE, bytes(current[4]), acceptance.statement.state_after_id, acceptance.statement.decision_id, bytes((int(acceptance.statement.directive),))) if advanced else bytes(current[4])
        count_after = int(current[5]) + int(advanced)
        replay_after = _sha(_STATE_REPLAY, bytes(current[6]), acceptance.statement.attempt_id, acceptance.statement.request_id, acceptance.statement.receipt_id)
        binding_after = _sha(_STATE_BINDING, bytes(current[9]), bytes(tx[11]), acceptance.statement.state_after_id, replay_after, clearance_after, _u64(count_after), bytes(current[7]), _u64(0), _u64(int(current[1])), _u64(sequence_after), bytes.fromhex(str(config["verifier_sha256"])), _profile_digest(acceptance.statement, bytes.fromhex(str(config["verifier_sha256"]))))
        audit_after = _expected_audit(bytes(current[10]), acceptance.statement.decision_id, int(acceptance.effective_directive))
        if bytes.fromhex(receipt["clearance_root_after"]) != clearance_after or int(receipt["clearance_count_after"]) != count_after or bytes.fromhex(receipt["state_binding_after"]) != binding_after or bytes.fromhex(receipt["audit_head_after"]) != audit_after or receipt["payment_root_before"] != _hex(_INITIAL_PAYMENT) or receipt["payment_root_after"] != _hex(_INITIAL_PAYMENT) or receipt["settled_batch_count_before"] != 0 or receipt["settled_batch_count_after"] != 0: _fail("receipt_state")
        envelope = _parse_envelope(bytes(tx[17]))
        if bytes(tx[18]) != _sha(_ENVELOPE, bytes(tx[17])) or bytes.fromhex(envelope["operation_id"]) != bytes(tx[2]) or bytes.fromhex(envelope["disposition_digest"]) != bytes(tx[12]) or bytes.fromhex(envelope["state_receipt_digest"]) != bytes(tx[15]) or bytes.fromhex(envelope["composition_config_digest"]) != config_digest or envelope["settlement_id"] != receipt["settlement_id"] or envelope["settlement_domain"] != receipt["settlement_domain"] or int(envelope["policy_result"]) != int(receipt["policy_result"]) or int(envelope["effective_directive"]) != int(receipt["effective_directive"]) or any(envelope[name] != receipt[name] for name in ("exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until")): _fail("envelope_binding")
        if bytes(tx[19]) != _sha(_OUTBOX_OPERATION, config_digest, _fixed_ascii(str(config["composition_id"])), _fixed_ascii(str(tx[1])), bytes(tx[18])) or bytes(tx[20]) != _sha(_IDEMPOTENCY, config_digest, _fixed_ascii(str(config["composition_id"])), _fixed_ascii(str(tx[1])), bytes(tx[18])): _fail("outbox_identity")
        if tx[21] == "ACKNOWLEDGED":
            if any(tx[index] is None for index in (30, 31, 32, 33, 34, 35)): _fail("ack_missing")
            ack = _parse_ack(bytes(tx[30])); qualification = _parse_qualification(bytes(tx[35]))
            if bytes(tx[31]) != _sha(_ACK, bytes(tx[30])) or bytes.fromhex(ack["envelope_digest"]) != bytes(tx[18]) or bytes.fromhex(ack["idempotency_key"]) != bytes(tx[20]) or bytes.fromhex(ack["receiver_identity"]) != bytes.fromhex(str(config["receiver_identity"])) or int(ack["receiver_epoch"]) != int(config["receiver_epoch"]) or bytes.fromhex(ack["verifier_identity"]) != bytes.fromhex(str(config["verifier_sha256"])) or int(ack["verifier_epoch"]) != int(config["verifier_epoch"]) or bytes.fromhex(ack["profile_digest"]) != profile or int(ack["effective_directive"]) != int(envelope["effective_directive"]) or ("policy_result" in ack and int(ack["policy_result"]) != int(envelope["policy_result"])) or str(ack["acknowledgment_id"]) != str(tx[32]) or bytes(tx[34]) != profile or bytes.fromhex(qualification["ack_digest"]) != bytes(tx[31]) or bytes.fromhex(qualification["profile_digest"]) != profile or bytes.fromhex(qualification["verifier_identity"]) != bytes.fromhex(str(config["verifier_sha256"])) or int(qualification["verifier_epoch"]) != int(config["verifier_epoch"]) or bytes.fromhex(qualification["receiver_identity"]) != bytes.fromhex(str(config["receiver_identity"])) or int(qualification["receiver_epoch"]) != int(config["receiver_epoch"]) or bytes.fromhex(qualification["operation_id"]) != bytes(tx[2]) or bytes.fromhex(qualification["job_id_digest"]) != _sha(_ACK_RECEIPT, str(tx[1]).encode("ascii")) or bytes.fromhex(qualification["idempotency_key"]) != bytes(tx[20]) or bytes.fromhex(qualification["envelope_digest"]) != bytes(tx[18]) or bytes.fromhex(qualification["acknowledgment_id"]) != bytes.fromhex(str(ack["acknowledgment_id"])) or int(qualification["policy_result"]) != int(envelope["policy_result"]) or int(qualification["effective_directive"]) != int(envelope["effective_directive"]) or qualification["lease_kind"] not in ("DISPATCH", "RECONCILIATION") or int(qualification["attempt"]) != int(tx[22] if qualification["lease_kind"] == "DISPATCH" else tx[23]): _fail("ack_binding")
        current = (bytes(acceptance.statement.state_after_id), int(acceptance.statement.epoch), sequence_after, bytes(acceptance.statement.state("after_continuity_root")), clearance_after, count_after, replay_after, _INITIAL_PAYMENT, 0, binding_after, audit_after, bytes(tx[11])); current_state_bytes = bytes(acceptance.statement.get("state_commitment_bytes")); applied_sequence += 1
        if int(tx[16]) != sequence_after: _fail("applied_sequence")
    for composition_batch_id, entries in batch_groups.items():
        first_view = entries[0][2]
        member_count = int(first_view["queue_batch_member_count"])
        if len(entries) != member_count or sorted(index for index, _operation_id, _view, _tx in entries) != list(range(member_count)): _fail("composition_batch_completeness")
        for _index, _operation_id, view, _tx in entries:
            if any(view[name] != first_view[name] for name in ("queue_batch_id", "queue_batch_member_set_digest", "queue_batch_pre_head_root", "queue_batch_post_head_root", "queue_batch_pre_transition_count", "queue_batch_member_count")): _fail("composition_batch_binding")
        ordered = tuple(operation_id for _index, operation_id, _view, _tx in sorted(entries, key=lambda item: item[0]))
        if _sha(_QUEUE_BATCH, b"".join(ordered)) != bytes.fromhex(str(first_view["queue_batch_member_set_digest"])) or _composition_batch_id(config_digest, first_view, ordered) != composition_batch_id: _fail("composition_batch_identity")
    applied_sequences = sorted(int(tx[16]) for tx in applied)
    if any(right != left + 1 for left, right in zip(applied_sequences, applied_sequences[1:])): _fail("applied_sequence_chain")
    if applied:
        first_applied = min(applied, key=lambda row: int(row[16]))
        first_acceptance = parse_acceptance_bytes(bytes(first_applied[5]))
        expected_identity = _state_identity(first_acceptance.statement, bytes.fromhex(str(config["verifier_sha256"])))
        if meta[5] != expected_identity or current_state_bytes is None or meta[6] != current_state_bytes: _fail("learned_state_profile")
        if current is None or tuple(meta[11:23]) != current: _fail("current_state")
    elif meta[5] is not None or meta[6] is not None: _fail("learned_state_without_apply")
    active_dispatch = sum(1 for tx in tx_rows if tx[13] == "APPLIED" and tx[21] not in {"ACKNOWLEDGED", "DISPATCH_EXHAUSTED", "RECONCILIATION_EXHAUSTED"})
    active_reconciliation = sum(1 for tx in tx_rows if tx[24] == "RECONCILIATION")
    if int(meta[9]) != active_dispatch or int(meta[10]) != active_reconciliation: _fail("active_counters")
    for tx in tx_rows:
        if tx[13] == "HELD": continue
        if tx[21] == "READY" and tx[24] is not None or tx[21] == "DISPATCH_LEASED" and tx[24] != "DISPATCH" or tx[21] == "DELIVERY_UNCONFIRMED" and tx[24] is not None or tx[21] == "RECONCILIATION_LEASED" and tx[24] != "RECONCILIATION" or tx[21] in {"ACKNOWLEDGED", "DISPATCH_EXHAUSTED", "RECONCILIATION_EXHAUSTED"} and tx[24] is not None: _fail("lease_state")
        if tx[24] is not None and any(tx[index] is None for index in (25, 26, 27, 28)): _fail("lease_shape")
    expected_head = _sha(_GENESIS, str(config["composition_id"]).encode("ascii"), config_digest)
    jobs: dict[str, list[int]] = {}
    job_events: dict[str, list[tuple[Any, ...]]] = {}
    for number, event in enumerate(event_rows, start=1):
        if len(event) != len(_EVENT_COLUMNS) or int(event[0]) != number or bytes(event[9]) != expected_head or event[3] not in _EVENT_KINDS or bytes(event[6]) not in by_id: _fail("event_chain")
        tx = by_id[bytes(event[6])]
        try: value = json.loads(bytes(event[11]).decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError): _raise_fixed("event_encoding")
        keys = {"event_kind", "global_sequence", "job_sequence", "job_id", "operation_id", "request_id", "transaction_id", "before_state", "after_state", "previous_root", "payload", "receipt_digest", "at_ms"}
        if type(value) is not dict or set(value) != keys or bytes(event[11]) != _json_bytes(value) or value["event_kind"] != event[3] or value["global_sequence"] != number or value["job_sequence"] != event[2] or value["job_id"] != event[1] or bytes.fromhex(value["operation_id"]) != bytes(event[4]) or bytes.fromhex(value["request_id"]) != bytes(event[5]) or bytes.fromhex(value["transaction_id"]) != bytes(event[6]) or value["before_state"] != event[7] or value["after_state"] != event[8] or bytes.fromhex(value["previous_root"]) != expected_head or (value["receipt_digest"] is None) != (event[13] is None) or value["at_ms"] != event[14] or set(value["payload"]) != _PAYLOAD_KEYS[event[3]]: _fail("event_binding")
        if str(event[1]) != str(tx[1]) or bytes(event[4]) != bytes(tx[2]) or bytes(event[5]) != bytes(tx[8]) or bytes(event[6]) != bytes(tx[0]): _fail("event_transaction_binding")
        _event_payload(str(event[3]), value["payload"], tx, config, profile)
        payload = value["payload"]
        if event[3] == "APPLIED":
            receipt = _parse_receipt(bytes(tx[14]))
            if payload["queue_view_digest"] != _hex(bytes(tx[4])) or payload["acceptance_digest"] != _hex(bytes(tx[6])) or payload["artifact_digest"] != _hex(bytes(tx[7])) or payload["state_receipt_digest"] != _hex(bytes(tx[15])) or payload["envelope_digest"] != _hex(bytes(tx[18])) or payload["outbox_operation_id"] != _hex(bytes(tx[19])) or payload["idempotency_key"] != _hex(bytes(tx[20])) or payload["operation_digest"] != _hex(bytes(tx[11])) or payload["policy_result"] != int(receipt["policy_result"]) or payload["effective_directive"] != int(receipt["effective_directive"]) or payload["payment_root_unchanged"] is not True or payload["settlement_id"] != receipt["settlement_id"] or payload["settlement_domain"] != receipt["settlement_domain"] or any(payload[name] != receipt[name] for name in ("exception_authorization_id", "exception_scope_id", "exception_valid_from", "exception_valid_until", "queue_batch_id", "queue_batch_member_set_digest", "composition_batch_id", "batch_member_index", "batch_member_count")): _fail("applied_event_binding")
        receipt_digest = None if event[13] is None else bytes(event[13])
        if event[3] in {"APPLIED", "ACKNOWLEDGED", "ACKNOWLEDGED_BY_RECONCILIATION", "ACK_CONFLICT"} and receipt_digest != bytes(tx[15]): _fail("event_receipt_binding")
        if event[3] not in {"APPLIED", "ACKNOWLEDGED", "ACKNOWLEDGED_BY_RECONCILIATION", "ACK_CONFLICT"} and receipt_digest is not None: _fail("event_receipt_binding")
        event_digest = _sha(_EVENT, _u64(number), _u64(int(event[2])), str(event[3]).encode("ascii"), _fixed_ascii(str(event[1])), bytes(event[4]), bytes(event[5]), bytes(event[6]), str(event[7]).encode("ascii"), str(event[8]).encode("ascii"), expected_head, bytes(event[11]), b"" if receipt_digest is None else receipt_digest)
        if bytes(event[12]) != event_digest or bytes(event[10]) != _sha(_HEAD, expected_head, _u64(number), event_digest): _fail("event_root")
        expected_head = bytes(event[10]); jobs.setdefault(str(event[1]), []).append(int(event[2]))
        job_events.setdefault(str(event[1]), []).append(event)
        if value["receipt_digest"] is not None and bytes.fromhex(value["receipt_digest"]) != receipt_digest: _fail("event_receipt")
    if int(meta[8]) != len(event_rows) or bytes(meta[7]) != expected_head or any(values != list(range(1, len(values) + 1)) for values in jobs.values()): _fail("event_head")
    legal: dict[str, dict[str, str]] = {
        "READY": {"DISPATCH_LEASED": "DISPATCH_LEASED", "DISPATCH_EXHAUSTED": "DISPATCH_EXHAUSTED"},
        "DISPATCH_LEASED": {"DISPATCH_RELEASED": "READY", "DISPATCH_EXHAUSTED": "DISPATCH_EXHAUSTED", "DELIVERY_UNCONFIRMED": "DELIVERY_UNCONFIRMED", "DISPATCH_LEASE_EXPIRED": "DELIVERY_UNCONFIRMED", "ACKNOWLEDGED": "ACKNOWLEDGED"},
        "DELIVERY_UNCONFIRMED": {"RECONCILIATION_LEASED": "RECONCILIATION_LEASED", "RECONCILIATION_EXHAUSTED": "RECONCILIATION_EXHAUSTED"},
        "RECONCILIATION_LEASED": {"RECONCILIATION_INDETERMINATE": "DELIVERY_UNCONFIRMED", "RECONCILIATION_LEASE_EXPIRED": "DELIVERY_UNCONFIRMED", "RECONCILIATION_EXHAUSTED": "RECONCILIATION_EXHAUSTED", "ACKNOWLEDGED_BY_RECONCILIATION": "ACKNOWLEDGED"},
        "ACKNOWLEDGED": {"ACK_CONFLICT": "ACKNOWLEDGED"},
    }
    for tx in tx_rows:
        events = job_events.get(str(tx[1]), [])
        if not events: _fail("transaction_event_missing")
        if tx[13] == "HELD":
            if len(events) != 1 or events[0][3] != "HELD" or events[0][7] != "NONE" or events[0][8] != "NONE": _fail("held_event")
            continue
        if events[0][3] != "APPLIED" or events[0][7] != "NONE" or events[0][8] != "READY": _fail("applied_event")
        state = "READY"
        for event in events[1:]:
            if event[7] != state or event[3] not in legal.get(state, {}) or legal[state][event[3]] != event[8]: _fail("event_transition")
            state = str(event[8])
        if state != tx[21]: _fail("event_terminal_state")
    counts = {status: sum(1 for tx in tx_rows if tx[21] == status) for status in sorted(_DELIVERY_STATES)}
    return {"schema": _SCHEMA, "composition_id": config["composition_id"], "config_digest": _hex(config_digest), "table_counts": {"composition_meta": 1, "composition_transactions": len(tx_rows), "composition_events": len(event_rows)}, "delivery_counts": counts, "proof_suite_id": None, "production_usable": False, "activation": False}


@_public
def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink(): _fail("database_path")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=5.0)
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",): _fail("database_integrity")
        return _verify_rows(connection, expected_config=expected_config)
    except sqlite3.Error:
        _raise_fixed("database_read")
    finally:
        if connection is not None: connection.close()


@_public
def verify_database_connection(connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(connection, sqlite3.Connection): _fail("connection")
    return _verify_rows(connection, expected_config=expected_config)


__all__ = ("IndependentCompositionError", "verify_database", "verify_database_connection")
