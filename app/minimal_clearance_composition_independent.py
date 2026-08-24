"""Independent reconstruction for the synthetic clearance composition V2.

This module deliberately does not import the composition producer, the native
verifier, the state store, the queue producer, or the settlement database.  It
parses a canonical export and reconstructs the small V2 SQLite checkpoint.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Final, Mapping

from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes


class IndependentCompositionError(RuntimeError):
    """Bounded independent reconstruction failure."""


_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v2"
_HANDOFF_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/v2"
_SCHEMA_VERSION: Final[int] = 2
_ACK_MODE: Final[str] = "SYNTHETIC_ONLY"
_MAX_EXPORT: Final[int] = 64 * 1024 * 1024
_MAX_RECEIPT: Final[int] = 16 * 1024
_MAX_ENVELOPE: Final[int] = 16 * 1024
_MAX_ACK: Final[int] = 4096
_MAX_ID: Final[int] = 128
_CAP_BYTES: Final[int] = 5_000_000_000
_ACTIVE_PROCESS_LIMIT: Final[int] = 1
_ZERO_SUITE = bytes(64)
_CIRCUIT_ID = bytes.fromhex("1eaaf14f3b23db1ed02f3c378099627767f81142e0114f90448cac7c1cc66be0")
_DIRECTIVES = ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED")
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/MATERIAL/v2\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/GENESIS/v2\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/HEAD/v2\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/EVENT/v2\x00"
_STATE_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/PROOF-OPERATION/v1\x00"
_STATE_REPLAY = b"BL/MINIMAL-CLEARANCE/PROOF-REPLAY/v1\x00"
_STATE_CLEARANCE = b"BL/MINIMAL-CLEARANCE/CLEARANCE-ROOT/v1\x00"
_STATE_BINDING = b"BL/MINIMAL-CLEARANCE/STATE-BINDING/v1\x00"
_STATE_GENESIS = b"BL/MINIMAL-CLEARANCE/GENESIS/v1\x00"
_STATE_AUDIT_EVENT = b"BL/MINIMAL-CLEARANCE/AUDIT-EVENT/v1\x00"
_STATE_AUDIT_HEAD = b"BL/MINIMAL-CLEARANCE/AUDIT-HEAD/v1\x00"
_STATE_RECEIPT = b"BL/MINIMAL-CLEARANCE/RECEIPT/v1\x00"
_STATE_IDENTITY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/STATE-STORE-IDENTITY/v1\x00"
_ENVELOPE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ENVELOPE/v2\x00"
_ACK = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK/v2\x00"
_ACK_PROFILE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-PROFILE/v2\x00"
_ACK_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-RECEIPT/v2\x00"
_OUTBOX_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-OPERATION/v2\x00"
_IDEMPOTENCY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-IDEMPOTENCY/v2\x00"

_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "composition_metadata": ("id", "schema_version", "composition_id", "config_json", "config_digest", "queue_id", "queue_config_digest", "verifier_sha256", "state_profile_identity", "receiver_identity", "receiver_epoch", "verifier_epoch", "ack_profile_digest", "expected_statement", "proof_suite_id", "production_usable", "activation", "head_root", "next_sequence"),
    "composition_state": ("id", "expected_statement", "circuit_id", "state_id", "epoch", "sequence", "continuity_root", "clearance_root", "clearance_count", "replay_root", "payment_root", "settled_batch_count", "state_binding", "audit_head", "last_operation_digest", "verifier_sha256", "profile_digest"),
    "composition_transitions": ("sequence", "transition_kind", "job_id", "before_root", "after_root", "event_bytes", "event_digest"),
    "proof_requests": ("operation_digest", "queue_job_id", "queue_operation_id", "queue_receipt_bytes", "queue_receipt_digest", "acceptance_bytes", "acceptance_digest", "receipt_bytes", "artifact_digest", "request_id", "attempt_id", "decision_id", "sequence_before", "sequence_after", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "clearance_count_before", "clearance_count_after", "state_binding_before", "state_binding_after", "audit_head_before", "audit_head_after", "policy_result", "effective_directive", "created_ms"),
    "proof_audit": ("sequence", "previous_head", "event_commitment", "current_head", "payload"),
    "proof_transitions": ("sequence_after", "operation_digest", "state_binding_before", "state_binding_after", "payment_root_before", "payment_root_after", "settled_batch_count_before", "settled_batch_count_after"),
    "application_dispositions": ("disposition_id", "queue_job_id", "queue_operation_id", "operation_digest", "acceptance_digest", "status", "receipt_bytes", "receipt_digest", "duplicate_convergence", "error_code", "created_ms"),
    "outbox_jobs": ("job_id", "operation_id", "disposition_id", "envelope_bytes", "envelope_digest", "idempotency_key", "status", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "outbox_leases": ("job_id", "worker_id", "token", "attempt", "leased_ms", "expires_ms"),
    "outbox_acks": ("job_id", "status", "acknowledgment_bytes", "acknowledgment_digest", "operation_id", "acknowledged_ms", "qualification_receipt", "profile_digest", "acknowledgment_id"),
    "outbox_transitions": ("sequence", "transition_kind", "job_id", "before_root", "after_root", "event_bytes", "event_digest"),
    "reconciliation_records": ("job_id", "operation_id", "envelope_digest", "idempotency_key", "status", "attempt", "worker_id", "token", "leased_ms", "expires_ms", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
}
_TABLE_ORDER = tuple(_TABLE_COLUMNS)
_TABLE_DATA_ORDER = _TABLE_ORDER[1:]
_BLOB_COLUMNS: Final[dict[str, frozenset[int]]] = {
    "composition_metadata": frozenset({3, 4, 6, 7, 8, 9, 12, 13, 14, 17}),
    "composition_state": frozenset({1, 2, 3, 6, 7, 9, 10, 12, 13, 14, 15, 16}),
    "composition_transitions": frozenset({3, 4, 5, 6}),
    "proof_requests": frozenset({0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 15, 16, 17, 20, 21, 22, 23}),
    "proof_audit": frozenset({1, 2, 3, 4}),
    "proof_transitions": frozenset({1, 2, 3, 4, 5}),
    "application_dispositions": frozenset({0, 2, 3, 4, 6, 7}),
    "outbox_jobs": frozenset({1, 2, 3, 4, 5}),
    "outbox_leases": frozenset({2}),
    "outbox_acks": frozenset({2, 3, 4, 6, 7}),
    "outbox_transitions": frozenset({3, 4, 5, 6}),
    "reconciliation_records": frozenset({1, 2, 3, 7}),
}


def _fail(code: str) -> None:
    raise IndependentCompositionError(code)


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
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IndependentCompositionError("json") from exc


def _hex(raw: bytes) -> str:
    return raw.hex().upper()


def _blob(value: Any, size: int, label: str, *, nullable: bool = False) -> bytes | None:
    if value is None and nullable:
        return None
    if type(value) is not str:
        _fail(label)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentCompositionError(label) from exc
    if len(raw) != size:
        _fail(label)
    return raw


def _u64(value: int) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**64:
        _fail("integer")
    return value.to_bytes(8, "big")


def _fixed_ascii(value: str) -> bytes:
    if type(value) is not str:
        _fail("identifier")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentCompositionError("identifier_ascii") from exc
    if len(encoded) > _MAX_ID:
        _fail("identifier_width")
    return len(encoded).to_bytes(2, "big") + encoded + bytes(_MAX_ID - len(encoded))


def _private_identity(label: str) -> bytes:
    return _sha(b"BL/NATIVE-V3/PRIVATE-ZK/IDENTITY/v1\x00", label.encode("ascii"))


_PRIVATE_CONTEXT = _private_identity("database-context.v1")
_PRIVATE_SCHEMA = _private_identity("database-schema.v1")
_PRIVATE_PROGRAM = _private_identity("database-program.v1")
_PRIVATE_MODE = _private_identity("mode.PRIVATE_ZK.v1")
_INITIAL_PAYMENT = _private_identity("payment-genesis.v1")
_INITIAL_CLEARANCE = _private_identity("clearance-genesis.v1")


def _profile_digest(statement: Any, verifier: bytes) -> bytes:
    return _sha(b"BL/NATIVE-V3/PRIVATE-ZK/PROFILE/v1\x00", _PRIVATE_MODE, _PRIVATE_CONTEXT, _PRIVATE_SCHEMA, _PRIVATE_PROGRAM, bytes(statement.get("execution_context")), bytes(statement.get("evaluator_id")), bytes(statement.get("schema_id")), bytes(statement.get("program_id")), bytes(statement.get("automatic_control_set")), _CIRCUIT_ID, verifier, _ZERO_SUITE, _u64(7))


def _state_identity(statement: Any, verifier: bytes) -> bytes:
    return _sha(_STATE_IDENTITY, _PRIVATE_CONTEXT, _PRIVATE_SCHEMA, _PRIVATE_PROGRAM, _PRIVATE_MODE, _CIRCUIT_ID, bytes(statement.statement_bytes), verifier, _profile_digest(statement, verifier))


def _decode_export(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_EXPORT:
        _fail("export_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentCompositionError("export_encoding") from exc
    if type(value) is not dict or set(value) != {"schema", "config", "metadata", "tables"} or raw != _json_bytes(value):
        _fail("export_canonical")
    if value["schema"] != _SCHEMA or type(value["config"]) is not dict or type(value["metadata"]) is not list or type(value["tables"]) is not dict:
        _fail("export_schema")
    if set(value["tables"]) != set(_TABLE_DATA_ORDER):
        _fail("export_tables")
    return value


def _decode_row(table: str, row: Any) -> list[Any]:
    if type(row) is not list or len(row) != len(_TABLE_COLUMNS[table]):
        _fail(table + "_shape")
    result = list(row)
    for index in _BLOB_COLUMNS[table]:
        value = result[index]
        if value is None:
            if table == "composition_metadata" and index in {8, 13, 14} or table == "composition_state" and index == 14 or table == "application_dispositions" and index in {6, 7} or table == "reconciliation_records" and index in {6, 7, 8, 9}:
                continue
            _fail(table + "_null_blob")
        if type(value) is not str:
            _fail(table + "_blob")
        try:
            result[index] = bytes.fromhex(value)
        except ValueError as exc:
            raise IndependentCompositionError(table + "_blob") from exc
    return result


def _decode_blob_exact(value: Any, size: int, label: str, *, nullable: bool = False) -> bytes | None:
    return _blob(value, size, label, nullable=nullable)


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT:
        _fail("receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentCompositionError("receipt_encoding") from exc
    if type(value) is not dict or raw != _json_bytes(value):
        _fail("receipt_canonical")
    required = {"operation_digest", "artifact_sha256", "artifact_digest", "statement_digest", "circuit_id", "bundle_id", "receipt_id", "join_id", "settlement_id", "request_id", "attempt_id", "decision_id", "sequence_before", "sequence_after", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "clearance_count_before", "clearance_count_after", "payment_root_before", "payment_root_after", "settled_batch_count_before", "settled_batch_count_after", "state_binding_after", "audit_head_after", "policy_result", "effective_directive", "proof_session_accepted", "economic_mutation", "proof_suite_id"}
    if set(value) != required:
        _fail("receipt_keys")
    for name in ("operation_digest", "artifact_digest", "statement_digest", "bundle_id", "receipt_id", "join_id", "settlement_id", "request_id", "attempt_id", "decision_id", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after", "payment_root_before", "payment_root_after", "state_binding_after", "audit_head_after"):
        _blob(value[name], 64, "receipt_" + name)
    _blob(value["artifact_sha256"], 32, "receipt_artifact_sha256")
    _blob(value["circuit_id"], 32, "receipt_circuit")
    for name in ("sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after", "settled_batch_count_before", "settled_batch_count_after"):
        if type(value[name]) is not int or value[name] < 0:
            _fail("receipt_integer")
    for name in ("policy_result", "effective_directive"):
        if type(value[name]) is not int or not 1 <= value[name] <= 5:
            _fail("receipt_directive")
    if value["proof_session_accepted"] is not True or value["economic_mutation"] is not False or value["proof_suite_id"] is not None:
        _fail("receipt_nonactivation")
    return value


def _parse_envelope(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ENVELOPE:
        _fail("envelope_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentCompositionError("envelope_encoding") from exc
    keys = {"schema", "composition_config_digest", "composition_id_digest", "receiver_identity", "receiver_epoch", "verifier_epoch", "ack_evidence_profile_digest", "job_id_digest", "operation_id", "disposition_digest", "state_store_identity", "state_receipt_digest", "request_id", "attempt_id", "decision_id", "receipt_id", "state_after_id", "state_binding_after", "audit_head_after", "policy_result", "effective_directive", "proof_session_accepted", "proof_acceptance_is_clear", "payment_root_unchanged", "settled_batch_count_unchanged", "economic_mutation", "proof_suite_id"}
    if type(value) is not dict or set(value) != keys or raw != _json_bytes(value) or value["schema"] != _HANDOFF_SCHEMA:
        _fail("envelope_canonical")
    for name, size in (("composition_config_digest", 64), ("composition_id_digest", 64), ("receiver_identity", 32), ("ack_evidence_profile_digest", 64), ("job_id_digest", 64), ("operation_id", 64), ("disposition_digest", 64), ("state_store_identity", 64), ("state_receipt_digest", 64), ("request_id", 64), ("attempt_id", 64), ("decision_id", 64), ("receipt_id", 64), ("state_after_id", 64), ("state_binding_after", 64), ("audit_head_after", 64)):
        _blob(value[name], size, "envelope_" + name)
    for name in ("receiver_epoch", "verifier_epoch", "policy_result", "effective_directive"):
        if type(value[name]) is not int or value[name] < 1:
            _fail("envelope_integer")
    if value["proof_session_accepted"] is not True or value["proof_acceptance_is_clear"] is not False or value["payment_root_unchanged"] is not True or value["settled_batch_count_unchanged"] is not True or value["economic_mutation"] is not False or value["proof_suite_id"] is not None:
        _fail("envelope_nonactivation")
    return value


def _parse_ack(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ACK:
        _fail("ack_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentCompositionError("ack_encoding") from exc
    keys = {"schema", "receiver_identity", "receiver_epoch", "idempotency_key", "envelope_digest", "effective_directive", "accepted_ms", "acknowledgment_id"}
    if type(value) is not dict or set(value) not in (keys, keys | {"policy_result"}) or raw != _json_bytes(value) or value["schema"] != _HANDOFF_SCHEMA:
        _fail("ack_canonical")
    _blob(value["receiver_identity"], 32, "ack_receiver")
    _blob(value["idempotency_key"], 64, "ack_idempotency")
    _blob(value["envelope_digest"], 64, "ack_envelope")
    _blob(value["acknowledgment_id"], 64, "ack_id")
    if type(value["receiver_epoch"]) is not int or value["receiver_epoch"] < 1 or type(value["accepted_ms"]) is not int or value["accepted_ms"] < 0 or type(value["effective_directive"]) is not int or not 1 <= value["effective_directive"] <= 5:
        _fail("ack_values")
    if "policy_result" in value and (type(value["policy_result"]) is not int or not 1 <= value["policy_result"] <= 5):
        _fail("ack_policy")
    return value


def _parse_qualification_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT:
        _fail("qualification_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentCompositionError("qualification_encoding") from exc
    required = {
        "schema_version", "mode", "profile_digest", "verifier_identity", "verifier_epoch",
        "receiver_identity", "receiver_epoch", "operation_id", "job_id_digest", "idempotency_key",
        "envelope_digest", "ack_digest", "acknowledgment_id", "policy_result", "effective_directive",
        "proof_suite_id", "production_usable", "activation",
    }
    if type(value) is not dict or set(value) != required or raw != _json_bytes(value):
        _fail("qualification_canonical")
    if value["schema_version"] != 2 or value["mode"] != _ACK_MODE:
        _fail("qualification_profile")
    for name in ("profile_digest", "operation_id", "job_id_digest", "idempotency_key", "envelope_digest", "ack_digest", "acknowledgment_id"):
        _blob(value[name], 64, "qualification_" + name)
    _blob(value["verifier_identity"], 32, "qualification_verifier")
    _blob(value["receiver_identity"], 32, "qualification_receiver")
    for name in ("verifier_epoch", "receiver_epoch", "policy_result", "effective_directive"):
        if type(value[name]) is not int or value[name] < 1:
            _fail("qualification_integer")
    if value["policy_result"] > 5 or value["effective_directive"] > 5 or value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("qualification_nonactivation")
    return value


def _verify_config(config: Mapping[str, Any]) -> tuple[bytes, bytes]:
    if type(config) is not dict or config.get("schema_version") != _SCHEMA_VERSION or config.get("proof_suite_id") is not None or config.get("production_usable") is not False or config.get("activation") is not False or tuple(config.get("directives", ())) != _DIRECTIVES:
        _fail("config")
    try:
        if not isinstance(config.get("composition_id"), str) or not isinstance(config.get("queue_id"), str) or _fixed_ascii(config["composition_id"]) is None or _fixed_ascii(config["queue_id"]) is None:
            _fail("config_identifiers")
        canonical = _json_bytes(config)
        digest = _sha(_MATERIAL, canonical)
        queue_digest = bytes.fromhex(str(config["queue_config_digest"]))
        verifier = bytes.fromhex(str(config["verifier_sha256"]))
        receiver = bytes.fromhex(str(config["receiver_identity"]))
        profile = bytes.fromhex(str(config["ack_evidence_profile_digest"]))
        state_identity = config.get("state_profile_identity")
        if state_identity is not None and len(bytes.fromhex(str(state_identity))) != 64:
            _fail("config_state_identity")
        expected_statement = config.get("expected_statement")
        if expected_statement is not None and len(bytes.fromhex(str(expected_statement))) != 3340:
            _fail("config_expected_statement")
    except (KeyError, ValueError) as exc:
        raise IndependentCompositionError("config_fields") from exc
    if len(queue_digest) != 64 or len(verifier) != 32 or len(receiver) != 32 or len(profile) != 64:
        _fail("config_width")
    for name, maximum in (("receiver_epoch", 2**63), ("verifier_epoch", 2**63), ("capacity", 10_000), ("reconciliation_capacity", 10_000), ("lease_seconds", 3_600), ("reconciliation_lease_seconds", 3_600)):
        if type(config.get(name)) is not int or not 1 <= config[name] <= maximum:
            _fail("config_integer")
    if config.get("max_attempts") != 3 or config.get("busy_timeout_ms") != 5_000:
        _fail("config_fixed")
    return digest, profile


def _verify_rows(value: dict[str, Any], *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    config = value["config"]
    config_digest, profile_digest = _verify_config(config)
    ack_profile = profile_digest
    if expected_config is not None and _json_bytes(config) != _json_bytes(dict(expected_config)):
        _fail("config_substitution")
    metadata = value["metadata"]
    if len(metadata) != len(_TABLE_COLUMNS["composition_metadata"]):
        _fail("metadata_shape")
    metadata_config_digest = _blob(metadata[4], 64, "metadata_config_digest")
    metadata_queue_digest = _blob(metadata[6], 64, "metadata_queue_digest")
    metadata_verifier = _blob(metadata[7], 32, "metadata_verifier")
    metadata_receiver = _blob(metadata[9], 32, "metadata_receiver")
    metadata_profile = _blob(metadata[12], 64, "metadata_profile")
    metadata_state_identity = _blob(metadata[8], 64, "metadata_state_identity", nullable=True)
    metadata_expected_statement = _blob(metadata[13], 3340, "metadata_expected_statement", nullable=True)
    config_state_identity = _blob(config.get("state_profile_identity"), 64, "config_state_identity", nullable=True)
    config_expected_statement = _blob(config.get("expected_statement"), 3340, "config_expected_statement", nullable=True)
    if (
        int(metadata[1]) != _SCHEMA_VERSION or str(metadata[2]) != config["composition_id"]
        or metadata_config_digest != config_digest or metadata_queue_digest != bytes.fromhex(str(config["queue_config_digest"]))
        or metadata_verifier != bytes.fromhex(str(config["verifier_sha256"]))
        or metadata_receiver != bytes.fromhex(str(config["receiver_identity"]))
        or int(metadata[10]) != int(config["receiver_epoch"]) or int(metadata[11]) != int(config["verifier_epoch"])
        or metadata_profile != profile_digest or metadata[14] is not None or metadata[15] != 0 or metadata[16] != 0
        or (config_state_identity is not None and metadata_state_identity != config_state_identity)
        or (config_expected_statement is not None and metadata_expected_statement != config_expected_statement)
    ):
        _fail("metadata_binding")
    rows: dict[str, list[list[Any]]] = {}
    for table in _TABLE_DATA_ORDER:
        raw_rows = value["tables"].get(table)
        if type(raw_rows) is not list:
            _fail(table + "_rows")
        rows[table] = [_decode_row(table, row) for row in raw_rows]
    state_rows = rows["composition_state"]
    if len(state_rows) > 1:
        _fail("state_singleton")
    composition_transitions = rows["composition_transitions"]
    if int(metadata[18]) != len(composition_transitions):
        _fail("composition_transition_count")
    expected_head = _sha(_GENESIS, str(config["composition_id"]).encode("ascii"), config_digest)
    for number, transition in enumerate(composition_transitions, start=1):
        try:
            event = json.loads(bytes(transition[5]).decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IndependentCompositionError("composition_transition_event") from exc
        if int(transition[0]) != number or bytes(transition[3]) != expected_head or bytes(transition[5]) != _json_bytes(event) or bytes(transition[6]) != _sha(_EVENT, str(transition[1]).encode("ascii"), str(transition[2]).encode("ascii"), bytes(transition[5])) or bytes(transition[4]) != _sha(_HEAD, expected_head, _u64(number), bytes(transition[6])):
            _fail("composition_head_chain")
        expected_head = bytes(transition[4])
    if bytes.fromhex(str(metadata[17])) != expected_head:
        _fail("composition_head_current")
    verifier = bytes.fromhex(str(config["verifier_sha256"]))
    profile = profile_digest
    state = state_rows[0] if state_rows else None
    if state is not None:
        if metadata_state_identity is None or metadata_expected_statement is None:
            _fail("state_metadata_missing")
        if bytes(state[2]) != _CIRCUIT_ID or bytes(state[10]) != _INITIAL_PAYMENT or int(state[11]) != 0 or bytes(state[15]) != verifier:
            _fail("state_genesis_binding")
        statement = parse_acceptance_bytes(b"BLPACV1\x00" + (1).to_bytes(4, "big") + (1).to_bytes(8, "big") + bytes(32) + b"\x01" + bytes(63) + _CIRCUIT_ID + len(bytes(state[1])).to_bytes(4, "big") + bytes(state[1]))
        state_profile = _profile_digest(statement.statement, verifier)
        genesis_clearance = _sha(_STATE_GENESIS, statement.statement.state_before_id, _INITIAL_CLEARANCE)
        genesis_replay = _sha(_STATE_GENESIS, statement.statement.attempt_id, statement.statement.request_id)
        genesis_binding = _sha(
            _STATE_BINDING, statement.statement.statement_bytes, statement.statement.state_before_id,
            _u64(statement.statement.epoch), _u64(statement.statement.sequence_before),
            bytes(statement.statement.state("before_continuity_root")), genesis_clearance, genesis_replay,
            _INITIAL_PAYMENT, _u64(0), verifier, state_profile,
        )
        if (
            bytes(state[1]) != statement.statement.statement_bytes or bytes(state[16]) != state_profile
            or _state_identity(statement.statement, verifier) != metadata_state_identity
            or metadata_expected_statement != bytes(state[1])
        ):
            _fail("state_profile_identity")
        if int(state[4]) < 0 or int(state[5]) < 0 or int(state[8]) < 0:
            _fail("state_integer")
    requests = rows["proof_requests"]
    audits = rows["proof_audit"]
    transitions = rows["proof_transitions"]
    if len(requests) != len(audits) or len(requests) != len(transitions):
        _fail("proof_ledger_count")
    dispositions = rows["application_dispositions"]
    outboxes = rows["outbox_jobs"]
    if len(outboxes) != sum(1 for row in dispositions if row[5] == "APPLIED"):
        _fail("outbox_disposition_count")
    request_map: dict[bytes, list[Any]] = {}
    previous_binding = None
    previous_head = None
    previous_clearance = None
    previous_count = None
    previous_replay = None
    if state is not None:
        statement = parse_acceptance_bytes(b"BLPACV1\x00" + (1).to_bytes(4, "big") + (1).to_bytes(8, "big") + bytes(32) + b"\x01" + bytes(63) + _CIRCUIT_ID + len(bytes(state[1])).to_bytes(4, "big") + bytes(state[1])).statement
        previous_binding = _sha(_STATE_BINDING, bytes(statement.statement_bytes), statement.state_before_id, _u64(statement.epoch), _u64(statement.sequence_before), bytes(statement.state("before_continuity_root")), _sha(_STATE_GENESIS, statement.state_before_id, _INITIAL_CLEARANCE), _sha(_STATE_GENESIS, statement.attempt_id, statement.request_id), _INITIAL_PAYMENT, _u64(0), verifier, state_profile)
        previous_head = bytes(statement.state("before_audit_head"))
        previous_clearance = _sha(_STATE_GENESIS, statement.state_before_id, _INITIAL_CLEARANCE)
        previous_count = int(statement.state("clearance_count_before"))
        previous_replay = _sha(_STATE_GENESIS, statement.attempt_id, statement.request_id)
    for index, row in enumerate(requests):
        if state is None:
            _fail("request_without_state")
        acceptance = parse_acceptance_bytes(bytes(row[5]))
        if acceptance.canonical_bytes() != bytes(row[5]) or bytes(row[6]) != _sha(_MATERIAL, b"acceptance", bytes(row[5])) or bytes(row[4]) != _sha(_MATERIAL, b"queue-receipt", bytes(row[3])):
            _fail("request_binding")
        operation = _sha(_STATE_OPERATION, bytes(row[5]), bytes(previous_binding), bytes(previous_head), _INITIAL_PAYMENT, verifier)
        if bytes(row[0]) != operation or bytes(row[8]) != acceptance.artifact_digest or bytes(row[9]) != acceptance.statement.request_id or bytes(row[10]) != acceptance.statement.attempt_id or bytes(row[11]) != acceptance.statement.decision_id or int(row[24]) != int(acceptance.policy_result) or int(row[25]) != int(acceptance.statement.directive):
            _fail("request_identity")
        if int(row[12]) != int(state[5]) - len(requests) + index or int(row[13]) != int(row[12]) + 1 or bytes(row[14]) != acceptance.statement.state_before_id or bytes(row[15]) != acceptance.statement.state_after_id:
            _fail("request_sequence")
        replay_after = _sha(_STATE_REPLAY, bytes(previous_replay), acceptance.statement.attempt_id, acceptance.statement.request_id, acceptance.statement.receipt_id)
        advanced = acceptance.statement.directive in (1, 5)
        clearance_after = _sha(_STATE_CLEARANCE, bytes(previous_clearance), acceptance.statement.state_after_id, acceptance.statement.decision_id, bytes((acceptance.statement.directive,))) if advanced else bytes(previous_clearance)
        count_after = int(previous_count) + int(advanced)
        binding_after = _sha(_STATE_BINDING, bytes(previous_binding), operation, acceptance.statement.state_after_id, replay_after, clearance_after, _u64(count_after), _INITIAL_PAYMENT, _u64(0), _u64(acceptance.statement.epoch), _u64(int(row[13])), verifier, state_profile)
        receipt = _parse_receipt(bytes(row[7]))
        if (
            bytes.fromhex(receipt["operation_digest"]) != operation
            or bytes.fromhex(receipt["artifact_digest"]) != acceptance.artifact_digest
            or bytes.fromhex(receipt["statement_digest"]) != acceptance.statement_digest
            or bytes.fromhex(receipt["request_id"]) != acceptance.statement.request_id
            or bytes.fromhex(receipt["attempt_id"]) != acceptance.statement.attempt_id
            or bytes.fromhex(receipt["decision_id"]) != acceptance.statement.decision_id
            or int(receipt["policy_result"]) != int(acceptance.policy_result)
            or int(receipt["effective_directive"]) != int(acceptance.statement.directive)
            or int(receipt["sequence_before"]) != int(row[12]) or int(receipt["sequence_after"]) != int(row[13])
            or bytes.fromhex(receipt["state_binding_after"]) != binding_after
            or bytes.fromhex(receipt["clearance_root_before"]) != bytes(previous_clearance)
            or bytes.fromhex(receipt["clearance_root_after"]) != clearance_after
            or int(receipt["clearance_count_before"]) != int(previous_count)
            or int(receipt["clearance_count_after"]) != count_after
            or bytes.fromhex(receipt["payment_root_before"]) != _INITIAL_PAYMENT
            or bytes.fromhex(receipt["payment_root_after"]) != _INITIAL_PAYMENT
            or int(receipt["settled_batch_count_before"]) != 0 or int(receipt["settled_batch_count_after"]) != 0
        ):
            _fail("receipt_binding")
        audit = audits[index]
        payload = bytes(audit[4])
        event_commitment = _sha(_STATE_AUDIT_EVENT, bytes(previous_head), payload)
        audit_after = _sha(_STATE_AUDIT_HEAD, bytes(previous_head), event_commitment)
        if int(audit[0]) != int(row[13]) or bytes(audit[1]) != bytes(previous_head) or bytes(audit[2]) != event_commitment or bytes(audit[3]) != audit_after or bytes.fromhex(receipt["audit_head_after"]) != audit_after:
            _fail("audit_chain")
        transition = transitions[index]
        if (
            int(transition[0]) != int(row[13]) or bytes(transition[1]) != operation
            or bytes(transition[2]) != bytes(row[20]) or bytes(transition[3]) != bytes(row[21])
            or bytes(transition[4]) != _INITIAL_PAYMENT or bytes(transition[5]) != _INITIAL_PAYMENT
            or int(transition[6]) != 0 or int(transition[7]) != 0
        ):
            _fail("proof_transition_binding")
        request_map[operation] = row
        previous_binding, previous_head, previous_clearance, previous_count, previous_replay = binding_after, audit_after, clearance_after, count_after, replay_after
    if state is not None and requests:
        last = requests[-1]
        if int(state[5]) != int(last[13]) or bytes(state[3]) != bytes(last[15]) or bytes(state[6]) != bytes(parse_acceptance_bytes(bytes(last[5])).statement.state("after_continuity_root")) or bytes(state[7]) != bytes(last[17]) or int(state[8]) != int(last[19]) or bytes(state[9]) != previous_replay or bytes(state[10]) != _INITIAL_PAYMENT or int(state[11]) != 0 or bytes(state[12]) != previous_binding or bytes(state[13]) != previous_head or bytes(state[14]) != bytes(last[0]):
            _fail("current_state")
    elif state is not None:
        statement = parse_acceptance_bytes(b"BLPACV1\x00" + (1).to_bytes(4, "big") + (1).to_bytes(8, "big") + bytes(32) + b"\x01" + bytes(63) + _CIRCUIT_ID + len(bytes(state[1])).to_bytes(4, "big") + bytes(state[1])).statement
        if (
            bytes(state[3]) != statement.state_before_id or int(state[4]) != int(statement.epoch)
            or int(state[5]) != int(statement.sequence_before) or bytes(state[6]) != bytes(statement.state("before_continuity_root"))
            or bytes(state[7]) != genesis_clearance or int(state[8]) != int(statement.state("clearance_count_before"))
            or bytes(state[9]) != genesis_replay or bytes(state[12]) != genesis_binding
            or bytes(state[13]) != bytes(statement.state("before_audit_head")) or state[14] is not None
        ):
            _fail("current_genesis_state")
    disposition_map: dict[str, list[Any]] = {}
    disposition_by_id: dict[bytes, list[Any]] = {}
    applied_count = 0
    for row in dispositions:
        job = str(row[1])
        disposition_id = bytes(row[0])
        if row[5] not in {"APPLIED", "HELD"} or job in disposition_map or disposition_id in disposition_by_id:
            _fail("disposition_shape")
        if type(row[8]) is not int or row[8] not in {0, 1} or type(row[10]) is not int or row[10] < 0:
            _fail("disposition_values")
        disposition_map[job] = row
        disposition_by_id[disposition_id] = row
        if row[5] == "APPLIED":
            applied_count += 1
            request = request_map.get(bytes(row[3]))
            if (
                row[6] is None or row[7] is None or bytes(row[7]) != _sha(_STATE_RECEIPT, bytes(row[6]))
                or request is None or bytes(row[2]) != bytes(request[2]) or bytes(row[4]) != bytes(request[6])
                or job != str(request[1])
                or disposition_id != _sha(_MATERIAL, b"disposition", job.encode("ascii"), bytes(row[2]), bytes(row[4]))
            ):
                _fail("disposition_binding")
        elif row[6] is not None or row[7] is not None or row[9] is None:
            _fail("held_mutation")
    if applied_count != len(requests):
        _fail("applied_request_count")

    outbox_by_job: dict[str, list[Any]] = {}
    for row in outboxes:
        job = str(row[0])
        if row[6] not in {"DISCOVERED", "LEASED", "DELIVERY_UNCONFIRMED", "ACKNOWLEDGED"} or job in outbox_by_job:
            _fail("outbox_shape")
        if type(row[7]) is not int or row[7] < 0 or any(type(row[index]) is not int or row[index] < 0 for index in (8, 9, 10)):
            _fail("outbox_values")
        disp = disposition_by_id.get(bytes(row[2]))
        if disp is None or disp[5] != "APPLIED" or bytes(row[2]) != bytes(disp[0]):
            _fail("outbox_binding")
        envelope_raw = bytes(row[3])
        envelope = _parse_envelope(envelope_raw)
        receipt = _parse_receipt(bytes(disp[6]))
        if (
            bytes(row[4]) != _sha(_ENVELOPE, envelope_raw)
            or bytes(row[1]) != _sha(_OUTBOX_OPERATION, config_digest, _fixed_ascii(str(config["composition_id"])), _fixed_ascii(job), bytes(row[4]))
            or bytes(row[5]) != _sha(_IDEMPOTENCY, config_digest, _fixed_ascii(str(config["composition_id"])), _fixed_ascii(job), bytes(row[4]))
            or bytes.fromhex(envelope["composition_config_digest"]) != config_digest
            or bytes.fromhex(envelope["composition_id_digest"]) != _sha(_ENVELOPE, str(config["composition_id"]).encode("ascii"))
            or bytes.fromhex(envelope["receiver_identity"]) != bytes.fromhex(str(config["receiver_identity"]))
            or int(envelope["receiver_epoch"]) != int(config["receiver_epoch"])
            or int(envelope["verifier_epoch"]) != int(config["verifier_epoch"])
            or bytes.fromhex(envelope["ack_evidence_profile_digest"]) != ack_profile
            or bytes.fromhex(envelope["job_id_digest"]) != _sha(_ENVELOPE, job.encode("ascii"))
            or bytes.fromhex(envelope["operation_id"]) != bytes(disp[2])
            or bytes.fromhex(envelope["disposition_digest"]) != bytes(row[2])
            or (metadata_state_identity is None or bytes.fromhex(envelope["state_store_identity"]) != metadata_state_identity)
            or bytes.fromhex(envelope["state_receipt_digest"]) != bytes(disp[7])
            or envelope["request_id"] != receipt["request_id"] or envelope["attempt_id"] != receipt["attempt_id"]
            or envelope["decision_id"] != receipt["decision_id"] or envelope["receipt_id"] != receipt["receipt_id"]
            or envelope["state_after_id"] != receipt["state_after_id"] or envelope["state_binding_after"] != receipt["state_binding_after"]
            or envelope["audit_head_after"] != receipt["audit_head_after"]
            or int(envelope["policy_result"]) != int(receipt["policy_result"])
            or int(envelope["effective_directive"]) != int(receipt["effective_directive"])
        ):
            _fail("outbox_identity")
        outbox_by_job[job] = row
    if any(str(row[0]) not in outbox_by_job for row in rows["outbox_leases"]):
        _fail("lease_orphan")
    leases: dict[str, list[Any]] = {}
    for row in rows["outbox_leases"]:
        job = str(row[0])
        if job in leases or outbox_by_job[job][6] != "LEASED" or type(row[3]) is not int or row[3] < 1 or bytes(row[2]) == b"" or len(bytes(row[2])) != 24 or type(row[4]) is not int or type(row[5]) is not int or int(row[5]) <= int(row[4]) or int(row[3]) != int(outbox_by_job[job][7]):
            _fail("lease_binding")
        leases[job] = row
    for job, row in outbox_by_job.items():
        if row[6] == "LEASED" and job not in leases:
            _fail("lease_missing")
        if row[6] != "LEASED" and job in leases:
            _fail("lease_unexpected")

    ack_map: dict[str, list[Any]] = {}
    for row in rows["outbox_acks"]:
        job = str(row[0])
        outbox = outbox_by_job.get(job)
        if outbox is None or job in ack_map or row[1] != "ACKNOWLEDGED" or outbox[6] != "ACKNOWLEDGED":
            _fail("ack_orphan")
        ack = _parse_ack(bytes(row[2]))
        envelope = _parse_envelope(bytes(outbox[3]))
        qualification = _parse_qualification_receipt(bytes(row[6]))
        if (
            bytes(row[3]) != _sha(_ACK, bytes(row[2])) or bytes(row[4]) != bytes(outbox[1]) or bytes(row[7]) != ack_profile
            or str(row[8]) != str(ack["acknowledgment_id"]) or type(row[5]) is not int or row[5] < 0
            or bytes.fromhex(ack["receiver_identity"]) != bytes.fromhex(str(config["receiver_identity"]))
            or int(ack["receiver_epoch"]) != int(config["receiver_epoch"])
            or bytes.fromhex(ack["idempotency_key"]) != bytes(outbox[5]) or bytes.fromhex(ack["envelope_digest"]) != bytes(outbox[4])
            or int(ack["effective_directive"]) != int(envelope["effective_directive"])
            or ("policy_result" in ack and int(ack["policy_result"]) != int(envelope["policy_result"]))
            or bytes.fromhex(qualification["profile_digest"]) != ack_profile
            or bytes.fromhex(qualification["verifier_identity"]) != bytes.fromhex(str(config["verifier_sha256"]))
            or int(qualification["verifier_epoch"]) != int(config["verifier_epoch"])
            or bytes.fromhex(qualification["receiver_identity"]) != bytes.fromhex(str(config["receiver_identity"]))
            or int(qualification["receiver_epoch"]) != int(config["receiver_epoch"])
            or bytes.fromhex(qualification["operation_id"]) != bytes(outbox[1])
            or bytes.fromhex(qualification["job_id_digest"]) != _sha(_ACK_RECEIPT, job.encode("ascii"))
            or bytes.fromhex(qualification["idempotency_key"]) != bytes(outbox[5])
            or bytes.fromhex(qualification["envelope_digest"]) != bytes(outbox[4])
            or bytes.fromhex(qualification["ack_digest"]) != bytes(row[3])
            or qualification["acknowledgment_id"] != ack["acknowledgment_id"]
            or int(qualification["policy_result"]) != int(envelope["policy_result"])
            or int(qualification["effective_directive"]) != int(envelope["effective_directive"])
        ):
            _fail("ack_binding")
        ack_map[job] = row
    for job, outbox in outbox_by_job.items():
        if outbox[6] == "ACKNOWLEDGED" and job not in ack_map:
            _fail("ack_missing")
        if outbox[6] != "ACKNOWLEDGED" and job in ack_map:
            _fail("ack_unexpected")

    outbox_ids = set(outbox_by_job)
    reconciliation = rows["reconciliation_records"]
    recon_map: dict[str, list[Any]] = {}
    for row in reconciliation:
        job = str(row[0])
        outbox = outbox_by_job.get(job)
        if outbox is None or job in recon_map or row[4] not in {"DISCOVERED", "LEASED", "EXHAUSTED", "ACKNOWLEDGED"}:
            _fail("reconciliation_binding")
        if (
            bytes(row[1]) != bytes(outbox[1]) or bytes(row[2]) != bytes(outbox[4]) or bytes(row[3]) != bytes(outbox[5])
            or type(row[5]) is not int or row[5] < 0 or row[5] > int(config["max_attempts"])
            or any(type(row[index]) is not int or row[index] < 0 for index in (10, 11, 12))
            or (row[4] == "ACKNOWLEDGED" and outbox[6] != "ACKNOWLEDGED")
            or (row[4] != "ACKNOWLEDGED" and outbox[6] not in {"DELIVERY_UNCONFIRMED", "LEASED"})
        ):
            _fail("reconciliation_binding")
        if row[4] == "LEASED":
            if row[6] is None or row[7] is None or len(bytes(row[7])) != 24 or row[8] is None or row[9] is None or int(row[9]) <= int(row[8]):
                _fail("reconciliation_lease")
        elif any(row[index] is not None for index in (6, 7, 8, 9)):
            _fail("reconciliation_lease")
        recon_map[job] = row
    for job, outbox in outbox_by_job.items():
        if outbox[6] == "DELIVERY_UNCONFIRMED" and job not in recon_map:
            _fail("reconciliation_missing")

    for number, transition in enumerate(rows["outbox_transitions"], start=1):
        if int(transition[0]) != number or str(transition[2]) not in outbox_ids:
            _fail("outbox_transition_shape")
        try:
            event = json.loads(bytes(transition[5]).decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IndependentCompositionError("outbox_transition_event") from exc
        if bytes(transition[5]) != _json_bytes(event) or bytes(transition[6]) != _sha(_EVENT, str(transition[1]).encode("ascii"), str(transition[2]).encode("ascii"), bytes(transition[5])) or bytes(transition[4]) != _sha(_HEAD, bytes(transition[3]), _u64(number), bytes(transition[6])):
            _fail("outbox_transition_chain")
    return {"schema": _SCHEMA, "composition_id": config["composition_id"], "config_digest": _hex(config_digest), "table_counts": {"composition_metadata": 1, **{name: len(rows[name]) for name in _TABLE_DATA_ORDER}}, "proof_suite_id": None, "production_usable": False, "activation": False}


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return _verify_rows(_decode_export(raw), expected_config=expected_config)


def _db_export(connection: sqlite3.Connection) -> bytes:
    names = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if names != set(_TABLE_ORDER):
        _fail("database_tables")
    metadata = connection.execute("SELECT * FROM composition_metadata WHERE id=1").fetchone()
    if metadata is None:
        _fail("database_metadata")
    tables: dict[str, list[list[Any]]] = {}
    for table in _TABLE_DATA_ORDER:
        tables[table] = [[_hex(x) if isinstance(x, bytes) else x for x in row] for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()]
    config_raw = bytes(metadata[3])
    try:
        config = json.loads(config_raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentCompositionError("database_config") from exc
    value = {"schema": _SCHEMA, "config": config, "metadata": [_hex(x) if isinstance(x, bytes) else x for x in metadata], "tables": tables}
    return _json_bytes(value)


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=5.0)
        connection.execute("PRAGMA query_only=ON")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity != ("ok",):
            _fail("database_integrity")
        connection.execute("BEGIN")
        raw = _db_export(connection)
        result = verify_export_bytes(raw, expected_config=expected_config)
        connection.execute("ROLLBACK")
        return result
    except sqlite3.Error as exc:
        raise IndependentCompositionError("database_read") from exc
    finally:
        if connection is not None:
            connection.close()


def verify_database_connection(connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(connection, sqlite3.Connection):
        _fail("connection")
    return verify_export_bytes(_db_export(connection), expected_config=expected_config)


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE composition_metadata (id INTEGER PRIMARY KEY CHECK(id=1),schema_version INTEGER NOT NULL,composition_id TEXT NOT NULL,config_json BLOB NOT NULL,config_digest BLOB NOT NULL,queue_id TEXT NOT NULL,queue_config_digest BLOB NOT NULL,verifier_sha256 BLOB NOT NULL,state_profile_identity BLOB,receiver_identity BLOB NOT NULL,receiver_epoch INTEGER NOT NULL,verifier_epoch INTEGER NOT NULL,ack_profile_digest BLOB NOT NULL,expected_statement BLOB,proof_suite_id BLOB,production_usable INTEGER NOT NULL,activation INTEGER NOT NULL,head_root BLOB NOT NULL,next_sequence INTEGER NOT NULL);
        CREATE TABLE composition_state (id INTEGER PRIMARY KEY CHECK(id=1),expected_statement BLOB NOT NULL,circuit_id BLOB NOT NULL,state_id BLOB NOT NULL,epoch INTEGER NOT NULL,sequence INTEGER NOT NULL,continuity_root BLOB NOT NULL,clearance_root BLOB NOT NULL,clearance_count INTEGER NOT NULL,replay_root BLOB NOT NULL,payment_root BLOB NOT NULL,settled_batch_count INTEGER NOT NULL,state_binding BLOB NOT NULL,audit_head BLOB NOT NULL,last_operation_digest BLOB,verifier_sha256 BLOB NOT NULL,profile_digest BLOB NOT NULL);
        CREATE TABLE composition_transitions (sequence INTEGER PRIMARY KEY,transition_kind TEXT NOT NULL,job_id TEXT NOT NULL,before_root BLOB NOT NULL,after_root BLOB NOT NULL,event_bytes BLOB NOT NULL,event_digest BLOB NOT NULL UNIQUE);
        CREATE TABLE proof_requests (operation_digest BLOB PRIMARY KEY,queue_job_id TEXT NOT NULL UNIQUE,queue_operation_id BLOB NOT NULL UNIQUE,queue_receipt_bytes BLOB NOT NULL,queue_receipt_digest BLOB NOT NULL,acceptance_bytes BLOB NOT NULL,acceptance_digest BLOB NOT NULL,receipt_bytes BLOB NOT NULL,artifact_digest BLOB NOT NULL UNIQUE,request_id BLOB NOT NULL,attempt_id BLOB NOT NULL,decision_id BLOB NOT NULL,sequence_before INTEGER NOT NULL,sequence_after INTEGER NOT NULL,state_before_id BLOB NOT NULL,state_after_id BLOB NOT NULL,clearance_root_before BLOB NOT NULL,clearance_root_after BLOB NOT NULL,clearance_count_before INTEGER NOT NULL,clearance_count_after INTEGER NOT NULL,state_binding_before BLOB NOT NULL,state_binding_after BLOB NOT NULL,audit_head_before BLOB NOT NULL,audit_head_after BLOB NOT NULL,policy_result INTEGER NOT NULL,effective_directive INTEGER NOT NULL,created_ms INTEGER NOT NULL);
        CREATE TABLE proof_audit (sequence INTEGER PRIMARY KEY,previous_head BLOB NOT NULL,event_commitment BLOB NOT NULL UNIQUE,current_head BLOB NOT NULL,payload BLOB NOT NULL);
        CREATE TABLE proof_transitions (sequence_after INTEGER PRIMARY KEY,operation_digest BLOB NOT NULL UNIQUE,state_binding_before BLOB NOT NULL,state_binding_after BLOB NOT NULL,payment_root_before BLOB NOT NULL,payment_root_after BLOB NOT NULL,settled_batch_count_before INTEGER NOT NULL,settled_batch_count_after INTEGER NOT NULL);
        CREATE TABLE application_dispositions (disposition_id BLOB PRIMARY KEY,queue_job_id TEXT NOT NULL UNIQUE,queue_operation_id BLOB NOT NULL UNIQUE,operation_digest BLOB NOT NULL UNIQUE,acceptance_digest BLOB NOT NULL,status TEXT NOT NULL,receipt_bytes BLOB,receipt_digest BLOB,duplicate_convergence INTEGER NOT NULL,error_code TEXT,created_ms INTEGER NOT NULL);
        CREATE TABLE outbox_jobs (job_id TEXT PRIMARY KEY,operation_id BLOB NOT NULL UNIQUE,disposition_id BLOB NOT NULL UNIQUE,envelope_bytes BLOB NOT NULL,envelope_digest BLOB NOT NULL UNIQUE,idempotency_key BLOB NOT NULL UNIQUE,status TEXT NOT NULL,attempt INTEGER NOT NULL,next_eligible_ms INTEGER NOT NULL,created_ms INTEGER NOT NULL,updated_ms INTEGER NOT NULL,last_error_code TEXT);
        CREATE TABLE outbox_leases (job_id TEXT PRIMARY KEY,worker_id TEXT NOT NULL,token BLOB NOT NULL,attempt INTEGER NOT NULL,leased_ms INTEGER NOT NULL,expires_ms INTEGER NOT NULL);
        CREATE TABLE outbox_acks (job_id TEXT PRIMARY KEY,status TEXT NOT NULL,acknowledgment_bytes BLOB NOT NULL,acknowledgment_digest BLOB NOT NULL,operation_id BLOB NOT NULL UNIQUE,acknowledged_ms INTEGER NOT NULL,qualification_receipt BLOB NOT NULL,profile_digest BLOB NOT NULL,acknowledgment_id TEXT NOT NULL);
        CREATE TABLE outbox_transitions (sequence INTEGER PRIMARY KEY,transition_kind TEXT NOT NULL,job_id TEXT NOT NULL,before_root BLOB NOT NULL,after_root BLOB NOT NULL,event_bytes BLOB NOT NULL,event_digest BLOB NOT NULL UNIQUE);
        CREATE TABLE reconciliation_records (job_id TEXT PRIMARY KEY,operation_id BLOB NOT NULL UNIQUE,envelope_digest BLOB NOT NULL UNIQUE,idempotency_key BLOB NOT NULL UNIQUE,status TEXT NOT NULL,attempt INTEGER NOT NULL,worker_id TEXT,token BLOB,leased_ms INTEGER,expires_ms INTEGER,next_eligible_ms INTEGER NOT NULL,created_ms INTEGER NOT NULL,updated_ms INTEGER NOT NULL,last_error_code TEXT);
        """
    )


def restore_export_to_fresh_database(path: Path, raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or path.exists() or not path.parent.is_dir():
        _fail("restore_target")
    value = _decode_export(raw)
    result = verify_export_bytes(raw, expected_config=expected_config)
    connection = sqlite3.connect(path)
    try:
        _create_schema(connection)
        def decode_meta(row: list[Any]) -> tuple[Any, ...]:
            blobs = {3, 4, 6, 7, 8, 9, 12, 13, 14, 17}
            output = list(row)
            for index in blobs:
                if output[index] is not None:
                    output[index] = bytes.fromhex(str(output[index]))
            return tuple(output)
        connection.execute("INSERT INTO composition_metadata VALUES (" + ",".join("?" for _ in _TABLE_COLUMNS["composition_metadata"]) + ")", decode_meta(value["metadata"]))
        for table in _TABLE_ORDER[1:]:
            for row in value["tables"][table]:
                output = list(row)
                for index in _BLOB_COLUMNS[table]:
                    if output[index] is not None:
                        output[index] = bytes.fromhex(str(output[index]))
                connection.execute(f"INSERT INTO {table} VALUES (" + ",".join("?" for _ in output) + ")", tuple(output))
        connection.commit()
    except Exception:
        connection.rollback()
        connection.close()
        try:
            path.unlink()
        except OSError:
            pass
        raise
    connection.close()
    verify_database(path, expected_config=expected_config)
    return result


__all__ = ("IndependentCompositionError", "restore_export_to_fresh_database", "verify_database", "verify_database_connection", "verify_export_bytes")
