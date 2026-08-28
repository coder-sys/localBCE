"""Independent reconstruction for the state-owned V7 composition image."""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Final, Mapping


class IndependentCompositionError(RuntimeError):
    pass


_SCHEMA_VERSION: Final[int] = 4
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/v4"
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/MATERIAL/v4\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/GENESIS/v4\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/EVENT/v4\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/HEAD/v4\x00"
_STATE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/COMPOSITION/STATE/v4\x00"
_DIRECTIVES = ("CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED")
_POLICY = ("PASS", "MISSING", "AMBIGUOUS", "FAIL")
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_META = ("id", "schema_version", "config_json", "config_digest", "event_head", "next_event_sequence", "state_profile_identity", "state_id", "state_bytes", "state_epoch", "state_sequence", "state_continuity_root", "state_audit_head", "state_clearance_root", "state_clearance_count", "payment_root", "active_dispatch_count")
_TX = ("transaction_id", "operation_ref", "status", "proof_accepted", "policy_result", "effective_directive", "disposition_id", "state_profile_identity", "state_before_id", "state_after_id", "sequence_before", "sequence_after", "state_receipt_bytes", "state_receipt_digest", "error_code", "created_ms", "updated_ms")
_EVENT_COLUMNS = ("sequence", "operation_ref", "event_kind", "before_state", "after_state", "payload", "event_digest", "event_root", "at_ms")
_OUTBOX = ("operation_ref", "effective_directive", "status", "attempt", "worker_id", "lease_token", "lease_expires_ms", "updated_ms")
_EVENT_PAYLOAD_KEYS = {"APPLIED": frozenset({"operation_ref", "proof_accepted", "policy_result", "effective_directive", "state_receipt_digest", "sequence_before", "sequence_after"})}
_ZERO = bytes(64)
_QUEUE_TABLES = frozenset(("queue_metadata", "queue_batches", "queue_members", "queue_leases", "queue_attempts", "queue_results", "queue_transitions"))
_COMPOSITION_TABLES = frozenset(("composition_meta", "composition_transactions", "composition_events", "composition_outbox"))


def _fail(code: str) -> None:
    error = IndependentCompositionError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("json")


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _blob(value: object, size: int, code: str) -> bytes:
    if type(value) is not str or value != value.upper() or re.fullmatch(rf"[0-9A-F]{{{size * 2}}}\Z", value) is None:
        _fail(code)
    return bytes.fromhex(value)


def _token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _fail(code)
    return value


def _parse_config(raw: bytes, expected_config: Mapping[str, Any] | None) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("config_encoding")
    required = {"schema_version", "composition_id", "queue_id", "queue_config_digest", "capacity", "verifier_profile_identity", "verifier_epoch", "receiver_identity", "receiver_epoch", "lease_seconds", "reconciliation_capacity", "reconciliation_lease_seconds", "max_attempts", "busy_timeout_ms", "directives", "policy_results", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required or value["schema_version"] != _SCHEMA_VERSION or value["directives"] != list(_DIRECTIVES) or value["policy_results"] != list(_POLICY) or value["proof_suite_id"] is not None or type(value["production_usable"]) is not bool or value["production_usable"] is not False or type(value["activation"]) is not bool or value["activation"] is not False:
        _fail("config_shape")
    _token(value["composition_id"], "composition_id")
    _token(value["queue_id"], "queue_id")
    _blob(value["queue_config_digest"], 64, "queue_config_digest")
    _blob(value["verifier_profile_identity"], 32, "verifier_profile_identity")
    _blob(value["receiver_identity"], 32, "receiver_identity")
    if type(value["verifier_epoch"]) is not int or value["verifier_epoch"] < 1 or type(value["receiver_epoch"]) is not int or value["receiver_epoch"] < 1 or type(value["lease_seconds"]) is not int or not 1 <= value["lease_seconds"] <= 86_400 or type(value["reconciliation_capacity"]) is not int or not 1 <= value["reconciliation_capacity"] <= 10_000 or type(value["reconciliation_lease_seconds"]) is not int or not 1 <= value["reconciliation_lease_seconds"] <= 86_400 or type(value["max_attempts"]) is not int or value["max_attempts"] != 3 or type(value["busy_timeout_ms"]) is not int or not 1 <= value["busy_timeout_ms"] <= 60_000:
        _fail("config_delivery")
    if expected_config is not None and value != dict(expected_config):
        _fail("config_binding")
    return value


def _parse_state_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= 16 * 1024:
        _fail("receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("receipt_encoding")
    required = {"schema", "operation_ref", "proof_accepted", "policy_result", "effective_directive", "state_profile_identity", "state_before_id", "state_before_bytes", "state_after_id", "state_after_bytes", "epoch", "predecessor_continuity_root", "state_after_continuity_root", "predecessor_audit_head", "decision_id", "state_after_audit_head", "predecessor_clearance_root", "state_after_clearance_root", "clearance_marker_before", "clearance_marker_after", "sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after", "payment_root", "exception_approved", "exception_authorization_id", "economic_mutation", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required or raw != _json_bytes(value) or value["schema"] != _SCHEMA or value["proof_suite_id"] is not None or type(value["production_usable"]) is not bool or value["production_usable"] is not False or type(value["activation"]) is not bool or value["activation"] is not False:
        _fail("receipt_keys")
    _blob(value["operation_ref"], 32, "receipt_operation_ref")
    _blob(value["state_profile_identity"], 64, "receipt_profile")
    _blob(value["state_before_id"], 64, "receipt_before")
    _blob(value["state_before_bytes"], 64, "receipt_before_bytes")
    _blob(value["state_after_id"], 64, "receipt_after")
    _blob(value["state_after_bytes"], 64, "receipt_after_bytes")
    for name in ("predecessor_continuity_root", "state_after_continuity_root", "predecessor_audit_head", "decision_id", "state_after_audit_head", "predecessor_clearance_root", "state_after_clearance_root", "payment_root", "exception_authorization_id"):
        _blob(value[name], 64, "receipt_" + name)
    if type(value["epoch"]) is not int or value["epoch"] < 1:
        _fail("receipt_epoch")
    if value["policy_result"] not in _POLICY or value["effective_directive"] not in _DIRECTIVES or type(value["proof_accepted"]) is not bool or value["proof_accepted"] is not True or type(value["exception_approved"]) is not bool or type(value["economic_mutation"]) is not bool or value["economic_mutation"] is not False:
        _fail("receipt_disposition")
    if value["exception_approved"] != (value["policy_result"] == "FAIL" and value["exception_authorization_id"] != "0" * 128):
        _fail("receipt_exception")
    expected = {"PASS": "CLEAR", "MISSING": "HOLD", "AMBIGUOUS": "HUMAN_REVIEW", "FAIL": "EXCEPTION_APPROVED" if value["exception_approved"] else "BLOCK"}
    if value["effective_directive"] != expected[value["policy_result"]]:
        _fail("receipt_mapping")
    for name in ("sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after"):
        if type(value[name]) is not int or value[name] < 0:
            _fail("receipt_counter")
    if type(value["clearance_marker_before"]) is not int or value["clearance_marker_before"] not in (0, 1) or type(value["clearance_marker_after"]) is not int or value["clearance_marker_after"] not in (0, 1) or value["payment_root"] != "0" * 128:
        _fail("receipt_state")
    if value["sequence_after"] != value["sequence_before"] + 1:
        _fail("receipt_sequence")
    advanced = value["effective_directive"] in {"CLEAR", "EXCEPTION_APPROVED"}
    if value["clearance_count_after"] != value["clearance_count_before"] + int(advanced) or value["clearance_marker_after"] != int(bool(value["clearance_marker_before"] or advanced)):
        _fail("receipt_clearance")
    predecessor_continuity = bytes.fromhex(value["predecessor_continuity_root"])
    after_id = bytes.fromhex(value["state_after_id"])
    expected_continuity = _sha(_STATE, predecessor_continuity, after_id, value["effective_directive"].encode("ascii"))
    if bytes.fromhex(value["state_after_continuity_root"]) != expected_continuity:
        _fail("receipt_continuity")
    expected_audit = _sha(_STATE, bytes.fromhex(value["predecessor_audit_head"]), bytes.fromhex(value["decision_id"]), value["effective_directive"].encode("ascii"))
    if bytes.fromhex(value["state_after_audit_head"]) != expected_audit:
        _fail("receipt_audit")
    expected_clearance = bytes.fromhex(value["predecessor_clearance_root"])
    if advanced:
        expected_clearance = _sha(_STATE, expected_clearance, after_id, value["effective_directive"].encode("ascii"))
    if bytes.fromhex(value["state_after_clearance_root"]) != expected_clearance:
        _fail("receipt_clearance_root")
    return value


def _verify(connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None) -> dict[str, Any]:
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != _QUEUE_TABLES | _COMPOSITION_TABLES:
        _fail("schema_tables")
    for table, expected in (("composition_meta", _META), ("composition_transactions", _TX), ("composition_events", _EVENT_COLUMNS), ("composition_outbox", _OUTBOX)):
        if tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")) != expected:
            _fail("schema_columns")
    meta = connection.execute("SELECT * FROM composition_meta WHERE id=1").fetchone()
    if meta is None or int(meta[0]) != 1 or int(meta[1]) != _SCHEMA_VERSION or bytes(meta[15]) != _ZERO or int(meta[16]) < 0:
        _fail("meta")
    config_raw = bytes(meta[2])
    config = _parse_config(config_raw, expected_config)
    config_digest = _sha(_MATERIAL, config_raw)
    if bytes(meta[3]) != config_digest:
        _fail("config_digest")

    transactions = [tuple(row) for row in connection.execute("SELECT * FROM composition_transactions ORDER BY sequence_before,operation_ref").fetchall()]
    status_counts = {"APPLIED": 0, "HELD": 0}
    if any(str(row[2]) == "APPLIED" for row in transactions) and any(str(row[2]) == "HELD" for row in transactions):
        _fail("mixed_semantic_batch")
    if any(str(row[2]) != "APPLIED" for row in transactions):
        _fail("held_transaction")
    transaction_map: dict[bytes, tuple[Any, ...]] = {}
    receipts: dict[bytes, dict[str, Any]] = {}
    previous: dict[str, Any] | None = None
    expected_sequence = 0
    for row in transactions:
        ref = bytes(row[1])
        if len(ref) != 32 or str(row[2]) != "APPLIED" or int(row[3]) != 1 or str(row[4]) not in _POLICY or str(row[5]) not in _DIRECTIVES or any(len(bytes(row[index])) != 64 for index in (6, 7, 8, 9)) or row[12] is None or row[13] is None:
            _fail("transaction_shape")
        status_counts["APPLIED"] += 1
        receipt_raw = bytes(row[12])
        receipt = _parse_state_receipt(receipt_raw)
        if bytes.fromhex(receipt["operation_ref"]) != ref or bytes.fromhex(receipt["state_profile_identity"]) != bytes(row[7]) or bytes.fromhex(receipt["state_before_id"]) != bytes(row[8]) or bytes.fromhex(receipt["state_after_id"]) != bytes(row[9]) or receipt["policy_result"] != str(row[4]) or receipt["effective_directive"] != str(row[5]) or int(receipt["sequence_before"]) != int(row[10]) or int(receipt["sequence_after"]) != int(row[11]) or bytes(row[13]) != _sha(_STATE, receipt_raw):
            _fail("receipt_binding")
        if int(row[10]) != expected_sequence or int(row[11]) != expected_sequence + 1:
            _fail("state_sequence")
        if bytes.fromhex(receipt["state_after_id"]) != _sha(_STATE, b"state-after", ref, int(row[10]).to_bytes(8, "big")) or bytes.fromhex(receipt["state_after_bytes"]) != _sha(_STATE, b"state-bytes", ref, int(row[10]).to_bytes(8, "big")):
            _fail("state_after_binding")
        disposition = _sha(_MATERIAL, b"disposition", ref, str(row[5]).encode("ascii"), bytes(row[7]))
        if bytes(row[6]) != disposition or bytes(row[0]) != _sha(_MATERIAL, b"transaction", disposition):
            _fail("transaction_binding")
        if previous is None:
            if any(bytes.fromhex(receipt[name]) != _ZERO for name in ("state_before_id", "state_before_bytes", "predecessor_continuity_root", "predecessor_audit_head", "predecessor_clearance_root")) or receipt["sequence_before"] != 0 or receipt["clearance_count_before"] != 0 or receipt["clearance_marker_before"] != 0:
                _fail("state_genesis")
        else:
            if receipt["state_before_id"] != previous["state_after_id"] or receipt["state_before_bytes"] != previous["state_after_bytes"] or receipt["predecessor_continuity_root"] != previous["state_after_continuity_root"] or receipt["predecessor_audit_head"] != previous["state_after_audit_head"] or receipt["predecessor_clearance_root"] != previous["state_after_clearance_root"] or receipt["clearance_count_before"] != previous["clearance_count_after"] or receipt["clearance_marker_before"] != previous["clearance_marker_after"] or receipt["epoch"] != previous["epoch"]:
                _fail("state_predecessor")
        previous = receipt
        expected_sequence += 1
        transaction_map[ref] = row
        receipts[ref] = receipt

    outbox_rows = [tuple(row) for row in connection.execute("SELECT * FROM composition_outbox").fetchall()]
    seen_outbox: set[bytes] = set()
    active = 0
    for row in outbox_rows:
        ref = bytes(row[0])
        if len(ref) != 32 or ref in seen_outbox or str(row[1]) not in _DIRECTIVES or str(row[2]) not in {"READY", "LEASED", "ACKNOWLEDGED", "DELIVERY_UNCONFIRMED"} or type(row[3]) is not int or int(row[3]) < 0 or int(row[3]) > int(config["max_attempts"]):
            _fail("outbox_shape")
        if ref not in transaction_map or str(row[1]) != str(transaction_map[ref][5]):
            _fail("outbox_binding")
        seen_outbox.add(ref)
        if str(row[2]) in {"READY", "LEASED", "DELIVERY_UNCONFIRMED"}:
            active += 1
        if str(row[2]) == "LEASED":
            if row[4] is None or row[5] is None or len(bytes(row[5])) != 64 or row[6] is None or int(row[6]) <= 0:
                _fail("outbox_lease")
        elif row[4] is not None or row[5] is not None or row[6] is not None:
            _fail("outbox_lease")
    if seen_outbox != set(transaction_map):
        _fail("outbox_set")

    expected_head = _sha(_GENESIS, config_digest)
    events = [tuple(row) for row in connection.execute("SELECT * FROM composition_events ORDER BY sequence").fetchall()]
    event_refs: set[bytes] = set()
    for index, row in enumerate(events, start=1):
        ref = bytes(row[1])
        if int(row[0]) != index or len(ref) != 32 or str(row[2]) != "APPLIED" or str(row[3]) != "NONE" or str(row[4]) != "READY" or ref not in transaction_map or ref in event_refs:
            _fail("event_chain")
        try:
            payload = json.loads(bytes(row[5]).decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("event_encoding")
        if type(payload) is not dict or set(payload) != _EVENT_PAYLOAD_KEYS["APPLIED"] or bytes(row[5]) != _json_bytes(payload) or payload["operation_ref"] != ref.hex().upper() or payload["proof_accepted"] is not True or payload["policy_result"] != str(transaction_map[ref][4]) or payload["effective_directive"] != str(transaction_map[ref][5]) or payload["state_receipt_digest"] != bytes(transaction_map[ref][13]).hex().upper() or payload["sequence_before"] != int(transaction_map[ref][10]) or payload["sequence_after"] != int(transaction_map[ref][11]):
            _fail("event_binding")
        raw = _json_bytes({"schema": _SCHEMA, "sequence": index, "operation_ref": _hex(ref), "event_kind": str(row[2]), "before_state": str(row[3]), "after_state": str(row[4]), "payload": payload, "at_ms": int(row[8])})
        digest = _sha(_EVENT, index.to_bytes(8, "big"), raw)
        root = _sha(_HEAD, expected_head, index.to_bytes(8, "big"), digest)
        if bytes(row[6]) != digest or bytes(row[7]) != root:
            _fail("event_root")
        expected_head = root
        event_refs.add(ref)
    if event_refs != set(transaction_map) or bytes(meta[4]) != expected_head or int(meta[5]) != len(events) or int(meta[16]) != active:
        _fail("meta_head")

    if previous is None:
        if any(meta[index] is not None for index in range(6, 15)):
            _fail("meta_state")
    else:
        expected_state = ((6, bytes.fromhex(previous["state_profile_identity"])), (7, bytes.fromhex(previous["state_after_id"])), (8, bytes.fromhex(previous["state_after_bytes"])), (9, int(previous["epoch"])), (10, int(previous["sequence_after"])), (11, bytes.fromhex(previous["state_after_continuity_root"])), (12, bytes.fromhex(previous["state_after_audit_head"])), (13, bytes.fromhex(previous["state_after_clearance_root"])), (14, int(previous["clearance_count_after"])))
        if any(meta[index] != value for index, value in expected_state):
            _fail("meta_state")
    return {"schema": _SCHEMA, "composition_id": str(config["composition_id"]), "transaction_counts": status_counts, "event_count": len(events), "outbox_count": len(outbox_rows), "state_sequence": meta[10], "proof_suite_id": None, "production_usable": False, "activation": False}


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    try:
        with closing(sqlite3.connect(str(path), timeout=5.0)) as connection:
            result = _verify(connection, expected_config=expected_config)
            try:
                from app.minimal_clearance_verification_queue_independent import verify_database as verify_queue_database
                verify_queue_database(path)
            except Exception:
                _fail("queue_schema")
            return result
    except sqlite3.Error:
        _fail("database_sqlite")


def verify_database_connection(connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result = _verify(connection, expected_config=expected_config)
    try:
        from app.minimal_clearance_verification_queue_independent import _verify_connection as verify_queue_connection
        verify_queue_connection(connection)
    except Exception:
        _fail("queue_schema")
    return result


__all__ = ("IndependentCompositionError", "verify_database", "verify_database_connection")
