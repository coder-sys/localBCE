"""Independent V8 reconstruction of the durable batch verification image.

This module deliberately does not import the queue writer. It recomputes the
V8 statement, batch root, reservation chain, and lifecycle from SQLite rows and
only exposes a complete VERIFIED batch to the state/composition owner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any, Final, Mapping


class IndependentQueueError(RuntimeError):
    pass


SCHEMA_VERSION: Final[int] = 8
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/v8"
_ADMISSION_CAP: Final[int] = 4_500_000_000
_DATABASE_CAP: Final[int] = 128 * 1024 * 1024
_COUNT: Final[int] = 100
_ATTEMPT_UNITS: Final[int] = 101
_UNITS_CAP: Final[int] = 2**32
_MAX_WINDOW: Final[int] = 3_600_000
_MAX_EPOCH: Final[int] = 2**31
_MAX_RECEIPT: Final[int] = 16 * 1024
_MAX_EVENT: Final[int] = 4096
_STATEMENT_BYTES: Final[int] = 240
_MAGIC: Final[bytes] = b"BL-R100-STMT-V1\x00"
_CIRCUIT: Final[bytes] = bytes.fromhex(
    "982cbb064e424c3734b09a4e8579338092fd3b71d7ae81f7a64174d9ba8919f6"
    "c1fcc3b7c0837d64dc1cec954194e1648f3375bfe7f08a8a9347aa320137efd4"
)
_PROFILE: Final[bytes] = bytes.fromhex(
    "625af0b814643d81b5848bb3ee1f76935e5f05c8232d31c9f6b969e810e28c88"
    "5897a5bab2a89ae3f4721208b64f9b99c677a8e8e90b481aec4fc3ddc9b921fe"
)
_PROFILE_TOKEN: Final[str] = "BLIND-ZKBPP-CUNRUH-RANGE100-V3"
_DIRECTIVES: Final[list[str]] = ["CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"]
_BATCH_LEAF: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-LEAF/v8\x00"
_BATCH_ROOT: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-ROOT/v8\x00"
_GENESIS: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/GENESIS/v8\x00"
_EVENT: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/EVENT/v8\x00"
_HEAD: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/HEAD/v8\x00"
_MATERIAL: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v8\x00"
_MEMBER_SET: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MEMBER-SET/v8\x00"
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_FORBIDDEN = (
    "artifact_ref", "artifact_sha", "source_path", "patient", "provider", "claimant",
    "case_id", "stdout", "stderr", "acceptance_bytes", "raw_proof", "raw_signature",
    "public_key", "credential", "stable_fingerprint", "policy_result", "effective_directive",
)
_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": ("id", "schema_version", "queue_id", "config_json", "config_digest", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "profile_version", "profile_digest", "head_root", "next_transition_seq", "next_admission_seq", "nonterminal_count", "live_lease_count", "computational_units_used", "computational_units_cap", "next_attempt_seq"),
    "queue_batches": ("batch_id", "batch_root", "state_challenge", "ordered_binding", "proof_statement", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "queue_jobs": ("operation_ref", "batch_id", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "batch_position", "batch_root", "approved_source_registry_root", "qualification_flags", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "queue_leases": ("batch_id", "worker_id", "token_digest", "attempt", "claim_sequence", "leased_ms", "expires_ms"),
    "queue_attempts": ("attempt_id", "batch_id", "reservation_before", "reservation_after", "reserved_units", "source_key_epoch", "status", "reserved_ms", "closed_ms", "result_code"),
    "queue_results": ("batch_id", "terminal_status", "receipt_id", "receipt_bytes", "proof_accepted", "source_authenticated", "proof_statement", "batch_root", "source_auth_profile", "source_key_epoch", "result_code", "qualification_flags", "completed_ms", "attempt", "error_code"),
    "queue_transitions": ("sequence", "transition_kind", "batch_id", "before_root", "after_root", "event_bytes", "event_digest"),
}
_TABLES = frozenset(_TABLE_COLUMNS)
_STATUSES = frozenset(("AWAITING_HANDOFF", "QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"))
_TERMINAL = frozenset(("VERIFIED", "REJECTED", "HELD"))


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


def _token(value: object, code: str, maximum: int = 128) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _SAFE_TOKEN.fullmatch(value) is None:
        _fail(code)
    if any(word in value.lower() for word in ("patient", "provider", "claimant", "case", "source_path", "credential", "identity")):
        _fail(code)
    return value


def _code(value: object, code: str = "code") -> str:
    if type(value) is not str or _SAFE_CODE.fullmatch(value) is None:
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
    required = {"schema_version", "handoff_protocol", "queue_id", "capacity", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "profile_version", "profile_digest", "profile_epoch", "source_auth_profile", "source_key_epoch", "qualification_flags", "directives", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required:
        _fail("config_shape")
    if value["schema_version"] != SCHEMA_VERSION or value["handoff_protocol"] != "BATCH_ISSUE_THEN_HANDOFF_V1":
        _fail("config_shape")
    if type(value["capacity"]) is not int or not 100 <= value["capacity"] <= 512:
        _fail("config_capacity")
    if value["admission_cap_bytes"] != _ADMISSION_CAP or type(value["process_tree_peak_cap_bytes"]) is not int or not 0 < value["process_tree_peak_cap_bytes"] < 5_000_000_000 or value["active_process_limit"] != 1:
        _fail("config_limits")
    _token(value["queue_id"], "config_queue_id", 96)
    if value["profile_version"] != _PROFILE_TOKEN:
        _fail("config_profile_version")
    if _parse_hex(value["profile_digest"], 64, "config_profile_digest") != _PROFILE:
        _fail("config_profile_digest")
    if type(value["profile_epoch"]) is not int or value["profile_epoch"] != 3:
        _fail("config_profile_epoch")
    _token(value["source_auth_profile"], "config_source_profile", 96)
    if type(value["source_key_epoch"]) is not int or not 0 <= value["source_key_epoch"] <= _MAX_EPOCH:
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
    if len(row) != len(_TABLE_COLUMNS["queue_jobs"]):
        _fail("job_shape")
    root = None if row[9] is None else _hex(_blob(_db_bytes(row[9], "registry_root"), 64, "registry_root"))
    return _json_bytes({
        "assertion_identifier": str(row[2]),
        "assertion_version": int(row[3]),
        "state_profile_version": str(row[4]),
        "valid_from_ms": int(row[5]),
        "valid_until_ms": int(row[6]),
        "approved_source_registry_root": root,
        "qualification_flags": list(_parse_flags(_db_bytes(row[10], "flags"))),
    })


def _expected_batch_root(rows: tuple[tuple[Any, ...], ...]) -> bytes:
    if len(rows) != _COUNT:
        _fail("batch_member_count")
    ordered = tuple(sorted(rows, key=lambda row: int(row[7])))
    if tuple(int(row[7]) for row in ordered) != tuple(range(_COUNT)):
        _fail("batch_positions")
    leaves = tuple(_sha(_BATCH_LEAF, _u64(int(row[7])), _blob(_db_bytes(row[0], "operation_ref"), 32, "operation_ref"), _template_bytes(row)) for row in ordered)
    return _sha(_BATCH_ROOT, _u64(_COUNT), b"".join(leaves))


def _build_statement(*, batch_root: bytes, state_challenge: bytes, valid_from_ms: int, valid_until_ms: int) -> bytes:
    _blob(batch_root, 64, "batch_root")
    _blob(state_challenge, 32, "state_challenge")
    if type(valid_from_ms) is not int or type(valid_until_ms) is not int or not 0 <= valid_from_ms < valid_until_ms or valid_until_ms - valid_from_ms > _MAX_WINDOW:
        _fail("statement_window")
    statement = _MAGIC + (1).to_bytes(2, "little") + _STATEMENT_BYTES.to_bytes(2, "little") + state_challenge + batch_root[:32] + (3).to_bytes(4, "little") + (1).to_bytes(4, "little") + (1).to_bytes(4, "little") + _u64le(valid_from_ms) + _u64le(valid_until_ms) + _CIRCUIT + _PROFILE
    if len(statement) != _STATEMENT_BYTES:
        _fail("statement_length")
    return statement


def _parse_statement(statement: bytes, *, batch_root: bytes, state_challenge: bytes, valid_from_ms: int, valid_until_ms: int) -> None:
    if type(statement) is not bytes or len(statement) != _STATEMENT_BYTES or statement[:16] != _MAGIC or statement[16:18] != b"\x01\x00" or statement[18:20] != _STATEMENT_BYTES.to_bytes(2, "little"):
        _fail("statement_shape")
    if statement != _build_statement(batch_root=batch_root, state_challenge=state_challenge, valid_from_ms=valid_from_ms, valid_until_ms=valid_until_ms):
        _fail("statement_binding")


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
    _parse_hex(value["proof_statement"], 240, "receipt_statement")
    _parse_hex(value["batch_root"], 64, "receipt_root")
    _token(value["source_auth_profile"], "receipt_source_profile", 96)
    if type(value["source_key_epoch"]) is not int or not 0 <= value["source_key_epoch"] <= _MAX_EPOCH:
        _fail("receipt_source_epoch")
    _code(value["result_code"], "receipt_result_code")
    _parse_flags(_json_bytes({"qualification_flags": value["qualification_flags"]}))
    if value["error_code"] is not None:
        _code(value["error_code"], "receipt_error_code")
    return value


def _forbidden_bytes(blobs: tuple[bytes, ...]) -> None:
    for blob in blobs:
        lowered = blob.lower()
        if any(word.encode("ascii") in lowered for word in _FORBIDDEN):
            _fail("forbidden_durable_data")


def _verify_lifecycle(events: list[dict[str, Any]], status: str, attempt: int) -> None:
    if not events or events[0]["kind"] != "BATCH_ISSUED" or events[0]["status"] != "AWAITING_HANDOFF" or events[0]["attempt"] != 0 or events[0]["error_code"] is not None:
        _fail("lifecycle_issue")
    if status == "AWAITING_HANDOFF":
        if len(events) != 1:
            _fail("lifecycle_awaiting")
        return
    if len(events) < 2 or events[1]["kind"] != "HANDOFF_SUBMITTED" or events[1]["status"] != "QUEUED" or events[1]["attempt"] != 0 or events[1]["error_code"] is not None:
        if status == "HELD" and len(events) == 2 and events[1]["kind"] == "BATCH_HELD" and events[1]["status"] == "HELD" and events[1]["attempt"] == 0:
            return
        _fail("lifecycle_handoff")
    if status == "QUEUED":
        if len(events) != 2:
            _fail("lifecycle_queue")
        return
    if status == "HELD" and len(events) == 3 and events[2]["kind"] == "BATCH_HELD" and events[2]["status"] == "HELD" and events[2]["attempt"] == 0:
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


def _verify_connection(connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    connection.execute("PRAGMA foreign_keys=ON")
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != _TABLES or any(_columns(connection, table) != _TABLE_COLUMNS[table] for table in _TABLES):
        _fail("schema")
    meta = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
    if meta is None or len(meta) != len(_TABLE_COLUMNS["queue_metadata"]):
        _fail("metadata")
    if int(meta[1]) != SCHEMA_VERSION or int(meta[5]) != _ADMISSION_CAP or not 0 < int(meta[6]) < 5_000_000_000 or int(meta[7]) != 1 or _db_bytes(meta[9], "profile_digest") != _PROFILE or int(meta[17]) < 0:
        _fail("metadata")
    config_raw = _db_bytes(meta[3], "config")
    config = _parse_config(config_raw, expected_config)
    config_digest = _sha(_MATERIAL, config_raw)
    if _db_bytes(meta[4], "config_digest") != config_digest or _db_bytes(meta[9], "profile_digest") != _parse_hex(config["profile_digest"], 64, "profile_digest"):
        _fail("config_digest")
    _forbidden_bytes((config_raw,))
    batch_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_batches ORDER BY admission_seq").fetchall()]
    job_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_jobs ORDER BY admission_seq").fetchall()]
    lease_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_leases").fetchall()]
    attempt_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_attempts ORDER BY attempt_id").fetchall()]
    result_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_results").fetchall()]
    transition_rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_transitions ORDER BY sequence").fetchall()]
    if len(lease_rows) > 1 or len(job_rows) != len(batch_rows) * _COUNT:
        _fail("batch_cardinality")
    batch_map = {_db_bytes(row[0], "batch_id"): row for row in batch_rows}
    if len(batch_map) != len(batch_rows) or tuple(int(row[6]) for row in batch_rows) != tuple(range(1, len(batch_rows) + 1)):
        _fail("batch_order")
    job_groups: dict[bytes, list[tuple[Any, ...]]] = {batch_id: [] for batch_id in batch_map}
    status_counts = {status: 0 for status in _STATUSES}
    for index, row in enumerate(job_rows, start=1):
        ref = _blob(_db_bytes(row[0], "operation_ref"), 32, "operation_ref")
        batch_id = _blob(_db_bytes(row[1], "batch_id"), 32, "batch_id")
        if batch_id not in batch_map or int(row[12]) != index or not 0 <= int(row[13]) <= 1:
            _fail("job_binding")
        if str(row[11]) not in _STATUSES:
            _fail("job_status")
        if type(row[2]) is not str or _SAFE_TOKEN.fullmatch(row[2]) is None or any(word in row[2].lower() for word in ("patient", "provider", "claimant", "case")):
            _fail("job_assertion")
        if type(row[3]) is not int or not 1 <= int(row[3]) <= 2**31 or type(row[4]) is not str or _SAFE_TOKEN.fullmatch(row[4]) is None:
            _fail("job_metadata")
        if type(row[5]) is not int or type(row[6]) is not int or not 0 <= int(row[5]) < int(row[6]) or int(row[6]) - int(row[5]) > _MAX_WINDOW:
            _fail("job_window")
        if type(row[7]) is not int or not 0 <= int(row[7]) < _COUNT or _db_bytes(row[8], "batch_root") != _db_bytes(batch_map[batch_id][1], "batch_root") or row[9] is not None and len(_db_bytes(row[9], "registry_root")) != 64:
            _fail("job_statement")
        _parse_flags(_db_bytes(row[10], "flags"))
        status_counts[str(row[11])] += 1
        job_groups[batch_id].append(row)
        _forbidden_bytes((_db_bytes(row[10], "flags"),))
    for batch_id, row in batch_map.items():
        group = tuple(job_groups[batch_id])
        if len(group) != _COUNT or tuple(sorted(int(item[7]) for item in group)) != tuple(range(_COUNT)):
            _fail("batch_members")
        root = _blob(_db_bytes(row[1], "batch_root"), 64, "batch_root")
        if _expected_batch_root(group) != root or _db_bytes(row[3], "ordered_binding") != root[:32]:
            _fail("batch_root_binding")
        if int(row[7]) not in (0, 1) or str(row[5]) not in _STATUSES:
            _fail("batch_status")
        if any(str(item[11]) != str(row[5]) or int(item[13]) != int(row[7]) for item in group):
            _fail("batch_status_binding")
        common_window = (int(group[0][5]), int(group[0][6]))
        if any((int(item[5]), int(item[6])) != common_window for item in group):
            _fail("batch_window")
        _parse_statement(_db_bytes(row[4], "proof_statement"), batch_root=root, state_challenge=_blob(_db_bytes(row[2], "state_challenge"), 32, "state_challenge"), valid_from_ms=common_window[0], valid_until_ms=common_window[1])
        if _db_bytes(row[4], "proof_statement")[52:84] != _db_bytes(row[3], "ordered_binding"):
            _fail("ordered_binding")
    result_map = {_db_bytes(row[0], "result_batch_id"): row for row in result_rows}
    if len(result_map) != len(result_rows):
        _fail("result_duplicate")
    for batch_id, row in batch_map.items():
        status = str(row[5])
        result = result_map.get(batch_id)
        if (status in _TERMINAL and result is None) or (status not in _TERMINAL and result is not None):
            _fail("result_set")
        if result is not None:
            if str(result[1]) != status or int(result[13]) != int(row[7]) or int(result[4]) not in (0, 1) or int(result[5]) not in (0, 1) or _db_bytes(result[6], "result_statement") != _db_bytes(row[4], "proof_statement") or _db_bytes(result[7], "result_root") != _db_bytes(row[1], "batch_root") or str(result[8]) != str(config["source_auth_profile"]) or int(result[9]) != int(config["source_key_epoch"]) or _parse_flags(_db_bytes(result[11], "flags")) != tuple(config["qualification_flags"]):
                _fail("result_binding")
            receipt = _parse_receipt(_db_bytes(result[3], "receipt"))
            if _parse_hex(receipt["batch_id"], 32, "receipt_batch_id") != batch_id or _parse_hex(receipt["proof_statement"], 240, "receipt_statement") != _db_bytes(row[4], "proof_statement") or _parse_hex(receipt["batch_root"], 64, "receipt_root") != _db_bytes(row[1], "batch_root") or receipt["source_auth_profile"] != config["source_auth_profile"] or int(receipt["source_key_epoch"]) != int(config["source_key_epoch"]) or tuple(receipt["qualification_flags"]) != tuple(config["qualification_flags"]):
                _fail("receipt_binding")
            if bool(result[4]) != bool(receipt["proof_accepted"]) or bool(result[5]) != bool(receipt["source_authenticated"]) or str(result[10]) != receipt["result_code"] or (None if result[14] is None else str(result[14])) != receipt["error_code"]:
                _fail("receipt_result_binding")
            if status == "VERIFIED" and not (bool(result[4]) and bool(result[5]) and receipt["error_code"] is None):
                _fail("verified_acceptance")
            if status != "VERIFIED" and bool(result[4]) and bool(result[5]):
                _fail("terminal_acceptance")
            expected_receipt_id = _sha(_MATERIAL, b"receipt", batch_id, _u64(int(row[7])))[:32]
            if _db_bytes(result[2], "receipt_id") != expected_receipt_id or len(_db_bytes(result[3], "receipt")) > _MAX_RECEIPT:
                _fail("receipt_id")
            _forbidden_bytes((_db_bytes(result[3], "receipt"), str(result[10]).encode("ascii"), _db_bytes(result[11], "flags")))
    if set(result_map) != {batch_id for batch_id, row in batch_map.items() if str(row[5]) in _TERMINAL}:
        _fail("result_set")
    lease_map = {_db_bytes(row[0], "lease_batch_id"): row for row in lease_rows}
    attempt_map = {_db_bytes(row[1], "attempt_batch_id"): row for row in attempt_rows}
    if len(attempt_map) != len(attempt_rows):
        _fail("attempt_duplicate")
    previous_after = 0
    for expected_id, row in enumerate(attempt_rows, start=1):
        batch_id = _blob(_db_bytes(row[1], "attempt_batch"), 32, "attempt_batch")
        before, after, units = int(row[2]), int(row[3]), int(row[4])
        if int(row[0]) != expected_id or batch_id not in batch_map or before != previous_after or after != before + _ATTEMPT_UNITS or units != _ATTEMPT_UNITS or not 0 <= int(row[5]) <= _MAX_EPOCH or str(row[6]) not in {"RESERVED", "ACCEPTED", "REJECTED", "HELD"} or int(row[7]) < 0 or (row[8] is not None and int(row[8]) < int(row[7])):
            _fail("attempt_chain")
        previous_after = after
        batch = batch_map[batch_id]
        if int(batch[7]) != 1 or int(row[5]) != int(config["source_key_epoch"]):
            _fail("attempt_binding")
        if str(batch[5]) == "LEASED" and str(row[6]) != "RESERVED":
            _fail("attempt_status")
        if str(batch[5]) == "VERIFIED" and str(row[6]) != "ACCEPTED":
            _fail("attempt_status")
        if str(batch[5]) == "REJECTED" and str(row[6]) != "REJECTED":
            _fail("attempt_status")
        if str(batch[5]) == "HELD" and str(row[6]) != "HELD":
            _fail("attempt_status")
        result = result_map.get(batch_id)
        if result is not None and (result[10] is None or str(row[9]) != str(result[10])):
            _fail("attempt_result_binding")
    if int(meta[15]) != previous_after or int(meta[16]) != _UNITS_CAP or int(meta[17]) != len(attempt_rows):
        _fail("attempt_ledger")
    for batch_id, row in batch_map.items():
        status = str(row[5])
        attempt = int(row[7])
        attempt_row = attempt_map.get(batch_id)
        if attempt == 0 and attempt_row is not None:
            _fail("attempt_unexpected")
        if attempt == 1 and attempt_row is None:
            _fail("attempt_missing")
        if status == "LEASED":
            lease = lease_map.get(batch_id)
            if lease is None or int(lease[3]) != 1 or type(lease[1]) is not str or _SAFE_TOKEN.fullmatch(lease[1]) is None or len(_db_bytes(lease[2], "lease_digest")) != 64 or int(lease[6]) <= int(lease[5]):
                _fail("lease_binding")
        elif batch_id in lease_map:
            _fail("lease_status")
    if set(lease_map) != {batch_id for batch_id, row in batch_map.items() if str(row[5]) == "LEASED"}:
        _fail("lease_set")
    expected_nonterminal = sum(1 for row in batch_map.values() if str(row[5]) in {"AWAITING_HANDOFF", "QUEUED", "LEASED"})
    if int(meta[13]) != expected_nonterminal or int(meta[14]) != len(lease_rows):
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
        allowed = {"schema", "sequence", "kind", "batch_id", "status", "error_code", "attempt", "at_ms", "member_count", "reservation_before", "reservation_after", "receipt_id"}
        if set(event) - allowed or "member_count" not in event or event["member_count"] != _COUNT:
            _fail("transition_fields")
        if str(event["kind"]) == "ATTEMPT_RESERVED":
            if set(event) != allowed - {"receipt_id"} or type(event.get("reservation_before")) is not int or type(event.get("reservation_after")) is not int or event["reservation_after"] != event["reservation_before"] + _ATTEMPT_UNITS:
                _fail("transition_reservation")
        elif set(event) != allowed - {"reservation_before", "reservation_after", "receipt_id"}:
            _fail("transition_fields")
        digest = _sha(_EVENT, _u64(index), _db_bytes(row[5], "event"))
        after = _sha(_HEAD, expected_head, _u64(index), digest)
        if _db_bytes(row[6], "event_digest") != digest or _db_bytes(row[4], "transition_after") != after:
            _fail("transition_root")
        expected_head = after
        events_by_batch[batch_id].append(event)
        _forbidden_bytes((_db_bytes(row[5], "event"),))
    if _db_bytes(meta[10], "head_root") != expected_head or int(meta[11]) != len(transition_rows) or int(meta[12]) != len(job_rows):
        _fail("head_binding")
    for batch_id, row in batch_map.items():
        _verify_lifecycle(events_by_batch[batch_id], str(row[5]), int(row[7]))
    return {"schema": _SCHEMA, "config": config, "config_digest": config_digest, "meta": tuple(meta), "batches": batch_map, "jobs": job_groups, "results": result_map, "transitions": transition_rows, "events": events_by_batch, "head_root": _db_bytes(meta[10], "head_root"), "status_counts": status_counts, "transition_count": len(transition_rows), "verified_count": status_counts["VERIFIED"], "proof_bytes_persisted": False, "path_custody": False, "proof_suite_id": None, "production_usable": False, "activation": False}


def _verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    try:
        if path.stat().st_size > _DATABASE_CAP:
            _fail("database_bounds")
        with closing(sqlite3.connect(str(path), timeout=5.0)) as connection:
            connection.execute("BEGIN")
            return _verify_connection(connection, expected_config=expected_config)
    except sqlite3.Error:
        _fail("database_sqlite")


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    verified = _verify_database(path, expected_config=expected_config)
    return {key: value for key, value in verified.items() if key not in {"config", "config_digest", "meta", "batches", "jobs", "results", "transitions", "events"}}


def _job_from_rows(config: Mapping[str, Any], config_digest: bytes, row: tuple[Any, ...], result: tuple[Any, ...]) -> IndependentVerifiedQueueJob:
    receipt_raw = bytes(result[3])
    _parse_receipt(receipt_raw)
    return IndependentVerifiedQueueJob(
        str(config["queue_id"]), config_digest, bytes(row[0]), str(row[11]), bool(result[4]), int(row[13]), receipt_raw, bytes(result[2]),
        str(row[2]), int(row[3]), str(row[4]), int(row[5]), int(row[6]), int(row[7]), None if row[8] is None else bytes(row[8]), None if row[9] is None else bytes(row[9]), str(config["profile_version"]), str(result[10]), tuple(_parse_flags(bytes(result[11]))),
    )


def _empty_batch(config_digest: bytes, head_root: bytes, transition_count: int) -> IndependentVerifiedQueueBatch:
    return IndependentVerifiedQueueBatch(IndependentBatchAcceptance(bytes(64), head_root, config_digest, (), bytes(64), bytes(32), 0, transition_count), ())


def _promotion_batch(verified: dict[str, Any], batch_id: bytes) -> IndependentVerifiedQueueBatch:
    row = verified["batches"].get(batch_id)
    if row is None:
        _fail("batch_selector")
    if str(row[5]) != "VERIFIED":
        _fail("batch_incomplete")
    rows = tuple(sorted(verified["jobs"][batch_id], key=lambda item: int(item[7])))
    result = verified["results"].get(batch_id)
    if len(rows) != _COUNT or result is None or not bool(result[4]) or not bool(result[5]) or any(str(item[11]) != "VERIFIED" for item in rows):
        _fail("batch_incomplete")
    config = verified["config"]
    jobs = tuple(_job_from_rows(config, verified["config_digest"], item, result) for item in rows)
    refs = tuple(job.operation_ref for job in jobs)
    member_digest = _sha(_MEMBER_SET, _u64(_COUNT), b"".join(refs))
    events = verified["events"][batch_id]
    issued_sequence = next(event["sequence"] for event in events if event["kind"] == "BATCH_ISSUED")
    before = bytes(verified["transitions"][int(issued_sequence) - 1][3])
    batch = IndependentBatchAcceptance(before, verified["head_root"], verified["config_digest"], refs, member_digest, batch_id, _COUNT, int(issued_sequence) - 1)
    return IndependentVerifiedQueueBatch(batch, jobs)


def read_verified_batch(path: Path, selector: bytes | None = None) -> IndependentVerifiedQueueBatch:
    verified = _verify_database(path)
    if selector is not None and (type(selector) is not bytes or len(selector) != 32):
        _fail("batch_selector")
    if selector is not None:
        return _promotion_batch(verified, selector)
    candidates = [(int(row[6]), batch_id) for batch_id, row in verified["batches"].items() if str(row[5]) == "VERIFIED" and bool(verified["results"].get(batch_id) and verified["results"][batch_id][4] and verified["results"][batch_id][5])]
    if not candidates:
        return _empty_batch(verified["config_digest"], verified["head_root"], verified["transition_count"])
    _admission, batch_id = min(candidates)
    return _promotion_batch(verified, batch_id)


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _DATABASE_CAP:
        _fail("export_bytes")
    with tempfile.TemporaryDirectory(prefix="bl-v8-export-") as directory:
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
