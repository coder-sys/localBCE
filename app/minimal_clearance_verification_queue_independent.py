"""Independent binary reconstruction boundary for the local verification queue.

The public export is the exact bounded SQLite image.  This module owns no
producer validation and never imports a verifier or a clearance state owner.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
from typing import Any, Final, Mapping

from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes


class IndependentQueueError(RuntimeError):
    """Bounded independent reconstruction failure."""


@dataclass(frozen=True, slots=True)
class IndependentVerifiedQueueJob:
    queue_id: str
    config_digest: bytes
    verifier_sha256: bytes
    job_id: str
    operation_id: bytes
    attempt: int
    receipt_bytes: bytes
    receipt_id: bytes
    acceptance_bytes: bytes
    proof_acceptance_digest: bytes
    artifact_ref: str
    artifact_bytes: int
    artifact_sha256: bytes
    artifact_sha3_512: bytes
    circuit_id: bytes
    peak_job_commit_bytes: int
    cap_bytes: int
    cap_enforced: bool
    active_process_limit: int
    timed_out: bool
    exit_code: int
    stdout_sha3_512: bytes
    stderr_sha3_512: bytes


_SCHEMA_VERSION: Final[int] = 2
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFICATION-QUEUE/v2"
_STATUS: Final = frozenset({"QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"})
_NONTERMINAL: Final = frozenset({"QUEUED", "LEASED"})
_TERMINAL: Final = frozenset({"VERIFIED", "REJECTED", "HELD"})
_MAX_DATABASE: Final[int] = 64 * 1024 * 1024
_MAX_CAPACITY: Final[int] = 512
_MAX_WORKERS: Final[int] = 4
_MAX_TERMINAL_GROWTH: Final[int] = 64 * 1024
_PAGE_SIZE: Final[int] = 4096
_MAX_PAGES: Final[int] = _MAX_DATABASE // _PAGE_SIZE
_MAX_ERROR: Final[int] = 96
_MAX_ACCEPTANCE: Final[int] = 65_536
_MAX_RECEIPT: Final[int] = 16 * 1024
_CAP_BYTES: Final[int] = 5_000_000_000
_ACTIVE_PROCESS_LIMIT: Final[int] = 1
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_MATERIAL_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/MATERIAL/v1\x00"
_GENESIS_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/GENESIS/v1\x00"
_OPERATION_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/OPERATION/v1\x00"
_EVENT_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/EVENT/v1\x00"
_HEAD_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/HEAD/v1\x00"
_ACCEPTANCE_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/ACCEPTANCE/v1\x00"
_RECEIPT_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/RECEIPT/v1\x00"
_LEASE_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/LEASE-FENCE/v2\x00"
_LEASE_RAW_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/LEASE-RAW/v2\x00"
RESTORE_CAPABILITY_LIMITATION_COUNT = 0

_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": ("id", "schema_version", "queue_id", "config_json", "config_digest", "verifier_sha256", "artifact_bytes_cap", "head_root", "next_transition_seq", "next_admission_seq", "storage_used_bytes", "storage_reserved_bytes", "nonterminal_count", "live_lease_count"),
    "queue_jobs": ("job_id", "operation_id", "material_digest", "artifact_ref", "artifact_bytes", "artifact_sha256", "artifact_sha3_512", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "queue_operations": ("operation_id", "job_id", "material_digest", "result_status", "result_receipt", "result_error_code"),
    "queue_leases": ("job_id", "worker_id", "token", "attempt", "leased_ms", "expires_ms"),
    "queue_results": ("operation_id", "job_id", "terminal_status", "receipt_bytes", "error_code", "completed_ms"),
    "queue_transitions": ("sequence", "transition_kind", "job_id", "operation_id", "before_root", "after_root", "event_bytes", "event_digest"),
}
_TABLES = frozenset(_TABLE_COLUMNS)
_TRIGGERS = frozenset({"queue_jobs_no_delete", "queue_jobs_no_update", "queue_operations_no_delete", "queue_transitions_no_update", "queue_transitions_no_delete", "queue_metadata_immutable"})
_INDEXES = frozenset({"queue_jobs_status_eligible", "queue_leases_expiry", "queue_leases_worker_unique"})


def _fail(code: str) -> None:
    try:
        raise IndependentQueueError(code)
    except IndependentQueueError as fixed:
        fixed.__cause__ = None
        fixed.__context__ = None
        fixed.__suppress_context__ = True
        raise


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _lease_raw(queue_id: str, config_digest: bytes, job_id: str, worker_id: str, attempt: int, leased_ms: int, expires_ms: int) -> bytes:
    return _sha(_LEASE_RAW_DOMAIN, queue_id.encode("ascii"), config_digest, job_id.encode("ascii"), worker_id.encode("ascii"), attempt.to_bytes(8, "big"), leased_ms.to_bytes(8, "big"), expires_ms.to_bytes(8, "big"))[:24]


def _lease_digest(queue_id: str, config_digest: bytes, job_id: str, worker_id: str, attempt: int, leased_ms: int, expires_ms: int, raw_token: bytes) -> bytes:
    # This reconstructs a fencing identity only; it is not authentication.
    return _sha(_LEASE_DOMAIN, queue_id.encode("ascii"), config_digest, job_id.encode("ascii"), worker_id.encode("ascii"), attempt.to_bytes(8, "big"), leased_ms.to_bytes(8, "big"), expires_ms.to_bytes(8, "big"), raw_token)


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("independent_json")


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _blob(value: Any, length: int | None, code: str, *, nullable: bool = False) -> bytes | None:
    if value is None and nullable:
        return None
    if type(value) is not str or value != value.upper() or re.fullmatch(r"[0-9A-F]+\Z", value) is None:
        _fail(code)
    try:
        result = bytes.fromhex(value)
    except ValueError:
        _fail(code)
    if length is not None and len(result) != length:
        _fail(code)
    return result


def _token(value: Any, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _fail(code)
    return value


def _code(value: Any, code: str) -> str:
    if type(value) is not str or len(value) > _MAX_ERROR or _CODE.fullmatch(value) is None:
        _fail(code)
    return value


def _integer(value: Any, code: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(code)
    return value


def _parse_config(value: Any) -> tuple[dict[str, Any], bytes, bytes]:
    keys = {"schema_version", "queue_id", "capacity", "lease_seconds", "max_attempts", "max_worker_concurrency", "verifier_sha256", "artifact_bytes_cap", "retryable_codes"}
    if type(value) is not dict or set(value) != keys or value["schema_version"] != _SCHEMA_VERSION:
        _fail("config_keys")
    queue_id = _token(value["queue_id"], "config_queue_id")
    capacity = _integer(value["capacity"], "config_capacity", minimum=1)
    lease_seconds = _integer(value["lease_seconds"], "config_lease_seconds", minimum=1)
    if capacity > _MAX_CAPACITY or lease_seconds > 3600 or value["max_attempts"] != 3 or value["max_worker_concurrency"] != _MAX_WORKERS:
        _fail("config_bounds")
    artifact_cap = _integer(value["artifact_bytes_cap"], "config_artifact_cap", minimum=1)
    if artifact_cap > 512 * 1024 * 1024:
        _fail("config_artifact_cap")
    _blob(value["verifier_sha256"], 32, "config_verifier")
    retryable = value["retryable_codes"]
    if type(retryable) is not list or not retryable or any(type(item) is not str or _CODE.fullmatch(item) is None for item in retryable) or retryable != sorted(set(retryable)):
        _fail("config_retryable")
    canonical = _json_bytes(value)
    return value, canonical, _sha(_MATERIAL_DOMAIN, canonical)


def _parse_evidence(value: Any, verifier: bytes) -> dict[str, Any]:
    keys = {"artifact_bytes", "artifact_sha256", "artifact_sha3_512", "verifier_sha256", "circuit_id", "acceptance_bytes", "proof_acceptance_digest", "peak_job_commit_bytes", "cap_bytes", "cap_enforced", "active_process_limit", "timed_out", "exit_code", "stdout_sha3_512", "stderr_sha3_512"}
    if type(value) is not dict or set(value) != keys:
        _fail("receipt_evidence_keys")
    for field in ("artifact_bytes", "peak_job_commit_bytes", "cap_bytes", "active_process_limit", "exit_code"):
        if type(value[field]) is not int:
            _fail("receipt_evidence_types")
    if type(value["cap_enforced"]) is not bool or type(value["timed_out"]) is not bool:
        _fail("receipt_evidence_types")
    result = dict(value)
    result["artifact_sha256"] = _blob(value["artifact_sha256"], 32, "receipt_artifact_sha256")
    result["artifact_sha3_512"] = _blob(value["artifact_sha3_512"], 64, "receipt_artifact_sha3")
    result["verifier_sha256"] = _blob(value["verifier_sha256"], 32, "receipt_verifier")
    result["circuit_id"] = _blob(value["circuit_id"], 32, "receipt_circuit")
    result["acceptance_bytes"] = _blob(value["acceptance_bytes"], None, "receipt_acceptance_bytes")
    if not 0 < len(result["acceptance_bytes"]) <= _MAX_ACCEPTANCE:
        _fail("receipt_acceptance_bounds")
    result["proof_acceptance_digest"] = _blob(value["proof_acceptance_digest"], 64, "receipt_acceptance")
    result["stdout_sha3_512"] = _blob(value["stdout_sha3_512"], 64, "receipt_stdout")
    result["stderr_sha3_512"] = _blob(value["stderr_sha3_512"], 64, "receipt_stderr")
    if result["verifier_sha256"] != verifier or result["cap_bytes"] != _CAP_BYTES or result["cap_enforced"] is not True or result["active_process_limit"] != _ACTIVE_PROCESS_LIMIT or result["timed_out"] is not False or result["exit_code"] != 0 or not 0 <= result["peak_job_commit_bytes"] <= _CAP_BYTES:
        _fail("receipt_containment_binding")
    try:
        acceptance = parse_acceptance_bytes(result["acceptance_bytes"])
    except Exception:
        _fail("receipt_acceptance_invalid")
    if acceptance.canonical_bytes() != result["acceptance_bytes"] or acceptance.artifact_bytes != result["artifact_bytes"] or acceptance.artifact_sha256 != result["artifact_sha256"] or acceptance.artifact_digest != result["artifact_sha3_512"] or acceptance.circuit_id != result["circuit_id"] or _sha(_ACCEPTANCE_DOMAIN, result["acceptance_bytes"]) != result["proof_acceptance_digest"]:
        _fail("receipt_acceptance_binding")
    return result


def _parse_receipt(value: Any, config: Mapping[str, Any]) -> dict[str, Any]:
    keys = {"schema", "queue_id", "job_id", "operation_id", "attempt", "evidence", "receipt_id"}
    if type(value) is not dict or set(value) != keys or value["schema"] != _SCHEMA or value["queue_id"] != config["queue_id"]:
        _fail("receipt_keys")
    job_id = _token(value["job_id"], "receipt_job_id")
    operation = _blob(value["operation_id"], 64, "receipt_operation")
    receipt_id = _blob(value["receipt_id"], 64, "receipt_id")
    attempt = _integer(value["attempt"], "receipt_attempt", minimum=1)
    evidence = _parse_evidence(value["evidence"], _blob(config["verifier_sha256"], 32, "config_verifier"))
    without_id = {"schema": _SCHEMA, "queue_id": config["queue_id"], "job_id": job_id, "operation_id": _hex(operation), "attempt": attempt, "evidence": {key: (_hex(item) if isinstance(item, bytes) else item) for key, item in evidence.items()}}
    if receipt_id != _sha(_RECEIPT_DOMAIN, _json_bytes(without_id)):
        _fail("receipt_identity")
    return {"job_id": job_id, "operation_id": operation, "attempt": attempt, "evidence": evidence, "receipt_id": receipt_id}


def _event_expected(kind: str, event: Any) -> None:
    if kind == "ADMIT": keys = {"at_ms", "status", "admission_seq"}
    elif kind == "CLAIM": keys = {"at_ms", "status", "attempt", "worker_id", "expires_ms"}
    elif kind in {"LEASE_EXPIRE_QUEUED", "LEASE_EXPIRE_HELD", "RETRY_QUEUED"}: keys = {"at_ms", "status", "attempt", "error_code"}
    elif kind.startswith("COMPLETE_"): keys = {"at_ms", "status", "attempt", "error_code", "receipt_digest"}
    else: _fail("transition_kind")
    if type(event) is not dict or set(event) != keys or type(event["status"]) is not str or event["status"] not in _STATUS:
        _fail("transition_event_keys")
    _integer(event["at_ms"], "transition_time")
    if kind == "ADMIT":
        if event["status"] != "QUEUED": _fail("transition_admit_status")
        _integer(event["admission_seq"], "transition_admission", minimum=1)
    elif kind == "CLAIM":
        if event["status"] != "LEASED": _fail("transition_claim_status")
        _integer(event["attempt"], "transition_attempt", minimum=1); _token(event["worker_id"], "transition_worker"); _integer(event["expires_ms"], "transition_expiry", minimum=1)
    else:
        _integer(event["attempt"], "transition_attempt", minimum=1)
        if event["error_code"] is not None: _code(event["error_code"], "transition_error")
        if kind == "RETRY_QUEUED" and event["status"] != "QUEUED": _fail("transition_retry_status")
        if kind == "LEASE_EXPIRE_QUEUED" and (event["status"] != "QUEUED" or event["error_code"] != "lease_expired"): _fail("transition_expire_status")
        if kind == "LEASE_EXPIRE_HELD" and (event["status"] != "HELD" or event["error_code"] != "lease_expired"): _fail("transition_expire_status")
        if kind.startswith("COMPLETE_"):
            expected = kind.removeprefix("COMPLETE_")
            if expected not in _TERMINAL or event["status"] != expected: _fail("transition_complete_status")
            if event["receipt_digest"] is not None: _blob(event["receipt_digest"], 64, "transition_receipt_digest")


def _path_identity(path: Path, *, allow_missing: bool = False) -> tuple[int, int, int, int, int] | None:
    if not isinstance(path, Path): _fail("database_path")
    try: item = os.lstat(path)
    except FileNotFoundError:
        if allow_missing: return None
        _fail("database_path")
    except (OSError, ValueError): _fail("database_path")
    attrs = int(getattr(item, "st_file_attributes", 0))
    if not stat.S_ISREG(item.st_mode) or int(item.st_nlink) != 1 or bool(attrs & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))): _fail("database_path")
    if int(item.st_size) > _MAX_DATABASE: _fail("database_capacity")
    return (int(item.st_dev), int(item.st_ino), int(item.st_nlink), int(item.st_size), int(item.st_mtime_ns))


def _owned_directory(path: Path) -> bool:
    try:
        item = os.lstat(path); attrs = int(getattr(item, "st_file_attributes", 0))
        return stat.S_ISDIR(item.st_mode) and int(item.st_nlink) == 1 and not bool(attrs & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
    except (OSError, ValueError): return False


def _fsync_parent(path: Path) -> None:
    global RESTORE_CAPABILITY_LIMITATION_COUNT
    flags = int(getattr(os, "O_RDONLY", 0)) | int(getattr(os, "O_DIRECTORY", 0))
    descriptor: int | None = None
    try:
        descriptor = os.open(str(path.parent), flags)
        os.fsync(descriptor)
    except (OSError, ValueError):
        RESTORE_CAPABILITY_LIMITATION_COUNT += 1
    finally:
        if descriptor is not None:
            try: os.close(descriptor)
            except OSError: pass


def _schema(connection: sqlite3.Connection) -> None:
    objects = connection.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
    expected_objects = {("table", name) for name in _TABLES} | {("trigger", name) for name in _TRIGGERS} | {("index", name) for name in _INDEXES}
    if {(str(kind), str(name)) for kind, name in objects} != expected_objects: _fail("database_objects")
    for table, columns in _TABLE_COLUMNS.items():
        if tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()) != columns: _fail("database_columns")
    mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
    is_memory = not any(str(row[2]) for row in connection.execute("PRAGMA database_list").fetchall())
    if int(connection.execute("PRAGMA page_size").fetchone()[0]) != _PAGE_SIZE or mode != "delete" and not (is_memory and mode == "memory") or int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2 or not 1 <= int(connection.execute("PRAGMA page_count").fetchone()[0]) <= _MAX_PAGES: _fail("database_pages")


def _verify_connection(connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    _schema(connection)
    meta_rows = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchall()
    if len(meta_rows) != 1: _fail("metadata_count")
    meta = tuple(meta_rows[0])
    try: config_value = json.loads(bytes(meta[3]).decode("ascii"))
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError): _fail("metadata_config")
    config, canonical, config_digest = _parse_config(config_value); verifier = _blob(config["verifier_sha256"], 32, "config_verifier")
    if bytes(meta[3]) != canonical or bytes(meta[4]) != config_digest or bytes(meta[5]) != verifier or int(meta[6]) != config["artifact_bytes_cap"]: _fail("metadata_binding")
    if expected_config is not None:
        expected, _, _ = _parse_config(dict(expected_config))
        if expected != config: _fail("expected_config_mismatch")
    jobs = connection.execute("SELECT * FROM queue_jobs ORDER BY admission_seq").fetchall(); operations = connection.execute("SELECT * FROM queue_operations ORDER BY job_id").fetchall(); leases = connection.execute("SELECT * FROM queue_leases ORDER BY job_id").fetchall(); results = connection.execute("SELECT * FROM queue_results ORDER BY job_id").fetchall(); transitions = connection.execute("SELECT * FROM queue_transitions ORDER BY sequence").fetchall()
    if len(jobs) != int(meta[9]) or len(transitions) != int(meta[8]): _fail("metadata_counts")
    page_bytes = int(connection.execute("PRAGMA page_count").fetchone()[0]) * _PAGE_SIZE
    if int(meta[10]) != page_bytes or int(meta[11]) != int(meta[12]) * _MAX_TERMINAL_GROWTH or int(meta[12]) != sum(1 for row in jobs if row[7] in _NONTERMINAL) or int(meta[13]) != len(leases) or page_bytes + int(meta[11]) > _MAX_DATABASE: _fail("metadata_counters")
    if len(leases) > _MAX_WORKERS: _fail("worker_capacity")
    job_map: dict[str, tuple[Any, ...]] = {}; operation_ids: set[bytes] = set()
    for index, row in enumerate(jobs, 1):
        if len(row) != 14: _fail("job_shape")
        job_id, operation, material, ref, size, sha256, sha3, status, admission, attempt, next_ms, created, updated, error = row
        if type(job_id) is not str or _TOKEN.fullmatch(job_id) is None or type(operation) is not bytes or len(operation) != 64 or operation in operation_ids or type(material) is not bytes or len(material) != 64 or admission != index: _fail("job_identity")
        if type(ref) is not str or _TOKEN.fullmatch(ref) is None or type(size) is not int or not 0 < size <= config["artifact_bytes_cap"] or type(sha256) is not bytes or len(sha256) != 32 or type(sha3) is not bytes or len(sha3) != 64 or status not in _STATUS or type(attempt) is not int or not 0 <= attempt <= 3: _fail("job_fields")
        if any(type(item) is not int or item < 0 for item in (next_ms, created, updated)) or (error is not None and (type(error) is not str or _CODE.fullmatch(error) is None)): _fail("job_fields")
        metadata = {"artifact_ref": ref, "artifact_bytes": size, "artifact_sha256": _hex(sha256), "artifact_sha3_512": _hex(sha3)}
        expected_material = _sha(_MATERIAL_DOMAIN, config["queue_id"].encode("ascii"), job_id.encode("ascii"), _json_bytes(metadata), verifier); expected_operation = _sha(_OPERATION_DOMAIN, config["queue_id"].encode("ascii"), job_id.encode("ascii"), expected_material)
        if material != expected_material or operation != expected_operation: _fail("job_material")
        job_map[job_id] = tuple(row); operation_ids.add(operation)
    if len(operations) != len(jobs): _fail("operation_count")
    operation_map: dict[bytes, tuple[Any, ...]] = {}
    for row in operations:
        if len(row) != 6 or type(row[0]) is not bytes or len(row[0]) != 64 or row[0] in operation_map or row[1] not in job_map or row[0] != job_map[row[1]][1] or row[2] != job_map[row[1]][2]: _fail("operation_binding")
        if row[3] is not None and row[3] not in _TERMINAL: _fail("operation_status")
        if row[4] is not None and (type(row[4]) is not bytes or len(row[4]) > _MAX_RECEIPT): _fail("operation_receipt")
        if row[5] is not None and (type(row[5]) is not str or _CODE.fullmatch(row[5]) is None): _fail("operation_error")
        operation_map[bytes(row[0])] = tuple(row)
    lease_map: dict[str, tuple[Any, ...]] = {}; worker_ids: set[str] = set()
    for row in leases:
        if len(row) != 6 or row[0] in lease_map or row[0] not in job_map or job_map[row[0]][7] != "LEASED" or type(row[1]) is not str or not _TOKEN.fullmatch(row[1]) or row[1] in worker_ids or type(row[2]) is not bytes or len(row[2]) != 64 or row[3] != job_map[row[0]][9] or type(row[4]) is not int or type(row[5]) is not int or row[5] <= row[4]: _fail("lease_binding")
        expected_token = _lease_digest(
            config["queue_id"], config_digest, str(row[0]), str(row[1]), int(row[3]), int(row[4]), int(row[5]),
            _lease_raw(config["queue_id"], config_digest, str(row[0]), str(row[1]), int(row[3]), int(row[4]), int(row[5])),
        )
        if bytes(row[2]) != expected_token: _fail("lease_fence")
        lease_map[str(row[0])] = tuple(row); worker_ids.add(str(row[1]))
    result_map: dict[bytes, tuple[Any, ...]] = {}
    for row in results:
        if len(row) != 6 or type(row[0]) is not bytes or len(row[0]) != 64 or row[0] in result_map or row[0] not in operation_map or row[1] != operation_map[row[0]][1] or row[2] != job_map[row[1]][7] or row[2] not in _TERMINAL: _fail("result_binding")
        if row[3] is not None and (type(row[3]) is not bytes or len(row[3]) > _MAX_RECEIPT): _fail("result_receipt")
        if row[4] is not None and (type(row[4]) is not str or _CODE.fullmatch(row[4]) is None): _fail("result_error")
        result_map[bytes(row[0])] = tuple(row)
    for job_id, job in job_map.items():
        operation = bytes(job[1]); has_lease = job_id in lease_map; has_result = operation in result_map
        if (job[7] == "LEASED") != has_lease or (job[7] in _TERMINAL) != has_result: _fail("job_state_binding")
        if job[7] == "VERIFIED":
            result = result_map[operation]
            if result[3] is None: _fail("verified_receipt")
            try: receipt_value = json.loads(bytes(result[3]).decode("ascii")); receipt = _parse_receipt(receipt_value, config)
            except (UnicodeDecodeError, json.JSONDecodeError): _fail("verified_receipt")
            if bytes(result[3]) != _json_bytes(receipt_value) or receipt["job_id"] != job_id or receipt["operation_id"] != operation or receipt["attempt"] != job[9] or receipt["evidence"]["artifact_bytes"] != job[4] or receipt["evidence"]["artifact_sha256"] != job[5] or receipt["evidence"]["artifact_sha3_512"] != job[6]: _fail("verified_receipt_binding")
        elif job[7] in {"REJECTED", "HELD"} and result_map[operation][4] is None: _fail("terminal_error")
    for operation, operation_row in operation_map.items():
        result = result_map.get(operation)
        if operation_row[3] is None:
            if result is not None: _fail("operation_result_binding")
        elif result is None or operation_row[3] != result[2] or operation_row[4] != result[3] or operation_row[5] != result[4]:
            _fail("operation_result_binding")
    expected_head = _sha(_GENESIS_DOMAIN, config["queue_id"].encode("ascii"), config_digest); replay: dict[str, str] = {}
    for index, row in enumerate(transitions, 1):
        if len(row) != 8 or row[0] != index or row[2] not in job_map or row[3] != job_map[row[2]][1] or row[4] != expected_head or type(row[6]) is not bytes or type(row[7]) is not bytes or len(row[7]) != 64: _fail("transition_binding")
        event_digest = _sha(_EVENT_DOMAIN, int(row[0]).to_bytes(8, "big"), str(row[1]).encode("ascii"), str(row[2]).encode("ascii"), bytes(row[3]), bytes(row[6]))
        if event_digest != row[7] or _sha(_HEAD_DOMAIN, expected_head, index.to_bytes(8, "big"), event_digest) != row[5]: _fail("transition_chain")
        try: event = json.loads(bytes(row[6]).decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError): _fail("transition_event")
        if bytes(row[6]) != _json_bytes(event): _fail("transition_event")
        _event_expected(str(row[1]), event); kind = str(row[1]); job = job_map[str(row[2])]; current = replay.get(str(row[2]))
        if kind == "ADMIT" and event["admission_seq"] != job[8]: _fail("transition_admission_binding")
        if kind == "CLAIM" and event["expires_ms"] <= event["at_ms"]: _fail("transition_expiry_binding")
        if kind.startswith("COMPLETE_"):
            result = result_map.get(bytes(row[3]))
            if result is None or event["status"] != result[2] or event["error_code"] != result[4]: _fail("transition_result_binding")
            expected_receipt_digest = None if result[3] is None else _hex(_sha(_RECEIPT_DOMAIN, bytes(result[3])))
            if event["receipt_digest"] != expected_receipt_digest: _fail("transition_receipt_binding")
        if kind == "ADMIT":
            if current is not None: _fail("transition_replay")
            replay[str(row[2])] = "QUEUED"
        elif kind == "CLAIM":
            if current != "QUEUED": _fail("transition_replay")
            replay[str(row[2])] = "LEASED"
        elif kind in {"RETRY_QUEUED", "LEASE_EXPIRE_QUEUED"}:
            if current != "LEASED": _fail("transition_replay")
            replay[str(row[2])] = "QUEUED"
        elif kind == "LEASE_EXPIRE_HELD" or kind.startswith("COMPLETE_"):
            expected = "HELD" if kind == "LEASE_EXPIRE_HELD" else kind.removeprefix("COMPLETE_")
            if current != "LEASED" or expected not in _TERMINAL: _fail("transition_replay")
            replay[str(row[2])] = expected
        expected_head = bytes(row[5])
    if expected_head != bytes(meta[7]) or set(replay) != set(job_map) or any(replay[job_id] != job[7] for job_id, job in job_map.items()): _fail("transition_final")
    counts = {status: sum(1 for row in jobs if row[7] == status) for status in sorted(_STATUS)}
    return {"schema": _SCHEMA, "queue_id": config["queue_id"], "head_root": _hex(bytes(meta[7])), "status_counts": counts, "lease_count": len(leases), "transition_count": len(transitions), "config_digest": _hex(config_digest), "storage_used_bytes": int(meta[10]), "storage_reserved_bytes": int(meta[11])}


def _open_readonly(path: Path) -> sqlite3.Connection:
    identity = _path_identity(path)
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=5.0, isolation_level=None); connection.execute("PRAGMA query_only=ON")
        current = _path_identity(path)
        if identity is None or current is None or identity[:3] != current[:3]: connection.close(); _fail("database_identity")
        return connection
    except IndependentQueueError: raise
    except (OSError, sqlite3.Error): _fail("database_read")


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    identity = _path_identity(path)
    connection = _open_readonly(path)
    try:
        connection.execute("BEGIN"); summary = _verify_connection(connection, expected_config=expected_config)
        if identity is None or identity[3] != int(connection.execute("PRAGMA page_count").fetchone()[0]) * _PAGE_SIZE: _fail("database_image_bounds")
        connection.execute("COMMIT"); return summary
    except IndependentQueueError:
        if connection.in_transaction: connection.execute("ROLLBACK")
        raise
    except (sqlite3.Error, OSError, ValueError):
        if connection.in_transaction: connection.execute("ROLLBACK")
        _fail("database_read")
    finally: connection.close()


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_DATABASE: _fail("export_bounds")
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        try: connection.deserialize(bytes(raw))
        except (sqlite3.Error, ValueError, MemoryError): _fail("export_database")
        connection.execute("BEGIN"); summary = _verify_connection(connection, expected_config=expected_config)
        if len(raw) != int(connection.execute("PRAGMA page_count").fetchone()[0]) * _PAGE_SIZE: _fail("export_image_bounds")
        if connection.serialize() != raw: _fail("export_image_mismatch")
        connection.execute("COMMIT"); return summary
    except IndependentQueueError:
        if connection.in_transaction: connection.execute("ROLLBACK")
        raise
    except (sqlite3.Error, ValueError, MemoryError):
        if connection.in_transaction: connection.execute("ROLLBACK")
        _fail("export_database")
    finally: connection.close()


def _database_bytes(path: Path) -> bytes:
    identity = _path_identity(path)
    connection = _open_readonly(path)
    try:
        connection.execute("BEGIN"); _verify_connection(connection)
        if identity is None or identity[3] != int(connection.execute("PRAGMA page_count").fetchone()[0]) * _PAGE_SIZE: _fail("database_image_bounds")
        raw = connection.serialize(); connection.execute("COMMIT")
        if type(raw) is not bytes or not 0 < len(raw) <= _MAX_DATABASE: _fail("database_capacity")
        return raw
    except IndependentQueueError:
        raise
    except (sqlite3.Error, OSError, ValueError):
        _fail("database_read")
    finally: connection.close()


def read_verified_job(path: Path, job_id: str, *, expected_config: Mapping[str, Any] | None = None) -> IndependentVerifiedQueueJob:
    if type(job_id) is not str or _TOKEN.fullmatch(job_id) is None: _fail("job_id")
    identity = _path_identity(path)
    connection = _open_readonly(path)
    try:
        connection.execute("BEGIN"); summary = _verify_connection(connection, expected_config=expected_config)
        if identity is None or identity[3] != int(connection.execute("PRAGMA page_count").fetchone()[0]) * _PAGE_SIZE: _fail("database_image_bounds")
        metadata = connection.execute("SELECT config_json FROM queue_metadata WHERE id=1").fetchone(); row = connection.execute("SELECT j.*,r.terminal_status,r.receipt_bytes FROM queue_jobs j JOIN queue_results r ON r.operation_id=j.operation_id WHERE j.job_id=?", (job_id,)).fetchone()
        if metadata is None or row is None or row[7] != "VERIFIED" or row[14] != "VERIFIED" or row[15] is None: _fail("job_not_verified")
        config = json.loads(bytes(metadata[0]).decode("ascii")); receipt_bytes = bytes(row[15]); receipt_value = json.loads(receipt_bytes.decode("ascii")); receipt = _parse_receipt(receipt_value, config); evidence = receipt["evidence"]
        result = IndependentVerifiedQueueJob(queue_id=str(config["queue_id"]), config_digest=bytes.fromhex(summary["config_digest"]), verifier_sha256=bytes(evidence["verifier_sha256"]), job_id=job_id, operation_id=bytes(receipt["operation_id"]), attempt=int(receipt["attempt"]), receipt_bytes=receipt_bytes, receipt_id=bytes(receipt["receipt_id"]), acceptance_bytes=bytes(evidence["acceptance_bytes"]), proof_acceptance_digest=bytes(evidence["proof_acceptance_digest"]), artifact_ref=str(row[3]), artifact_bytes=int(row[4]), artifact_sha256=bytes(row[5]), artifact_sha3_512=bytes(row[6]), circuit_id=bytes(evidence["circuit_id"]), peak_job_commit_bytes=int(evidence["peak_job_commit_bytes"]), cap_bytes=int(evidence["cap_bytes"]), cap_enforced=bool(evidence["cap_enforced"]), active_process_limit=int(evidence["active_process_limit"]), timed_out=bool(evidence["timed_out"]), exit_code=int(evidence["exit_code"]), stdout_sha3_512=bytes(evidence["stdout_sha3_512"]), stderr_sha3_512=bytes(evidence["stderr_sha3_512"]))
        connection.execute("ROLLBACK"); return result
    except IndependentQueueError:
        if connection.in_transaction: connection.execute("ROLLBACK")
        raise
    except (sqlite3.Error, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        if connection.in_transaction: connection.execute("ROLLBACK")
        _fail("job_read")
    finally: connection.close()


def restore_export_to_fresh_database(path: Path, raw: bytes) -> dict[str, Any]:
    if not isinstance(path, Path) or not _owned_directory(path.parent): _fail("restore_target")
    summary = verify_export_bytes(raw)
    if _path_identity(path, allow_missing=True) is not None:
        if _database_bytes(path) != raw: _fail("restore_target_conflict")
        return verify_database(path)
    stage: Path | None = None; stage_identity: tuple[int, int, int, int, int] | None = None; published_identity: tuple[int, int] | None = None; published_by_call = False
    try:
        fd, name = tempfile.mkstemp(prefix=".queue-restore-", dir=path.parent); stage = Path(name); stage_identity = _path_identity(stage)
        try:
            offset = 0
            while offset < len(raw): offset += os.write(fd, raw[offset:offset + (1 << 20)])
            os.fsync(fd)
        finally: os.close(fd)
        if verify_database(stage) != summary: _fail("restore_stage")
        try: os.link(stage, path); published_by_call = True; _fsync_parent(path)
        except FileExistsError:
            if _database_bytes(path) != raw: _fail("restore_target_conflict")
        target_stat = os.lstat(path); published_identity = (int(target_stat.st_dev), int(target_stat.st_ino))
        if stage is not None:
            current = os.lstat(stage)
            if stage_identity is None or (int(current.st_dev), int(current.st_ino)) != stage_identity[:2]: _fail("restore_stage_identity")
            os.unlink(stage); stage = None; _fsync_parent(path)
        result = verify_database(path)
        if result != summary: _fail("restore_parity")
        published_by_call = False
        return result
    except IndependentQueueError: raise
    except (OSError, sqlite3.Error, ValueError): _fail("restore_publication")
    finally:
        if stage is not None and stage_identity is not None:
            try:
                current = os.lstat(stage)
                if (int(current.st_dev), int(current.st_ino)) == stage_identity[:2]: os.unlink(stage)
            except (OSError, ValueError): pass
        if published_by_call and published_identity is not None:
            try:
                current = os.lstat(path)
                if (int(current.st_dev), int(current.st_ino)) == published_identity and int(current.st_nlink) == 1: os.unlink(path)
            except (OSError, ValueError): pass


__all__ = ("IndependentQueueError", "IndependentVerifiedQueueJob", "read_verified_job", "restore_export_to_fresh_database", "verify_database", "verify_export_bytes")
