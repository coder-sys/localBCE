"""Independent reconstruction of the queue-to-state application ledger."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Final, Mapping

from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes
from app.minimal_clearance_verification_queue_independent import (
    IndependentQueueError,
    IndependentVerifiedQueueJob,
    read_verified_job,
)


class IndependentQueueApplicationError(RuntimeError):
    """Bounded independent coordinator reconstruction failure."""


_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE-QUEUE-APPLICATION/v1"
_SCHEMA_VERSION: Final[int] = 1
_STATUS: Final[frozenset[str]] = frozenset({"DISCOVERED", "LEASED", "APPLIED", "HELD"})
_CAP_BYTES: Final[int] = 5_000_000_000
_ACTIVE_PROCESS_LIMIT: Final[int] = 1
_MAX_ACCEPTANCE: Final[int] = 65_536
_MAX_RECEIPT: Final[int] = 16 * 1024
_MAX_EXPORT: Final[int] = 64 * 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_APP_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/MATERIAL/v1\x00"
_APP_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/OPERATION/v1\x00"
_APP_ACCEPTANCE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/ACCEPTANCE/v1\x00"
_APP_QUEUE_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/QUEUE-RECEIPT/v1\x00"
_APP_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/GENESIS/v1\x00"
_APP_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/EVENT/v1\x00"
_APP_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/HEAD/v1\x00"
_APP_STATE_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/STATE-RECEIPT/v1\x00"


def _fail(code: str) -> None:
    raise IndependentQueueApplicationError(code)


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
        raise IndependentQueueApplicationError("json") from exc


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _blob(value: Any, size: int | None, label: str) -> bytes:
    if type(value) is not str:
        _fail(label)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentQueueApplicationError(label) from exc
    if size is not None and len(raw) != size:
        _fail(label)
    return raw


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(label)
    return value


def _token(value: Any, label: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _fail(label)
    return value


def _parse_config(value: Any) -> tuple[dict[str, Any], bytes, bytes]:
    keys = {
        "schema_version", "application_id", "queue_id", "queue_config_digest", "verifier_sha256",
        "state_store_identity", "capacity", "lease_seconds", "max_attempts", "busy_timeout_ms",
        "proof_suite_id", "production_usable", "activation",
    }
    if type(value) is not dict or set(value) != keys or value["schema_version"] != _SCHEMA_VERSION:
        _fail("config_keys")
    app_id = _token(value["application_id"], "application_id")
    queue_id = _token(value["queue_id"], "queue_id")
    queue_digest = _blob(value["queue_config_digest"], 64, "queue_config_digest")
    verifier = _blob(value["verifier_sha256"], 32, "verifier_sha256")
    state_id = _blob(value["state_store_identity"], 64, "state_store_identity")
    capacity = _integer(value["capacity"], "capacity", 1)
    lease = _integer(value["lease_seconds"], "lease_seconds", 1)
    if not 1 <= capacity <= 10_000 or not 1 <= lease <= 3_600 or value["max_attempts"] != 3 or value["busy_timeout_ms"] != 5_000:
        _fail("config_bounds")
    if value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("config_nonactivation")
    canonical = _json_bytes(value)
    digest = _sha(_APP_MATERIAL, canonical)
    parsed = dict(value)
    parsed.update(application_id=app_id, queue_id=queue_id, queue_config_digest=queue_digest, verifier_sha256=verifier, state_store_identity=state_id)
    return parsed, canonical, digest


def _decode_state_receipt(raw: Any, acceptance) -> None:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT:
        _fail("state_receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentQueueApplicationError("state_receipt_encoding") from exc
    if raw != _json_bytes(value) or type(value) is not dict:
        _fail("state_receipt_noncanonical")
    fields = {
        "operation_digest", "artifact_sha256", "artifact_digest", "statement_digest", "circuit_id", "bundle_id",
        "receipt_id", "join_id", "settlement_id", "request_id", "attempt_id", "decision_id", "sequence_before",
        "sequence_after", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after",
        "clearance_count_before", "clearance_count_after", "payment_root_before", "payment_root_after",
        "settled_batch_count_before", "settled_batch_count_after", "state_binding_after", "audit_head_after",
        "policy_result", "effective_directive", "proof_session_accepted", "economic_mutation", "proof_suite_id",
    }
    if set(value) != fields:
        _fail("state_receipt_keys")
    for name in fields - {"sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after", "settled_batch_count_before", "settled_batch_count_after", "policy_result", "effective_directive", "proof_session_accepted", "economic_mutation", "proof_suite_id"}:
        size = 32 if name in {"artifact_sha256", "circuit_id"} else 64
        _blob(value[name], size, "state_receipt_" + name)
    for name in ("sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after", "settled_batch_count_before", "settled_batch_count_after", "policy_result", "effective_directive"):
        _integer(value[name], "state_receipt_" + name)
    if (
        value["proof_session_accepted"] is not True or value["economic_mutation"] is not False
        or value["proof_suite_id"] is not None or not 1 <= value["effective_directive"] <= 5
        or value["artifact_sha256"].upper() != _hex(acceptance.artifact_sha256)
        or value["artifact_digest"].upper() != _hex(acceptance.artifact_digest)
        or value["circuit_id"].upper() != _hex(acceptance.circuit_id)
        or value["statement_digest"].upper() != _hex(acceptance.statement_digest)
        or value["receipt_id"].upper() != _hex(acceptance.statement.receipt_id)
        or value["join_id"].upper() != _hex(acceptance.statement.join_id)
        or value["request_id"].upper() != _hex(acceptance.statement.request_id)
        or value["attempt_id"].upper() != _hex(acceptance.statement.attempt_id)
        or value["decision_id"].upper() != _hex(acceptance.statement.decision_id)
        or value["policy_result"] != acceptance.policy_result
        or value["effective_directive"] != acceptance.effective_directive
        or value["payment_root_before"] != value["payment_root_after"]
        or value["settled_batch_count_before"] != value["settled_batch_count_after"]
    ):
        _fail("state_receipt_binding")


def read_application_job(path: Path, job_id: str) -> IndependentVerifiedQueueJob:
    try:
        return read_verified_job(path, job_id)
    except IndependentQueueError as exc:
        raise IndependentQueueApplicationError("queue_verification_failed") from exc


def _parse_queue_receipt(raw: bytes, acceptance) -> None:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentQueueApplicationError("queue_receipt_encoding") from exc
    if raw != _json_bytes(value) or type(value) is not dict or "evidence" not in value:
        _fail("queue_receipt")
    evidence = value["evidence"]
    if type(evidence) is not dict or evidence.get("acceptance_bytes") != _hex(acceptance.canonical_bytes()):
        _fail("queue_acceptance_binding")


def _parse_export(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_EXPORT:
        _fail("export_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentQueueApplicationError("export_encoding") from exc
    top = {"schema", "config", "metadata", "jobs", "leases", "results", "transitions"}
    if type(value) is not dict or set(value) != top or value["schema"] != _SCHEMA or raw != _json_bytes(value):
        _fail("export_keys")
    config, config_bytes, config_digest = _parse_config(value["config"])
    metadata = value["metadata"]
    if type(metadata) is not dict or set(metadata) != {"head_root", "next_sequence"}:
        _fail("metadata_keys")
    head = _blob(metadata["head_root"], 64, "metadata_head")
    next_sequence = _integer(metadata["next_sequence"], "metadata_sequence")
    jobs = value["jobs"]
    if type(jobs) is not list:
        _fail("jobs_shape")
    job_map: dict[str, dict[str, Any]] = {}
    for index, job in enumerate(jobs, start=1):
        keys = {"job_id", "operation_id", "queue_receipt_digest", "acceptance_digest", "acceptance_bytes", "queue_receipt_bytes", "status", "admission_sequence", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"}
        if type(job) is not dict or set(job) != keys:
            _fail("job_keys")
        job_id = _token(job["job_id"], "job_id")
        if job_id in job_map or _integer(job["admission_sequence"], "admission_sequence", 1) != index:
            _fail("job_order")
        operation = _blob(job["operation_id"], 64, "job_operation")
        queue_digest = _blob(job["queue_receipt_digest"], 64, "job_queue_digest")
        acceptance_raw = _blob(job["acceptance_bytes"], None, "job_acceptance")
        receipt_raw = _blob(job["queue_receipt_bytes"], None, "job_receipt")
        if not 0 < len(acceptance_raw) <= _MAX_ACCEPTANCE or not 0 < len(receipt_raw) <= _MAX_RECEIPT:
            _fail("job_bounds")
        try:
            acceptance = parse_acceptance_bytes(acceptance_raw)
        except Exception as exc:
            raise IndependentQueueApplicationError("job_acceptance") from exc
        if acceptance.canonical_bytes() != acceptance_raw:
            _fail("job_acceptance_canonical")
        _parse_queue_receipt(receipt_raw, acceptance)
        if queue_digest != _sha(_APP_QUEUE_RECEIPT, receipt_raw) or _blob(job["acceptance_digest"], 64, "job_acceptance_digest") != _sha(_APP_ACCEPTANCE, acceptance_raw):
            _fail("job_digest_binding")
        try:
            queue_value = json.loads(receipt_raw.decode("ascii"))
            queue_operation = _blob(queue_value["operation_id"], 64, "queue_operation")
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IndependentQueueApplicationError("queue_receipt_operation") from exc
        expected_operation = _sha(_APP_OPERATION, job_id.encode("ascii"), queue_operation, acceptance_raw, bytes(config["state_store_identity"]), bytes(config["verifier_sha256"]))
        if operation != expected_operation:
            _fail("job_operation_binding")
        if job["status"] not in _STATUS or type(job["last_error_code"]) not in (str, type(None)):
            _fail("job_status")
        for name in ("attempt", "next_eligible_ms", "created_ms", "updated_ms"):
            _integer(job[name], "job_" + name)
        if job["attempt"] > 3 or (job["status"] == "DISCOVERED" and job["attempt"] < 0):
            _fail("job_attempt")
        job_map[job_id] = dict(job, operation_id=operation, acceptance_bytes=acceptance_raw, queue_receipt_bytes=receipt_raw)
    if next_sequence < len(jobs):
        _fail("metadata_sequence")
    leases = value["leases"]
    if type(leases) is not list:
        _fail("leases_shape")
    lease_map: dict[str, dict[str, Any]] = {}
    for lease in leases:
        keys = {"job_id", "worker_id", "token", "attempt", "leased_ms", "expires_ms"}
        if type(lease) is not dict or set(lease) != keys:
            _fail("lease_keys")
        jid = _token(lease["job_id"], "lease_job")
        if jid in lease_map or jid not in job_map or job_map[jid]["status"] != "LEASED":
            _fail("lease_binding")
        _token(lease["worker_id"], "lease_worker")
        _blob(lease["token"], 24, "lease_token")
        _integer(lease["attempt"], "lease_attempt", 1)
        leased = _integer(lease["leased_ms"], "lease_time")
        if _integer(lease["expires_ms"], "lease_expiry") <= leased or lease["attempt"] != job_map[jid]["attempt"] or lease["attempt"] > 3:
            _fail("lease_state")
        lease_map[jid] = dict(lease)
    results = value["results"]
    if type(results) is not list:
        _fail("results_shape")
    result_map: dict[str, dict[str, Any]] = {}
    for result in results:
        keys = {"job_id", "status", "state_receipt_bytes", "state_receipt_digest", "operation_id", "duplicate_convergence", "completed_ms"}
        if type(result) is not dict or set(result) != keys:
            _fail("result_keys")
        jid = _token(result["job_id"], "result_job")
        if jid in result_map or jid not in job_map or result["status"] not in {"APPLIED", "HELD"} or job_map[jid]["status"] != result["status"]:
            _fail("result_binding")
        operation = _blob(result["operation_id"], 64, "result_operation")
        if operation != job_map[jid]["operation_id"] or type(result["duplicate_convergence"]) is not bool:
            _fail("result_operation")
        _integer(result["completed_ms"], "result_time")
        receipt = None if result["state_receipt_bytes"] is None else _blob(result["state_receipt_bytes"], None, "state_receipt")
        digest = None if result["state_receipt_digest"] is None else _blob(result["state_receipt_digest"], 64, "state_receipt_digest")
        if result["status"] == "APPLIED":
            if receipt is None or digest != _sha(_APP_STATE_RECEIPT, receipt):
                _fail("result_receipt")
            acceptance = parse_acceptance_bytes(job_map[jid]["acceptance_bytes"])
            _decode_state_receipt(receipt, acceptance)
        elif receipt is not None or digest is not None:
            _fail("held_receipt")
        result_map[jid] = dict(result, operation_id=operation)
    for jid, job in job_map.items():
        if (job["status"] == "LEASED") != (jid in lease_map):
            _fail("lease_final")
        if (job["status"] in {"APPLIED", "HELD"}) != (jid in result_map):
            _fail("result_final")
    transitions = value["transitions"]
    if type(transitions) is not list or next_sequence != len(transitions):
        _fail("transition_count")
    expected_head = _sha(_APP_GENESIS, config["application_id"].encode("ascii"), config_digest)
    replay: dict[str, str] = {}
    for index, transition in enumerate(transitions, start=1):
        keys = {"sequence", "transition_kind", "job_id", "before_root", "after_root", "event_bytes", "event_digest"}
        if type(transition) is not dict or set(transition) != keys or _integer(transition["sequence"], "transition_sequence", 1) != index:
            _fail("transition_keys")
        jid = _token(transition["job_id"], "transition_job")
        if jid not in job_map:
            _fail("transition_job")
        before = _blob(transition["before_root"], 64, "transition_before")
        after = _blob(transition["after_root"], 64, "transition_after")
        event = _blob(transition["event_bytes"], None, "transition_event")
        digest = _blob(transition["event_digest"], 64, "transition_digest")
        if before != expected_head or _sha(_APP_EVENT, str(transition["transition_kind"]).encode("ascii"), jid.encode("ascii"), event) != digest:
            _fail("transition_digest")
        try:
            event_value = json.loads(event.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IndependentQueueApplicationError("transition_event_encoding") from exc
        if event != _json_bytes(event_value):
            _fail("transition_event_canonical")
        kind = str(transition["transition_kind"])
        status = str(event_value.get("status"))
        if kind == "DISCOVER":
            if replay.get(jid) is not None or status != "DISCOVERED":
                _fail("transition_discover")
            replay[jid] = "DISCOVERED"
        elif kind == "CLAIM":
            if replay.get(jid) != "DISCOVERED" or status != "LEASED":
                _fail("transition_claim")
            replay[jid] = "LEASED"
        elif kind == "EXPIRED_REQUEUE":
            if replay.get(jid) != "LEASED" or status != "DISCOVERED":
                _fail("transition_requeue")
            replay[jid] = "DISCOVERED"
        elif kind == "EXPIRED_HELD":
            if replay.get(jid) != "LEASED" or status != "HELD" or jid not in result_map:
                _fail("transition_expired_held")
            replay[jid] = "HELD"
        elif kind == "APPLIED":
            if replay.get(jid) != "LEASED" or status != "APPLIED":
                _fail("transition_applied")
            replay[jid] = "APPLIED"
        elif kind == "HELD":
            if replay.get(jid) != "LEASED" or status != "HELD":
                _fail("transition_held")
            replay[jid] = "HELD"
        else:
            _fail("transition_kind")
        expected_head = _sha(_APP_HEAD, expected_head, index.to_bytes(8, "big"), digest)
        if expected_head != after:
            _fail("transition_head")
    if expected_head != head or set(replay) != set(job_map) or any(replay[jid] != job["status"] for jid, job in job_map.items()):
        _fail("transition_final")
    counts = {status: sum(1 for item in jobs if item["status"] == status) for status in sorted(_STATUS)}
    if counts["DISCOVERED"] + counts["LEASED"] > config["capacity"]:
        _fail("capacity")
    summary = {"schema": _SCHEMA, "application_id": config["application_id"], "head_root": _hex(head), "status_counts": counts, "transition_count": len(transitions), "config_digest": _hex(config_digest), "applied_count": counts["APPLIED"], "duplicate_convergence_count": sum(1 for item in results if item["duplicate_convergence"])}
    return value, summary


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    value, summary = _parse_export(raw)
    if expected_config is not None and _json_bytes(expected_config) != _json_bytes(value["config"]):
        _fail("expected_config_mismatch")
    return summary


def _schema(connection: sqlite3.Connection) -> None:
    expected = {"app_metadata", "app_jobs", "app_leases", "app_results", "app_transitions"}
    actual = {str(row[1]) for row in connection.execute("SELECT type,name FROM sqlite_master WHERE type='table'")}
    if actual != expected:
        _fail("database_objects")


def _db_export(connection: sqlite3.Connection) -> bytes:
    _schema(connection)
    rows = connection.execute("SELECT * FROM app_metadata WHERE id=1").fetchall()
    if len(rows) != 1:
        _fail("database_metadata")
    meta = rows[0]
    if len(meta) != 11 or type(meta[3]) is not bytes:
        _fail("database_metadata_shape")
    try:
        config_value = json.loads(bytes(meta[3]).decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentQueueApplicationError("database_config_encoding") from exc
    config, config_bytes, config_digest = _parse_config(config_value)
    if (
        int(meta[1]) != _SCHEMA_VERSION
        or str(meta[2]) != config["application_id"]
        or bytes(meta[3]) != config_bytes
        or bytes(meta[4]) != config_digest
        or str(meta[5]) != config["queue_id"]
        or bytes(meta[6]) != config["queue_config_digest"]
        or bytes(meta[7]) != config["verifier_sha256"]
        or bytes(meta[8]) != config["state_store_identity"]
    ):
        _fail("database_metadata_binding")
    def blob(value: Any) -> str | None:
        return None if value is None else _hex(bytes(value))
    data = {
        "schema": _SCHEMA,
        "config": config_value,
        "metadata": {"head_root": blob(meta[9]), "next_sequence": int(meta[10])},
        "jobs": [
            {"job_id": str(row[0]), "operation_id": blob(row[1]), "queue_receipt_digest": blob(row[2]), "acceptance_digest": blob(row[3]), "acceptance_bytes": blob(row[4]), "queue_receipt_bytes": blob(row[5]), "status": str(row[6]), "admission_sequence": int(row[7]), "attempt": int(row[8]), "next_eligible_ms": int(row[9]), "created_ms": int(row[10]), "updated_ms": int(row[11]), "last_error_code": row[12]}
            for row in connection.execute("SELECT * FROM app_jobs ORDER BY admission_sequence")
        ],
        "leases": [
            {"job_id": str(row[0]), "worker_id": str(row[1]), "token": blob(row[2]), "attempt": int(row[3]), "leased_ms": int(row[4]), "expires_ms": int(row[5])}
            for row in connection.execute("SELECT * FROM app_leases ORDER BY job_id")
        ],
        "results": [
            {"job_id": str(row[0]), "status": str(row[1]), "state_receipt_bytes": blob(row[2]), "state_receipt_digest": blob(row[3]), "operation_id": blob(row[4]), "duplicate_convergence": bool(row[5]), "completed_ms": int(row[6])}
            for row in connection.execute("SELECT * FROM app_results ORDER BY job_id")
        ],
        "transitions": [
            {"sequence": int(row[0]), "transition_kind": str(row[1]), "job_id": str(row[2]), "before_root": blob(row[3]), "after_root": blob(row[4]), "event_bytes": blob(row[5]), "event_digest": blob(row[6])}
            for row in connection.execute("SELECT * FROM app_transitions ORDER BY sequence")
        ],
    }
    return _json_bytes(data)


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=5.0)
        connection.execute("PRAGMA query_only=ON")
        return verify_export_bytes(_db_export(connection), expected_config=expected_config)
    except sqlite3.Error as exc:
        raise IndependentQueueApplicationError("database_read") from exc
    finally:
        if connection is not None:
            connection.close()


def verify_database_connection(
    connection: sqlite3.Connection, *, expected_config: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Verify an already-open read transaction without changing its snapshot."""
    if not isinstance(connection, sqlite3.Connection):
        _fail("database_connection")
    try:
        return verify_export_bytes(_db_export(connection), expected_config=expected_config)
    except sqlite3.Error as exc:
        raise IndependentQueueApplicationError("database_read") from exc


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE app_metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, application_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL, queue_id TEXT NOT NULL, queue_config_digest BLOB NOT NULL, verifier_sha256 BLOB NOT NULL, state_store_identity BLOB NOT NULL, head_root BLOB NOT NULL, next_sequence INTEGER NOT NULL);
        CREATE TABLE app_jobs (job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, queue_receipt_digest BLOB NOT NULL, acceptance_digest BLOB NOT NULL, acceptance_bytes BLOB NOT NULL, queue_receipt_bytes BLOB NOT NULL, status TEXT NOT NULL, admission_sequence INTEGER NOT NULL UNIQUE, attempt INTEGER NOT NULL, next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT);
        CREATE TABLE app_leases (job_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, token BLOB NOT NULL, attempt INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL, FOREIGN KEY(job_id) REFERENCES app_jobs(job_id));
        CREATE TABLE app_results (job_id TEXT PRIMARY KEY, status TEXT NOT NULL, state_receipt_bytes BLOB, state_receipt_digest BLOB, operation_id BLOB NOT NULL UNIQUE, duplicate_convergence INTEGER NOT NULL, completed_ms INTEGER NOT NULL, FOREIGN KEY(job_id) REFERENCES app_jobs(job_id));
        CREATE TABLE app_transitions (sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, job_id TEXT NOT NULL, before_root BLOB NOT NULL, after_root BLOB NOT NULL, event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL UNIQUE, FOREIGN KEY(job_id) REFERENCES app_jobs(job_id));
        """
    )


def restore_export_to_fresh_database(path: Path, raw: bytes) -> dict[str, Any]:
    if not isinstance(path, Path) or path.exists() or path.is_symlink() or not path.parent.is_dir():
        _fail("restore_target")
    value, summary = _parse_export(raw)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        _create_schema(connection)
        connection.execute("BEGIN IMMEDIATE")
        config = value["config"]
        config_bytes = _json_bytes(config)
        config_digest = _sha(_APP_MATERIAL, config_bytes)
        meta = value["metadata"]
        connection.execute("INSERT INTO app_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?)", (1, _SCHEMA_VERSION, config["application_id"], config_bytes, config_digest, config["queue_id"], _blob(config["queue_config_digest"], 64, "queue_digest"), _blob(config["verifier_sha256"], 32, "verifier"), _blob(config["state_store_identity"], 64, "state"), _blob(meta["head_root"], 64, "head"), meta["next_sequence"]))
        for job in value["jobs"]:
            connection.execute("INSERT INTO app_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (job["job_id"], _blob(job["operation_id"], 64, "operation"), _blob(job["queue_receipt_digest"], 64, "queue_digest"), _blob(job["acceptance_digest"], 64, "acceptance_digest"), _blob(job["acceptance_bytes"], None, "acceptance"), _blob(job["queue_receipt_bytes"], None, "receipt"), job["status"], job["admission_sequence"], job["attempt"], job["next_eligible_ms"], job["created_ms"], job["updated_ms"], job["last_error_code"]))
        for lease in value["leases"]:
            connection.execute("INSERT INTO app_leases VALUES (?,?,?,?,?,?)", (lease["job_id"], lease["worker_id"], _blob(lease["token"], 24, "token"), lease["attempt"], lease["leased_ms"], lease["expires_ms"]))
        for result in value["results"]:
            connection.execute("INSERT INTO app_results VALUES (?,?,?,?,?,?,?)", (result["job_id"], result["status"], None if result["state_receipt_bytes"] is None else _blob(result["state_receipt_bytes"], None, "state_receipt"), None if result["state_receipt_digest"] is None else _blob(result["state_receipt_digest"], 64, "state_digest"), _blob(result["operation_id"], 64, "operation"), int(result["duplicate_convergence"]), result["completed_ms"]))
        for transition in value["transitions"]:
            connection.execute("INSERT INTO app_transitions VALUES (?,?,?,?,?,?,?)", (transition["sequence"], transition["transition_kind"], transition["job_id"], _blob(transition["before_root"], 64, "before"), _blob(transition["after_root"], 64, "after"), _blob(transition["event_bytes"], None, "event"), _blob(transition["event_digest"], 64, "event_digest")))
        connection.execute("COMMIT")
    except Exception:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        if connection is not None:
            connection.close()
    restored = verify_database(path, expected_config=value["config"])
    if restored != summary:
        _fail("restore_parity")
    return restored


__all__ = (
    "IndependentQueueApplicationError", "read_application_job", "restore_export_to_fresh_database",
    "verify_database", "verify_database_connection", "verify_export_bytes",
)
