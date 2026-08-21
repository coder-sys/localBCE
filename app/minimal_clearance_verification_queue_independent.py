"""Independent read/reconstruction boundary for the experimental queue.

This module deliberately duplicates the queue wire/schema rules instead of
importing the producer.  It verifies exports and databases, replays durable
transitions, and restores only into a fresh database.  It has no verifier or
clearance-state dependency.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
from typing import Any, Final, Mapping

from app.minimal_clearance_proof_state import parse_acceptance_bytes


class IndependentQueueError(RuntimeError):
    """Bounded independent reconstruction failure."""


@dataclass(frozen=True, slots=True)
class IndependentVerifiedQueueJob:
    """A proof-only snapshot extracted after independent queue verification."""

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


_SCHEMA: Final = "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFICATION-QUEUE/v1"
_SCHEMA_VERSION: Final = 1
_STATUS: Final = frozenset({"QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"})
_NONTERMINAL: Final = frozenset({"QUEUED", "LEASED"})
_TERMINAL: Final = frozenset({"VERIFIED", "REJECTED", "HELD"})
_CAP_BYTES: Final = 5_000_000_000
_ACTIVE_PROCESS_LIMIT: Final = 1
_MAX_ERROR: Final = 96
_MAX_ACCEPTANCE: Final[int] = 65_536
_MAX_RECEIPT: Final = 16 * 1024
_MAX_EXPORT: Final = 64 * 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")

_MATERIAL_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/MATERIAL/v1\x00"
_GENESIS_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/GENESIS/v1\x00"
_OPERATION_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/OPERATION/v1\x00"
_EVENT_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/EVENT/v1\x00"
_HEAD_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/HEAD/v1\x00"
_ACCEPTANCE_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/ACCEPTANCE/v1\x00"
_RECEIPT_DOMAIN = b"BL/NATIVE-V3/VERIFICATION-QUEUE/RECEIPT/v1\x00"

_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": (
        "id", "schema_version", "queue_id", "config_json", "config_digest", "verifier_sha256",
        "artifact_bytes_cap", "head_root", "next_transition_seq", "next_admission_seq",
    ),
    "queue_jobs": (
        "job_id", "operation_id", "material_digest", "artifact_ref", "artifact_bytes", "artifact_sha256",
        "artifact_sha3_512", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms",
        "updated_ms", "last_error_code",
    ),
    "queue_operations": (
        "operation_id", "job_id", "material_digest", "result_status", "result_receipt", "result_error_code",
    ),
    "queue_leases": ("job_id", "worker_id", "token", "attempt", "leased_ms", "expires_ms"),
    "queue_results": (
        "operation_id", "job_id", "terminal_status", "receipt_bytes", "error_code", "completed_ms",
    ),
    "queue_transitions": (
        "sequence", "transition_kind", "job_id", "operation_id", "before_root", "after_root",
        "event_bytes", "event_digest",
    ),
}
_TABLES = frozenset(_TABLE_COLUMNS)
_TRIGGERS = frozenset({
    "queue_jobs_no_delete", "queue_jobs_no_update", "queue_operations_no_delete",
    "queue_transitions_no_update", "queue_transitions_no_delete",
})


def _fail(code: str) -> None:
    raise IndependentQueueError(code)


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IndependentQueueError("independent_json") from exc


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _blob(value: Any, length: int | None, label: str, *, nullable: bool = False) -> bytes | None:
    if value is None and nullable:
        return None
    if type(value) is not str or value != value.upper() or re.fullmatch(r"[0-9A-F]+\Z", value) is None:
        _fail(label)
    if length is not None and len(value) != length * 2:
        _fail(label)
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentQueueError(label) from exc
    if length is not None and len(result) != length:
        _fail(label)
    return result


def _token(value: Any, label: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _fail(label)
    return value


def _code(value: Any, label: str) -> str:
    if type(value) is not str or len(value) > _MAX_ERROR or _CODE.fullmatch(value) is None:
        _fail(label)
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(label)
    return value


def _parse_config(value: Any) -> tuple[dict[str, Any], bytes, bytes]:
    keys = {
        "schema_version", "queue_id", "capacity", "lease_seconds", "max_attempts",
        "max_worker_concurrency", "verifier_sha256", "artifact_bytes_cap", "retryable_codes",
    }
    if type(value) is not dict or set(value) != keys or value["schema_version"] != _SCHEMA_VERSION:
        _fail("config_keys")
    queue_id = _token(value["queue_id"], "config_queue_id")
    capacity = _integer(value["capacity"], "config_capacity", minimum=1)
    lease_seconds = _integer(value["lease_seconds"], "config_lease_seconds", minimum=1)
    max_attempts = _integer(value["max_attempts"], "config_max_attempts", minimum=1)
    max_workers = _integer(value["max_worker_concurrency"], "config_workers", minimum=1)
    artifact_cap = _integer(value["artifact_bytes_cap"], "config_artifact_cap", minimum=1)
    verifier = _blob(value["verifier_sha256"], 32, "config_verifier")
    retryable = value["retryable_codes"]
    if type(retryable) is not list or not retryable or any(type(item) is not str for item in retryable):
        _fail("config_retryable")
    retryable_tuple = tuple(retryable)
    if tuple(sorted(set(retryable_tuple))) != retryable_tuple or any(_CODE.fullmatch(item) is None for item in retryable_tuple):
        _fail("config_retryable")
    if not 1 <= capacity <= 10_000 or not 1 <= lease_seconds <= 3_600 or max_attempts != 3 or max_workers != 4:
        _fail("config_bounds")
    if not 0 < artifact_cap <= 512 * 1024 * 1024:
        _fail("config_artifact_cap")
    canonical = _json_bytes(value)
    digest = _sha(_MATERIAL_DOMAIN, canonical)
    return value, canonical, digest


def _parse_metadata(job: Mapping[str, Any], artifact_cap: int) -> tuple[dict[str, Any], bytes, bytes]:
    keys = {"artifact_ref", "artifact_bytes", "artifact_sha256", "artifact_sha3_512"}
    if set(job) & keys != keys:
        _fail("job_metadata_keys")
    ref = _token(job["artifact_ref"], "artifact_ref")
    size = _integer(job["artifact_bytes"], "artifact_bytes", minimum=1)
    sha256 = _blob(job["artifact_sha256"], 32, "artifact_sha256")
    sha3 = _blob(job["artifact_sha3_512"], 64, "artifact_sha3")
    if size > artifact_cap:
        _fail("artifact_cap")
    return {
        "artifact_ref": ref, "artifact_bytes": size,
        "artifact_sha256": sha256, "artifact_sha3_512": sha3,
    }, sha256, sha3


def _metadata_json(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "artifact_ref": metadata["artifact_ref"], "artifact_bytes": metadata["artifact_bytes"],
        "artifact_sha256": _hex(metadata["artifact_sha256"]),
        "artifact_sha3_512": _hex(metadata["artifact_sha3_512"]),
    }


def _parse_evidence(value: Any, verifier: bytes) -> dict[str, Any]:
    keys = {
        "artifact_bytes", "artifact_sha256", "artifact_sha3_512", "verifier_sha256",
        "circuit_id", "acceptance_bytes", "proof_acceptance_digest", "peak_job_commit_bytes", "cap_bytes", "cap_enforced",
        "active_process_limit", "timed_out", "exit_code", "stdout_sha3_512", "stderr_sha3_512",
    }
    if type(value) is not dict or set(value) != keys:
        _fail("receipt_evidence_keys")
    ints = ("artifact_bytes", "peak_job_commit_bytes", "cap_bytes", "active_process_limit", "exit_code")
    if any(type(value[item]) is not int for item in ints):
        _fail("receipt_evidence_types")
    if type(value["cap_enforced"]) is not bool or type(value["timed_out"]) is not bool:
        _fail("receipt_evidence_types")
    parsed = dict(value)
    parsed["artifact_sha256"] = _blob(value["artifact_sha256"], 32, "receipt_artifact_sha256")
    parsed["artifact_sha3_512"] = _blob(value["artifact_sha3_512"], 64, "receipt_artifact_sha3")
    parsed["verifier_sha256"] = _blob(value["verifier_sha256"], 32, "receipt_verifier")
    parsed["circuit_id"] = _blob(value["circuit_id"], 32, "receipt_circuit")
    parsed["acceptance_bytes"] = _blob(value["acceptance_bytes"], None, "receipt_acceptance_bytes")
    if not 0 < len(parsed["acceptance_bytes"]) <= _MAX_ACCEPTANCE:
        _fail("receipt_acceptance_bounds")
    parsed["proof_acceptance_digest"] = _blob(value["proof_acceptance_digest"], 64, "receipt_acceptance")
    parsed["stdout_sha3_512"] = _blob(value["stdout_sha3_512"], 64, "receipt_stdout")
    parsed["stderr_sha3_512"] = _blob(value["stderr_sha3_512"], 64, "receipt_stderr")
    if parsed["verifier_sha256"] != verifier or parsed["cap_bytes"] != _CAP_BYTES:
        _fail("receipt_containment_binding")
    if parsed["cap_enforced"] is not True or parsed["active_process_limit"] != _ACTIVE_PROCESS_LIMIT:
        _fail("receipt_containment_binding")
    if parsed["timed_out"] is not False or parsed["exit_code"] != 0 or parsed["peak_job_commit_bytes"] > _CAP_BYTES:
        _fail("receipt_containment_binding")
    try:
        acceptance = parse_acceptance_bytes(parsed["acceptance_bytes"])
    except Exception as exc:
        raise IndependentQueueError("receipt_acceptance_invalid") from exc
    if (
        acceptance.canonical_bytes() != parsed["acceptance_bytes"]
        or acceptance.artifact_bytes != parsed["artifact_bytes"]
        or acceptance.artifact_sha256 != parsed["artifact_sha256"]
        or acceptance.artifact_digest != parsed["artifact_sha3_512"]
        or acceptance.circuit_id != parsed["circuit_id"]
        or _sha(_ACCEPTANCE_DOMAIN, parsed["acceptance_bytes"]) != parsed["proof_acceptance_digest"]
    ):
        _fail("receipt_acceptance_binding")
    return parsed


def _parse_receipt(value: Any, config: Mapping[str, Any]) -> dict[str, Any]:
    keys = {"schema", "queue_id", "job_id", "operation_id", "attempt", "evidence", "receipt_id"}
    if type(value) is not dict or set(value) != keys or value["schema"] != _SCHEMA or value["queue_id"] != config["queue_id"]:
        _fail("receipt_keys")
    job_id = _token(value["job_id"], "receipt_job_id")
    operation = _blob(value["operation_id"], 64, "receipt_operation")
    receipt_id = _blob(value["receipt_id"], 64, "receipt_id")
    attempt = _integer(value["attempt"], "receipt_attempt", minimum=1)
    evidence = _parse_evidence(value["evidence"], _blob(config["verifier_sha256"], 32, "config_verifier"))
    canonical_without_id = {
        "schema": _SCHEMA, "queue_id": config["queue_id"], "job_id": job_id,
        "operation_id": _hex(operation), "attempt": attempt,
        "evidence": {key: (_hex(item) if isinstance(item, bytes) else item) for key, item in evidence.items()},
    }
    expected_id = _sha(_RECEIPT_DOMAIN, _json_bytes(canonical_without_id))
    if receipt_id != expected_id:
        _fail("receipt_identity")
    return {"job_id": job_id, "operation_id": operation, "attempt": attempt, "evidence": evidence, "receipt_id": receipt_id}


def _event_expected(kind: str, event: Any) -> None:
    if kind == "ADMIT":
        keys = {"at_ms", "status", "admission_seq"}
    elif kind == "CLAIM":
        keys = {"at_ms", "status", "attempt", "worker_id", "expires_ms"}
    elif kind.startswith("LEASE_EXPIRE_"):
        keys = {"at_ms", "status", "attempt", "error_code"}
    elif kind == "RETRY_QUEUED":
        keys = {"at_ms", "status", "attempt", "error_code"}
    elif kind.startswith("COMPLETE_"):
        keys = {"at_ms", "status", "attempt", "error_code", "receipt_digest"}
    else:
        _fail("transition_kind")
    if type(event) is not dict or set(event) != keys:
        _fail("transition_event_keys")
    _integer(event["at_ms"], "transition_time")
    if event["status"] not in _STATUS:
        _fail("transition_status")
    if kind == "ADMIT":
        if event["status"] != "QUEUED":
            _fail("transition_admit_status")
        _integer(event["admission_seq"], "transition_admission", minimum=1)
    elif kind == "CLAIM":
        if event["status"] != "LEASED":
            _fail("transition_claim_status")
        _integer(event["attempt"], "transition_attempt", minimum=1)
        _token(event["worker_id"], "transition_worker")
        _integer(event["expires_ms"], "transition_expiry", minimum=1)
    else:
        _integer(event["attempt"], "transition_attempt", minimum=1)
        if event["error_code"] is not None:
            _code(event["error_code"], "transition_error")
        if kind.startswith("COMPLETE_"):
            expected = kind.removeprefix("COMPLETE_")
            if expected not in _TERMINAL or event["status"] != expected:
                _fail("transition_complete_status")
            if event["receipt_digest"] is not None:
                _blob(event["receipt_digest"], 64, "transition_receipt_digest")


def _parse_export(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_EXPORT:
        _fail("export_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentQueueError("export_encoding") from exc
    top_keys = {"schema", "config", "metadata", "jobs", "operations", "leases", "results", "transitions"}
    if type(value) is not dict or set(value) != top_keys or value["schema"] != _SCHEMA:
        _fail("export_keys")
    if raw != _json_bytes(value):
        _fail("export_noncanonical")
    config, config_bytes, config_digest = _parse_config(value["config"])
    metadata = value["metadata"]
    if type(metadata) is not dict or set(metadata) != {"head_root", "next_transition_seq", "next_admission_seq"}:
        _fail("export_metadata")
    head = _blob(metadata["head_root"], 64, "metadata_head")
    next_transition = _integer(metadata["next_transition_seq"], "metadata_transition_seq")
    next_admission = _integer(metadata["next_admission_seq"], "metadata_admission_seq")
    jobs = value["jobs"]
    if type(jobs) is not list:
        _fail("export_jobs")
    job_map: dict[str, dict[str, Any]] = {}
    operation_ids: set[bytes] = set()
    admission_seqs: set[int] = set()
    for index, raw_job in enumerate(jobs, start=1):
        keys = {
            "job_id", "operation_id", "material_digest", "artifact_ref", "artifact_bytes", "artifact_sha256",
            "artifact_sha3_512", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms",
            "updated_ms", "last_error_code",
        }
        if type(raw_job) is not dict or set(raw_job) != keys:
            _fail("job_keys")
        job_id = _token(raw_job["job_id"], "job_id")
        operation = _blob(raw_job["operation_id"], 64, "job_operation")
        material = _blob(raw_job["material_digest"], 64, "job_material")
        if job_id in job_map or operation in operation_ids:
            _fail("job_duplicate")
        metadata_value, sha256, sha3 = _parse_metadata(raw_job, int(config["artifact_bytes_cap"]))
        status = raw_job["status"]
        if status not in _STATUS:
            _fail("job_status")
        admission = _integer(raw_job["admission_seq"], "job_admission", minimum=1)
        if admission != index or admission in admission_seqs:
            _fail("job_admission_order")
        attempt = _integer(raw_job["attempt"], "job_attempt")
        for field in ("next_eligible_ms", "created_ms", "updated_ms"):
            _integer(raw_job[field], "job_time")
        error = raw_job["last_error_code"]
        if error is not None:
            _code(error, "job_error")
        expected_material = _sha(
            _MATERIAL_DOMAIN, config["queue_id"].encode("ascii"), job_id.encode("ascii"),
            _json_bytes(_metadata_json(metadata_value)), _blob(config["verifier_sha256"], 32, "config_verifier"),
        )
        expected_operation = _sha(_OPERATION_DOMAIN, config["queue_id"].encode("ascii"), job_id.encode("ascii"), expected_material)
        if material != expected_material or operation != expected_operation or sha256 != metadata_value["artifact_sha256"] or sha3 != metadata_value["artifact_sha3_512"]:
            _fail("job_material_binding")
        job = dict(raw_job)
        job["operation_id"] = operation
        job["material_digest"] = material
        job["metadata"] = metadata_value
        job_map[job_id] = job
        operation_ids.add(operation)
        admission_seqs.add(admission)
    if next_admission != len(jobs):
        _fail("metadata_admission_count")
    operations = value["operations"]
    if type(operations) is not list or len(operations) != len(jobs):
        _fail("operations_count")
    operation_map: dict[bytes, dict[str, Any]] = {}
    for raw_operation in operations:
        keys = {"operation_id", "job_id", "material_digest", "result_status", "result_receipt", "result_error_code"}
        if type(raw_operation) is not dict or set(raw_operation) != keys:
            _fail("operation_keys")
        operation = _blob(raw_operation["operation_id"], 64, "operation_id")
        job_id = _token(raw_operation["job_id"], "operation_job")
        material = _blob(raw_operation["material_digest"], 64, "operation_material")
        if operation in operation_map or job_id not in job_map or operation != job_map[job_id]["operation_id"] or material != job_map[job_id]["material_digest"]:
            _fail("operation_binding")
        status = raw_operation["result_status"]
        if status is not None and status not in _TERMINAL:
            _fail("operation_status")
        receipt = _blob(raw_operation["result_receipt"], None, "operation_receipt", nullable=True)
        if receipt is not None and len(receipt) > _MAX_RECEIPT:
            _fail("operation_receipt_bounds")
        error = raw_operation["result_error_code"]
        if error is not None:
            _code(error, "operation_error")
        operation_map[operation] = dict(raw_operation)
    if [str(item["job_id"]) for item in operations] != sorted(str(item["job_id"]) for item in operations):
        _fail("operation_order")
    leases = value["leases"]
    if type(leases) is not list:
        _fail("leases_shape")
    lease_map: dict[str, dict[str, Any]] = {}
    for raw_lease in leases:
        keys = {"job_id", "worker_id", "token", "attempt", "leased_ms", "expires_ms"}
        if type(raw_lease) is not dict or set(raw_lease) != keys:
            _fail("lease_keys")
        job_id = _token(raw_lease["job_id"], "lease_job")
        if job_id in lease_map or job_id not in job_map:
            _fail("lease_binding")
        _token(raw_lease["worker_id"], "lease_worker")
        token = _blob(raw_lease["token"], 24, "lease_token")
        attempt = _integer(raw_lease["attempt"], "lease_attempt", minimum=1)
        leased = _integer(raw_lease["leased_ms"], "lease_time")
        expires = _integer(raw_lease["expires_ms"], "lease_expiry")
        if expires <= leased or attempt != job_map[job_id]["attempt"] or job_map[job_id]["status"] != "LEASED":
            _fail("lease_state")
        lease_map[job_id] = dict(raw_lease)
        lease_map[job_id]["token"] = token
    if [str(item["job_id"]) for item in leases] != sorted(str(item["job_id"]) for item in leases):
        _fail("lease_order")
    results = value["results"]
    if type(results) is not list:
        _fail("results_shape")
    result_map: dict[bytes, dict[str, Any]] = {}
    for raw_result in results:
        keys = {"operation_id", "job_id", "terminal_status", "receipt_bytes", "error_code", "completed_ms"}
        if type(raw_result) is not dict or set(raw_result) != keys:
            _fail("result_keys")
        operation = _blob(raw_result["operation_id"], 64, "result_operation")
        job_id = _token(raw_result["job_id"], "result_job")
        if operation in result_map or operation not in operation_map or job_id not in job_map or job_map[job_id]["operation_id"] != operation:
            _fail("result_binding")
        status = raw_result["terminal_status"]
        if status not in _TERMINAL or job_map[job_id]["status"] != status:
            _fail("result_status")
        receipt = _blob(raw_result["receipt_bytes"], None, "result_receipt", nullable=True)
        if receipt is not None and len(receipt) > _MAX_RECEIPT:
            _fail("result_receipt_bounds")
        error = raw_result["error_code"]
        if status == "VERIFIED":
            if receipt is None or error is not None:
                _fail("result_verified_shape")
            try:
                receipt_value = json.loads(receipt.decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise IndependentQueueError("result_receipt_encoding") from exc
            if receipt != _json_bytes(receipt_value):
                _fail("result_receipt_noncanonical")
            parsed_receipt = _parse_receipt(receipt_value, config)
            job = job_map[job_id]
            if parsed_receipt["job_id"] != job_id or parsed_receipt["operation_id"] != operation or parsed_receipt["attempt"] != job["attempt"]:
                _fail("result_receipt_binding")
            evidence = parsed_receipt["evidence"]
            if evidence["artifact_bytes"] != job["artifact_bytes"] or evidence["artifact_sha256"] != _blob(job["artifact_sha256"], 32, "job_sha256") or evidence["artifact_sha3_512"] != _blob(job["artifact_sha3_512"], 64, "job_sha3"):
                _fail("result_receipt_artifact")
        else:
            if receipt is not None or error is None:
                _fail("result_terminal_shape")
            _code(error, "result_error")
        _integer(raw_result["completed_ms"], "result_time")
        result_map[operation] = dict(raw_result)
        result_map[operation]["receipt_bytes"] = receipt
        operation_row = operation_map[operation]
        if operation_row["result_status"] != status or operation_row["result_error_code"] != raw_result["error_code"]:
            _fail("operation_result_binding")
        operation_receipt = operation_row["result_receipt"]
        if (operation_receipt is None) != (receipt is None):
            _fail("operation_receipt_binding")
        if operation_receipt is not None and _blob(operation_receipt, None, "operation_receipt") != receipt:
            _fail("operation_receipt_binding")
    if [str(item["job_id"]) for item in results] != sorted(str(item["job_id"]) for item in results):
        _fail("result_order")
    for job_id, job in job_map.items():
        if (job["status"] == "LEASED") != (job_id in lease_map):
            _fail("lease_final_binding")
        if (job["status"] in _TERMINAL) != (job["operation_id"] in result_map):
            _fail("result_final_binding")
    for operation in operation_map.values():
        if operation["result_status"] is None and (operation["result_receipt"] is not None or operation["result_error_code"] is not None):
            _fail("operation_unfinished_result")
    transitions = value["transitions"]
    if type(transitions) is not list or next_transition != len(transitions):
        _fail("transition_count")
    expected_head = _sha(_GENESIS_DOMAIN, config["queue_id"].encode("ascii"), config_digest)
    replay: dict[str, str] = {}
    for sequence, raw_transition in enumerate(transitions, start=1):
        keys = {"sequence", "transition_kind", "job_id", "operation_id", "before_root", "after_root", "event_bytes", "event_digest"}
        if type(raw_transition) is not dict or set(raw_transition) != keys:
            _fail("transition_keys")
        if _integer(raw_transition["sequence"], "transition_sequence", minimum=1) != sequence:
            _fail("transition_order")
        kind = _token(raw_transition["transition_kind"], "transition_kind")
        job_id = _token(raw_transition["job_id"], "transition_job")
        operation = _blob(raw_transition["operation_id"], 64, "transition_operation")
        if job_id not in job_map or job_map[job_id]["operation_id"] != operation:
            _fail("transition_binding")
        before = _blob(raw_transition["before_root"], 64, "transition_before")
        after = _blob(raw_transition["after_root"], 64, "transition_after")
        event_bytes = _blob(raw_transition["event_bytes"], None, "transition_event")
        event_digest = _blob(raw_transition["event_digest"], 64, "transition_digest")
        if before != expected_head or _sha(_EVENT_DOMAIN, kind.encode("ascii"), event_bytes) != event_digest:
            _fail("transition_digest")
        try:
            event = json.loads(event_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IndependentQueueError("transition_event_encoding") from exc
        if event_bytes != _json_bytes(event):
            _fail("transition_event_noncanonical")
        _event_expected(kind, event)
        current = replay.get(job_id)
        if kind == "ADMIT":
            if current is not None or event["admission_seq"] != job_map[job_id]["admission_seq"]:
                _fail("transition_admit_replay")
            replay[job_id] = "QUEUED"
        elif kind == "CLAIM":
            if current != "QUEUED":
                _fail("transition_claim_replay")
            replay[job_id] = "LEASED"
        elif kind in {"RETRY_QUEUED", "LEASE_EXPIRE_QUEUED"}:
            if current != "LEASED" or event["status"] != "QUEUED":
                _fail("transition_retry_replay")
            replay[job_id] = "QUEUED"
        elif kind == "LEASE_EXPIRE_HELD":
            if current != "LEASED" or event["status"] != "HELD":
                _fail("transition_expire_replay")
            replay[job_id] = "HELD"
        elif kind.startswith("COMPLETE_"):
            expected = kind.removeprefix("COMPLETE_")
            if current != "LEASED" or event["status"] != expected:
                _fail("transition_complete_replay")
            replay[job_id] = expected
        expected_head = _sha(_HEAD_DOMAIN, expected_head, sequence.to_bytes(8, "big"), event_digest)
        if expected_head != after:
            _fail("transition_head")
    if expected_head != head:
        _fail("metadata_head")
    if set(replay) != set(job_map) or any(replay[job_id] != job["status"] for job_id, job in job_map.items()):
        _fail("transition_final_state")
    counts = {status: sum(1 for job in jobs if job["status"] == status) for status in sorted(_STATUS)}
    if counts["QUEUED"] + counts["LEASED"] > int(config["capacity"]):
        _fail("capacity_integrity")
    summary = {
        "schema": _SCHEMA, "queue_id": config["queue_id"], "head_root": _hex(head),
        "status_counts": counts, "lease_count": len(leases), "transition_count": len(transitions),
        "config_digest": _hex(config_digest),
    }
    return value, summary


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    value, summary = _parse_export(raw)
    if expected_config is not None and _json_bytes(expected_config) != _json_bytes(value["config"]):
        _fail("expected_config_mismatch")
    return summary


def _schema(connection: sqlite3.Connection) -> None:
    objects = connection.execute(
        "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    tables = {str(name) for kind, name in objects if kind == "table"}
    triggers = {str(name) for kind, name in objects if kind == "trigger"}
    if tables != _TABLES or triggers != _TRIGGERS:
        _fail("database_objects")
    for table, columns in _TABLE_COLUMNS.items():
        actual = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall())
        if actual != columns:
            _fail("database_columns")


def _db_export(connection: sqlite3.Connection) -> bytes:
    _schema(connection)
    def blob(value: Any) -> str | None:
        if value is None:
            return None
        if type(value) is not bytes:
            _fail("database_blob")
        return _hex(value)
    metadata_rows = connection.execute("SELECT * FROM queue_metadata ORDER BY id").fetchall()
    if len(metadata_rows) != 1:
        _fail("database_metadata")
    meta = metadata_rows[0]
    data = {
        "schema": _SCHEMA,
        "config": json.loads(bytes(meta[3]).decode("ascii")),
        "metadata": {"head_root": blob(meta[7]), "next_transition_seq": int(meta[8]), "next_admission_seq": int(meta[9])},
        "jobs": [
            {"job_id": str(row[0]), "operation_id": blob(row[1]), "material_digest": blob(row[2]), "artifact_ref": str(row[3]),
             "artifact_bytes": int(row[4]), "artifact_sha256": blob(row[5]), "artifact_sha3_512": blob(row[6]), "status": str(row[7]),
             "admission_seq": int(row[8]), "attempt": int(row[9]), "next_eligible_ms": int(row[10]), "created_ms": int(row[11]),
             "updated_ms": int(row[12]), "last_error_code": row[13]}
            for row in connection.execute("SELECT * FROM queue_jobs ORDER BY admission_seq")
        ],
        "operations": [
            {"operation_id": blob(row[0]), "job_id": str(row[1]), "material_digest": blob(row[2]), "result_status": row[3],
             "result_receipt": blob(row[4]), "result_error_code": row[5]}
            for row in connection.execute("SELECT * FROM queue_operations ORDER BY job_id")
        ],
        "leases": [
            {"job_id": str(row[0]), "worker_id": str(row[1]), "token": blob(row[2]), "attempt": int(row[3]),
             "leased_ms": int(row[4]), "expires_ms": int(row[5])}
            for row in connection.execute("SELECT * FROM queue_leases ORDER BY job_id")
        ],
        "results": [
            {"operation_id": blob(row[0]), "job_id": str(row[1]), "terminal_status": str(row[2]), "receipt_bytes": blob(row[3]),
             "error_code": row[4], "completed_ms": int(row[5])}
            for row in connection.execute("SELECT * FROM queue_results ORDER BY job_id")
        ],
        "transitions": [
            {"sequence": int(row[0]), "transition_kind": str(row[1]), "job_id": str(row[2]), "operation_id": blob(row[3]),
             "before_root": blob(row[4]), "after_root": blob(row[5]), "event_bytes": blob(row[6]), "event_digest": blob(row[7])}
            for row in connection.execute("SELECT * FROM queue_transitions ORDER BY sequence")
        ],
    }
    try:
        config_value = data["config"]
        config, config_bytes, config_digest = _parse_config(config_value)
        stored_config = bytes(meta[3])
        stored_digest = bytes(meta[4])
        stored_verifier = bytes(meta[5])
        if (
            int(meta[1]) != _SCHEMA_VERSION or str(meta[2]) != config["queue_id"]
            or stored_config != config_bytes or stored_digest != config_digest
            or stored_verifier != _blob(config["verifier_sha256"], 32, "config_verifier")
            or int(meta[6]) != int(config["artifact_bytes_cap"])
        ):
            _fail("database_metadata_binding")
    except (TypeError, ValueError) as exc:
        raise IndependentQueueError("database_metadata_binding") from exc
    return _json_bytes(data)


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=5.0)
        connection.execute("PRAGMA query_only=ON")
        raw = _db_export(connection)
        return verify_export_bytes(raw, expected_config=expected_config)
    except sqlite3.Error as exc:
        raise IndependentQueueError("database_read") from exc
    finally:
        try:
            connection.close()
        except UnboundLocalError:
            pass


def read_verified_job(
    path: Path,
    job_id: str,
    *,
    expected_config: Mapping[str, Any] | None = None,
) -> IndependentVerifiedQueueJob:
    """Verify a queue database, then extract one terminal VERIFIED result."""
    summary = verify_database(path, expected_config=expected_config)
    if type(job_id) is not str or _TOKEN.fullmatch(job_id) is None:
        _fail("job_id")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=5.0)
        connection.execute("PRAGMA query_only=ON")
        metadata = connection.execute("SELECT config_json FROM queue_metadata WHERE id=1").fetchone()
        row = connection.execute(
            "SELECT j.status,r.terminal_status,r.receipt_bytes FROM queue_jobs j "
            "LEFT JOIN queue_results r ON r.operation_id=j.operation_id WHERE j.job_id=?",
            (job_id,),
        ).fetchone()
        if metadata is None or row is None or str(row[0]) != "VERIFIED" or str(row[1]) != "VERIFIED" or row[2] is None:
            _fail("job_not_verified")
        config = json.loads(bytes(metadata[0]).decode("ascii"))
        receipt_bytes = bytes(row[2])
        try:
            receipt_value = json.loads(receipt_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IndependentQueueError("job_receipt_encoding") from exc
        if receipt_bytes != _json_bytes(receipt_value):
            _fail("job_receipt_noncanonical")
        receipt = _parse_receipt(receipt_value, config)
        evidence = receipt["evidence"]
        operation = receipt["operation_id"]
        acceptance_bytes = bytes(evidence["acceptance_bytes"])
        return IndependentVerifiedQueueJob(
            queue_id=str(config["queue_id"]),
            config_digest=bytes.fromhex(str(summary["config_digest"])),
            verifier_sha256=bytes(evidence["verifier_sha256"]),
            job_id=job_id,
            operation_id=operation,
            attempt=int(receipt["attempt"]),
            receipt_bytes=receipt_bytes,
            receipt_id=bytes(receipt["receipt_id"]),
            acceptance_bytes=acceptance_bytes,
            proof_acceptance_digest=bytes(evidence["proof_acceptance_digest"]),
            artifact_bytes=int(evidence["artifact_bytes"]),
            artifact_sha256=bytes(evidence["artifact_sha256"]),
            artifact_sha3_512=bytes(evidence["artifact_sha3_512"]),
            circuit_id=bytes(evidence["circuit_id"]),
            peak_job_commit_bytes=int(evidence["peak_job_commit_bytes"]),
            cap_bytes=int(evidence["cap_bytes"]),
            cap_enforced=bool(evidence["cap_enforced"]),
            active_process_limit=int(evidence["active_process_limit"]),
            timed_out=bool(evidence["timed_out"]),
            exit_code=int(evidence["exit_code"]),
            stdout_sha3_512=bytes(evidence["stdout_sha3_512"]),
            stderr_sha3_512=bytes(evidence["stderr_sha3_512"]),
        )
    except sqlite3.Error as exc:
        raise IndependentQueueError("database_read") from exc
    finally:
        if connection is not None:
            connection.close()


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE queue_metadata (
            id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
            queue_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL,
            verifier_sha256 BLOB NOT NULL, artifact_bytes_cap INTEGER NOT NULL,
            head_root BLOB NOT NULL, next_transition_seq INTEGER NOT NULL,
            next_admission_seq INTEGER NOT NULL
        );
        CREATE TABLE queue_jobs (
            job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, material_digest BLOB NOT NULL,
            artifact_ref TEXT NOT NULL, artifact_bytes INTEGER NOT NULL, artifact_sha256 BLOB NOT NULL,
            artifact_sha3_512 BLOB NOT NULL, status TEXT NOT NULL, admission_seq INTEGER NOT NULL UNIQUE,
            attempt INTEGER NOT NULL, next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL,
            updated_ms INTEGER NOT NULL, last_error_code TEXT
        );
        CREATE TABLE queue_operations (
            operation_id BLOB PRIMARY KEY, job_id TEXT NOT NULL UNIQUE, material_digest BLOB NOT NULL,
            result_status TEXT, result_receipt BLOB, result_error_code TEXT,
            FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id)
        );
        CREATE TABLE queue_leases (
            job_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, token BLOB NOT NULL,
            attempt INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL,
            FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id)
        );
        CREATE TABLE queue_results (
            operation_id BLOB PRIMARY KEY, job_id TEXT NOT NULL UNIQUE, terminal_status TEXT NOT NULL,
            receipt_bytes BLOB, error_code TEXT, completed_ms INTEGER NOT NULL,
            FOREIGN KEY(operation_id) REFERENCES queue_operations(operation_id), FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id)
        );
        CREATE TABLE queue_transitions (
            sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, job_id TEXT NOT NULL, operation_id BLOB NOT NULL,
            before_root BLOB NOT NULL, after_root BLOB NOT NULL, event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL UNIQUE,
            FOREIGN KEY(job_id) REFERENCES queue_jobs(job_id), FOREIGN KEY(operation_id) REFERENCES queue_operations(operation_id)
        );
        CREATE TRIGGER queue_jobs_no_delete BEFORE DELETE ON queue_jobs BEGIN SELECT RAISE(ABORT,'queue_jobs_append_only'); END;
        CREATE TRIGGER queue_jobs_no_update BEFORE UPDATE OF job_id,operation_id,material_digest,artifact_ref,artifact_bytes,artifact_sha256,artifact_sha3_512,admission_seq ON queue_jobs BEGIN SELECT RAISE(ABORT,'queue_jobs_identity_immutable'); END;
        CREATE TRIGGER queue_operations_no_delete BEFORE DELETE ON queue_operations BEGIN SELECT RAISE(ABORT,'queue_operations_append_only'); END;
        CREATE TRIGGER queue_transitions_no_update BEFORE UPDATE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transitions_append_only'); END;
        CREATE TRIGGER queue_transitions_no_delete BEFORE DELETE ON queue_transitions BEGIN SELECT RAISE(ABORT,'queue_transitions_append_only'); END;
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
        config_digest = _sha(_MATERIAL_DOMAIN, config_bytes)
        metadata = value["metadata"]
        verifier = _blob(config["verifier_sha256"], 32, "config_verifier")
        connection.execute(
            "INSERT INTO queue_metadata VALUES (?,?,?,?,?,?,?,?,?,?)",
            (1, _SCHEMA_VERSION, config["queue_id"], config_bytes, config_digest, verifier,
             config["artifact_bytes_cap"], _blob(metadata["head_root"], 64, "metadata_head"),
             metadata["next_transition_seq"], metadata["next_admission_seq"]),
        )
        for job in value["jobs"]:
            connection.execute(
                "INSERT INTO queue_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (job["job_id"], _blob(job["operation_id"], 64, "job_operation"), _blob(job["material_digest"], 64, "job_material"),
                 job["artifact_ref"], job["artifact_bytes"], _blob(job["artifact_sha256"], 32, "job_sha256"),
                 _blob(job["artifact_sha3_512"], 64, "job_sha3"), job["status"], job["admission_seq"], job["attempt"],
                 job["next_eligible_ms"], job["created_ms"], job["updated_ms"], job["last_error_code"]),
            )
        for operation in value["operations"]:
            connection.execute(
                "INSERT INTO queue_operations VALUES (?,?,?,?,?,?)",
                ( _blob(operation["operation_id"], 64, "operation_id"), operation["job_id"], _blob(operation["material_digest"], 64, "operation_material"),
                  operation["result_status"], None if operation["result_receipt"] is None else _blob(operation["result_receipt"], None, "operation_receipt"), operation["result_error_code"]),
            )
        for lease in value["leases"]:
            connection.execute(
                "INSERT INTO queue_leases VALUES (?,?,?,?,?,?)",
                (lease["job_id"], lease["worker_id"], _blob(lease["token"], 24, "lease_token"), lease["attempt"], lease["leased_ms"], lease["expires_ms"]),
            )
        for result in value["results"]:
            connection.execute(
                "INSERT INTO queue_results VALUES (?,?,?,?,?,?)",
                (_blob(result["operation_id"], 64, "result_operation"), result["job_id"], result["terminal_status"],
                 None if result["receipt_bytes"] is None else _blob(result["receipt_bytes"], None, "result_receipt"), result["error_code"], result["completed_ms"]),
            )
        for transition in value["transitions"]:
            connection.execute(
                "INSERT INTO queue_transitions VALUES (?,?,?,?,?,?,?,?)",
                (transition["sequence"], transition["transition_kind"], transition["job_id"], _blob(transition["operation_id"], 64, "transition_operation"),
                 _blob(transition["before_root"], 64, "transition_before"), _blob(transition["after_root"], 64, "transition_after"),
                 _blob(transition["event_bytes"], None, "transition_event"), _blob(transition["event_digest"], 64, "transition_digest")),
            )
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
    verified = verify_database(path, expected_config=value["config"])
    if verified != summary:
        _fail("restore_parity")
    return verified


__all__ = (
    "IndependentQueueError", "IndependentVerifiedQueueJob", "read_verified_job",
    "restore_export_to_fresh_database", "verify_database", "verify_export_bytes",
)
