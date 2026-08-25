"""Independent V7 queue reconstruction.

This reader knows only the V7 durable allowlist. It intentionally cannot parse
or reconstruct proof material and rejects the V6 schema as unsupported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
from typing import Any, Final, Mapping


class IndependentQueueError(RuntimeError):
    pass


SCHEMA_VERSION: Final[int] = 7
_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/v7"
_ADMISSION_CAP: Final[int] = 4_500_000_000
_PROCESS_TREE_CAP: Final[int] = 4_999_999_999
_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "queue_metadata": ("id", "schema_version", "queue_id", "config_json", "config_digest", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "profile_version", "profile_digest", "head_root", "next_transition_seq", "next_admission_seq", "nonterminal_count", "live_lease_count"),
    "queue_jobs": ("operation_ref", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "batch_position", "batch_root", "approved_source_registry_root", "qualification_flags", "status", "admission_seq", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"),
    "queue_leases": ("operation_ref", "worker_id", "token_digest", "attempt", "claim_sequence", "leased_ms", "expires_ms"),
    "queue_results": ("operation_ref", "terminal_status", "receipt_bytes", "error_code", "completed_ms", "attempt"),
    "queue_transitions": ("sequence", "transition_kind", "operation_ref", "before_root", "after_root", "event_bytes", "event_digest"),
}
_TABLES = frozenset(_TABLE_COLUMNS)
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/GENESIS/v7\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/EVENT/v7\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/HEAD/v7\x00"
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/MATERIAL/v7\x00"
_BATCH = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH/v7\x00"
_BATCH_LEAF = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-LEAF/v7\x00"
_BATCH_ROOT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/BATCH-ROOT/v7\x00"
_HANDOFF_PROTOCOL = "ISSUE_THEN_HANDOFF_V1"
_FORBIDDEN = ("artifact", "source_path", "patient", "provider", "case_id", "stdout", "stderr", "acceptance_bytes", "policy_result", "effective_directive")


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


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _fail("integer")
    return value.to_bytes(8, "big")


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
    try:
        return bytes.fromhex(value)
    except ValueError:
        _fail(code)


def _token(value: object, code: str, maximum: int = 128) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or _SAFE_TOKEN.fullmatch(value) is None:
        _fail(code)
    return value


def _code(value: object, code: str) -> str:
    if type(value) is not str or _SAFE_CODE.fullmatch(value) is None:
        _fail(code)
    return value


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


def _parse_config(raw: bytes, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("config_encoding")
    required = {"schema_version", "handoff_protocol", "queue_id", "capacity", "admission_cap_bytes", "process_tree_peak_cap_bytes", "active_process_limit", "profile_version", "profile_digest", "profile_epoch", "directives", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required or value["schema_version"] != SCHEMA_VERSION or value["handoff_protocol"] != _HANDOFF_PROTOCOL or value["admission_cap_bytes"] != _ADMISSION_CAP or type(value["process_tree_peak_cap_bytes"]) is not int or value["process_tree_peak_cap_bytes"] >= 5_000_000_000 or value["active_process_limit"] != 1 or value["proof_suite_id"] is not None or type(value["production_usable"]) is not bool or value["production_usable"] is not False or type(value["activation"]) is not bool or value["activation"] is not False:
        _fail("config_shape")
    _token(value["queue_id"], "config_queue_id", 96)
    _token(value["profile_version"], "config_profile_version", 96)
    _blob(value["profile_digest"], 64, "config_profile_digest")
    if value["directives"] != ["CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"]:
        _fail("config_directives")
    if expected_config is not None and value != dict(expected_config):
        _fail("config_binding")
    return value


def _parse_flags(raw: bytes) -> tuple[str, ...]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("flags_encoding")
    if type(value) is not dict or set(value) != {"qualification_flags"} or type(value["qualification_flags"]) is not list:
        _fail("flags_shape")
    flags = tuple(value["qualification_flags"])
    if tuple(sorted(flags)) != flags or len(set(flags)) != len(flags):
        _fail("flags_shape")
    for flag in flags:
        _token(flag, "flag")
    return flags


def _template_bytes(row: tuple[Any, ...]) -> bytes:
    return _json_bytes({
        "assertion_identifier": str(row[1]),
        "assertion_version": int(row[2]),
        "state_profile_version": str(row[3]),
        "valid_from_ms": int(row[4]),
        "valid_until_ms": int(row[5]),
        "approved_source_registry_root": None if row[8] is None else _hex(bytes(row[8])),
        "qualification_flags": list(_parse_flags(bytes(row[9]))),
    })


def _expected_batch_root(rows: list[tuple[Any, ...]] | tuple[tuple[Any, ...], ...]) -> bytes:
    ordered = tuple(sorted(rows, key=lambda row: int(row[6])))
    if not ordered or tuple(int(row[6]) for row in ordered) != tuple(range(len(ordered))):
        _fail("batch_positions")
    leaves = tuple(_sha(_BATCH_LEAF, _u64(int(row[6])), bytes(row[0]), _template_bytes(row)) for row in ordered)
    return _sha(_BATCH_ROOT, _u64(len(leaves)), b"".join(leaves))


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= 16 * 1024:
        _fail("receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("receipt_encoding")
    required = {"schema", "proof_accepted", "operation_ref", "assertion_identifier", "assertion_version", "state_profile_version", "valid_from_ms", "valid_until_ms", "batch_position", "batch_root", "approved_source_registry_root", "verifier_profile_version", "outcome_code", "error_code", "resource_code", "qualification_flags", "proof_suite_id", "production_usable", "activation"}
    if type(value) is not dict or set(value) != required or raw != _json_bytes(value) or value["schema"] != _SCHEMA or value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("receipt_keys")
    if type(value["proof_accepted"]) is not bool:
        _fail("receipt_acceptance")
    if value["operation_ref"] != value["operation_ref"].upper():
        _fail("receipt_operation_ref")
    _blob(value["operation_ref"], 32, "receipt_operation_ref")
    _token(value["assertion_identifier"], "receipt_assertion")
    if type(value["assertion_version"]) is not int or value["assertion_version"] < 1:
        _fail("receipt_assertion_version")
    _token(value["state_profile_version"], "receipt_profile")
    if type(value["valid_from_ms"]) is not int or type(value["valid_until_ms"]) is not int or not 0 <= value["valid_from_ms"] < value["valid_until_ms"]:
        _fail("receipt_window")
    if type(value["batch_position"]) is not int or not 0 <= value["batch_position"] < 256:
        _fail("receipt_position")
    if value["batch_root"] is not None:
        _blob(value["batch_root"], 64, "receipt_batch_root")
    if value["approved_source_registry_root"] is not None:
        _blob(value["approved_source_registry_root"], 64, "receipt_source_registry_root")
    _token(value["verifier_profile_version"], "receipt_verifier_profile")
    _code(value["outcome_code"], "receipt_outcome")
    for name in ("error_code", "resource_code"):
        if value[name] is not None:
            _code(value[name], "receipt_" + name)
    if type(value["qualification_flags"]) is not list:
        _fail("receipt_flags")
    _parse_flags(_json_bytes({"qualification_flags": value["qualification_flags"]}))
    return value


def _verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    try:
        connection = sqlite3.connect(str(path), timeout=5.0)
        connection.execute("PRAGMA foreign_keys=ON")
        tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if tables != _TABLES or any(_columns(connection, table) != _TABLE_COLUMNS[table] for table in _TABLES):
            _fail("schema")
        meta = connection.execute("SELECT * FROM queue_metadata WHERE id=1").fetchone()
        if meta is None or int(meta[1]) != SCHEMA_VERSION or int(meta[5]) != _ADMISSION_CAP or int(meta[6]) >= 5_000_000_000 or int(meta[7]) != 1:
            _fail("metadata")
        config = _parse_config(bytes(meta[3]), expected_config)
        config_digest = _sha(_MATERIAL, bytes(meta[3]))
        if bytes(meta[4]) != config_digest or bytes(meta[9]) != _blob(config["profile_digest"], 64, "profile_digest"):
            _fail("config_digest")
        jobs = [tuple(row) for row in connection.execute("SELECT * FROM queue_jobs ORDER BY admission_seq").fetchall()]
        results = {bytes(row[0]): tuple(row) for row in connection.execute("SELECT * FROM queue_results").fetchall()}
        leases = {bytes(row[0]): tuple(row) for row in connection.execute("SELECT * FROM queue_leases").fetchall()}
        if len(leases) > 1:
            _fail("lease_count")
        status_counts = {status: 0 for status in ("AWAITING_HANDOFF", "QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD")}
        refs = {bytes(job[0]) for job in jobs}
        batch_groups: dict[bytes, list[tuple[Any, ...]]] = {}
        for index, row in enumerate(jobs, start=1):
            ref = bytes(row[0])
            if len(ref) != 32 or int(row[11]) != index:
                _fail("operation_ref")
            _token(row[1], "assertion_identifier", 96)
            if type(row[2]) is not int or int(row[2]) < 1:
                _fail("assertion_version")
            _token(row[3], "state_profile_version", 96)
            if int(row[4]) < 0 or int(row[5]) <= int(row[4]) or not 0 <= int(row[6]) < 256:
                _fail("job_window")
            if row[7] is not None and len(bytes(row[7])) != 64:
                _fail("job_batch_root")
            if row[8] is not None and len(bytes(row[8])) != 64:
                _fail("job_registry_root")
            _parse_flags(bytes(row[9]))
            status = str(row[10])
            if status not in status_counts or int(row[12]) < 0 or int(row[12]) > 3:
                _fail("job_status")
            status_counts[status] += 1
            if row[7] is None:
                if int(row[6]) != 0:
                    _fail("single_position")
            else:
                batch_groups.setdefault(bytes(row[7]), []).append(row)
            if any(word in bytes(row[9]).decode("ascii", errors="ignore").lower() for word in _FORBIDDEN):
                _fail("forbidden_metadata")
            result = results.get(ref)
            if status in {"VERIFIED", "REJECTED", "HELD"}:
                if result is None or str(result[1]) != status or int(result[5]) != int(row[12]) or (status == "VERIFIED") != (result[2] is not None):
                    _fail("result_binding")
                if status != "VERIFIED" and (result[2] is not None or result[3] is None):
                    _fail("result_binding")
                if status == "VERIFIED":
                    receipt = _parse_receipt(bytes(result[2]))
                    if receipt["proof_accepted"] is not True:
                        _fail("receipt_acceptance")
                    expected_batch_root = None if row[7] is None else bytes(row[7]).hex().upper()
                    expected_flags = tuple(_parse_flags(bytes(row[9])))
                    expected_registry_root = None if row[8] is None else bytes(row[8]).hex().upper()
                    if bytes.fromhex(str(receipt["operation_ref"])) != ref or receipt["assertion_identifier"] != str(row[1]) or int(receipt["assertion_version"]) != int(row[2]) or receipt["state_profile_version"] != str(row[3]) or int(receipt["valid_from_ms"]) != int(row[4]) or int(receipt["valid_until_ms"]) != int(row[5]) or int(receipt["batch_position"]) != int(row[6]) or receipt["batch_root"] != expected_batch_root or receipt["approved_source_registry_root"] != expected_registry_root or receipt["qualification_flags"] != list(expected_flags) or receipt["verifier_profile_version"] != str(config["profile_version"]):
                        _fail("receipt_binding")
            elif result is not None:
                _fail("result_status")
            if status == "LEASED":
                if ref not in leases:
                    _fail("lease_binding")
            elif ref in leases:
                _fail("lease_status")
        for root, group in batch_groups.items():
            if _expected_batch_root(group) != root:
                _fail("batch_root_binding")
        expected_results = {bytes(row[0]) for row in jobs if str(row[10]) in {"VERIFIED", "REJECTED", "HELD"}}
        if set(results) != expected_results:
            _fail("result_set")
        expected_leases = {bytes(row[0]) for row in jobs if str(row[10]) == "LEASED"}
        if set(leases) != expected_leases:
            _fail("lease_set")
        if int(meta[13]) != sum(status_counts[s] for s in ("AWAITING_HANDOFF", "QUEUED", "LEASED")) or int(meta[14]) != len(leases):
            _fail("metadata_counts")
        expected_head = _sha(_GENESIS, str(config["queue_id"]).encode("ascii"), config_digest)
        transitions = [tuple(row) for row in connection.execute("SELECT * FROM queue_transitions ORDER BY sequence").fetchall()]
        events_by_ref: dict[bytes, list[dict[str, Any]]] = {}
        for index, row in enumerate(transitions, start=1):
            ref = bytes(row[2]) if row[2] is not None else None
            if int(row[0]) != index or ref is None or ref not in refs or bytes(row[3]) != expected_head or len(bytes(row[5])) > 4096:
                _fail("transition_chain")
            try:
                event = json.loads(bytes(row[5]).decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                _fail("transition_encoding")
            keys = {"schema", "sequence", "kind", "operation_ref", "status", "error_code", "attempt", "at_ms"}
            if type(event) is not dict or set(event) != keys or bytes(row[5]) != _json_bytes(event) or event["schema"] != _SCHEMA or int(event["sequence"]) != index or event["operation_ref"] != ref.hex().upper() or event["kind"] != str(row[1]) or event["status"] not in {"AWAITING_HANDOFF", "QUEUED", "LEASED", "VERIFIED", "REJECTED", "HELD"} or type(event["attempt"]) is not int or event["attempt"] < 0:
                _fail("transition_binding")
            digest = _sha(_EVENT, _u64(index), bytes(row[5]))
            after = _sha(_HEAD, expected_head, _u64(index), digest)
            if bytes(row[6]) != digest or bytes(row[4]) != after:
                _fail("transition_root")
            expected_head = after
            events_by_ref.setdefault(ref, []).append(event)
        if bytes(meta[10]) != expected_head or int(meta[11]) != len(transitions) or int(meta[12]) != len(jobs):
            _fail("head_binding")
        for job in jobs:
            ref = bytes(job[0])
            events = events_by_ref.get(ref, [])
            status = str(job[10])
            if not events or events[0]["kind"] != "ISSUED" or events[0]["status"] != "AWAITING_HANDOFF" or events[0]["attempt"] != 0 or events[0]["error_code"] is not None:
                _fail("lifecycle_issue")
            if status == "AWAITING_HANDOFF":
                if len(events) != 1:
                    _fail("lifecycle_awaiting")
                continue
            if status == "HELD" and len(events) == 2 and events[1]["kind"] == "HELD":
                if events[1]["status"] != "HELD" or events[1]["error_code"] != "fresh_handoff_required":
                    _fail("lifecycle_held")
                continue
            if len(events) < 2 or events[1]["kind"] != "HANDOFF_SUBMITTED" or events[1]["status"] != "QUEUED" or events[1]["attempt"] != 0 or events[1]["error_code"] is not None:
                _fail("lifecycle_handoff")
            if status == "QUEUED":
                if len(events) != 2:
                    _fail("lifecycle_queue")
                continue
            if status == "HELD" and len(events) == 3 and events[2]["kind"] == "HELD":
                if events[2]["status"] != "HELD" or events[2]["error_code"] != "fresh_handoff_required":
                    _fail("lifecycle_held")
                continue
            if len(events) < 3 or events[2]["kind"] != "LEASED" or events[2]["status"] != "LEASED" or events[2]["attempt"] != int(job[12]) or events[2]["error_code"] is not None:
                _fail("lifecycle_lease")
            if status == "LEASED":
                if len(events) != 3:
                    _fail("lifecycle_leased")
                continue
            result = results[ref]
            if len(events) != 4:
                _fail("lifecycle_terminal")
            terminal = events[3]
            if terminal["kind"] in {"HELD", "LEASE_EXPIRED"}:
                if status != "HELD" or str(result[3]) != "fresh_handoff_required" or terminal["status"] != "HELD" or terminal["error_code"] != "fresh_handoff_required" or terminal["attempt"] != int(result[5]):
                    _fail("lifecycle_expiry")
            elif terminal["kind"] == "COMPLETED":
                if terminal["status"] != str(result[1]) or terminal["error_code"] != (None if result[3] is None else str(result[3])) or terminal["attempt"] != int(result[5]):
                    _fail("lifecycle_completion")
            else:
                _fail("lifecycle_terminal")
        for blob in (bytes(meta[3]),):
            text_value = blob.decode("ascii", errors="ignore").lower()
            if any(word in text_value for word in ("artifact_ref", "artifact_sha", "stdout_sha", "stderr_sha", "acceptance_bytes", "source_path")):
                _fail("forbidden_schema_data")
        return {"schema": _SCHEMA, "queue_id": str(config["queue_id"]), "head_root": bytes(meta[10]), "status_counts": status_counts, "transition_count": len(transitions), "verified_count": status_counts["VERIFIED"], "proof_bytes_persisted": False, "path_custody": False, "proof_suite_id": None, "production_usable": False, "activation": False}
    except sqlite3.Error:
        _fail("database_sqlite")
    finally:
        try:
            connection.close()
        except UnboundLocalError:
            pass


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return _verify_database(path, expected_config=expected_config)


def _job_from_rows(config: Mapping[str, Any], config_digest: bytes, row: tuple[Any, ...], result: tuple[Any, ...]) -> IndependentVerifiedQueueJob:
    receipt_raw = bytes(result[2])
    receipt = _parse_receipt(receipt_raw)
    ref = bytes(row[0])
    return IndependentVerifiedQueueJob(str(config["queue_id"]), config_digest, ref, str(row[10]), bool(receipt["proof_accepted"]), int(result[5]), receipt_raw, _sha(_MATERIAL, receipt_raw), str(row[1]), int(row[2]), str(row[3]), int(row[4]), int(row[5]), int(row[6]), None if row[7] is None else bytes(row[7]), None if row[8] is None else bytes(row[8]), str(receipt["verifier_profile_version"]), str(receipt["outcome_code"]), tuple(receipt["qualification_flags"]))


def read_verified_batch(path: Path, selector: bytes | None = None) -> IndependentVerifiedQueueBatch:
    summary = verify_database(path)
    with closing(sqlite3.connect(str(path), timeout=5.0)) as connection:
        config_raw = bytes(connection.execute("SELECT config_json FROM queue_metadata WHERE id=1").fetchone()[0])
        config = _parse_config(config_raw)
        config_digest = _sha(_MATERIAL, config_raw)
        rows = [tuple(row) for row in connection.execute("SELECT * FROM queue_jobs WHERE status='VERIFIED' ORDER BY admission_seq").fetchall()]
        result_map = {bytes(row[0]): tuple(row) for row in connection.execute("SELECT * FROM queue_results WHERE terminal_status='VERIFIED'").fetchall()}
    if selector is not None and type(selector) is not bytes:
        _fail("batch_selector")
    if rows:
        groups: dict[bytes | None, list[tuple[Any, ...]]] = {}
        for row in rows:
            groups.setdefault(None if row[7] is None else bytes(row[7]), []).append(row)
        if selector is not None:
            selected: list[tuple[Any, ...]] = []
            for group in groups.values():
                refs = tuple(bytes(row[0]) for row in group)
                member = _sha(_BATCH, b"".join(refs))
                batch_id = _sha(_BATCH, config_digest, b"" if group[0][7] is None else bytes(group[0][7]), member)
                if selector in {member, batch_id}:
                    selected = group
                    break
            if not selected:
                _fail("batch_selector")
            rows = selected
        elif len(groups) > 1:
            rows = next(iter(groups.values()))
        rows.sort(key=lambda row: (int(row[6]), int(row[11])) )
        if tuple(int(row[6]) for row in rows) != tuple(range(len(rows))):
            _fail("batch_order")
    jobs = tuple(_job_from_rows(config, config_digest, row, result_map[bytes(row[0])]) for row in rows)
    refs = tuple(job.operation_ref for job in jobs)
    member_digest = _sha(_BATCH, b"".join(refs))
    root = None if not jobs else jobs[0].batch_root
    batch_id = _sha(_BATCH, config_digest, b"" if root is None else root, member_digest)
    batch = IndependentBatchAcceptance(_sha(_GENESIS, str(config["queue_id"]).encode("ascii"), config_digest), bytes(summary["head_root"]), config_digest, refs, member_digest, batch_id, len(jobs), int(summary["transition_count"]))
    return IndependentVerifiedQueueBatch(batch, jobs)


def read_verified_jobs(path: Path) -> tuple[IndependentVerifiedQueueJob, ...]:
    return read_verified_batch(path).jobs


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if type(raw) is not bytes or not raw:
        _fail("export_bytes")
    with tempfile.TemporaryDirectory(prefix="bl-v7-export-") as directory:
        path = Path(directory) / "queue.sqlite"
        path.write_bytes(raw)
        return verify_database(path, expected_config=expected_config)


def restore_export_to_fresh_database(*, export_bytes: bytes, destination: Path, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(destination, Path) or not destination.parent.is_dir():
        _fail("restore_path")
    if destination.exists():
        _fail("restore_exists")
    destination.write_bytes(export_bytes)
    try:
        return verify_database(destination, expected_config=expected_config)
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise


__all__ = ("IndependentQueueError", "IndependentVerifiedQueueBatch", "IndependentVerifiedQueueJob", "IndependentBatchAcceptance", "read_verified_batch", "read_verified_jobs", "restore_export_to_fresh_database", "verify_database", "verify_export_bytes", "_parse_config")
