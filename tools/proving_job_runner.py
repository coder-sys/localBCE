"""Serial, fail-closed job control for verified Blind Ledger proof runs.

This operations wrapper invokes ``tools.run_verified_bootloader_proof``. It does
not adjudicate production claims or weaken the requirement that a proof, its
public output, and the protected Cairo source manifest all verify successfully.
Generated jobs and artifacts must live outside the application source tree.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import secrets
import shutil
import socket
import stat
import sys
import time
from typing import Any

from tools.batch_package import validate_batch_package
from tools.encrypted_witness_envelope import (
    validate_envelope,
    validate_envelope_authorization,
)
from tools import proving_evidence_policy as evidence_policy
from tools.proving_process_boundary import ProvingProcessError, run_contained_process
from tools.proving_resource_policy import (
    MAX_AUDIT_BYTES,
    MAX_AUDIT_EVENTS,
    MAX_AUDIT_LINE_BYTES,
    MAX_JOB_BYTES,
    MAX_NONTERMINAL_JOBS,
    MAX_OWNED_FILES,
    MAX_QUEUE_BYTES,
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    MAX_TOTAL_JOBS,
    ProvingResourcePolicyError,
    ProvingResourcePolicyV1,
    derive_policy,
    policy_file_bytes,
    read_policy_file,
    validate_bound_policy,
)


ROOT = Path(__file__).resolve().parents[1]
PROTECTED_CAIRO = ROOT / "zk-cairo-sharp"
RUNNER_SCHEMA_VERSION = 2
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TERMINAL_STATES = {"succeeded", "failed"}
AUDIT_SCHEMA_VERSION = 1
PACKAGE_RESERVATION_SCHEMA_VERSION = 1
MAX_PACKAGE_RESERVATION_BYTES = 4096
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_STATUS_BYTES = 2 * 1024 * 1024
_ADMISSION_EVENT_RESERVE = 1 + (2 * 2) + 1


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _path_error(code: str) -> RuntimeError:
    return RuntimeError(code)


_PUBLIC_CODE_PATTERN = re.compile(
    r"(?:batch|encrypted|evidence|proof|proving|queue|trusted)_[a-z0-9_]{1,95}\Z"
)


def _public_call(operation: Any, fallback: str) -> Any:
    code = fallback
    try:
        return operation()
    except Exception as exc:
        candidate = str(exc)
        if _PUBLIC_CODE_PATTERN.fullmatch(candidate):
            code = candidate
    raise RuntimeError(code)


def _regular_file_stat(path: Path) -> os.stat_result:
    if not isinstance(path, Path):
        raise _path_error("queue_file_invalid")
    try:
        before = os.lstat(path)
    except OSError:
        raise _path_error("queue_file_unavailable") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise _path_error("queue_file_not_regular")
    return before


def _bounded_regular_read(path: Path, maximum_bytes: int) -> bytes:
    if type(maximum_bytes) is not int or not 0 < maximum_bytes <= MAX_JOB_BYTES:
        raise _path_error("queue_file_cap_invalid")
    before = _regular_file_stat(path)
    if before.st_size > maximum_bytes:
        raise _path_error("queue_file_cap")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum_bytes:
            raise _path_error("queue_file_identity")
        data = bytearray()
        while len(data) <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum_bytes:
                raise _path_error("queue_file_cap")
        after_open = os.fstat(descriptor)
    except RuntimeError as exc:
        raise exc
    except (OSError, ValueError):
        raise _path_error("queue_file_read") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise _path_error("queue_file_close") from None
    try:
        after = os.lstat(path)
    except OSError:
        raise _path_error("queue_file_replaced") from None
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or opened_identity != identity
        or after_identity != identity
        or len(data) != before.st_size
        or len(data) != after.st_size
        or len(data) != after_open.st_size
    ):
        raise _path_error("queue_file_identity")
    return bytes(data)


def _hash_regular_file(path: Path, maximum_bytes: int) -> tuple[int, str, str]:
    before = _regular_file_stat(path)
    if before.st_size > maximum_bytes:
        raise _path_error("queue_file_cap")
    descriptor: int | None = None
    sha256 = hashlib.sha256()
    sha3 = hashlib.sha3_512()
    total = 0
    try:
        flags = os.O_RDONLY | (os.O_BINARY if hasattr(os, "O_BINARY") else 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum_bytes:
            raise _path_error("queue_file_identity")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise _path_error("queue_file_cap")
            sha256.update(chunk)
            sha3.update(chunk)
        after_open = os.fstat(descriptor)
    except RuntimeError as exc:
        raise exc
    except (OSError, ValueError):
        raise _path_error("queue_file_read") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise _path_error("queue_file_close") from None
    try:
        after = os.lstat(path)
    except OSError:
        raise _path_error("queue_file_replaced") from None
    expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != expected
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != expected
        or (after_open.st_dev, after_open.st_ino, after_open.st_size, after_open.st_mtime_ns) != expected
        or total != before.st_size
    ):
        raise _path_error("queue_file_identity")
    return total, sha256.hexdigest(), sha3.hexdigest()


def _sha256_file(path: Path) -> str:
    """Bounded compatibility helper used only by focused evidence tests."""

    return _hash_regular_file(path, MAX_JOB_BYTES)[1]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _path_error("queue_json_duplicate_key")
        result[key] = value
    return result


def _write_bytes_atomic(path: Path, payload: bytes, *, maximum_bytes: int = MAX_JSON_BYTES) -> None:
    if type(payload) is not bytes or len(payload) > maximum_bytes:
        raise _path_error("queue_write_cap")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    except OSError:
        raise _path_error("queue_write") from None
    finally:
        temporary.unlink(missing_ok=True)


def _write_json_atomic(path: Path, value: object) -> None:
    _write_bytes_atomic(path, _canonical_json_bytes(value) + b"\n")


def _read_json(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    try:
        value = json.loads(
            _bounded_regular_read(path, maximum_bytes).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except RuntimeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _path_error("queue_json_invalid") from None
    if not isinstance(value, dict):
        raise _path_error("queue_json_object")
    return value


def _prepare_queue_root(path: Path) -> Path:
    if not isinstance(path, Path):
        raise _path_error("queue_root_invalid")
    candidate = Path(os.path.abspath(os.fspath(path)))
    try:
        existing = os.lstat(candidate)
    except FileNotFoundError:
        existing = None
    except OSError:
        raise _path_error("queue_root_unavailable") from None
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode):
            raise _path_error("queue_root_not_directory")
        if not stat.S_ISDIR(existing.st_mode):
            raise _path_error("queue_root_not_directory")
    root = candidate.resolve()
    try:
        root.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise _path_error("queue_root_inside_source")
    try:
        if root.exists() and (root.is_symlink() or not root.is_dir()):
            raise _path_error("queue_root_not_directory")
        root.mkdir(parents=True, exist_ok=True)
        for directory in (root / "jobs", root / "package_claims"):
            if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
                raise _path_error("queue_root_not_directory")
            directory.mkdir(exist_ok=True)
    except RuntimeError:
        raise
    except OSError:
        raise _path_error("queue_root_unavailable") from None
    return root


def _reserve_package_once(root: Path, package_sha256: str, job_id: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", package_sha256):
        raise _path_error("queue_package_digest")
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise _path_error("queue_job_id")
    reservation = root / "package_claims" / package_sha256
    payload = _canonical_json_bytes(
        {
            "schema_version": PACKAGE_RESERVATION_SCHEMA_VERSION,
            "package_sha256": package_sha256,
            "job_id": job_id,
            "reserved_at": _utc_now(),
        }
    ) + b"\n"

    def existing_is_same_job() -> bool:
        try:
            existing_bytes = _bounded_regular_read(reservation, MAX_PACKAGE_RESERVATION_BYTES)
            if len(existing_bytes) > MAX_PACKAGE_RESERVATION_BYTES:
                return False
            existing = json.loads(existing_bytes.decode("utf-8"))
        except (OSError, RuntimeError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        return (
            isinstance(existing, dict)
            and set(existing)
            == {"schema_version", "package_sha256", "job_id", "reserved_at"}
            and existing.get("schema_version") == PACKAGE_RESERVATION_SCHEMA_VERSION
            and existing.get("package_sha256") == package_sha256
            and existing.get("job_id") == job_id
            and isinstance(existing.get("reserved_at"), str)
        )

    temporary = reservation.with_name(
        f".{reservation.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, reservation)
        except FileExistsError as exc:
            if existing_is_same_job():
                return
            raise _path_error("queue_package_replay") from None
    finally:
        temporary.unlink(missing_ok=True)


def _process_is_alive(pid: int) -> bool:
    if os.name == "nt":
        process_query_limited_information = 0x1000
        error_access_denied = 5
        error_invalid_parameter = 87
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        error = ctypes.get_last_error()
        if error == error_invalid_parameter:
            return False
        if error == error_access_denied:
            return True
        raise OSError(error, f"unable to inspect process {pid}")

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _remove_stale_process_lock(path: Path) -> bool:
    try:
        payload = _read_json(path)
    except (OSError, RuntimeError, json.JSONDecodeError):
        return False
    if payload.get("hostname") != socket.gethostname():
        return False
    pid = payload.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
        return False
    try:
        alive = _process_is_alive(pid)
    except OSError:
        return False
    if not alive:
        path.unlink(missing_ok=True)
        return True
    return False


class _AuditLock:
    def __init__(self, queue_root: Path) -> None:
        self.path = queue_root / ".audit.lock"
        self.descriptor: int | None = None

    def __enter__(self) -> "_AuditLock":
        for attempt in range(2):
            try:
                self.descriptor = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                break
            except FileExistsError as exc:
                if attempt == 0 and _remove_stale_process_lock(self.path):
                    continue
                raise _path_error("queue_audit_locked") from None
        assert self.descriptor is not None
        payload = _canonical_json_bytes(
            {"pid": os.getpid(), "hostname": socket.gethostname(), "started_at": _utc_now()}
        ) + b"\n"
        os.write(self.descriptor, payload)
        os.fsync(self.descriptor)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        self.path.unlink(missing_ok=True)


def _verified_audit_events(root: Path) -> list[dict[str, Any]]:
    path = root / "audit.jsonl"
    try:
        initial = os.lstat(path)
    except FileNotFoundError:
        return []
    except OSError:
        raise _path_error("queue_audit_unavailable") from None
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
        raise _path_error("queue_audit_not_regular")
    if initial.st_size > MAX_AUDIT_BYTES:
        raise _path_error("queue_audit_bytes")
    events: list[dict[str, Any]] = []
    previous_hash = ""
    try:
        stream = path.open("rb")
    except OSError:
        raise _path_error("queue_audit_unavailable") from None
    try:
      line_number = 0
      while True:
        raw_line = stream.readline(MAX_AUDIT_LINE_BYTES + 1)
        if not raw_line:
            break
        line_number += 1
        if len(raw_line) > MAX_AUDIT_LINE_BYTES:
            raise _path_error("queue_audit_line_bytes")
        if not raw_line.endswith(b"\n"):
            raise _path_error("queue_audit_line_encoding")
        line = raw_line[:-1]
        try:
            event = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError):
            raise _path_error("queue_audit_json") from None
        if not isinstance(event, dict):
            raise _path_error("queue_audit_event")
        if line_number > MAX_AUDIT_EVENTS:
            raise _path_error("queue_audit_events")
        recorded_hash = event.get("event_sha256")
        unsigned = dict(event)
        unsigned.pop("event_sha256", None)
        if event.get("sequence") != line_number or event.get("previous_event_sha256") != previous_hash:
            raise _path_error("queue_audit_chain")
        computed_hash = _sha256_bytes(_canonical_json_bytes(unsigned))
        if recorded_hash != computed_hash:
            raise _path_error("queue_audit_integrity")
        previous_hash = computed_hash
        events.append(event)
    finally:
        stream.close()
    try:
        final = os.lstat(path)
    except OSError:
        raise _path_error("queue_audit_replaced") from None
    if (
        stat.S_ISLNK(final.st_mode)
        or not stat.S_ISREG(final.st_mode)
        or (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
        != (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns)
    ):
        raise _path_error("queue_audit_replaced")
    return events


def _append_audit_event_unlocked(
    root: Path,
    events: list[dict[str, Any]],
    event_type: str,
    details: dict[str, object],
) -> None:
    if len(events) >= MAX_AUDIT_EVENTS:
        raise _path_error("queue_audit_events")
    event: dict[str, object] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "sequence": len(events) + 1,
        "previous_event_sha256": events[-1]["event_sha256"] if events else "",
        "recorded_at": _utc_now(),
        "event_type": event_type,
        "details": details,
    }
    event["event_sha256"] = _sha256_bytes(_canonical_json_bytes(event))
    raw = _canonical_json_bytes(event) + b"\n"
    if len(raw) > MAX_AUDIT_LINE_BYTES:
        raise _path_error("queue_audit_line_bytes")
    path = root / "audit.jsonl"
    descriptor: int | None = None
    try:
        try:
            before = os.lstat(path)
        except FileNotFoundError:
            before = None
        if before is not None and (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)):
            raise _path_error("queue_audit_not_regular")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        expected_size = 0 if before is None else before.st_size
        expected_identity = None if before is None else (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != expected_size
            or expected_identity is not None
            and (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != expected_identity
        ):
            raise _path_error("queue_audit_replaced")
        if opened.st_size + len(raw) > MAX_AUDIT_BYTES:
            raise _path_error("queue_audit_bytes")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise _path_error("queue_audit_write")
            offset += written
        os.fsync(descriptor)
        after_open = os.fstat(descriptor)
        if after_open.st_size != opened.st_size + len(raw):
            raise _path_error("queue_audit_write")
    except RuntimeError:
        raise
    except OSError:
        raise _path_error("queue_audit_write") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise _path_error("queue_audit_write") from None
    try:
        final = os.lstat(path)
    except OSError:
        raise _path_error("queue_audit_replaced") from None
    if (
        stat.S_ISLNK(final.st_mode)
        or not stat.S_ISREG(final.st_mode)
        or final.st_size != expected_size + len(raw)
        or before is not None
        and (final.st_dev, final.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise _path_error("queue_audit_replaced")


def _append_audit_event(root: Path, event_type: str, details: dict[str, object]) -> None:
    with _AuditLock(root):
        events = _verified_audit_events(root)
        _append_audit_event_unlocked(root, events, event_type, details)


def _require_job_audit_binding(root: Path, request: dict[str, Any]) -> None:
    expected = {
        "job_id": request["job_id"],
        "request_sha256": request["request_sha256"],
        "input_kind": request.get("input_kind", "synthetic"),
        "package_sha256": request.get("package_sha256", ""),
        "authorized_principal": request.get("authorized_principal", ""),
        "agency_id": request.get("agency_id", ""),
        "resource_policy_sha256": request.get("resource_policy_sha256", ""),
    }
    for event in _verified_audit_events(root):
        if event.get("event_type") == "job_enqueued" and event.get("details") == expected:
            return
    raise _path_error("queue_enqueue_audit_binding")


def _validate_positive(name: str, value: int) -> None:
    if type(value) is not int or value < 1:
        raise _path_error("queue_claim_count")


def _load_batch_package_bounded(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_bounded_regular_read(path.resolve(), MAX_JSON_BYTES).decode("utf-8"))
        return validate_batch_package(value)
    except RuntimeError:
        raise _path_error("queue_package_invalid") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _path_error("queue_package_json") from None


def _load_envelope_bounded(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_bounded_regular_read(path.resolve(), 2 * 1024 * 1024).decode("utf-8"))
        return validate_envelope(value)
    except RuntimeError:
        raise _path_error("queue_envelope_invalid") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _path_error("queue_envelope_json") from None


def _measure_queue(root: Path, policy: ProvingResourcePolicyV1) -> tuple[int, int, int, int]:
    """Return (regular-file count, bytes, total jobs, nonterminal jobs)."""

    file_count = 0
    total_bytes = 0

    def visit(directory: Path, *, job_bytes: list[int] | None = None, count_global: bool = True) -> None:
        nonlocal file_count, total_bytes
        try:
            entries = os.scandir(directory)
        except OSError:
            raise _path_error("queue_measurement") from None
        try:
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    raise _path_error("queue_measurement") from None
                if stat.S_ISLNK(info.st_mode):
                    raise _path_error("queue_symlink")
                if stat.S_ISREG(info.st_mode):
                    if count_global:
                        file_count += 1
                        total_bytes += int(info.st_size)
                    if job_bytes is not None:
                        job_bytes[0] += int(info.st_size)
                        if job_bytes[0] > policy.max_job_bytes:
                            raise _path_error("queue_job_bytes")
                elif stat.S_ISDIR(info.st_mode):
                    visit(Path(entry.path), job_bytes=job_bytes, count_global=count_global)
                else:
                    raise _path_error("queue_nonregular")
                if count_global and (file_count > policy.max_owned_files or total_bytes > policy.max_queue_bytes):
                    raise _path_error("queue_capacity")
        finally:
            entries.close()

    visit(root)
    jobs_directory = root / "jobs"
    total_jobs = 0
    nonterminal_jobs = 0
    try:
        job_entries = os.scandir(jobs_directory)
    except OSError:
        raise _path_error("queue_measurement") from None
    try:
        for entry in job_entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise _path_error("queue_job_directory")
            total_jobs += 1
            if total_jobs > policy.max_total_jobs:
                raise _path_error("queue_total_capacity")
            job_bytes = [0]
            visit(Path(entry.path), job_bytes=job_bytes, count_global=False)
            status_path = Path(entry.path) / "status.json"
            status = _read_json(status_path, maximum_bytes=MAX_STATUS_BYTES)
            if status.get("state") in {"queued", "retrying", "running"}:
                nonterminal_jobs += 1
                if nonterminal_jobs > policy.max_nonterminal_jobs:
                    raise _path_error("queue_nonterminal_capacity")
    finally:
        job_entries.close()
    return file_count, total_bytes, total_jobs, nonterminal_jobs


def _measure_job_bytes(job_dir: Path, policy: ProvingResourcePolicyV1) -> int:
    total = 0

    def visit(directory: Path) -> None:
        nonlocal total
        try:
            entries = os.scandir(directory)
        except OSError:
            raise _path_error("queue_measurement") from None
        try:
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    raise _path_error("queue_measurement") from None
                if stat.S_ISLNK(info.st_mode):
                    raise _path_error("queue_symlink")
                if stat.S_ISREG(info.st_mode):
                    total += int(info.st_size)
                    if total > policy.max_job_bytes:
                        raise _path_error("queue_job_bytes")
                elif stat.S_ISDIR(info.st_mode):
                    visit(Path(entry.path))
                else:
                    raise _path_error("queue_nonregular")
        finally:
            entries.close()

    visit(job_dir)
    return total


def _remove_uncommitted_job(job_dir: Path) -> None:
    try:
        if job_dir.is_symlink():
            raise _path_error("queue_job_directory")
        if job_dir.exists():
            shutil.rmtree(job_dir)
    except RuntimeError:
        raise
    except OSError:
        raise _path_error("queue_rollback") from None


def enqueue_job(
    queue_root: Path,
    *,
    job_id: str,
    claim_count: int,
) -> dict[str, Any]:
    return _public_call(
        lambda: (
            _path_error("queue_synthetic_production")
            if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}
            else _enqueue_request(
                queue_root,
                job_id=job_id,
                claim_count=claim_count,
                batch_package_path=None,
            )
        ),
        "queue_request_rejected",
    )


def enqueue_package_job(
    queue_root: Path,
    *,
    job_id: str,
    batch_package_path: Path,
) -> dict[str, Any]:
    def operation() -> dict[str, Any]:
        if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
            raise _path_error("queue_plaintext_production")
        package = _load_batch_package_bounded(batch_package_path)
        return _enqueue_request(
            queue_root,
            job_id=job_id,
            claim_count=int(package["claim_count"]),
            batch_package_path=batch_package_path.resolve(),
            package=package,
        )

    return _public_call(
        operation,
        "queue_request_rejected",
    )


def enqueue_encrypted_package_job(
    queue_root: Path,
    *,
    job_id: str,
    encrypted_envelope_path: Path,
    batch_record: dict[str, Any],
    authenticated_principal: str,
) -> dict[str, Any]:
    def operation() -> dict[str, Any]:
        from tools.proving_submission import validate_batch_record

        validated_record = validate_batch_record(dict(batch_record))
        envelope = _load_envelope_bounded(encrypted_envelope_path)
        validate_envelope_authorization(
            envelope,
            authenticated_principal=authenticated_principal,
        )
        return _enqueue_request(
            queue_root,
            job_id=job_id,
            claim_count=int(envelope["claim_count"]),
            batch_package_path=None,
            encrypted_envelope_path=encrypted_envelope_path.resolve(),
            envelope=envelope,
            batch_record=validated_record,
            authenticated_principal=authenticated_principal,
        )

    return _public_call(
        operation,
        "queue_request_rejected",
    )


def _enqueue_request(
    queue_root: Path,
    *,
    job_id: str,
    claim_count: int,
    batch_package_path: Path | None,
    package: dict[str, Any] | None = None,
    encrypted_envelope_path: Path | None = None,
    envelope: dict[str, Any] | None = None,
    batch_record: dict[str, Any] | None = None,
    authenticated_principal: str = "",
) -> dict[str, Any]:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise _path_error("queue_job_id")
    _validate_positive("claim_count", claim_count)
    policy = derive_policy()

    root = _prepare_queue_root(queue_root)
    job_dir = root / "jobs" / job_id
    with _AuditLock(root):
        events = _verified_audit_events(root)
        _, _, total_jobs, nonterminal_jobs = _measure_queue(root, policy)
        if total_jobs >= policy.max_total_jobs:
            raise _path_error("queue_total_capacity")
        if nonterminal_jobs >= policy.max_nonterminal_jobs:
            raise _path_error("queue_nonterminal_capacity")
        if len(events) + _ADMISSION_EVENT_RESERVE > policy.max_audit_events:
            raise _path_error("queue_audit_headroom")
        try:
            audit_size = (root / "audit.jsonl").stat().st_size
        except FileNotFoundError:
            audit_size = 0
        except OSError:
            raise _path_error("queue_audit_unavailable") from None
        if audit_size + (_ADMISSION_EVENT_RESERVE * policy.max_audit_line_bytes) > policy.max_audit_bytes:
            raise _path_error("queue_audit_headroom")

        reservation = root / "package_claims" / str(package["package_sha256"]) if package is not None else None
        reservation_preexisting = bool(reservation and reservation.exists())
        try:
            if job_dir.exists():
                raise _path_error("queue_duplicate_job")
            if package is not None:
                _reserve_package_once(root, str(package["package_sha256"]), job_id)
            job_dir.mkdir()
            request: dict[str, Any] = {
                "schema_version": RUNNER_SCHEMA_VERSION,
                "job_id": job_id,
                "claim_count": claim_count,
                "created_at": _utc_now(),
                "input_kind": (
                    "encrypted_envelope"
                    if encrypted_envelope_path is not None
                    else "batch_package" if batch_package_path is not None else "synthetic"
                ),
                "resource_policy": policy.as_json(),
                "resource_policy_sha256": policy.digest,
            }
            _write_bytes_atomic(job_dir / "resource_policy.json", policy_file_bytes(policy))
            if batch_package_path is not None:
                assert package is not None
                package_snapshot = job_dir / "batch_package.json"
                _write_bytes_atomic(
                    package_snapshot,
                    _bounded_regular_read(batch_package_path, MAX_JSON_BYTES),
                )
                _load_batch_package_bounded(package_snapshot)
                request.update(
                    {
                        "package_sha256": package["package_sha256"],
                        "witness_sha256": package["witness_sha256"],
                        "package_id": package["package_id"],
                        "batch_id": package["batch_id"],
                        "authorized_principal": package["authorization"]["principal"],
                        "agency_id": package["authorization"].get("agency_id", "local-dev"),
                        "retain_until": package["retain_until"],
                    }
                )
            if encrypted_envelope_path is not None:
                assert envelope is not None and batch_record is not None
                _write_json_atomic(job_dir / "witness.envelope.json", envelope)
                _load_envelope_bounded(job_dir / "witness.envelope.json")
                _write_json_atomic(job_dir / "batch_record.json", batch_record)
                request.update(
                    {
                        "package_sha256": envelope["package_sha256"],
                        "witness_sha256": envelope["witness_sha256"],
                        "envelope_sha256": envelope["envelope_sha256"],
                        "agency_id": envelope["agency_id"],
                        "retain_until": envelope["retain_until"],
                        "authorized_principal": authenticated_principal,
                        "batch_record_sha256": batch_record.get("record_sha256", ""),
                    }
                )
            request["request_sha256"] = _sha256_bytes(_canonical_json_bytes(request))
            status = {
                "schema_version": RUNNER_SCHEMA_VERSION,
                "job_id": job_id,
                "state": "queued",
                "request_sha256": request["request_sha256"],
                "resource_policy_sha256": policy.digest,
                "attempts": [],
                "updated_at": _utc_now(),
            }
            _write_json_atomic(job_dir / "request.json", request)
            _write_json_atomic(job_dir / "status.json", status, )
            file_count, queue_bytes, _, _ = _measure_queue(root, policy)
            job_bytes = _measure_job_bytes(job_dir, policy)
            if file_count > policy.max_owned_files or queue_bytes > policy.max_queue_bytes or job_bytes > policy.max_job_bytes:
                raise _path_error("queue_capacity")
            details = {
                "job_id": job_id,
                "request_sha256": request["request_sha256"],
                "input_kind": request["input_kind"],
                "package_sha256": request.get("package_sha256", ""),
                "authorized_principal": request.get("authorized_principal", ""),
                "agency_id": request.get("agency_id", ""),
                "resource_policy_sha256": policy.digest,
            }
            _append_audit_event_unlocked(root, events, "job_enqueued", details)
            return status
        except BaseException:
            _remove_uncommitted_job(job_dir)
            if reservation is not None and not reservation_preexisting:
                try:
                    reservation.unlink(missing_ok=True)
                except OSError:
                    pass
            raise


def _validate_request(request: dict[str, Any], path: Path) -> None:
    if not isinstance(request, dict):
        raise _path_error("queue_request_schema")
    recorded_hash = request.get("request_sha256")
    unsigned_request = dict(request)
    unsigned_request.pop("request_sha256", None)
    computed_hash = _sha256_bytes(_canonical_json_bytes(unsigned_request))
    if type(recorded_hash) is not str or recorded_hash != computed_hash:
        raise _path_error("queue_request_integrity")
    if request.get("schema_version") != RUNNER_SCHEMA_VERSION:
        raise _path_error("queue_request_schema")
    job_id = request.get("job_id")
    if not isinstance(job_id, str) or not JOB_ID_PATTERN.fullmatch(job_id):
        raise _path_error("queue_request_job_id")
    claim_count = request.get("claim_count")
    if type(claim_count) is not int or claim_count < 1:
        raise _path_error("queue_request_claim_count")
    policy = validate_bound_policy(
        request.get("resource_policy"), request.get("resource_policy_sha256")
    )
    if not isinstance(path, Path):
        raise _path_error("queue_request_file")
    try:
        if read_policy_file(path.parent / "resource_policy.json") != policy:
            raise _path_error("queue_request_policy_binding")
    except ProvingResourcePolicyError:
        raise _path_error("queue_request_policy_binding") from None
    input_kind = request.get("input_kind", "synthetic")
    if input_kind not in {"synthetic", "batch_package", "encrypted_envelope"}:
        raise _path_error("queue_request_input_kind")
    common = {
        "schema_version", "job_id", "claim_count", "created_at", "input_kind",
        "resource_policy", "resource_policy_sha256", "request_sha256",
    }
    if not isinstance(request.get("created_at"), str):
        raise _path_error("queue_request_created_at")
    if input_kind == "batch_package":
        expected = common | {
            "package_sha256", "witness_sha256", "package_id", "batch_id",
            "authorized_principal", "agency_id", "retain_until",
        }
        if set(request) != expected:
            raise _path_error("queue_request_keys")
        package_path = path.parent / "batch_package.json"
        package = _load_batch_package_bounded(package_path)
        for field in ("package_sha256", "witness_sha256", "package_id", "batch_id"):
            if request.get(field) != package.get(field):
                raise _path_error("queue_request_package_binding")
        if request.get("authorized_principal") != package["authorization"]["principal"]:
            raise _path_error("queue_request_package_binding")
        if request.get("agency_id") != package["authorization"].get("agency_id", "local-dev"):
            raise _path_error("queue_request_package_binding")
        if request.get("retain_until") != package.get("retain_until"):
            raise _path_error("queue_request_package_binding")
    elif input_kind == "encrypted_envelope":
        expected = common | {
            "package_sha256", "witness_sha256", "envelope_sha256", "agency_id",
            "retain_until", "authorized_principal", "batch_record_sha256",
        }
        if set(request) != expected:
            raise _path_error("queue_request_keys")
        envelope = _load_envelope_bounded(path.parent / "witness.envelope.json")
        try:
            validate_envelope_authorization(
                envelope,
                authenticated_principal=str(request.get("authorized_principal", "")),
            )
        except RuntimeError:
            raise _path_error("queue_request_envelope_binding") from None
        for field in ("package_sha256", "witness_sha256", "envelope_sha256", "agency_id", "retain_until"):
            if request.get(field) != envelope.get(field):
                raise _path_error("queue_request_envelope_binding")
        record = _read_json(path.parent / "batch_record.json")
        if request.get("batch_record_sha256") != record.get("record_sha256"):
            raise _path_error("queue_request_record_binding")
        from tools.proving_submission import validate_batch_record
        try:
            validate_batch_record(record)
        except RuntimeError:
            raise _path_error("queue_request_record_binding") from None
    else:
        if set(request) != common:
            raise _path_error("queue_request_keys")
class _QueueLock:
    def __init__(self, queue_root: Path) -> None:
        self.path = queue_root / ".prover.lock"
        self.descriptor: int | None = None

    def __enter__(self) -> "_QueueLock":
        for attempt in range(2):
            try:
                self.descriptor = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                break
            except FileExistsError as exc:
                if attempt == 0 and self._remove_stale_lock():
                    continue
                raise _path_error("queue_runner_locked") from None
        assert self.descriptor is not None
        payload = _canonical_json_bytes(
            {"pid": os.getpid(), "hostname": socket.gethostname(), "started_at": _utc_now()}
        ) + b"\n"
        os.write(self.descriptor, payload)
        os.fsync(self.descriptor)
        return self

    def _remove_stale_lock(self) -> bool:
        return _remove_stale_process_lock(self.path)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        self.path.unlink(missing_ok=True)


def _next_queued_job(root: Path) -> Path | None:
    candidates: list[tuple[str, str, Path]] = []
    try:
        job_dirs = list((root / "jobs").iterdir())
    except OSError:
        raise _path_error("queue_measurement") from None
    for job_dir in job_dirs:
        info = _regular_file_stat(job_dir) if job_dir.is_file() else None
        if info is not None:
            raise _path_error("queue_job_directory")
        if job_dir.is_symlink() or not job_dir.is_dir():
            raise _path_error("queue_job_directory")
        status_path = job_dir / "status.json"
        request_path = job_dir / "request.json"
        if not status_path.is_file() or not request_path.is_file():
            raise _path_error("queue_job_shape")
        status = _read_json(status_path, maximum_bytes=MAX_STATUS_BYTES)
        if status.get("state") not in {"queued", "retrying"}:
            continue
        request = _read_json(request_path)
        candidates.append((str(request.get("created_at", "")), job_dir.name, job_dir))
    return min(candidates)[2] if candidates else None


def _recover_interrupted_jobs(root: Path) -> None:
    try:
        status_paths = sorted((root / "jobs").glob("*/status.json"))
    except OSError:
        raise _path_error("queue_measurement") from None
    for status_path in status_paths:
        status = _read_json(status_path, maximum_bytes=MAX_STATUS_BYTES)
        if status.get("state") != "running":
            continue
        request_path = status_path.with_name("request.json")
        request = _read_json(request_path)
        _validate_request(request, request_path)
        try:
            policy = validate_bound_policy(
                request.get("resource_policy"), request.get("resource_policy_sha256")
            )
        except ProvingResourcePolicyError:
            raise _path_error("queue_request_policy_binding") from None
        _require_job_audit_binding(root, request)
        active_attempt = status.get("active_attempt")
        if isinstance(active_attempt, bool) or not isinstance(active_attempt, int) or active_attempt < 1:
            raise _path_error("queue_active_attempt")
        attempts = list(status.get("attempts", []))
        if len(attempts) >= policy.max_attempts:
            raise _path_error("queue_attempt_exhaustion")
        attempts.append(
            {
                "attempt": active_attempt,
                "finished_at": _utc_now(),
                "succeeded": False,
                "retryable": True,
                "failure_class": "interrupted",
                "error_code": "interrupted_attempt",
            }
        )
        next_state = "retrying" if active_attempt < policy.max_attempts else "failed"
        _update_status(
            status_path,
            status,
            state=next_state,
            attempts=attempts,
            active_attempt=None,
            last_failure=attempts[-1],
        )
        _append_audit_event(
            root,
            "job_recovered_after_interruption",
            {"job_id": request["job_id"], "attempt": active_attempt, "state": next_state},
        )


def _validate_success_manifest(
    attempt_dir: Path,
    policy: evidence_policy.ProvingEvidencePolicy | None = None,
) -> dict[str, Any]:
    if policy is None:
        raise _path_error("queue_evidence_policy_required")
    manifest_path = attempt_dir / "run_manifest.json"
    try:
        manifest = _read_json(manifest_path, maximum_bytes=MAX_JSON_BYTES)
    except RuntimeError:
        raise _path_error("queue_manifest_invalid") from None
    if _canonical_json_bytes(manifest) + b"\n" != _bounded_regular_read(manifest_path, MAX_JSON_BYTES):
        raise _path_error("queue_manifest_noncanonical")
    required_true = {
        "semantic_output_match": manifest.get("semantic_output_match"),
        "independent_verifier": manifest.get("independent_verifier"),
        "verification_success_marker": manifest.get("verification_success_marker"),
    }
    if manifest.get("status") != "independently_verified" or not all(
        value is True for value in required_true.values()
    ):
        raise _path_error("queue_manifest_status")
    if manifest.get("evidence_scope") != evidence_policy.POLICY_PURPOSE:
        raise _path_error("queue_manifest_scope")
    if manifest.get("production_verifier_claimed") is not False:
        raise _path_error("queue_manifest_production_claim")
    if manifest.get("settlement_contract_verification_run") is not False:
        raise _path_error("queue_manifest_settlement_claim")
    if manifest.get("verification_interface") != evidence_policy.VERIFIER_INTERFACE:
        raise _path_error("queue_manifest_interface")

    expected_policy = {
        "storage_key": "trusted-evidence-policy",
        "registry_sha3_512": policy.registry_sha3_512,
        "sha3_512": policy.sha3_512,
    }
    if manifest.get("evidence_policy") != expected_policy:
        raise _path_error("queue_manifest_policy")
    expected_provenance = evidence_policy.trusted_manifest_bindings(policy)
    if manifest.get("trusted_provenance") != expected_provenance:
        raise _path_error("queue_manifest_provenance")
    expected_source = expected_provenance["source_manifest_sha3_512"]
    before = manifest.get("protected_source_manifest_sha3_512_before")
    after = manifest.get("protected_source_manifest_sha3_512_after")
    if before != expected_source or after != expected_source:
        raise _path_error("queue_manifest_source")

    proof = manifest.get("proof")
    if not isinstance(proof, dict):
        raise _path_error("queue_manifest_proof")
    if set(proof) != {"bytes", "path", "sha256", "sha3_512"}:
        raise _path_error("queue_manifest_proof")
    proof_path_value = proof.get("path")
    if (
        not isinstance(proof_path_value, str)
        or not proof_path_value
        or Path(proof_path_value).is_absolute()
        or any(part in {"", ".", ".."} for part in PurePosixPath(proof_path_value).parts)
        or PurePosixPath(proof_path_value).as_posix() != proof_path_value
    ):
        raise _path_error("queue_manifest_proof")
    proof_path = (attempt_dir / Path(*PurePosixPath(proof_path_value).parts)).resolve()
    try:
        proof_path.relative_to(attempt_dir.resolve())
    except ValueError:
        raise _path_error("queue_manifest_proof_path") from None
    try:
        proof_path.relative_to(attempt_dir.resolve())
        actual_bytes, actual_hash, actual_sha3_512 = _hash_regular_file(proof_path, MAX_JOB_BYTES)
    except (RuntimeError, OSError, ValueError):
        raise _path_error("queue_manifest_proof_file") from None
    if (
        proof.get("bytes") != actual_bytes
        or proof.get("sha256") != actual_hash
        or proof.get("sha3_512") != actual_sha3_512
    ):
        raise _path_error("queue_manifest_proof_binding")

    return {
        "manifest_storage_key": "run_manifest.json",
        "proof_storage_key": proof_path.relative_to(attempt_dir.resolve()).as_posix(),
        "proof_bytes": actual_bytes,
        "proof_sha256": actual_hash,
        "proof_sha3_512": actual_sha3_512,
        "evidence_policy_sha3_512": policy.sha3_512,
        "independent_verifier": True,
        "semantic_output_match": True,
        "protected_source_unchanged": True,
        "production_verifier_claimed": False,
        "settlement_contract_verification_run": False,
    }


def _update_status(path: Path, status: dict[str, Any], **changes: object) -> None:
    status.update(changes)
    status["updated_at"] = _utc_now()
    _write_bytes_atomic(path, _canonical_json_bytes(status) + b"\n", maximum_bytes=MAX_STATUS_BYTES)


def _cleanup_ephemeral_diagnostics(attempt_dir: Path) -> None:
    try:
        paths = [item for item in attempt_dir.rglob("*") if item.is_file() and item.name.endswith(".log")]
    except OSError:
        raise _path_error("queue_diagnostic_cleanup") from None
    for item in paths:
        try:
            item.unlink(missing_ok=True)
        except OSError:
            raise _path_error("queue_diagnostic_cleanup") from None


def _run_attempt(
    request: dict[str, Any],
    attempt_dir: Path,
    status_path: Path,
    status: dict[str, Any],
    queue_root: Path,
) -> tuple[bool, bool, dict[str, Any]]:
    started = time.monotonic()
    attempt_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        resource_policy = validate_bound_policy(
            request.get("resource_policy"), request.get("resource_policy_sha256")
        )
        if read_policy_file(status_path.parent / "resource_policy.json") != resource_policy:
            raise ProvingResourcePolicyError("proving_policy_binding")
        policy_path = evidence_policy.policy_path_from_environment()
        policy = evidence_policy.load_approved_policy(policy_path)
        attestation_before = evidence_policy.attest_policy(
            policy, source_root=PROTECTED_CAIRO
        )
    except (OSError, RuntimeError, ValueError):
        return False, False, {
            "failure_class": "trusted_evidence_policy",
            "error_code": "trusted_evidence_policy",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    command = [
        sys.executable,
        "-m",
        "tools.run_verified_bootloader_proof",
    ]
    if request.get("input_kind", "synthetic") == "batch_package":
        command.extend(["--batch-package", str(status_path.parent / "batch_package.json")])
    elif request.get("input_kind") == "encrypted_envelope":
        ram_token = secrets.token_hex(16)
        command = [
            sys.executable,
            "-m",
            "tools.isolated_proving_worker",
            "--encrypted-envelope",
            str(status_path.parent / "witness.envelope.json"),
            "--batch-record",
            str(status_path.parent / "batch_record.json"),
            "--authenticated-principal",
            request["authorized_principal"],
            "--queue-root",
            str(queue_root),
            "--job-id",
            request["job_id"],
            "--ram-token",
            ram_token,
        ]
    else:
        command.extend(["--claim-count", str(request["claim_count"])])
    command.extend(
        [
            "--output-dir",
            str(attempt_dir),
            "--resource-policy",
            str(status_path.parent / "resource_policy.json"),
            "--evidence-policy",
            str(policy.path),
        ]
    )
    try:
        result = run_contained_process(
            command,
            cwd=ROOT,
            policy=resource_policy,
            owned_root=status_path.parent,
        )
    except (OSError, RuntimeError, ValueError, ProvingProcessError) as exc:
        _cleanup_ephemeral_diagnostics(attempt_dir)
        code = getattr(exc, "code", "process_launch")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
            code = "process_launch"
        capacity_failure = code.startswith("proving_process_owned_")
        return False, not capacity_failure, {
            "failure_class": "queue_capacity" if capacity_failure else "process_launch",
            "error_code": "queue_capacity" if capacity_failure else "process_launch",
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "cap_enforced": os.name == "nt",
            "tree_confirmed": False,
        }
    elapsed = time.monotonic() - started
    telemetry = {
        "elapsed_seconds": round(elapsed, 3),
        "stdout_bytes": min(result.stdout_bytes, MAX_STDOUT_BYTES),
        "stderr_bytes": min(result.stderr_bytes, MAX_STDERR_BYTES),
        "peak_job_commit_bytes": result.peak_job_commit_bytes,
        "cap_bytes": result.cap_bytes,
        "cap_enforced": result.cap_enforced,
        "active_process_limit": result.active_process_limit,
        "timed_out": result.timed_out,
        "tree_confirmed": result.tree_confirmed,
    }
    if result.output_overflow:
        _cleanup_ephemeral_diagnostics(attempt_dir)
        return False, False, {
            "failure_class": "output_cap",
            "error_code": "output_cap",
            **telemetry,
        }
    if getattr(result, "capacity_breach", False) is True:
        _cleanup_ephemeral_diagnostics(attempt_dir)
        return False, False, {
            "failure_class": "queue_capacity",
            "error_code": "queue_capacity",
            **telemetry,
        }
    if result.timed_out:
        _cleanup_ephemeral_diagnostics(attempt_dir)
        return False, bool(result.tree_confirmed), {
            "failure_class": "timeout" if result.tree_confirmed else "process_tree_termination",
            "error_code": "timeout" if result.tree_confirmed else "process_tree_termination",
            **telemetry,
        }
    if result.exit_code != 0:
        _cleanup_ephemeral_diagnostics(attempt_dir)
        return False, False, {
            "failure_class": "proof_command",
            "error_code": "proof_command",
            "return_code": result.exit_code,
            **telemetry,
        }
    try:
        attestation_after = evidence_policy.attest_policy(
            policy, source_root=PROTECTED_CAIRO
        )
        if attestation_after != attestation_before:
            raise RuntimeError("policy_attestation")
        verified = _validate_success_manifest(attempt_dir, policy)
    except (OSError, RuntimeError, ValueError):
        _cleanup_ephemeral_diagnostics(attempt_dir)
        return False, False, {
            "failure_class": "trusted_evidence_verification",
            "error_code": "trusted_evidence_verification",
            **telemetry,
        }
    if request.get("input_kind") in {"batch_package", "encrypted_envelope"}:
        manifest = _read_json(attempt_dir / "run_manifest.json", maximum_bytes=MAX_JSON_BYTES)
        package_record = manifest.get("batch_package")
        if not isinstance(package_record, dict) or package_record.get("package_sha256") != request.get(
            "package_sha256"
        ):
            _cleanup_ephemeral_diagnostics(attempt_dir)
            return False, False, {
                "failure_class": "batch_package_binding",
                "error_code": "batch_package_binding",
                **telemetry,
            }
        verified["package_sha256"] = request["package_sha256"]
        if request.get("input_kind") == "encrypted_envelope":
            verified["envelope_sha256"] = request["envelope_sha256"]
    verified.update(telemetry)
    _cleanup_ephemeral_diagnostics(attempt_dir)
    return True, False, verified


def run_next_job(queue_root: Path) -> dict[str, Any] | None:
    root = _prepare_queue_root(queue_root)
    queue_policy = derive_policy()
    with _QueueLock(root):
        _verified_audit_events(root)
        _measure_queue(root, queue_policy)
        _recover_interrupted_jobs(root)
        job_dir = _next_queued_job(root)
        if job_dir is None:
            return None
        request_path = job_dir / "request.json"
        status_path = job_dir / "status.json"
        request = _read_json(request_path)
        _validate_request(request, request_path)
        _require_job_audit_binding(root, request)
        resource_policy = validate_bound_policy(
            request["resource_policy"], request["resource_policy_sha256"]
        )
        status = _read_json(status_path, maximum_bytes=MAX_STATUS_BYTES)
        if status.get("request_sha256") != request.get("request_sha256"):
            raise _path_error("queue_status_binding")

        attempts_value = status.get("attempts", [])
        if not isinstance(attempts_value, list) or len(attempts_value) > resource_policy.max_attempts:
            raise _path_error("queue_attempt_history")
        completed_attempts = len(attempts_value)
        for attempt_number in range(completed_attempts + 1, resource_policy.max_attempts + 1):
            attempt_dir = job_dir / "attempts" / f"attempt-{attempt_number:03d}"
            if attempt_dir.exists():
                raise _path_error("queue_attempt_directory")
            _update_status(
                status_path,
                status,
                state="running",
                active_attempt=attempt_number,
                heartbeat_at=_utc_now(),
                elapsed_seconds=0.0,
            )
            _append_audit_event(
                root,
                "proof_attempt_started",
                {"job_id": request["job_id"], "attempt": attempt_number},
            )
            succeeded, retryable, result = _run_attempt(
                request,
                attempt_dir,
                status_path,
                status,
                root,
            )
            try:
                _measure_queue(root, resource_policy)
            except RuntimeError:
                succeeded = False
                retryable = False
                result = {
                    "failure_class": "queue_capacity",
                    "error_code": "queue_capacity",
                    "elapsed_seconds": result.get("elapsed_seconds", 0.0),
                    "stdout_bytes": result.get("stdout_bytes", 0),
                    "stderr_bytes": result.get("stderr_bytes", 0),
                    "cap_enforced": result.get("cap_enforced", os.name == "nt"),
                    "tree_confirmed": result.get("tree_confirmed", True),
                }
            attempt_record = {
                "attempt": attempt_number,
                "finished_at": _utc_now(),
                "succeeded": succeeded,
                "retryable": retryable,
                **result,
            }
            attempts = list(status.get("attempts", []))
            attempts.append(attempt_record)
            _append_audit_event(
                root,
                "proof_attempt_finished",
                {
                    "job_id": request["job_id"],
                    "attempt": attempt_number,
                    "succeeded": succeeded,
                    "failure_class": result.get("failure_class", ""),
                    "proof_sha256": result.get("proof_sha256", ""),
                    "resource_policy_sha256": request["resource_policy_sha256"],
                },
            )
            if succeeded:
                _update_status(
                    status_path,
                    status,
                    state="succeeded",
                    attempts=attempts,
                    active_attempt=None,
                    result=result,
                )
                return status
            if retryable and attempt_number < resource_policy.max_attempts:
                _update_status(
                    status_path,
                    status,
                    state="retrying",
                    attempts=attempts,
                    active_attempt=None,
                    last_failure=result,
                )
                continue
            _update_status(
                status_path,
                status,
                state="failed",
                attempts=attempts,
                active_attempt=None,
                last_failure=result,
            )
            return status
        raise _path_error("queue_attempt_exhaustion")


def _print_status(queue_root: Path, job_id: str | None) -> None:
    root = _prepare_queue_root(queue_root)
    if job_id is not None:
        if not JOB_ID_PATTERN.fullmatch(job_id):
            raise RuntimeError("invalid job_id")
        path = root / "jobs" / job_id / "status.json"
        if not path.is_file():
            raise RuntimeError(f"job does not exist: {job_id}")
        print(json.dumps(_read_json(path), indent=2, sort_keys=True))
        return
    for path in sorted((root / "jobs").glob("*/status.json")):
        status = _read_json(path)
        print(
            f"job_id={status.get('job_id')} state={status.get('state')} "
            f"attempts={len(status.get('attempts', []))} updated_at={status.get('updated_at')}"
        )


def retention_report(queue_root: Path, *, now: datetime | None = None) -> list[dict[str, object]]:
    from datetime import datetime, timezone

    root = _prepare_queue_root(queue_root)
    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    report: list[dict[str, object]] = []
    for request_path in sorted((root / "jobs").glob("*/request.json")):
        request = _read_json(request_path)
        if request.get("input_kind") not in {"batch_package", "encrypted_envelope"}:
            continue
        status = _read_json(request_path.with_name("status.json"))
        retain_until_text = request.get("retain_until")
        retain_until = datetime.fromisoformat(str(retain_until_text)).astimezone(timezone.utc)
        report.append(
            {
                "job_id": request["job_id"],
                "state": status.get("state"),
                "retain_until": retain_until_text,
                "retention_expired": reference >= retain_until,
                "deletion_performed": False,
            }
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Queue and serially run verifier-clean Blind Ledger proof jobs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enqueue = subparsers.add_parser("enqueue", help="Create an immutable queued proof request.")
    enqueue.add_argument("--queue-root", type=Path, required=True)
    enqueue.add_argument("--job-id", required=True)
    enqueue.add_argument("--claim-count", type=int, required=True)

    enqueue_package = subparsers.add_parser(
        "enqueue-package", help="Queue one signed immutable batch witness package."
    )
    enqueue_package.add_argument("--queue-root", type=Path, required=True)
    enqueue_package.add_argument("--job-id", required=True)
    enqueue_package.add_argument("--batch-package", type=Path, required=True)

    run_next = subparsers.add_parser("run-next", help="Run one queued job under an exclusive lock.")
    run_next.add_argument("--queue-root", type=Path, required=True)

    status = subparsers.add_parser("status", help="Read queue or job status.")
    status.add_argument("--queue-root", type=Path, required=True)
    status.add_argument("--job-id")

    retention = subparsers.add_parser(
        "retention-report", help="Report expired package jobs without deleting evidence."
    )
    retention.add_argument("--queue-root", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "enqueue":
        result = enqueue_job(
            args.queue_root,
            job_id=args.job_id,
            claim_count=args.claim_count,
        )
        print(f"job_id={result['job_id']}")
        print("state=queued")
        print(f"request_sha256={result['request_sha256']}")
        return
    if args.command == "enqueue-package":
        result = enqueue_package_job(
            args.queue_root,
            job_id=args.job_id,
            batch_package_path=args.batch_package,
        )
        print(f"job_id={result['job_id']}")
        print("state=queued")
        print(f"request_sha256={result['request_sha256']}")
        return
    if args.command == "run-next":
        result = run_next_job(args.queue_root)
        if result is None:
            print("queue_empty=true")
            return
        print(f"job_id={result['job_id']}")
        print(f"state={result['state']}")
        if result["state"] == "succeeded":
            verified = result["result"]
            print(f"proof_sha256={verified['proof_sha256']}")
            print(f"proof_storage_key={verified['proof_storage_key']}")
            print(
                "settlement_contract_verification_run="
                f"{str(verified['settlement_contract_verification_run']).lower()}"
            )
        else:
            raise SystemExit(1)
        return
    if args.command == "retention-report":
        print(json.dumps(retention_report(args.queue_root), indent=2, sort_keys=True))
        return
    _print_status(args.queue_root, args.job_id)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        print("queue_request_rejected", file=sys.stderr)
        raise SystemExit(1) from None
