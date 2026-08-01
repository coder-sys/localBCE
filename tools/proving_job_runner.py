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
import re
import secrets
import socket
import subprocess
import sys
import time
from typing import Any

from tools.batch_package import load_batch_package
from tools.encrypted_witness_envelope import load_envelope, validate_envelope_authorization
from tools import proving_evidence_policy as evidence_policy


ROOT = Path(__file__).resolve().parents[1]
PROTECTED_CAIRO = ROOT / "zk-cairo-sharp"
RUNNER_SCHEMA_VERSION = 1
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TERMINAL_STATES = {"succeeded", "failed"}
AUDIT_SCHEMA_VERSION = 1
PACKAGE_RESERVATION_SCHEMA_VERSION = 1
MAX_PACKAGE_RESERVATION_BYTES = 4096


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(_canonical_json_bytes(value) + b"\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected a JSON object: {path}")
    return value


def _default_threads() -> int:
    configured = os.environ.get("BL_PROVER_THREADS")
    if configured is not None:
        try:
            value = int(configured)
        except ValueError as exc:
            raise RuntimeError("BL_PROVER_THREADS must be a positive integer") from exc
        if value < 1:
            raise RuntimeError("BL_PROVER_THREADS must be a positive integer")
        return value
    return min(os.cpu_count() or 1, 8)


def _prepare_queue_root(path: Path) -> Path:
    root = path.resolve()
    try:
        root.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise RuntimeError(f"queue root must be outside the application source tree: {root}")
    root.mkdir(parents=True, exist_ok=True)
    (root / "jobs").mkdir(exist_ok=True)
    (root / "package_claims").mkdir(exist_ok=True)
    return root


def _reserve_package_once(root: Path, package_sha256: str, job_id: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", package_sha256):
        raise RuntimeError("invalid package_sha256")
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise RuntimeError("invalid reservation job_id")
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
            with reservation.open("rb") as stream:
                existing_bytes = stream.read(MAX_PACKAGE_RESERVATION_BYTES + 1)
            if len(existing_bytes) > MAX_PACKAGE_RESERVATION_BYTES:
                return False
            existing = json.loads(existing_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
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
            raise RuntimeError(f"batch package replay rejected: {package_sha256}") from exc
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
                raise RuntimeError(f"audit log is locked: {self.path}") from exc
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
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    previous_hash = ""
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"audit log contains invalid JSON at line {line_number}") from exc
        if not isinstance(event, dict):
            raise RuntimeError(f"audit log event is not an object at line {line_number}")
        recorded_hash = event.get("event_sha256")
        unsigned = dict(event)
        unsigned.pop("event_sha256", None)
        if event.get("sequence") != line_number or event.get("previous_event_sha256") != previous_hash:
            raise RuntimeError(f"audit log chain is broken at line {line_number}")
        computed_hash = _sha256_bytes(_canonical_json_bytes(unsigned))
        if recorded_hash != computed_hash:
            raise RuntimeError(f"audit log integrity check failed at line {line_number}")
        previous_hash = computed_hash
        events.append(event)
    return events


def _append_audit_event(root: Path, event_type: str, details: dict[str, object]) -> None:
    with _AuditLock(root):
        events = _verified_audit_events(root)
        event: dict[str, object] = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "sequence": len(events) + 1,
            "previous_event_sha256": events[-1]["event_sha256"] if events else "",
            "recorded_at": _utc_now(),
            "event_type": event_type,
            "details": details,
        }
        event["event_sha256"] = _sha256_bytes(_canonical_json_bytes(event))
        path = root / "audit.jsonl"
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(_canonical_json_bytes(event).decode("utf-8") + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def _require_job_audit_binding(root: Path, request: dict[str, Any]) -> None:
    expected = {
        "job_id": request["job_id"],
        "request_sha256": request["request_sha256"],
        "input_kind": request.get("input_kind", "synthetic"),
        "package_sha256": request.get("package_sha256", ""),
        "authorized_principal": request.get("authorized_principal", ""),
        "agency_id": request.get("agency_id", ""),
    }
    for event in _verified_audit_events(root):
        if event.get("event_type") == "job_enqueued" and event.get("details") == expected:
            return
    raise RuntimeError(
        f"job request has no matching verified enqueue audit event: {request['job_id']}"
    )


def _validate_positive(name: str, value: int) -> None:
    if value < 1:
        raise RuntimeError(f"{name} must be at least 1")


def enqueue_job(
    queue_root: Path,
    *,
    job_id: str,
    claim_count: int,
    threads: int,
    max_attempts: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
        raise RuntimeError("synthetic claim-count jobs are disabled in production")
    return _enqueue_request(
        queue_root,
        job_id=job_id,
        claim_count=claim_count,
        threads=threads,
        max_attempts=max_attempts,
        timeout_seconds=timeout_seconds,
        batch_package_path=None,
    )


def enqueue_package_job(
    queue_root: Path,
    *,
    job_id: str,
    batch_package_path: Path,
    threads: int,
    max_attempts: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
        raise RuntimeError(
            "production forbids plaintext witness package queues; encrypted envelope required"
        )
    package = load_batch_package(batch_package_path.resolve())
    return _enqueue_request(
        queue_root,
        job_id=job_id,
        claim_count=int(package["claim_count"]),
        threads=threads,
        max_attempts=max_attempts,
        timeout_seconds=timeout_seconds,
        batch_package_path=batch_package_path.resolve(),
        package=package,
    )


def enqueue_encrypted_package_job(
    queue_root: Path,
    *,
    job_id: str,
    encrypted_envelope_path: Path,
    batch_record: dict[str, Any],
    authenticated_principal: str,
    threads: int,
    max_attempts: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    envelope = load_envelope(encrypted_envelope_path.resolve())
    validate_envelope_authorization(
        envelope,
        authenticated_principal=authenticated_principal,
    )
    return _enqueue_request(
        queue_root,
        job_id=job_id,
        claim_count=int(envelope["claim_count"]),
        threads=threads,
        max_attempts=max_attempts,
        timeout_seconds=timeout_seconds,
        batch_package_path=None,
        encrypted_envelope_path=encrypted_envelope_path.resolve(),
        envelope=envelope,
        batch_record=batch_record,
        authenticated_principal=authenticated_principal,
    )


def _enqueue_request(
    queue_root: Path,
    *,
    job_id: str,
    claim_count: int,
    threads: int,
    max_attempts: int,
    timeout_seconds: int,
    batch_package_path: Path | None,
    package: dict[str, Any] | None = None,
    encrypted_envelope_path: Path | None = None,
    envelope: dict[str, Any] | None = None,
    batch_record: dict[str, Any] | None = None,
    authenticated_principal: str = "",
) -> dict[str, Any]:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise RuntimeError(
            "job_id must be 1-64 characters using only letters, digits, dot, underscore, or hyphen"
        )
    _validate_positive("claim_count", claim_count)
    _validate_positive("threads", threads)
    _validate_positive("max_attempts", max_attempts)
    _validate_positive("timeout_seconds", timeout_seconds)

    root = _prepare_queue_root(queue_root)
    job_dir = root / "jobs" / job_id
    if job_dir.exists():
        raise RuntimeError(f"job already exists and cannot be overwritten: {job_id}")
    if package is not None:
        _reserve_package_once(root, str(package["package_sha256"]), job_id)
    try:
        job_dir.mkdir()
    except FileExistsError as exc:
        raise RuntimeError(f"job already exists and cannot be overwritten: {job_id}") from exc

    request: dict[str, Any] = {
        "schema_version": RUNNER_SCHEMA_VERSION,
        "job_id": job_id,
        "claim_count": claim_count,
        "threads": threads,
        "max_attempts": max_attempts,
        "timeout_seconds": timeout_seconds,
        "created_at": _utc_now(),
        "input_kind": (
            "encrypted_envelope"
            if encrypted_envelope_path is not None
            else "batch_package" if batch_package_path is not None else "synthetic"
        ),
    }
    if batch_package_path is not None:
        assert package is not None
        package_snapshot = job_dir / "batch_package.json"
        package_snapshot.write_bytes(batch_package_path.read_bytes())
        load_batch_package(package_snapshot)
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
        envelope_snapshot = job_dir / "witness.envelope.json"
        _write_json_atomic(envelope_snapshot, envelope)
        load_envelope(envelope_snapshot)
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
        "attempts": [],
        "updated_at": _utc_now(),
    }
    _write_json_atomic(job_dir / "request.json", request)
    _write_json_atomic(job_dir / "status.json", status)
    _append_audit_event(
        root,
        "job_enqueued",
        {
            "job_id": job_id,
            "request_sha256": request["request_sha256"],
            "input_kind": request["input_kind"],
            "package_sha256": request.get("package_sha256", ""),
            "authorized_principal": request.get("authorized_principal", ""),
            "agency_id": request.get("agency_id", ""),
        },
    )
    return status


def _validate_request(request: dict[str, Any], path: Path) -> None:
    recorded_hash = request.get("request_sha256")
    unsigned_request = dict(request)
    unsigned_request.pop("request_sha256", None)
    computed_hash = _sha256_bytes(_canonical_json_bytes(unsigned_request))
    if recorded_hash != computed_hash:
        raise RuntimeError(f"job request integrity check failed: {path}")
    if request.get("schema_version") != RUNNER_SCHEMA_VERSION:
        raise RuntimeError(f"unsupported job request schema: {path}")
    job_id = request.get("job_id")
    if not isinstance(job_id, str) or not JOB_ID_PATTERN.fullmatch(job_id):
        raise RuntimeError(f"invalid job_id in request: {path}")
    for name in ("claim_count", "threads", "max_attempts", "timeout_seconds"):
        value = request.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise RuntimeError(f"invalid {name} in request: {path}")
    input_kind = request.get("input_kind", "synthetic")
    if input_kind not in {"synthetic", "batch_package", "encrypted_envelope"}:
        raise RuntimeError(f"invalid input_kind in request: {path}")
    if input_kind == "batch_package":
        package_path = path.parent / "batch_package.json"
        package = load_batch_package(package_path)
        for field in ("package_sha256", "witness_sha256", "package_id", "batch_id"):
            if request.get(field) != package.get(field):
                raise RuntimeError(f"job request is not bound to its batch package: {path}")
        if request.get("authorized_principal") != package["authorization"]["principal"]:
            raise RuntimeError(f"job request principal does not match its batch package: {path}")
        if request.get("agency_id") != package["authorization"].get("agency_id", "local-dev"):
            raise RuntimeError(f"job request agency does not match its batch package: {path}")
    if input_kind == "encrypted_envelope":
        envelope = load_envelope(path.parent / "witness.envelope.json")
        validate_envelope_authorization(
            envelope,
            authenticated_principal=str(request.get("authorized_principal", "")),
        )
        for field in ("package_sha256", "witness_sha256", "envelope_sha256", "agency_id"):
            if request.get(field) != envelope.get(field):
                raise RuntimeError(f"job request is not bound to its encrypted envelope: {path}")
        record = _read_json(path.parent / "batch_record.json")
        if request.get("batch_record_sha256") != record.get("record_sha256"):
            raise RuntimeError(f"job request is not bound to its batch record: {path}")


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
                raise RuntimeError(
                    f"another proof runner holds the queue lock; inspect before removing it: {self.path}"
                ) from exc
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
    for job_dir in (root / "jobs").iterdir():
        if not job_dir.is_dir():
            continue
        status_path = job_dir / "status.json"
        request_path = job_dir / "request.json"
        if not status_path.is_file() or not request_path.is_file():
            continue
        status = _read_json(status_path)
        if status.get("state") not in {"queued", "retrying"}:
            continue
        request = _read_json(request_path)
        candidates.append((str(request.get("created_at", "")), job_dir.name, job_dir))
    return min(candidates)[2] if candidates else None


def _recover_interrupted_jobs(root: Path) -> None:
    for status_path in sorted((root / "jobs").glob("*/status.json")):
        status = _read_json(status_path)
        if status.get("state") != "running":
            continue
        request_path = status_path.with_name("request.json")
        request = _read_json(request_path)
        _validate_request(request, request_path)
        _require_job_audit_binding(root, request)
        active_attempt = status.get("active_attempt")
        if isinstance(active_attempt, bool) or not isinstance(active_attempt, int) or active_attempt < 1:
            raise RuntimeError(f"running job has an invalid active attempt: {status_path.parent.name}")
        attempts = list(status.get("attempts", []))
        attempts.append(
            {
                "attempt": active_attempt,
                "finished_at": _utc_now(),
                "succeeded": False,
                "retryable": True,
                "failure_class": "interrupted",
                "error": "proof runner stopped before the attempt reached a terminal result",
            }
        )
        next_state = "retrying" if active_attempt < request["max_attempts"] else "failed"
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
        raise RuntimeError("an independently provisioned trusted evidence policy is required")
    manifest_path = attempt_dir / "run_manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("proof command exited successfully without run_manifest.json")
    manifest = evidence_policy.read_canonical_json_object(
        manifest_path, maximum_bytes=16 * 1024 * 1024
    )
    required_true = {
        "semantic_output_match": manifest.get("semantic_output_match"),
        "independent_verifier": manifest.get("independent_verifier"),
        "verification_success_marker": manifest.get("verification_success_marker"),
    }
    if manifest.get("status") != "independently_verified" or not all(
        value is True for value in required_true.values()
    ):
        raise RuntimeError(f"proof manifest does not establish verified success: {manifest_path}")
    if manifest.get("evidence_scope") != evidence_policy.POLICY_PURPOSE:
        raise RuntimeError(f"proof manifest evidence scope is invalid: {manifest_path}")
    if manifest.get("production_verifier_claimed") is not False:
        raise RuntimeError(f"proof manifest makes an unauthorized production claim: {manifest_path}")
    if manifest.get("settlement_contract_verification_run") is not False:
        raise RuntimeError(f"proof manifest makes an unauthorized settlement claim: {manifest_path}")
    if manifest.get("verification_interface") != evidence_policy.VERIFIER_INTERFACE:
        raise RuntimeError(f"proof manifest verifier interface is invalid: {manifest_path}")

    expected_policy = {
        "path": str(policy.path),
        "registry_sha3_512": policy.registry_sha3_512,
        "sha3_512": policy.sha3_512,
    }
    if manifest.get("evidence_policy") != expected_policy:
        raise RuntimeError(f"proof manifest policy is missing, altered, or unapproved: {manifest_path}")
    expected_provenance = evidence_policy.trusted_manifest_bindings(policy)
    if manifest.get("trusted_provenance") != expected_provenance:
        raise RuntimeError(f"proof manifest provenance is missing, altered, or unapproved: {manifest_path}")
    expected_source = expected_provenance["source_manifest_sha3_512"]
    before = manifest.get("protected_source_manifest_sha3_512_before")
    after = manifest.get("protected_source_manifest_sha3_512_after")
    if before != expected_source or after != expected_source:
        raise RuntimeError(f"protected source manifest is missing, altered, or unapproved: {manifest_path}")

    proof = manifest.get("proof")
    if not isinstance(proof, dict):
        raise RuntimeError(f"proof metadata is missing: {manifest_path}")
    if set(proof) != {"bytes", "path", "sha256", "sha3_512"}:
        raise RuntimeError(f"proof metadata is ambiguous or incomplete: {manifest_path}")
    proof_path_value = proof.get("path")
    if not isinstance(proof_path_value, str):
        raise RuntimeError(f"proof path is missing: {manifest_path}")
    proof_path = Path(proof_path_value).resolve()
    try:
        proof_path.relative_to(attempt_dir.resolve())
    except ValueError as exc:
        raise RuntimeError(f"proof path escapes its attempt directory: {proof_path}") from exc
    if not proof_path.is_file():
        raise RuntimeError(f"verified proof file is missing: {proof_path}")
    actual_bytes = proof_path.stat().st_size
    actual_hash = _sha256_file(proof_path)
    actual_sha3_512 = evidence_policy.sha3_512_file(proof_path)
    if (
        proof.get("bytes") != actual_bytes
        or proof.get("sha256") != actual_hash
        or proof.get("sha3_512") != actual_sha3_512
    ):
        raise RuntimeError(f"verified proof metadata does not match the proof file: {proof_path}")

    return {
        "manifest": str(manifest_path),
        "proof_path": str(proof_path),
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
    _write_json_atomic(path, status)


def _run_attempt(
    request: dict[str, Any],
    attempt_dir: Path,
    status_path: Path,
    status: dict[str, Any],
    queue_root: Path,
) -> tuple[bool, bool, dict[str, Any]]:
    try:
        policy_path = evidence_policy.policy_path_from_environment()
        policy = evidence_policy.load_approved_policy(policy_path)
        attestation_before = evidence_policy.attest_policy(
            policy, source_root=PROTECTED_CAIRO
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return False, False, {
            "failure_class": "trusted_evidence_policy",
            "error": str(exc),
        }

    command = [
        sys.executable,
        "-m",
        "tools.run_verified_bootloader_proof",
    ]
    ram_cleanup_path: str | None = None
    if request.get("input_kind", "synthetic") == "batch_package":
        command.extend(["--batch-package", str(status_path.parent / "batch_package.json")])
    elif request.get("input_kind") == "encrypted_envelope":
        ram_token = secrets.token_hex(16)
        ram_cleanup_path = f"/dev/shm/blind-ledger-witness-{ram_token}.json"
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
            "--threads",
            str(request["threads"]),
            "--evidence-policy",
            str(policy.path),
        ]
    )
    attempt_dir.parent.mkdir(parents=True, exist_ok=True)
    stdout_path = attempt_dir.parent / f"{attempt_dir.name}.runner.stdout.log"
    stderr_path = attempt_dir.parent / f"{attempt_dir.name}.runner.stderr.log"
    started = time.monotonic()
    try:
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                stdout=stdout,
                stderr=stderr,
                text=True,
                shell=False,
            )
            last_heartbeat = 0.0
            timed_out = False
            while process.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed >= request["timeout_seconds"]:
                    timed_out = True
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                    break
                if elapsed - last_heartbeat >= 5.0:
                    last_heartbeat = elapsed
                    _update_status(
                        status_path,
                        status,
                        heartbeat_at=_utc_now(),
                        elapsed_seconds=round(elapsed, 3),
                    )
                time.sleep(1.0)
            returncode = process.returncode
    except OSError as exc:
        if ram_cleanup_path is not None:
            subprocess.run(
                ["wsl", "rm", "-f", "--", ram_cleanup_path],
                capture_output=True,
                check=False,
                timeout=30,
            )
        return False, True, {
            "failure_class": "process_launch",
            "error": str(exc),
            "command": command,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
        }

    if ram_cleanup_path is not None:
        subprocess.run(
            ["wsl", "rm", "-f", "--", ram_cleanup_path],
            capture_output=True,
            check=False,
            timeout=30,
        )
    elapsed = time.monotonic() - started
    if timed_out:
        return False, True, {
            "failure_class": "timeout",
            "error": f"proof command exceeded {request['timeout_seconds']} seconds",
            "command": command,
            "elapsed_seconds": elapsed,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
        }
    if returncode != 0:
        return False, False, {
            "failure_class": "proof_command",
            "error": f"proof command exited with code {returncode}",
            "command": command,
            "returncode": returncode,
            "elapsed_seconds": elapsed,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
        }
    try:
        attestation_after = evidence_policy.attest_policy(
            policy, source_root=PROTECTED_CAIRO
        )
        if attestation_after != attestation_before:
            raise RuntimeError("trusted proof source or tool attestation changed during the job")
        verified = _validate_success_manifest(attempt_dir, policy)
    except (OSError, RuntimeError, ValueError) as exc:
        return False, False, {
            "failure_class": "trusted_evidence_verification",
            "error": str(exc),
            "command": command,
            "elapsed_seconds": elapsed,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
        }
    if request.get("input_kind") in {"batch_package", "encrypted_envelope"}:
        manifest = _read_json(attempt_dir / "run_manifest.json")
        package_record = manifest.get("batch_package")
        if not isinstance(package_record, dict) or package_record.get("package_sha256") != request.get(
            "package_sha256"
        ):
            return False, False, {
                "failure_class": "batch_package_binding",
                "error": "verified proof manifest is not bound to the queued batch package",
                "command": command,
                "elapsed_seconds": elapsed,
                "stdout_log": str(stdout_path),
                "stderr_log": str(stderr_path),
            }
        verified["package_sha256"] = request["package_sha256"]
        if request.get("input_kind") == "encrypted_envelope":
            verified["envelope_sha256"] = request["envelope_sha256"]
    verified.update(
        {
            "command": command,
            "elapsed_seconds": elapsed,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
        }
    )
    return True, False, verified


def run_next_job(queue_root: Path) -> dict[str, Any] | None:
    root = _prepare_queue_root(queue_root)
    with _QueueLock(root):
        _verified_audit_events(root)
        _recover_interrupted_jobs(root)
        job_dir = _next_queued_job(root)
        if job_dir is None:
            return None
        request_path = job_dir / "request.json"
        status_path = job_dir / "status.json"
        request = _read_json(request_path)
        _validate_request(request, request_path)
        _require_job_audit_binding(root, request)
        status = _read_json(status_path)
        if status.get("request_sha256") != request.get("request_sha256"):
            raise RuntimeError(f"job status is bound to a different request: {job_dir.name}")

        completed_attempts = len(status.get("attempts", []))
        for attempt_number in range(completed_attempts + 1, request["max_attempts"] + 1):
            attempt_dir = job_dir / "attempts" / f"attempt-{attempt_number:03d}"
            if attempt_dir.exists():
                raise RuntimeError(f"refusing to overwrite existing attempt directory: {attempt_dir}")
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
            if retryable and attempt_number < request["max_attempts"]:
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
        raise RuntimeError(f"job has no remaining attempts but is not terminal: {job_dir.name}")


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
    enqueue.add_argument("--threads", type=int, default=_default_threads())
    enqueue.add_argument("--max-attempts", type=int, default=2)
    enqueue.add_argument("--timeout-seconds", type=int, default=1800)

    enqueue_package = subparsers.add_parser(
        "enqueue-package", help="Queue one signed immutable batch witness package."
    )
    enqueue_package.add_argument("--queue-root", type=Path, required=True)
    enqueue_package.add_argument("--job-id", required=True)
    enqueue_package.add_argument("--batch-package", type=Path, required=True)
    enqueue_package.add_argument("--threads", type=int, default=_default_threads())
    enqueue_package.add_argument("--max-attempts", type=int, default=2)
    enqueue_package.add_argument("--timeout-seconds", type=int, default=1800)

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
            threads=args.threads,
            max_attempts=args.max_attempts,
            timeout_seconds=args.timeout_seconds,
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
            threads=args.threads,
            max_attempts=args.max_attempts,
            timeout_seconds=args.timeout_seconds,
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
            print(f"proof_path={verified['proof_path']}")
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
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
