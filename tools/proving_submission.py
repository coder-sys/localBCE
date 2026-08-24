"""Production boundary between an adjudicated batch and the proving queue."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from tools.batch_package import validate_batch_package
from tools.encrypted_witness_envelope import validate_envelope, validate_envelope_authorization
from tools.proving_job_runner import enqueue_encrypted_package_job, enqueue_package_job


BATCH_RECORD_SCHEMA_VERSION = 1
AGENCY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BATCH_RECORD_FIELDS = {
    "schema_version",
    "batch_id",
    "agency_id",
    "claim_count",
    "expected_output_values",
    "created_at",
    "source_system",
    "record_sha256",
}
_MAX_SUBMISSION_JSON_BYTES = 8 * 1024 * 1024
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


def _bounded_json(path: Path, maximum_bytes: int = _MAX_SUBMISSION_JSON_BYTES) -> dict[str, Any]:
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise RuntimeError("submission_file_not_regular")
        if before.st_size > maximum_bytes:
            raise RuntimeError("submission_file_cap")
        descriptor = os.open(path, os.O_RDONLY | (os.O_BINARY if hasattr(os, "O_BINARY") else 0))
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum_bytes:
            raise RuntimeError("submission_file_identity")
        raw_buffer = bytearray()
        while len(raw_buffer) <= maximum_bytes:
            chunk = os.read(descriptor, maximum_bytes + 1 - len(raw_buffer))
            if not chunk:
                break
            raw_buffer.extend(chunk)
            if len(raw_buffer) > maximum_bytes:
                raise RuntimeError("submission_file_cap")
        after_open = os.fstat(descriptor)
    except RuntimeError:
        raise
    except (OSError, ValueError):
        raise RuntimeError("submission_file_invalid") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise RuntimeError("submission_file_invalid") from None
    try:
        after = os.lstat(path)
    except OSError:
        raise RuntimeError("submission_file_identity") from None
    expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or len(raw_buffer) != before.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != expected
        or (after_open.st_dev, after_open.st_ino, after_open.st_size, after_open.st_mtime_ns)
        != expected
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != expected
    ):
        raise RuntimeError("submission_file_identity")
    try:
        value = json.loads(bytes(raw_buffer).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("submission_file_invalid") from None
    if not isinstance(value, dict):
        raise RuntimeError("submission_file_object")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _hex_outputs(values: object) -> list[str]:
    if not isinstance(values, list) or not values:
        raise RuntimeError("expected_output_values must be a non-empty list")
    outputs: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]+", value):
            raise RuntimeError(f"expected_output_values[{index}] must be a lowercase hex felt")
        outputs.append(value)
    return outputs


def create_batch_record(
    *,
    batch_id: str,
    agency_id: str,
    claim_count: int,
    expected_output_values: list[str],
    source_system: str,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    if not batch_id or len(batch_id) > 256:
        raise RuntimeError("batch_id must be 1-256 characters")
    if not AGENCY_ID_PATTERN.fullmatch(agency_id):
        raise RuntimeError("invalid agency_id")
    if isinstance(claim_count, bool) or not isinstance(claim_count, int) or claim_count < 1:
        raise RuntimeError("claim_count must be a positive integer")
    if not source_system or len(source_system) > 256:
        raise RuntimeError("source_system must be 1-256 characters")
    record: dict[str, Any] = {
        "schema_version": BATCH_RECORD_SCHEMA_VERSION,
        "batch_id": batch_id,
        "agency_id": agency_id,
        "claim_count": claim_count,
        "expected_output_values": _hex_outputs(expected_output_values),
        "created_at": (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(),
        "source_system": source_system,
    }
    record["record_sha256"] = _sha256(record)
    validate_batch_record(record)
    return record


def validate_batch_record(record: object) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != _BATCH_RECORD_FIELDS:
        raise RuntimeError("batch record fields do not match the locked schema")
    if record.get("schema_version") != BATCH_RECORD_SCHEMA_VERSION:
        raise RuntimeError("unsupported batch record schema")
    if not isinstance(record.get("batch_id"), str) or not record["batch_id"]:
        raise RuntimeError("invalid batch record batch_id")
    if not isinstance(record.get("agency_id"), str) or not AGENCY_ID_PATTERN.fullmatch(
        record["agency_id"]
    ):
        raise RuntimeError("invalid batch record agency_id")
    claim_count = record.get("claim_count")
    if isinstance(claim_count, bool) or not isinstance(claim_count, int) or claim_count < 1:
        raise RuntimeError("invalid batch record claim_count")
    _hex_outputs(record.get("expected_output_values"))
    try:
        created_at = datetime.fromisoformat(str(record.get("created_at")))
    except ValueError:
        raise RuntimeError("invalid batch record created_at") from None
    if created_at.tzinfo is None:
        raise RuntimeError("batch record created_at must include a timezone")
    if not isinstance(record.get("source_system"), str) or not record["source_system"]:
        raise RuntimeError("invalid batch record source_system")
    unsigned = dict(record)
    recorded_hash = unsigned.pop("record_sha256", None)
    if recorded_hash != _sha256(unsigned):
        raise RuntimeError("batch record integrity check failed")
    return record


def batch_record_source_reference(record: Mapping[str, Any]) -> str:
    validated = validate_batch_record(dict(record))
    return f"batch-record-sha256:{validated['record_sha256']}"


def validate_package_submission(
    batch_record: Mapping[str, Any],
    package: Mapping[str, Any],
    *,
    authenticated_principal: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    record = validate_batch_record(dict(batch_record))
    package = dict(package)
    reference_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    record_created_at = datetime.fromisoformat(record["created_at"]).astimezone(timezone.utc)
    package_created_at = datetime.fromisoformat(package["created_at"]).astimezone(timezone.utc)
    retain_until = datetime.fromisoformat(package["retain_until"]).astimezone(timezone.utc)
    if package_created_at < record_created_at:
        raise RuntimeError("package predates its batch record")
    if package_created_at > record_created_at + timedelta(hours=24):
        raise RuntimeError("package was created too long after its batch record")
    if package_created_at > reference_time + timedelta(minutes=5):
        raise RuntimeError("package creation time is in the future")
    if retain_until <= reference_time:
        raise RuntimeError("batch package retention window has expired")
    authorization = package["authorization"]
    if authorization.get("scheme") != "ecdsa-p256-sha256":
        raise RuntimeError("production proving submission requires external P-256 authorization")
    if authorization.get("principal") != authenticated_principal:
        raise RuntimeError("authenticated principal does not match the package authorization")
    if authorization.get("agency_id") != record["agency_id"]:
        raise RuntimeError("package authorization agency does not match the batch record")
    if package["batch_id"] != record["batch_id"]:
        raise RuntimeError("package batch_id does not match the batch record")
    if package["claim_count"] != record["claim_count"]:
        raise RuntimeError("package claim_count does not match the batch record")
    if package["witness"]["expected_output_values"] != record["expected_output_values"]:
        raise RuntimeError("package public outputs do not match the batch record")
    if int(package["witness"]["expected_output_values"][-1], 0) != record["claim_count"]:
        raise RuntimeError("in-circuit claim count does not match the signed batch record")
    if package["source_reference"] != batch_record_source_reference(record):
        raise RuntimeError("package source reference does not match the batch record")
    return record


def submit_batch_package(
    queue_root: Path,
    *,
    job_id: str,
    batch_record: Mapping[str, Any],
    batch_package_path: Path,
    authenticated_principal: str,
) -> dict[str, Any]:
    def operation() -> dict[str, Any]:
        if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
            raise RuntimeError("queue_plaintext_production")
        record = validate_batch_record(dict(batch_record))
        package = validate_batch_package(_bounded_json(batch_package_path.resolve()))
        validate_package_submission(
            record,
            package,
            authenticated_principal=authenticated_principal,
        )
        agency_root = queue_root.resolve() / "agencies" / record["agency_id"]
        status = enqueue_package_job(
            agency_root,
            job_id=job_id,
            batch_package_path=batch_package_path,
        )
        return {**status, "agency_queue_storage_key": f"agencies/{record['agency_id']}"}

    return _public_call(operation, "queue_submission_rejected")


def submit_encrypted_batch_package(
    queue_root: Path,
    *,
    job_id: str,
    batch_record: Mapping[str, Any],
    encrypted_envelope_path: Path,
    authenticated_principal: str,
) -> dict[str, Any]:
    def operation() -> dict[str, Any]:
        record = validate_batch_record(dict(batch_record))
        envelope = validate_envelope(
            _bounded_json(encrypted_envelope_path.resolve(), 2 * 1024 * 1024)
        )
        validate_envelope_authorization(
            envelope,
            authenticated_principal=authenticated_principal,
        )
        if envelope["agency_id"] != record["agency_id"]:
            raise RuntimeError("queue_envelope_binding")
        if envelope["claim_count"] != record["claim_count"]:
            raise RuntimeError("queue_envelope_binding")
        agency_root = queue_root.resolve() / "agencies" / record["agency_id"]
        status = enqueue_encrypted_package_job(
            agency_root,
            job_id=job_id,
            encrypted_envelope_path=encrypted_envelope_path,
            batch_record=record,
            authenticated_principal=authenticated_principal,
        )
        return {**status, "agency_queue_storage_key": f"agencies/{record['agency_id']}"}

    return _public_call(operation, "queue_submission_rejected")
