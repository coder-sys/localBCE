"""Tamper-evident, redacted witness packages for Blind Ledger proving jobs.

Packages contain the already-built Cairo witness and ordered public outputs, not
raw claims or EDI. Submission authorization uses an environment-supplied HMAC
key so secret key material is never written into the package or queue.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


PACKAGE_SCHEMA_VERSION = 1
PACKAGE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SUBMISSION_KEY_ENV = "BL_PROVING_SUBMISSION_HMAC_KEY"
SUBMISSION_KEY_ID_ENV = "BL_PROVING_SUBMISSION_HMAC_KEY_ID"
P256_KEY_REGISTRY_ENV = "BL_PROVING_P256_KEY_REGISTRY_JSON"
P256_KEY_REGISTRY_PATH_ENV = "BL_PROVING_P256_KEY_REGISTRY_PATH"
P256_KEY_REGISTRY_SHA256_ENV = "BL_PROVING_P256_KEY_REGISTRY_SHA256"
P256_SIGNATURE_MAX_BYTES = 128
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "package_id",
    "batch_id",
    "claim_count",
    "created_at",
    "retain_until",
    "source_reference",
    "witness",
    "witness_sha256",
    "package_sha256",
    "authorization",
}
_WITNESS_FIELDS = {"serialized_arguments_hex_json", "expected_output_values"}
_AUTHORIZATION_FIELDS = {"scheme", "key_id", "principal", "signature"}
_P256_AUTHORIZATION_FIELDS = _AUTHORIZATION_FIELDS | {"agency_id"}


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _parse_timestamp(name: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise RuntimeError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RuntimeError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _submission_key() -> bytes:
    value = os.environ.get(SUBMISSION_KEY_ENV, "").encode("utf-8")
    if len(value) < 32:
        raise RuntimeError(f"{SUBMISSION_KEY_ENV} must contain at least 32 bytes")
    return value


def _authorization_message(
    package_sha256: str, principal: str, key_id: str, agency_id: str | None = None
) -> bytes:
    value = {
        "package_sha256": package_sha256,
        "principal": principal,
        "key_id": key_id,
    }
    if agency_id is not None:
        value["agency_id"] = agency_id
    return _canonical_json_bytes(value)


def _validate_hex_felts(name: str, values: object) -> list[str]:
    if not isinstance(values, list) or not values:
        raise RuntimeError(f"{name} must be a non-empty list")
    result: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]+", value):
            raise RuntimeError(f"{name}[{index}] must be a lowercase hexadecimal felt")
        result.append(value)
    return result


def _ordered_output_values(expected_output: object) -> list[str]:
    if isinstance(expected_output, dict):
        values = list(expected_output.values())
    elif isinstance(expected_output, list):
        values = expected_output
    else:
        raise RuntimeError("expected output must be an object or ordered list")
    if not values:
        raise RuntimeError("expected output must not be empty")
    result: list[str] = []
    for index, value in enumerate(values):
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise RuntimeError(f"expected output value {index} is not a felt")
        try:
            integer = int(value, 0) if isinstance(value, str) else value
        except ValueError as exc:
            raise RuntimeError(f"expected output value {index} is not a felt") from exc
        if integer < 0:
            raise RuntimeError(f"expected output value {index} is negative")
        result.append(hex(integer))
    return result


def _build_batch_package_core(
    *,
    package_id: str,
    batch_id: str,
    claim_count: int,
    serialized_arguments_hex_json: list[str],
    expected_output: object,
    source_reference: str,
    retention_days: int = 2555,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    if not PACKAGE_ID_PATTERN.fullmatch(package_id):
        raise RuntimeError("invalid package_id")
    if not batch_id or len(batch_id) > 256:
        raise RuntimeError("batch_id must be 1-256 characters")
    if isinstance(claim_count, bool) or not isinstance(claim_count, int) or claim_count < 1:
        raise RuntimeError("claim_count must be a positive integer")
    if not source_reference or len(source_reference) > 512:
        raise RuntimeError("source_reference must be 1-512 characters")
    if isinstance(retention_days, bool) or retention_days < 1:
        raise RuntimeError("retention_days must be at least 1")

    arguments = _validate_hex_felts(
        "serialized_arguments_hex_json", serialized_arguments_hex_json
    )
    output_values = _ordered_output_values(expected_output)
    now = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    witness = {
        "serialized_arguments_hex_json": arguments,
        "expected_output_values": output_values,
    }
    package: dict[str, Any] = {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "package_id": package_id,
        "batch_id": batch_id,
        "claim_count": claim_count,
        "created_at": now.isoformat(),
        "retain_until": (now + timedelta(days=retention_days)).isoformat(),
        "source_reference": source_reference,
        "witness": witness,
        "witness_sha256": _sha256(witness),
    }
    package["package_sha256"] = _sha256(package)
    return package


def create_batch_package(
    *,
    package_id: str,
    batch_id: str,
    claim_count: int,
    serialized_arguments_hex_json: list[str],
    expected_output: object,
    principal: str,
    source_reference: str,
    retention_days: int = 2555,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    if not principal or len(principal) > 256:
        raise RuntimeError("principal must be 1-256 characters")
    package = _build_batch_package_core(
        package_id=package_id,
        batch_id=batch_id,
        claim_count=claim_count,
        serialized_arguments_hex_json=serialized_arguments_hex_json,
        expected_output=expected_output,
        source_reference=source_reference,
        retention_days=retention_days,
        created_at=created_at,
    )
    package_sha256 = package["package_sha256"]
    key_id = os.environ.get(SUBMISSION_KEY_ID_ENV, "").strip()
    if not key_id or len(key_id) > 128:
        raise RuntimeError(f"{SUBMISSION_KEY_ID_ENV} must identify the active submission key")
    signature = hmac.new(
        _submission_key(),
        _authorization_message(package_sha256, principal, key_id),
        hashlib.sha256,
    ).hexdigest()
    package["authorization"] = {
        "scheme": "hmac-sha256",
        "key_id": key_id,
        "principal": principal,
        "signature": signature,
    }
    validate_batch_package(package)
    return package


def create_unsigned_batch_package(
    *,
    package_id: str,
    batch_id: str,
    claim_count: int,
    serialized_arguments_hex_json: list[str],
    expected_output: object,
    source_reference: str,
    retention_days: int = 2555,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    return _build_batch_package_core(
        package_id=package_id,
        batch_id=batch_id,
        claim_count=claim_count,
        serialized_arguments_hex_json=serialized_arguments_hex_json,
        expected_output=expected_output,
        source_reference=source_reference,
        retention_days=retention_days,
        created_at=created_at,
    )


def batch_package_signing_message(
    package: dict[str, Any], *, principal: str, key_id: str, agency_id: str
) -> bytes:
    if set(package) != _TOP_LEVEL_FIELDS - {"authorization"}:
        raise RuntimeError("unsigned batch package fields do not match the locked schema")
    if not principal or len(principal) > 256:
        raise RuntimeError("principal must be 1-256 characters")
    if not key_id or len(key_id) > 128:
        raise RuntimeError("key_id must be 1-128 characters")
    if not PACKAGE_ID_PATTERN.fullmatch(agency_id):
        raise RuntimeError("invalid agency_id")
    unsigned = dict(package)
    recorded_hash = unsigned.pop("package_sha256")
    if recorded_hash != _sha256(unsigned):
        raise RuntimeError("batch package integrity check failed")
    return _authorization_message(recorded_hash, principal, key_id, agency_id)


def authorize_batch_package_p256(
    package: dict[str, Any],
    *,
    principal: str,
    key_id: str,
    agency_id: str,
    signature_b64: str,
) -> dict[str, Any]:
    batch_package_signing_message(
        package, principal=principal, key_id=key_id, agency_id=agency_id
    )
    authorized = dict(package)
    authorized["authorization"] = {
        "scheme": "ecdsa-p256-sha256",
        "key_id": key_id,
        "agency_id": agency_id,
        "principal": principal,
        "signature": signature_b64,
    }
    validate_batch_package(authorized)
    return authorized


def _p256_registry_entry(key_id: str) -> dict[str, Any]:
    production = os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}
    registry_path_text = os.environ.get(P256_KEY_REGISTRY_PATH_ENV, "").strip()
    if registry_path_text:
        registry_path = Path(registry_path_text).expanduser().resolve()
        try:
            registry_bytes = registry_path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"unable to read proving key registry: {registry_path}") from exc
        expected_hash = os.environ.get(P256_KEY_REGISTRY_SHA256_ENV, "").strip().lower()
        actual_hash = hashlib.sha256(registry_bytes).hexdigest()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or expected_hash != actual_hash:
            raise RuntimeError("proving key registry hash pin does not match the registry file")
        raw = registry_bytes.decode("utf-8")
    else:
        if production:
            raise RuntimeError("production requires a hash-pinned proving key registry file")
        raw = os.environ.get(P256_KEY_REGISTRY_ENV, "")
    try:
        registry = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{P256_KEY_REGISTRY_ENV} must contain valid JSON") from exc
    if not isinstance(registry, dict):
        raise RuntimeError(f"{P256_KEY_REGISTRY_ENV} must contain a JSON object")
    entry = registry.get(key_id)
    if not isinstance(entry, dict):
        raise RuntimeError("batch package authorization key_id is not registered")
    required = {"public_key_pem_b64", "agency_id", "status", "not_before", "not_after"}
    if set(entry) != required:
        raise RuntimeError("batch package key registry entry does not match the locked schema")
    return entry


def validate_p256_package_authorization(
    *,
    package_sha256: object,
    created_at: object,
    authorization: object,
) -> dict[str, Any]:
    """Verify the externally checkable authorization for one package digest.

    This deliberately does not replace full package validation. It exists so an
    encrypted envelope can authenticate its signer and principal before any KMS
    unwrap, decryption, JSON parsing, or proof work is attempted.
    """

    if not isinstance(package_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", package_sha256
    ):
        raise RuntimeError("invalid P-256 authorized package_sha256")
    package_created_at = _parse_timestamp("created_at", created_at)
    if not isinstance(authorization, dict) or set(authorization) != _P256_AUTHORIZATION_FIELDS:
        raise RuntimeError("batch package authorization fields do not match the locked schema")
    if authorization.get("scheme") != "ecdsa-p256-sha256":
        raise RuntimeError("unsupported batch package authorization scheme")
    key_id = authorization.get("key_id")
    principal = authorization.get("principal")
    agency_id = authorization.get("agency_id")
    signature = authorization.get("signature")
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        raise RuntimeError("invalid batch package authorization key_id")
    if not isinstance(principal, str) or not principal or len(principal) > 256:
        raise RuntimeError("invalid batch package authorization principal")
    if not isinstance(agency_id, str) or not PACKAGE_ID_PATTERN.fullmatch(agency_id):
        raise RuntimeError("invalid batch package authorization agency_id")
    if not isinstance(signature, str):
        raise RuntimeError("invalid batch package authorization signature")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except ValueError as exc:
        raise RuntimeError("invalid batch package authorization signature") from exc
    if (
        not signature_bytes
        or len(signature_bytes) > P256_SIGNATURE_MAX_BYTES
        or base64.b64encode(signature_bytes).decode("ascii") != signature
    ):
        raise RuntimeError("invalid batch package authorization signature")

    entry = _p256_registry_entry(key_id)
    if entry["status"] != "active":
        raise RuntimeError("batch package authorization key is not active")
    if entry["agency_id"] != agency_id:
        raise RuntimeError("batch package authorization agency does not own the key")
    not_before = _parse_timestamp("key not_before", entry["not_before"])
    not_after = _parse_timestamp("key not_after", entry["not_after"])
    if not_before > package_created_at or package_created_at > not_after:
        raise RuntimeError("batch package was created outside the key validity window")
    try:
        public_key_pem = base64.b64decode(entry["public_key_pem_b64"], validate=True)
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("invalid P-256 key registry encoding") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise RuntimeError("registered proving key must be ECDSA P-256")
    try:
        public_key.verify(
            signature_bytes,
            _authorization_message(package_sha256, principal, key_id, agency_id),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise RuntimeError("batch package authorization failed") from exc
    return authorization


def validate_batch_package(package: object) -> dict[str, Any]:
    if not isinstance(package, dict):
        raise RuntimeError("batch package must be a JSON object")
    if set(package) != _TOP_LEVEL_FIELDS:
        raise RuntimeError("batch package fields do not match the locked schema")
    if package.get("schema_version") != PACKAGE_SCHEMA_VERSION:
        raise RuntimeError("unsupported batch package schema")
    package_id = package.get("package_id")
    if not isinstance(package_id, str) or not PACKAGE_ID_PATTERN.fullmatch(package_id):
        raise RuntimeError("invalid package_id")
    batch_id = package.get("batch_id")
    if not isinstance(batch_id, str) or not batch_id or len(batch_id) > 256:
        raise RuntimeError("invalid batch_id")
    claim_count = package.get("claim_count")
    if isinstance(claim_count, bool) or not isinstance(claim_count, int) or claim_count < 1:
        raise RuntimeError("invalid claim_count")
    created_at = _parse_timestamp("created_at", package.get("created_at"))
    retain_until = _parse_timestamp("retain_until", package.get("retain_until"))
    if retain_until <= created_at:
        raise RuntimeError("retain_until must be later than created_at")
    source_reference = package.get("source_reference")
    if not isinstance(source_reference, str) or not source_reference or len(source_reference) > 512:
        raise RuntimeError("invalid source_reference")

    witness = package.get("witness")
    if not isinstance(witness, dict) or set(witness) != _WITNESS_FIELDS:
        raise RuntimeError("witness fields do not match the locked schema")
    _validate_hex_felts(
        "serialized_arguments_hex_json", witness.get("serialized_arguments_hex_json")
    )
    _validate_hex_felts("expected_output_values", witness.get("expected_output_values"))
    if package.get("witness_sha256") != _sha256(witness):
        raise RuntimeError("batch package witness integrity check failed")

    unsigned = dict(package)
    authorization = unsigned.pop("authorization", None)
    recorded_package_hash = unsigned.pop("package_sha256", None)
    computed_package_hash = _sha256(unsigned)
    if recorded_package_hash != computed_package_hash:
        raise RuntimeError("batch package integrity check failed")
    if not isinstance(authorization, dict):
        raise RuntimeError("batch package authorization is missing or malformed")
    scheme = authorization.get("scheme")
    expected_fields = (
        _AUTHORIZATION_FIELDS if scheme == "hmac-sha256" else _P256_AUTHORIZATION_FIELDS
    )
    if set(authorization) != expected_fields:
        raise RuntimeError("batch package authorization fields do not match the locked schema")
    key_id = authorization.get("key_id")
    principal = authorization.get("principal")
    signature = authorization.get("signature")
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        raise RuntimeError("invalid batch package authorization key_id")
    if not isinstance(principal, str) or not principal or len(principal) > 256:
        raise RuntimeError("invalid batch package authorization principal")
    if scheme == "hmac-sha256":
        if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
            raise RuntimeError("HMAC batch package authorization is disabled in production")
        if key_id != os.environ.get(SUBMISSION_KEY_ID_ENV, "").strip():
            raise RuntimeError("batch package authorization key_id is not active")
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
            raise RuntimeError("invalid batch package authorization signature")
        expected_signature = hmac.new(
            _submission_key(),
            _authorization_message(computed_package_hash, principal, key_id),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise RuntimeError("batch package authorization failed")
        return package
    if scheme != "ecdsa-p256-sha256":
        raise RuntimeError("unsupported batch package authorization scheme")

    validate_p256_package_authorization(
        package_sha256=computed_package_hash,
        created_at=package.get("created_at"),
        authorization=authorization,
    )
    return package


def load_batch_package(path: Path) -> dict[str, Any]:
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to read batch package: {path}") from exc
    return validate_batch_package(package)


def write_batch_package(path: Path, package: dict[str, Any]) -> None:
    if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
        raise RuntimeError(
            "production forbids plaintext witness package files; encrypted envelope required"
        )
    validate_batch_package(package)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(package, indent=2, sort_keys=True))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise RuntimeError(f"refusing to overwrite batch package: {path}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a signed, redacted proving package.")
    parser.add_argument("--arguments-file", type=Path, required=True)
    parser.add_argument("--expected-output-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package-id", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--claim-count", type=int, required=True)
    parser.add_argument("--submitted-by", required=True)
    parser.add_argument("--source-reference", required=True)
    parser.add_argument("--retention-days", type=int, default=2555)
    args = parser.parse_args()
    arguments = json.loads(args.arguments_file.read_text(encoding="utf-8"))
    expected_output = json.loads(args.expected_output_file.read_text(encoding="utf-8"))
    package = create_batch_package(
        package_id=args.package_id,
        batch_id=args.batch_id,
        claim_count=args.claim_count,
        serialized_arguments_hex_json=arguments,
        expected_output=expected_output,
        principal=args.submitted_by,
        source_reference=args.source_reference,
        retention_days=args.retention_days,
    )
    write_batch_package(args.output, package)
    print(f"package_id={package['package_id']}")
    print(f"package_sha256={package['package_sha256']}")
    print(f"witness_sha256={package['witness_sha256']}")
    print(f"package_path={args.output.resolve()}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=os.sys.stderr)
        raise SystemExit(1) from exc
