"""Encrypted-at-rest envelope for signed Blind Ledger proving packages.

The application uses only the wrapping public key. The corresponding private
key remains in an external KMS/HSM and is represented here by an unwrap
callback supplied by the trusted proving worker.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tools.batch_package import (
    _parse_timestamp,
    validate_batch_package,
    validate_p256_package_authorization,
)


ENVELOPE_SCHEMA_VERSION = 2
ENVELOPE_ALGORITHM = "AES-256-GCM"
KEY_WRAP_ALGORITHM = "RSA-OAEP-SHA256-CONTEXT-V2"
DEK_BYTES = 32
NONCE_BYTES = 12
MINIMUM_RSA_BITS = 3072
MAXIMUM_RSA_BITS = 8192
OAEP_LABEL_DOMAIN = b"BL/WITNESS-ENVELOPE/OAEP/V2\x00"

# These are finite safety ceilings for the current synthetic prototype. They
# are not A01 production capacities and must not be represented as such.
PROTOTYPE_MAX_PLAINTEXT_BYTES = 1024 * 1024
PROTOTYPE_MAX_CIPHERTEXT_BYTES = PROTOTYPE_MAX_PLAINTEXT_BYTES + 16
PROTOTYPE_MAX_ENVELOPE_FILE_BYTES = 2 * 1024 * 1024
PROTOTYPE_MAX_WRAPPED_KEY_BYTES = MAXIMUM_RSA_BITS // 8
PROTOTYPE_MAX_AUTHORIZATION_SIGNATURE_BYTES = 128
_FIELDS = {
    "schema_version",
    "algorithm",
    "key_wrap_algorithm",
    "wrapping_key_id",
    "agency_id",
    "package_sha256",
    "witness_sha256",
    "claim_count",
    "created_at",
    "retain_until",
    "authorization_scheme",
    "authorization_key_id",
    "authorized_principal",
    "authorization_signature_b64",
    "nonce_b64",
    "wrapped_key_b64",
    "ciphertext_b64",
    "envelope_sha256",
}
_HEADER_FIELDS = (
    "schema_version",
    "algorithm",
    "key_wrap_algorithm",
    "wrapping_key_id",
    "agency_id",
    "package_sha256",
    "witness_sha256",
    "claim_count",
    "created_at",
    "retain_until",
    "authorization_scheme",
    "authorization_key_id",
    "authorized_principal",
    "authorization_signature_b64",
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _header(envelope: dict[str, Any]) -> dict[str, Any]:
    return {name: envelope[name] for name in _HEADER_FIELDS}


def envelope_header_context_sha256(envelope: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes(_header(envelope))).hexdigest()


def oaep_label_for_context(context_sha256: str) -> bytes:
    if not isinstance(context_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", context_sha256
    ):
        raise RuntimeError("invalid witness envelope OAEP context")
    return OAEP_LABEL_DOMAIN + bytes.fromhex(context_sha256)


def _maximum_base64_characters(maximum_bytes: int) -> int:
    return 4 * ((maximum_bytes + 2) // 3)


def _decode_canonical_base64(
    name: str,
    value: object,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    size_label: str,
) -> bytes:
    if not isinstance(value, str):
        raise RuntimeError(f"invalid encrypted witness {name}")
    if len(value) > _maximum_base64_characters(maximum_bytes):
        raise RuntimeError(f"encrypted witness {size_label} exceeds prototype byte limit")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise RuntimeError(f"invalid encrypted witness {name}") from exc
    if not minimum_bytes <= len(decoded) <= maximum_bytes:
        if len(decoded) > maximum_bytes:
            raise RuntimeError(f"encrypted witness {size_label} exceeds prototype byte limit")
        raise RuntimeError(f"invalid encrypted witness {size_label} length")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise RuntimeError(f"noncanonical encrypted witness {name}")
    return decoded


def _load_rsa_public_key(public_key_pem: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except ValueError as exc:
        raise RuntimeError("invalid witness wrapping public key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < MINIMUM_RSA_BITS:
        raise RuntimeError(f"witness wrapping key must be RSA-{MINIMUM_RSA_BITS} or stronger")
    if key.key_size > MAXIMUM_RSA_BITS:
        raise RuntimeError(
            f"witness wrapping key exceeds the prototype RSA-{MAXIMUM_RSA_BITS} ceiling"
        )
    return key


def encrypt_batch_package(
    package: dict[str, Any],
    *,
    wrapping_public_key_pem: bytes,
    wrapping_key_id: str,
    agency_id: str,
) -> dict[str, Any]:
    package = validate_batch_package(package)
    if not wrapping_key_id or len(wrapping_key_id) > 128:
        raise RuntimeError("wrapping_key_id must be 1-128 characters")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", agency_id):
        raise RuntimeError("invalid envelope agency_id")
    if package["authorization"].get("agency_id") != agency_id:
        raise RuntimeError("envelope agency does not match package authorization")
    authorization = package["authorization"]
    if authorization.get("scheme") != "ecdsa-p256-sha256":
        raise RuntimeError("encrypted witness envelope requires external P-256 authorization")
    public_key = _load_rsa_public_key(wrapping_public_key_pem)
    envelope: dict[str, Any] = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "algorithm": ENVELOPE_ALGORITHM,
        "key_wrap_algorithm": KEY_WRAP_ALGORITHM,
        "wrapping_key_id": wrapping_key_id,
        "agency_id": agency_id,
        "package_sha256": package["package_sha256"],
        "witness_sha256": package["witness_sha256"],
        "claim_count": package["claim_count"],
        "created_at": package["created_at"],
        "retain_until": package["retain_until"],
        "authorization_scheme": authorization["scheme"],
        "authorization_key_id": authorization["key_id"],
        "authorized_principal": authorization["principal"],
        "authorization_signature_b64": authorization["signature"],
    }
    plaintext = _canonical_json_bytes(package)
    if len(plaintext) > PROTOTYPE_MAX_PLAINTEXT_BYTES:
        raise RuntimeError("encrypted witness plaintext exceeds prototype byte limit")
    aad = _canonical_json_bytes(_header(envelope))
    context_sha256 = envelope_header_context_sha256(envelope)
    dek = bytearray(os.urandom(DEK_BYTES))
    nonce = os.urandom(NONCE_BYTES)
    try:
        ciphertext = AESGCM(bytes(dek)).encrypt(nonce, plaintext, aad)
        wrapped_key = public_key.encrypt(
            bytes(dek),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=oaep_label_for_context(context_sha256),
            ),
        )
    finally:
        for index in range(len(dek)):
            dek[index] = 0
    envelope.update(
        {
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "wrapped_key_b64": base64.b64encode(wrapped_key).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        }
    )
    envelope["envelope_sha256"] = _sha256(envelope)
    validate_envelope(envelope)
    return envelope


def validate_envelope(envelope: object) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != _FIELDS:
        raise RuntimeError("encrypted witness envelope fields do not match the locked schema")
    if (
        type(envelope.get("schema_version")) is not int
        or envelope["schema_version"] != ENVELOPE_SCHEMA_VERSION
    ):
        raise RuntimeError("unsupported encrypted witness envelope schema")
    if envelope.get("algorithm") != ENVELOPE_ALGORITHM:
        raise RuntimeError("unsupported encrypted witness algorithm")
    if envelope.get("key_wrap_algorithm") != KEY_WRAP_ALGORITHM:
        raise RuntimeError("unsupported witness key-wrap algorithm")
    for name in ("package_sha256", "witness_sha256"):
        if not isinstance(envelope.get(name), str) or not re.fullmatch(
            r"[0-9a-f]{64}", envelope[name]
        ):
            raise RuntimeError(f"invalid encrypted witness {name}")
    if not isinstance(envelope.get("claim_count"), int) or isinstance(
        envelope.get("claim_count"), bool
    ) or envelope["claim_count"] < 1:
        raise RuntimeError("invalid encrypted witness claim_count")
    wrapping_key_id = envelope.get("wrapping_key_id")
    if not isinstance(wrapping_key_id, str) or not 1 <= len(wrapping_key_id) <= 128:
        raise RuntimeError("invalid encrypted witness wrapping_key_id")
    agency_id = envelope.get("agency_id")
    if not isinstance(agency_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", agency_id
    ):
        raise RuntimeError("invalid encrypted witness agency_id")
    created_at = _parse_timestamp("created_at", envelope.get("created_at"))
    retain_until = _parse_timestamp("retain_until", envelope.get("retain_until"))
    if retain_until <= created_at:
        raise RuntimeError("encrypted witness retain_until must be later than created_at")
    if envelope.get("authorization_scheme") != "ecdsa-p256-sha256":
        raise RuntimeError("unsupported encrypted witness authorization scheme")
    authorization_key_id = envelope.get("authorization_key_id")
    if (
        not isinstance(authorization_key_id, str)
        or not 1 <= len(authorization_key_id) <= 128
    ):
        raise RuntimeError("invalid encrypted witness authorization_key_id")
    authorized_principal = envelope.get("authorized_principal")
    if (
        not isinstance(authorized_principal, str)
        or not 1 <= len(authorized_principal) <= 256
    ):
        raise RuntimeError("invalid encrypted witness authorized_principal")

    _decode_canonical_base64(
        "authorization_signature_b64",
        envelope.get("authorization_signature_b64"),
        minimum_bytes=1,
        maximum_bytes=PROTOTYPE_MAX_AUTHORIZATION_SIGNATURE_BYTES,
        size_label="authorization signature",
    )
    _decode_canonical_base64(
        "nonce_b64",
        envelope.get("nonce_b64"),
        minimum_bytes=NONCE_BYTES,
        maximum_bytes=NONCE_BYTES,
        size_label="nonce",
    )
    _decode_canonical_base64(
        "wrapped_key_b64",
        envelope.get("wrapped_key_b64"),
        minimum_bytes=MINIMUM_RSA_BITS // 8,
        maximum_bytes=PROTOTYPE_MAX_WRAPPED_KEY_BYTES,
        size_label="wrapped-key",
    )
    _decode_canonical_base64(
        "ciphertext_b64",
        envelope.get("ciphertext_b64"),
        minimum_bytes=16,
        maximum_bytes=PROTOTYPE_MAX_CIPHERTEXT_BYTES,
        size_label="ciphertext",
    )
    if len(_canonical_json_bytes(envelope)) > PROTOTYPE_MAX_ENVELOPE_FILE_BYTES:
        raise RuntimeError("encrypted witness envelope exceeds prototype byte limit")
    unsigned = dict(envelope)
    recorded_hash = unsigned.pop("envelope_sha256", None)
    if recorded_hash != _sha256(unsigned):
        raise RuntimeError("encrypted witness envelope integrity check failed")
    return envelope


def validate_envelope_authorization(
    envelope: dict[str, Any], *, authenticated_principal: str
) -> dict[str, Any]:
    envelope = validate_envelope(envelope)
    authorization = {
        "scheme": envelope["authorization_scheme"],
        "key_id": envelope["authorization_key_id"],
        "agency_id": envelope["agency_id"],
        "principal": envelope["authorized_principal"],
        "signature": envelope["authorization_signature_b64"],
    }
    validate_p256_package_authorization(
        package_sha256=envelope["package_sha256"],
        created_at=envelope["created_at"],
        authorization=authorization,
    )
    if envelope["authorized_principal"] != authenticated_principal:
        raise RuntimeError("authenticated principal does not match the envelope authorization")
    return envelope


def decrypt_batch_package(
    envelope: dict[str, Any],
    *,
    unwrap_key: Callable[[bytes, str, str], bytes],
) -> dict[str, Any]:
    envelope = validate_envelope(envelope)
    wrapped_key = base64.b64decode(envelope["wrapped_key_b64"], validate=True)
    context_sha256 = envelope_header_context_sha256(envelope)
    try:
        unwrapped = unwrap_key(
            wrapped_key,
            envelope["wrapping_key_id"],
            context_sha256,
        )
    except Exception as exc:
        raise RuntimeError("external KMS/HSM failed to unwrap the witness key") from exc
    if not isinstance(unwrapped, bytes) or len(unwrapped) != DEK_BYTES:
        raise RuntimeError("external KMS/HSM returned an invalid witness key")
    dek = bytearray(unwrapped)
    try:
        plaintext = AESGCM(bytes(dek)).decrypt(
            base64.b64decode(envelope["nonce_b64"], validate=True),
            base64.b64decode(envelope["ciphertext_b64"], validate=True),
            _canonical_json_bytes(_header(envelope)),
        )
    except Exception as exc:
        raise RuntimeError("encrypted witness authentication failed") from exc
    finally:
        for index in range(len(dek)):
            dek[index] = 0
    if len(plaintext) > PROTOTYPE_MAX_PLAINTEXT_BYTES:
        raise RuntimeError("decrypted witness plaintext exceeds prototype byte limit")
    try:
        package = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("decrypted witness package is invalid JSON") from exc
    package = validate_batch_package(package)
    if package["package_sha256"] != envelope["package_sha256"]:
        raise RuntimeError("decrypted package hash does not match its envelope")
    if package["witness_sha256"] != envelope["witness_sha256"]:
        raise RuntimeError("decrypted witness hash does not match its envelope")
    if package["claim_count"] != envelope["claim_count"]:
        raise RuntimeError("decrypted claim count does not match its envelope")
    if package["retain_until"] != envelope["retain_until"]:
        raise RuntimeError("decrypted retention window does not match its envelope")
    if package["authorization"].get("agency_id") != envelope["agency_id"]:
        raise RuntimeError("decrypted agency does not match its envelope")
    return package


def load_envelope(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            payload = stream.read(PROTOTYPE_MAX_ENVELOPE_FILE_BYTES + 1)
        if len(payload) > PROTOTYPE_MAX_ENVELOPE_FILE_BYTES:
            raise RuntimeError("encrypted witness envelope file exceeds prototype byte limit")
        value = json.loads(payload.decode("utf-8"))
    except RuntimeError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to read encrypted witness envelope: {path}") from exc
    return validate_envelope(value)


def write_envelope(path: Path, envelope: dict[str, Any]) -> None:
    validate_envelope(envelope)
    rendered = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(rendered) > PROTOTYPE_MAX_ENVELOPE_FILE_BYTES:
        raise RuntimeError("encrypted witness envelope file exceeds prototype byte limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise RuntimeError(f"refusing to overwrite encrypted witness envelope: {path}") from exc
