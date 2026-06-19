from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.batch.poseidon import domain_poseidon_hash

AUDIT_DATA_ENCRYPTION_KEY_ENV = "BL_AUDIT_DATA_ENCRYPTION_KEY_B64"
SCHEMA_VERSION = "blind_ledger_encrypted_claim_data_v3"
DEFAULT_KEY_EPOCH = "local-dev-epoch-1"
KEY_BYTES = 32
NONCE_BYTES = 12
CHUNK_BYTES = 30


@dataclass(frozen=True)
class EncryptedClaimData:
    schema_version: str
    algorithm: str
    key_id: str
    key_epoch: str
    nonce_b64: str
    aad: str
    plaintext_commitment: str
    plaintext_commitment_algorithm: str
    ciphertext_b64: str

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "key_epoch": self.key_epoch,
            "nonce_b64": self.nonce_b64,
            "aad": self.aad,
            "plaintext_commitment": self.plaintext_commitment,
            "plaintext_commitment_algorithm": self.plaintext_commitment_algorithm,
            "ciphertext_b64": self.ciphertext_b64,
        }


def generate_audit_key_b64() -> str:
    return base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def _normalize_json_value(payload: Any) -> Any:
    if isinstance(payload, str):
        return unicodedata.normalize("NFC", payload)
    if isinstance(payload, list):
        return [_normalize_json_value(item) for item in payload]
    if isinstance(payload, dict):
        normalized: dict[str, Any] = {}
        for key, value in payload.items():
            normalized_key = unicodedata.normalize("NFC", str(key))
            if normalized_key in normalized:
                raise ValueError("canonical_json_duplicate_key_after_unicode_normalization")
            normalized[normalized_key] = _normalize_json_value(value)
        return normalized
    return payload


def _canonical_json(payload: Any) -> bytes:
    normalized = _normalize_json_value(payload)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _key_from_b64(key_b64: str | None = None) -> bytes:
    configured = key_b64 or os.environ.get(AUDIT_DATA_ENCRYPTION_KEY_ENV, "")
    if not configured:
        raise RuntimeError(f"missing audit data encryption key: {AUDIT_DATA_ENCRYPTION_KEY_ENV}")
    try:
        key = base64.b64decode(configured.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("audit_data_key_invalid_base64") from exc
    if len(key) != KEY_BYTES:
        raise ValueError("audit_data_key_must_be_32_bytes")
    return key


def _derive_bytes(key: bytes, label: str, payload: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=sha256(label.encode("utf-8")).digest(),
        info=payload,
    ).derive(key)


def _canonical_key_epoch(key_epoch: str) -> str:
    normalized = unicodedata.normalize("NFC", str(key_epoch or ""))
    if not normalized:
        raise ValueError("encrypted_claim_data_key_epoch_required")
    if "|" in normalized:
        raise ValueError("encrypted_claim_data_key_epoch_invalid")
    return normalized


def _aead_aad(aad: str, key_id: str, key_epoch: str) -> bytes:
    return _canonical_json({"aad": aad, "key_epoch": key_epoch, "key_id": key_id})


def _plaintext_commitment(payload: Any, aad: str, key_epoch: str) -> str:
    canonical = _canonical_json({"aad": aad, "key_epoch": key_epoch, "payload": payload})
    acc = domain_poseidon_hash("data_availability", [len(canonical)])
    for index in range(0, len(canonical), CHUNK_BYTES):
        chunk = canonical[index : index + CHUNK_BYTES]
        chunk_felt = len(chunk)
        for byte in chunk:
            chunk_felt = (chunk_felt << 8) | byte
        acc = domain_poseidon_hash("data_availability", [len(canonical), index // CHUNK_BYTES, acc, chunk_felt])
    return f"{acc:064x}"


def encrypt_claim_data(
    payload: Any,
    *,
    key_b64: str | None = None,
    aad: str = "",
    key_id: str = "audit-key-local-dev",
    key_epoch: str = DEFAULT_KEY_EPOCH,
) -> EncryptedClaimData:
    if not aad:
        raise ValueError("encrypted_claim_data_aad_required")
    if not key_id:
        raise ValueError("encrypted_claim_data_key_id_required")
    key_epoch = _canonical_key_epoch(key_epoch)
    key = _key_from_b64(key_b64)
    plaintext = _canonical_json(payload)
    aad_bytes = _aead_aad(aad, key_id, key_epoch)
    per_record_key = _derive_bytes(
        key,
        f"blind-ledger-audit-da-key-v3:{key_epoch}",
        f"{key_id}|{aad}".encode("utf-8"),
        KEY_BYTES,
    )
    nonce = _derive_bytes(key, f"blind-ledger-audit-da-nonce-v3:{key_epoch}", aad_bytes + b"|" + plaintext, NONCE_BYTES)
    ciphertext = AESGCM(per_record_key).encrypt(nonce, plaintext, aad_bytes)
    return EncryptedClaimData(
        schema_version=SCHEMA_VERSION,
        algorithm="AES-256-GCM-HKDF-SHA256",
        key_id=key_id,
        key_epoch=key_epoch,
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        aad=aad,
        plaintext_commitment=_plaintext_commitment(payload, aad, key_epoch),
        plaintext_commitment_algorithm="POSEIDON-FIELD-CANONICAL-JSON-V1",
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
    )


def decrypt_claim_data(bundle: EncryptedClaimData | dict[str, str], *, key_b64: str | None = None) -> Any:
    payload = bundle.to_dict() if isinstance(bundle, EncryptedClaimData) else dict(bundle)
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("encrypted_claim_data_schema_mismatch")
    if payload.get("algorithm") != "AES-256-GCM-HKDF-SHA256":
        raise ValueError("encrypted_claim_data_algorithm_mismatch")
    aad_value = str(payload.get("aad") or "")
    if not aad_value:
        raise ValueError("encrypted_claim_data_aad_required")
    key_id = str(payload.get("key_id") or "")
    if not key_id:
        raise ValueError("encrypted_claim_data_key_id_required")
    key_epoch = _canonical_key_epoch(str(payload.get("key_epoch") or ""))
    key = _key_from_b64(key_b64)
    nonce = base64.b64decode(str(payload["nonce_b64"]).encode("ascii"), validate=True)
    ciphertext = base64.b64decode(str(payload["ciphertext_b64"]).encode("ascii"), validate=True)
    aad = _aead_aad(aad_value, key_id, key_epoch)
    per_record_key = _derive_bytes(
        key,
        f"blind-ledger-audit-da-key-v3:{key_epoch}",
        f"{key_id}|{aad_value}".encode("utf-8"),
        KEY_BYTES,
    )
    plaintext = AESGCM(per_record_key).decrypt(nonce, ciphertext, aad)
    decoded = json.loads(plaintext.decode("utf-8"))
    expected_commitment = _plaintext_commitment(decoded, aad_value, key_epoch)
    if payload.get("plaintext_commitment") != expected_commitment:
        raise ValueError("encrypted_claim_data_plaintext_commitment_mismatch")
    return decoded


def encrypted_claim_data_root(bundle: EncryptedClaimData | dict[str, str]) -> str:
    payload = bundle.to_dict() if isinstance(bundle, EncryptedClaimData) else dict(bundle)
    if payload.get("plaintext_commitment_algorithm") != "POSEIDON-FIELD-CANONICAL-JSON-V1":
        raise ValueError("encrypted_claim_data_plaintext_commitment_algorithm_mismatch")
    commitment = str(payload.get("plaintext_commitment") or "")
    if len(commitment) != 64:
        raise ValueError("encrypted_claim_data_plaintext_commitment_invalid")
    return commitment
