"""Fixture-only key custody and immutable storage for operational recovery tests.

These classes are deliberately synthetic and are not encryption, HSM, FIPS,
cloud, HA, or production-custody implementations.  They keep only sealed
bytes in storage and expose deterministic fault/revocation behavior.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Mapping

from app.mirror import operational_recovery as recovery


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


class SyntheticRecoveryClock:
    def __init__(self, start: int = 1_000) -> None:
        self.value = start
        self._monotonic = float(start)

    def now(self) -> int:
        return self.value

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, seconds: int) -> None:
        if type(seconds) is not int or seconds < 0:
            raise ValueError("synthetic-clock:advance")
        self.value += seconds
        self._monotonic += float(seconds)


class SyntheticKeyCustody:
    """Fixture-only reversible sealing with an in-memory synthetic key ring."""

    custody_id = "SYNTHETIC_KEY_CUSTODY_V1"
    _key_id = "SYNTHETIC_RECOVERY_KEY"

    def __init__(self, epoch: int = 1) -> None:
        if type(epoch) is not int or epoch < 1:
            raise ValueError("synthetic-key:epoch")
        self._current_epoch = epoch
        self._keys: dict[int, bytes] = {epoch: hashlib.sha3_512(f"synthetic-key-{epoch}".encode("ascii")).digest()}
        self._states: dict[int, str] = {epoch: "ACTIVE"}

    def current_key(self) -> Mapping[str, object]:
        return {"key_id": self._key_id, "key_epoch": self._current_epoch, "key_state": self._states[self._current_epoch]}

    def key_state(self, key_id: str, key_epoch: int) -> str:
        if key_id != self._key_id or key_epoch not in self._states:
            return "REVOKED"
        return self._states[key_epoch]

    def rotate(self, epoch: int) -> None:
        if type(epoch) is not int or epoch <= self._current_epoch:
            raise ValueError("synthetic-key:nonmonotonic")
        self._keys[epoch] = hashlib.sha3_512(f"synthetic-key-{epoch}".encode("ascii")).digest()
        self._states[epoch] = "ACTIVE"
        self._current_epoch = epoch

    def revoke(self, epoch: int) -> None:
        if epoch not in self._states:
            raise ValueError("synthetic-key:unknown")
        self._states[epoch] = "REVOKED"

    @staticmethod
    def _stream(key: bytes, object_id: str, size: int) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < size:
            output.extend(hashlib.sha3_512(key + object_id.encode("ascii") + counter.to_bytes(4, "big")).digest())
            counter += 1
        return bytes(output[:size])

    def seal(self, plaintext: bytes, *, object_id: str) -> recovery.SealedRecoveryObjectV1:
        return self.seal_for(plaintext, object_id=object_id, key_id=self._key_id, key_epoch=self._current_epoch)

    def seal_for(self, plaintext: bytes, *, object_id: str, key_id: str, key_epoch: int) -> recovery.SealedRecoveryObjectV1:
        if type(plaintext) is not bytes or not plaintext or len(plaintext) > 4 * 1024 * 1024:
            raise ValueError("synthetic-key:plaintext-cap")
        if key_id != self._key_id or key_epoch not in self._keys:
            raise ValueError("synthetic-key:unknown-key")
        epoch = key_epoch
        if self._states[epoch] != "ACTIVE":
            raise ValueError("synthetic-key:revoked")
        key = self._keys[epoch]
        mask = self._stream(key, object_id, len(plaintext))
        ciphertext = bytes(left ^ right for left, right in zip(plaintext, mask))
        tag = hmac.new(key, object_id.encode("ascii") + ciphertext, hashlib.sha3_512).hexdigest()
        body = {
            "schema": "synthetic-sealed-operational-recovery-v1",
            "object_id": object_id,
            "key_id": self._key_id,
            "key_epoch": epoch,
            "ciphertext_hex": ciphertext.hex(),
            "tag": tag,
        }
        sealed = _canonical(body)
        return recovery.SealedRecoveryObjectV1(object_id, self._key_id, epoch, "ACTIVE", sealed)

    def open(self, sealed_bytes: bytes, *, key_id: str, key_epoch: int) -> bytes:
        if key_id != self._key_id or key_epoch not in self._keys or self._states[key_epoch] != "ACTIVE":
            raise ValueError("synthetic-key:revoked")
        try:
            value = json.loads(sealed_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("synthetic-key:sealed-json") from exc
        if not isinstance(value, dict) or set(value) != {"schema", "object_id", "key_id", "key_epoch", "ciphertext_hex", "tag"} or value["schema"] != "synthetic-sealed-operational-recovery-v1" or value["key_id"] != key_id or value["key_epoch"] != key_epoch:
            raise ValueError("synthetic-key:sealed-binding")
        if _canonical(value) != sealed_bytes:
            raise ValueError("synthetic-key:sealed-canonical")
        try:
            ciphertext = bytes.fromhex(str(value["ciphertext_hex"]))
        except ValueError as exc:
            raise ValueError("synthetic-key:ciphertext") from exc
        key = self._keys[key_epoch]
        expected_tag = hmac.new(key, str(value["object_id"]).encode("ascii") + ciphertext, hashlib.sha3_512).hexdigest()
        if not hmac.compare_digest(expected_tag, str(value["tag"])):
            raise ValueError("synthetic-key:tag")
        mask = self._stream(key, str(value["object_id"]), len(ciphertext))
        return bytes(left ^ right for left, right in zip(ciphertext, mask))


class SyntheticRecoveryStorage:
    """Fixture-only immutable content-addressed object store."""

    storage_id = "SYNTHETIC_IMMUTABLE_STORAGE_V1"

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def put(self, object_id: str, sealed_bytes: bytes) -> Mapping[str, object]:
        if object_id in self._objects and self._objects[object_id] != sealed_bytes:
            raise ValueError("synthetic-storage:overwrite")
        self._objects.setdefault(object_id, bytes(sealed_bytes))
        return self.stat(object_id)

    def get(self, object_id: str) -> bytes:
        if object_id not in self._objects:
            raise KeyError("synthetic-storage:missing")
        return bytes(self._objects[object_id])

    def stat(self, object_id: str) -> Mapping[str, object]:
        value = self.get(object_id)
        return {
            "object_id": object_id,
            "storage_id": self.storage_id,
            "sealed_digest": hashlib.sha3_512(value).hexdigest(),
            "sealed_length": len(value),
        }

    def corrupt(self, object_id: str) -> None:
        value = bytearray(self.get(object_id))
        value[-1] ^= 1
        self._objects[object_id] = bytes(value)

    def remove(self, object_id: str) -> None:
        self._objects.pop(object_id, None)


__all__ = ["SyntheticRecoveryClock", "SyntheticKeyCustody", "SyntheticRecoveryStorage"]
