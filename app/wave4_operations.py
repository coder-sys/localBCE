"""Wave 4 operations and release primitives.

These are internal, local/sandbox implementations of O01-O06 and O12.  They
make the production boundary explicit: software KEM custody, local audit,
fixed-cadence batching, incident controls, and reproducible release evidence
are real and testable, but software custody and synthetic deployment are never
reported as HSM/FIPS validation or operator activation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Final, Protocol

from app.wave4_adapters import REQUIRED_CAPABILITIES, _canonical_json, _digest, _digest_hex


WAVE4_OPERATIONS_SCHEMA: Final[str] = "blind_ledger_operations_v1"
MAX_QUEUE_CAPACITY: Final[int] = 256
MAX_AUDIT_METADATA_FIELDS: Final[int] = 32
MAX_AUDIT_FILE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_RELEASE_FILES: Final[int] = 10_000
MAX_RELEASE_FILE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_KMS_PLAINTEXT_BYTES: Final[int] = 1 * 1024 * 1024
MAX_KMS_ASSOCIATED_DATA_BYTES: Final[int] = 64 * 1024
MAX_KMS_ENVELOPE_BYTES: Final[int] = 2 * 1024 * 1024
MAX_NONCE_RESERVATIONS: Final[int] = 1_000_000
NO_SWAP_RSS_LIMIT_BYTES: Final[int] = 5_000_000_000
NO_SWAP_SCRATCH_LIMIT_BYTES_EXCLUSIVE: Final[int] = 5_000_000_000
_WINDOWS_REPARSE_POINT: Final[int] = 0x400
_WAVE4_PACKAGE_IDS: Final[frozenset[str]] = frozenset(
    {*(f"I{index:02d}" for index in range(1, 9)), *(f"O{index:02d}" for index in (1, 2, 3, 4, 5, 6, 12))}
)

_IDENTIFIER = re.compile(r"[A-Z0-9][A-Z0-9_.:-]{0,127}\Z")
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_EVENT_TYPE = re.compile(r"[A-Z0-9][A-Z0-9_.:-]{0,63}\Z")
_SAFE_METADATA_KEY = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_FORBIDDEN_PATH_PARTS = frozenset({".git", "__pycache__", ".pytest_cache", "target", "out", "cache", "scratch"})
_FORBIDDEN_PUBLIC_TERMS = frozenset(
    {
        "patient",
        "member",
        "diagnosis",
        "procedure",
        "document",
        "medical",
        "phi",
        "amount",
        "payment",
        "ciphertext",
        "payload",
        "secret",
        "credential",
        "token",
        "raw",
    }
)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _require_regular_unlinked_file(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise Wave4OperationsError(f"{label}_unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink > 1
    ):
        raise Wave4OperationsError(f"{label}_must_be_unlinked_regular_file")
    return metadata


class Wave4OperationsError(RuntimeError):
    """Stable fail-closed error for the operations boundary."""


class UniformQueueError(Wave4OperationsError):
    """All public queue failures intentionally share one error class."""

    code: Final[str] = "BATCH_REJECTED"

    def __init__(self) -> None:
        super().__init__(self.code)


def _identifier(label: str, value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")
    return value


def _hex(label: str, value: object, *, length: int = 128) -> str:
    pattern = _HEX128 if length == 128 else _HEX64
    if not isinstance(value, str) or value != value.lower() or pattern.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")
    return value


def _bounded_int(label: str, value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label}_out_of_bounds")
    return value


def _safe_metadata(metadata: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(metadata, Mapping) or len(metadata) > MAX_AUDIT_METADATA_FIELDS:
        raise Wave4OperationsError("audit_metadata_bounds_invalid")
    allowed = {
        "adapter_id",
        "adapter_version",
        "capability",
        "status",
        "error_class",
        "reason_code",
        "source_epoch",
        "attempt",
        "queue_depth",
        "identity_digest_sha3_512",
        "release_digest_sha3_512",
        "checkpoint_digest_sha3_512",
        "event_digest_sha3_512",
        "profile_id",
        "provider_id",
        "severity",
    }
    result: dict[str, object] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or _SAFE_METADATA_KEY.fullmatch(key) is None or key not in allowed:
            raise Wave4OperationsError("audit_metadata_key_forbidden")
        if isinstance(value, (dict, list, tuple, set, bytes)) or not isinstance(value, (str, int, bool, type(None))):
            raise Wave4OperationsError("audit_metadata_value_invalid")
        if isinstance(value, str):
            capability_label = key == "capability" and value in REQUIRED_CAPABILITIES
            if not capability_label and any(term in value.lower() for term in _FORBIDDEN_PUBLIC_TERMS):
                raise Wave4OperationsError("audit_metadata_private_term_forbidden")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class DeploymentProfile:
    """Explicit resource and isolation policy for a local/sandbox worker."""

    profile_id: str
    network_access: bool = False
    live_credentials: bool = False
    swap_allowed: bool = False
    core_dumps_allowed: bool = False
    max_resident_bytes: int = NO_SWAP_RSS_LIMIT_BYTES
    max_scratch_bytes: int = NO_SWAP_SCRATCH_LIMIT_BYTES_EXCLUSIVE - 1
    fixed_cadence_ms: int = 1_000
    queue_capacity: int = 64

    def __post_init__(self) -> None:
        _identifier("deployment_profile_id", self.profile_id)
        for label, value in (
            ("network_access", self.network_access),
            ("live_credentials", self.live_credentials),
            ("swap_allowed", self.swap_allowed),
            ("core_dumps_allowed", self.core_dumps_allowed),
        ):
            if type(value) is not bool:
                raise ValueError(f"deployment_{label}_invalid")
        _bounded_int("deployment_max_resident_bytes", self.max_resident_bytes, minimum=1, maximum=NO_SWAP_RSS_LIMIT_BYTES)
        _bounded_int("deployment_max_scratch_bytes", self.max_scratch_bytes, minimum=0, maximum=NO_SWAP_SCRATCH_LIMIT_BYTES_EXCLUSIVE - 1)
        _bounded_int("deployment_fixed_cadence_ms", self.fixed_cadence_ms, minimum=1, maximum=60_000)
        _bounded_int("deployment_queue_capacity", self.queue_capacity, minimum=1, maximum=MAX_QUEUE_CAPACITY)
        if self.network_access or self.live_credentials or self.swap_allowed or self.core_dumps_allowed:
            raise ValueError("wave4_sandbox_profile_must_be_isolated")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "schema": WAVE4_OPERATIONS_SCHEMA,
            "profile_id": self.profile_id,
            "network_access": self.network_access,
            "live_credentials": self.live_credentials,
            "swap_allowed": self.swap_allowed,
            "core_dumps_allowed": self.core_dumps_allowed,
            "max_resident_bytes": self.max_resident_bytes,
            "max_scratch_bytes": self.max_scratch_bytes,
            "fixed_cadence_ms": self.fixed_cadence_ms,
            "queue_capacity": self.queue_capacity,
        }

    @property
    def profile_digest_sha3_512(self) -> str:
        return _digest_hex(b"BL/WAVE4/DEPLOYMENT-PROFILE/V1", _canonical_json(self.canonical_dict()))


class PqKmsPort(Protocol):
    provider_id: str
    kem_id: str
    software_only: bool
    hsm_backed: bool
    fips_validated: bool
    production_usable: bool

    def seal(self, *, plaintext: bytes, associated_data: bytes) -> bytes: ...

    def open(self, *, envelope: bytes, associated_data: bytes) -> bytes: ...

    def destroy(self) -> None: ...


class SoftwarePqKmsReference:
    """ML-KEM-1024/AES-256-GCM local reference with an explicit non-prod flag."""

    provider_id: Final[str] = "SYNTHETIC-SOFTWARE-PQ-KMS"
    kem_id: Final[str] = "ML-KEM-1024-AES-256-GCM"
    software_only: Final[bool] = True
    hsm_backed: Final[bool] = False
    fips_validated: Final[bool] = False
    production_usable: Final[bool] = False

    __slots__ = ("key_id", "public_key", "_secret_key", "_destroyed")

    def __init__(self, *, key_id: bytes | None = None) -> None:
        from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import (
            MlKem1024Aes256ReferenceV1,
        )

        public_key, secret_key = MlKem1024Aes256ReferenceV1.generate_keypair()
        if key_id is None:
            key_id = _digest(b"BL/WAVE4/KMS-KEY-ID/V1", public_key)
        if type(key_id) is not bytes or len(key_id) != 64 or not any(key_id):
            raise ValueError("wave4_kms_key_id_invalid")
        self.key_id = key_id
        self.public_key = public_key
        self._secret_key = bytearray(secret_key)
        self._destroyed = False

    def _require_active(self) -> None:
        if self._destroyed or not self._secret_key:
            raise Wave4OperationsError("wave4_kms_key_destroyed")

    def seal(self, *, plaintext: bytes, associated_data: bytes) -> bytes:
        self._require_active()
        if (
            type(plaintext) is not bytes
            or len(plaintext) > MAX_KMS_PLAINTEXT_BYTES
            or type(associated_data) is not bytes
            or len(associated_data) > MAX_KMS_ASSOCIATED_DATA_BYTES
        ):
            raise Wave4OperationsError("wave4_kms_input_bounds_invalid")
        from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import (
            MlKem1024Aes256ReferenceV1,
        )

        try:
            return MlKem1024Aes256ReferenceV1.seal(
                key_id=self.key_id,
                public_key=self.public_key,
                plaintext=plaintext,
                associated_data=associated_data,
            )
        except Exception as exc:
            raise Wave4OperationsError("wave4_kms_seal_failed_closed") from exc

    def open(self, *, envelope: bytes, associated_data: bytes) -> bytes:
        self._require_active()
        if (
            type(envelope) is not bytes
            or len(envelope) > MAX_KMS_ENVELOPE_BYTES
            or type(associated_data) is not bytes
            or len(associated_data) > MAX_KMS_ASSOCIATED_DATA_BYTES
        ):
            raise Wave4OperationsError("wave4_kms_input_bounds_invalid")
        from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import (
            MlKem1024Aes256ReferenceV1,
        )

        try:
            return MlKem1024Aes256ReferenceV1.open(
                secret_key=bytes(self._secret_key),
                envelope=envelope,
                associated_data=associated_data,
                expected_key_id=self.key_id,
            )
        except Exception as exc:
            raise Wave4OperationsError("wave4_kms_open_rejected") from exc

    def destroy(self) -> None:
        for index in range(len(self._secret_key)):
            self._secret_key[index] = 0
        self._secret_key.clear()
        self._destroyed = True


@dataclass(frozen=True, slots=True)
class KeyRootRecord:
    handle_id: str
    epoch: int
    root_digest_sha3_512: str
    status: str = "active"

    def __post_init__(self) -> None:
        _identifier("key_handle_id", self.handle_id)
        _bounded_int("key_epoch", self.epoch, minimum=1, maximum=2**63 - 1)
        _hex("key_root_digest", self.root_digest_sha3_512)
        if self.status not in {"active", "retired", "destroyed"}:
            raise ValueError("key_status_invalid")


class KeyLifecycleRegistry:
    """Root-only lifecycle registry; raw private key material is never stored."""

    def __init__(self) -> None:
        self._records: dict[str, KeyRootRecord] = {}

    def register(self, handle_id: str, root_digest_sha3_512: str, *, epoch: int = 1) -> KeyRootRecord:
        handle = _identifier("key_handle_id", handle_id)
        if handle in self._records:
            raise Wave4OperationsError("key_handle_already_registered")
        record = KeyRootRecord(handle, epoch, _hex("key_root_digest", root_digest_sha3_512))
        self._records[handle] = record
        return record

    def rotate(self, handle_id: str, root_digest_sha3_512: str) -> KeyRootRecord:
        handle = _identifier("key_handle_id", handle_id)
        try:
            current = self._records[handle]
        except KeyError as exc:
            raise Wave4OperationsError("key_handle_unknown") from exc
        if current.status != "active":
            raise Wave4OperationsError("key_handle_not_active")
        new_root = _hex("key_root_digest", root_digest_sha3_512)
        if new_root == current.root_digest_sha3_512:
            raise Wave4OperationsError("key_root_unchanged")
        self._records[handle] = KeyRootRecord(handle, current.epoch + 1, new_root)
        return self._records[handle]

    def retire(self, handle_id: str) -> KeyRootRecord:
        handle = _identifier("key_handle_id", handle_id)
        current = self._records.get(handle)
        if current is None:
            raise Wave4OperationsError("key_handle_unknown")
        if current.status != "active":
            raise Wave4OperationsError("key_handle_not_active")
        self._records[handle] = KeyRootRecord(handle, current.epoch, current.root_digest_sha3_512, "retired")
        return self._records[handle]

    def destroy(self, handle_id: str) -> KeyRootRecord:
        handle = _identifier("key_handle_id", handle_id)
        current = self._records.get(handle)
        if current is None:
            raise Wave4OperationsError("key_handle_unknown")
        self._records[handle] = KeyRootRecord(handle, current.epoch, current.root_digest_sha3_512, "destroyed")
        return self._records[handle]

    def records(self) -> tuple[KeyRootRecord, ...]:
        return tuple(self._records[key] for key in sorted(self._records))

    @property
    def registry_digest_sha3_512(self) -> str:
        return _digest_hex(
            b"BL/WAVE4/KEY-REGISTRY/V1",
            *(
                _canonical_json(
                    {
                        "handle_id": item.handle_id,
                        "epoch": item.epoch,
                        "root_digest_sha3_512": item.root_digest_sha3_512,
                        "status": item.status,
                    }
                )
                for item in self.records()
            ),
        )


def secure_zeroize(buffer: bytearray) -> None:
    if type(buffer) is not bytearray:
        raise TypeError("zeroize_requires_bytearray")
    for index in range(len(buffer)):
        buffer[index] = 0
    buffer.clear()


class NonceReuseGuard:
    """O02 nonce/entropy admission guard using only digest records."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def reserve(self, nonce: bytes, *, context: bytes) -> str:
        if type(nonce) is not bytes or not nonce or len(nonce) > 128 or type(context) is not bytes or len(context) > 4096:
            raise Wave4OperationsError("nonce_input_bounds_invalid")
        digest = _digest_hex(b"BL/WAVE4/NONCE/V1", context, nonce)
        if digest in self._used:
            raise Wave4OperationsError("nonce_reuse_rejected")
        if len(self._used) >= MAX_NONCE_RESERVATIONS:
            raise Wave4OperationsError("nonce_reservation_capacity_exceeded")
        self._used.add(digest)
        return digest

    @property
    def reservation_count(self) -> int:
        return len(self._used)


def healthy_entropy_sample(length: int = 32) -> bytes:
    size = _bounded_int("entropy_sample_length", length, minimum=16, maximum=1024)
    sample = secrets.token_bytes(size)
    if len(sample) != size or not any(sample):
        raise Wave4OperationsError("entropy_health_failed_closed")
    return sample


@dataclass(frozen=True, slots=True)
class AuditEvent:
    sequence: int
    event_type: str
    correlation_digest_sha3_512: str
    metadata: Mapping[str, object]
    previous_digest_sha3_512: str
    event_digest_sha3_512: str

    def canonical_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "event_type": self.event_type,
            "correlation_digest_sha3_512": self.correlation_digest_sha3_512,
            "metadata": dict(self.metadata),
            "previous_digest_sha3_512": self.previous_digest_sha3_512,
            "event_digest_sha3_512": self.event_digest_sha3_512,
        }


class NonPhiAuditLog:
    """Append-only hash chain whose admission schema excludes private payloads."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            metadata = None
        except OSError as exc:
            raise Wave4OperationsError("audit_log_unreadable") from exc
        if metadata is not None:
            _require_regular_unlinked_file(self.path, label="audit_log")
            if metadata.st_size > MAX_AUDIT_FILE_BYTES:
                raise Wave4OperationsError("audit_log_size_limit_exceeded")
        self._events = self._read_and_verify()

    def _read_and_verify(self) -> tuple[AuditEvent, ...]:
        if not self.path.exists():
            return ()
        events: list[AuditEvent] = []
        previous = "0" * 128
        for line_number, raw in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            try:
                payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
                if not isinstance(payload, dict):
                    raise ValueError
                if set(payload) != {
                    "sequence",
                    "event_type",
                    "correlation_digest_sha3_512",
                    "metadata",
                    "previous_digest_sha3_512",
                    "event_digest_sha3_512",
                }:
                    raise ValueError
                event = AuditEvent(
                    sequence=payload["sequence"],
                    event_type=payload["event_type"],
                    correlation_digest_sha3_512=payload["correlation_digest_sha3_512"],
                    metadata=payload["metadata"],
                    previous_digest_sha3_512=payload["previous_digest_sha3_512"],
                    event_digest_sha3_512=payload["event_digest_sha3_512"],
                )
                _bounded_int("audit_sequence", event.sequence, minimum=1, maximum=2**63 - 1)
                if event.sequence != line_number or event.previous_digest_sha3_512 != previous:
                    raise ValueError
                if _SAFE_EVENT_TYPE.fullmatch(event.event_type) is None:
                    raise ValueError
                _hex("audit_correlation", event.correlation_digest_sha3_512)
                _hex("audit_previous", event.previous_digest_sha3_512)
                _hex("audit_event_digest", event.event_digest_sha3_512)
                metadata = _safe_metadata(event.metadata)
                unsigned = _canonical_json(
                    {
                        "sequence": event.sequence,
                        "event_type": event.event_type,
                        "correlation_digest_sha3_512": event.correlation_digest_sha3_512,
                        "metadata": metadata,
                        "previous_digest_sha3_512": previous,
                    }
                )
                expected = _digest_hex(b"BL/WAVE4/AUDIT-EVENT/V1", unsigned)
                if expected != event.event_digest_sha3_512:
                    raise ValueError
                previous = expected
                events.append(event)
            except Exception as exc:
                raise Wave4OperationsError(f"audit_log_corrupt_at_line_{line_number}") from exc
        return tuple(events)

    @property
    def head_digest_sha3_512(self) -> str:
        return self._events[-1].event_digest_sha3_512 if self._events else "0" * 128

    def append(self, event_type: str, *, correlation_digest_sha3_512: str, metadata: Mapping[str, object] | None = None) -> AuditEvent:
        if not isinstance(event_type, str) or _SAFE_EVENT_TYPE.fullmatch(event_type) is None:
            raise Wave4OperationsError("audit_event_type_invalid")
        correlation = _hex("audit_correlation", correlation_digest_sha3_512)
        safe = _safe_metadata(metadata or {})
        sequence = len(self._events) + 1
        unsigned = _canonical_json(
            {
                "sequence": sequence,
                "event_type": event_type,
                "correlation_digest_sha3_512": correlation,
                "metadata": safe,
                "previous_digest_sha3_512": self.head_digest_sha3_512,
            }
        )
        event = AuditEvent(sequence, event_type, correlation, safe, self.head_digest_sha3_512, _digest_hex(b"BL/WAVE4/AUDIT-EVENT/V1", unsigned))
        serialized = json.dumps(event.canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        try:
            existing = self.path.lstat()
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise Wave4OperationsError("audit_log_unreadable") from exc
        if existing is not None:
            _require_regular_unlinked_file(self.path, label="audit_log")
            current_size = existing.st_size
        else:
            current_size = 0
        if current_size + len(serialized.encode("utf-8")) > MAX_AUDIT_FILE_BYTES:
            raise Wave4OperationsError("audit_log_size_limit_exceeded")
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        self._events = (*self._events, event)
        return event

    def events(self) -> tuple[AuditEvent, ...]:
        return self._events


@dataclass(frozen=True, slots=True)
class CadenceSlot:
    slot_index: int
    kind: str
    commitment_sha3_512: str

    def __post_init__(self) -> None:
        _bounded_int("cadence_slot_index", self.slot_index, minimum=0, maximum=MAX_QUEUE_CAPACITY - 1)
        if self.kind not in {"real", "cover"}:
            raise ValueError("cadence_slot_kind_invalid")
        _hex("cadence_slot_commitment", self.commitment_sha3_512)


class FixedCadenceQueue:
    """Bounded fixed-shape queue with cover slots and uniform public failures."""

    def __init__(self, *, capacity: int, batch_size: int, cadence_ms: int) -> None:
        self.capacity = _bounded_int("queue_capacity", capacity, minimum=1, maximum=MAX_QUEUE_CAPACITY)
        self.batch_size = _bounded_int("queue_batch_size", batch_size, minimum=1, maximum=self.capacity)
        self.cadence_ms = _bounded_int("queue_cadence_ms", cadence_ms, minimum=1, maximum=60_000)
        self._pending: dict[str, str] = {}
        self._tick = 0

    def submit(self, *, job_id: str, opaque_commitment_sha3_512: str) -> None:
        _identifier("queue_job_id", job_id)
        _hex("queue_commitment", opaque_commitment_sha3_512)
        if job_id in self._pending or len(self._pending) >= self.capacity:
            raise UniformQueueError()
        self._pending[job_id] = opaque_commitment_sha3_512

    def tick(self) -> tuple[CadenceSlot, ...]:
        items = tuple(self._pending.items())[: self.batch_size]
        for job_id, _ in items:
            del self._pending[job_id]
        slots: list[CadenceSlot] = []
        for index in range(self.batch_size):
            if index < len(items):
                slots.append(CadenceSlot(index, "real", items[index][1]))
            else:
                slots.append(
                    CadenceSlot(
                        index,
                        "cover",
                        _digest_hex(b"BL/WAVE4/COVER-SLOT/V1", self._tick.to_bytes(8, "big"), index.to_bytes(4, "big")),
                    )
                )
        self._tick += 1
        return tuple(slots)

    @property
    def depth(self) -> int:
        return len(self._pending)


@dataclass(frozen=True, slots=True)
class IncidentState:
    status: str
    reason_code: str
    checkpoint_digest_sha3_512: str

    def __post_init__(self) -> None:
        if self.status not in {"healthy", "paused", "recovering"}:
            raise ValueError("incident_state_invalid")
        if not re.fullmatch(r"[A-Z0-9_]{0,64}", self.reason_code):
            raise ValueError("incident_reason_invalid")
        _hex("incident_checkpoint_digest", self.checkpoint_digest_sha3_512)


class IncidentController:
    """Non-PHI pause/recovery/rollback state machine for O06 drills."""

    def __init__(self, audit_log: NonPhiAuditLog) -> None:
        self.audit_log = audit_log
        self.state = IncidentState("healthy", "", "0" * 128)

    def pause(self, *, reason_code: str, checkpoint_digest_sha3_512: str) -> IncidentState:
        if self.state.status != "healthy":
            raise Wave4OperationsError("incident_pause_requires_healthy")
        reason = reason_code if re.fullmatch(r"[A-Z0-9_]{1,64}", reason_code or "") else "INCIDENT"
        checkpoint = _hex("incident_checkpoint_digest", checkpoint_digest_sha3_512)
        self.state = IncidentState("paused", reason, checkpoint)
        self.audit_log.append(
            "INCIDENT_PAUSED",
            correlation_digest_sha3_512=checkpoint,
            metadata={"reason_code": reason, "status": "paused", "checkpoint_digest_sha3_512": checkpoint},
        )
        return self.state

    def begin_recovery(self) -> IncidentState:
        if self.state.status != "paused":
            raise Wave4OperationsError("incident_recovery_requires_pause")
        self.state = IncidentState("recovering", self.state.reason_code, self.state.checkpoint_digest_sha3_512)
        self.audit_log.append(
            "INCIDENT_RECOVERY_STARTED",
            correlation_digest_sha3_512=self.state.checkpoint_digest_sha3_512,
            metadata={"reason_code": self.state.reason_code, "status": "recovering", "checkpoint_digest_sha3_512": self.state.checkpoint_digest_sha3_512},
        )
        return self.state

    def resume(self, *, recovery_digest_sha3_512: str) -> IncidentState:
        digest = _hex("incident_recovery_digest", recovery_digest_sha3_512)
        if self.state.status != "recovering" or digest != self.state.checkpoint_digest_sha3_512:
            raise Wave4OperationsError("incident_recovery_binding_invalid")
        self.state = IncidentState("healthy", "", digest)
        self.audit_log.append(
            "INCIDENT_RECOVERY_COMPLETED",
            correlation_digest_sha3_512=digest,
            metadata={"status": "healthy", "checkpoint_digest_sha3_512": digest},
        )
        return self.state

    def drill(self, *, checkpoint_digest_sha3_512: str) -> tuple[str, ...]:
        self.pause(reason_code="SYNTHETIC_DRILL", checkpoint_digest_sha3_512=checkpoint_digest_sha3_512)
        self.begin_recovery()
        self.resume(recovery_digest_sha3_512=checkpoint_digest_sha3_512)
        return ("pause", "recovery", "resume")


@dataclass(frozen=True, slots=True)
class ReleaseFile:
    path: str
    size: int
    sha256: str
    sha3_512: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, str)
            or not self.path
            or "\\" in self.path
            or self.path.startswith("/")
            or any(part in {"", ".", ".."} for part in Path(self.path).parts)
        ):
            raise ValueError("wave4_release_file_path_invalid")
        _bounded_int("wave4_release_file_size", self.size, minimum=0, maximum=MAX_RELEASE_FILE_BYTES)
        _hex("wave4_release_file_sha256", self.sha256, length=64)
        _hex("wave4_release_file_sha3_512", self.sha3_512)

    def canonical_dict(self) -> dict[str, object]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256, "sha3_512": self.sha3_512}


@dataclass(frozen=True, slots=True)
class Wave4ReleaseManifest:
    profile: DeploymentProfile
    package_status: Mapping[str, str]
    files: tuple[ReleaseFile, ...]
    production_usable: bool = False
    proof_suite_id: None = None

    def __post_init__(self) -> None:
        if type(self.profile) is not DeploymentProfile:
            raise ValueError("wave4_release_profile_invalid")
        if self.production_usable is not False or self.proof_suite_id is not None:
            raise ValueError("wave4_release_must_remain_nonactivating")
        if type(self.files) is not tuple or not self.files or len(self.files) > MAX_RELEASE_FILES:
            raise ValueError("wave4_release_file_list_invalid")
        if any(type(item) is not ReleaseFile for item in self.files):
            raise ValueError("wave4_release_file_type_invalid")
        if any(item.path != item.path.replace("\\", "/") for item in self.files):
            raise ValueError("wave4_release_path_not_posix")
        if tuple(item.path for item in self.files) != tuple(sorted(item.path for item in self.files)):
            raise ValueError("wave4_release_file_order_invalid")
        if not isinstance(self.package_status, Mapping) or set(self.package_status) != _WAVE4_PACKAGE_IDS:
            raise ValueError("wave4_release_package_status_invalid")
        if any(status != "complete_internal_nonactivating" for status in self.package_status.values()):
            raise ValueError("wave4_release_package_status_invalid")
        if len({item.path for item in self.files}) != len(self.files):
            raise ValueError("wave4_release_duplicate_file")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "schema": WAVE4_OPERATIONS_SCHEMA,
            "wave": 4,
            "profile": self.profile.canonical_dict(),
            "package_status": dict(sorted(self.package_status.items())),
            "files": [item.canonical_dict() for item in self.files],
            "production_usable": False,
            "proofSuiteId": None,
        }

    @property
    def manifest_digest_sha3_512(self) -> str:
        return _digest_hex(b"BL/WAVE4/RELEASE-MANIFEST/V1", _canonical_json(self.canonical_dict()))


def _release_file(repo_root: Path, relative: str) -> ReleaseFile:
    path = repo_root / relative
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise Wave4OperationsError(f"release_source_missing:{relative}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink > 1
    ):
        raise Wave4OperationsError(f"release_source_not_unlinked_regular_file:{relative}")
    normalized = relative.replace("\\", "/")
    if any(part in _FORBIDDEN_PATH_PARTS for part in Path(normalized).parts) or path.suffix.lower() in {".zip", ".pyc", ".key", ".pem"}:
        raise Wave4OperationsError(f"release_generated_or_secret_path:{normalized}")
    if metadata.st_size > MAX_RELEASE_FILE_BYTES:
        raise Wave4OperationsError(f"release_source_size_limit_exceeded:{normalized}")
    raw = path.read_bytes()
    return ReleaseFile(normalized, len(raw), hashlib.sha256(raw).hexdigest(), hashlib.sha3_512(raw).hexdigest())


def build_wave4_release_manifest(repo_root: Path) -> Wave4ReleaseManifest:
    """Build deterministic evidence for the Wave 4 source boundary."""
    root = Path(repo_root).resolve()
    relative_paths = (
        "app/wave4_adapters.py",
        "app/wave4_operations.py",
        "tools/wave4_conformance.py",
        "tests/test_wave4_adapters_operations.py",
        "ops/wave4_release_profile.json",
        "ops/wave4_sandbox_config.json",
        "ops/monitoring_events.json",
    )
    files = tuple(sorted((_release_file(root, relative) for relative in relative_paths), key=lambda item: item.path))
    package_status = {
        **{f"I{index:02d}": "complete_internal_nonactivating" for index in range(1, 9)},
        **{f"O{index:02d}": "complete_internal_nonactivating" for index in (1, 2, 3, 4, 5, 6, 12)},
    }
    return Wave4ReleaseManifest(DeploymentProfile("SYNTHETIC-WAVE4-SANDBOX"), package_status, files)


__all__ = (
    "AuditEvent",
    "CadenceSlot",
    "DeploymentProfile",
    "FixedCadenceQueue",
    "IncidentController",
    "IncidentState",
    "KeyLifecycleRegistry",
    "KeyRootRecord",
    "NO_SWAP_RSS_LIMIT_BYTES",
    "NO_SWAP_SCRATCH_LIMIT_BYTES_EXCLUSIVE",
    "NonceReuseGuard",
    "NonPhiAuditLog",
    "PqKmsPort",
    "ReleaseFile",
    "RetryPolicy",
    "SoftwarePqKmsReference",
    "UniformQueueError",
    "WAVE4_OPERATIONS_SCHEMA",
    "Wave4OperationsError",
    "Wave4ReleaseManifest",
    "build_wave4_release_manifest",
    "healthy_entropy_sample",
    "secure_zeroize",
)
