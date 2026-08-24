"""Small, bounded operational owner for the Mirror V2 services.

The owner composes the existing Ingress, Core, and Recovery services.  It does
not own raw captures, database state, source truth, payment, clearance, or
publication.  All public failures and results are fixed-shape and sanitized.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import stat
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from app.mirror import core_v2 as core
from app.mirror import core_v2_independent as core_independent
from app.mirror import ingress_v2 as ingress
from app.mirror import ingress_v2_independent as ingress_independent
from app.mirror import recovery_v2 as recovery
from app.mirror import recovery_v2_independent as recovery_independent


SCHEMA = "mirror-operational-owner-v1"
SCHEMA_VERSION = 1
STATUS_COMPLETE = "COMPLETE"
OUTCOME_KEYS = (
    "eligible",
    "processed",
    "scheduled",
    "claimed",
    "admitted",
    "held",
    "acquisition_rejected",
    "admission_rejected",
    "claim_rejected",
    "core_ingested",
    "recovery_created",
)
_EXPECTED_CHILDREN = {
    "ingress.sqlite",
    "core.sqlite",
    "recovery.sqlite",
    "operational.lock",
}
_SIDECARS = ("-wal", "-shm", "-journal")
_REPARSE_POINT = 0x400
_HEX = frozenset("0123456789abcdef")


class OperationalOwnerError(ValueError):
    """Fixed public operational-owner error."""


@dataclass(frozen=True)
class OperationalConfigV1:
    """Pinned acquisition identity, policy/profile, and per-run bound."""

    acquisition_identity: str
    external_policy_digest: str
    profile_digest: str
    max_due: int = 16

    def __post_init__(self) -> None:
        if (
            type(self.acquisition_identity) is not str
            or not self.acquisition_identity
            or len(self.acquisition_identity) > 256
        ):
            raise OperationalOwnerError("mirror:operational-config")
        try:
            encoded = self.acquisition_identity.encode("ascii")
        except UnicodeEncodeError:
            raise OperationalOwnerError("mirror:operational-config") from None
        if not encoded or any(byte < 0x21 or byte > 0x7E for byte in encoded):
            raise OperationalOwnerError("mirror:operational-config")
        for value in (self.external_policy_digest, self.profile_digest):
            if (
                type(value) is not str
                or len(value) != 128
                or any(char not in _HEX for char in value)
            ):
                raise OperationalOwnerError("mirror:operational-config")
        if type(self.max_due) is not int or not 1 <= self.max_due <= 16:
            raise OperationalOwnerError("mirror:operational-config")


@dataclass(frozen=True)
class AcquisitionPayloadV1:
    """Exactly the two bounded payloads handed to Ingress admission."""

    envelope_raw: bytes
    external_evidence_raw: bytes

    def __post_init__(self) -> None:
        if (
            type(self.envelope_raw) is not bytes
            or type(self.external_evidence_raw) is not bytes
            or not self.envelope_raw
            or not self.external_evidence_raw
        ):
            raise OperationalOwnerError("mirror:operational-acquisition")


class AcquisitionPort(Protocol):
    acquisition_identity: str
    external_policy_digest: str
    profile_digest: str

    def acquire(self, slot_id: str, scheduled_at: int, attempt: int) -> AcquisitionPayloadV1: ...


AcquisitionPayload = AcquisitionPayloadV1
AcquisitionResult = AcquisitionPayloadV1
AcquisitionPortV1 = AcquisitionPort


@dataclass(frozen=True)
class OperationalAggregateV1:
    schema: str
    schema_version: int
    status: str
    counts: Mapping[str, int]
    recovery_created: bool
    ingress_config_digest: str
    core_config_digest: str
    recovery_config_digest: str
    external_policy_digest: str
    profile_digest: str
    ingress_head_root: str
    ingress_sequence: int
    core_head_root: str
    core_sequence: int
    recovery_head_root: str
    recovery_sequence: int

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.schema_version != SCHEMA_VERSION or self.status != STATUS_COMPLETE:
            raise OperationalOwnerError("mirror:operational-result")
        if type(self.counts) is not MappingProxyType:
            object.__setattr__(self, "counts", MappingProxyType(dict(self.counts)))
        if tuple(self.counts) != OUTCOME_KEYS or any(type(value) is not int or value < 0 for value in self.counts.values()):
            raise OperationalOwnerError("mirror:operational-result")
        if type(self.recovery_created) is not bool:
            raise OperationalOwnerError("mirror:operational-result")
        for value in (
            self.ingress_config_digest,
            self.core_config_digest,
            self.recovery_config_digest,
            self.external_policy_digest,
            self.profile_digest,
            self.ingress_head_root,
            self.core_head_root,
            self.recovery_head_root,
        ):
            if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
                raise OperationalOwnerError("mirror:operational-result")
        for value in (self.ingress_sequence, self.core_sequence, self.recovery_sequence):
            if type(value) is not int or value < 0:
                raise OperationalOwnerError("mirror:operational-result")


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return int(info.st_dev), int(info.st_ino), int(info.st_nlink)


def _safe_root(root: str | Path) -> Path:
    if not isinstance(root, (str, Path)):
        raise OperationalOwnerError("mirror:operational-root")
    path = Path(root)
    raw = os.fspath(path)
    if (
        not path.is_absolute()
        or not path.anchor
        or raw.startswith("\\\\")
        or path.parent == path
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise OperationalOwnerError("mirror:operational-root")
    try:
        resolved = path.resolve(strict=True)
        info = os.lstat(path)
    except (OSError, RuntimeError):
        raise OperationalOwnerError("mirror:operational-root") from None
    if (
        os.path.normcase(os.fspath(resolved)) != os.path.normcase(os.fspath(path))
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
    ):
        raise OperationalOwnerError("mirror:operational-root")
    cursor = path
    while True:
        try:
            ancestor = os.lstat(cursor)
        except OSError:
            raise OperationalOwnerError("mirror:operational-root") from None
        if stat.S_ISLNK(ancestor.st_mode) or _is_reparse(ancestor):
            raise OperationalOwnerError("mirror:operational-root")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return path


def _child_identity(path: Path, *, allow_missing: bool) -> tuple[int, int, int] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise OperationalOwnerError("mirror:operational-indeterminate") from None
    except OSError:
        raise OperationalOwnerError("mirror:operational-indeterminate") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or _is_reparse(info)
        or info.st_nlink != 1
    ):
        raise OperationalOwnerError("mirror:operational-indeterminate")
    for suffix in _SIDECARS:
        if os.path.lexists(os.fspath(path) + suffix):
            raise OperationalOwnerError("mirror:operational-indeterminate")
    return _identity(info)


def _layout(root: Path, *, allow_missing_stores: bool) -> dict[str, tuple[int, int, int] | None]:
    try:
        entries = {entry.name for entry in os.scandir(root)}
    except OSError:
        raise OperationalOwnerError("mirror:operational-indeterminate") from None
    if not entries.issubset(_EXPECTED_CHILDREN):
        raise OperationalOwnerError("mirror:operational-indeterminate")
    result: dict[str, tuple[int, int, int] | None] = {}
    for name in sorted(_EXPECTED_CHILDREN):
        result[name] = _child_identity(root / name, allow_missing=allow_missing_stores)
    return result


class _OwnerLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None
        self._locked = False
        before = _child_identity(path, allow_missing=True)
        try:
            flags = os.O_RDWR | os.O_CREAT
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags | nofollow, 0o600)
            self._descriptor = descriptor
            opened = os.fstat(descriptor)
            if before is not None and _identity(opened) != before:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            if opened.st_size == 0:
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
                opened = os.fstat(descriptor)
            if opened.st_size != 1 or _identity(opened)[2] != 1:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            final = _child_identity(path, allow_missing=False)
            if final != _identity(opened):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise OperationalOwnerError("mirror:operational-lock") from None
            else:
                import fcntl

                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise OperationalOwnerError("mirror:operational-lock") from None
            self._locked = True
            self.identity = final
        except OperationalOwnerError:
            self.close()
            raise
        except OSError:
            self.close()
            raise OperationalOwnerError("mirror:operational-lock") from None

    def assert_identity(self) -> None:
        if self._descriptor is None or not self._locked:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        current = _child_identity(self.path, allow_missing=False)
        if current != self.identity:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        try:
            opened = os.fstat(self._descriptor)
        except OSError:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        if _identity(opened) != self.identity:
            raise OperationalOwnerError("mirror:operational-indeterminate")

    def close(self) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        was_locked = self._locked
        self._locked = False
        if descriptor is None:
            return
        try:
            if was_locked and os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            elif was_locked and os.name != "nt":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(descriptor)
        except OSError:
            pass


def _port_value(port: object, *names: str) -> object:
    for name in names:
        try:
            value = getattr(port, name)
        except Exception:
            continue
        if value is not None:
            return value
    return None


def _admission_is_operational(error: BaseException) -> bool:
    try:
        value = str(error)
    except Exception:
        return True
    return (
        value.startswith("ingress:database")
        or value in {"ingress:busy", "ingress:capacity", "ingress:clock", "ingress:clock-rewind"}
    )


def _claim_is_operational(error: BaseException) -> bool:
    try:
        value = str(error)
    except Exception:
        return True
    return value in {
        "ingress:database-open",
        "ingress:database",
        "ingress:database-initialize",
        "ingress:busy",
        "ingress:capacity",
        "ingress:clock",
        "ingress:clock-rewind",
    }


class MirrorOperationalOwnerV1:
    """One locked, bounded owner for the three existing Mirror V2 services."""

    def __init__(
        self,
        root: str | Path,
        ingress_config: ingress.IngressConfigV2,
        core_config: core.CoreConfigV2,
        recovery_config: recovery.RecoveryConfigV2,
        acquisition_port: AcquisitionPort,
        custody: recovery.KeyCustodyPort,
        storage: recovery.RecoveryStoragePort,
        *,
        clock: Callable[[], int],
        operational_config: OperationalConfigV1,
    ) -> None:
        if not callable(clock):
            raise OperationalOwnerError("mirror:operational-config")
        if not isinstance(operational_config, OperationalConfigV1):
            raise OperationalOwnerError("mirror:operational-config")
        root_path = _safe_root(root)
        if not isinstance(ingress_config, ingress.IngressConfigV2) or not isinstance(core_config, core.CoreConfigV2) or not isinstance(recovery_config, recovery.RecoveryConfigV2):
            raise OperationalOwnerError("mirror:operational-config")
        if (
            core_config.ingress_database_id != ingress_config.database_id
            or core_config.ingress_chain_id != ingress_config.chain_id
            or core_config.ingress_config_digest != ingress_config.digest
            or core_config.runtime_profile_digest != ingress_config.source_contract_digest
            or recovery_config.ingress_database_id != ingress_config.database_id
            or recovery_config.core_database_id != core_config.database_id
            or recovery_config.ingress_config_digest != ingress_config.digest
            or recovery_config.core_config_digest != core_config.digest
            or operational_config.external_policy_digest != ingress_config.external_policy().digest
            or operational_config.profile_digest != ingress_config.source_contract_digest
        ):
            raise OperationalOwnerError("mirror:operational-config")
        if (
            _port_value(acquisition_port, "acquisition_identity", "identity", "port_id") != operational_config.acquisition_identity
            or _port_value(acquisition_port, "external_policy_digest", "policy_digest") != operational_config.external_policy_digest
            or _port_value(acquisition_port, "profile_digest", "source_profile_digest") != operational_config.profile_digest
            or not callable(getattr(acquisition_port, "acquire", None))
        ):
            raise OperationalOwnerError("mirror:operational-config")

        self.root = root_path
        self.ingress_path = root_path / "ingress.sqlite"
        self.core_path = root_path / "core.sqlite"
        self.recovery_path = root_path / "recovery.sqlite"
        self.lock_path = root_path / "operational.lock"
        self.ingress_config = ingress_config
        self.core_config = core_config
        self.recovery_config = recovery_config
        self.acquisition = acquisition_port
        self.custody = custody
        self.storage = storage
        self.clock = clock
        self.operational_config = operational_config
        self._closed = False
        self._lock: _OwnerLock | None = None
        self._root_identity: tuple[int, int, int] | None = None
        self.ingress: ingress.IngressServiceV2 | None = None
        self.core: core.CoreServiceV2 | None = None
        self.recovery: recovery.RecoveryServiceV2 | None = None
        try:
            _layout(root_path, allow_missing_stores=True)
            self._root_identity = _identity(os.lstat(root_path))
            self._lock = _OwnerLock(self.lock_path)
            _layout(root_path, allow_missing_stores=True)
            self.ingress = ingress.IngressServiceV2(self.ingress_path, ingress_config, clock=clock)
            self.core = core.CoreServiceV2(self.core_path, core_config, clock=clock)
            self.recovery = recovery.RecoveryServiceV2(self.recovery_path, recovery_config, custody, storage)
            self._store_identities = self._read_store_identities()
            self._assert_owner_identity()
        except OperationalOwnerError:
            self.close()
            raise
        except Exception:
            self.close()
            raise OperationalOwnerError("mirror:operational-initialize") from None

    def _read_store_identities(self) -> dict[str, tuple[int, int, int]]:
        result = _layout(self.root, allow_missing_stores=False)
        values: dict[str, tuple[int, int, int]] = {}
        for name in ("ingress.sqlite", "core.sqlite", "recovery.sqlite", "operational.lock"):
            value = result.get(name)
            if value is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            values[name] = value
        return values

    def _assert_port_identity(self) -> None:
        if (
            _port_value(self.acquisition, "acquisition_identity", "identity", "port_id") != self.operational_config.acquisition_identity
            or _port_value(self.acquisition, "external_policy_digest", "policy_digest") != self.operational_config.external_policy_digest
            or _port_value(self.acquisition, "profile_digest", "source_profile_digest") != self.operational_config.profile_digest
        ):
            raise OperationalOwnerError("mirror:operational-indeterminate")

    def _assert_owner_identity(self) -> None:
        if self._closed:
            raise OperationalOwnerError("mirror:operational-closed")
        try:
            try:
                _safe_root(self.root)
            except OperationalOwnerError:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            if self._lock is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._lock.assert_identity()
            current_root = os.lstat(self.root)
            if (
                self._root_identity is None
                or _identity(current_root) != self._root_identity
                or not stat.S_ISDIR(current_root.st_mode)
                or stat.S_ISLNK(current_root.st_mode)
                or _is_reparse(current_root)
            ):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            current = self._read_store_identities()
            if current != self._store_identities:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_port_identity()
        except OperationalOwnerError:
            raise
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None

    @staticmethod
    def _validate_schedule(values: tuple[int, ...], config: ingress.IngressConfigV2) -> None:
        if type(values) is not tuple or len(values) > 16 or len(set(values)) != len(values):
            raise OperationalOwnerError("mirror:operational-input")
        for value in values:
            if (
                type(value) is not int
                or not config.effective_start <= value <= config.effective_end
                or (value - config.effective_start) % config.cadence_seconds
            ):
                raise OperationalOwnerError("mirror:operational-input")

    def _process_slot(self, slot: ingress.EligibleSlotV1, counts: dict[str, int], admitted: list[str]) -> None:
        self._assert_owner_identity()
        assert self.ingress is not None
        try:
            lease_token = secrets.token_hex(32)
            receipt = self.ingress.claim_slot(slot.slot_id, lease_token=lease_token)
        except (ingress.IngressConflictError, ingress.IngressError) as error:
            if _claim_is_operational(error):
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            counts["claim_rejected"] += 1
            return
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        self._assert_owner_identity()
        counts["claimed"] += 1
        if receipt.next_state == "HELD":
            counts["held"] += 1
            counts["processed"] += 1
            return
        if receipt.next_state != "LEASED" or type(slot.attempt) is not int or slot.attempt < 0:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        attempt = slot.attempt + 1
        try:
            self._assert_port_identity()
            payload = self.acquisition.acquire(slot.slot_id, slot.scheduled_at, attempt)
        except Exception:
            self._assert_owner_identity()
            counts["acquisition_rejected"] += 1
            counts["processed"] += 1
            return
        if not isinstance(payload, AcquisitionPayloadV1):
            self._assert_owner_identity()
            counts["acquisition_rejected"] += 1
            counts["processed"] += 1
            return
        self._assert_owner_identity()
        try:
            admitted_receipt = self.ingress.admit_capture(
                payload.envelope_raw,
                evidence_raw=payload.external_evidence_raw,
                scheduled_at=slot.scheduled_at,
                attempt=attempt,
                lease_token=lease_token,
            )
        except (ingress.IngressConflictError, ingress.IngressError) as error:
            if _admission_is_operational(error):
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            self._assert_owner_identity()
            counts["admission_rejected"] += 1
            counts["processed"] += 1
            return
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        self._assert_owner_identity()
        if admitted_receipt.next_state != "QUARANTINED" or type(admitted_receipt.artifact_id) is not str or len(admitted_receipt.artifact_id) != 128 or any(char not in _HEX for char in admitted_receipt.artifact_id):
            counts["admission_rejected"] += 1
            counts["processed"] += 1
            return
        admitted.append(admitted_receipt.artifact_id)
        counts["admitted"] += 1
        counts["processed"] += 1

    def run(
        self,
        scheduled_at: tuple[int, ...] = (),
        *,
        recovery_generation: int | None = None,
    ) -> OperationalAggregateV1:
        """Process at most ``max_due`` slots and verify all three stores."""

        self._assert_owner_identity()
        self._validate_schedule(scheduled_at, self.ingress_config)
        if recovery_generation is not None and (
            type(recovery_generation) is not int
            or not 1 <= recovery_generation <= recovery_independent.MAX_RECOVERY_POINTS
        ):
            raise OperationalOwnerError("mirror:operational-input")
        assert self.ingress is not None and self.core is not None and self.recovery is not None
        counts = {key: 0 for key in OUTCOME_KEYS}
        admitted: list[str] = []
        try:
            first = self.ingress.eligible_slots(self.operational_config.max_due)
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        counts["eligible"] += len(first)
        for slot in first:
            self._process_slot(slot, counts, admitted)
        remaining = self.operational_config.max_due - len(first)
        self._assert_owner_identity()
        for value in scheduled_at:
            try:
                self.ingress.ensure_slot(value)
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            counts["scheduled"] += 1
        if remaining:
            try:
                second = self.ingress.eligible_slots(remaining)
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            counts["eligible"] += len(second)
            for slot in second:
                self._process_slot(slot, counts, admitted)
        if admitted:
            if len(set(admitted)) != len(admitted):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_owner_identity()
            try:
                self.core.ingest_sources(self.ingress_path, tuple(admitted))
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            counts["core_ingested"] = len(admitted)
        recovery_created = False
        if recovery_generation is not None:
            self._assert_owner_identity()
            try:
                self.recovery.create_point(self.ingress_path, self.core_path, generation=recovery_generation)
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            recovery_created = True
            counts["recovery_created"] = 1
        self._assert_owner_identity()
        try:
            ingress_result = ingress_independent.verify_database(
                self.ingress_path,
                expected_database_id=self.ingress_config.database_id,
                expected_config_digest=self.ingress_config.digest,
            )
            core_result = core_independent.verify_database(
                self.core_path,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
                ingress_path=self.ingress_path,
            )
            recovery_result = recovery_independent.verify_database(
                self.recovery_path,
                expected_database_id=self.recovery_config.database_id,
                expected_config_digest=self.recovery_config.digest,
            )
            if core_result.get("ingress_bound") is not True:
                raise ValueError("core-bound")
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        self._assert_owner_identity()
        try:
            return OperationalAggregateV1(
                schema=SCHEMA,
                schema_version=SCHEMA_VERSION,
                status=STATUS_COMPLETE,
                counts=MappingProxyType(dict(counts)),
                recovery_created=recovery_created,
                ingress_config_digest=self.ingress_config.digest,
                core_config_digest=self.core_config.digest,
                recovery_config_digest=self.recovery_config.digest,
                external_policy_digest=self.operational_config.external_policy_digest,
                profile_digest=self.operational_config.profile_digest,
                ingress_head_root=str(ingress_result["head_root"]),
                ingress_sequence=int(ingress_result["sequence"]),
                core_head_root=str(core_result["head_root"]),
                core_sequence=int(core_result["sequence"]),
                recovery_head_root=str(recovery_result["head_root"]),
                recovery_sequence=int(recovery_result["sequence"]),
            )
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for service in (self.ingress, self.core, self.recovery):
            close = getattr(service, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def __enter__(self) -> "MirrorOperationalOwnerV1":
        self._assert_owner_identity()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


OperationalOwnerV1 = MirrorOperationalOwnerV1
AcquisitionResultV1 = AcquisitionPayloadV1
MirrorOperationalOwner = MirrorOperationalOwnerV1
OperationalOwner = MirrorOperationalOwnerV1
OperationalConfig = OperationalConfigV1


__all__ = [
    "SCHEMA",
    "SCHEMA_VERSION",
    "STATUS_COMPLETE",
    "OUTCOME_KEYS",
    "OperationalOwnerError",
    "OperationalConfigV1",
    "AcquisitionPort",
    "AcquisitionPortV1",
    "AcquisitionPayloadV1",
    "AcquisitionPayload",
    "AcquisitionResultV1",
    "AcquisitionResult",
    "OperationalAggregateV1",
    "MirrorOperationalOwnerV1",
    "OperationalOwnerV1",
    "OperationalOwner",
    "MirrorOperationalOwner",
    "OperationalConfig",
]
