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
    "core_recovered",
    "core_ingested",
    "core_pending",
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
_MAX_OBSERVATION_BYTES = ingress_independent.MAX_OBSERVATION_BYTES
_MAX_VERIFICATION_RECEIPT_BYTES = ingress_independent.MAX_VERIFICATION_RECEIPT_BYTES


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
class SanitizedObservationPayloadV1:
    """Exactly the two bounded non-PHI bytes handed to Ingress admission."""

    observation: bytes
    verification_receipt: bytes

    def __post_init__(self) -> None:
        if (
            type(self.observation) is not bytes
            or type(self.verification_receipt) is not bytes
            or not self.observation
            or not self.verification_receipt
            or len(self.observation) > _MAX_OBSERVATION_BYTES
            or len(self.verification_receipt) > _MAX_VERIFICATION_RECEIPT_BYTES
        ):
            raise OperationalOwnerError("mirror:operational-acquisition")
        try:
            ingress_independent.verify_observation_pair(self.observation, self.verification_receipt)
        except Exception:
            raise OperationalOwnerError("mirror:operational-acquisition") from None


class AcquisitionPort(Protocol):
    acquisition_identity: str
    external_policy_digest: str
    profile_digest: str

    def acquire(self, slot_id: str, scheduled_at: int, attempt: int) -> SanitizedObservationPayloadV1: ...

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
    try:
        path = Path(root)
        raw = os.fspath(path)
    except (OSError, TypeError, ValueError, RuntimeError):
        raise OperationalOwnerError("mirror:operational-root") from None
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


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _WIN_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _WIN_GENERIC_READ = 0x80000000
    _WIN_GENERIC_WRITE = 0x40000000
    _WIN_FILE_SHARE_READ = 0x00000001
    _WIN_FILE_SHARE_WRITE = 0x00000002
    _WIN_OPEN_EXISTING = 3
    _WIN_CREATE_NEW = 1
    _WIN_FILE_ATTRIBUTE_NORMAL = 0x00000080
    _WIN_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _WIN_FILE_TYPE_DISK = 0x00000001
    _WIN_LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    _WIN_LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    _WIN_INVALID_HANDLE = ctypes.c_void_p(-1).value
    _WIN_ULONG_PTR = getattr(wintypes, "ULONG_PTR", ctypes.c_size_t)

    class _WinFileTime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class _WinFileInfo(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _WinFileTime),
            ("ftLastAccessTime", _WinFileTime),
            ("ftLastWriteTime", _WinFileTime),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _WinOverlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", _WIN_ULONG_PTR),
            ("InternalHigh", _WIN_ULONG_PTR),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    _WIN_CreateFileW = _WIN_KERNEL32.CreateFileW
    _WIN_CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _WIN_CreateFileW.restype = wintypes.HANDLE
    _WIN_GetFileInformationByHandle = _WIN_KERNEL32.GetFileInformationByHandle
    _WIN_GetFileInformationByHandle.argtypes = (wintypes.HANDLE, ctypes.POINTER(_WinFileInfo))
    _WIN_GetFileInformationByHandle.restype = wintypes.BOOL
    _WIN_GetFileType = _WIN_KERNEL32.GetFileType
    _WIN_GetFileType.argtypes = (wintypes.HANDLE,)
    _WIN_GetFileType.restype = wintypes.DWORD
    _WIN_CloseHandle = _WIN_KERNEL32.CloseHandle
    _WIN_CloseHandle.argtypes = (wintypes.HANDLE,)
    _WIN_CloseHandle.restype = wintypes.BOOL
    _WIN_LockFileEx = _WIN_KERNEL32.LockFileEx
    _WIN_LockFileEx.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_WinOverlapped),
    )
    _WIN_LockFileEx.restype = wintypes.BOOL
    _WIN_UnlockFileEx = _WIN_KERNEL32.UnlockFileEx
    _WIN_UnlockFileEx.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_WinOverlapped),
    )
    _WIN_UnlockFileEx.restype = wintypes.BOOL

    def _win_handle_value(handle: object) -> int | None:
        return ctypes.cast(handle, ctypes.c_void_p).value

    def _win_close(handle: object | None) -> None:
        if handle is not None and _win_handle_value(handle) not in {None, _WIN_INVALID_HANDLE}:
            _WIN_CloseHandle(handle)

    def _win_open(path: Path, *, access: int, disposition: int, directory: bool = False) -> object:
        flags = _WIN_FILE_FLAG_OPEN_REPARSE_POINT
        if directory:
            flags |= _WIN_FILE_FLAG_BACKUP_SEMANTICS
        handle = _WIN_CreateFileW(
            str(path),
            access,
            _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE,
            None,
            disposition,
            flags | (_WIN_FILE_ATTRIBUTE_NORMAL if not directory else 0),
            None,
        )
        if _win_handle_value(handle) in {None, _WIN_INVALID_HANDLE}:
            error = ctypes.get_last_error()
            raise OSError(error, "CreateFileW")
        return handle

    def _win_info(handle: object) -> tuple[int, int, int, int, int]:
        info = _WinFileInfo()
        if not _WIN_GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.get_last_error()
            raise OSError(error, "GetFileInformationByHandle")
        size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
        index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
        return (
            int(info.dwVolumeSerialNumber),
            index,
            int(info.nNumberOfLinks),
            size,
            int(info.dwFileAttributes),
        )

    def _win_lock(handle: object) -> _WinOverlapped:
        overlapped = _WinOverlapped()
        if not _WIN_LockFileEx(
            handle,
            _WIN_LOCKFILE_EXCLUSIVE_LOCK | _WIN_LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            ctypes.byref(overlapped),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "LockFileEx")
        return overlapped

    def _win_unlock(handle: object, overlapped: _WinOverlapped | None) -> None:
        if overlapped is not None:
            _WIN_UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped))


class _OwnerLock:
    def __init__(self, root: Path, path: Path) -> None:
        self.root = root
        self.path = path
        self._descriptor: int | None = None
        self._root_descriptor: int | None = None
        self._handle: object | None = None
        self._root_handle: object | None = None
        self._overlapped = None
        self._root_locked = False
        self._locked = False
        try:
            if os.name == "nt":
                self._init_windows()
            else:
                self._init_posix()
            self._locked = True
        except OperationalOwnerError:
            self.close()
            raise
        except OSError:
            self.close()
            raise OperationalOwnerError("mirror:operational-lock") from None
        except Exception:
            self.close()
            raise OperationalOwnerError("mirror:operational-lock") from None

    def _init_posix(self) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        root_before = _identity(os.lstat(self.root))
        root_descriptor = os.open(self.root, os.O_RDONLY | directory | nofollow)
        self._root_descriptor = root_descriptor
        root_info = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_info.st_mode) or _is_reparse(root_info) or _identity(root_info) != root_before:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        current_root = os.lstat(self.root)
        if _identity(current_root) != root_before:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        import fcntl

        try:
            fcntl.flock(root_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise OperationalOwnerError("mirror:operational-lock") from None
        self._root_locked = True
        if _identity(os.lstat(self.root)) != root_before:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        self.root_identity = root_before
        name = self.path.name
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
                0o600,
                dir_fd=root_descriptor,
            )
        except FileExistsError:
            descriptor = os.open(name, os.O_RDWR | nofollow, dir_fd=root_descriptor)
        self._descriptor = descriptor
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse(opened) or opened.st_nlink != 1 or opened.st_size > 1:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        relative = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(relative.st_mode)
            or _is_reparse(relative)
            or relative.st_nlink != 1
            or _identity(relative) != _identity(opened)
        ):
            raise OperationalOwnerError("mirror:operational-indeterminate")
        final = _child_identity(self.path, allow_missing=False)
        if final != _identity(opened):
            raise OperationalOwnerError("mirror:operational-indeterminate")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise OperationalOwnerError("mirror:operational-lock") from None
        self.identity = final

    def _init_windows(self) -> None:
        root_before = _identity(os.lstat(self.root))
        root_handle = _win_open(self.root, access=_WIN_GENERIC_READ, disposition=_WIN_OPEN_EXISTING, directory=True)
        self._root_handle = root_handle
        root_info = _win_info(root_handle)
        if (
            not root_info[4] & _WIN_FILE_ATTRIBUTE_DIRECTORY
            or root_info[4] & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
            or _WIN_GetFileType(root_handle) != _WIN_FILE_TYPE_DISK
        ):
            raise OperationalOwnerError("mirror:operational-indeterminate")
        current_root = os.lstat(self.root)
        if _identity(current_root) != root_before:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        existing = _child_identity(self.path, allow_missing=True)
        disposition = _WIN_OPEN_EXISTING if existing is not None else _WIN_CREATE_NEW
        handle = _win_open(
            self.path,
            access=_WIN_GENERIC_READ | _WIN_GENERIC_WRITE,
            disposition=disposition,
        )
        self._handle = handle
        opened = _win_info(handle)
        if (
            _WIN_GetFileType(handle) != _WIN_FILE_TYPE_DISK
            or opened[4] & (_WIN_FILE_ATTRIBUTE_DIRECTORY | _WIN_FILE_ATTRIBUTE_REPARSE_POINT)
            or opened[2] != 1
            or opened[3] > 1
        ):
            raise OperationalOwnerError("mirror:operational-indeterminate")
        probe = _win_open(self.path, access=_WIN_GENERIC_READ, disposition=_WIN_OPEN_EXISTING)
        try:
            probed = _win_info(probe)
        finally:
            _win_close(probe)
        if opened[:3] != probed[:3]:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        final = _child_identity(self.path, allow_missing=False)
        if final is None or final[2] != 1:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        self.identity = final
        self._overlapped = _win_lock(handle)
        if _identity(os.lstat(self.root)) != root_before:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        self.root_identity = root_before

    def assert_identity(self) -> None:
        if not self._locked:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        if os.name == "nt":
            if self._handle is None or self._root_handle is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
        elif self._descriptor is None or self._root_descriptor is None:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        current_root = os.lstat(self.root)
        if _identity(current_root) != self.root_identity:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        current = _child_identity(self.path, allow_missing=False)
        if current != self.identity:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        if os.name == "nt":
            root_info = _win_info(self._root_handle)
            handle_info = _win_info(self._handle)
            if (
                root_info[1] != int(current_root.st_ino)
                or root_info[2] != int(current_root.st_nlink)
                or handle_info[0] != root_info[0]
                or handle_info[1] != current[1]
                or handle_info[2] != current[2]
                or root_info[4] & (_WIN_FILE_ATTRIBUTE_REPARSE_POINT | _WIN_FILE_ATTRIBUTE_DIRECTORY) != _WIN_FILE_ATTRIBUTE_DIRECTORY
                or handle_info[4] & (_WIN_FILE_ATTRIBUTE_DIRECTORY | _WIN_FILE_ATTRIBUTE_REPARSE_POINT)
                or handle_info[2] != 1
                or handle_info[3] > 1
            ):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            return
        try:
            root_info = os.fstat(self._root_descriptor)
            opened = os.fstat(self._descriptor)
        except OSError:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        if _identity(root_info) != self.root_identity or _identity(opened) != self.identity:
            raise OperationalOwnerError("mirror:operational-indeterminate")

    def close(self) -> None:
        descriptor = self._descriptor
        root_descriptor = self._root_descriptor
        handle = self._handle
        root_handle = self._root_handle
        self._descriptor = None
        self._root_descriptor = None
        self._handle = None
        self._root_handle = None
        was_locked = self._locked
        self._locked = False
        if os.name == "nt":
            if was_locked and handle is not None:
                _win_unlock(handle, self._overlapped)
            _win_close(handle)
            _win_close(root_handle)
            self._overlapped = None
            return
        try:
            if descriptor is not None:
                os.close(descriptor)
        except OSError:
            pass
        try:
            if was_locked and root_descriptor is not None and self._root_locked:
                import fcntl

                fcntl.flock(root_descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            if root_descriptor is not None:
                os.close(root_descriptor)
        except OSError:
            pass
        self._root_locked = False


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
        if type(operational_config) is not OperationalConfigV1:
            raise OperationalOwnerError("mirror:operational-config")
        root_path = _safe_root(root)
        if type(ingress_config) is not ingress.IngressConfigV2 or type(core_config) is not core.CoreConfigV2 or type(recovery_config) is not recovery.RecoveryConfigV2:
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
            or operational_config.profile_digest != ingress_config.source_contract_digest
        ):
            raise OperationalOwnerError("mirror:operational-config")
        try:
            acquisition_identity = getattr(acquisition_port, "acquisition_identity")
            external_policy_digest = getattr(acquisition_port, "external_policy_digest")
            profile_digest = getattr(acquisition_port, "profile_digest")
            custody_id = getattr(custody, "custody_id")
            storage_id = getattr(storage, "storage_id")
            acquire = getattr(acquisition_port, "acquire")
        except Exception:
            raise OperationalOwnerError("mirror:operational-config") from None
        if (
            type(acquisition_identity) is not str
            or acquisition_identity != operational_config.acquisition_identity
            or type(external_policy_digest) is not str
            or external_policy_digest != operational_config.external_policy_digest
            or type(profile_digest) is not str
            or profile_digest != operational_config.profile_digest
            or type(custody_id) is not str
            or custody_id != recovery_config.custody_id
            or type(storage_id) is not str
            or storage_id != recovery_config.storage_id
            or not callable(acquire)
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
            initial_layout = _layout(root_path, allow_missing_stores=True)
            self._lock = _OwnerLock(root_path, self.lock_path)
            self._root_identity = self._lock.root_identity
            locked_layout = _layout(root_path, allow_missing_stores=True)
            self._assert_layout_transition(initial_layout, locked_layout)
            self._assert_root_lock_identity()
            before_ingress = _layout(root_path, allow_missing_stores=True)
            self._assert_root_lock_identity()
            self.ingress = ingress.IngressServiceV2(self.ingress_path, ingress_config, clock=clock)
            after_ingress = _layout(root_path, allow_missing_stores=True)
            self._assert_layout_transition(before_ingress, after_ingress)
            if after_ingress["ingress.sqlite"] is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_root_lock_identity()
            before_core = _layout(root_path, allow_missing_stores=True)
            self._assert_root_lock_identity()
            self.core = core.CoreServiceV2(self.core_path, core_config, clock=clock)
            after_core = _layout(root_path, allow_missing_stores=True)
            self._assert_layout_transition(before_core, after_core)
            if after_core["core.sqlite"] is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_root_lock_identity()
            before_recovery = _layout(root_path, allow_missing_stores=True)
            self._assert_root_lock_identity()
            self.recovery = recovery.RecoveryServiceV2(self.recovery_path, recovery_config, custody, storage)
            after_recovery = _layout(root_path, allow_missing_stores=True)
            self._assert_layout_transition(before_recovery, after_recovery)
            if after_recovery["recovery.sqlite"] is None:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            self._assert_root_lock_identity()
            self._store_identities = self._read_store_identities()
            self._assert_owner_identity()
        except OperationalOwnerError:
            self.close()
            raise
        except (ingress.IngressError, core.CoreError, recovery.RecoveryError):
            self.close()
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
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

    @staticmethod
    def _assert_layout_transition(
        before: Mapping[str, tuple[int, int, int] | None],
        after: Mapping[str, tuple[int, int, int] | None],
    ) -> None:
        for name in _EXPECTED_CHILDREN:
            if before.get(name) is not None and after.get(name) != before[name]:
                raise OperationalOwnerError("mirror:operational-indeterminate")

    def _assert_root_lock_identity(self) -> None:
        if self._closed or self._lock is None or self._root_identity is None:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        try:
            _safe_root(self.root)
            self._lock.assert_identity()
            current_root = os.lstat(self.root)
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        if _identity(current_root) != self._root_identity or not stat.S_ISDIR(current_root.st_mode) or _is_reparse(current_root):
            raise OperationalOwnerError("mirror:operational-indeterminate")

    def _assert_port_identity(self) -> None:
        try:
            acquisition_identity = getattr(self.acquisition, "acquisition_identity")
            external_policy_digest = getattr(self.acquisition, "external_policy_digest")
            profile_digest = getattr(self.acquisition, "profile_digest")
            custody_id = getattr(self.custody, "custody_id")
            storage_id = getattr(self.storage, "storage_id")
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        if (
            type(acquisition_identity) is not str
            or acquisition_identity != self.operational_config.acquisition_identity
            or type(external_policy_digest) is not str
            or external_policy_digest != self.operational_config.external_policy_digest
            or type(profile_digest) is not str
            or profile_digest != self.operational_config.profile_digest
            or type(custody_id) is not str
            or custody_id != self.recovery_config.custody_id
            or type(storage_id) is not str
            or storage_id != self.recovery_config.storage_id
        ):
            raise OperationalOwnerError("mirror:operational-indeterminate")

    def _assert_owner_identity(self) -> None:
        if self._closed:
            raise OperationalOwnerError("mirror:operational-closed")
        try:
            self._assert_root_lock_identity()
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
        if type(values) is not tuple or len(values) > 16:
            raise OperationalOwnerError("mirror:operational-input")
        for value in values:
            if (
                type(value) is not int
                or not config.effective_start <= value <= config.effective_end
                or (value - config.effective_start) % config.cadence_seconds
            ):
                raise OperationalOwnerError("mirror:operational-input")
        if len(set(values)) != len(values):
            raise OperationalOwnerError("mirror:operational-input")

    def _validate_eligible(self, values: object, limit: int) -> tuple[ingress.EligibleSlotV1, ...]:
        if type(values) is not tuple or len(values) > limit:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        seen: set[str] = set()
        for slot in values:
            if type(slot) is not ingress.EligibleSlotV1:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            if (
                type(slot.slot_id) is not str
                or len(slot.slot_id) != 128
                or any(char not in _HEX for char in slot.slot_id)
                or slot.slot_id in seen
                or type(slot.scheduled_at) is not int
                or not self.ingress_config.effective_start <= slot.scheduled_at <= self.ingress_config.effective_end
                or (slot.scheduled_at - self.ingress_config.effective_start) % self.ingress_config.cadence_seconds
                or type(slot.attempt) is not int
                or not 0 <= slot.attempt <= self.ingress_config.max_attempts
                or type(slot.state) is not str
                or slot.state not in {"DUE", "LEASED"}
            ):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            seen.add(slot.slot_id)
        return values

    @staticmethod
    def _validate_projection(values: object, limit: int) -> tuple[str, ...]:
        if type(values) is not tuple or len(values) > limit:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        seen: set[str] = set()
        for value in values:
            if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value) or value in seen:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            seen.add(value)
        return values

    def _reconciliation_pending(self) -> tuple[str, ...]:
        assert self.ingress is not None and self.core is not None
        try:
            self._assert_owner_identity()
            ingress_result = ingress_independent.verify_database(
                self.ingress_path,
                expected_database_id=self.ingress_config.database_id,
                expected_config_digest=self.ingress_config.digest,
            )
            self._assert_owner_identity()
            core_result = core_independent.verify_database(
                self.core_path,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
                ingress_path=self.ingress_path,
            )
            self._assert_owner_identity()
            if ingress_result.get("database_id") != self.ingress_config.database_id or core_result.get("ingress_bound") is not True:
                raise ValueError("mirror:reconciliation-binding")
            quarantined = self.ingress._operational_quarantined_artifact_ids(self.ingress_config.max_slots)
            self._assert_owner_identity()
            represented = self.core._operational_represented_ingress_artifact_ids(self.ingress_config.max_slots)
            self._assert_owner_identity()
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        quarantined = self._validate_projection(quarantined, self.ingress_config.max_slots)
        represented = self._validate_projection(represented, self.ingress_config.max_slots)
        quarantined_set = set(quarantined)
        represented_set = set(represented)
        if not represented_set.issubset(quarantined_set):
            raise OperationalOwnerError("mirror:operational-indeterminate")
        if tuple(value for value in quarantined if value in represented_set) != represented:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        return tuple(value for value in quarantined if value not in represented_set)

    def _verified_recovery_point_count(self) -> int:
        """Read the recovery count from one independently verified snapshot."""

        self._assert_owner_identity()
        try:
            result = recovery_independent.verify_database(
                self.recovery_path,
                expected_database_id=self.recovery_config.database_id,
                expected_config_digest=self.recovery_config.digest,
            )
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        self._assert_owner_identity()
        count = result.get("point_count")
        if type(count) is not int or count < 0 or count > recovery_independent.MAX_RECOVERY_POINTS:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        return count

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
        if type(receipt) is not ingress.IngressReceipt or type(receipt.next_state) is not str:
            raise OperationalOwnerError("mirror:operational-indeterminate")
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
        if type(payload) is not SanitizedObservationPayloadV1:
            self._assert_owner_identity()
            counts["acquisition_rejected"] += 1
            counts["processed"] += 1
            return
        self._assert_owner_identity()
        try:
            admitted_receipt = self.ingress.admit_observation(
                payload.observation,
                payload.verification_receipt,
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
        if type(admitted_receipt) is not ingress.IngressReceipt:
            raise OperationalOwnerError("mirror:operational-indeterminate")
        if type(admitted_receipt.next_state) is not str or admitted_receipt.next_state != "QUARANTINED" or type(admitted_receipt.artifact_id) is not str or len(admitted_receipt.artifact_id) != 128 or any(char not in _HEX for char in admitted_receipt.artifact_id):
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
        pending = self._reconciliation_pending()
        budget = self.operational_config.max_due
        recovered = pending[:budget]
        if recovered:
            self._assert_owner_identity()
            try:
                self.core.ingest_sources(self.ingress_path, tuple(recovered))
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            self._assert_owner_identity()
            if set(recovered).intersection(self._reconciliation_pending()):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            counts["core_recovered"] = len(recovered)
            budget -= len(recovered)
        try:
            first = self.ingress.eligible_slots(budget) if budget else ()
        except Exception:
            raise OperationalOwnerError("mirror:operational-indeterminate") from None
        first = self._validate_eligible(first, budget) if budget else ()
        counts["eligible"] += len(first)
        for slot in first:
            self._process_slot(slot, counts, admitted)
        remaining = budget - len(first)
        self._assert_owner_identity()
        for value in scheduled_at:
            try:
                self._assert_owner_identity()
                self.ingress.ensure_slot(value)
                self._assert_owner_identity()
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            counts["scheduled"] += 1
        if remaining:
            try:
                second = self.ingress.eligible_slots(remaining)
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            second = self._validate_eligible(second, remaining)
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
            self._assert_owner_identity()
            if set(admitted).intersection(self._reconciliation_pending()):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            counts["core_ingested"] = len(admitted)
        recovery_created = False
        if recovery_generation is not None:
            self._assert_owner_identity()
            try:
                self._assert_port_identity()
                before_points = self._verified_recovery_point_count()
                receipt = self.recovery.create_point(self.ingress_path, self.core_path, generation=recovery_generation)
            except Exception:
                raise OperationalOwnerError("mirror:operational-indeterminate") from None
            self._assert_owner_identity()
            after_points = self._verified_recovery_point_count()
            point_delta = after_points - before_points
            if point_delta not in (0, 1):
                raise OperationalOwnerError("mirror:operational-indeterminate")
            if type(receipt) is not recovery.RecoveryReceipt or type(receipt.state) is not str or receipt.state not in {"VERIFIED", "PUBLISHED"}:
                raise OperationalOwnerError("mirror:operational-indeterminate")
            recovery_created = point_delta == 1
            counts["recovery_created"] = point_delta
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
        final_pending = self._reconciliation_pending()
        counts["core_pending"] = len(final_pending)
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


__all__ = [
    "SCHEMA",
    "SCHEMA_VERSION",
    "STATUS_COMPLETE",
    "OUTCOME_KEYS",
    "OperationalOwnerError",
    "OperationalConfigV1",
    "AcquisitionPort",
    "SanitizedObservationPayloadV1",
    "OperationalAggregateV1",
    "MirrorOperationalOwnerV1",
]
