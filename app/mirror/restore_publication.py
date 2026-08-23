"""One create-only, marker-owned publication owner for Mirror SQLite images.

Component modules own schemas, exports, and independent semantic verification.
This module owns only the filesystem boundary.  A closed and independently
verified stage is published with an atomic same-filesystem hard link; an
existing target is accepted only after one non-mutating independent semantic
verification.  Recovery begins only after the ownership marker is durable.
The parent-directory durability assumption remains external to this software
contract.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Callable, Mapping, Sequence, TypeVar

from app.mirror.error_boundary import raise_redacted


MAX_IMAGE_BYTES = 128 * 1024 * 1024
MAX_MARKER_BYTES = 4096
MAX_PARENT_ENTRIES = 4096
MAX_NAMESPACE_ENTRIES = 16
LOCK_ATTEMPTS = 40
LOCK_SLEEP_SECONDS = 0.025
STAGING_SCHEMA = "mirror-restore-publication-stage-v2"
STAGING_VERSION = 2
WORKSPACE_SCHEMA = "mirror-restore-workspace-v1"
WORKSPACE_VERSION = 1
MAX_WORKSPACE_CHILDREN = 8
MAX_WORKSPACE_RECEIPT_BYTES = 8192
PUBLICATION_RECEIPT_NAME = "publication.json"
MAX_PUBLICATION_RECEIPT_BYTES = 8192


class RestorePublicationError(ValueError):
    """A bounded create-only restore publication failure."""


class RestorePublicationConflict(RestorePublicationError):
    """The destination already contains different or unverifiable state."""


class RestorePublicationVerification(RestorePublicationError):
    """The staged or published database failed its independent check."""


class RestorePublicationCleanupError(RestorePublicationError):
    """An owned staging artifact could not be removed safely."""


T = TypeVar("T")


@dataclass(frozen=True)
class VerifiedRestoreImageV1:
    """Opaque semantic/file identity passed between verification and publish."""

    semantic_digest: str
    byte_length: int
    file_digest: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:noncanonical")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/RESTORE-PUBLICATION-V2/" + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _regular_identity(path: Path, *, allow_empty: bool = False, expected_links: int = 1) -> tuple[int, int, int, int, int]:
    try:
        value = os.lstat(os.fspath(path))
    except OSError as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:file-stat")
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != expected_links:
        raise RestorePublicationVerification("restore-publication:file-ownership")
    size = int(value.st_size)
    if size < 0 or (size == 0 and not allow_empty) or size > MAX_IMAGE_BYTES:
        raise RestorePublicationVerification("restore-publication:file-cap")
    return int(value.st_dev), int(value.st_ino), int(value.st_nlink), size, int(value.st_mtime_ns)


def _delete_exact_object(
    path: Path,
    *,
    expected_identity: tuple[int, ...] | None,
    kind: str,
    expected_inode: tuple[int, int] | None = None,
    expected_bytes: bytes | None = None,
    allow_empty: bool = True,
    label: str = "cleanup",
) -> None:
    """Delete one previously-bound file or directory through its handle.

    The pathname is used only to acquire the object.  The identity is checked
    on the opened descriptor and the disposition is then applied to that same
    native handle.  There is deliberately no pathname-unlink/rmdir fallback.
    """

    try:
        present = os.path.lexists(os.fspath(path))
    except Exception:
        raise_redacted(RestorePublicationCleanupError, f"restore-publication:{label}")
    if not present:
        if expected_identity is not None or expected_inode is not None or expected_bytes is not None:
            raise_redacted(RestorePublicationCleanupError, f"restore-publication:{label}")
        return
    if kind not in {"file", "directory"}:
        raise RestorePublicationCleanupError(f"restore-publication:{label}")
    try:
        preliminary = os.lstat(os.fspath(path))
    except OSError:
        raise_redacted(RestorePublicationCleanupError, f"restore-publication:{label}")
    is_directory = stat.S_ISDIR(preliminary.st_mode) and not stat.S_ISLNK(preliminary.st_mode)
    if (kind == "directory") != is_directory or (kind == "file" and not stat.S_ISREG(preliminary.st_mode)):
        raise RestorePublicationCleanupError(f"restore-publication:{label}")
    if os.name != "nt":
        raise RestorePublicationCleanupError("restore-publication:exact-delete-unsupported")

    import ctypes
    from ctypes import wintypes
    import msvcrt

    GENERIC_READ = 0x80000000
    DELETE = 0x00010000
    FILE_READ_ATTRIBUTES = 0x00000080
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_DISPOSITION_INFO = 4
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD]
    set_information.restype = wintypes.BOOL
    flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
    if kind == "directory":
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    handle = create_file(
        os.fspath(path),
        DELETE | FILE_READ_ATTRIBUTES | (GENERIC_READ if kind == "file" else 0),
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        flags,
        None,
    )
    invalid = ctypes.cast(handle, ctypes.c_void_p).value in (None, ctypes.c_void_p(-1).value)
    if invalid:
        raise RestorePublicationCleanupError(f"restore-publication:{label}")
    descriptor = -1
    try:
        descriptor = msvcrt.open_osfhandle(int(ctypes.cast(handle, ctypes.c_void_p).value), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        handle = None
        actual_stat = os.fstat(descriptor)
        actual = (
            int(actual_stat.st_dev), int(actual_stat.st_ino), int(actual_stat.st_nlink),
            int(actual_stat.st_size), int(actual_stat.st_mtime_ns),
        )
        if kind == "directory":
            if not stat.S_ISDIR(actual_stat.st_mode) or stat.S_ISLNK(actual_stat.st_mode):
                raise RestorePublicationCleanupError(f"restore-publication:{label}")
            if expected_identity is not None and actual[:2] != expected_identity[:2]:
                raise RestorePublicationCleanupError(f"restore-publication:{label}")
        else:
            if not stat.S_ISREG(actual_stat.st_mode) or actual[3] < 0 or (actual[3] == 0 and not allow_empty) or actual[3] > MAX_IMAGE_BYTES:
                raise RestorePublicationCleanupError(f"restore-publication:{label}")
            if expected_identity is not None and actual != expected_identity:
                raise RestorePublicationCleanupError(f"restore-publication:{label}")
            if expected_inode is not None and actual[:2] != expected_inode:
                raise RestorePublicationCleanupError(f"restore-publication:{label}")
            if expected_bytes is not None:
                os.lseek(descriptor, 0, os.SEEK_SET)
                observed = os.read(descriptor, len(expected_bytes) + 1)
                if observed != expected_bytes:
                    raise RestorePublicationCleanupError(f"restore-publication:{label}")

        class _Disposition(ctypes.Structure):
            _fields_ = [("DeleteFile", wintypes.BOOL)]

        disposition = _Disposition(1)
        native_handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
        if not set_information(native_handle, FILE_DISPOSITION_INFO, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise RestorePublicationCleanupError(f"restore-publication:{label}")
    except RestorePublicationError:
        raise
    except Exception:
        raise_redacted(RestorePublicationCleanupError, f"restore-publication:{label}")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except Exception:
                raise_redacted(RestorePublicationCleanupError, f"restore-publication:{label}")
        elif handle not in (None, 0):
            try:
                kernel32.CloseHandle(handle)
            except Exception:
                raise_redacted(RestorePublicationCleanupError, f"restore-publication:{label}")


def _delete_exact_file(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int, int] | None = None,
    expected_inode: tuple[int, int] | None = None,
    expected_bytes: bytes | None = None,
    allow_empty: bool = True,
    label: str = "cleanup",
) -> None:
    _delete_exact_object(
        path,
        expected_identity=expected_identity,
        expected_inode=expected_inode,
        expected_bytes=expected_bytes,
        allow_empty=allow_empty,
        kind="file",
        label=label,
    )


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        value = os.lstat(os.fspath(path))
    except Exception:
        raise_redacted(RestorePublicationCleanupError, "restore-publication:directory-stat")
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
        raise RestorePublicationCleanupError("restore-publication:directory-ownership")
    return int(value.st_dev), int(value.st_ino)


def _delete_exact_directory(path: Path, *, expected_identity: tuple[int, int], label: str) -> None:
    _delete_exact_object(path, expected_identity=expected_identity, kind="directory", label=label)


def _file_identity(path: Path, *, allow_empty: bool = False, expected_links: int = 1) -> tuple[int, str]:
    before = _regular_identity(path, allow_empty=allow_empty, expected_links=expected_links)
    digest = hashlib.sha3_512()
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        opened = os.fstat(descriptor)
        if (int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink), int(opened.st_size), int(opened.st_mtime_ns)) != before:
            raise RestorePublicationVerification("restore-publication:file-changed")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            remaining = before[3]
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise RestorePublicationVerification("restore-publication:file-short-read")
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                raise RestorePublicationVerification("restore-publication:file-changed")
            closed = os.fstat(stream.fileno())
            if (int(closed.st_dev), int(closed.st_ino), int(closed.st_nlink), int(closed.st_size), int(closed.st_mtime_ns)) != before:
                raise RestorePublicationVerification("restore-publication:file-changed")
    except RestorePublicationError:
        raise
    except OSError as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:file-read")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except Exception:
                raise_redacted(RestorePublicationVerification, "restore-publication:file-read")
    if _regular_identity(path, allow_empty=allow_empty, expected_links=expected_links) != before:
        raise RestorePublicationVerification("restore-publication:file-changed")
    return before[3], digest.hexdigest()


def _read_owned_bytes(path: Path, *, cap: int, label: str) -> tuple[bytes, tuple[int, int, int, int, int]]:
    """Read a small owned regular file without trusting its pathname."""

    descriptor = -1
    try:
        before = _regular_identity(path)
        if before[3] > cap:
            raise RestorePublicationVerification(f"restore-publication:{label}")
        descriptor = os.open(os.fspath(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        opened = os.fstat(descriptor)
        if (int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink), int(opened.st_size), int(opened.st_mtime_ns)) != before:
            raise RestorePublicationVerification(f"restore-publication:{label}")
        raw = os.read(descriptor, cap + 1)
        closed = os.fstat(descriptor)
        if (int(closed.st_dev), int(closed.st_ino), int(closed.st_nlink), int(closed.st_size), int(closed.st_mtime_ns)) != before:
            raise RestorePublicationVerification(f"restore-publication:{label}")
    except RestorePublicationError:
        raise
    except OSError:
        raise_redacted(RestorePublicationVerification, f"restore-publication:{label}")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except Exception:
                raise_redacted(RestorePublicationVerification, f"restore-publication:{label}")
    if len(raw) != before[3] or len(raw) > cap or _regular_identity(path) != before:
        raise RestorePublicationVerification(f"restore-publication:{label}")
    return raw, before


def _read_owned_marker(path: Path, *, label: str) -> bytes:
    raw, _identity = _read_owned_bytes(path, cap=MAX_MARKER_BYTES, label=label)
    return raw


def _target(path: str | Path) -> Path:
    try:
        value = os.fspath(path)
    except Exception as exc:
        raise_redacted(RestorePublicationError, "restore-publication:target")
    if isinstance(value, bytes) or not value:
        raise RestorePublicationError("restore-publication:target")
    target = Path(os.path.abspath(value))
    if target.name in ("", ".", "..") or not target.parent.is_dir() or target.parent.is_symlink() or target.is_symlink():
        raise RestorePublicationError("restore-publication:target")
    return target


def _target_identity(target: Path) -> str:
    material = os.path.normcase(os.path.abspath(os.fspath(target))).encode("utf-8", "surrogatepass")
    return hashlib.sha3_512(material).hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 128 or any(ch not in "0123456789abcdef" for ch in value):
        raise RestorePublicationVerification(f"restore-publication:{label}")
    return value


def _semantic_projection(value: Mapping[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if key not in {"snapshot", "export_root", "export_bytes"}}


def _semantic_digest(value: Mapping[str, object]) -> str:
    def safe(item: object) -> object:
        if isinstance(item, bytes):
            return {"byte_length": len(item), "byte_digest": hashlib.sha3_512(item).hexdigest()}
        if isinstance(item, Mapping):
            return {str(key): safe(value) for key, value in item.items()}
        if isinstance(item, (list, tuple)):
            return [safe(value) for value in item]
        return item

    return _digest("semantic", safe(_semantic_projection(value)))


def _verified_image(
    path: Path,
    verify_database: Callable[[Path], object],
    *,
    expected_links: int = 1,
) -> tuple[VerifiedRestoreImageV1, Mapping[str, object]]:
    try:
        evidence = verify_database(path)
    except RestorePublicationError:
        raise
    except Exception as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:database")
    if not isinstance(evidence, Mapping):
        raise RestorePublicationVerification("restore-publication:evidence")
    size, file_digest = _file_identity(path, expected_links=expected_links)
    return VerifiedRestoreImageV1(_semantic_digest(evidence), size, file_digest), evidence


def _expected_semantic(expected_evidence: Mapping[str, object] | None) -> str | None:
    if expected_evidence is None:
        return None
    return _semantic_digest(expected_evidence)


def _sidecar(path: Path, suffix: str) -> Path:
    return Path(str(path) + suffix)


def _storage_file_identity(path: Path, *, allow_empty: bool = False) -> tuple[tuple[int, int, int, int, int], str]:
    regular = _regular_identity(path, allow_empty=allow_empty)
    size, digest = _file_identity(path, allow_empty=allow_empty)
    if size != regular[3] or _regular_identity(path, allow_empty=allow_empty) != regular:
        raise RestorePublicationVerification("restore-publication:file-changed")
    return regular, digest


def _existing_storage_shape(
    path: Path,
) -> tuple[tuple[int, int, int, int, int], tuple[int, int, int, int, int] | None, tuple[int, int, int, int, int] | None]:
    """Capture only race-detection identities before semantic verification."""

    sidecar_shapes: list[tuple[int, int, int, int, int] | None] = []
    for suffix in ("-wal", "-shm"):
        sidecar = _sidecar(path, suffix)
        if not os.path.lexists(os.fspath(sidecar)):
            sidecar_shapes.append(None)
            continue
        if sidecar.is_symlink() or sidecar.is_dir() or not sidecar.is_file():
            raise RestorePublicationVerification("restore-publication:existing-sidecar")
        sidecar_shapes.append(_regular_identity(sidecar, allow_empty=True))
    if (sidecar_shapes[0] is None) != (sidecar_shapes[1] is None):
        raise RestorePublicationVerification("restore-publication:existing-sidecar")
    if all(identity is not None and identity[3] == 0 for identity in sidecar_shapes):
        raise RestorePublicationVerification("restore-publication:existing-sidecar")
    return _regular_identity(path), sidecar_shapes[0], sidecar_shapes[1]


def _existing_storage_identity(path: Path) -> tuple[tuple[tuple[int, int, int, int, int], str], tuple[tuple[int, int, int, int, int], str] | None, tuple[tuple[int, int, int, int, int], str] | None]:
    """Read one immutable identity without checkpointing caller-owned state."""

    sidecar_identities: list[tuple[tuple[int, int, int, int, int], str] | None] = []
    for suffix in ("-wal", "-shm"):
        sidecar = _sidecar(path, suffix)
        if not os.path.lexists(os.fspath(sidecar)):
            sidecar_identities.append(None)
            continue
        if sidecar.is_symlink() or sidecar.is_dir() or not sidecar.is_file():
            raise RestorePublicationVerification("restore-publication:existing-sidecar")
        sidecar_identities.append(_storage_file_identity(sidecar, allow_empty=True))
    if (sidecar_identities[0] is None) != (sidecar_identities[1] is None):
        raise RestorePublicationVerification("restore-publication:existing-sidecar")
    if all(identity is not None and identity[0][3] == 0 for identity in sidecar_identities):
        raise RestorePublicationVerification("restore-publication:existing-sidecar")
    return _storage_file_identity(path), sidecar_identities[0], sidecar_identities[1]


def _require_no_sidecars(path: Path, *, label: str, remove_empty: bool) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = _sidecar(path, suffix)
        if not os.path.lexists(os.fspath(sidecar)):
            continue
        if sidecar.is_symlink() or sidecar.is_dir():
            raise RestorePublicationVerification(f"restore-publication:{label}-sidecar")
        try:
            size = _regular_identity(sidecar, allow_empty=True)[3]
        except OSError as exc:
            raise_redacted(RestorePublicationVerification, f"restore-publication:{label}-sidecar")
        if size != 0:
            raise RestorePublicationVerification(f"restore-publication:{label}-sidecar-nonempty")
        if remove_empty:
            try:
                identity = _regular_identity(sidecar, allow_empty=True)
                _delete_exact_file(sidecar, expected_identity=identity, allow_empty=True, label=f"{label}-sidecar")
            except RestorePublicationError:
                raise
            except OSError as exc:
                raise_redacted(RestorePublicationVerification, f"restore-publication:{label}-sidecar")
    if any(os.path.lexists(os.fspath(_sidecar(path, suffix))) for suffix in ("-wal", "-shm")):
        raise RestorePublicationVerification(f"restore-publication:{label}-sidecar")


def _checkpoint_closed_database(path: Path) -> None:
    before = _regular_identity(path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=0.25)
        connection.execute("PRAGMA synchronous=FULL")
        row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if row is None or len(row) < 3:
            raise RestorePublicationVerification("restore-publication:checkpoint-result")
        busy, log_frames, checkpointed_frames = (int(row[0]), int(row[1]), int(row[2]))
        if busy != 0 or log_frames != checkpointed_frames:
            raise RestorePublicationVerification("restore-publication:checkpoint-busy")
    except RestorePublicationError:
        raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:checkpoint")
    finally:
        if connection is not None:
            connection.close()
    after = _regular_identity(path)
    if before[:3] != after[:3]:
        raise RestorePublicationVerification("restore-publication:checkpoint-identity")
    _require_no_sidecars(path, label="staging", remove_empty=True)


def _namespace_paths(target: Path, export_root: str) -> tuple[Path, Path, Path]:
    export_root = _hex(export_root, "stage-identity")
    namespace = target.parent / f".{target.name}.restore-v2-{export_root}"
    return namespace, namespace / "stage.db", namespace / "marker.json"


def _publication_receipt_path(namespace: Path) -> Path:
    return namespace / PUBLICATION_RECEIPT_NAME


def stage_paths(target: str | Path, export_root: str, *, create_parent: bool = False) -> tuple[Path, Path]:
    """Return compatibility/test paths for the owned stage namespace."""
    normalized = _target(target)
    namespace, stage, marker = _namespace_paths(normalized, export_root)
    if create_parent:
        if os.path.lexists(os.fspath(namespace)) and (namespace.is_symlink() or not namespace.is_dir()):
            raise RestorePublicationError("restore-publication:staging-object")
        namespace.mkdir(mode=0o700, exist_ok=True)
    return stage, marker


def _marker_value(target: Path, namespace: Path, stage: Path, export_root: str) -> dict[str, object]:
    return {
        "schema": STAGING_SCHEMA,
        "schema_version": STAGING_VERSION,
        "target_identity": _target_identity(target),
        "target_name": target.name,
        "namespace_name": namespace.name,
        "stage_name": stage.name,
        "export_root": _hex(export_root, "stage-identity"),
    }


def _marker_bytes(target: Path, namespace: Path, stage: Path, export_root: str) -> bytes:
    raw = _canonical(_marker_value(target, namespace, stage, export_root))
    if len(raw) > MAX_MARKER_BYTES:
        raise RestorePublicationVerification("restore-publication:marker-cap")
    return raw


def _validate_marker(marker: Path, target: Path, namespace: Path, stage: Path, export_root: str) -> None:
    raw = _read_owned_marker(marker, label="staging-marker")
    if raw != _marker_bytes(target, namespace, stage, export_root):
        raise RestorePublicationVerification("restore-publication:staging-marker-binding")


def _ensure_marker(marker: Path, target: Path, namespace: Path, stage: Path, export_root: str) -> None:
    expected = _marker_bytes(target, namespace, stage, export_root)
    try:
        descriptor = os.open(os.fspath(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        _validate_marker(marker, target, namespace, stage, export_root)
        return
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(expected)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except Exception:
                raise_redacted(RestorePublicationVerification, "restore-publication:file-read")
    _validate_marker(marker, target, namespace, stage, export_root)


def _lock_path(target: Path) -> Path:
    return target.parent / f".{target.name}.restore-v2.lock"


def _lock_bytes(target: Path) -> bytes:
    return _canonical({
        "schema": STAGING_SCHEMA,
        "schema_version": STAGING_VERSION,
        "target_identity": _target_identity(target),
        "target_name": target.name,
        "purpose": "restore-coordination",
    }) + b"\0"


def _lock_file_bytes(target: Path) -> bytes:
    """Return the marker plus a separate byte-range-lock sentinel.

    The sentinel is deliberately outside the marker bytes.  Windows denies a
    second process a read that overlaps a locked byte, so locking the final
    marker byte makes concurrent validation report a spurious lock-read
    failure.  The extra byte keeps the immutable marker readable while the
    coordination byte is held exclusively.
    """

    return _lock_bytes(target) + b"\0"


def _validate_lock(stream, target: Path) -> None:
    expected = _lock_bytes(target)
    try:
        stream.seek(0)
        raw = stream.read(len(expected))
        opened = os.fstat(stream.fileno())
        size = opened.st_size
    except OSError as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:lock-read")
    try:
        path_identity = _regular_identity(_lock_path(target))
    except RestorePublicationError as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:lock-binding")
    if raw != expected or size != len(expected) + 1 or (int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink)) != path_identity[:3]:
        raise RestorePublicationVerification("restore-publication:lock-binding")


@contextmanager
def _target_lock(target: Path):
    lock_path = _lock_path(target)
    if os.path.lexists(os.fspath(lock_path)) and (lock_path.is_symlink() or lock_path.is_dir()):
        raise RestorePublicationVerification("restore-publication:lock-object")
    expected = _lock_bytes(target)
    descriptor = -1
    stream = None
    try:
        try:
            descriptor = os.open(os.fspath(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0), 0o600)
            created = True
        except FileExistsError:
            descriptor = os.open(os.fspath(lock_path), os.O_RDWR | getattr(os, "O_BINARY", 0))
            created = False
        stream = os.fdopen(descriptor, "r+b", buffering=0)
        descriptor = -1
        if created:
            stream.write(_lock_file_bytes(target))
            stream.flush()
            os.fsync(stream.fileno())
            _validate_lock(stream, target)
        else:
            for attempt in range(LOCK_ATTEMPTS):
                try:
                    _validate_lock(stream, target)
                    break
                except RestorePublicationVerification as exc:
                    if str(exc) not in {
                        "restore-publication:lock-binding",
                        "restore-publication:lock-read",
                    } or attempt + 1 == LOCK_ATTEMPTS:
                        raise
                    time.sleep(LOCK_SLEEP_SECONDS)
        acquired = False
        for attempt in range(LOCK_ATTEMPTS):
            try:
                stream.seek(len(expected))
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except (OSError, PermissionError):
                if attempt + 1 == LOCK_ATTEMPTS:
                    raise RestorePublicationError("restore-publication:lock-busy")
                time.sleep(LOCK_SLEEP_SECONDS)
        if not acquired:
            raise RestorePublicationError("restore-publication:lock-busy")
        _validate_lock(stream, target)
        try:
            yield
        finally:
            try:
                stream.seek(len(expected))
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally:
                stream.close()
                stream = None
    finally:
        if stream is not None:
            stream.close()
        if descriptor != -1:
            os.close(descriptor)


def _workspace_paths(base: str | Path, identity: str) -> tuple[Path, Path, Path]:
    try:
        value = os.fspath(base)
    except TypeError as exc:
        raise_redacted(RestorePublicationError, "restore-publication:workspace-base")
    if isinstance(value, bytes) or not value:
        raise RestorePublicationError("restore-publication:workspace-base")
    parent = Path(os.path.abspath(value))
    if parent.is_symlink() or not parent.is_dir():
        raise RestorePublicationError("restore-publication:workspace-base")
    identity = _hex(identity, "workspace-identity")
    namespace = parent / f".mirror-restore-workspace-v1-{identity}"
    return namespace, namespace / "workspace.json", namespace / "workspace.json.tmp"


def _workspace_children(children: Sequence[str]) -> tuple[str, ...]:
    values = tuple(children)
    if not values or len(values) > MAX_WORKSPACE_CHILDREN or len(set(values)) != len(values):
        raise RestorePublicationVerification("restore-publication:workspace-children")
    for value in values:
        if not isinstance(value, str) or not value:
            raise RestorePublicationVerification("restore-publication:workspace-children")
        try:
            if len(value.encode("ascii", "strict")) > 64:
                raise RestorePublicationVerification("restore-publication:workspace-children")
        except UnicodeEncodeError as exc:
            raise_redacted(RestorePublicationVerification, "restore-publication:workspace-children")
        if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in value):
            raise RestorePublicationVerification("restore-publication:workspace-children")
    return values


def _workspace_receipt_name(child_name: str) -> str:
    return f"{child_name}.publication.json"


def _workspace_marker_bytes(namespace: Path, identity: str, children: Sequence[str]) -> bytes:
    children = _workspace_children(children)
    value = {
        "schema": WORKSPACE_SCHEMA,
        "schema_version": WORKSPACE_VERSION,
        "workspace_identity": _hex(identity, "workspace-identity"),
        "target_identity": _target_identity(namespace),
        "children": list(children),
        "receipt_names": [_workspace_receipt_name(child) for child in children],
    }
    raw = _canonical(value)
    if len(raw) > MAX_MARKER_BYTES:
        raise RestorePublicationVerification("restore-publication:workspace-marker-cap")
    return raw


def _validate_workspace_marker(marker: Path, namespace: Path, identity: str, children: Sequence[str]) -> None:
    raw = _read_owned_marker(marker, label="workspace-marker")
    if raw != _workspace_marker_bytes(namespace, identity, children):
        raise RestorePublicationVerification("restore-publication:workspace-marker-binding")


def _ensure_workspace_marker(namespace: Path, marker: Path, temporary: Path, identity: str, children: Sequence[str]) -> None:
    expected = _workspace_marker_bytes(namespace, identity, children)
    if os.path.lexists(os.fspath(marker)):
        _validate_workspace_marker(marker, namespace, identity, children)
        if os.path.lexists(os.fspath(temporary)):
            if _read_owned_marker(temporary, label="workspace-marker-temp") != expected:
                raise RestorePublicationVerification("restore-publication:workspace-marker-temp")
            _delete_exact_file(
                temporary,
                expected_identity=_regular_identity(temporary, allow_empty=True),
                expected_bytes=expected,
                allow_empty=True,
                label="workspace-marker-temp",
            )
        return
    if os.path.lexists(os.fspath(temporary)):
        if _read_owned_marker(temporary, label="workspace-marker-temp") != expected:
            raise RestorePublicationVerification("restore-publication:workspace-marker-temp")
    else:
        descriptor = os.open(
            os.fspath(temporary),
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if descriptor != -1:
                os.close(descriptor)
    try:
        os.link(temporary, marker)
    except FileExistsError:
        _validate_workspace_marker(marker, namespace, identity, children)
    except OSError as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:workspace-marker-link")
    finally:
        if os.path.lexists(os.fspath(temporary)):
            if temporary.is_symlink() or temporary.is_dir():
                raise RestorePublicationVerification("restore-publication:workspace-marker-temp")
            temporary_identity = _regular_identity(temporary, expected_links=2)
            marker_identity = _regular_identity(marker, expected_links=2)
            if temporary_identity[:2] != marker_identity[:2]:
                raise RestorePublicationVerification("restore-publication:workspace-marker-link")
            _delete_exact_file(
                temporary,
                expected_inode=temporary_identity[:2],
                expected_bytes=expected,
                allow_empty=True,
                label="workspace-marker-temp",
            )
    _validate_workspace_marker(marker, namespace, identity, children)


@contextmanager
def owned_restore_workspace(base: str | Path, identity: str, *, children: Sequence[str]):
    """Open one deterministic, marker-owned fresh-target workspace.

    The workspace is deliberately retained when the caller fails.  A later
    operation with the same state identity reacquires the same lock and lets
    each component publisher reconcile its own target-scoped stage before the
    workspace is removed.
    """

    children = _workspace_children(children)
    namespace, marker, temporary = _workspace_paths(base, identity)
    with _target_lock(namespace):
        existed = os.path.lexists(os.fspath(namespace))
        if existed:
            if namespace.is_symlink() or not namespace.is_dir():
                raise RestorePublicationVerification("restore-publication:workspace-object")
        else:
            try:
                namespace.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError as exc:
                raise_redacted(RestorePublicationVerification, "restore-publication:workspace-object")
        entries = _namespace_entries(namespace)
        allowed = {marker.name, temporary.name, *children, *(_workspace_receipt_name(child) for child in children)}
        if not entries <= allowed:
            raise RestorePublicationVerification("restore-publication:workspace-foreign")
        if existed and marker.name not in entries:
            raise RestorePublicationVerification("restore-publication:workspace-marker")
        _ensure_workspace_marker(namespace, marker, temporary, identity, children)
        for child_name in children:
            child = namespace / child_name
            if os.path.lexists(os.fspath(child)) and (child.is_symlink() or not child.is_dir()):
                raise RestorePublicationVerification("restore-publication:workspace-child")
            child.mkdir(mode=0o700, exist_ok=True)
        yield namespace


def _read_workspace_receipt(path: Path) -> tuple[dict[str, object], tuple[int, int, int, int, int]]:
    try:
        raw, identity = _read_owned_bytes(path, cap=MAX_WORKSPACE_RECEIPT_BYTES, label="workspace-receipt")
        value = json.loads(raw.decode("ascii"))
        if not isinstance(value, dict) or _canonical(value) != raw:
            raise RestorePublicationCleanupError("restore-publication:workspace-receipt-canonical")
        return value, identity
    except RestorePublicationCleanupError:
        raise
    except RestorePublicationVerification:
        raise_redacted(RestorePublicationCleanupError, "restore-publication:workspace-receipt")
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise_redacted(RestorePublicationCleanupError, "restore-publication:workspace-receipt")


def _validate_publication_receipt(
    receipt: Mapping[str, object],
    *,
    identity: str,
    child_name: str,
    target: Path,
    export_root: str,
    expected_semantic: str | None,
    storage_identity: tuple[
        tuple[tuple[int, int, int, int, int], str],
        tuple[tuple[int, int, int, int, int], str] | None,
        tuple[tuple[int, int, int, int, int], str] | None,
    ] | None,
) -> None:
    required = {
        "schema", "schema_version", "publication_kind", "target_identity", "export_root",
        "semantic_digest", "byte_length", "file_digest", "storage_identity", "marker_identity",
        "publication_operation_id", "receipt_digest", "workspace_identity", "child_name",
        "child_identity", "canonical_target", "workspace_receipt_digest",
    }
    if set(receipt) != required or receipt["schema"] != "mirror-restore-publication-receipt-v1" or receipt["schema_version"] != 1:
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-binding")
    if receipt["publication_kind"] not in {"CREATED", "ADOPTED_EXISTING"}:
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-binding")
    expected_target = _target_identity(target)
    if (
        receipt["workspace_identity"] != _hex(identity, "workspace-identity")
        or receipt["child_name"] != child_name
        or receipt["child_identity"] != _digest("workspace-child", {"workspace_identity": identity, "child_name": child_name})
        or receipt["canonical_target"] != expected_target
        or receipt["target_identity"] != expected_target
        or receipt["export_root"] != _hex(export_root, "receipt-export-root")
    ):
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-binding")
    publication_namespace, publication_stage, publication_marker = _namespace_paths(target, export_root)
    expected_marker_raw = _marker_bytes(target, publication_namespace, publication_stage, export_root)
    expected_marker_identity = _digest(
        "marker-identity",
        {"byte_length": len(expected_marker_raw), "byte_digest": hashlib.sha3_512(expected_marker_raw).hexdigest()},
    )
    if receipt["marker_identity"] != expected_marker_identity:
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-marker")
    if os.path.lexists(os.fspath(publication_marker)):
        try:
            _validate_marker(publication_marker, target, publication_namespace, publication_stage, export_root)
        except RestorePublicationError as exc:
            raise_redacted(RestorePublicationCleanupError, "restore-publication:workspace-receipt-marker")
    if expected_semantic is not None and receipt["semantic_digest"] != expected_semantic:
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-semantic")
    if not isinstance(receipt["semantic_digest"], str) or not isinstance(receipt["file_digest"], str):
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-binding")
    _hex(receipt["semantic_digest"], "receipt-semantic")
    _hex(receipt["file_digest"], "receipt-file")
    _hex(receipt["marker_identity"], "receipt-marker")
    _hex(receipt["publication_operation_id"], "receipt-operation")
    _hex(receipt["receipt_digest"], "receipt-digest")
    _hex(receipt["workspace_receipt_digest"], "workspace-receipt-digest")
    if type(receipt["byte_length"]) is not int or receipt["byte_length"] <= 0 or receipt["byte_length"] > MAX_IMAGE_BYTES:
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-binding")
    storage = receipt["storage_identity"]
    if not isinstance(storage, Mapping) or set(storage) != {"dev", "ino", "nlink", "size", "mtime_ns"} or any(type(storage[key]) is not int for key in storage):
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-storage")
    base = {key: receipt[key] for key in required if key not in {"workspace_identity", "child_name", "child_identity", "canonical_target", "workspace_receipt_digest"}}
    receipt_digest = base.pop("receipt_digest")
    operation_id = base.pop("publication_operation_id")
    if _digest("publication-receipt", {**base, "publication_operation_id": operation_id}) != receipt_digest:
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-digest")
    operation_material = dict(base)
    operation_material.pop("receipt_digest", None)
    if _digest("publication-operation", operation_material) != operation_id:
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-operation")
    workspace_digest_material = {key: receipt[key] for key in required if key != "workspace_receipt_digest"}
    if _digest("workspace-receipt", workspace_digest_material) != receipt["workspace_receipt_digest"]:
        raise RestorePublicationCleanupError("restore-publication:workspace-receipt-digest")
    if storage_identity is not None:
        regular = storage_identity[0][0]
        if storage != {"dev": regular[0], "ino": regular[1], "nlink": regular[2], "size": regular[3], "mtime_ns": regular[4]}:
            raise RestorePublicationCleanupError("restore-publication:workspace-receipt-storage")
        if receipt["byte_length"] != storage_identity[0][0][3] or receipt["file_digest"] != storage_identity[0][1]:
            raise RestorePublicationCleanupError("restore-publication:workspace-receipt-storage")


def persist_workspace_receipt(
    namespace: str | Path,
    identity: str,
    child_name: str,
    receipt: Mapping[str, object],
    *,
    children: Sequence[str],
    target: str | Path | None = None,
) -> None:
    """Persist one bounded, marker-bound receipt before workspace cleanup."""

    children = _workspace_children(children)
    namespace = Path(os.path.abspath(os.fspath(namespace)))
    expected_namespace, marker, _temporary = _workspace_paths(namespace.parent, identity)
    if namespace != expected_namespace or child_name not in children or namespace.is_symlink() or not namespace.is_dir():
        raise RestorePublicationVerification("restore-publication:workspace-receipt-binding")
    _validate_workspace_marker(marker, namespace, identity, children)
    if not isinstance(receipt, Mapping):
        raise RestorePublicationVerification("restore-publication:workspace-receipt")
    base_required = {
        "schema", "schema_version", "publication_kind", "target_identity", "export_root",
        "semantic_digest", "byte_length", "file_digest", "storage_identity", "marker_identity",
        "publication_operation_id", "receipt_digest",
    }
    if set(receipt) != base_required or receipt["schema"] != "mirror-restore-publication-receipt-v1" or receipt["schema_version"] != 1 or receipt["publication_kind"] not in {"CREATED", "ADOPTED_EXISTING"}:
        raise RestorePublicationVerification("restore-publication:workspace-receipt")
    target_identity = receipt.get("target_identity")
    export_root = receipt.get("export_root")
    semantic_digest = receipt.get("semantic_digest")
    file_digest = receipt.get("file_digest")
    storage = receipt.get("storage_identity")
    if not all(isinstance(value, str) for value in (target_identity, export_root, semantic_digest, file_digest)) or not isinstance(storage, Mapping) or set(storage) != {"dev", "ino", "nlink", "size", "mtime_ns"} or any(type(storage[key]) is not int for key in storage):
        raise RestorePublicationVerification("restore-publication:workspace-receipt")
    _hex(target_identity, "receipt-target")
    _hex(export_root, "receipt-export-root")
    _hex(semantic_digest, "receipt-semantic")
    _hex(file_digest, "receipt-file")
    _hex(receipt["marker_identity"], "receipt-marker")
    _hex(receipt["publication_operation_id"], "receipt-operation")
    _hex(receipt["receipt_digest"], "receipt-digest")
    if type(receipt["byte_length"]) is not int or receipt["byte_length"] <= 0 or receipt["byte_length"] > MAX_IMAGE_BYTES:
        raise RestorePublicationVerification("restore-publication:workspace-receipt")
    receipt_base = dict(receipt)
    receipt_digest = receipt_base.pop("receipt_digest")
    operation_id = receipt_base.pop("publication_operation_id")
    if _digest("publication-operation", receipt_base) != operation_id or _digest("publication-receipt", {**receipt_base, "publication_operation_id": operation_id}) != receipt_digest:
        raise RestorePublicationVerification("restore-publication:workspace-receipt-digest")
    body = dict(receipt)
    body.update({
        "workspace_identity": _hex(identity, "workspace-identity"),
        "child_name": child_name,
        "child_identity": _digest("workspace-child", {"workspace_identity": identity, "child_name": child_name}),
        "canonical_target": target_identity,
    })
    body["workspace_receipt_digest"] = _digest("workspace-receipt", body)
    raw = _canonical(body)
    if len(raw) > MAX_WORKSPACE_RECEIPT_BYTES:
        raise RestorePublicationVerification("restore-publication:workspace-receipt-cap")
    path = namespace / _workspace_receipt_name(child_name)
    if os.path.lexists(os.fspath(path)):
        if path.is_symlink() or path.is_dir():
            raise RestorePublicationVerification("restore-publication:workspace-receipt-object")
        existing, _ = _read_workspace_receipt(path)
        # An existing receipt is the durable proof of our earlier publication;
        # an ADOPTED_EXISTING callback may therefore replay it byte-for-byte.
        if existing.get("target_identity") != body["target_identity"] or existing.get("export_root") != body["export_root"] or existing.get("semantic_digest") != body["semantic_digest"] or existing.get("file_digest") != body["file_digest"] or existing.get("storage_identity") != body["storage_identity"]:
            raise RestorePublicationVerification("restore-publication:workspace-receipt-conflict")
        return
    marker_raw = _read_owned_marker(marker, label="workspace-marker")
    expected_marker_identity = _digest(
        "marker-identity",
        {"byte_length": len(marker_raw), "byte_digest": hashlib.sha3_512(marker_raw).hexdigest()},
    )
    owned_publication = False
    if target is not None:
        target_path = _target(target)
        if target_identity != _target_identity(target_path):
            raise RestorePublicationVerification("restore-publication:workspace-receipt-target")
        publication_namespace, publication_stage, publication_marker = _namespace_paths(target_path, export_root)
        _validate_marker(publication_marker, target_path, publication_namespace, publication_stage, export_root)
        # A new receipt is durable proof only while the marker and the two
        # hard links still bind the publication.  A marker-only target is not
        # an owned publication; an already persisted receipt is handled by
        # the existing-receipt branch above.
        try:
            target_links = _regular_identity(target_path, expected_links=2)
            stage_links = _regular_identity(publication_stage, expected_links=2)
        except RestorePublicationError:
            raise_redacted(RestorePublicationVerification, "restore-publication:workspace-receipt-required")
        if target_links[:2] != stage_links[:2] or target_links[2] != 2 or stage_links[2] != 2:
            raise RestorePublicationVerification("restore-publication:workspace-receipt-required")
        owned_publication = True
        publication_raw = _read_owned_marker(publication_marker, label="publication-marker")
        expected_marker_identity = _digest(
            "marker-identity",
            {"byte_length": len(publication_raw), "byte_digest": hashlib.sha3_512(publication_raw).hexdigest()},
        )
    if receipt["marker_identity"] != expected_marker_identity:
        raise RestorePublicationVerification("restore-publication:workspace-receipt-marker")
    if not owned_publication:
        raise RestorePublicationVerification("restore-publication:workspace-receipt-required")
    try:
        descriptor = os.open(os.fspath(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        raise RestorePublicationVerification("restore-publication:workspace-receipt-race")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except Exception:
                raise_redacted(RestorePublicationVerification, "restore-publication:workspace-receipt")


def cleanup_owned_workspace(
    namespace: str | Path,
    identity: str,
    bindings: Mapping[
        str,
        tuple[str | Path, str, Mapping[str, object], Callable[[Path], object]],
    ],
    *,
    children: Sequence[str],
) -> None:
    """Remove only a completed, marker-owned fresh-target workspace."""

    children = _workspace_children(children)
    namespace = Path(os.path.abspath(os.fspath(namespace)))
    expected_namespace, marker, temporary = _workspace_paths(namespace.parent, identity)
    if namespace != expected_namespace:
        raise RestorePublicationCleanupError("restore-publication:workspace-binding")
    if namespace.is_symlink() or not namespace.is_dir():
        raise RestorePublicationCleanupError("restore-publication:workspace-object")
    namespace_identity = _directory_identity(namespace)
    _validate_workspace_marker(marker, namespace, identity, children)
    if set(bindings) != set(children):
        raise RestorePublicationCleanupError("restore-publication:workspace-bindings")
    if os.path.lexists(os.fspath(temporary)):
        if _read_owned_marker(temporary, label="workspace-marker-temp") != _workspace_marker_bytes(namespace, identity, children):
            raise RestorePublicationCleanupError("restore-publication:workspace-marker-temp")
        _delete_exact_file(
            temporary,
            expected_identity=_regular_identity(temporary, allow_empty=True),
            expected_bytes=_workspace_marker_bytes(namespace, identity, children),
            allow_empty=True,
            label="workspace-marker-temp",
        )
    for child_name in children:
        child = namespace / child_name
        child_identity = _directory_identity(child)
        target_value, export_root, expected_evidence, verify_database = bindings[child_name]
        target = _target(target_value)
        if target.parent != child:
            raise RestorePublicationCleanupError("restore-publication:workspace-target")
        receipt_path = namespace / _workspace_receipt_name(child_name)
        if not os.path.lexists(os.fspath(receipt_path)):
            raise RestorePublicationCleanupError("restore-publication:workspace-receipt-missing")
        receipt, receipt_file_identity = _read_workspace_receipt(receipt_path)
        target_namespace, stage, target_marker = _namespace_paths(target, export_root)
        target_lock = _lock_path(target)
        with _target_lock(target):
            if child.is_symlink() or not child.is_dir():
                raise RestorePublicationCleanupError("restore-publication:workspace-child")
            entries = _namespace_entries(child)
            allowed = {target.name, target.name + "-wal", target.name + "-shm", target_namespace.name, target_lock.name}
            if not entries <= allowed:
                raise RestorePublicationCleanupError("restore-publication:workspace-foreign")
            owned_storage = None
            if target.exists() and not target.is_symlink() and not target.is_dir():
                _owned_image, _owned_evidence, owned_storage = _verify_existing(
                    target,
                    _expected_semantic(expected_evidence),
                    verify_database=verify_database,
                )
            elif any(os.path.lexists(os.fspath(_sidecar(target, suffix))) for suffix in ("-wal", "-shm")):
                raise RestorePublicationCleanupError("restore-publication:workspace-target")
            else:
                raise RestorePublicationCleanupError("restore-publication:workspace-target")
            _validate_publication_receipt(
                receipt,
                identity=identity,
                child_name=child_name,
                target=target,
                export_root=export_root,
                expected_semantic=_expected_semantic(expected_evidence),
                storage_identity=owned_storage,
            )
            if os.path.lexists(os.fspath(target_namespace)):
                if target_namespace.is_symlink() or not target_namespace.is_dir():
                    raise RestorePublicationCleanupError("restore-publication:workspace-stage-object")
                if stage.exists():
                    raise RestorePublicationCleanupError("restore-publication:workspace-stage-pending")
                _validate_marker(target_marker, target, target_namespace, stage, export_root)
                _cleanup_namespace(target_namespace, stage, target_marker)
            if owned_storage is not None:
                for path, expected in (
                    (_sidecar(target, "-wal"), owned_storage[1]),
                    (_sidecar(target, "-shm"), owned_storage[2]),
                    (target, owned_storage[0]),
                ):
                    if expected is None:
                        if os.path.lexists(os.fspath(path)):
                            raise RestorePublicationCleanupError("restore-publication:workspace-target-changed")
                        continue
                    if _storage_file_identity(path, allow_empty=True) != expected:
                        raise RestorePublicationCleanupError("restore-publication:workspace-target-changed")
                    _delete_exact_file(
                        path,
                        expected_identity=expected[0],
                        allow_empty=True,
                        label="workspace-target",
                    )
        if os.path.lexists(os.fspath(target_lock)):
            if _read_owned_marker(target_lock, label="workspace-lock") != _lock_file_bytes(target):
                raise RestorePublicationCleanupError("restore-publication:workspace-lock")
            _delete_exact_file(
                target_lock,
                expected_identity=_regular_identity(target_lock, allow_empty=True),
                expected_bytes=_lock_file_bytes(target),
                allow_empty=True,
                label="workspace-lock",
            )
        _delete_exact_file(
            receipt_path,
            expected_identity=receipt_file_identity,
            allow_empty=False,
            label="workspace-receipt",
        )
        _delete_exact_directory(child, expected_identity=child_identity, label="workspace-child")
    _validate_workspace_marker(marker, namespace, identity, children)
    _delete_exact_file(
        marker,
        expected_identity=_regular_identity(marker, allow_empty=True),
        expected_bytes=_workspace_marker_bytes(namespace, identity, children),
        allow_empty=True,
        label="workspace-marker",
    )
    _delete_exact_directory(namespace, expected_identity=namespace_identity, label="workspace")


def _namespace_entries(namespace: Path) -> set[str]:
    try:
        if namespace.is_symlink() or not namespace.is_dir():
            raise RestorePublicationVerification("restore-publication:staging-object")
        result: set[str] = set()
        for index, item in enumerate(namespace.iterdir(), start=1):
            if index > MAX_NAMESPACE_ENTRIES:
                raise RestorePublicationVerification("restore-publication:staging-entry-cap")
            result.add(item.name)
        return result
    except RestorePublicationError:
        raise
    except OSError as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:staging-scan")


def _scan_target_namespaces(target: Path, current: Path) -> None:
    prefix = f".{target.name}.restore-"
    try:
        candidates = target.parent.iterdir()
    except OSError as exc:
        raise_redacted(RestorePublicationVerification, "restore-publication:staging-scan")
    for index, item in enumerate(candidates, start=1):
        if index > MAX_PARENT_ENTRIES:
            raise RestorePublicationVerification("restore-publication:staging-scan-cap")
        if not item.name.startswith(prefix):
            continue
        if item == _lock_path(target):
            continue
        if item != current:
            raise RestorePublicationConflict("restore-publication:staging-foreign")


def _cleanup_namespace(namespace: Path, stage: Path, marker: Path) -> None:
    if not os.path.lexists(os.fspath(namespace)):
        return
    namespace_identity = _directory_identity(namespace)
    entries = _namespace_entries(namespace)
    publication_receipt = _publication_receipt_path(namespace)
    allowed = {stage.name, stage.name + "-wal", stage.name + "-shm", marker.name, publication_receipt.name}
    if not entries <= allowed:
        raise RestorePublicationCleanupError("restore-publication:staging-foreign")
    for path in (_sidecar(stage, "-wal"), _sidecar(stage, "-shm"), stage, marker, publication_receipt):
        if not os.path.lexists(os.fspath(path)):
            continue
        if path.is_symlink() or path.is_dir():
            raise RestorePublicationCleanupError("restore-publication:staging-object")
        expected_bytes = None
        if path == marker:
            expected_bytes = _read_owned_marker(path, label="staging-marker")
        elif path == publication_receipt:
            expected_bytes, _ = _read_owned_bytes(path, cap=MAX_PUBLICATION_RECEIPT_BYTES, label="publication-receipt")
        try:
            _delete_exact_file(
                path,
                expected_identity=_regular_identity(path, allow_empty=True),
                expected_bytes=expected_bytes,
                allow_empty=True,
                label="staging-cleanup",
            )
        except RestorePublicationError:
            raise
        except OSError as exc:
            raise_redacted(RestorePublicationCleanupError, "restore-publication:cleanup")
    _delete_exact_directory(namespace, expected_identity=namespace_identity, label="cleanup")


def _reconcile_namespace(target: Path, namespace: Path, stage: Path, marker: Path, export_root: str) -> bool:
    if not os.path.lexists(os.fspath(namespace)):
        return False
    entries = _namespace_entries(namespace)
    publication_receipt = _publication_receipt_path(namespace)
    allowed = {stage.name, stage.name + "-wal", stage.name + "-shm", marker.name, publication_receipt.name}
    if not entries <= allowed:
        raise RestorePublicationVerification("restore-publication:staging-foreign")
    if marker.name not in entries:
        raise RestorePublicationVerification("restore-publication:staging-state")
    _validate_marker(marker, target, namespace, stage, export_root)
    if stage.name not in entries:
        if any(name in entries for name in (stage.name + "-wal", stage.name + "-shm")):
            raise RestorePublicationVerification("restore-publication:staging-state")
        if not os.path.lexists(os.fspath(target)):
            raise RestorePublicationConflict("restore-publication:publication-receipt-target")
        if publication_receipt.name not in entries:
            raise RestorePublicationConflict("restore-publication:publication-receipt-missing")
        receipt, _ = _read_publication_receipt(publication_receipt)
        _validate_direct_publication_receipt(
            receipt,
            target=target,
            namespace=namespace,
            stage=stage,
            export_root=export_root,
            expected_semantic=None,
            storage_identity=_existing_storage_identity(target),
        )
        return False
    return True


def _same_semantic(image: VerifiedRestoreImageV1, expected_semantic: str | None) -> None:
    if expected_semantic is not None and image.semantic_digest != expected_semantic:
        raise RestorePublicationConflict("restore-publication:semantic-conflict")


def _is_empty_evidence(evidence: Mapping[str, object]) -> bool:
    """Recognize only the fresh schema image left by an interrupted build."""

    counters = [
        value for key, value in evidence.items()
        if key.endswith("_count") and type(value) is int
    ]
    return bool(counters) and all(value == 0 for value in counters)


def _verify_existing(
    target: Path,
    expected_semantic: str | None,
    *,
    verify_database: Callable[[Path], object],
) -> tuple[
    VerifiedRestoreImageV1,
    Mapping[str, object],
    tuple[
        tuple[tuple[int, int, int, int, int], str],
        tuple[tuple[int, int, int, int, int], str] | None,
        tuple[tuple[int, int, int, int, int], str] | None,
    ],
]:
    if target.is_symlink() or target.is_dir() or not target.is_file():
        raise RestorePublicationConflict("restore-publication:existing-object")
    try:
        before_shape = _existing_storage_shape(target)
        image, evidence = _verified_image(target, verify_database)
        after_identity = _existing_storage_identity(target)
        after_shape = tuple(
            identity[0] if identity is not None else None
            for identity in after_identity
        )
        if before_shape != after_shape or (after_identity[0][0][3], after_identity[0][1]) != (image.byte_length, image.file_digest):
            raise RestorePublicationVerification("restore-publication:existing-changed")
    except RestorePublicationError as exc:
        raise_redacted(RestorePublicationConflict, "restore-publication:existing-invalid")
    _same_semantic(image, expected_semantic)
    return image, evidence, after_identity


def _publish_link(stage: Path, target: Path) -> bool:
    try:
        os.link(stage, target)
        return True
    except FileExistsError:
        return False
    except OSError as exc:
        if os.path.lexists(os.fspath(target)):
            return False
        raise_redacted(RestorePublicationError, "restore-publication:atomic-create")


def _remove_created_link(target: Path, owned_inode: tuple[int, int]) -> None:
    """Remove only the link just created from the still-owned stage inode."""

    try:
        current = _regular_identity(target, allow_empty=False, expected_links=target.stat().st_nlink)
        if current[:2] != owned_inode:
            raise RestorePublicationCleanupError("restore-publication:published-ownership")
        _delete_exact_file(
            target,
            expected_inode=owned_inode,
            allow_empty=False,
            label="published-cleanup",
        )
    except RestorePublicationError:
        raise
    except OSError as exc:
        raise_redacted(RestorePublicationCleanupError, "restore-publication:published-cleanup")


def _call_fault(fault_injector: Callable[[str], None] | None, point: str) -> None:
    if fault_injector is not None:
        fault_injector(point)


def _finish_linked_publication(
    target: Path,
    namespace: Path,
    stage: Path,
    export_root: str,
    expected_semantic: str | None,
    *,
    verify_database: Callable[[Path], object],
    fault_injector: Callable[[str], None] | None,
    publication_receipt_sink: Callable[[Mapping[str, object]], object] | None,
    created: bool,
) -> tuple[
    VerifiedRestoreImageV1,
    tuple[
        tuple[tuple[int, int, int, int, int], str],
        tuple[tuple[int, int, int, int, int], str] | None,
        tuple[tuple[int, int, int, int, int], str] | None,
    ],
]:
    """Finish one publication while its target and stage still share an inode."""

    try:
        target_links = _regular_identity(target, expected_links=target.stat().st_nlink)
        stage_links = _regular_identity(stage, expected_links=stage.stat().st_nlink)
    except (OSError, RestorePublicationError) as exc:
        raise_redacted(RestorePublicationConflict, "restore-publication:published-recovery")
    if target_links[:2] != stage_links[:2] or target_links[2] != 2 or stage_links[2] != 2:
        if created and target_links[:2] == stage_links[:2]:
            try:
                _remove_created_link(target, target_links[:2])
            except RestorePublicationError:
                raise_redacted(RestorePublicationCleanupError, "restore-publication:published-cleanup")
        raise RestorePublicationConflict("restore-publication:published-recovery")
    receipt_persisted = False
    stage_delete_started = False
    stage_delete_completed = False
    try:
        image, _ = _verified_image(target, verify_database, expected_links=2)
        stage_image, _ = _verified_image(stage, verify_database, expected_links=2)
        _same_semantic(image, expected_semantic)
        if (image.byte_length, image.file_digest) != (stage_image.byte_length, stage_image.file_digest):
            raise RestorePublicationConflict("restore-publication:published-recovery")
        _require_no_sidecars(target, label="published", remove_empty=False)
        predicted = (target_links[0], target_links[1], 1, target_links[3], target_links[4])
        stable_storage = ((predicted, image.file_digest), None, None)
        receipt = _publication_receipt(
            target, namespace, stage, export_root, image, created=created,
            storage_identity=stable_storage,
        )
        local_receipt_path = _publication_receipt_path(namespace)
        if os.path.lexists(os.fspath(local_receipt_path)):
            existing_receipt, _ = _read_publication_receipt(local_receipt_path)
            _validate_direct_publication_receipt(
                existing_receipt,
                target=target,
                namespace=namespace,
                stage=stage,
                export_root=export_root,
                expected_semantic=image.semantic_digest,
                storage_identity=stable_storage,
            )
            receipt = existing_receipt
        if publication_receipt_sink is not None:
            try:
                publication_receipt_sink(receipt)
            except Exception:
                # A callback may have durably written before losing its
                # response.  A fresh link can be rolled back exactly; an
                # adopted target is pre-existing and must remain in place.
                if created:
                    try:
                        _remove_created_link(target, target_links[:2])
                    except RestorePublicationError:
                        raise_redacted(RestorePublicationCleanupError, "restore-publication:published-cleanup")
                raise_redacted(RestorePublicationError, "restore-publication:receipt")
        try:
            _persist_local_publication_receipt(namespace, target, stage, export_root, receipt)
        except RestorePublicationError:
            if created:
                try:
                    _remove_created_link(target, target_links[:2])
                except RestorePublicationError:
                    raise_redacted(RestorePublicationCleanupError, "restore-publication:published-cleanup")
            raise
        receipt_persisted = True
        _call_fault(fault_injector, "before_stage_delete")
        stage_delete_started = True
        _delete_exact_file(stage, expected_inode=stage_links[:2], allow_empty=False, label="stage-delete")
        stage_delete_completed = True
        final = _regular_identity(target)
        if final[:2] != target_links[:2] or final[2] != 1:
            raise RestorePublicationConflict("restore-publication:published-recovery")
        stable_storage = ((final, image.file_digest), None, None)
        if created:
            _call_fault(fault_injector, "after_atomic_publication_before_response")
    except RestorePublicationConflict:
        if created and not receipt_persisted and (not stage_delete_started or stage_delete_completed):
            try:
                _remove_created_link(target, target_links[:2])
            except RestorePublicationError:
                raise_redacted(RestorePublicationCleanupError, "restore-publication:published-cleanup")
        raise
    except RestorePublicationError:
        if created and not receipt_persisted and (not stage_delete_started or stage_delete_completed):
            try:
                _remove_created_link(target, target_links[:2])
            except RestorePublicationError:
                raise_redacted(RestorePublicationCleanupError, "restore-publication:published-cleanup")
        raise
    return image, stable_storage


def _recognized_owned_publication(
    target: Path,
    namespace: Path,
    stage: Path,
    export_root: str,
    expected_semantic: str | None,
    *,
    verify_database: Callable[[Path], object],
    fault_injector: Callable[[str], None] | None,
    publication_receipt_sink: Callable[[Mapping[str, object]], object] | None,
) -> tuple[
    VerifiedRestoreImageV1,
    tuple[
        tuple[tuple[int, int, int, int, int], str],
        tuple[tuple[int, int, int, int, int], str] | None,
        tuple[tuple[int, int, int, int, int], str] | None,
    ],
]:
    """Adopt a target whose still-present stage proves the same hard link."""

    return _finish_linked_publication(
        target, namespace, stage, export_root, expected_semantic,
        verify_database=verify_database, fault_injector=fault_injector,
        publication_receipt_sink=publication_receipt_sink, created=False,
    )


def _publication_receipt(
    target: Path,
    namespace: Path,
    stage: Path,
    export_root: str,
    image: VerifiedRestoreImageV1,
    *,
    created: bool,
    storage_identity: tuple[
        tuple[tuple[int, int, int, int, int], str],
        tuple[tuple[int, int, int, int, int], str] | None,
        tuple[tuple[int, int, int, int, int], str] | None,
    ] | None = None,
) -> dict[str, object]:
    if storage_identity is None:
        storage_identity = _existing_storage_identity(target)
    regular = storage_identity[0][0]
    marker_raw = _marker_bytes(target, namespace, stage, export_root)
    marker_identity = _digest(
        "marker-identity",
        {"byte_length": len(marker_raw), "byte_digest": hashlib.sha3_512(marker_raw).hexdigest()},
    )
    body: dict[str, object] = {
        "schema": "mirror-restore-publication-receipt-v1",
        "schema_version": 1,
        "publication_kind": "CREATED" if created else "ADOPTED_EXISTING",
        "target_identity": _target_identity(target),
        "export_root": _hex(export_root, "receipt-export-root"),
        "semantic_digest": image.semantic_digest,
        "byte_length": image.byte_length,
        "file_digest": image.file_digest,
        "storage_identity": {
            "dev": regular[0],
            "ino": regular[1],
            "nlink": regular[2],
            "size": regular[3],
            "mtime_ns": regular[4],
        },
        "marker_identity": marker_identity,
    }
    body["publication_operation_id"] = _digest("publication-operation", body)
    body["receipt_digest"] = _digest("publication-receipt", body)
    return body


def _read_publication_receipt(path: Path) -> tuple[dict[str, object], tuple[int, int, int, int, int]]:
    try:
        raw, identity = _read_owned_bytes(path, cap=MAX_PUBLICATION_RECEIPT_BYTES, label="publication-receipt")
        value = json.loads(raw.decode("ascii"))
        if not isinstance(value, dict) or _canonical(value) != raw:
            raise RestorePublicationVerification("restore-publication:publication-receipt-canonical")
        return value, identity
    except RestorePublicationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise_redacted(RestorePublicationVerification, "restore-publication:publication-receipt")


def _validate_direct_publication_receipt(
    receipt: Mapping[str, object],
    *,
    target: Path,
    namespace: Path,
    stage: Path,
    export_root: str,
    expected_semantic: str | None,
    storage_identity: tuple[
        tuple[tuple[int, int, int, int, int], str],
        tuple[tuple[int, int, int, int, int], str] | None,
        tuple[tuple[int, int, int, int, int], str] | None,
    ] | None,
) -> None:
    required = {
        "schema", "schema_version", "publication_kind", "target_identity", "export_root",
        "semantic_digest", "byte_length", "file_digest", "storage_identity", "marker_identity",
        "publication_operation_id", "receipt_digest",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != required:
        raise RestorePublicationVerification("restore-publication:publication-receipt-binding")
    if receipt["schema"] != "mirror-restore-publication-receipt-v1" or receipt["schema_version"] != 1:
        raise RestorePublicationVerification("restore-publication:publication-receipt-binding")
    if receipt["publication_kind"] not in {"CREATED", "ADOPTED_EXISTING"}:
        raise RestorePublicationVerification("restore-publication:publication-receipt-binding")
    if receipt["target_identity"] != _target_identity(target) or receipt["export_root"] != _hex(export_root, "receipt-export-root"):
        raise RestorePublicationVerification("restore-publication:publication-receipt-binding")
    _validate_marker(namespace / "marker.json", target, namespace, stage, export_root)
    marker_raw = _marker_bytes(target, namespace, stage, export_root)
    expected_marker_identity = _digest(
        "marker-identity",
        {"byte_length": len(marker_raw), "byte_digest": hashlib.sha3_512(marker_raw).hexdigest()},
    )
    if receipt["marker_identity"] != expected_marker_identity:
        raise RestorePublicationVerification("restore-publication:publication-receipt-marker")
    for key, label in (
        ("target_identity", "receipt-target"),
        ("export_root", "receipt-export-root"),
        ("semantic_digest", "receipt-semantic"),
        ("file_digest", "receipt-file"),
        ("marker_identity", "receipt-marker"),
        ("publication_operation_id", "receipt-operation"),
        ("receipt_digest", "receipt-digest"),
    ):
        _hex(receipt[key], label)
    if type(receipt["byte_length"]) is not int or receipt["byte_length"] <= 0 or receipt["byte_length"] > MAX_IMAGE_BYTES:
        raise RestorePublicationVerification("restore-publication:publication-receipt-binding")
    storage = receipt["storage_identity"]
    if (
        not isinstance(storage, Mapping)
        or set(storage) != {"dev", "ino", "nlink", "size", "mtime_ns"}
        or any(type(storage[key]) is not int for key in storage)
    ):
        raise RestorePublicationVerification("restore-publication:publication-receipt-storage")
    base = dict(receipt)
    receipt_digest = base.pop("receipt_digest")
    operation_id = base.pop("publication_operation_id")
    if _digest("publication-operation", base) != operation_id or _digest("publication-receipt", {**base, "publication_operation_id": operation_id}) != receipt_digest:
        raise RestorePublicationVerification("restore-publication:publication-receipt-digest")
    if expected_semantic is not None and receipt["semantic_digest"] != expected_semantic:
        raise RestorePublicationConflict("restore-publication:publication-receipt-semantic")
    if storage_identity is not None:
        if storage_identity[1] is not None or storage_identity[2] is not None:
            raise RestorePublicationVerification("restore-publication:publication-receipt-storage")
        regular, file_digest = storage_identity[0]
        expected_storage = {
            "dev": regular[0], "ino": regular[1], "nlink": regular[2],
            "size": regular[3], "mtime_ns": regular[4],
        }
        if storage != expected_storage or receipt["byte_length"] != regular[3] or receipt["file_digest"] != file_digest:
            raise RestorePublicationConflict("restore-publication:publication-receipt-storage")


def _persist_local_publication_receipt(
    namespace: Path,
    target: Path,
    stage: Path,
    export_root: str,
    receipt: Mapping[str, object],
) -> None:
    """Durably recognize a publication before its stage link is removed."""

    _validate_direct_publication_receipt(
        receipt,
        target=target,
        namespace=namespace,
        stage=stage,
        export_root=export_root,
        expected_semantic=None,
        storage_identity=None,
    )
    raw = _canonical(dict(receipt))
    if len(raw) > MAX_PUBLICATION_RECEIPT_BYTES:
        raise RestorePublicationVerification("restore-publication:publication-receipt-cap")
    path = _publication_receipt_path(namespace)
    if os.path.lexists(os.fspath(path)):
        existing, _ = _read_publication_receipt(path)
        _validate_direct_publication_receipt(
            existing,
            target=target,
            namespace=namespace,
            stage=stage,
            export_root=export_root,
            expected_semantic=None,
            storage_identity=None,
        )
        if _canonical(existing) != raw:
            raise RestorePublicationConflict("restore-publication:publication-receipt-conflict")
        return
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise RestorePublicationConflict("restore-publication:publication-receipt-race")
    except OSError:
        raise_redacted(RestorePublicationVerification, "restore-publication:publication-receipt")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                raise_redacted(RestorePublicationVerification, "restore-publication:publication-receipt")


def publish_create_only(
    destination: str | Path,
    *,
    export_root: str,
    expected_evidence: Mapping[str, object] | None = None,
    build_stage: Callable[[Path], object],
    verify_database: Callable[[Path], object],
    open_service: Callable[[Path], T] | None = None,
    result_factory: Callable[[Path], T] | None = None,
    fault_injector: Callable[[str], None] | None = None,
    publication_receipt_sink: Callable[[Mapping[str, object]], object] | None = None,
) -> T:
    """Build and atomically publish one independently verified image."""
    if (open_service is None) == (result_factory is None):
        raise RestorePublicationError("restore-publication:result-owner")
    target = _target(destination)
    export_root = _hex(export_root, "export-root")
    if expected_evidence is not None and "export_root" in expected_evidence and expected_evidence["export_root"] != export_root:
        raise RestorePublicationVerification("restore-publication:export-root-binding")
    expected_semantic = _expected_semantic(expected_evidence)
    namespace, stage, marker = _namespace_paths(target, export_root)

    def build_owned_stage(path: Path) -> None:
        try:
            build_stage(path)
        except RestorePublicationError:
            raise
        except (OSError, sqlite3.Error):
            raise_redacted(RestorePublicationVerification, "restore-publication:stage-build")

    def open_owned_service(path: Path) -> T:
        try:
            result = open_service(path) if open_service is not None else (result_factory(path) if result_factory is not None else None)
        except (OSError, sqlite3.Error):
            raise_redacted(RestorePublicationError, "restore-publication:result")
        except Exception:
            raise_redacted(RestorePublicationError, "restore-publication:result")
        if result is None:
            raise RestorePublicationError("restore-publication:result")
        return result

    with _target_lock(target):
        _scan_target_namespaces(target, namespace)
        has_stage = _reconcile_namespace(target, namespace, stage, marker, export_root)

        if os.path.lexists(os.fspath(target)):
            if has_stage:
                image, stable_storage = _recognized_owned_publication(
                    target,
                    namespace,
                    stage,
                    export_root,
                    expected_semantic,
                    verify_database=verify_database,
                    fault_injector=fault_injector,
                    publication_receipt_sink=publication_receipt_sink,
                )
            else:
                image, _evidence, stable_storage = _verify_existing(target, expected_semantic, verify_database=verify_database)
            if publication_receipt_sink is not None and not has_stage:
                publication_receipt_sink(_publication_receipt(target, namespace, stage, export_root, image, created=False, storage_identity=stable_storage))
            if os.path.lexists(os.fspath(namespace)):
                _cleanup_namespace(namespace, stage, marker)
            return open_owned_service(target)

        # A sidecar beside an absent target is never ours to clean.  Reject it
        # before creating a database or publishing a hard link.
        if any(os.path.lexists(os.fspath(_sidecar(target, suffix))) for suffix in ("-wal", "-shm")):
            raise RestorePublicationVerification("restore-publication:target-sidecar-existing")

        if not has_stage:
            _call_fault(fault_injector, "before_staging_creation")
            try:
                namespace.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError as exc:
                raise_redacted(RestorePublicationVerification, "restore-publication:staging-state")
            _ensure_marker(marker, target, namespace, stage, export_root)
            build_owned_stage(stage)
            _call_fault(fault_injector, "after_empty_staging_db_creation")

        if not stage.is_file() or stage.is_symlink():
            raise RestorePublicationVerification("restore-publication:staging-object")
        stage_image, stage_evidence = _verified_image(stage, verify_database)
        # A process can die after the fresh schema is created but before the
        # source snapshot is written.  Reuse that owned empty stage and let
        # the existing builder perform the complete restore; never treat an
        # empty image as a semantic conflict or as a valid publication.
        if expected_semantic is not None and stage_image.semantic_digest != expected_semantic:
            if not _is_empty_evidence(stage_evidence):
                _same_semantic(stage_image, expected_semantic)
            build_owned_stage(stage)
            stage_image, stage_evidence = _verified_image(stage, verify_database)
        _same_semantic(stage_image, expected_semantic)
        _checkpoint_closed_database(stage)
        _call_fault(fault_injector, "after_independent_verification_checkpoint")
        # Checkpointing changes the SQLite image.  Reverify that exact closed
        # image before it can become the destination inode.
        stage_image, _ = _verified_image(stage, verify_database)
        _same_semantic(stage_image, expected_semantic)
        _require_no_sidecars(stage, label="staging", remove_empty=False)

        _call_fault(fault_injector, "before_publish")
        created = _publish_link(stage, target)
        if created:
            image, stable_storage = _finish_linked_publication(
                target,
                namespace,
                stage,
                export_root,
                expected_semantic,
                verify_database=verify_database,
                fault_injector=fault_injector,
                publication_receipt_sink=publication_receipt_sink,
                created=True,
            )
        else:
            image, _evidence, _stable_storage = _verify_existing(target, expected_semantic, verify_database=verify_database)
            if publication_receipt_sink is not None:
                publication_receipt_sink(_publication_receipt(target, namespace, stage, export_root, image, created=False, storage_identity=_stable_storage))
        _cleanup_namespace(namespace, stage, marker)
        return open_owned_service(target)

__all__ = [
    "VerifiedRestoreImageV1", "RestorePublicationError",
    "RestorePublicationConflict", "RestorePublicationVerification", "RestorePublicationCleanupError",
    "publish_create_only", "_delete_exact_file",
    "owned_restore_workspace", "persist_workspace_receipt", "cleanup_owned_workspace", "stage_paths", "_publish_link", "_canonical", "_digest",
]
