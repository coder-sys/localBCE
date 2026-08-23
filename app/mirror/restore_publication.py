"""Create-only publication of independently verified Mirror SQLite restores.

The component owning a database remains responsible for its schema and
verification.  This module owns only the filesystem boundary between a closed,
verified staging database and a destination path.  Publication never replaces
an existing path: a same-directory hard link is the atomic create-if-absent
operation, and a losing writer may return the existing file only after exact
export parity is independently checked.
"""

from __future__ import annotations

from pathlib import Path
import os
import sqlite3
import tempfile
from typing import Callable, Protocol, TypeVar


class RestorePublicationError(ValueError):
    """A bounded create-only restore publication failure."""


class RestorePublicationConflict(RestorePublicationError):
    """The destination already contains different or unverifiable state."""


class RestorePublicationVerification(RestorePublicationError):
    """The staged or published database failed its independent check."""


class RestorePublicationCleanupError(RestorePublicationError):
    """A private staging artifact could not be removed safely."""


class _Service(Protocol):
    def export_bytes(self) -> bytes: ...


T = TypeVar("T", bound=_Service)


def _target(path: str | Path) -> Path:
    try:
        value = os.fspath(path)
    except TypeError as exc:
        raise RestorePublicationError("restore-publication:target") from exc
    if isinstance(value, bytes) or not value:
        raise RestorePublicationError("restore-publication:target")
    target = Path(os.path.abspath(value))
    if target.name in ("", ".", "..") or not target.parent.is_dir() or target.parent.is_symlink() or target.is_symlink():
        raise RestorePublicationError("restore-publication:target")
    return target


def _remove_private(path: Path) -> None:
    failures: list[str] = []
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        try:
            if candidate.is_symlink():
                failures.append("symlink")
            elif candidate.exists():
                candidate.unlink()
        except OSError:
            failures.append(candidate.name)
    if failures or path.exists() or Path(str(path) + "-wal").exists() or Path(str(path) + "-shm").exists():
        raise RestorePublicationCleanupError("restore-publication:cleanup")


def _close_sqlite_artifacts(path: Path) -> None:
    """Checkpoint a closed database and require no live sidecar files."""
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, isolation_level=None, timeout=0.25)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error as exc:
        raise RestorePublicationVerification("restore-publication:checkpoint") from exc
    finally:
        if connection is not None:
            connection.close()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists():
            try:
                sidecar.unlink()
            except OSError as exc:
                raise RestorePublicationVerification("restore-publication:sidecar") from exc
        if sidecar.exists():
            raise RestorePublicationVerification("restore-publication:sidecar")


def _same_export(service: _Service, expected: bytes) -> bool:
    try:
        return service.export_bytes() == expected
    except Exception:
        return False


def _verify_existing(
    target: Path,
    expected: bytes,
    *,
    verify_database: Callable[[Path], object],
    open_service: Callable[[Path], T],
) -> T:
    if target.is_symlink():
        raise RestorePublicationConflict("restore-publication:existing-symlink")
    try:
        verify_database(target)
        service = open_service(target)
    except Exception as exc:
        raise RestorePublicationConflict("restore-publication:existing-invalid") from exc
    if not _same_export(service, expected):
        raise RestorePublicationConflict("restore-publication:existing-conflict")
    return service


def publish_create_only(
    destination: str | Path,
    expected_export: bytes,
    *,
    build_stage: Callable[[Path], object],
    verify_database: Callable[[Path], object],
    open_service: Callable[[Path], T],
    fault_injector: Callable[[str], None] | None = None,
) -> T:
    """Build, verify, and atomically publish one immutable restore target.

    ``build_stage`` must close every connection it opens before returning.
    The helper verifies the exact exported bytes both before and after the
    create-only link.  It intentionally has no overwrite or copy fallback.
    """
    if type(expected_export) is not bytes or not expected_export:
        raise RestorePublicationError("restore-publication:export")
    target = _target(destination)
    if target.exists():
        return _verify_existing(target, expected_export, verify_database=verify_database, open_service=open_service)

    descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.restore-", suffix=".db", dir=target.parent)
    os.close(descriptor)
    stage = Path(name)
    try:
        build_stage(stage)
        verify_database(stage)
        _close_sqlite_artifacts(stage)
        verify_database(stage)
        staged_service = open_service(stage)
        if not _same_export(staged_service, expected_export):
            raise RestorePublicationVerification("restore-publication:staged-export")
        _close_sqlite_artifacts(stage)
        if fault_injector is not None:
            fault_injector("before_publish")
        try:
            os.link(stage, target)
        except FileExistsError:
            return _verify_existing(target, expected_export, verify_database=verify_database, open_service=open_service)
        except OSError as exc:
            raise RestorePublicationError("restore-publication:atomic-create") from exc
        if fault_injector is not None:
            fault_injector("after_publish_before_response")
        published = _verify_existing(target, expected_export, verify_database=verify_database, open_service=open_service)
        return published
    finally:
        _remove_private(stage)


__all__ = [
    "RestorePublicationError", "RestorePublicationConflict", "RestorePublicationVerification",
    "RestorePublicationCleanupError", "publish_create_only",
]
