"""One bounded, non-mutating SQLite image gate for Mirror verifiers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat


class SQLiteSnapshotError(ValueError):
    """A SQLite path is not one bounded WAL-owned image."""


@dataclass(frozen=True)
class ReadOnlySQLiteImageV1:
    uri: str
    immutable: bool


def _regular_identity(path: Path, maximum: int, label: str) -> tuple[int, int, int, int, int]:
    try:
        value = os.lstat(os.fspath(path))
    except OSError as exc:
        raise SQLiteSnapshotError(label) from exc
    if not stat.S_ISREG(value.st_mode) or value.st_size < 0 or value.st_size > maximum:
        raise SQLiteSnapshotError(label)
    return (
        int(value.st_dev), int(value.st_ino), int(value.st_nlink),
        int(value.st_size), int(value.st_mtime_ns),
    )


def _read_header(path: Path, identity: tuple[int, int, int, int, int], label: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        opened = os.fstat(descriptor)
        opened_identity = (
            int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink),
            int(opened.st_size), int(opened.st_mtime_ns),
        )
        if opened_identity != identity:
            raise SQLiteSnapshotError(label)
        header = os.read(descriptor, 20)
        closed = os.fstat(descriptor)
        closed_identity = (
            int(closed.st_dev), int(closed.st_ino), int(closed.st_nlink),
            int(closed.st_size), int(closed.st_mtime_ns),
        )
        if closed_identity != identity:
            raise SQLiteSnapshotError(label)
    except SQLiteSnapshotError:
        raise
    except OSError as exc:
        raise SQLiteSnapshotError(label) from exc
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if _regular_identity(path, identity[3], label) != identity:
        raise SQLiteSnapshotError(label)
    return header


def read_only_image(
    path: str | Path,
    *,
    max_database_bytes: int,
    max_sidecar_bytes: int,
) -> ReadOnlySQLiteImageV1:
    """Validate one WAL image and choose the only non-mutating SQLite URI."""

    database = Path(path)
    database_identity = _regular_identity(database, max_database_bytes, "database")
    if database_identity[3] < 20:
        raise SQLiteSnapshotError("database")
    wal = Path(str(database) + "-wal")
    shm = Path(str(database) + "-shm")
    wal_exists = os.path.lexists(os.fspath(wal))
    shm_exists = os.path.lexists(os.fspath(shm))
    if wal_exists != shm_exists:
        raise SQLiteSnapshotError("sidecar-pair")
    if wal_exists:
        wal_identity = _regular_identity(wal, max_sidecar_bytes, "wal")
        shm_identity = _regular_identity(shm, max_sidecar_bytes, "shm")
    header = _read_header(database, database_identity, "database")
    if wal_exists:
        if _regular_identity(wal, max_sidecar_bytes, "wal") != wal_identity:
            raise SQLiteSnapshotError("wal")
        if _regular_identity(shm, max_sidecar_bytes, "shm") != shm_identity:
            raise SQLiteSnapshotError("shm")
    if header[:16] != b"SQLite format 3\x00" or header[18:20] != b"\x02\x02":
        raise SQLiteSnapshotError("journal-mode")
    immutable = not wal_exists
    query = "mode=ro&immutable=1" if immutable else "mode=ro"
    return ReadOnlySQLiteImageV1(database.absolute().as_uri() + "?" + query, immutable)


__all__ = ["ReadOnlySQLiteImageV1", "SQLiteSnapshotError", "read_only_image"]
