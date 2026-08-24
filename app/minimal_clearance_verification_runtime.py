"""Single-owner, synchronous V3 verification runtime.

This module is the only composition boundary that constructs the native
verifier.  It owns no clearance state and returns aggregate exercise facts
only; queue receipts remain the independent durable evidence boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat

from app.minimal_clearance_proof_primitives import (
    NativeMinimalClearanceVerifier,
    _WORKSPACE_MARKER,
    _WORKSPACE_MARKER_NAME,
    _WORKSPACE_PREFIX,
    _workspace_parent_ok,
)
from app.minimal_clearance_verification_queue import (
    FilesystemArtifactCustody,
    QueueConfig,
    QueueIndeterminateError,
    QueueResult,
    VerificationQueueStore,
    _directory_identity,
    _is_reparse,
    _owned_directory,
)


class VerificationRuntimeError(RuntimeError):
    """A fixed-code runtime boundary error."""


def _raise_fixed(code: str) -> None:
    try:
        raise VerificationRuntimeError(code)
    except VerificationRuntimeError as fixed:
        fixed.__cause__ = None
        fixed.__context__ = None
        fixed.__suppress_context__ = True
        raise


@dataclass(frozen=True, slots=True)
class RuntimeRunResult:
    """Sanitized aggregate result; no identifiers, paths, or evidence bytes."""

    processed: int
    verified: int
    rejected: int
    held: int
    requeued: int
    indeterminate: bool
    recovered_leases: int
    scavenged_workspaces: int


def _identity(path: Path) -> tuple[int, int, int, int]:
    try:
        item = os.lstat(path)
    except (OSError, ValueError):
        _raise_fixed("runtime_identity")
    if not stat.S_ISREG(item.st_mode) or int(item.st_nlink) != 1 or _is_reparse(item):
        _raise_fixed("runtime_identity")
    return int(item.st_dev), int(item.st_ino), int(item.st_nlink), int(item.st_size)


def _marker_bytes(path: Path) -> tuple[int, int, int, bytes]:
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or int(before.st_nlink) != 1 or _is_reparse(before):
            raise OSError
        flags = int(os.O_RDONLY) | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(str(path), flags)
        try:
            opened = os.fstat(descriptor)
            value = os.read(descriptor, len(_WORKSPACE_MARKER) + 1)
        finally:
            os.close(descriptor)
        identity = (int(before.st_dev), int(before.st_ino), int(before.st_nlink))
        if (int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink)) != identity:
            raise OSError
    except (OSError, ValueError):
        _raise_fixed("runtime_workspace")
    return identity[0], identity[1], identity[2], value


def _remove_owned_workspace(directory: Path, expected_identity: tuple[int, int, int]) -> None:
    """Remove one positively identified V3 workspace, without recursion."""

    try:
        current = os.lstat(directory)
        identity = (int(current.st_dev), int(current.st_ino), int(current.st_nlink))
        if identity != expected_identity or not stat.S_ISDIR(current.st_mode) or _is_reparse(current):
            raise OSError
        marker = directory / _WORKSPACE_MARKER_NAME
        marker_dev, marker_ino, marker_nlink, marker_bytes = _marker_bytes(marker)
        if marker_bytes != _WORKSPACE_MARKER:
            raise OSError
        entries = list(directory.iterdir())
        for entry in entries:
            item = os.lstat(entry)
            if entry == marker:
                if (int(item.st_dev), int(item.st_ino), int(item.st_nlink)) != (marker_dev, marker_ino, marker_nlink) or not stat.S_ISREG(item.st_mode) or _is_reparse(item):
                    raise OSError
                continue
            if not stat.S_ISREG(item.st_mode) or int(item.st_nlink) != 1 or _is_reparse(item):
                raise OSError
            entry.unlink()
        marker.unlink()
        directory.rmdir()
    except (OSError, ValueError):
        _raise_fixed("runtime_workspace")


def _scavenge_workspaces(parent: Path) -> int:
    if not isinstance(parent, Path) or not _workspace_parent_ok(parent):
        _raise_fixed("runtime_workspace_parent")
    try:
        parent_stat = os.lstat(parent)
        parent_identity = (int(parent_stat.st_dev), int(parent_stat.st_ino), int(parent_stat.st_nlink))
        entries = list(parent.iterdir())
    except (OSError, ValueError):
        _raise_fixed("runtime_workspace_parent")
    removed = 0
    for entry in entries:
        if not entry.name.startswith(_WORKSPACE_PREFIX):
            continue
        try:
            item = os.lstat(entry)
        except (OSError, ValueError):
            _raise_fixed("runtime_workspace")
        if not stat.S_ISDIR(item.st_mode) or int(item.st_nlink) != 1 or _is_reparse(item):
            _raise_fixed("runtime_workspace")
        if _directory_identity(parent) != parent_identity:
            _raise_fixed("runtime_workspace_parent")
        _remove_owned_workspace(entry, (int(item.st_dev), int(item.st_ino), int(item.st_nlink)))
        removed += 1
    if _directory_identity(parent) != parent_identity:
        _raise_fixed("runtime_workspace_parent")
    return removed


class _RuntimeOwnership:
    """OS-released process ownership for one queue path."""

    def __init__(self, database: Path) -> None:
        if not isinstance(database, Path) or not _owned_directory(database.parent):
            _raise_fixed("runtime_owner")
        self._parent_identity = _directory_identity(database.parent)
        self._path = database.with_name(database.name + ".runtime-lock")
        self._descriptor: int | None = None
        self._locked = False
        try:
            before = None
            try:
                before = os.lstat(self._path)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                _raise_fixed("runtime_owner")
            flags = int(os.O_RDWR) | int(os.O_CREAT) | int(getattr(os, "O_BINARY", 0))
            if before is None:
                flags |= int(getattr(os, "O_EXCL", 0))
            descriptor = os.open(str(self._path), flags, 0o600)
            self._descriptor = descriptor
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or int(opened.st_nlink) != 1 or _is_reparse(opened):
                _raise_fixed("runtime_owner")
            if before is not None and (int(before.st_dev), int(before.st_ino), int(before.st_nlink)) != (int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink)):
                _raise_fixed("runtime_owner")
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\x00")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._locked = True
            if _directory_identity(database.parent) != self._parent_identity:
                _raise_fixed("runtime_owner")
        except VerificationRuntimeError:
            self.close()
            raise
        except (OSError, ValueError):
            self.close()
            _raise_fixed("runtime_owner")

    def close(self) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is None:
            return
        try:
            if self._locked:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        except (OSError, ValueError):
            _raise_fixed("runtime_owner_close")
        finally:
            self._locked = False


class MinimalClearanceVerificationRuntime:
    """One-owner bounded synchronous verification runtime."""

    def __init__(
        self,
        *,
        database: Path,
        config: QueueConfig,
        executable: Path,
        source_root: Path,
        workspace_parent: Path,
    ) -> None:
        if type(config) is not QueueConfig or not isinstance(database, Path) or not isinstance(executable, Path):
            _raise_fixed("runtime_configuration")
        if not isinstance(source_root, Path) or not isinstance(workspace_parent, Path):
            _raise_fixed("runtime_configuration")
        if not _owned_directory(source_root) or not _workspace_parent_ok(workspace_parent):
            _raise_fixed("runtime_workspace_parent")
        self._closed = False
        self._owner: _RuntimeOwnership | None = None
        self._store: VerificationQueueStore | None = None
        self._custody: FilesystemArtifactCustody | None = None
        self._verifier: NativeMinimalClearanceVerifier | None = None
        try:
            self._owner = _RuntimeOwnership(database)
            scavenged = _scavenge_workspaces(workspace_parent)
            self._store = VerificationQueueStore(path=database, config=config)
            self._custody = FilesystemArtifactCustody(source_root=source_root, workspace_parent=workspace_parent)
            self._verifier = NativeMinimalClearanceVerifier(
                executable,
                executable_sha256=config.verifier_sha256.hex(),
                workspace_parent=workspace_parent,
                timeout_seconds=30.0 * 60.0,
            )
            self._verifier.preflight()
            self._recovered_leases = self._store.recover_expired()
            self._scavenged_workspaces = scavenged
        except VerificationRuntimeError:
            self.close()
            raise
        except BaseException:
            self.close()
            _raise_fixed("runtime_startup")

    def run(self, *, max_jobs: int = 256) -> RuntimeRunResult:
        if self._closed or self._store is None or self._custody is None or self._verifier is None:
            _raise_fixed("runtime_closed")
        if type(max_jobs) is not int or not 1 <= max_jobs <= 256:
            _raise_fixed("runtime_max_jobs")
        processed = verified = rejected = held = requeued = 0
        indeterminate = False
        for _ in range(max_jobs):
            try:
                result = self._store._process_one(verifier=self._verifier, custody=self._custody)
            except QueueIndeterminateError:
                indeterminate = True
                break
            if result is None:
                break
            processed += 1
            if result.status == "VERIFIED":
                verified += 1
            elif result.status == "REJECTED":
                rejected += 1
            elif result.status == "HELD":
                held += 1
            elif result.status == "QUEUED":
                requeued += 1
            else:
                indeterminate = True
                break
        return RuntimeRunResult(
            processed=processed,
            verified=verified,
            rejected=rejected,
            held=held,
            requeued=requeued,
            indeterminate=indeterminate,
            recovered_leases=self._recovered_leases,
            scavenged_workspaces=self._scavenged_workspaces,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        store, self._store = self._store, None
        self._custody = None
        self._verifier = None
        if store is not None:
            store.close()
        owner, self._owner = self._owner, None
        if owner is not None:
            owner.close()

    def __enter__(self) -> "MinimalClearanceVerificationRuntime":
        if self._closed:
            _raise_fixed("runtime_closed")
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


__all__ = (
    "MinimalClearanceVerificationRuntime",
    "RuntimeRunResult",
    "VerificationRuntimeError",
)
