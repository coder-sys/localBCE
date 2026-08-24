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
    ArtifactMetadata,
    _FilesystemArtifactCustody,
    _QueueRuntimeOwnership,
    QueueConfig,
    QueueIndeterminateError,
    _VerificationQueueStore,
    _directory_identity,
    _is_reparse,
    _owned_directory,
)
from app.minimal_clearance_verification_profile import ExperimentalPrivateZkProfile, derive_installation_id


class VerificationRuntimeError(RuntimeError):
    """A fixed-code runtime boundary error."""


_MAX_WORKSPACE_ENTRIES = 256
_MAX_WORKSPACE_BYTES = 64 * 1024 * 1024


def _raise_fixed(code: str) -> None:
    try:
        raise VerificationRuntimeError(code)
    except VerificationRuntimeError as fixed:
        fixed.__cause__ = None
        fixed.__context__ = None
        fixed.__suppress_context__ = True
        raise


def _hex_batch(value: object) -> str:
    if type(value) is not bytes or len(value) != 64:
        _raise_fixed("runtime_promotion")
    return value.hex().upper()


@dataclass(frozen=True, slots=True)
class RuntimeRunResult:
    """Sanitized aggregate result; no identifiers, paths, or evidence bytes."""
    outcome: str
    code: str | None
    accepted_count: int | None
    rejected_count: int | None
    held_count: int | None
    requeued_count: int | None
    acceptance_batch_ids: tuple[str, ...]
    acceptance_head_roots: tuple[str, ...]
    recovered_leases: int
    scavenged_workspaces: int

    @property
    def processed(self) -> int:
        return 0 if self.outcome == "INDETERMINATE" else int(self.accepted_count or 0) + int(self.rejected_count or 0) + int(self.held_count or 0) + int(self.requeued_count or 0)

    @property
    def verified(self) -> int:
        return int(self.accepted_count or 0)

    @property
    def rejected(self) -> int:
        return int(self.rejected_count or 0)

    @property
    def held(self) -> int:
        return int(self.held_count or 0)

    @property
    def requeued(self) -> int:
        return int(self.requeued_count or 0)

    @property
    def indeterminate(self) -> bool:
        return self.outcome == "INDETERMINATE"


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
        entries: list[tuple[Path, os.stat_result]] = []
        total_bytes = 0
        with os.scandir(directory) as scan:
            for entry in scan:
                if len(entries) >= _MAX_WORKSPACE_ENTRIES:
                    raise OSError
                item = entry.stat(follow_symlinks=False)
                entries.append((Path(entry.path), item))
                total_bytes += int(item.st_size)
                if total_bytes > _MAX_WORKSPACE_BYTES:
                    raise OSError
        for entry, item in entries:
            if entry == marker:
                if (int(item.st_dev), int(item.st_ino), int(item.st_nlink)) != (marker_dev, marker_ino, marker_nlink) or not stat.S_ISREG(item.st_mode) or _is_reparse(item):
                    raise OSError
                continue
            if entry.name != "artifact.bin":
                raise OSError
            if not stat.S_ISREG(item.st_mode) or int(item.st_nlink) != 1 or _is_reparse(item):
                raise OSError
            current = os.lstat(entry)
            if (int(current.st_dev), int(current.st_ino), int(current.st_nlink)) != (int(item.st_dev), int(item.st_ino), int(item.st_nlink)):
                raise OSError
            os.chmod(entry, stat.S_IRUSR | stat.S_IWUSR)
            entry.unlink()
        marker_dev2, marker_ino2, marker_nlink2, marker_bytes2 = _marker_bytes(marker)
        current_directory = os.lstat(directory)
        if (
            (int(current_directory.st_dev), int(current_directory.st_ino), int(current_directory.st_nlink)) != expected_identity
            or (marker_dev2, marker_ino2, marker_nlink2) != (marker_dev, marker_ino, marker_nlink)
            or marker_bytes2 != _WORKSPACE_MARKER
        ):
            raise OSError
        os.chmod(marker, stat.S_IRUSR | stat.S_IWUSR)
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
        entries: list[Path] = []
        with os.scandir(parent) as scan:
            for entry in scan:
                if len(entries) >= _MAX_WORKSPACE_ENTRIES:
                    raise OSError
                entries.append(Path(entry.path))
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


class MinimalClearanceVerificationRuntime:
    """One-owner bounded synchronous verification runtime."""

    def __init__(
        self,
        *,
        root: Path,
        profile: ExperimentalPrivateZkProfile,
        source_root: Path,
    ) -> None:
        if not isinstance(root, Path) or type(profile) is not ExperimentalPrivateZkProfile or not root.is_absolute() or not _owned_directory(root) or not isinstance(source_root, Path):
            _raise_fixed("runtime_configuration")
        try:
            workspace_parent = root / "workspaces"
            if not workspace_parent.exists(): workspace_parent.mkdir()
            database = root / "queue.sqlite"
            executable = profile.executable
            config = QueueConfig.from_profile(profile, queue_id="minimal-clearance-queue-v4", capacity=512, artifact_bytes_cap=512 * 1024 * 1024, installation_id=derive_installation_id(root), installation_epoch=1)
        except (OSError, ValueError):
            _raise_fixed("runtime_configuration")
        if not _owned_directory(source_root) or not _workspace_parent_ok(workspace_parent):
            _raise_fixed("runtime_workspace_parent")
        self._closed = False
        self._database_owner: _QueueRuntimeOwnership | None = None
        self._workspace_owner: _QueueRuntimeOwnership | None = None
        self._database_path = database
        self._root = root
        self._root_identity = None if root is None else _directory_identity(root)
        self._source_root = source_root
        self._source_identity = _directory_identity(source_root)
        self._workspace_parent = workspace_parent
        self._config = config
        self._store: _VerificationQueueStore | None = None
        self._custody: _FilesystemArtifactCustody | None = None
        self._verifier: NativeMinimalClearanceVerifier | None = None
        try:
            try:
                self._database_owner = _QueueRuntimeOwnership(
                    lock_path=database.with_name(database.name + ".runtime-lock"),
                    parent=database.parent,
                )
            except BaseException:
                self.close()
                _raise_fixed("runtime_owner")
            try:
                self._workspace_owner = _QueueRuntimeOwnership(
                    lock_path=workspace_parent / ".BLV3-WORKSPACE-PARENT-LOCK",
                    parent=workspace_parent,
                )
            except BaseException:
                self.close()
                _raise_fixed("runtime_owner")
            scavenged = _scavenge_workspaces(workspace_parent)
            self._store = _VerificationQueueStore(
                path=database,
                config=config,
                owner=self._database_owner,
            )
            self._recovered_leases = self._store._recover_startup_leases()
            self._promotion_batches = self._store._promote_candidates()
            self._custody = _FilesystemArtifactCustody(source_root=source_root, workspace_parent=workspace_parent)
            self._verifier = NativeMinimalClearanceVerifier(
                executable,
                executable_sha256=config.verifier_sha256.hex(),
                workspace_parent=workspace_parent,
                timeout_seconds=30.0 * 60.0,
            )
            self._verifier.preflight()
            self._scavenged_workspaces = scavenged
            self._assert_owners()
        except VerificationRuntimeError:
            self.close()
            raise
        except BaseException:
            self.close()
            _raise_fixed("runtime_startup")

    def _assert_owners(self) -> None:
        if self._closed or type(self._database_owner) is not _QueueRuntimeOwnership or type(self._workspace_owner) is not _QueueRuntimeOwnership:
            _raise_fixed("runtime_closed" if self._closed else "runtime_owner")
        try:
            self._database_owner.assert_scope(
                lock_path=self._database_path.with_name(self._database_path.name + ".runtime-lock"),
                parent=self._database_path.parent,
            )
            self._workspace_owner.assert_scope(
                lock_path=self._workspace_parent / ".BLV3-WORKSPACE-PARENT-LOCK",
                parent=self._workspace_parent,
            )
            if _directory_identity(self._source_root) != self._source_identity:
                _raise_fixed(VerificationRuntimeError("runtime_source_root"))
            if self._root is not None and _directory_identity(self._root) != self._root_identity:
                _raise_fixed(VerificationRuntimeError("runtime_root"))
        except BaseException:
            _raise_fixed("runtime_owner")

    def run(self, *, max_jobs: int = 256) -> RuntimeRunResult:
        self._assert_owners()
        if self._closed or self._store is None or self._custody is None or self._verifier is None:
            _raise_fixed("runtime_closed")
        if type(max_jobs) is not int or not 1 <= max_jobs <= 256:
            _raise_fixed("runtime_max_jobs")
        startup_batches = self._promotion_batches
        self._promotion_batches = ()
        candidate = rejected = held = requeued = 0
        indeterminate = False
        for _ in range(max_jobs):
            self._assert_owners()
            try:
                result = self._store._process_one(verifier=self._verifier, custody=self._custody)
            except QueueIndeterminateError:
                indeterminate = True
                break
            finally:
                self._assert_owners()
            if result is None:
                break
            if result.status == "CANDIDATE":
                candidate += 1
            elif result.status == "REJECTED":
                rejected += 1
            elif result.status == "HELD":
                held += 1
            elif result.status == "QUEUED":
                requeued += 1
            else:
                indeterminate = True
                break
        batches: tuple[dict[str, object], ...] = tuple(startup_batches)
        if not indeterminate:
            try:
                batches += self._store._promote_candidates()
            except QueueIndeterminateError:
                indeterminate = True
        self._assert_owners()
        if indeterminate:
            return RuntimeRunResult("INDETERMINATE", "runtime_indeterminate", None, None, None, None, (), (), self._recovered_leases, self._scavenged_workspaces)
        if candidate == rejected == held == requeued == 0 and not batches:
            return RuntimeRunResult("EMPTY", None, None, None, None, None, (), (), self._recovered_leases, self._scavenged_workspaces)
        accepted = sum(int(item.get("accepted_count", 0)) for item in batches)
        return RuntimeRunResult("ACCEPTED", None, accepted, rejected, held, requeued, tuple(_hex_batch(item.get("batch_id")) for item in batches), tuple(_hex_batch(item.get("head_root")) for item in batches), self._recovered_leases, self._scavenged_workspaces)

    def admit(self, *, job_id: str, metadata: ArtifactMetadata) -> None:
        self._assert_owners()
        if self._closed or self._store is None:
            _raise_fixed("runtime_closed")
        try:
            self._store._admit(job_id=job_id, metadata=metadata)
        finally:
            self._assert_owners()

    def _verify_integrity(self) -> None:
        self._assert_owners()
        if self._closed or self._store is None:
            _raise_fixed("runtime_closed")
        try:
            self._store._verify_integrity()
        finally:
            self._assert_owners()

    def _export_bytes(self) -> bytes:
        self._assert_owners()
        if self._closed or self._store is None:
            _raise_fixed("runtime_closed")
        try:
            return self._store._export_bytes()
        finally:
            self._assert_owners()

    def _expected_config(self) -> dict[str, object]:
        """Return the runtime-owned queue configuration for internal evidence consumers."""
        self._assert_owners()
        if self._closed:
            _raise_fixed("runtime_closed")
        return self._config.as_json()

    def support_summary(self) -> dict[str, object]:
        self._assert_owners()
        if self._closed or self._store is None:
            _raise_fixed("runtime_closed")
        try:
            return self._store._support_summary()
        finally:
            self._assert_owners()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        store, self._store = self._store, None
        self._custody = None
        self._verifier = None
        first_error: VerificationRuntimeError | None = None
        if store is not None:
            try:
                store._close()
            except BaseException:
                first_error = VerificationRuntimeError("runtime_owner")
        for attribute in ("_workspace_owner", "_database_owner"):
            owner = getattr(self, attribute)
            setattr(self, attribute, None)
            if owner is not None:
                try:
                    owner.close()
                except BaseException:
                    if first_error is None:
                        first_error = VerificationRuntimeError("runtime_owner_close")
        if first_error is not None:
            raise first_error

    def __enter__(self) -> "MinimalClearanceVerificationRuntime":
        if self._closed:
            _raise_fixed("runtime_closed")
        self._assert_owners()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


__all__ = (
    "MinimalClearanceVerificationRuntime",
    "RuntimeRunResult",
    "VerificationRuntimeError",
)
