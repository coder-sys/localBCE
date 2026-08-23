"""One create-only, crash-recoverable publication owner for Mirror SQLite images.

Component modules own schemas, exports, and independent semantic verification.
This module owns only the filesystem boundary.  A closed and independently
verified stage is published with an atomic same-filesystem hard link; an
existing target is accepted only after one independent semantic verification.
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
import time
from typing import Callable, Mapping, Protocol, TypeVar


MAX_IMAGE_BYTES = 128 * 1024 * 1024
MAX_MARKER_BYTES = 4096
LOCK_ATTEMPTS = 40
LOCK_SLEEP_SECONDS = 0.025
STAGING_SCHEMA = "mirror-restore-publication-stage-v2"
STAGING_VERSION = 2
WORKSPACE_SCHEMA = "mirror-restore-workspace-v1"
WORKSPACE_VERSION = 1
WORKSPACE_CHILDREN = ("quarantine", "runtime")


class RestorePublicationError(ValueError):
    """A bounded create-only restore publication failure."""


class RestorePublicationConflict(RestorePublicationError):
    """The destination already contains different or unverifiable state."""


class RestorePublicationVerification(RestorePublicationError):
    """The staged or published database failed its independent check."""


class RestorePublicationCleanupError(RestorePublicationError):
    """An owned staging artifact could not be removed safely."""


class RestorePublicationInjectedFault(RestorePublicationError):
    """Test-only interruption; owned staging remains for recovery."""


class _Service(Protocol):
    def export_bytes(self) -> bytes: ...


T = TypeVar("T")


@dataclass(frozen=True)
class VerifiedRestoreImageV1:
    """Opaque semantic/file identity passed between verification and publish."""

    semantic_digest: str
    byte_length: int
    file_digest: str


@dataclass(frozen=True)
class RestorePublicationReceiptV1:
    """Bounded publication result; no path, payload, or source identifiers."""

    schema: str
    schema_version: int
    created: bool
    byte_length: int
    file_digest: str
    semantic_digest: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise RestorePublicationVerification("restore-publication:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/RESTORE-PUBLICATION-V2/" + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _file_identity(path: Path) -> tuple[int, str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RestorePublicationVerification("restore-publication:file-stat") from exc
    if size <= 0 or size > MAX_IMAGE_BYTES:
        raise RestorePublicationVerification("restore-publication:file-cap")
    digest = hashlib.sha3_512()
    try:
        with path.open("rb") as stream:
            remaining = size
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise RestorePublicationVerification("restore-publication:file-short-read")
                digest.update(chunk)
                remaining -= len(chunk)
    except OSError as exc:
        raise RestorePublicationVerification("restore-publication:file-read") from exc
    return size, digest.hexdigest()


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


def _verified_image(path: Path, verify_database: Callable[[Path], object]) -> tuple[VerifiedRestoreImageV1, Mapping[str, object]]:
    try:
        evidence = verify_database(path)
    except RestorePublicationError:
        raise
    except Exception as exc:
        raise RestorePublicationVerification("restore-publication:database") from exc
    if not isinstance(evidence, Mapping):
        raise RestorePublicationVerification("restore-publication:evidence")
    size, file_digest = _file_identity(path)
    return VerifiedRestoreImageV1(_semantic_digest(evidence), size, file_digest), evidence


def _expected_semantic(expected_evidence: Mapping[str, object] | None) -> str | None:
    if expected_evidence is None:
        return None
    return _semantic_digest(expected_evidence)


def _sidecar(path: Path, suffix: str) -> Path:
    return Path(str(path) + suffix)


def _require_no_sidecars(path: Path, *, label: str, remove_empty: bool) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = _sidecar(path, suffix)
        if not os.path.lexists(os.fspath(sidecar)):
            continue
        if sidecar.is_symlink() or sidecar.is_dir():
            raise RestorePublicationVerification(f"restore-publication:{label}-sidecar")
        try:
            size = sidecar.stat().st_size
        except OSError as exc:
            raise RestorePublicationVerification(f"restore-publication:{label}-sidecar") from exc
        if size != 0:
            raise RestorePublicationVerification(f"restore-publication:{label}-sidecar-nonempty")
        if remove_empty:
            try:
                sidecar.unlink()
            except OSError as exc:
                raise RestorePublicationVerification(f"restore-publication:{label}-sidecar") from exc
    if any(os.path.lexists(os.fspath(_sidecar(path, suffix))) for suffix in ("-wal", "-shm")):
        raise RestorePublicationVerification(f"restore-publication:{label}-sidecar")


def _checkpoint_closed_database(path: Path) -> None:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, isolation_level=None, timeout=0.25)
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
        raise RestorePublicationVerification("restore-publication:checkpoint") from exc
    finally:
        if connection is not None:
            connection.close()
    _require_no_sidecars(path, label="staging", remove_empty=True)


def _namespace_paths(target: Path, export_root: str) -> tuple[Path, Path, Path]:
    export_root = _hex(export_root, "stage-identity")
    namespace = target.parent / f".{target.name}.restore-v2-{export_root}"
    return namespace, namespace / "stage.db", namespace / "marker.json"


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
    if marker.is_symlink() or marker.is_dir() or not marker.is_file():
        raise RestorePublicationVerification("restore-publication:staging-marker")
    try:
        raw = marker.read_bytes()
    except OSError as exc:
        raise RestorePublicationVerification("restore-publication:staging-marker") from exc
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
            os.close(descriptor)


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
        size = os.fstat(stream.fileno()).st_size
    except OSError as exc:
        raise RestorePublicationVerification("restore-publication:lock-read") from exc
    if raw != expected or size != len(expected) + 1:
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
        raise RestorePublicationError("restore-publication:workspace-base") from exc
    if isinstance(value, bytes) or not value:
        raise RestorePublicationError("restore-publication:workspace-base")
    parent = Path(os.path.abspath(value))
    if parent.is_symlink() or not parent.is_dir():
        raise RestorePublicationError("restore-publication:workspace-base")
    identity = _hex(identity, "workspace-identity")
    namespace = parent / f".mirror-restore-workspace-v1-{identity}"
    return namespace, namespace / "workspace.json", namespace / "workspace.json.tmp"


def _workspace_marker_bytes(namespace: Path, identity: str) -> bytes:
    value = {
        "schema": WORKSPACE_SCHEMA,
        "schema_version": WORKSPACE_VERSION,
        "workspace_identity": _hex(identity, "workspace-identity"),
        "target_identity": _target_identity(namespace),
    }
    raw = _canonical(value)
    if len(raw) > MAX_MARKER_BYTES:
        raise RestorePublicationVerification("restore-publication:workspace-marker-cap")
    return raw


def _validate_workspace_marker(marker: Path, namespace: Path, identity: str) -> None:
    if marker.is_symlink() or marker.is_dir() or not marker.is_file():
        raise RestorePublicationVerification("restore-publication:workspace-marker")
    try:
        raw = marker.read_bytes()
    except OSError as exc:
        raise RestorePublicationVerification("restore-publication:workspace-marker") from exc
    if raw != _workspace_marker_bytes(namespace, identity):
        raise RestorePublicationVerification("restore-publication:workspace-marker-binding")


def _ensure_workspace_marker(namespace: Path, marker: Path, temporary: Path, identity: str) -> None:
    expected = _workspace_marker_bytes(namespace, identity)
    if os.path.lexists(os.fspath(marker)):
        _validate_workspace_marker(marker, namespace, identity)
        if os.path.lexists(os.fspath(temporary)):
            if temporary.is_symlink() or temporary.is_dir() or temporary.read_bytes() != expected:
                raise RestorePublicationVerification("restore-publication:workspace-marker-temp")
            temporary.unlink()
        return
    if os.path.lexists(os.fspath(temporary)):
        if temporary.is_symlink() or temporary.is_dir() or temporary.read_bytes() != expected:
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
        _validate_workspace_marker(marker, namespace, identity)
    except OSError as exc:
        raise RestorePublicationVerification("restore-publication:workspace-marker-link") from exc
    finally:
        if os.path.lexists(os.fspath(temporary)):
            if temporary.is_symlink() or temporary.is_dir():
                raise RestorePublicationVerification("restore-publication:workspace-marker-temp")
            temporary.unlink()


@contextmanager
def owned_restore_workspace(base: str | Path, identity: str):
    """Open one deterministic, marker-owned fresh-target workspace.

    The workspace is deliberately retained when the caller fails.  A later
    operation with the same state identity reacquires the same lock and lets
    each component publisher reconcile its own target-scoped stage before the
    workspace is removed.
    """

    namespace, marker, temporary = _workspace_paths(base, identity)
    with _target_lock(namespace):
        if os.path.lexists(os.fspath(namespace)) and (namespace.is_symlink() or not namespace.is_dir()):
            raise RestorePublicationVerification("restore-publication:workspace-object")
        namespace.mkdir(mode=0o700, exist_ok=True)
        entries = _namespace_entries(namespace)
        allowed = {marker.name, temporary.name, *WORKSPACE_CHILDREN}
        if not entries <= allowed:
            raise RestorePublicationVerification("restore-publication:workspace-foreign")
        _ensure_workspace_marker(namespace, marker, temporary, identity)
        for child_name in WORKSPACE_CHILDREN:
            child = namespace / child_name
            if os.path.lexists(os.fspath(child)) and (child.is_symlink() or not child.is_dir()):
                raise RestorePublicationVerification("restore-publication:workspace-child")
            child.mkdir(mode=0o700, exist_ok=True)
        yield namespace


def cleanup_owned_workspace(
    namespace: str | Path,
    identity: str,
    bindings: Mapping[str, tuple[str | Path, str]],
) -> None:
    """Remove only a completed, marker-owned fresh-target workspace."""

    namespace = Path(os.path.abspath(os.fspath(namespace)))
    expected_namespace, marker, temporary = _workspace_paths(namespace.parent, identity)
    if namespace != expected_namespace:
        raise RestorePublicationCleanupError("restore-publication:workspace-binding")
    if namespace.is_symlink() or not namespace.is_dir():
        raise RestorePublicationCleanupError("restore-publication:workspace-object")
    _validate_workspace_marker(marker, namespace, identity)
    if set(bindings) != set(WORKSPACE_CHILDREN):
        raise RestorePublicationCleanupError("restore-publication:workspace-bindings")
    if os.path.lexists(os.fspath(temporary)):
        if temporary.is_symlink() or temporary.is_dir():
            raise RestorePublicationCleanupError("restore-publication:workspace-marker-temp")
        temporary.unlink()
    for child_name in WORKSPACE_CHILDREN:
        child = namespace / child_name
        target_value, export_root = bindings[child_name]
        target = _target(target_value)
        if target.parent != child:
            raise RestorePublicationCleanupError("restore-publication:workspace-target")
        target_namespace, stage, target_marker = _namespace_paths(target, export_root)
        target_lock = _lock_path(target)
        with _target_lock(target):
            if child.is_symlink() or not child.is_dir():
                raise RestorePublicationCleanupError("restore-publication:workspace-child")
            entries = _namespace_entries(child)
            allowed = {target.name, target.name + "-wal", target.name + "-shm", target_namespace.name, target_lock.name}
            if not entries <= allowed:
                raise RestorePublicationCleanupError("restore-publication:workspace-foreign")
            if target.is_symlink() or target.is_dir():
                raise RestorePublicationCleanupError("restore-publication:workspace-target")
            if target.exists():
                _checkpoint_closed_database(target)
            if os.path.lexists(os.fspath(target_namespace)):
                if target_namespace.is_symlink() or not target_namespace.is_dir():
                    raise RestorePublicationCleanupError("restore-publication:workspace-stage-object")
                if stage.exists():
                    raise RestorePublicationCleanupError("restore-publication:workspace-stage-pending")
                _validate_marker(target_marker, target, target_namespace, stage, export_root)
                _cleanup_namespace(target_namespace, stage, target_marker)
            for suffix in ("-wal", "-shm"):
                sidecar = _sidecar(target, suffix)
                if not os.path.lexists(os.fspath(sidecar)):
                    continue
                if sidecar.is_symlink() or sidecar.is_dir() or sidecar.stat().st_size != 0:
                    raise RestorePublicationCleanupError("restore-publication:workspace-sidecar")
                sidecar.unlink()
            if target.exists():
                target.unlink()
        if os.path.lexists(os.fspath(target_lock)):
            if target_lock.is_symlink() or target_lock.is_dir():
                raise RestorePublicationCleanupError("restore-publication:workspace-lock")
            target_lock.unlink()
        child.rmdir()
    marker.unlink()
    namespace.rmdir()


def _namespace_entries(namespace: Path) -> set[str]:
    try:
        if namespace.is_symlink() or not namespace.is_dir():
            raise RestorePublicationVerification("restore-publication:staging-object")
        return {item.name for item in namespace.iterdir()}
    except RestorePublicationError:
        raise
    except OSError as exc:
        raise RestorePublicationVerification("restore-publication:staging-scan") from exc


def _scan_target_namespaces(target: Path, current: Path) -> None:
    prefix = f".{target.name}.restore-"
    try:
        candidates = list(target.parent.iterdir())
    except OSError as exc:
        raise RestorePublicationVerification("restore-publication:staging-scan") from exc
    for item in candidates:
        if not item.name.startswith(prefix):
            continue
        if item == _lock_path(target):
            continue
        if item != current:
            raise RestorePublicationConflict("restore-publication:staging-foreign")


def _cleanup_namespace(namespace: Path, stage: Path, marker: Path) -> None:
    if not os.path.lexists(os.fspath(namespace)):
        return
    entries = _namespace_entries(namespace)
    allowed = {stage.name, stage.name + "-wal", stage.name + "-shm", marker.name}
    if not entries <= allowed:
        raise RestorePublicationCleanupError("restore-publication:staging-foreign")
    for path in (_sidecar(stage, "-wal"), _sidecar(stage, "-shm"), stage, marker):
        if not os.path.lexists(os.fspath(path)):
            continue
        if path.is_symlink() or path.is_dir():
            raise RestorePublicationCleanupError("restore-publication:staging-object")
        try:
            path.unlink()
        except OSError as exc:
            raise RestorePublicationCleanupError("restore-publication:cleanup") from exc
    try:
        namespace.rmdir()
    except OSError as exc:
        raise RestorePublicationCleanupError("restore-publication:cleanup") from exc


def _reconcile_namespace(target: Path, namespace: Path, stage: Path, marker: Path, export_root: str) -> bool:
    if not os.path.lexists(os.fspath(namespace)):
        return False
    entries = _namespace_entries(namespace)
    allowed = {stage.name, stage.name + "-wal", stage.name + "-shm", marker.name}
    if not entries <= allowed:
        raise RestorePublicationVerification("restore-publication:staging-foreign")
    if marker.name not in entries:
        if entries:
            raise RestorePublicationVerification("restore-publication:staging-state")
        namespace.rmdir()
        return False
    _validate_marker(marker, target, namespace, stage, export_root)
    if stage.name not in entries:
        if any(name in entries for name in (stage.name + "-wal", stage.name + "-shm")):
            raise RestorePublicationVerification("restore-publication:staging-state")
        _cleanup_namespace(namespace, stage, marker)
        return False
    return True


def _same_semantic(image: VerifiedRestoreImageV1, expected_semantic: str | None) -> None:
    if expected_semantic is not None and image.semantic_digest != expected_semantic:
        raise RestorePublicationConflict("restore-publication:semantic-conflict")


def _is_empty_evidence(evidence: Mapping[str, object]) -> bool:
    """Recognize only the fresh schema image left by an interrupted build."""

    counters = ("artifact_count", "event_count", "receipt_count", "head_count")
    return all(evidence.get(key) == 0 for key in counters)


def _verify_existing(target: Path, expected_semantic: str | None, *, verify_database: Callable[[Path], object]) -> tuple[VerifiedRestoreImageV1, Mapping[str, object]]:
    if target.is_symlink() or target.is_dir() or not target.is_file():
        raise RestorePublicationConflict("restore-publication:existing-object")
    try:
        # Reconcile any prior read sidecars through SQLite's own checkpoint
        # result.  No sidecar is deleted while a reader/writer keeps it busy.
        _checkpoint_closed_database(target)
        image, evidence = _verified_image(target, verify_database)
        _checkpoint_closed_database(target)
    except RestorePublicationError as exc:
        raise RestorePublicationConflict("restore-publication:existing-invalid") from exc
    image = VerifiedRestoreImageV1(image.semantic_digest, *_file_identity(target))
    _same_semantic(image, expected_semantic)
    return image, evidence


def _publish_link(stage: Path, target: Path) -> bool:
    try:
        os.link(stage, target)
        return True
    except FileExistsError:
        return False
    except OSError as exc:
        if os.path.lexists(os.fspath(target)):
            return False
        raise RestorePublicationError("restore-publication:atomic-create") from exc


def _call_fault(fault_injector: Callable[[str], None] | None, point: str) -> None:
    if fault_injector is not None:
        # Existing component test ports used the shorter historical callback
        # name.  Keep that test-only compatibility alias at this shared owner;
        # publication itself still has one canonical phase name.
        if point == "after_atomic_publication_before_response":
            fault_injector("after_publish_before_response")
        fault_injector(point)


def publish_create_only_with_receipt(
    destination: str | Path,
    expected_export: bytes,
    *,
    expected_evidence: Mapping[str, object] | None = None,
    build_stage: Callable[[Path], object],
    verify_database: Callable[[Path], object],
    open_service: Callable[[Path], T] | None = None,
    result_factory: Callable[[Path], T] | None = None,
    fault_injector: Callable[[str], None] | None = None,
    publish: Callable[[Path, Path], bool] = _publish_link,
) -> tuple[T | RestorePublicationReceiptV1, RestorePublicationReceiptV1]:
    """Build and publish one image, returning a typed bounded receipt."""
    if type(expected_export) is not bytes or not expected_export:
        raise RestorePublicationError("restore-publication:export")
    target = _target(destination)
    export_root = _extract_export_root(expected_export)
    expected_semantic = _expected_semantic(expected_evidence)
    namespace, stage, marker = _namespace_paths(target, export_root)
    with _target_lock(target):
        _scan_target_namespaces(target, namespace)
        has_stage = _reconcile_namespace(target, namespace, stage, marker, export_root)

        if os.path.lexists(os.fspath(target)):
            image, _evidence = _verify_existing(target, expected_semantic, verify_database=verify_database)
            if has_stage:
                stage_image, _ = _verified_image(stage, verify_database)
                _same_semantic(stage_image, expected_semantic)
            if os.path.lexists(os.fspath(namespace)):
                _cleanup_namespace(namespace, stage, marker)
            result = open_service(target) if open_service is not None else (result_factory(target) if result_factory is not None else None)
            receipt = RestorePublicationReceiptV1("mirror-restore-publication-receipt-v1", 1, False, image.byte_length, image.file_digest, image.semantic_digest)
            return (result if result is not None else receipt), receipt

        # A sidecar beside an absent target is never ours to clean.  Reject it
        # before creating a database or publishing a hard link.
        if any(os.path.lexists(os.fspath(_sidecar(target, suffix))) for suffix in ("-wal", "-shm")):
            raise RestorePublicationVerification("restore-publication:target-sidecar-existing")

        if not has_stage:
            _call_fault(fault_injector, "before_staging_creation")
            namespace.mkdir(mode=0o700, exist_ok=True)
            if namespace.is_symlink():
                raise RestorePublicationVerification("restore-publication:staging-object")
            _ensure_marker(marker, target, namespace, stage, export_root)
            build_stage(stage)
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
            build_stage(stage)
            stage_image, stage_evidence = _verified_image(stage, verify_database)
        _same_semantic(stage_image, expected_semantic)
        _checkpoint_closed_database(stage)
        _call_fault(fault_injector, "after_independent_verification_checkpoint")
        stage_size, stage_digest = _file_identity(stage)
        stage_image = VerifiedRestoreImageV1(stage_image.semantic_digest, stage_size, stage_digest)
        _require_no_sidecars(stage, label="staging", remove_empty=False)

        _call_fault(fault_injector, "before_publish")
        created = publish(stage, target)
        if created:
            linked_size, linked_digest = _file_identity(target)
            if (linked_size, linked_digest) != (stage_image.byte_length, stage_image.file_digest):
                raise RestorePublicationVerification("restore-publication:published-image")
            stage.unlink()
            _call_fault(fault_injector, "after_atomic_publication_before_response")
            image = VerifiedRestoreImageV1(stage_image.semantic_digest, linked_size, linked_digest)
        else:
            image, _evidence = _verify_existing(target, expected_semantic, verify_database=verify_database)
        _cleanup_namespace(namespace, stage, marker)
        result = open_service(target) if open_service is not None else (result_factory(target) if result_factory is not None else None)
        receipt = RestorePublicationReceiptV1("mirror-restore-publication-receipt-v1", 1, created, image.byte_length, image.file_digest, image.semantic_digest)
        return (result if result is not None else receipt), receipt


def _extract_export_root(expected_export: bytes) -> str:
    try:
        value = json.loads(
            expected_export.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                RestorePublicationVerification("restore-publication:export-constant")
            ),
        )
        if not isinstance(value, dict) or _canonical(value) != expected_export:
            raise RestorePublicationVerification("restore-publication:export-canonical")
        root = value.get("export_root")
    except RestorePublicationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError, ValueError) as exc:
        raise RestorePublicationVerification("restore-publication:export-root") from exc
    return _hex(root, "export-root")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise RestorePublicationVerification("restore-publication:export-duplicate-key")
        value[key] = item
    return value


def publish_create_only(*args, **kwargs):
    result, _receipt = publish_create_only_with_receipt(*args, **kwargs)
    return result


__all__ = [
    "VerifiedRestoreImageV1", "RestorePublicationReceiptV1", "RestorePublicationError",
    "RestorePublicationConflict", "RestorePublicationVerification", "RestorePublicationCleanupError",
    "RestorePublicationInjectedFault", "publish_create_only", "publish_create_only_with_receipt",
    "owned_restore_workspace", "cleanup_owned_workspace", "stage_paths", "_publish_link", "_canonical", "_digest",
]
