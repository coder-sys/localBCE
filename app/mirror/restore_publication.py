"""Crash-resumable create-only publication for one Recovery V2 image pair.

Recovery owns the meaning of a verified point and its eventual ``PUBLISHED``
receipt.  This module owns only the filesystem boundary: two bounded images,
two independently verified semantic bindings, deterministic per-target locks,
same-filesystem hard links, and ownership-safe cleanup.  A published file is
never overwritten or removed by this owner.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Callable, Iterator, Mapping

from app.mirror.error_boundary import raise_redacted


MAX_IMAGE_BYTES = 128 * 1024 * 1024
MAX_MARKER_BYTES = 8192
MAX_RECEIPT_BYTES = 8192
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_NAMESPACE_ENTRIES = 8
MAX_PARENT_ENTRIES = 4096
LOCK_ATTEMPTS = 80
LOCK_SLEEP_SECONDS = 0.01
SCHEMA = "mirror-restore-pair-v1"
SCHEMA_VERSION = 1
SIDECARS = ("-wal", "-shm", "-journal")
_FAULT_HOOK: Callable[[str], None] | None = None


class RestorePublicationError(ValueError):
    """A bounded create-only restore publication failure."""


class RestorePublicationConflict(RestorePublicationError):
    """A destination, pair, or owned remnant conflicts with the request."""


class RestorePublicationVerification(RestorePublicationError):
    """An image, marker, target, or independent verifier failed."""


class RestorePublicationCleanupError(RestorePublicationError):
    """An owned staging object could not be removed safely."""


@dataclass(frozen=True)
class PublicationResultV1:
    """Opaque result for one target; no path or raw bytes leave the owner."""

    kind: str
    created_by_this_call: bool
    semantic_digest: str
    file_digest: str
    byte_length: int
    storage_identity: str

    @property
    def publication_kind(self) -> str:
        return self.kind


@dataclass(frozen=True)
class PublicationPairResultV1:
    """The two target results and the Recovery-derived pair operation ID."""

    pair_operation_id: str
    ingress: PublicationResultV1
    core: PublicationResultV1


def _fail(error_type: type[RestorePublicationError], code: str) -> None:
    raise_redacted(error_type, code)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail(RestorePublicationVerification, "restore-publication:noncanonical")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/RESTORE-PUBLICATION-V1/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _file_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _hex(value: object, code: str) -> str:
    if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
        _fail(RestorePublicationVerification, code)
    return value


def _reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _safe_parent(path: Path) -> tuple[int, int]:
    try:
        info = os.lstat(os.fspath(path))
    except OSError:
        _fail(RestorePublicationError, "restore-publication:target")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _reparse(info):
        _fail(RestorePublicationError, "restore-publication:target")
    return int(info.st_dev), int(info.st_ino)


def _regular(path: Path, *, allow_empty: bool, nlinks: tuple[int, ...]) -> tuple[int, int, int, int]:
    try:
        info = os.lstat(os.fspath(path))
    except OSError:
        _fail(RestorePublicationVerification, "restore-publication:file")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or _reparse(info) or int(info.st_nlink) not in nlinks:
        _fail(RestorePublicationVerification, "restore-publication:file")
    size = int(info.st_size)
    if size < 0 or size > MAX_IMAGE_BYTES or (size == 0 and not allow_empty):
        _fail(RestorePublicationVerification, "restore-publication:file-cap")
    return int(info.st_dev), int(info.st_ino), int(info.st_nlink), size


def _same_file_identity(first: tuple[int, int, int, int], second: tuple[int, int, int, int]) -> bool:
    return first == second


def _read_file(path: Path, *, cap: int = MAX_IMAGE_BYTES, allow_empty: bool = False, nlinks: tuple[int, ...] = (1,)) -> tuple[bytes, tuple[int, int, int, int]]:
    descriptor = -1
    try:
        before = _regular(path, allow_empty=allow_empty, nlinks=nlinks)
        if before[3] > cap:
            _fail(RestorePublicationVerification, "restore-publication:file-cap")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(os.fspath(path), flags)
        opened_stat = os.fstat(descriptor)
        opened = (int(opened_stat.st_dev), int(opened_stat.st_ino), int(opened_stat.st_nlink), int(opened_stat.st_size))
        if not _same_file_identity(before, opened):
            _fail(RestorePublicationVerification, "restore-publication:file-changed")
        chunks = bytearray()
        while len(chunks) <= cap:
            piece = os.read(descriptor, cap + 1 - len(chunks))
            if not piece:
                break
            chunks.extend(piece)
            if len(chunks) > cap:
                _fail(RestorePublicationVerification, "restore-publication:file-cap")
        after_stat = os.fstat(descriptor)
        after = (int(after_stat.st_dev), int(after_stat.st_ino), int(after_stat.st_nlink), int(after_stat.st_size))
        if not _same_file_identity(opened, after) or len(chunks) != after[3] or (not allow_empty and not chunks):
            _fail(RestorePublicationVerification, "restore-publication:file-changed")
        os.close(descriptor)
        descriptor = -1
        final = _regular(path, allow_empty=allow_empty, nlinks=nlinks)
        if not _same_file_identity(after, final):
            _fail(RestorePublicationVerification, "restore-publication:file-changed")
        return bytes(chunks), final
    except RestorePublicationError:
        raise
    except (OSError, TypeError, ValueError):
        _fail(RestorePublicationVerification, "restore-publication:file-read")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _sidecars(path: Path) -> bool:
    try:
        return any(os.path.lexists(os.fspath(path) + suffix) for suffix in SIDECARS)
    except (OSError, TypeError, ValueError):
        _fail(RestorePublicationVerification, "restore-publication:sidecar")


def _target(value: str | Path) -> Path:
    try:
        raw = os.fspath(value)
    except (OSError, TypeError, ValueError):
        _fail(RestorePublicationError, "restore-publication:target")
    if type(raw) is not str or not raw or "\x00" in raw:
        _fail(RestorePublicationError, "restore-publication:target")
    try:
        path = Path(os.path.abspath(raw))
    except (OSError, TypeError, ValueError):
        _fail(RestorePublicationError, "restore-publication:target")
    if not path.name or path.name in {".", ".."}:
        _fail(RestorePublicationError, "restore-publication:target")
    _safe_parent(path.parent)
    try:
        if os.path.lexists(os.fspath(path)) and (path.is_symlink() or path.is_dir()):
            _fail(RestorePublicationConflict, "restore-publication:target")
    except (OSError, ValueError):
        _fail(RestorePublicationConflict, "restore-publication:target")
    return path


def _target_identity(path: Path) -> str:
    try:
        material = os.path.normcase(os.path.abspath(os.fspath(path))).encode("utf-8", "strict")
    except (OSError, TypeError, UnicodeError):
        _fail(RestorePublicationError, "restore-publication:target")
    return hashlib.sha3_512(material).hexdigest()


def _semantic_safe(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> object:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > 4096 or depth > 12:
        _fail(RestorePublicationVerification, "restore-publication:evidence-cap")
    if isinstance(value, bytes):
        if len(value) > MAX_IMAGE_BYTES:
            _fail(RestorePublicationVerification, "restore-publication:evidence-cap")
        return {"byte_length": len(value), "byte_digest": _file_digest(value)}
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or len(key) > 128:
                _fail(RestorePublicationVerification, "restore-publication:evidence")
            result[key] = _semantic_safe(item, depth=depth + 1, nodes=nodes)
        return result
    if isinstance(value, (list, tuple)):
        return [_semantic_safe(item, depth=depth + 1, nodes=nodes) for item in value]
    if type(value) in {str, int, float, bool} or value is None:
        if type(value) is str and len(value) > 4096:
            _fail(RestorePublicationVerification, "restore-publication:evidence-cap")
        return value
    _fail(RestorePublicationVerification, "restore-publication:evidence")


def _semantic_digest(evidence: Mapping[str, object]) -> str:
    if not isinstance(evidence, Mapping):
        _fail(RestorePublicationVerification, "restore-publication:evidence")
    safe = _semantic_safe(evidence)
    raw = _canonical(safe)
    if len(raw) > MAX_EVIDENCE_BYTES:
        _fail(RestorePublicationVerification, "restore-publication:evidence-cap")
    return _digest("semantic", safe)


def _binding_digest(expected: Mapping[str, object]) -> str:
    if not isinstance(expected, Mapping):
        _fail(RestorePublicationVerification, "restore-publication:binding")
    return _digest("binding", _semantic_safe(expected))


def _check_binding(evidence: Mapping[str, object], expected: Mapping[str, object], code: str) -> None:
    if not isinstance(expected, Mapping) or not expected:
        _fail(RestorePublicationVerification, code)
    _semantic_safe(expected)
    for key, value in expected.items():
        if key not in evidence or evidence[key] != value:
            _fail(RestorePublicationConflict, code)


def _invoke_verifier(verifier: Callable[..., object], *images: bytes) -> Mapping[str, object]:
    try:
        evidence = verifier(*images)
    except RestorePublicationError:
        raise
    except Exception:
        _fail(RestorePublicationVerification, "restore-publication:independent-verify")
    if not isinstance(evidence, Mapping):
        _fail(RestorePublicationVerification, "restore-publication:evidence")
    return evidence


def _lock_path(target: Path) -> Path:
    return target.parent / f".mirror-restore-lock-v1-{_target_identity(target)[:32]}.lck"


def _lock_marker(target: Path) -> bytes:
    return _canonical({
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "target_identity": _target_identity(target),
        "purpose": "target-lock",
    })


def _lock_file_check(stream, target: Path, expected: bytes) -> None:
    try:
        stream.seek(0)
        raw = stream.read(MAX_MARKER_BYTES + 1)
        info = os.fstat(stream.fileno())
        current = (int(info.st_dev), int(info.st_ino), int(info.st_nlink), int(info.st_size))
        path_identity = _regular(_lock_path(target), allow_empty=True, nlinks=(1,))
    except (OSError, ValueError):
        _fail(RestorePublicationVerification, "restore-publication:lock")
    if current[:3] != path_identity[:3] or len(raw) > len(expected) or raw != expected[:len(raw)]:
        _fail(RestorePublicationVerification, "restore-publication:lock")
    if raw != expected:
        try:
            stream.seek(0)
            stream.write(expected)
            stream.truncate(len(expected))
            stream.flush()
            os.fsync(stream.fileno())
        except OSError:
            _fail(RestorePublicationVerification, "restore-publication:lock")
    try:
        stream.seek(0)
        if stream.read(len(expected)) != expected:
            _fail(RestorePublicationVerification, "restore-publication:lock")
    except OSError:
        _fail(RestorePublicationVerification, "restore-publication:lock")


def _lock_os(stream) -> None:
    for attempt in range(LOCK_ATTEMPTS):
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except (OSError, PermissionError):
            if attempt + 1 == LOCK_ATTEMPTS:
                _fail(RestorePublicationError, "restore-publication:lock-busy")
            time.sleep(LOCK_SLEEP_SECONDS)
    _fail(RestorePublicationError, "restore-publication:lock-busy")


def _unlock_os(stream) -> None:
    try:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    except (OSError, PermissionError):
        _fail(RestorePublicationCleanupError, "restore-publication:lock-release")


@contextmanager
def _target_lock(target: Path) -> Iterator[None]:
    lock = _lock_path(target)
    expected = _lock_marker(target)
    descriptor = -1
    stream = None
    try:
        if os.path.lexists(os.fspath(lock)):
            _regular(lock, allow_empty=True, nlinks=(1,))
            created = False
        else:
            created = True
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(os.fspath(lock), flags | os.O_CREAT | (os.O_EXCL if created else 0), 0o600)
        except FileExistsError:
            descriptor = os.open(os.fspath(lock), flags)
            created = False
        stream = os.fdopen(descriptor, "r+b", buffering=0)
        descriptor = -1
        _lock_os(stream)
        _lock_file_check(stream, target, expected)
        _safe_parent(target.parent)
        try:
            yield
        finally:
            _unlock_os(stream)
    except RestorePublicationError:
        raise
    except (OSError, TypeError, ValueError):
        _fail(RestorePublicationError, "restore-publication:lock")
    finally:
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                pass


@contextmanager
def _pair_locks(first: Path, second: Path) -> Iterator[None]:
    ordered = sorted((first, second), key=lambda path: (_target_identity(path), os.path.normcase(os.path.abspath(os.fspath(path)))))
    with _target_lock(ordered[0]):
        with _target_lock(ordered[1]):
            yield


def _namespace(target: Path, pair_operation_id: str) -> Path:
    return target.parent / f".mirror-restore-pair-v1-{_target_identity(target)[:32]}-{pair_operation_id[:32]}"


def _marker(target: Path, *, role: str, pair_operation_id: str, image: bytes, semantic: str, binding: str) -> bytes:
    target_identity = _target_identity(target)
    return _canonical({
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "role": role,
        "target_identity": target_identity, "pair_operation_id": pair_operation_id,
        "image_digest": _file_digest(image), "semantic_digest": semantic,
        "binding_digest": binding,
        "byte_length": len(image), "namespace_identity": _digest("namespace", {"target_identity": target_identity, "pair_operation_id": pair_operation_id}),
    })


def _namespace_identity(namespace: Path) -> tuple[int, int]:
    try:
        info = os.lstat(os.fspath(namespace))
    except OSError:
        _fail(RestorePublicationVerification, "restore-publication:namespace")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _reparse(info):
        _fail(RestorePublicationVerification, "restore-publication:namespace")
    return int(info.st_dev), int(info.st_ino)


def _namespace_entries(namespace: Path) -> set[str]:
    _namespace_identity(namespace)
    result: set[str] = set()
    try:
        for index, item in enumerate(namespace.iterdir(), start=1):
            if index > MAX_NAMESPACE_ENTRIES:
                _fail(RestorePublicationVerification, "restore-publication:namespace-cap")
            result.add(item.name)
    except RestorePublicationError:
        raise
    except OSError:
        _fail(RestorePublicationVerification, "restore-publication:namespace")
    return result


def _ensure_prefix(path: Path, expected: bytes, *, cap: int, code: str) -> None:
    if len(expected) > cap:
        _fail(RestorePublicationVerification, code)
    if os.path.lexists(os.fspath(path)):
        raw, _identity = _read_file(path, cap=cap, allow_empty=True, nlinks=(1,))
        if len(raw) > len(expected) or raw != expected[:len(raw)]:
            _fail(RestorePublicationVerification, code)
        if raw == expected:
            return
        append = expected[len(raw):]
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(os.fspath(path), flags)
            os.write(descriptor, append)
            os.fsync(descriptor)
        except OSError:
            _fail(RestorePublicationVerification, code)
        finally:
            if descriptor != -1:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        actual, _identity = _read_file(path, cap=cap, allow_empty=False, nlinks=(1,))
        if actual != expected:
            _fail(RestorePublicationVerification, code)
        return
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.write(descriptor, expected)
        os.fsync(descriptor)
    except FileExistsError:
        _ensure_prefix(path, expected, cap=cap, code=code)
        return
    except OSError:
        _fail(RestorePublicationVerification, code)
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _scan_namespaces(target: Path, current: Path) -> None:
    prefix = f".mirror-restore-pair-v1-{_target_identity(target)[:32]}-"
    try:
        for index, entry in enumerate(target.parent.iterdir(), start=1):
            if index > MAX_PARENT_ENTRIES:
                _fail(RestorePublicationVerification, "restore-publication:parent-cap")
            if entry.name.startswith(prefix) and entry != current:
                _fail(RestorePublicationConflict, "restore-publication:foreign-stage")
    except RestorePublicationError:
        raise
    except OSError:
        _fail(RestorePublicationVerification, "restore-publication:parent")


def _prepare_namespace(target: Path, pair_operation_id: str, *, role: str, image: bytes, semantic: str, binding: str) -> Path:
    namespace = _namespace(target, pair_operation_id)
    if os.path.lexists(os.fspath(namespace)):
        _namespace_identity(namespace)
    else:
        try:
            namespace.mkdir(mode=0o700)
        except FileExistsError:
            _namespace_identity(namespace)
        except OSError:
            _fail(RestorePublicationVerification, "restore-publication:namespace")
    expected_marker = _marker(target, role=role, pair_operation_id=pair_operation_id, image=image, semantic=semantic, binding=binding)
    entries = _namespace_entries(namespace)
    allowed = {"marker.json", "stage.db", "publication.json"}
    if not entries <= allowed:
        _fail(RestorePublicationVerification, "restore-publication:foreign-stage")
    _ensure_prefix(namespace / "marker.json", expected_marker, cap=MAX_MARKER_BYTES, code="restore-publication:marker")
    return namespace


def _write_stage(stage: Path, image: bytes) -> None:
    if len(image) <= 0 or len(image) > MAX_IMAGE_BYTES:
        _fail(RestorePublicationVerification, "restore-publication:image-cap")
    if _sidecars(stage):
        _fail(RestorePublicationVerification, "restore-publication:stage-sidecar")
    if os.path.lexists(os.fspath(stage)):
        raw, identity = _read_file(stage, cap=MAX_IMAGE_BYTES, allow_empty=True, nlinks=(1, 2))
        if raw and not image.startswith(raw):
            _fail(RestorePublicationConflict, "restore-publication:stage-conflict")
        if len(raw) == len(image):
            if raw != image:
                _fail(RestorePublicationConflict, "restore-publication:stage-conflict")
            return
        if identity[2] != 1:
            _fail(RestorePublicationConflict, "restore-publication:stage-ownership")
        descriptor = -1
        try:
            descriptor = os.open(os.fspath(stage), os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
            remaining = image[len(raw):]
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    _fail(RestorePublicationVerification, "restore-publication:stage-write")
                remaining = remaining[written:]
            os.fsync(descriptor)
        except RestorePublicationError:
            raise
        except OSError:
            _fail(RestorePublicationVerification, "restore-publication:stage-write")
        finally:
            if descriptor != -1:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        actual, _identity = _read_file(stage, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(1,))
        if actual != image:
            _fail(RestorePublicationVerification, "restore-publication:stage-write")
        return
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(stage), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        remaining = image
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                _fail(RestorePublicationVerification, "restore-publication:stage-write")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except FileExistsError:
        _write_stage(stage, image)
        return
    except RestorePublicationError:
        raise
    except OSError:
        _fail(RestorePublicationVerification, "restore-publication:stage-write")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _storage_identity(identity: tuple[int, int, int, int], file_digest: str) -> str:
    return _digest("storage", {"device": identity[0], "inode": identity[1], "size": identity[3], "file_digest": file_digest})


def _receipt_body(target: Path, *, role: str, pair_operation_id: str, semantic: str, binding: str, image: bytes, identity: tuple[int, int, int, int]) -> dict[str, object]:
    digest = _file_digest(image)
    body: dict[str, object] = {
        "schema": "mirror-restore-pair-receipt-v1", "schema_version": 1,
        "role": role, "pair_operation_id": pair_operation_id,
        "target_identity": _target_identity(target), "semantic_digest": semantic, "binding_digest": binding,
        "file_digest": digest, "byte_length": len(image),
        "storage_identity": _storage_identity(identity, digest),
    }
    body["receipt_digest"] = _digest("receipt", body)
    return body


def _validate_receipt(path: Path, expected: Mapping[str, object]) -> None:
    try:
        raw, _identity = _read_file(path, cap=MAX_RECEIPT_BYTES, allow_empty=False, nlinks=(1,))
        value = json.loads(raw.decode("ascii"))
    except RestorePublicationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        _fail(RestorePublicationVerification, "restore-publication:receipt")
    if not isinstance(value, dict) or value != dict(expected) or _canonical(value) != raw:
        _fail(RestorePublicationConflict, "restore-publication:receipt")
    receipt_digest = value.pop("receipt_digest", None)
    if type(receipt_digest) is not str or _digest("receipt", value) != receipt_digest:
        _fail(RestorePublicationVerification, "restore-publication:receipt")


def _persist_receipt(namespace: Path, body: Mapping[str, object]) -> None:
    expected = _canonical(dict(body))
    path = namespace / "publication.json"
    _ensure_prefix(path, expected, cap=MAX_RECEIPT_BYTES, code="restore-publication:receipt")
    _validate_receipt(path, body)


def _remove_owned(path: Path, *, expected: tuple[int, int, int, int], allow_nlinks: tuple[int, ...]) -> None:
    try:
        actual = _regular(path, allow_empty=True, nlinks=allow_nlinks)
        if actual != expected:
            _fail(RestorePublicationCleanupError, "restore-publication:cleanup")
        descriptor = os.open(os.fspath(path), os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            opened = (int(info.st_dev), int(info.st_ino), int(info.st_nlink), int(info.st_size))
            if opened != expected:
                _fail(RestorePublicationCleanupError, "restore-publication:cleanup")
        finally:
            os.close(descriptor)
        if _regular(path, allow_empty=True, nlinks=allow_nlinks) != expected:
            _fail(RestorePublicationCleanupError, "restore-publication:cleanup")
        os.unlink(os.fspath(path))
        if os.path.lexists(os.fspath(path)):
            _fail(RestorePublicationCleanupError, "restore-publication:cleanup")
    except RestorePublicationError:
        raise
    except OSError:
        _fail(RestorePublicationCleanupError, "restore-publication:cleanup")


def _cleanup_namespace(namespace: Path, target: Path, image: bytes) -> None:
    if not os.path.lexists(os.fspath(namespace)):
        return
    namespace_id = _namespace_identity(namespace)
    entries = _namespace_entries(namespace)
    if not entries <= {"marker.json", "stage.db", "publication.json"}:
        _fail(RestorePublicationCleanupError, "restore-publication:foreign-stage")
    stage = namespace / "stage.db"
    marker = namespace / "marker.json"
    receipt = namespace / "publication.json"
    if os.path.lexists(os.fspath(stage)):
        raw, identity = _read_file(stage, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(1, 2))
        if raw != image:
            _fail(RestorePublicationCleanupError, "restore-publication:cleanup")
        _remove_owned(stage, expected=identity, allow_nlinks=(1, 2))
    for path in (receipt, marker):
        if os.path.lexists(os.fspath(path)):
            cap = MAX_RECEIPT_BYTES if path == receipt else MAX_MARKER_BYTES
            _raw, identity = _read_file(path, cap=cap, allow_empty=False, nlinks=(1,))
            _remove_owned(path, expected=identity, allow_nlinks=(1,))
    try:
        if _namespace_identity(namespace) != namespace_id or _namespace_entries(namespace):
            _fail(RestorePublicationCleanupError, "restore-publication:cleanup")
        os.rmdir(os.fspath(namespace))
    except RestorePublicationError:
        raise
    except OSError:
        _fail(RestorePublicationCleanupError, "restore-publication:cleanup")


def _existing_target(target: Path, image: bytes) -> tuple[bytes, tuple[int, int, int, int]] | None:
    try:
        present = os.path.lexists(os.fspath(target))
    except (OSError, ValueError):
        _fail(RestorePublicationConflict, "restore-publication:target")
    if not present:
        if _sidecars(target):
            _fail(RestorePublicationConflict, "restore-publication:target-sidecar")
        return None
    if _sidecars(target):
        _fail(RestorePublicationConflict, "restore-publication:target-sidecar")
    raw, identity = _read_file(target, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(1, 2))
    if raw != image:
        _fail(RestorePublicationConflict, "restore-publication:target-conflict")
    return raw, identity


def _preflight_target_namespace(
    target: Path,
    image: bytes,
    *,
    role: str,
    pair_operation_id: str,
    semantic: str,
    binding: str,
    existing: tuple[bytes, tuple[int, int, int, int]] | None,
) -> None:
    """Validate an owned remnant before either member of the pair is linked."""

    namespace = _namespace(target, pair_operation_id)
    if not os.path.lexists(os.fspath(namespace)):
        return
    _namespace_identity(namespace)
    entries = _namespace_entries(namespace)
    if not entries <= {"marker.json", "stage.db", "publication.json"}:
        _fail(RestorePublicationVerification, "restore-publication:foreign-stage")
    marker = namespace / "marker.json"
    expected_marker = _marker(target, role=role, pair_operation_id=pair_operation_id, image=image, semantic=semantic, binding=binding)
    if os.path.lexists(os.fspath(marker)):
        marker_raw, _marker_identity = _read_file(marker, cap=MAX_MARKER_BYTES, allow_empty=True, nlinks=(1,))
        if len(marker_raw) > len(expected_marker) or marker_raw != expected_marker[:len(marker_raw)]:
            _fail(RestorePublicationVerification, "restore-publication:marker")
    elif existing is not None:
        _fail(RestorePublicationVerification, "restore-publication:marker")
    stage = namespace / "stage.db"
    receipt = namespace / "publication.json"
    if existing is not None:
        # A pre-existing target is adoptable only with a complete receipt or
        # an exact owned stage that can finish that receipt.  Marker-only
        # state is indeterminate and must be rejected before the other target
        # can be published.
        if "stage.db" not in entries and "publication.json" not in entries:
            _fail(RestorePublicationConflict, "restore-publication:receipt")
        if "stage.db" in entries:
            stage_raw, stage_identity = _read_file(stage, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(1, 2))
            if stage_raw != image or (stage_identity[:2] != existing[1][:2] and stage_identity[2] != 1):
                _fail(RestorePublicationConflict, "restore-publication:stage-ownership")
        if "publication.json" in entries and "stage.db" not in entries:
            _validate_receipt(receipt, _receipt_body(target, role=role, pair_operation_id=pair_operation_id, semantic=semantic, binding=binding, image=image, identity=existing[1]))
        return
    # An absent target may resume a marker or an exact-prefix stage, but a
    # receipt without its target is never a valid adoption claim.
    if "publication.json" in entries:
        _fail(RestorePublicationConflict, "restore-publication:receipt")
    if "stage.db" in entries:
        stage_raw, _stage_identity = _read_file(stage, cap=MAX_IMAGE_BYTES, allow_empty=True, nlinks=(1,))
        if not image.startswith(stage_raw):
            _fail(RestorePublicationConflict, "restore-publication:stage-conflict")


def _result(kind: str, created: bool, semantic: str, image: bytes, identity: tuple[int, int, int, int]) -> PublicationResultV1:
    if kind not in {"CREATED_THIS_CALL", "ADOPTED_EXISTING"} or type(created) is not bool:
        _fail(RestorePublicationVerification, "restore-publication:result")
    digest = _file_digest(image)
    return PublicationResultV1(kind, created, semantic, digest, len(image), _storage_identity(identity, digest))


def _fault(point: str) -> None:
    if _FAULT_HOOK is None:
        return
    try:
        _FAULT_HOOK(point)
    except RestorePublicationError:
        raise
    except Exception:
        _fail(RestorePublicationError, "restore-publication:fault")


def _publish_one(
    target: Path,
    image: bytes,
    *,
    role: str,
    pair_operation_id: str,
    semantic: str,
    verifier: Callable[..., object],
    expected: Mapping[str, object],
    existing: tuple[bytes, tuple[int, int, int, int]] | None,
) -> PublicationResultV1:
    namespace = _namespace(target, pair_operation_id)
    binding = _binding_digest(expected)
    if existing is not None:
        if not os.path.lexists(os.fspath(namespace)):
            if existing[1][2] != 1:
                _fail(RestorePublicationConflict, "restore-publication:target-ownership")
            return _result("ADOPTED_EXISTING", False, semantic, image, existing[1])
        _prepare_namespace(target, pair_operation_id, role=role, image=image, semantic=semantic, binding=binding)
        entries = _namespace_entries(namespace)
        stage = namespace / "stage.db"
        receipt = namespace / "publication.json"
        if "stage.db" in entries:
            stage_raw, stage_identity = _read_file(stage, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(1, 2))
            if stage_raw != image:
                _fail(RestorePublicationConflict, "restore-publication:stage-conflict")
            if stage_identity[:2] != existing[1][:2] and stage_identity[2] != 1:
                _fail(RestorePublicationConflict, "restore-publication:stage-ownership")
            body = _receipt_body(target, role=role, pair_operation_id=pair_operation_id, semantic=semantic, binding=binding, image=image, identity=existing[1])
            _persist_receipt(namespace, body)
        elif "publication.json" not in entries or existing[1][2] != 1:
            _fail(RestorePublicationConflict, "restore-publication:receipt")
        else:
            body = _receipt_body(target, role=role, pair_operation_id=pair_operation_id, semantic=semantic, binding=binding, image=image, identity=existing[1])
            _validate_receipt(receipt, body)
        return _result("ADOPTED_EXISTING", False, semantic, image, existing[1])

    namespace = _prepare_namespace(target, pair_operation_id, role=role, image=image, semantic=semantic, binding=binding)
    stage = namespace / "stage.db"
    _write_stage(stage, image)
    staged, _stage_identity = _read_file(stage, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(1,))
    if staged != image:
        _fail(RestorePublicationVerification, "restore-publication:stage")
    if _sidecars(stage):
        _fail(RestorePublicationVerification, "restore-publication:stage-sidecar")
    _fault(f"before_{role}_link")
    created = False
    try:
        os.link(os.fspath(stage), os.fspath(target))
        created = True
    except FileExistsError:
        created = False
    except OSError:
        if os.path.lexists(os.fspath(target)):
            created = False
        else:
            _fail(RestorePublicationError, "restore-publication:atomic-create")
    if created:
        target_raw, target_identity = _read_file(target, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(2,))
        stage_check, stage_after = _read_file(stage, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(2,))
        if target_raw != image or stage_check != image or target_identity[:2] != stage_after[:2] or target_identity[2] != 2:
            _fail(RestorePublicationConflict, "restore-publication:publication")
        body = _receipt_body(target, role=role, pair_operation_id=pair_operation_id, semantic=semantic, binding=binding, image=image, identity=target_identity)
        _persist_receipt(namespace, body)
        _fault(f"after_{role}_link")
        return _result("CREATED_THIS_CALL", True, semantic, image, target_identity)
    if _sidecars(target):
        _fail(RestorePublicationConflict, "restore-publication:target-sidecar")
    target_raw, target_identity = _read_file(target, cap=MAX_IMAGE_BYTES, allow_empty=False, nlinks=(1,))
    if target_raw != image:
        _fail(RestorePublicationConflict, "restore-publication:target-conflict")
    evidence = _invoke_verifier(verifier, image)
    _check_binding(evidence, expected, "restore-publication:binding")
    if _semantic_digest(evidence) != semantic:
        _fail(RestorePublicationConflict, "restore-publication:semantic-conflict")
    body = _receipt_body(target, role=role, pair_operation_id=pair_operation_id, semantic=semantic, binding=binding, image=image, identity=target_identity)
    _persist_receipt(namespace, body)
    return _result("ADOPTED_EXISTING", False, semantic, image, target_identity)


def publish_pair_create_only(
    *,
    ingress_target: str | Path,
    core_target: str | Path,
    ingress_image: bytes,
    core_image: bytes,
    pair_operation_id: str,
    ingress_expected: Mapping[str, object],
    core_expected: Mapping[str, object],
    verify_ingress: Callable[[bytes], object],
    verify_core: Callable[[bytes, bytes], object],
) -> PublicationPairResultV1:
    """Publish exactly two independently verified images without overwriting.

    The function never removes a target.  If an exception occurs after one
    hard link, the owned namespace and the published target remain for the
    exact retry to reconcile.  The Recovery catalog, not this filesystem
    result, owns the logical ``PUBLISHED`` state.
    """
    operation = _hex(pair_operation_id, "restore-publication:operation")
    if type(ingress_image) is not bytes or type(core_image) is not bytes or not ingress_image or not core_image:
        _fail(RestorePublicationVerification, "restore-publication:image")
    if len(ingress_image) > MAX_IMAGE_BYTES or len(core_image) > MAX_IMAGE_BYTES:
        _fail(RestorePublicationVerification, "restore-publication:image-cap")
    ingress_path = _target(ingress_target)
    core_path = _target(core_target)
    if os.path.normcase(os.path.abspath(os.fspath(ingress_path))) == os.path.normcase(os.path.abspath(os.fspath(core_path))):
        _fail(RestorePublicationConflict, "restore-publication:target-alias")
    if _safe_parent(ingress_path.parent) == _safe_parent(core_path.parent) and os.path.normcase(ingress_path.name) == os.path.normcase(core_path.name):
        _fail(RestorePublicationConflict, "restore-publication:target-alias")
    with _pair_locks(ingress_path, core_path):
        parent_ingress = _safe_parent(ingress_path.parent)
        parent_core = _safe_parent(core_path.parent)
        existing_ingress = _existing_target(ingress_path, ingress_image)
        existing_core = _existing_target(core_path, core_image)
        if existing_ingress is not None and existing_core is not None and existing_ingress[1][:2] == existing_core[1][:2]:
            _fail(RestorePublicationConflict, "restore-publication:target-alias")
        _scan_namespaces(ingress_path, _namespace(ingress_path, operation))
        _scan_namespaces(core_path, _namespace(core_path, operation))
        ingress_evidence = _invoke_verifier(verify_ingress, ingress_image)
        _check_binding(ingress_evidence, ingress_expected, "restore-publication:ingress-binding")
        ingress_semantic = _semantic_digest(ingress_evidence)
        core_evidence = _invoke_verifier(verify_core, core_image, ingress_image)
        _check_binding(core_evidence, core_expected, "restore-publication:core-binding")
        core_semantic = _semantic_digest(core_evidence)
        _preflight_target_namespace(ingress_path, ingress_image, role="ingress", pair_operation_id=operation, semantic=ingress_semantic, binding=_binding_digest(ingress_expected), existing=existing_ingress)
        _preflight_target_namespace(core_path, core_image, role="core", pair_operation_id=operation, semantic=core_semantic, binding=_binding_digest(core_expected), existing=existing_core)
        if _safe_parent(ingress_path.parent) != parent_ingress or _safe_parent(core_path.parent) != parent_core:
            _fail(RestorePublicationConflict, "restore-publication:parent")
        # Core is the dependent read-only projection.  Publish it first so a
        # partial physical pair can never expose Ingress custody without its
        # independently verified consumer-side binding.  The catalog still
        # owns the logical PUBLISHED transition, and retry never removes a
        # target already created by an earlier invocation.
        core_result = _publish_one(core_path, core_image, role="core", pair_operation_id=operation, semantic=core_semantic, verifier=lambda raw: verify_core(raw, ingress_image), expected=core_expected, existing=existing_core)
        ingress_result = _publish_one(ingress_path, ingress_image, role="ingress", pair_operation_id=operation, semantic=ingress_semantic, verifier=verify_ingress, expected=ingress_expected, existing=existing_ingress)
        _fault("before_pair_cleanup")
        _cleanup_namespace(_namespace(ingress_path, operation), ingress_path, ingress_image)
        _cleanup_namespace(_namespace(core_path, operation), core_path, core_image)
        _fault("after_pair_cleanup")
        return PublicationPairResultV1(operation, ingress_result, core_result)


__all__ = [
    "MAX_IMAGE_BYTES", "PublicationResultV1", "PublicationPairResultV1",
    "RestorePublicationError", "RestorePublicationConflict",
    "RestorePublicationVerification", "RestorePublicationCleanupError",
    "publish_pair_create_only",
]
