"""The explicit process writer authority for the Mirror stores.

The authority is deliberately independent from the services.  It owns the
OS-backed root/lock identity and the in-process run, mutation, and external
callback scopes used to make the three stores one bounded writer surface.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import threading
from typing import Iterator


_EXPECTED_CHILDREN = {
    "ingress.sqlite",
    "core.sqlite",
    "recovery.sqlite",
    "operational.lock",
}
_SIDECARS = ("-wal", "-shm", "-journal")
_REPARSE_POINT = 0x400


class WriterAuthorityError(ValueError):
    """A closed, substituted, contended, or incorrectly scoped authority."""


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return int(info.st_dev), int(info.st_ino), int(info.st_nlink)


def safe_root(root: str | Path) -> Path:
    if not isinstance(root, (str, Path)):
        raise WriterAuthorityError("writer:root")
    try:
        path = Path(root)
        raw = os.fspath(path)
    except (OSError, TypeError, ValueError, RuntimeError):
        raise WriterAuthorityError("writer:root") from None
    if (
        not path.is_absolute()
        or not path.anchor
        or raw.startswith("\\\\")
        or path.parent == path
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise WriterAuthorityError("writer:root")
    try:
        resolved = path.resolve(strict=True)
        info = os.lstat(path)
    except (OSError, RuntimeError):
        raise WriterAuthorityError("writer:root") from None
    if (
        os.path.normcase(os.fspath(resolved)) != os.path.normcase(os.fspath(path))
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
    ):
        raise WriterAuthorityError("writer:root")
    cursor = path
    while True:
        try:
            ancestor = os.lstat(cursor)
        except OSError:
            raise WriterAuthorityError("writer:root") from None
        if stat.S_ISLNK(ancestor.st_mode) or _is_reparse(ancestor):
            raise WriterAuthorityError("writer:root")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return path


def child_identity(path: Path, *, allow_missing: bool) -> tuple[int, int, int] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise WriterAuthorityError("writer:indeterminate") from None
    except OSError:
        raise WriterAuthorityError("writer:indeterminate") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or _is_reparse(info)
        or info.st_nlink != 1
    ):
        raise WriterAuthorityError("writer:indeterminate")
    for suffix in _SIDECARS:
        if os.path.lexists(os.fspath(path) + suffix):
            raise WriterAuthorityError("writer:indeterminate")
    return _identity(info)


def layout(root: Path, *, allow_missing_stores: bool) -> dict[str, tuple[int, int, int] | None]:
    try:
        entries = {entry.name for entry in os.scandir(root)}
    except OSError:
        raise WriterAuthorityError("writer:indeterminate") from None
    if not entries.issubset(_EXPECTED_CHILDREN):
        raise WriterAuthorityError("writer:indeterminate")
    return {
        name: child_identity(root / name, allow_missing=allow_missing_stores)
        for name in sorted(_EXPECTED_CHILDREN)
    }


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
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
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
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(_WinOverlapped),
    )
    _WIN_LockFileEx.restype = wintypes.BOOL
    _WIN_UnlockFileEx = _WIN_KERNEL32.UnlockFileEx
    _WIN_UnlockFileEx.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
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
            str(path), access,
            _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE,
            None, disposition, flags | (_WIN_FILE_ATTRIBUTE_NORMAL if not directory else 0), None,
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
            int(info.dwVolumeSerialNumber), index, int(info.nNumberOfLinks),
            size, int(info.dwFileAttributes),
        )

    def _win_lock(handle: object) -> _WinOverlapped:
        overlapped = _WinOverlapped()
        if not _WIN_LockFileEx(
            handle,
            _WIN_LOCKFILE_EXCLUSIVE_LOCK | _WIN_LOCKFILE_FAIL_IMMEDIATELY,
            0, 1, 0, ctypes.byref(overlapped),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "LockFileEx")
        return overlapped

    def _win_unlock(handle: object, overlapped: _WinOverlapped | None) -> None:
        if overlapped is not None:
            _WIN_UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped))


class _ExclusiveLock:
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
        except WriterAuthorityError:
            self.close()
            raise
        except OSError:
            self.close()
            raise WriterAuthorityError("writer:lock") from None
        except Exception:
            self.close()
            raise WriterAuthorityError("writer:lock") from None

    def _init_posix(self) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise WriterAuthorityError("writer:indeterminate")
        root_before = _identity(os.lstat(self.root))
        root_descriptor = os.open(self.root, os.O_RDONLY | directory | nofollow)
        self._root_descriptor = root_descriptor
        root_info = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_info.st_mode) or _is_reparse(root_info) or _identity(root_info) != root_before:
            raise WriterAuthorityError("writer:indeterminate")
        if _identity(os.lstat(self.root)) != root_before:
            raise WriterAuthorityError("writer:indeterminate")
        import fcntl

        try:
            fcntl.flock(root_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise WriterAuthorityError("writer:lock") from None
        self._root_locked = True
        if _identity(os.lstat(self.root)) != root_before:
            raise WriterAuthorityError("writer:indeterminate")
        self.root_identity = root_before
        name = self.path.name
        try:
            descriptor = os.open(
                name, os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow, 0o600,
                dir_fd=root_descriptor,
            )
        except FileExistsError:
            descriptor = os.open(name, os.O_RDWR | nofollow, dir_fd=root_descriptor)
        self._descriptor = descriptor
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse(opened) or opened.st_nlink != 1 or opened.st_size > 1:
            raise WriterAuthorityError("writer:indeterminate")
        relative = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(relative.st_mode)
            or _is_reparse(relative)
            or relative.st_nlink != 1
            or _identity(relative) != _identity(opened)
        ):
            raise WriterAuthorityError("writer:indeterminate")
        final = child_identity(self.path, allow_missing=False)
        if final != _identity(opened):
            raise WriterAuthorityError("writer:indeterminate")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise WriterAuthorityError("writer:lock") from None
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
            raise WriterAuthorityError("writer:indeterminate")
        if _identity(os.lstat(self.root)) != root_before:
            raise WriterAuthorityError("writer:indeterminate")
        existing = child_identity(self.path, allow_missing=True)
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
            raise WriterAuthorityError("writer:indeterminate")
        probe = _win_open(self.path, access=_WIN_GENERIC_READ, disposition=_WIN_OPEN_EXISTING)
        try:
            probed = _win_info(probe)
        finally:
            _win_close(probe)
        if opened[:3] != probed[:3]:
            raise WriterAuthorityError("writer:indeterminate")
        final = child_identity(self.path, allow_missing=False)
        if final is None or final[2] != 1:
            raise WriterAuthorityError("writer:indeterminate")
        self.identity = final
        self._overlapped = _win_lock(handle)
        if _identity(os.lstat(self.root)) != root_before:
            raise WriterAuthorityError("writer:indeterminate")
        self.root_identity = root_before

    def assert_identity(self) -> None:
        if not self._locked:
            raise WriterAuthorityError("writer:indeterminate")
        if os.name == "nt":
            if self._handle is None or self._root_handle is None:
                raise WriterAuthorityError("writer:indeterminate")
        elif self._descriptor is None or self._root_descriptor is None:
            raise WriterAuthorityError("writer:indeterminate")
        try:
            current_root = os.lstat(self.root)
            current = child_identity(self.path, allow_missing=False)
        except OSError:
            raise WriterAuthorityError("writer:indeterminate") from None
        if _identity(current_root) != self.root_identity or current != self.identity:
            raise WriterAuthorityError("writer:indeterminate")
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
                or handle_info[4] & (_WIN_FILE_ATTRIBUTE_REPARSE_POINT | _WIN_FILE_ATTRIBUTE_DIRECTORY)
                or handle_info[2] != 1
                or handle_info[3] > 1
            ):
                raise WriterAuthorityError("writer:indeterminate")
            return
        try:
            root_info = os.fstat(self._root_descriptor)
            opened = os.fstat(self._descriptor)
        except OSError:
            raise WriterAuthorityError("writer:indeterminate") from None
        if _identity(root_info) != self.root_identity or _identity(opened) != self.identity:
            raise WriterAuthorityError("writer:indeterminate")

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


class WriterAuthority:
    """One live OS-backed writer authority for one exact safe root."""

    def __init__(self, root: str | Path) -> None:
        self.root = safe_root(root)
        self.lock_path = self.root / "operational.lock"
        self._state_lock = threading.Lock()
        self._run_thread: int | None = None
        self._run_value: int | None = None
        self._mutation_thread: int | None = None
        self._external_thread: int | None = None
        self._external_depth = 0
        self._closed = False
        self._lock = _ExclusiveLock(self.root, self.lock_path)
        self.root_identity = self._lock.root_identity
        self.lock_identity = self._lock.identity
        self.assert_identity()

    @property
    def closed(self) -> bool:
        with self._state_lock:
            return self._closed

    def assert_live(self) -> None:
        with self._state_lock:
            if self._closed:
                raise WriterAuthorityError("writer:closed")
        try:
            if _identity(os.lstat(self.root)) != self.root_identity:
                raise WriterAuthorityError("writer:indeterminate")
            self._lock.assert_identity()
        except WriterAuthorityError:
            raise
        except (OSError, RuntimeError):
            raise WriterAuthorityError("writer:indeterminate") from None

    def assert_database_parent(self, path: str | Path) -> None:
        self.assert_live()
        try:
            database = Path(path)
            if (
                not database.is_absolute()
                or any(part in {".", ".."} for part in database.parts)
                or os.path.normcase(os.fspath(database.parent)) != os.path.normcase(os.fspath(self.root))
            ):
                raise WriterAuthorityError("writer:root")
        except (OSError, TypeError, ValueError, RuntimeError):
            raise WriterAuthorityError("writer:root") from None

    def assert_identity(self) -> None:
        with self._state_lock:
            if self._closed:
                raise WriterAuthorityError("writer:closed")
        try:
            if _identity(os.lstat(self.root)) != self.root_identity:
                raise WriterAuthorityError("writer:indeterminate")
            self._lock.assert_identity()
        except WriterAuthorityError:
            raise
        except (OSError, RuntimeError):
            raise WriterAuthorityError("writer:indeterminate") from None

    def current_run_time(self) -> int:
        thread = threading.get_ident()
        with self._state_lock:
            if self._closed or self._run_thread != thread or self._run_value is None:
                raise WriterAuthorityError("writer:run-time")
            return self._run_value

    def set_run_time(self, value: int) -> None:
        if type(value) is not int or value < 0:
            raise WriterAuthorityError("writer:clock")
        thread = threading.get_ident()
        with self._state_lock:
            if self._closed or self._run_thread != thread or self._run_value is not None:
                raise WriterAuthorityError("writer:run-time")
            self._run_value = value

    @contextmanager
    def run_scope(self) -> Iterator["WriterAuthority"]:
        thread = threading.get_ident()
        self.assert_live()
        with self._state_lock:
            if self._closed or self._run_thread is not None or self._mutation_thread is not None or self._external_depth:
                raise WriterAuthorityError("writer:run")
            self._run_thread = thread
            self._run_value = None
        try:
            self.assert_live()
            yield self
        finally:
            with self._state_lock:
                if self._run_thread == thread:
                    self._run_thread = None
                    self._run_value = None

    @contextmanager
    def mutation_scope(self, database_parent: str | Path | None = None) -> Iterator["WriterAuthority"]:
        thread = threading.get_ident()
        if database_parent is not None:
            self.assert_database_parent(database_parent)
        else:
            self.assert_live()
        with self._state_lock:
            if self._closed:
                raise WriterAuthorityError("writer:closed")
            if self._external_depth:
                raise WriterAuthorityError("writer:external-reentry")
            if self._mutation_thread is not None:
                raise WriterAuthorityError("writer:mutation")
            if self._run_thread is not None and self._run_thread != thread:
                raise WriterAuthorityError("writer:run")
            self._mutation_thread = thread
        try:
            self.assert_live()
            yield self
        finally:
            with self._state_lock:
                if self._mutation_thread == thread:
                    self._mutation_thread = None

    @contextmanager
    def external_scope(self) -> Iterator["WriterAuthority"]:
        thread = threading.get_ident()
        self.assert_live()
        with self._state_lock:
            if self._closed:
                raise WriterAuthorityError("writer:closed")
            if self._external_depth and self._external_thread != thread:
                raise WriterAuthorityError("writer:external")
            if self._run_thread is not None and self._run_thread != thread:
                raise WriterAuthorityError("writer:run")
            if self._mutation_thread is not None and self._mutation_thread != thread:
                raise WriterAuthorityError("writer:mutation")
            self._external_thread = thread
            self._external_depth += 1
        try:
            self.assert_live()
            yield self
        finally:
            with self._state_lock:
                if self._external_thread == thread and self._external_depth:
                    self._external_depth -= 1
                    if self._external_depth == 0:
                        self._external_thread = None

    def layout(self, *, allow_missing_stores: bool) -> dict[str, tuple[int, int, int] | None]:
        self.assert_live()
        return layout(self.root, allow_missing_stores=allow_missing_stores)

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._run_thread = None
            self._run_value = None
            self._mutation_thread = None
            self._external_thread = None
            self._external_depth = 0
        self._lock.close()

    def __enter__(self) -> "WriterAuthority":
        self.assert_live()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


__all__ = [
    "WriterAuthority",
    "WriterAuthorityError",
    "safe_root",
    "child_identity",
    "layout",
]
