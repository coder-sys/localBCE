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
    _WIN_ERROR_INVALID_HANDLE = 6
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
            if not _WIN_CloseHandle(handle):
                error = ctypes.get_last_error()
                raise OSError(error, "CloseHandle")

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
            if not _WIN_UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped)):
                error = ctypes.get_last_error()
                raise OSError(error, "UnlockFileEx")


def _win_error_code(error: BaseException) -> int:
    return int(getattr(error, "winerror", None) or getattr(error, "errno", 0) or 0)


class _ExclusiveLock:
    def __init__(self, root: Path, path: Path) -> None:
        self.root = root
        self.path = path
        self._descriptor: int | None = None
        self._root_descriptor: int | None = None
        self._descriptor_locked = False
        self._handle: object | None = None
        self._root_handle: object | None = None
        self._overlapped = None
        self._root_locked = False
        self._locked = False
        self._pending_handles: dict[int, object] = {}
        self._pending_handle_unknown: set[int] = set()
        self._handle_release_unknown = False
        self._root_handle_release_unknown = False
        self._descriptor_release_unknown = False
        self._root_descriptor_release_unknown = False
        self._release_unknown = False
        try:
            if os.name == "nt":
                self._init_windows()
            else:
                self._init_posix()
            self._locked = True
        except WriterAuthorityError:
            self._constructor_cleanup()
            raise
        except OSError:
            self._constructor_cleanup()
            raise WriterAuthorityError("writer:lock") from None
        except BaseException:
            self._constructor_cleanup()
            raise WriterAuthorityError("writer:lock") from None

    def _constructor_cleanup(self) -> None:
        try:
            self.close()
        except BaseException:
            raise WriterAuthorityError("writer:indeterminate") from None

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
        self._descriptor_locked = True
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
        probe_key = id(probe)
        self._pending_handles[probe_key] = probe
        try:
            probed = _win_info(probe)
        finally:
            try:
                _win_close(probe)
            except BaseException as error:
                if _win_error_code(error) == _WIN_ERROR_INVALID_HANDLE:
                    self._pending_handle_unknown.add(probe_key)
                    self._release_unknown = True
                raise
            else:
                self._pending_handles.pop(probe_key, None)
                self._pending_handle_unknown.discard(probe_key)
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

    def _close_posix_descriptor(self, field: str, unknown_field: str, errors: list[BaseException]) -> None:
        descriptor = getattr(self, field)
        if descriptor is None or getattr(self, unknown_field):
            return
        try:
            os.close(descriptor)
        except BaseException as error:
            setattr(self, unknown_field, True)
            self._release_unknown = True
            errors.append(error)
        else:
            setattr(self, field, None)
            if field == "_descriptor":
                self._descriptor_locked = False
            else:
                self._root_locked = False

    def _close_posix(self, errors: list[BaseException]) -> None:
        if self._root_descriptor is not None and self._root_locked and not self._root_descriptor_release_unknown:
            try:
                import fcntl

                fcntl.flock(self._root_descriptor, fcntl.LOCK_UN)
            except BaseException as error:
                errors.append(error)
            else:
                self._root_locked = False
        self._close_posix_descriptor("_root_descriptor", "_root_descriptor_release_unknown", errors)
        self._close_posix_descriptor("_descriptor", "_descriptor_release_unknown", errors)

    def _mark_windows_failure(self, error: BaseException, *, unknown_field: str, errors: list[BaseException]) -> None:
        errors.append(error)
        if _win_error_code(error) == _WIN_ERROR_INVALID_HANDLE:
            setattr(self, unknown_field, True)
            self._release_unknown = True

    def _close_windows(self, errors: list[BaseException]) -> None:
        for key, handle in tuple(self._pending_handles.items()):
            if key in self._pending_handle_unknown:
                continue
            try:
                _win_close(handle)
            except BaseException as error:
                errors.append(error)
                if _win_error_code(error) == _WIN_ERROR_INVALID_HANDLE:
                    self._pending_handle_unknown.add(key)
                    self._release_unknown = True
            else:
                self._pending_handles.pop(key, None)

        if self._handle is not None and not self._handle_release_unknown:
            unlock_failed = False
            if self._overlapped is not None:
                try:
                    _win_unlock(self._handle, self._overlapped)
                except BaseException as error:
                    unlock_failed = True
                    self._mark_windows_failure(
                        error, unknown_field="_handle_release_unknown", errors=errors,
                    )
                else:
                    self._overlapped = None
            if self._handle is not None and not self._handle_release_unknown and not unlock_failed:
                try:
                    _win_close(self._handle)
                except BaseException as error:
                    self._mark_windows_failure(
                        error, unknown_field="_handle_release_unknown", errors=errors,
                    )
                else:
                    self._handle = None
                    self._overlapped = None

        if self._root_handle is not None and not self._root_handle_release_unknown:
            try:
                _win_close(self._root_handle)
            except BaseException as error:
                self._mark_windows_failure(
                    error, unknown_field="_root_handle_release_unknown", errors=errors,
                )
            else:
                self._root_handle = None

    def close(self) -> None:
        errors: list[BaseException] = []
        if os.name == "nt":
            self._close_windows(errors)
        else:
            self._close_posix(errors)
        self._locked = bool(
            self._release_unknown
            or self._descriptor is not None
            or self._root_descriptor is not None
            or self._handle is not None
            or self._root_handle is not None
            or self._overlapped is not None
            or self._pending_handles
        )
        if self._release_unknown:
            raise WriterAuthorityError("writer:indeterminate")
        if errors:
            raise WriterAuthorityError("writer:release")


class WriterAuthority:
    """One live OS-backed writer authority for one exact safe root."""

    def __init__(self, root: str | Path) -> None:
        self.root = safe_root(root)
        self.lock_path = self.root / "operational.lock"
        self._state_lock = threading.Lock()
        self._state_changed = threading.Condition(self._state_lock)
        self._run_thread: int | None = None
        self._run_value: int | None = None
        self._mutation_thread: int | None = None
        self._external_thread: int | None = None
        self._external_depth = 0
        self._closed = False
        self._closing = False
        self._active_scopes = 0
        self._lock = _ExclusiveLock(self.root, self.lock_path)
        self.root_identity = self._lock.root_identity
        self.lock_identity = self._lock.identity
        try:
            self.assert_identity()
        except BaseException:
            try:
                self._lock.close()
            except BaseException:
                raise WriterAuthorityError("writer:indeterminate") from None
            raise

    @property
    def closed(self) -> bool:
        with self._state_lock:
            return self._closed

    def _thread_owns_scope(self, thread: int) -> bool:
        return (
            self._run_thread == thread
            or self._mutation_thread == thread
            or self._external_thread == thread
        )

    def _leave_scope(self) -> None:
        with self._state_changed:
            self._active_scopes -= 1
            if self._closing and self._active_scopes == 0 and not self._closed:
                self._finish_close_locked()
            else:
                self._state_changed.notify_all()

    def _finish_close_locked(self) -> None:
        try:
            self._lock.close()
        except BaseException:
            self._state_changed.notify_all()
            raise
        self._closed = True
        self._run_thread = None
        self._run_value = None
        self._mutation_thread = None
        self._external_thread = None
        self._external_depth = 0
        self._state_changed.notify_all()

    def assert_live(self) -> None:
        thread = threading.get_ident()
        with self._state_lock:
            if self._closed or (self._closing and not self._thread_owns_scope(thread)):
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
            if self._closed or self._closing or self._run_thread is not None or self._mutation_thread is not None or self._external_depth:
                raise WriterAuthorityError("writer:run")
            self._run_thread = thread
            self._run_value = None
            self._active_scopes += 1
        try:
            self.assert_live()
            yield self
        finally:
            with self._state_lock:
                if self._run_thread == thread:
                    self._run_thread = None
                    self._run_value = None
            self._leave_scope()

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
            if self._closing:
                raise WriterAuthorityError("writer:closed")
            if self._external_depth:
                raise WriterAuthorityError("writer:external-reentry")
            if self._mutation_thread is not None:
                raise WriterAuthorityError("writer:mutation")
            if self._run_thread is not None and self._run_thread != thread:
                raise WriterAuthorityError("writer:run")
            self._mutation_thread = thread
            self._active_scopes += 1
        try:
            self.assert_live()
            yield self
        finally:
            with self._state_lock:
                if self._mutation_thread == thread:
                    self._mutation_thread = None
            self._leave_scope()

    @contextmanager
    def external_scope(self) -> Iterator["WriterAuthority"]:
        thread = threading.get_ident()
        self.assert_live()
        with self._state_lock:
            if self._closed or self._closing:
                raise WriterAuthorityError("writer:closed")
            if self._external_depth and self._external_thread != thread:
                raise WriterAuthorityError("writer:external")
            if self._run_thread is not None and self._run_thread != thread:
                raise WriterAuthorityError("writer:run")
            if self._mutation_thread is not None and self._mutation_thread != thread:
                raise WriterAuthorityError("writer:mutation")
            self._external_thread = thread
            self._external_depth += 1
            self._active_scopes += 1
        try:
            self.assert_live()
            yield self
        finally:
            with self._state_lock:
                if self._external_thread == thread and self._external_depth:
                    self._external_depth -= 1
                    if self._external_depth == 0:
                        self._external_thread = None
            self._leave_scope()

    def layout(self, *, allow_missing_stores: bool) -> dict[str, tuple[int, int, int] | None]:
        self.assert_live()
        return layout(self.root, allow_missing_stores=allow_missing_stores)

    def close(self) -> None:
        thread = threading.get_ident()
        with self._state_changed:
            if self._closed:
                return
            self._closing = True
            if self._active_scopes and self._thread_owns_scope(thread):
                return
            while self._active_scopes:
                self._state_changed.wait()
            if self._closed:
                return
            self._finish_close_locked()

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
