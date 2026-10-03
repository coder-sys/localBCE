"""Windows-only containment for the native minimal-clearance verifier.

The child is created suspended, assigned to a bounded Job Object, and only
then resumed.  Its only inherited handles are the two capture pipes and, for
verification, the already-open artifact supplied as standard input.  There
is deliberately no subprocess fallback: inability to establish the boundary
is a fail-closed error.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import threading
import time

from app.minimal_clearance_resource_limits import (
    ACTIVE_PROCESS_LIMIT,
    ADMISSION_CAP_BYTES,
)


class VerifierProcessError(RuntimeError):
    """The required Windows verifier containment boundary was not established."""



_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_OBJECT_0 = 0x00000000
_INFINITE = 0xFFFFFFFF
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_LIMIT_FLAGS = (
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | _JOB_OBJECT_LIMIT_JOB_MEMORY
    | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
)
_DUPLICATE_SAME_ACCESS = 0x00000002
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007
# The pinned exe's directory is first in the loader's search order, so a DLL planted beside it would run in the
# checked file's process (safety red team L1). These make the child take System32's DLLs and nothing from a share.
_IMAGE_LOAD_POLICY = (1 << 52) | (1 << 60)  # NO_REMOTE_ALWAYS_ON | PREFER_SYSTEM32_ALWAYS_ON
_GENERIC_READ = 0x80000000
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_TYPE_DISK = 1
_FILE_NAME_NORMALIZED = 0x00000000
_VOLUME_NAME_DOS = 0x00000000
_VOLUME_NAME_GUID = 0x00000001
_VOLUME_NAME_NT = 0x00000002
_FILE_INFO_BY_HANDLE_CLASS_FILE_ID = 18
_MAX_FINAL_PATH_CHARS = 32768
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_EXECUTABLE_HASH_CHUNK_BYTES = 1 << 20
_SHA256_BYTES = 32

_VOLUME_GUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class _FileIdInfo(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_ulonglong),
        ("FileId", ctypes.c_ubyte * 16),
    ]


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _ProcessMemoryCountersEx(ctypes.Structure):
    # The Windows structure retains PagefileUsage for ABI layout, but this
    # module never interprets it as OS pagefile growth or swap I/O.
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _StartupInfo),
        ("lpAttributeList", wintypes.LPVOID),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def _win_error(label: str) -> VerifierProcessError:
    return VerifierProcessError(f"{label}:{ctypes.get_last_error()}")


def _set_job_limits(kernel32: object, job: object, job_memory_cap_bytes: int) -> None:
    limits = _JobObjectExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = _JOB_LIMIT_FLAGS
    limits.BasicLimitInformation.ActiveProcessLimit = ACTIVE_PROCESS_LIMIT
    limits.JobMemoryLimit = job_memory_cap_bytes
    if not kernel32.SetInformationJobObject(
        job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        raise _win_error("verifier_job_limits")


def _handle_number(handle: object) -> int:
    value = getattr(handle, "value", handle)
    if value is None:
        return 0
    return int(value)


def _invalid_handle(handle: object) -> bool:
    return _handle_number(handle) in (0, -1, _INVALID_HANDLE_VALUE)


class _PinnedExecutableHandle:
    __slots__ = ("_kernel32", "_handle", "_closed")

    def __init__(self, kernel32: object, handle: object) -> None:
        self._kernel32 = kernel32
        self._handle = handle
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if not self._kernel32.CloseHandle(self._handle):
                raise _win_error("verifier_executable_close")
        except VerifierProcessError:
            raise
        except BaseException:
            raise VerifierProcessError("verifier_executable_close") from None


class _PinnedExecutable:
    """Single owner for the final files and every pinned ancestor directory."""

    __slots__ = (
        "canonical_path", "nt_path", "native_volume_prefix", "dos_drive",
        "_handles", "_closed",
    )

    def __init__(
        self,
        *,
        canonical_path: str,
        nt_path: str,
        native_volume_prefix: str,
        dos_drive: str,
        handles: list[_PinnedExecutableHandle],
    ) -> None:
        self.canonical_path = canonical_path
        self.nt_path = nt_path
        self.native_volume_prefix = native_volume_prefix
        self.dos_drive = dos_drive
        self._handles = handles
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        first_error: BaseException | None = None
        while self._handles:
            handle = self._handles.pop()
            try:
                handle.close()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            if isinstance(first_error, VerifierProcessError):
                raise first_error
            raise VerifierProcessError("verifier_executable_close") from None


def _configure_executable_pin_apis(kernel32: object) -> None:
    required = (
        "CreateFileW", "GetFileType", "GetFileInformationByHandle",
        "GetFinalPathNameByHandleW", "GetFileInformationByHandleEx",
        "QueryDosDeviceW", "CompareStringOrdinal", "K32GetProcessImageFileNameW",
        "ReadFile", "CloseHandle",
    )
    for name in required:
        if not hasattr(kernel32, name):
            raise VerifierProcessError(f"verifier_api_missing:{name}")
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileType.argtypes = [wintypes.HANDLE]
    kernel32.GetFileType.restype = wintypes.DWORD
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.QueryDosDeviceW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
    ]
    kernel32.QueryDosDeviceW.restype = wintypes.DWORD
    kernel32.CompareStringOrdinal.argtypes = [
        wintypes.LPCWSTR, wintypes.INT, wintypes.LPCWSTR, wintypes.INT, wintypes.BOOL,
    ]
    kernel32.CompareStringOrdinal.restype = wintypes.INT
    kernel32.K32GetProcessImageFileNameW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD,
    ]
    kernel32.K32GetProcessImageFileNameW.restype = wintypes.DWORD
    kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD,
    ]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL


def _validate_executable_pin(
    expected_executable_size_bytes: int | None,
    expected_executable_sha256: bytes | None,
) -> None:
    if (
        type(expected_executable_size_bytes) is not int
        or expected_executable_size_bytes <= 0
        or type(expected_executable_sha256) is not bytes
        or len(expected_executable_sha256) != _SHA256_BYTES
    ):
        raise VerifierProcessError("verifier_executable_pin")


def _open_executable_file_handle(
    *, kernel32: object, path: str, label: str,
) -> _PinnedExecutableHandle:
    handle = kernel32.CreateFileW(
        path,
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    if _invalid_handle(handle):
        raise _win_error(label)
    return _PinnedExecutableHandle(kernel32, handle)


def _read_regular_file_identity(
    *,
    kernel32: object,
    pinned: _PinnedExecutableHandle,
    expected_executable_size_bytes: int,
    expected_executable_sha256: bytes | None,
    label: str,
) -> tuple[int, bytes]:
    """Check a pinned handle is a regular disk file of the pinned size.

    With ``expected_executable_sha256`` it also hashes the content through
    that handle.  ``None`` is used only for the reopen of an already hashed
    file: the first handle denies write and delete sharing and stays open
    until the child image is verified, and the caller requires the same
    volume serial and 128-bit file ID, so rehashing would re-read identical
    bytes.
    """
    information = _ByHandleFileInformation()
    if not kernel32.GetFileInformationByHandle(
        pinned._handle, ctypes.byref(information)
    ):
        raise _win_error(f"{label}_stat")
    attributes = int(information.dwFileAttributes)
    if (
        attributes & _FILE_ATTRIBUTE_DIRECTORY
        or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or int(kernel32.GetFileType(pinned._handle)) != _FILE_TYPE_DISK
    ):
        raise VerifierProcessError(f"{label}_not_regular_file")
    actual_size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
    if actual_size != expected_executable_size_bytes:
        raise VerifierProcessError(f"{label}_size")
    if expected_executable_sha256 is None:
        return _file_id_info(kernel32=kernel32, handle=pinned._handle, label=label)

    digest = hashlib.sha256()
    buffer = ctypes.create_string_buffer(_EXECUTABLE_HASH_CHUNK_BYTES)
    total = 0
    try:
        while True:
            read = wintypes.DWORD()
            if not kernel32.ReadFile(
                pinned._handle, buffer, _EXECUTABLE_HASH_CHUNK_BYTES,
                ctypes.byref(read), None,
            ):
                raise _win_error(f"{label}_read")
            count = int(read.value)
            if count > _EXECUTABLE_HASH_CHUNK_BYTES:
                raise VerifierProcessError(f"{label}_read")
            if count == 0:
                break
            total += count
            if total > expected_executable_size_bytes:
                raise VerifierProcessError(f"{label}_size")
            digest.update(buffer.raw[:count])
    finally:
        ctypes.memset(buffer, 0, _EXECUTABLE_HASH_CHUNK_BYTES)
    if total != expected_executable_size_bytes:
        raise VerifierProcessError(f"{label}_size")
    if not hmac.compare_digest(digest.digest(), expected_executable_sha256):
        raise VerifierProcessError(f"{label}_identity")
    return _file_id_info(kernel32=kernel32, handle=pinned._handle, label=label)


def _file_id_info(*, kernel32: object, handle: object, label: str) -> tuple[int, bytes]:
    information = _FileIdInfo()
    if not kernel32.GetFileInformationByHandleEx(
        handle,
        _FILE_INFO_BY_HANDLE_CLASS_FILE_ID,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise _win_error(f"{label}_file_id")
    return int(information.VolumeSerialNumber), bytes(information.FileId)


def _final_path_by_handle(*, kernel32: object, handle: object, flags: int, label: str) -> str:
    size = 512
    while True:
        if size > _MAX_FINAL_PATH_CHARS:
            raise VerifierProcessError(label)
        buffer = ctypes.create_unicode_buffer(size)
        length = int(kernel32.GetFinalPathNameByHandleW(
            handle, buffer, size, flags,
        ))
        if length == 0:
            raise _win_error(label)
        if length < size:
            return buffer.value
        if size == _MAX_FINAL_PATH_CHARS:
            raise VerifierProcessError(f"{label}_truncated")
        size = min(_MAX_FINAL_PATH_CHARS, max(size * 2, length + 1))


_BACKSLASH = chr(92)


def _canonical_volume_path(path: str) -> tuple[str, str, list[str]]:
    marker = _BACKSLASH * 2 + "?" + _BACKSLASH + "Volume{"
    if not path.startswith(marker) or "/" in path:
        raise VerifierProcessError("verifier_executable_final_path")
    guid_start = len(marker)
    guid_end = path.find("}" + _BACKSLASH, guid_start)
    if guid_end < 0:
        raise VerifierProcessError("verifier_executable_final_path")
    guid = path[guid_start:guid_end]
    if not _VOLUME_GUID_RE.fullmatch(guid):
        raise VerifierProcessError("verifier_executable_final_path")
    prefix = path[:guid_end + 2]
    relative = path[guid_end + 2:]
    components = relative.split(_BACKSLASH)
    if not components or any(
        not component or component in {".", ".."} or "\x00" in component
        for component in components
    ):
        raise VerifierProcessError("verifier_executable_final_path")
    directory_components = components[:-1]
    directories = [prefix]
    for index in range(1, len(directory_components) + 1):
        directories.append(prefix + _BACKSLASH.join(directory_components[:index]))
    parent = directories[-1]
    return path, parent, directories


def _canonical_native_path(path: str) -> tuple[str, str]:
    match = re.fullmatch(
        rf"({_BACKSLASH * 2}Device{_BACKSLASH * 2}HarddiskVolume[0-9]+){_BACKSLASH * 2}(.+)",
        path,
        re.IGNORECASE,
    )
    if match is None or "/" in path:
        raise VerifierProcessError("verifier_executable_nt_path")
    native_volume_prefix = match.group(1)
    relative = match.group(2)
    components = relative.split(_BACKSLASH)
    if not components or any(
        not component or component in {".", ".."} or "\x00" in component
        for component in components
    ):
        raise VerifierProcessError("verifier_executable_nt_path")
    return path, native_volume_prefix


def _canonical_dos_path(path: str) -> tuple[str, str, str]:
    marker = _BACKSLASH * 2 + "?" + _BACKSLASH
    if not path.startswith(marker) or len(path) < len(marker) + 4:
        raise VerifierProcessError("verifier_executable_dos_path")
    drive = path[len(marker)]
    if not ("A" <= drive <= "Z" or "a" <= drive <= "z"):
        raise VerifierProcessError("verifier_executable_dos_path")
    if path[len(marker) + 1:len(marker) + 3] != ":" + _BACKSLASH:
        raise VerifierProcessError("verifier_executable_dos_path")
    relative = path[len(marker) + 3:]
    components = relative.split(_BACKSLASH)
    if not components or any(
        not component or component in {".", ".."} or "\x00" in component
        for component in components
    ):
        raise VerifierProcessError("verifier_executable_dos_path")
    directory_components = components[:-1]
    prefix = f"{marker}{drive}:{_BACKSLASH}"
    directories = [prefix]
    for index in range(1, len(directory_components) + 1):
        directories.append(prefix + _BACKSLASH.join(directory_components[:index]))
    return path, directories[-1], f"{drive}:"


def _query_dos_device_mapping(
    *, kernel32: object, drive: str, native_volume_prefix: str,
) -> None:
    size = 256
    while True:
        if size > _MAX_FINAL_PATH_CHARS:
            raise VerifierProcessError("verifier_drive_mapping_truncated")
        buffer = ctypes.create_unicode_buffer(size)
        length = int(kernel32.QueryDosDeviceW(drive, buffer, size))
        if length == 0:
            raise _win_error("verifier_drive_mapping")
        if length >= size:
            if size == _MAX_FINAL_PATH_CHARS:
                raise VerifierProcessError("verifier_drive_mapping_truncated")
            size = min(_MAX_FINAL_PATH_CHARS, max(size * 2, length + 1))
            continue
        mapping = buffer.value
        raw = ctypes.wstring_at(buffer, size)
        first_terminator = raw.find("\x00")
        if (
            first_terminator < 0
            or mapping != native_volume_prefix
            or any(character != "\x00" for character in raw[first_terminator:])
        ):
            raise VerifierProcessError("verifier_drive_mapping")
        return


def _process_image_path(*, kernel32: object, process_handle: object) -> str:
    size = 512
    while True:
        if size > _MAX_FINAL_PATH_CHARS:
            raise VerifierProcessError("verifier_child_image_truncated")
        buffer = ctypes.create_unicode_buffer(size)
        length = int(kernel32.K32GetProcessImageFileNameW(process_handle, buffer, size))
        if length == 0:
            raise _win_error("verifier_child_image")
        if length >= size:
            if size == _MAX_FINAL_PATH_CHARS:
                raise VerifierProcessError("verifier_child_image_truncated")
            size = min(_MAX_FINAL_PATH_CHARS, max(size * 2, length + 1))
            continue
        path = buffer.value
        if len(path) != length:
            raise VerifierProcessError("verifier_child_image_truncated")
        return path


def _ordinal_equal(
    *, kernel32: object, first: str, second: str, label: str,
) -> bool:
    comparison = int(kernel32.CompareStringOrdinal(first, -1, second, -1, True))
    if comparison == 0:
        raise _win_error(label)
    return comparison == 2


def _verify_suspended_child_image(
    *, kernel32: object, process_handle: object, expected_native_path: str,
    native_volume_prefix: str,
) -> None:
    observed = _process_image_path(kernel32=kernel32, process_handle=process_handle)
    try:
        _observed_path, observed_prefix = _canonical_native_path(observed)
    except VerifierProcessError:
        raise VerifierProcessError("verifier_child_image_path") from None
    if not _ordinal_equal(
        kernel32=kernel32,
        first=observed_prefix,
        second=native_volume_prefix,
        label="verifier_child_image_volume_compare",
    ):
        raise VerifierProcessError("verifier_child_image_volume")
    if not _ordinal_equal(
        kernel32=kernel32,
        first=observed,
        second=expected_native_path,
        label="verifier_child_image_compare",
    ):
        raise VerifierProcessError("verifier_child_image_identity")


def _open_pinned_directory(
    *, kernel32: object, path: str,
) -> _PinnedExecutableHandle:
    handle = kernel32.CreateFileW(
        path,
        _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if _invalid_handle(handle):
        raise _win_error("verifier_executable_directory_open")
    pinned = _PinnedExecutableHandle(kernel32, handle)
    try:
        information = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(
            handle, ctypes.byref(information)
        ):
            raise _win_error("verifier_executable_directory_stat")
        attributes = int(information.dwFileAttributes)
        if (
            not attributes & _FILE_ATTRIBUTE_DIRECTORY
            or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or int(kernel32.GetFileType(handle)) != _FILE_TYPE_DISK
        ):
            raise VerifierProcessError("verifier_executable_directory_not_regular")
        return pinned
    except BaseException:
        pinned.close()
        raise


def _open_pinned_executable(
    *,
    kernel32: object,
    executable: Path,
    expected_executable_size_bytes: int,
    expected_executable_sha256: bytes,
) -> _PinnedExecutable:
    """Atomically bind the verified executable path to the launched image."""

    _configure_executable_pin_apis(kernel32)
    _validate_executable_pin(expected_executable_size_bytes, expected_executable_sha256)
    if not isinstance(executable, Path) or not executable.is_absolute():
        raise VerifierProcessError("verifier_executable_path")
    handles: list[_PinnedExecutableHandle] = []
    try:
        original = _open_executable_file_handle(
            kernel32=kernel32, path=str(executable), label="verifier_executable_open",
        )
        handles.append(original)
        original_id = _read_regular_file_identity(
            kernel32=kernel32,
            pinned=original,
            expected_executable_size_bytes=expected_executable_size_bytes,
            expected_executable_sha256=expected_executable_sha256,
            label="verifier_executable",
        )
        volume_guid_path = _final_path_by_handle(
            kernel32=kernel32,
            handle=original._handle,
            flags=_FILE_NAME_NORMALIZED | _VOLUME_NAME_GUID,
            label="verifier_executable_final_path",
        )
        volume_guid_path, _volume_parent, directory_paths = _canonical_volume_path(
            volume_guid_path,
        )
        nt_path = _final_path_by_handle(
            kernel32=kernel32,
            handle=original._handle,
            flags=_FILE_NAME_NORMALIZED | _VOLUME_NAME_NT,
            label="verifier_executable_nt_path",
        )
        nt_path, native_volume_prefix = _canonical_native_path(nt_path)
        dos_path = _final_path_by_handle(
            kernel32=kernel32,
            handle=original._handle,
            flags=_FILE_NAME_NORMALIZED | _VOLUME_NAME_DOS,
            label="verifier_executable_dos_path",
        )
        dos_path, _dos_parent, dos_drive = _canonical_dos_path(dos_path)
        for directory_path in directory_paths:
            handles.append(_open_pinned_directory(kernel32=kernel32, path=directory_path))
        reopened = _open_executable_file_handle(
            kernel32=kernel32, path=dos_path,
            label="verifier_executable_reopen",
        )
        handles.append(reopened)
        reopened_id = _read_regular_file_identity(
            kernel32=kernel32,
            pinned=reopened,
            expected_executable_size_bytes=expected_executable_size_bytes,
            expected_executable_sha256=None,
            label="verifier_executable_reopen",
        )
        if reopened_id != original_id:
            raise VerifierProcessError("verifier_executable_file_id")
        _query_dos_device_mapping(
            kernel32=kernel32,
            drive=dos_drive,
            native_volume_prefix=native_volume_prefix,
        )
        return _PinnedExecutable(
            canonical_path=dos_path,
            nt_path=nt_path,
            native_volume_prefix=native_volume_prefix,
            dos_drive=dos_drive,
            handles=handles,
        )
    except BaseException:
        _PinnedExecutable(
            canonical_path="",
            nt_path="",
            native_volume_prefix="",
            dos_drive="",
            handles=handles,
        ).close()
        raise


def _quote_argument(value: str) -> str:
    if "\x00" in value:
        raise VerifierProcessError("verifier_argument_nul")
    if value and not any(char in value for char in " \t\""):
        return value
    backslashes = 0
    output = ['"']
    for char in value:
        if char == "\\":
            backslashes += 1
        elif char == '"':
            output.append("\\" * (backslashes * 2 + 1))
            output.append('"')
            backslashes = 0
        else:
            output.append("\\" * backslashes)
            output.append(char)
            backslashes = 0
    output.append("\\" * (backslashes * 2))
    output.append('"')
    return "".join(output)


def _environment_block(workspace: Path) -> ctypes.Array:
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    windir = os.environ.get("WINDIR") or system_root
    if not system_root or not windir:
        raise VerifierProcessError("verifier_environment_system_root")
    system32 = str(Path(system_root) / "System32")
    values = {
        "SystemRoot": system_root,
        "WINDIR": windir,
        "PATH": system32,
        "LEAN_ABORT_ON_PANIC": "1",  # a Lean panic must kill the process, never continue with a default value
        "TEMP": str(workspace),
        "TMP": str(workspace),
    }
    block = "\0".join(f"{key}={values[key]}" for key in sorted(values, key=str.upper)) + "\0\0"
    return ctypes.create_unicode_buffer(block)


def _is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _verifier_workspace_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int]:
    """Return stable containment identity bits, excluding volatile Windows flags."""

    attributes = int(getattr(metadata, "st_file_attributes", 0))
    # CPython can expose transient/provider-specific bits in this field.  The
    # containment boundary only relies on directory and reparse state; device,
    # inode, link count, and the entry-name snapshot provide the other identity
    # checks.  Reparse state is still rejected by the caller on every snapshot.
    stable_attributes = attributes & (
        _FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT
    )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_nlink),
        stable_attributes,
    )


def _verifier_workspace_snapshot(
    workspace: Path,
) -> tuple[tuple[int, int, int, int], tuple[str, ...]]:
    if not isinstance(workspace, Path) or not workspace.is_absolute():
        raise VerifierProcessError("verifier_workspace") from None
    try:
        if not workspace.is_dir() or _is_reparse_point(workspace):
            raise VerifierProcessError("verifier_workspace") from None
        metadata = os.lstat(workspace)
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or attributes & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", _FILE_ATTRIBUTE_REPARSE_POINT
            )
        ):
            raise VerifierProcessError("verifier_workspace") from None
        entries = tuple(sorted(entry.name for entry in workspace.iterdir()))
    except VerifierProcessError:
        raise
    except OSError:
        raise VerifierProcessError("verifier_workspace") from None
    identity = _verifier_workspace_identity(metadata)
    return identity, entries


def _create_output_pipe() -> tuple[int, int, int]:
    try:
        read_descriptor, write_descriptor = os.pipe()
    except OSError:
        raise VerifierProcessError("verifier_output_create") from None
    try:
        import msvcrt

        handle = msvcrt.get_osfhandle(write_descriptor)
        os.set_handle_inheritable(handle, True)
        return read_descriptor, write_descriptor, handle
    except BaseException:
        try:
            os.close(read_descriptor)
        finally:
            os.close(write_descriptor)
        raise VerifierProcessError("verifier_output_inherit") from None


def _close_parent_descriptors_once(descriptors: list[int]) -> None:
    """Close every owned parent descriptor exactly once and fail closed."""

    first_error: OSError | None = None
    while descriptors:
        descriptor = descriptors.pop()
        try:
            os.close(descriptor)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise VerifierProcessError("verifier_output_close") from None


def _create_process_with_owned_output_handles(
    *,
    kernel32: object,
    executable: str | Path,
    current_directory: str | None = None,
    output_handles: tuple[int, int],
    stdin_handle: int | None = None,
    parent_descriptors: list[int],
    startup: _StartupInfoEx,
    environment: ctypes.Array,
    command_line: ctypes.Array,
    creation_flags: int,
    process_info: _ProcessInformation,
) -> None:
    """Create the child with an explicit inherited-handle allowlist."""

    descriptors: list[int] = list(parent_descriptors)
    attribute_storage: ctypes.Array | None = None
    attribute_list = wintypes.LPVOID()
    attribute_list_initialized = False
    child_stdin_handle: int | None = None
    primary_error: BaseException | None = None
    try:
        stdout_handle, stderr_handle = output_handles
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.hStdInput = wintypes.HANDLE(0)
        startup.StartupInfo.hStdOutput = wintypes.HANDLE(stdout_handle)
        startup.StartupInfo.hStdError = wintypes.HANDLE(stderr_handle)

        inherited_values = [stdout_handle, stderr_handle]
        if stdin_handle is not None:
            if type(stdin_handle) is not int or stdin_handle <= 0:
                raise VerifierProcessError("verifier_input_handle")
            duplicate = wintypes.HANDLE()
            if not kernel32.DuplicateHandle(
                kernel32.GetCurrentProcess(), wintypes.HANDLE(stdin_handle),
                kernel32.GetCurrentProcess(), ctypes.byref(duplicate), 0,
                True, _DUPLICATE_SAME_ACCESS,
            ):
                raise _win_error("verifier_input_duplicate")
            child_stdin_handle = int(duplicate.value)
            startup.StartupInfo.hStdInput = wintypes.HANDLE(child_stdin_handle)
            inherited_values.append(child_stdin_handle)

        attribute_size = ctypes.c_size_t(0)
        first_call = kernel32.InitializeProcThreadAttributeList(
            None, 2, 0, ctypes.byref(attribute_size)
        )
        if first_call or not attribute_size.value:
            raise VerifierProcessError("verifier_attribute_list_size")
        attribute_storage = ctypes.create_string_buffer(attribute_size.value)
        attribute_list = ctypes.cast(attribute_storage, wintypes.LPVOID)
        if not kernel32.InitializeProcThreadAttributeList(
            attribute_list, 2, 0, ctypes.byref(attribute_size)
        ):
            raise _win_error("verifier_attribute_list_initialize")
        attribute_list_initialized = True
        inherited_handles = (wintypes.HANDLE * len(inherited_values))(
            *(wintypes.HANDLE(value) for value in inherited_values)
        )
        if not kernel32.UpdateProcThreadAttribute(
            attribute_list, 0, _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.cast(inherited_handles, wintypes.LPVOID),
            ctypes.sizeof(inherited_handles), None, None,
        ):
            raise _win_error("verifier_attribute_list_update")
        image_policy = ctypes.c_uint64(_IMAGE_LOAD_POLICY)
        if not kernel32.UpdateProcThreadAttribute(
            attribute_list, 0, _PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            ctypes.cast(ctypes.pointer(image_policy), wintypes.LPVOID),
            ctypes.sizeof(image_policy), None, None,
        ):
            raise _win_error("verifier_image_policy")
        startup.lpAttributeList = attribute_list
        if not kernel32.CreateProcessW(
            str(executable), command_line, None, None, True,
            creation_flags | _EXTENDED_STARTUPINFO_PRESENT,
            ctypes.cast(environment, wintypes.LPVOID),
            str(current_directory if current_directory is not None else Path(executable).parent),
            ctypes.cast(ctypes.byref(startup), ctypes.POINTER(_StartupInfo)),
            ctypes.byref(process_info)
        ):
            raise _win_error("verifier_process_create")
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if attribute_list_initialized:
            try:
                kernel32.DeleteProcThreadAttributeList(attribute_list)
            except BaseException:
                cleanup_errors.append(VerifierProcessError("verifier_attribute_list_delete"))
        if child_stdin_handle is not None:
            try:
                if not kernel32.CloseHandle(child_stdin_handle):
                    cleanup_errors.append(VerifierProcessError("verifier_input_close"))
            except BaseException:
                cleanup_errors.append(VerifierProcessError("verifier_input_close"))
        try:
            _close_parent_descriptors_once(descriptors)
        except VerifierProcessError as close_error:
            cleanup_errors.append(close_error)
        if cleanup_errors and primary_error is None:
            # The caller owns pre-assignment child termination and reaping.  Do
            # not terminate here: otherwise the caller could terminate twice
            # after this post-CreateProcess cleanup failure.
            raise VerifierProcessError("verifier_process_cleanup") from None


def _terminate_and_reap_child(
    *, kernel32: object, process_handle: object, job_handle: object | None,
    label: str,
) -> None:
    if job_handle is None:
        if not kernel32.TerminateProcess(process_handle, 1):
            raise _win_error(f"{label}_terminate")
    else:
        if not kernel32.TerminateJobObject(job_handle, 1):
            raise _win_error(f"{label}_terminate")
    if kernel32.WaitForSingleObject(process_handle, _INFINITE) != _WAIT_OBJECT_0:
        raise _win_error(f"{label}_wait")


def _launch_apis() -> tuple[object, object]:
    """kernel32 and psapi with every signature the suspended Job Object launch uses."""

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    required_apis = (
        "CreateJobObjectW", "SetInformationJobObject", "CreateProcessW",
        "AssignProcessToJobObject", "ResumeThread", "WaitForSingleObject",
        "TerminateJobObject",
        "CloseHandle", "SetHandleInformation", "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute", "DeleteProcThreadAttributeList",
        "GetCurrentProcess", "CreateFileW", "GetFileType",
        "GetFileInformationByHandle", "GetFinalPathNameByHandleW",
        "GetFileInformationByHandleEx", "QueryDosDeviceW",
        "CompareStringOrdinal", "K32GetProcessImageFileNameW", "ReadFile", "PeekNamedPipe",
    )
    for name in required_apis:
        if not hasattr(kernel32, name):
            raise VerifierProcessError(f"verifier_api_missing:{name}")
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID,
        wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfo), ctypes.POINTER(_ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    _configure_executable_pin_apis(kernel32)
    kernel32.PeekNamedPipe.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.PeekNamedPipe.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
    except OSError:
        raise VerifierProcessError("verifier_api_missing:GetProcessMemoryInfo") from None
    if not hasattr(psapi, "GetProcessMemoryInfo"):
        raise VerifierProcessError("verifier_api_missing:GetProcessMemoryInfo")
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_ProcessMemoryCountersEx), wintypes.DWORD
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    if not hasattr(kernel32, "DuplicateHandle"):
        raise VerifierProcessError("verifier_api_missing:DuplicateHandle")
    kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wintypes.BOOL
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [
        wintypes.LPVOID, wintypes.DWORD, ctypes.c_size_t, wintypes.LPVOID,
        ctypes.c_size_t, wintypes.LPVOID, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
    kernel32.DeleteProcThreadAttributeList.restype = None
    return kernel32, psapi


WORKER_MAX_FRAME_BYTES = 64 * 1024 * 1024


class ContainedWorker:
    """One pinned long-lived child in its own Job Object, spoken to in frames.

    Each exchange writes a u32 big-endian length and the frame to the child's
    standard input and reads one such frame back.  Any failure or timeout
    terminates the whole Job and the worker stays dead: the caller relaunches
    explicitly and never reuses a child whose stream position is unknown.
    """

    def __init__(
        self, *, kernel32: object, job: object, process_handle: object,
        stdin_descriptor: int, stdout_descriptor: int, stderr_descriptor: int, psapi: object,
    ) -> None:
        self._kernel32 = kernel32
        self._psapi = psapi
        self._job = job
        self._process = process_handle
        self._stdin = stdin_descriptor
        self._stdout = stdout_descriptor
        self._stderr = stderr_descriptor
        self._lock = threading.Lock()
        self._cond = threading.Condition()  # guards the armed deadline; held by the watchdog except while it sleeps
        self._deadline: float | None = None
        self._timed_out = False
        self.alive = True
        self._watchdog = threading.Thread(target=self._watch, daemon=True)
        self._watchdog.start()

    def _terminate(self) -> None:
        with self._cond:
            self.alive = False
            self._cond.notify_all()
        try:
            self._kernel32.TerminateJobObject(self._job, 1)
        except BaseException:
            pass

    def _watch(self) -> None:
        """The one thread that enforces every exchange's deadline: it sleeps to the armed deadline, or until one is armed, and kills the Job once it passes."""

        with self._cond:
            while self.alive:
                left = None if self._deadline is None else self._deadline - time.monotonic()
                if left is not None and left <= 0:
                    self._deadline = None
                    self._timed_out = True
                    self._terminate()
                else:
                    self._cond.wait(left)

    def _read_exact(self, count: int) -> bytes:
        data = bytearray()
        while len(data) < count:
            chunk = os.read(self._stdout, min(count - len(data), 1 << 20))
            if not chunk:
                raise VerifierProcessError("worker_exchange")
            data.extend(chunk)
        return bytes(data)

    def commit_bytes(self) -> int:
        """The child's private commit; an unreadable process counts as unbounded so its owner recycles it."""

        counters = _ProcessMemoryCountersEx()
        counters.cb = ctypes.sizeof(counters)
        if self._process is None or not self._psapi.GetProcessMemoryInfo(
            self._process, ctypes.byref(counters), ctypes.sizeof(counters)
        ):
            return 1 << 63
        return int(counters.PrivateUsage)

    def _pending(self, descriptor: int) -> bool:
        """An unread byte fails the request closed: on stderr a Lean panic message (the worker writes no diagnostics), on stdout a second frame that would answer the next request."""

        import msvcrt

        available = wintypes.DWORD()
        return not self._kernel32.PeekNamedPipe(
            msvcrt.get_osfhandle(descriptor), None, 0, None, ctypes.byref(available), None
        ) or available.value != 0

    def exchange(self, frame: bytes, *, response_cap_bytes: int, timeout_seconds: float) -> bytes:
        if type(frame) is not bytes or not 0 < len(frame) <= WORKER_MAX_FRAME_BYTES:
            raise VerifierProcessError("worker_frame_cap")
        if type(response_cap_bytes) is not int or not 0 < response_cap_bytes <= WORKER_MAX_FRAME_BYTES:
            raise VerifierProcessError("worker_response_cap")
        if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 30 * 60:
            raise VerifierProcessError("worker_timeout")
        with self._lock:
            if not self.alive:
                raise VerifierProcessError("worker_unavailable")
            with self._cond:
                self._deadline = time.monotonic() + timeout_seconds
                self._cond.notify()
            try:
                if self._pending(self._stdout):
                    raise VerifierProcessError("worker_exchange")
                payload = len(frame).to_bytes(4, "big") + frame
                offset = 0
                while offset < len(payload):
                    written = os.write(self._stdin, payload[offset : offset + (1 << 20)])
                    if written <= 0:
                        raise VerifierProcessError("worker_exchange")
                    offset += written
                length = int.from_bytes(self._read_exact(4), "big")
                if not 0 < length <= response_cap_bytes:
                    raise VerifierProcessError("worker_response_cap")
                response = self._read_exact(length)
                if self._pending(self._stdout):
                    raise VerifierProcessError("worker_exchange")
                if self._pending(self._stderr):
                    raise VerifierProcessError("worker_stderr")
                return response
            except BaseException as error:
                self._terminate()
                code = "worker_timeout" if self._timed_out else (
                    str(error) if isinstance(error, VerifierProcessError) else "worker_exchange"
                )
                raise VerifierProcessError(code) from None
            finally:
                self._deadline = None

    def close(self) -> None:
        """End of input lets the worker exit 0; a worker that lingers is terminated."""

        with self._lock:
            if self._process is None:
                return
            with self._cond:
                self.alive = False
                self._cond.notify_all()
            for descriptor in (self._stdin, self._stdout, self._stderr):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                if self._kernel32.WaitForSingleObject(self._process, 5000) != _WAIT_OBJECT_0:
                    self._kernel32.TerminateJobObject(self._job, 1)
                    self._kernel32.WaitForSingleObject(self._process, _INFINITE)
            finally:
                self._kernel32.CloseHandle(self._process)
                self._kernel32.CloseHandle(self._job)
                self._process = None


def launch_contained_worker(
    executable: Path,
    *,
    workspace: Path,
    job_memory_cap_bytes: int,
    expected_executable_size_bytes: int,
    expected_executable_sha256: bytes,
) -> ContainedWorker:
    """Launch a pinned worker through the same suspended, image-verified Job Object path."""

    if os.name != "nt":
        raise VerifierProcessError("verifier_windows_only")
    if not isinstance(executable, Path) or not executable.is_absolute():
        raise VerifierProcessError("verifier_executable_path")
    _verifier_workspace_snapshot(workspace)
    if (
        type(job_memory_cap_bytes) is not int
        or not 0 < job_memory_cap_bytes <= ADMISSION_CAP_BYTES
    ):
        raise VerifierProcessError("verifier_memory_cap")
    _validate_executable_pin(expected_executable_size_bytes, expected_executable_sha256)
    kernel32, psapi = _launch_apis()
    process_info = _ProcessInformation()
    job = wintypes.HANDLE()
    owned: list[int] = []
    pinned: _PinnedExecutable | None = None
    try:
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise _win_error("verifier_job_create")
        _set_job_limits(kernel32, job, job_memory_cap_bytes)
        stdout_read, stdout_write, stdout_handle = _create_output_pipe()
        owned += [stdout_read, stdout_write]
        stderr_read, stderr_write, stderr_handle = _create_output_pipe()
        owned += [stderr_read, stderr_write]
        try:
            stdin_read, stdin_write = os.pipe()
        except OSError:
            raise VerifierProcessError("worker_input_pipe") from None
        owned += [stdin_read, stdin_write]
        import msvcrt

        stdin_handle = int(msvcrt.get_osfhandle(stdin_read))
        pinned = _open_pinned_executable(
            kernel32=kernel32,
            executable=executable,
            expected_executable_size_bytes=expected_executable_size_bytes,
            expected_executable_sha256=expected_executable_sha256,
        )
        startup = _StartupInfoEx()
        startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
        # The helper closes these three parent descriptors on every path.
        for descriptor in (stdout_write, stderr_write, stdin_read):
            owned.remove(descriptor)
        try:
            _create_process_with_owned_output_handles(
                kernel32=kernel32,
                executable=pinned.canonical_path,
                current_directory=str(workspace),
                output_handles=(stdout_handle, stderr_handle),
                stdin_handle=stdin_handle,
                parent_descriptors=[stdout_write, stderr_write, stdin_read],
                startup=startup,
                environment=_environment_block(workspace),
                command_line=ctypes.create_unicode_buffer(_quote_argument(pinned.canonical_path)),
                creation_flags=_CREATE_SUSPENDED | _CREATE_NO_WINDOW | _CREATE_UNICODE_ENVIRONMENT,
                process_info=process_info,
            )
            _query_dos_device_mapping(
                kernel32=kernel32, drive=pinned.dos_drive,
                native_volume_prefix=pinned.native_volume_prefix,
            )
            _verify_suspended_child_image(
                kernel32=kernel32, process_handle=process_info.hProcess,
                expected_native_path=pinned.nt_path,
                native_volume_prefix=pinned.native_volume_prefix,
            )
            if not kernel32.AssignProcessToJobObject(job, process_info.hProcess):
                raise _win_error("verifier_job_assign")
        except BaseException:
            if process_info.hProcess:
                _terminate_and_reap_child(
                    kernel32=kernel32, process_handle=process_info.hProcess,
                    job_handle=None, label="worker_child_binding",
                )
            raise
        if kernel32.ResumeThread(process_info.hThread) == 0xFFFFFFFF:
            _terminate_and_reap_child(
                kernel32=kernel32, process_handle=process_info.hProcess,
                job_handle=job, label="verifier_process_resume",
            )
            raise _win_error("verifier_process_resume")
        pinned.close()
        pinned = None
        # The worker never writes diagnostics (IV.2); the worker keeps stderr_read and treats any byte as a failure.
        owned.remove(stderr_read)
        owned.remove(stdin_write)
        owned.remove(stdout_read)
        worker = ContainedWorker(
            kernel32=kernel32, job=job, process_handle=process_info.hProcess,
            stdin_descriptor=stdin_write, stdout_descriptor=stdout_read, stderr_descriptor=stderr_read,
            psapi=psapi,
        )
        process_info.hProcess = None
        job = None
        return worker
    finally:
        for descriptor in owned:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if pinned is not None:
            try:
                pinned.close()
            except BaseException:
                pass
        if process_info.hThread:
            kernel32.CloseHandle(process_info.hThread)
        if process_info.hProcess:
            if job:
                kernel32.TerminateJobObject(job, 1)
            kernel32.CloseHandle(process_info.hProcess)
        if job:
            kernel32.CloseHandle(job)
