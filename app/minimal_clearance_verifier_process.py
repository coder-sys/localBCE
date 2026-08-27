"""Windows-only containment for the native minimal-clearance verifier.

The child is created suspended, assigned to a bounded Job Object, and only
then resumed.  Its only inherited handles are the two capture pipes and, for
verification, the already-open artifact supplied as standard input.  There
is deliberately no subprocess fallback: inability to establish the boundary
is a fail-closed error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import os
from pathlib import Path
import threading
import time


class VerifierProcessError(RuntimeError):
    """The required Windows verifier containment boundary was not established."""


CAP_BYTES = 5_000_000_000
ADMISSION_CAP_BYTES = 4_500_000_000
ACTIVE_PROCESS_LIMIT = 1
MAX_STDOUT_BYTES = 65_536
MAX_STDERR_BYTES = 262_144
STREAM_MAX_AGGREGATE_BYTES = 2 * 1024 * 1024 * 1024
STREAM_MAX_FRAME_BYTES = STREAM_MAX_AGGREGATE_BYTES + 24 + 8 * 8

_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_HANDLE_FLAG_INHERIT = 0x00000001
_DUPLICATE_SAME_ACCESS = 0x00000002
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_TYPE_DISK = 1
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_EXECUTABLE_HASH_CHUNK_BYTES = 1 << 20
_SHA256_BYTES = 32


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


class _JobObjectBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
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


@dataclass(frozen=True, slots=True)
class ContainedVerifierResult:
    exit_code: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    peak_job_commit_bytes: int
    cap_bytes: int
    cap_enforced: bool
    active_process_limit: int
    timed_out: bool
    peak_working_set_bytes: int = 0
    peak_private_commit_bytes: int = 0
    parent_peak_working_set_bytes: int = 0
    parent_peak_private_commit_bytes: int = 0
    # This is a process-private-commit delta, not an OS pagefile or swap
    # measurement.  OS-level pagefile growth is intentionally reported as
    # unavailable by this containment primitive unless a separate attributed
    # sampler establishes it.
    private_commit_delta_bytes: int = 0
    pagefile_growth_evidence: str = "unavailable"
    scratch_peak_bytes: int = 0
    child_process_count: int = 0
    process_tree_complete: bool = False
    measurement_complete: bool = False
    cleanup_complete: bool = True


def _win_error(label: str) -> VerifierProcessError:
    return VerifierProcessError(f"{label}:{ctypes.get_last_error()}")


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


def _configure_executable_pin_apis(kernel32: object) -> None:
    required = (
        "CreateFileW", "GetFileType", "GetFileInformationByHandle",
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
    if expected_executable_size_bytes is None and expected_executable_sha256 is None:
        return
    if (
        type(expected_executable_size_bytes) is not int
        or expected_executable_size_bytes <= 0
        or type(expected_executable_sha256) is not bytes
        or len(expected_executable_sha256) != _SHA256_BYTES
    ):
        raise VerifierProcessError("verifier_executable_pin")


def _open_pinned_executable(
    *,
    kernel32: object,
    executable: Path,
    expected_executable_size_bytes: int,
    expected_executable_sha256: bytes,
) -> _PinnedExecutableHandle:
    """Hash one non-reparse file through a share-denying live handle."""

    _configure_executable_pin_apis(kernel32)
    _validate_executable_pin(expected_executable_size_bytes, expected_executable_sha256)
    if not isinstance(executable, Path) or not executable.is_absolute():
        raise VerifierProcessError("verifier_executable_path")
    handle = kernel32.CreateFileW(
        str(executable),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    if _invalid_handle(handle):
        raise _win_error("verifier_executable_open")
    pinned = _PinnedExecutableHandle(kernel32, handle)
    try:
        information = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise _win_error("verifier_executable_stat")
        attributes = int(information.dwFileAttributes)
        if (
            attributes & _FILE_ATTRIBUTE_DIRECTORY
            or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or int(kernel32.GetFileType(handle)) != _FILE_TYPE_DISK
        ):
            raise VerifierProcessError("verifier_executable_not_regular_file")
        actual_size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        if actual_size != expected_executable_size_bytes:
            raise VerifierProcessError("verifier_executable_size")

        digest = hashlib.sha256()
        buffer = ctypes.create_string_buffer(_EXECUTABLE_HASH_CHUNK_BYTES)
        total = 0
        try:
            while True:
                read = wintypes.DWORD()
                if not kernel32.ReadFile(
                    handle, buffer, _EXECUTABLE_HASH_CHUNK_BYTES,
                    ctypes.byref(read), None,
                ):
                    raise _win_error("verifier_executable_read")
                count = int(read.value)
                if count > _EXECUTABLE_HASH_CHUNK_BYTES:
                    raise VerifierProcessError("verifier_executable_read")
                if count == 0:
                    break
                total += count
                if total > expected_executable_size_bytes:
                    raise VerifierProcessError("verifier_executable_size")
                digest.update(buffer.raw[:count])
        finally:
            ctypes.memset(buffer, 0, _EXECUTABLE_HASH_CHUNK_BYTES)
        if total != expected_executable_size_bytes:
            raise VerifierProcessError("verifier_executable_size")
        if not hmac.compare_digest(digest.digest(), expected_executable_sha256):
            raise VerifierProcessError("verifier_executable_identity")
        return pinned
    except BaseException as primary_error:
        try:
            pinned.close()
        except BaseException:
            raise
        raise primary_error


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
        "TEMP": str(workspace),
        "TMP": str(workspace),
    }
    block = "\0".join(f"{key}={values[key]}" for key in sorted(values, key=str.upper)) + "\0\0"
    return ctypes.create_unicode_buffer(block)


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
    executable: Path,
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
    process_created = False
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
            if not hasattr(kernel32, "DuplicateHandle") or not hasattr(kernel32, "GetCurrentProcess"):
                raise VerifierProcessError("verifier_api_missing:DuplicateHandle")
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
            None, 1, 0, ctypes.byref(attribute_size)
        )
        if first_call or not attribute_size.value:
            raise VerifierProcessError("verifier_attribute_list_size")
        attribute_storage = ctypes.create_string_buffer(attribute_size.value)
        attribute_list = ctypes.cast(attribute_storage, wintypes.LPVOID)
        if not kernel32.InitializeProcThreadAttributeList(
            attribute_list, 1, 0, ctypes.byref(attribute_size)
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
        startup.lpAttributeList = attribute_list
        if not kernel32.CreateProcessW(
            str(executable), command_line, None, None, True,
            creation_flags | _EXTENDED_STARTUPINFO_PRESENT,
            ctypes.cast(environment, wintypes.LPVOID), str(executable.parent),
            ctypes.cast(ctypes.byref(startup), ctypes.POINTER(_StartupInfo)),
            ctypes.byref(process_info)
        ):
            raise _win_error("verifier_process_create")
        process_created = True
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
        if cleanup_errors:
            if process_created and process_info.hProcess:
                if not kernel32.TerminateProcess(process_info.hProcess, 1):
                    cleanup_errors.append(_win_error("verifier_output_close_process"))
            if primary_error is None:
                raise VerifierProcessError("verifier_process_cleanup") from None


def _drain_pipe(
    descriptor: int,
    limit: int,
    label: str,
    output: dict[str, bytes],
    failure: dict[str, str],
    overflow: threading.Event,
) -> None:
    data = bytearray()
    try:
        while len(data) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                overflow.set()
                failure.setdefault("code", f"{label}_cap")
                break
        if "code" not in failure:
            try:
                bytes(data).decode("ascii")
            except UnicodeDecodeError:
                failure["code"] = f"{label}_encoding"
    except BaseException:
        failure.setdefault("code", f"{label}_read")
    finally:
        output[label] = bytes(data[: limit + 1])
        try:
            os.close(descriptor)
        except OSError:
            failure.setdefault("code", f"{label}_close")


def run_contained_verifier(
    executable: Path,
    arguments: tuple[str, ...],
    *,
    workspace: Path,
    timeout_seconds: float,
    job_memory_cap_bytes: int = CAP_BYTES,
    _stdin_descriptor: int | None = None,
    expected_executable_size_bytes: int | None = None,
    expected_executable_sha256: bytes | None = None,
) -> ContainedVerifierResult:
    """Run one native verifier form under the required suspended Job Object."""

    if os.name != "nt":
        raise VerifierProcessError("verifier_windows_only")
    if not isinstance(executable, Path) or not executable.is_absolute():
        raise VerifierProcessError("verifier_executable_path")
    if not workspace.is_dir() or workspace.is_symlink():
        raise VerifierProcessError("verifier_workspace")
    if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 30 * 60:
        raise VerifierProcessError("verifier_timeout")
    if type(job_memory_cap_bytes) is not int or not 0 < job_memory_cap_bytes <= CAP_BYTES:
        raise VerifierProcessError("verifier_memory_cap")
    if any(type(argument) is not str for argument in arguments):
        raise VerifierProcessError("verifier_argument_type")
    if _stdin_descriptor is not None and (
        type(_stdin_descriptor) is not int or _stdin_descriptor < 0
    ):
        raise VerifierProcessError("verifier_input_handle")
    _validate_executable_pin(
        expected_executable_size_bytes,
        expected_executable_sha256,
    )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    required_apis = (
        "CreateJobObjectW", "SetInformationJobObject", "CreateProcessW",
        "AssignProcessToJobObject", "ResumeThread", "WaitForSingleObject",
        "TerminateJobObject", "GetExitCodeProcess", "QueryInformationJobObject",
        "CloseHandle", "SetHandleInformation", "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute", "DeleteProcThreadAttributeList",
        "GetCurrentProcess", "CreateFileW", "GetFileType",
        "GetFileInformationByHandle", "ReadFile",
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
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    _configure_executable_pin_apis(kernel32)
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
    if _stdin_descriptor is not None:
        if not hasattr(kernel32, "DuplicateHandle") or not hasattr(kernel32, "GetCurrentProcess"):
            raise VerifierProcessError("verifier_api_missing:DuplicateHandle")
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
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
    process_info = _ProcessInformation()
    job = wintypes.HANDLE()
    timed_out = False
    stdout_read: int | None = None
    stderr_read: int | None = None
    stdout_write: int | None = None
    stderr_write: int | None = None
    stdout_handle = 0
    stderr_handle = 0
    reader_threads: list[threading.Thread] = []
    reader_failure: dict[str, str] = {}
    reader_output: dict[str, bytes] = {}
    reader_overflow = threading.Event()
    peak_working_set = 0
    peak_private_commit = 0
    parent_peak_working_set = 0
    parent_peak_private_commit = 0
    initial_private_commit = 0
    peak_combined_private_commit = 0
    memory_sampled = False
    child_process_count = 0
    admission_exceeded = False
    pinned_executable: _PinnedExecutableHandle | None = None

    def _release_pinned_executable() -> None:
        nonlocal pinned_executable
        pin = pinned_executable
        pinned_executable = None
        if pin is None:
            return
        pin.close()

    def _read_memory(handle: wintypes.HANDLE) -> tuple[int, int] | None:
        counters = _ProcessMemoryCountersEx()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), ctypes.sizeof(counters)
        ):
            return None
        return (
            int(counters.PeakWorkingSetSize),
            int(counters.PrivateUsage),
        )

    def _sample_memory() -> bool:
        nonlocal peak_working_set, peak_private_commit
        nonlocal parent_peak_working_set, parent_peak_private_commit
        nonlocal initial_private_commit, peak_combined_private_commit
        nonlocal memory_sampled, admission_exceeded
        child = _read_memory(process_info.hProcess)
        parent = _read_memory(kernel32.GetCurrentProcess())
        if child is None or parent is None:
            return False
        peak_working_set = max(peak_working_set, child[0])
        peak_private_commit = max(peak_private_commit, child[1])
        parent_peak_working_set = max(parent_peak_working_set, parent[0])
        parent_peak_private_commit = max(parent_peak_private_commit, parent[1])
        combined_private_commit = child[1] + parent[1]
        if not memory_sampled:
            initial_private_commit = combined_private_commit
            peak_combined_private_commit = combined_private_commit
        else:
            peak_combined_private_commit = max(
                peak_combined_private_commit, combined_private_commit
            )
        memory_sampled = True
        if job_memory_cap_bytes == ADMISSION_CAP_BYTES and (
            child[1] + parent[1] > ADMISSION_CAP_BYTES
            or child[0] + parent[0] > ADMISSION_CAP_BYTES
        ):
            admission_exceeded = True
            return False
        return True

    try:
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise _win_error("verifier_job_create")
        limits = _JobObjectExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_JOB_MEMORY
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        )
        limits.BasicLimitInformation.ActiveProcessLimit = ACTIVE_PROCESS_LIMIT
        limits.JobMemoryLimit = job_memory_cap_bytes
        if not kernel32.SetInformationJobObject(
            job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise _win_error("verifier_job_limits")

        startup = _StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = wintypes.HANDLE(0)
        environment = _environment_block(workspace)
        command_line = ctypes.create_unicode_buffer(
            " ".join(
                [_quote_argument(str(executable))]
                + [_quote_argument(argument) for argument in arguments]
            )
        )
        creation_flags = (
            _CREATE_SUSPENDED | _CREATE_NO_WINDOW | _CREATE_UNICODE_ENVIRONMENT
            | _EXTENDED_STARTUPINFO_PRESENT
        )
        try:
            stdout_read, stdout_write, stdout_handle = _create_output_pipe()
            stderr_read, stderr_write, stderr_handle = _create_output_pipe()
        except BaseException:
            for descriptor in (stdout_read, stdout_write, stderr_read, stderr_write):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            stdout_read = stdout_write = stderr_read = stderr_write = None
            raise
        inherited_stdin: int | None = None
        if _stdin_descriptor is not None:
            try:
                import msvcrt

                inherited_stdin = int(msvcrt.get_osfhandle(_stdin_descriptor))
            except (OSError, ValueError, ImportError, TypeError):
                raise VerifierProcessError("verifier_input_handle") from None
        try:
            if expected_executable_size_bytes is not None:
                pinned_executable = _open_pinned_executable(
                    kernel32=kernel32,
                    executable=executable,
                    expected_executable_size_bytes=expected_executable_size_bytes,
                    expected_executable_sha256=expected_executable_sha256,  # type: ignore[arg-type]
                )
            _create_process_with_owned_output_handles(
                kernel32=kernel32,
                executable=executable,
                output_handles=(stdout_handle, stderr_handle),
                stdin_handle=inherited_stdin,
                parent_descriptors=[stdout_write, stderr_write],  # type: ignore[list-item]
                startup=startup,
                environment=environment,
                command_line=command_line,
                creation_flags=creation_flags,
                process_info=process_info,
            )
        finally:
            # The helper owns and closes both parent descriptors on every path.
            stdout_write = None
            stderr_write = None
            if pinned_executable is not None:
                try:
                    _release_pinned_executable()
                except BaseException:
                    if process_info.hProcess:
                        try:
                            kernel32.TerminateProcess(process_info.hProcess, 1)
                        except BaseException:
                            pass
                    raise
        if not kernel32.AssignProcessToJobObject(job, process_info.hProcess):
            kernel32.TerminateProcess(process_info.hProcess, 1)
            raise _win_error("verifier_job_assign")
        if not _sample_memory():
            kernel32.TerminateJobObject(job, 1)
            if admission_exceeded:
                raise VerifierProcessError("verifier_admission_cap")
            raise VerifierProcessError("verifier_memory_sample")
        if kernel32.ResumeThread(process_info.hThread) == 0xFFFFFFFF:
            kernel32.TerminateJobObject(job, 1)
            raise _win_error("verifier_process_resume")
        reader_threads = [
            threading.Thread(target=_drain_pipe, args=(stdout_read, MAX_STDOUT_BYTES, "stdout", reader_output, reader_failure, reader_overflow), daemon=True),
            threading.Thread(target=_drain_pipe, args=(stderr_read, MAX_STDERR_BYTES, "stderr", reader_output, reader_failure, reader_overflow), daemon=True),
        ]
        for reader in reader_threads:
            reader.start()
        stdout_read = None
        stderr_read = None
        wait_ms = max(1, int(timeout_seconds * 1000))
        deadline = time.monotonic() + (wait_ms / 1000.0)
        while True:
            if not _sample_memory():
                if not kernel32.TerminateJobObject(job, 1):
                    raise _win_error("verifier_memory_terminate")
                if kernel32.WaitForSingleObject(process_info.hProcess, _INFINITE) != _WAIT_OBJECT_0:
                    raise _win_error("verifier_memory_wait")
                if admission_exceeded:
                    raise VerifierProcessError("verifier_admission_cap")
                raise VerifierProcessError("verifier_memory_sample")
            if reader_overflow.is_set() or "code" in reader_failure:
                if not kernel32.TerminateJobObject(job, 1):
                    raise _win_error("verifier_output_terminate")
                if kernel32.WaitForSingleObject(process_info.hProcess, _INFINITE) != _WAIT_OBJECT_0:
                    raise _win_error("verifier_output_wait")
                raise VerifierProcessError(reader_failure.get("code", "verifier_output_read"))
            remaining = max(1, int((deadline - time.monotonic()) * 1000))
            wait_result = kernel32.WaitForSingleObject(process_info.hProcess, min(50, remaining))
            if wait_result == _WAIT_OBJECT_0:
                break
            if wait_result != _WAIT_TIMEOUT:
                raise _win_error("verifier_wait")
            if time.monotonic() >= deadline:
                timed_out = True
                if not kernel32.TerminateJobObject(job, 1):
                    raise _win_error("verifier_timeout_terminate")
                if kernel32.WaitForSingleObject(process_info.hProcess, _INFINITE) != _WAIT_OBJECT_0:
                    raise _win_error("verifier_timeout_wait")
                break
        for reader in reader_threads:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in reader_threads):
            raise VerifierProcessError("verifier_output_read")
        if reader_overflow.is_set() or "code" in reader_failure:
            raise VerifierProcessError(reader_failure.get("code", "verifier_output_read"))
        if not _sample_memory():
            if admission_exceeded:
                raise VerifierProcessError("verifier_admission_cap")
            raise VerifierProcessError("verifier_memory_sample")
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(process_info.hProcess, ctypes.byref(exit_code)):
            raise _win_error("verifier_exit_code")
        observed = _JobObjectExtendedLimitInformation()
        if not kernel32.QueryInformationJobObject(
            job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(observed),
            ctypes.sizeof(observed), None
        ):
            raise _win_error("verifier_job_query")
        peak_commit = int(observed.PeakJobMemoryUsed)
        stdout = reader_output.get("stdout", b"")
        stderr = reader_output.get("stderr", b"")
        if peak_commit > job_memory_cap_bytes:
            raise VerifierProcessError("verifier_job_memory_cap")
        accounting = _JobObjectBasicAccountingInformation()
        if not kernel32.QueryInformationJobObject(
            job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
        ):
            raise _win_error("verifier_job_accounting_query")
        child_process_count = int(accounting.TotalProcesses)
        active_process_count = int(accounting.ActiveProcesses)
        for _ in range(100):
            if child_process_count >= 1 and active_process_count == 0:
                break
            time.sleep(0.01)
            if not kernel32.QueryInformationJobObject(
                job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
            ):
                raise _win_error("verifier_job_accounting_query")
            child_process_count = int(accounting.TotalProcesses)
            active_process_count = int(accounting.ActiveProcesses)
        # The waited root handle plus Job Object ActiveProcesses==0 proves the
        # assigned tree is quiescent; TotalProcesses alone is not sufficient.
        process_tree_complete = (
            child_process_count >= 1
            and active_process_count == 0
        )
        if not process_tree_complete:
            raise VerifierProcessError("verifier_job_accounting")
        return ContainedVerifierResult(
            exit_code=int(exit_code.value), stdout=stdout, stderr=stderr,
            peak_job_commit_bytes=peak_commit, cap_bytes=job_memory_cap_bytes,
            cap_enforced=True, active_process_limit=ACTIVE_PROCESS_LIMIT,
            timed_out=timed_out,
            peak_working_set_bytes=peak_working_set,
            peak_private_commit_bytes=peak_private_commit,
            parent_peak_working_set_bytes=parent_peak_working_set,
            parent_peak_private_commit_bytes=parent_peak_private_commit,
            scratch_peak_bytes=0,
            child_process_count=child_process_count,
            measurement_complete=memory_sampled,
            cleanup_complete=True,
            private_commit_delta_bytes=max(
                0, peak_combined_private_commit - initial_private_commit
            ),
            pagefile_growth_evidence="unavailable",
            process_tree_complete=process_tree_complete,
        )
    finally:
        cleanup_errors: list[BaseException] = []
        for reader in reader_threads:
            if reader.is_alive():
                reader.join(timeout=5)
        for descriptor in (stdout_read, stderr_read, stdout_write, stderr_write):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if process_info.hThread:
            if not kernel32.CloseHandle(process_info.hThread):
                cleanup_errors.append(_win_error("verifier_thread_close"))
        if process_info.hProcess:
            if not kernel32.CloseHandle(process_info.hProcess):
                cleanup_errors.append(_win_error("verifier_process_close"))
        if job:
            if not kernel32.CloseHandle(job):
                cleanup_errors.append(_win_error("verifier_job_close"))
        if cleanup_errors:
            raise VerifierProcessError("verifier_cleanup") from None


def run_contained_verifier_stream(
    executable: Path,
    arguments: tuple[str, ...],
    frame: bytes,
    *,
    workspace: Path,
    timeout_seconds: float,
    expected_executable_size_bytes: int | None = None,
    expected_executable_sha256: bytes | None = None,
) -> ContainedVerifierResult:
    """Feed one bounded binary stream through the existing Job Object lane."""

    if type(frame) is not bytes or not 0 < len(frame) <= STREAM_MAX_FRAME_BYTES:
        raise VerifierProcessError("verifier_stream_frame_cap")
    try:
        read_descriptor, write_descriptor = os.pipe()
    except OSError:
        raise VerifierProcessError("verifier_stream_pipe") from None
    stop = threading.Event()
    writer_failure: dict[str, str] = {}

    def _write_frame() -> None:
        offset = 0
        try:
            while offset < len(frame) and not stop.is_set():
                chunk = frame[offset : offset + 64 * 1024]
                written = os.write(write_descriptor, chunk)
                if written <= 0:
                    raise OSError("verifier_stream_write")
                offset += written
        except BaseException:
            if not stop.is_set():
                writer_failure["code"] = "verifier_stream_write"
        finally:
            try:
                os.close(write_descriptor)
            except OSError:
                pass

    writer = threading.Thread(target=_write_frame, daemon=True)
    writer.start()
    result: ContainedVerifierResult | None = None
    try:
        result = run_contained_verifier(
            executable,
            arguments,
            workspace=workspace,
            timeout_seconds=timeout_seconds,
            job_memory_cap_bytes=ADMISSION_CAP_BYTES,
            _stdin_descriptor=read_descriptor,
            expected_executable_size_bytes=expected_executable_size_bytes,
            expected_executable_sha256=expected_executable_sha256,
        )
        return result
    finally:
        stop.set()
        try:
            os.close(read_descriptor)
        except OSError:
            pass
        writer.join(timeout=5)
        if writer.is_alive():
            raise VerifierProcessError("verifier_stream_cleanup")
        if writer_failure and result is not None:
            raise VerifierProcessError(writer_failure["code"])


__all__ = (
    "ACTIVE_PROCESS_LIMIT", "ADMISSION_CAP_BYTES", "CAP_BYTES", "ContainedVerifierResult",
    "STREAM_MAX_AGGREGATE_BYTES", "STREAM_MAX_FRAME_BYTES",
    "VerifierProcessError", "run_contained_verifier", "run_contained_verifier_stream",
)
