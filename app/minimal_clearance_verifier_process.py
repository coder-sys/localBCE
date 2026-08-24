"""Windows-only containment for the native minimal-clearance verifier.

The caller supplies a private executable snapshot and workspace.  The child is
created suspended, assigned to a bounded Job Object, and only then resumed;
stdout and stderr are drained through anonymous pipes.  There is deliberately
no subprocess fallback: inability to establish the boundary is a fail-closed
error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import threading
import time


class VerifierProcessError(RuntimeError):
    """The required Windows verifier containment boundary was not established."""


CAP_BYTES = 5_000_000_000
ACTIVE_PROCESS_LIMIT = 1
MAX_STDOUT_BYTES = 65_536
MAX_STDERR_BYTES = 262_144

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
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002


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


def _win_error(label: str) -> VerifierProcessError:
    return VerifierProcessError(f"{label}:{ctypes.get_last_error()}")


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
    primary_error: BaseException | None = None
    try:
        stdout_handle, stderr_handle = output_handles
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.hStdOutput = wintypes.HANDLE(stdout_handle)
        startup.StartupInfo.hStdError = wintypes.HANDLE(stderr_handle)

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
        inherited_handles = (wintypes.HANDLE * 2)(
            wintypes.HANDLE(stdout_handle), wintypes.HANDLE(stderr_handle)
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
) -> ContainedVerifierResult:
    """Run one native verifier form under the required suspended Job Object."""

    if os.name != "nt":
        raise VerifierProcessError("verifier_windows_only")
    if not isinstance(executable, Path) or executable.is_symlink() or not executable.is_file():
        raise VerifierProcessError("verifier_executable_not_regular_file")
    if not workspace.is_dir() or workspace.is_symlink():
        raise VerifierProcessError("verifier_workspace")
    if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 30 * 60:
        raise VerifierProcessError("verifier_timeout")
    if any(type(argument) is not str for argument in arguments):
        raise VerifierProcessError("verifier_argument_type")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    required_apis = (
        "CreateJobObjectW", "SetInformationJobObject", "CreateProcessW",
        "AssignProcessToJobObject", "ResumeThread", "WaitForSingleObject",
        "TerminateJobObject", "GetExitCodeProcess", "QueryInformationJobObject",
        "CloseHandle", "SetHandleInformation", "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute", "DeleteProcThreadAttributeList",
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
        limits.JobMemoryLimit = CAP_BYTES
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
        try:
            _create_process_with_owned_output_handles(
                kernel32=kernel32,
                executable=executable,
                output_handles=(stdout_handle, stderr_handle),
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
        if not kernel32.AssignProcessToJobObject(job, process_info.hProcess):
            kernel32.TerminateProcess(process_info.hProcess, 1)
            raise _win_error("verifier_job_assign")
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
        if peak_commit > CAP_BYTES:
            raise VerifierProcessError("verifier_job_memory_cap")
        return ContainedVerifierResult(
            exit_code=int(exit_code.value), stdout=stdout, stderr=stderr,
            peak_job_commit_bytes=peak_commit, cap_bytes=CAP_BYTES,
            cap_enforced=True, active_process_limit=ACTIVE_PROCESS_LIMIT,
            timed_out=timed_out,
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


__all__ = ("ACTIVE_PROCESS_LIMIT", "CAP_BYTES", "ContainedVerifierResult", "VerifierProcessError", "run_contained_verifier")
