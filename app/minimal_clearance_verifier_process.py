"""Windows-only containment for the native minimal-clearance verifier.

The caller supplies a private executable snapshot and private artifact/output
paths.  The child is created suspended, assigned to a bounded Job Object, and
only then resumed.  There is deliberately no subprocess fallback: inability
to establish the boundary is a fail-closed error.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import uuid


class VerifierProcessError(RuntimeError):
    """The required Windows verifier containment boundary was not established."""


CAP_BYTES = 5_000_000_000
ACTIVE_PROCESS_LIMIT = 1
MAX_STDOUT_BYTES = 65_536
MAX_STDERR_BYTES = 262_144

_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_HANDLE_FLAG_INHERIT = 0x00000001
_ERROR_SUCCESS = 0


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


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
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
    stdout: bytes
    stderr: bytes
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
        "BL_NETWORK_DISABLED": "1",
    }
    block = "\0".join(f"{key}={values[key]}" for key in sorted(values, key=str.upper)) + "\0\0"
    return ctypes.create_unicode_buffer(block)


def _create_output_handle(path: Path) -> tuple[int, int]:
    flags = os.O_BINARY | os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise VerifierProcessError("verifier_output_create") from exc
    try:
        import msvcrt

        handle = msvcrt.get_osfhandle(descriptor)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetHandleInformation.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD
        ]
        kernel32.SetHandleInformation.restype = wintypes.BOOL
        if not kernel32.SetHandleInformation(
            wintypes.HANDLE(handle), _HANDLE_FLAG_INHERIT, _HANDLE_FLAG_INHERIT
        ):
            raise _win_error("verifier_output_inherit")
        return descriptor, handle
    except Exception:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def _read_capped(path: Path, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size > limit:
            raise VerifierProcessError(f"{label}_cap")
        data = path.read_bytes()
    except VerifierProcessError:
        raise
    except OSError as exc:
        raise VerifierProcessError(f"{label}_read") from exc
    if len(data) != size or len(data) > limit:
        raise VerifierProcessError(f"{label}_read")
    try:
        data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerifierProcessError(f"{label}_encoding") from exc
    return data


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
    for name in (
        "CreateJobObjectW", "SetInformationJobObject", "CreateProcessW",
        "AssignProcessToJobObject", "ResumeThread", "WaitForSingleObject",
        "TerminateJobObject", "GetExitCodeProcess", "QueryInformationJobObject",
        "CloseHandle", "SetHandleInformation",
    ):
        if not hasattr(kernel32, name):
            raise VerifierProcessError(f"verifier_api_missing:{name}")

    output_paths = (
        workspace / f"stdout-{uuid.uuid4().hex}.bin",
        workspace / f"stderr-{uuid.uuid4().hex}.bin",
    )
    descriptors: list[int] = []
    process_info = _ProcessInformation()
    job = wintypes.HANDLE()
    timed_out = False
    try:
        stdout_fd, stdout_handle = _create_output_handle(output_paths[0])
        stderr_fd, stderr_handle = _create_output_handle(output_paths[1])
        descriptors.extend((stdout_fd, stderr_fd))
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

        startup = _StartupInfo()
        startup.cb = ctypes.sizeof(startup)
        startup.dwFlags = _STARTF_USESTDHANDLES
        startup.hStdInput = wintypes.HANDLE(0)
        startup.hStdOutput = wintypes.HANDLE(stdout_handle)
        startup.hStdError = wintypes.HANDLE(stderr_handle)
        environment = _environment_block(workspace)
        command_line = ctypes.create_unicode_buffer(
            " ".join(
                [_quote_argument(str(executable))]
                + [_quote_argument(argument) for argument in arguments]
            )
        )
        creation_flags = _CREATE_SUSPENDED | _CREATE_NO_WINDOW | _CREATE_UNICODE_ENVIRONMENT
        if not kernel32.CreateProcessW(
            str(executable), command_line, None, None, True, creation_flags,
            ctypes.cast(environment, wintypes.LPVOID), str(executable.parent),
            ctypes.byref(startup), ctypes.byref(process_info)
        ):
            raise _win_error("verifier_process_create")
        if not kernel32.AssignProcessToJobObject(job, process_info.hProcess):
            kernel32.TerminateProcess(process_info.hProcess, 1)
            raise _win_error("verifier_job_assign")
        if kernel32.ResumeThread(process_info.hThread) == 0xFFFFFFFF:
            kernel32.TerminateJobObject(job, 1)
            raise _win_error("verifier_process_resume")
        wait_ms = max(1, int(timeout_seconds * 1000))
        wait_result = kernel32.WaitForSingleObject(process_info.hProcess, wait_ms)
        if wait_result == _WAIT_TIMEOUT:
            timed_out = True
            if not kernel32.TerminateJobObject(job, 1):
                raise _win_error("verifier_timeout_terminate")
            if kernel32.WaitForSingleObject(process_info.hProcess, _INFINITE) != _WAIT_OBJECT_0:
                raise _win_error("verifier_timeout_wait")
        elif wait_result != _WAIT_OBJECT_0:
            raise _win_error("verifier_wait")
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
        stdout = _read_capped(output_paths[0], MAX_STDOUT_BYTES, "verifier_stdout")
        stderr = _read_capped(output_paths[1], MAX_STDERR_BYTES, "verifier_stderr")
        if peak_commit > CAP_BYTES:
            raise VerifierProcessError("verifier_job_memory_cap")
        return ContainedVerifierResult(
            exit_code=int(exit_code.value), stdout=stdout, stderr=stderr,
            peak_job_commit_bytes=peak_commit, cap_bytes=CAP_BYTES,
            cap_enforced=True, active_process_limit=ACTIVE_PROCESS_LIMIT,
            timed_out=timed_out,
        )
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if process_info.hThread:
            kernel32.CloseHandle(process_info.hThread)
        if process_info.hProcess:
            kernel32.CloseHandle(process_info.hProcess)
        if job:
            kernel32.CloseHandle(job)
        for path in output_paths:
            path.unlink(missing_ok=True)


__all__ = ("ACTIVE_PROCESS_LIMIT", "CAP_BYTES", "ContainedVerifierResult", "VerifierProcessError", "run_contained_verifier")
