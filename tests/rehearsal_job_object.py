"""Windows Job Object accounting for the synthetic rehearsal evidence gate.

This is test/evidence infrastructure only.  The child is created suspended,
assigned to a configured Job Object, and resumed only after ownership and the
hard job commit-charge limit are established.  No process-name or single
process working-set approximation is used.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Sequence


_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_MEMORY_LIMIT = 5_000_000_000
_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_STILL_ACTIVE = 259
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_TERMINATE = 0x0001
_PROCESS_SYNCHRONIZE = 0x00100000
_PROCESS_ACCESS = _PROCESS_QUERY_INFORMATION | _PROCESS_TERMINATE | _PROCESS_SYNCHRONIZE
_INFINITE = 0xFFFFFFFF


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
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
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
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


def _win_error(prefix: str) -> str:
    code = ctypes.get_last_error()
    try:
        detail = ctypes.FormatError(code).strip()
    except Exception:
        detail = "unavailable"
    return f"{prefix}:winerror={code}:{detail}"


def _base_result() -> dict[str, object]:
    return {
        "counter_name": "PeakJobMemoryUsed",
        "semantics": "job_commit_charge_bytes",
        "cap_bytes": _JOB_MEMORY_LIMIT,
        "cap_enforced": False,
        "measured": False,
        "peak_bytes": None,
        "exit_code": None,
        "elapsed_ms": 0,
        "blocker": None,
    }


def _close_handle(kernel32: object, handle: object | None) -> None:
    if handle:
        try:
            kernel32.CloseHandle(handle)
        except Exception:
            pass


def run_job_object(
    command: Sequence[str],
    *,
    cwd: str | Path,
    timeout_seconds: float = 360.0,
    _inject_failure: str | None = None,
) -> dict[str, object]:
    """Run one bounded child under an owned Job Object.

    ``_inject_failure`` is test-only instrumentation for setup/query failure
    paths; it never changes the successful ownership or cap sequence.
    """

    started = time.monotonic()
    result = _base_result()
    if os.name != "nt":
        result["blocker"] = "job-object:unsupported-platform"
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result
    if not isinstance(command, (list, tuple)) or not command or any(type(item) is not str or not item for item in command):
        result["blocker"] = "job-object:invalid-command"
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result
    working_directory = Path(cwd)
    if not working_directory.is_dir():
        result["blocker"] = "job-object:invalid-cwd"
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle_type = wintypes.HANDLE
    kernel32.CreateJobObjectW.argtypes = [handle_type, wintypes.LPWSTR]
    kernel32.CreateJobObjectW.restype = handle_type
    kernel32.SetInformationJobObject.argtypes = [handle_type, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfo), ctypes.POINTER(_ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [handle_type, handle_type]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [handle_type, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [handle_type]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [handle_type, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [handle_type, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [handle_type, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [handle_type, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [handle_type]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = None
    process_handle = None
    thread_handle = None
    output_fd = None
    error_fd = None
    input_fd = None
    try:
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            result["blocker"] = _win_error("job-object:create")
            return result

        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_JOB_MEMORY
        limits.JobMemoryLimit = _JOB_MEMORY_LIMIT
        if _inject_failure == "configure":
            result["blocker"] = "job-object:configure:injected"
            return result
        if not kernel32.SetInformationJobObject(
            job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            result["blocker"] = _win_error("job-object:configure")
            return result
        result["cap_enforced"] = True

        with tempfile.TemporaryDirectory(prefix="mirror-job-object-") as temporary:
            output_path = Path(temporary) / "stdout.bin"
            error_path = Path(temporary) / "stderr.bin"
            input_path = Path(temporary) / "stdin.bin"
            input_path.write_bytes(b"")
            output_fd = os.open(output_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
            error_fd = os.open(error_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
            input_fd = os.open(input_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            for descriptor in (output_fd, error_fd, input_fd):
                os.set_handle_inheritable(descriptor, True)
            import msvcrt

            startup = _StartupInfo()
            startup.cb = ctypes.sizeof(_StartupInfo)
            startup.dwFlags = _STARTF_USESTDHANDLES
            startup.hStdInput = wintypes.HANDLE(msvcrt.get_osfhandle(input_fd))
            startup.hStdOutput = wintypes.HANDLE(msvcrt.get_osfhandle(output_fd))
            startup.hStdError = wintypes.HANDLE(msvcrt.get_osfhandle(error_fd))
            process_info = _ProcessInformation()
            command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(list(command)))
            if not kernel32.CreateProcessW(
                None,
                command_line,
                None,
                None,
                True,
                _CREATE_SUSPENDED | _CREATE_NO_WINDOW,
                None,
                str(working_directory),
                ctypes.byref(startup),
                ctypes.byref(process_info),
            ):
                result["blocker"] = _win_error("job-object:spawn")
                return result
            process_handle = process_info.hProcess
            thread_handle = process_info.hThread
            os.close(output_fd)
            os.close(error_fd)
            os.close(input_fd)
            output_fd = error_fd = input_fd = None

            if _inject_failure == "assign":
                result["blocker"] = "job-object:assign-process:injected"
                kernel32.TerminateProcess(process_handle, 1)
                kernel32.WaitForSingleObject(process_handle, _INFINITE)
                kernel32.TerminateJobObject(job, 1)
                return result
            if not kernel32.AssignProcessToJobObject(job, process_handle):
                result["blocker"] = _win_error("job-object:assign-process")
                kernel32.TerminateProcess(process_handle, 1)
                kernel32.WaitForSingleObject(process_handle, _INFINITE)
                kernel32.TerminateJobObject(job, 1)
                return result

            if kernel32.ResumeThread(thread_handle) == 0xFFFFFFFF:
                result["blocker"] = _win_error("job-object:resume-thread")
                kernel32.TerminateProcess(process_handle, 1)
                kernel32.WaitForSingleObject(process_handle, _INFINITE)
                kernel32.TerminateJobObject(job, 1)
                return result

            wait_ms = max(1, int(timeout_seconds * 1000))
            wait_result = kernel32.WaitForSingleObject(process_handle, wait_ms)
            if wait_result == _WAIT_TIMEOUT:
                kernel32.TerminateJobObject(job, 2)
                kernel32.WaitForSingleObject(process_handle, _INFINITE)
                result["blocker"] = "job-object:child-timeout"
            elif wait_result != _WAIT_OBJECT_0:
                kernel32.TerminateJobObject(job, 3)
                kernel32.WaitForSingleObject(process_handle, _INFINITE)
                result["blocker"] = _win_error("job-object:wait")

            exit_code = wintypes.DWORD(0)
            if not kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
                result["blocker"] = result["blocker"] or _win_error("job-object:exit-code")
            else:
                result["exit_code"] = int(exit_code.value)

            peak = _ExtendedLimitInformation()
            returned = wintypes.DWORD(0)
            if _inject_failure == "query":
                result["blocker"] = result["blocker"] or "job-object:query-extended-limits:injected"
            elif not kernel32.QueryInformationJobObject(
                job,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(peak),
                ctypes.sizeof(peak),
                ctypes.byref(returned),
            ):
                result["blocker"] = result["blocker"] or _win_error("job-object:query-extended-limits")
            else:
                result["peak_bytes"] = int(peak.PeakJobMemoryUsed)
                result["measured"] = True
                if int(peak.PeakJobMemoryUsed) >= _JOB_MEMORY_LIMIT:
                    result["blocker"] = result["blocker"] or "job-object:memory-cap"

            if result["exit_code"] is not None and result["exit_code"] != 0 and result["blocker"] is None:
                result["blocker"] = f"job-object:child-exit:{result['exit_code']}"
            # Read bounded redirected output only after the owned process exits.
            with output_path.open("rb") as stream:
                stream.read(1 << 20)
            with error_path.open("rb") as stream:
                stream.read(1 << 20)
            return result
    except Exception as exc:
        if result["blocker"] is None:
            result["blocker"] = f"job-object:exception:{type(exc).__name__}"
        return result
    finally:
        if output_fd is not None:
            try:
                os.close(output_fd)
            except OSError:
                pass
        if error_fd is not None:
            try:
                os.close(error_fd)
            except OSError:
                pass
        if input_fd is not None:
            try:
                os.close(input_fd)
            except OSError:
                pass
        if "kernel32" in locals():
            if process_handle:
                exit_code = wintypes.DWORD(0)
                try:
                    if kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)) and exit_code.value == _STILL_ACTIVE:
                        kernel32.TerminateProcess(process_handle, 4)
                        kernel32.WaitForSingleObject(process_handle, _INFINITE)
                except Exception:
                    pass
            _close_handle(kernel32, thread_handle)
            _close_handle(kernel32, process_handle)
            _close_handle(kernel32, job)
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)


__all__ = ["run_job_object"]
