"""Windows Job Object accounting for the synthetic rehearsal evidence gate.

This is test/evidence infrastructure only.  It measures the Windows job's
``PeakJobMemoryUsed`` counter for a spawned rehearsal process after the process
has been assigned to the job, so descendants are accounted for by ownership.
If the host or sandbox refuses job creation, assignment, or accounting, the
result is explicitly unmeasured with the raw Win32 blocker.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import time
from typing import Sequence


_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_PROCESS_ACCESS = 0x0001 | 0x0100 | 0x0400 | 0x1000 | 0x00100000


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
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _win_error(prefix: str) -> str:
    code = ctypes.get_last_error()
    try:
        detail = ctypes.FormatError(code).strip()
    except Exception:
        detail = "unavailable"
    return f"{prefix}:winerror={code}:{detail}"


def run_job_object(
    command: Sequence[str],
    *,
    cwd: str | Path,
    timeout_seconds: float = 360.0,
) -> dict[str, object]:
    """Run one bounded rehearsal child and return owned-tree memory evidence."""

    started = time.monotonic()
    result: dict[str, object] = {
        "counter_name": "PeakJobMemoryUsed",
        "measured": False,
        "peak_bytes": None,
        "exit_code": None,
        "elapsed_ms": 0,
        "blocker": None,
    }
    if os.name != "nt":
        result["blocker"] = "job-object:unsupported-platform"
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle_type = ctypes.c_void_p
    kernel32.CreateJobObjectW.argtypes = [handle_type, ctypes.c_wchar_p]
    kernel32.CreateJobObjectW.restype = handle_type
    kernel32.SetInformationJobObject.argtypes = [handle_type, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    kernel32.SetInformationJobObject.restype = ctypes.c_int
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = handle_type
    kernel32.AssignProcessToJobObject.argtypes = [handle_type, handle_type]
    kernel32.AssignProcessToJobObject.restype = ctypes.c_int
    kernel32.QueryInformationJobObject.argtypes = [handle_type, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.QueryInformationJobObject.restype = ctypes.c_int
    kernel32.TerminateJobObject.argtypes = [handle_type, ctypes.c_uint32]
    kernel32.TerminateJobObject.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [handle_type]
    kernel32.CloseHandle.restype = ctypes.c_int

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        result["blocker"] = _win_error("job-object:create")
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result

    process = None
    process_handle = None
    try:
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            result["blocker"] = _win_error("job-object:configure")
            return result

        try:
            process = subprocess.Popen(
                list(command),
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as exc:
            result["blocker"] = f"job-object:spawn:{type(exc).__name__}"
            return result

        process_handle = kernel32.OpenProcess(_PROCESS_ACCESS, False, process.pid)
        if not process_handle:
            result["blocker"] = _win_error("job-object:open-process")
            process.kill()
            process.communicate()
            result["exit_code"] = process.returncode
            return result
        if not kernel32.AssignProcessToJobObject(job, process_handle):
            result["blocker"] = _win_error("job-object:assign-process")
            kernel32.TerminateJobObject(job, 1)
            if process.poll() is None:
                process.kill()
            process.communicate()
            result["exit_code"] = process.returncode
            return result

        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            kernel32.TerminateJobObject(job, 2)
            stdout, stderr = process.communicate()
            result["blocker"] = "job-object:child-timeout"
            result["exit_code"] = process.returncode
            return result
        result["exit_code"] = process.returncode
        if process.returncode != 0:
            result["blocker"] = f"job-object:child-exit:{process.returncode}"
            return result

        peak = _ExtendedLimitInformation()
        returned = ctypes.c_uint32(0)
        if not kernel32.QueryInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(peak),
            ctypes.sizeof(peak),
            ctypes.byref(returned),
        ):
            result["blocker"] = _win_error("job-object:query-extended-limits")
            return result
        result["peak_bytes"] = int(peak.PeakJobMemoryUsed)
        result["measured"] = True
        return result
    finally:
        if process_handle:
            kernel32.CloseHandle(process_handle)
        kernel32.CloseHandle(job)
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)


__all__ = ["run_job_object"]
