"""Small shared process boundary for experimental proving attempts.

On Windows this owns the suspended CreateProcessW/Job Object sequence and the
explicit standard-handle allowlist.  The non-Windows branch is retained only
as an explicitly non-qualified process-group exercise; it does not claim the
Windows memory cap.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Sequence
import uuid

from tools.proving_resource_policy import (
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    ProvingResourcePolicyV1,
)


CAP_BYTES = 5_000_000_000
# The trusted Python launcher is a small trampoline on Windows and starts the
# actual interpreter; leave a bounded slot for that child and for the native
# prover's short-lived descendants while keeping the complete Job tree finite.
ACTIVE_PROCESS_LIMIT = 64
_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_STARTF_USESTDHANDLES = 0x00000100
_HANDLE_FLAG_INHERIT = 0x00000001
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF
_STILL_ACTIVE = 259
_ERROR_INSUFFICIENT_BUFFER = 122
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_TEMPORARY = 0x00000100


class ProvingProcessError(RuntimeError):
    """A fixed, non-diagnostic process-boundary error."""

    def __init__(self, code: str) -> None:
        super().__init__(code if isinstance(code, str) else "proving_process_error")
        self.code = str(self)


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
        ("lpReserved2", wintypes.LPBYTE),
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


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTime", ctypes.c_longlong),
        ("PerJobUserTime", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
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


@dataclass(frozen=True, slots=True)
class ContainedProcessResult:
    exit_code: int
    stdout_bytes: int
    stderr_bytes: int
    peak_job_commit_bytes: int
    cap_bytes: int
    cap_enforced: bool
    active_process_limit: int
    timed_out: bool
    output_overflow: bool
    tree_confirmed: bool
    capacity_breach: bool = False


def _win_error(code: str) -> ProvingProcessError:
    return ProvingProcessError(code)


def _read_capped_file(
    path: Path, maximum: int, code: str, *, allow_overflow: bool = False
) -> bytes:
    try:
        size = path.stat().st_size
        if size > maximum and not allow_overflow:
            raise ProvingProcessError(f"{code}_cap")
        with path.open("rb") as stream:
            data = stream.read(maximum if allow_overflow else maximum + 1)
        if len(data) > maximum or (not allow_overflow and len(data) != size):
            raise ProvingProcessError(f"{code}_read")
        return data
    except ProvingProcessError:
        raise
    except OSError:
        raise ProvingProcessError(f"{code}_read") from None


def _configure_kernel32(kernel32: Any) -> None:
    required = (
        "CreateJobObjectW",
        "SetInformationJobObject",
        "CreateProcessW",
        "AssignProcessToJobObject",
        "ResumeThread",
        "WaitForSingleObject",
        "TerminateJobObject",
        "GetExitCodeProcess",
        "QueryInformationJobObject",
        "CloseHandle",
        "SetHandleInformation",
        "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute",
        "DeleteProcThreadAttributeList",
        "CreateFileW",
        "CreatePipe",
        "WriteFile",
        "TerminateProcess",
    )
    if any(not hasattr(kernel32, name) for name in required):
        raise ProvingProcessError("proving_process_api_missing")
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.POINTER(_SecurityAttributes),
        ctypes.POINTER(_SecurityAttributes),
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfo),
        ctypes.POINTER(_ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    kernel32.SetHandleInformation.restype = wintypes.BOOL
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
    kernel32.DeleteProcThreadAttributeList.restype = None
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
    ]
    kernel32.CreatePipe.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL


def _close_handle_once(kernel32: Any, handle: Any) -> bool:
    if not handle:
        return True
    try:
        result = kernel32.CloseHandle(handle)
        return True if result is None else bool(result)
    except Exception:
        return False


class _WindowsContainedProcess:
    def __init__(
        self,
        *,
        kernel32: Any,
        process_info: _ProcessInformation,
        job: Any,
        stdin_write: Any,
        output_paths: tuple[Path, Path],
        policy: ProvingResourcePolicyV1,
    ) -> None:
        self._kernel32 = kernel32
        self._process_info = process_info
        self._job = job
        self._stdin_write = stdin_write
        self._output_paths = output_paths
        self._policy = policy
        self._closed = False
        self._returncode: int | None = None
        self.pid = int(process_info.dwProcessId)

    @property
    def returncode(self) -> int | None:
        if self._returncode is not None:
            return self._returncode
        code = wintypes.DWORD()
        if not self._kernel32.GetExitCodeProcess(self._process_info.hProcess, ctypes.byref(code)):
            raise _win_error("proving_process_exit_code")
        if int(code.value) == _STILL_ACTIVE:
            return None
        self._returncode = int(code.value)
        return self._returncode

    def poll(self) -> int | None:
        return self.returncode

    def send_input(self, payload: bytes) -> None:
        if not isinstance(payload, bytes) or len(payload) > 128 * 1024 * 1024:
            raise ProvingProcessError("proving_process_input_cap")
        if self._stdin_write is None:
            if payload:
                raise ProvingProcessError("proving_process_input_unavailable")
            return
        try:
            offset = 0
            while offset < len(payload):
                chunk = payload[offset : offset + 1_048_576]
                buffer = ctypes.create_string_buffer(chunk)
                written = wintypes.DWORD()
                if not self._kernel32.WriteFile(
                    self._stdin_write,
                    ctypes.cast(buffer, wintypes.LPCVOID),
                    len(chunk),
                    ctypes.byref(written),
                    None,
                ):
                    raise _win_error("proving_process_input_write")
                if int(written.value) != len(chunk):
                    raise ProvingProcessError("proving_process_input_write")
                offset += len(chunk)
        finally:
            _close_handle_once(self._kernel32, self._stdin_write)
            self._stdin_write = None

    def close_input(self) -> None:
        if self._stdin_write is not None:
            _close_handle_once(self._kernel32, self._stdin_write)
            self._stdin_write = None

    def wait(self, timeout_seconds: float | None = None) -> int:
        wait_ms = _INFINITE if timeout_seconds is None else max(1, int(timeout_seconds * 1000))
        result = self._kernel32.WaitForSingleObject(self._process_info.hProcess, wait_ms)
        if result == _WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired("proving process", timeout_seconds)
        if result != _WAIT_OBJECT_0:
            raise _win_error("proving_process_wait")
        code = self.returncode
        if code is None:
            raise ProvingProcessError("proving_process_exit_code")
        return code

    def terminate_tree(self) -> bool:
        if self.poll() is not None:
            return True
        if not self._kernel32.TerminateJobObject(self._job, 1):
            return False
        try:
            self.wait(None)
        except (OSError, ProvingProcessError, subprocess.TimeoutExpired):
            return False
        return True

    def collect(
        self,
        *,
        timed_out: bool = False,
        output_overflow: bool = False,
        capacity_breach: bool = False,
    ) -> ContainedProcessResult:
        self.wait(None)
        observed = _ExtendedLimitInformation()
        if not self._kernel32.QueryInformationJobObject(
            self._job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(observed),
            ctypes.sizeof(observed),
            None,
        ):
            raise _win_error("proving_process_job_query")
        peak = int(observed.PeakJobMemoryUsed)
        try:
            observed_overflow = output_overflow or (
                self._output_paths[0].stat().st_size > self._policy.max_stdout_bytes
                or self._output_paths[1].stat().st_size > self._policy.max_stderr_bytes
            )
        except OSError:
            raise ProvingProcessError("proving_process_output_stat") from None
        stdout = _read_capped_file(
            self._output_paths[0],
            self._policy.max_stdout_bytes,
            "proving_stdout",
            allow_overflow=observed_overflow,
        )
        stderr = _read_capped_file(
            self._output_paths[1],
            self._policy.max_stderr_bytes,
            "proving_stderr",
            allow_overflow=observed_overflow,
        )
        if peak > self._policy.windows_job_memory_cap_bytes:
            raise ProvingProcessError("proving_process_memory_cap")
        return ContainedProcessResult(
            exit_code=int(self.returncode or 0),
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            peak_job_commit_bytes=peak,
            cap_bytes=self._policy.windows_job_memory_cap_bytes,
            cap_enforced=True,
            active_process_limit=ACTIVE_PROCESS_LIMIT,
            timed_out=timed_out,
            output_overflow=observed_overflow,
            tree_confirmed=True,
            capacity_breach=capacity_breach,
        )

    def output_over_limit(self) -> bool:
        try:
            return (
                self._output_paths[0].stat().st_size > self._policy.max_stdout_bytes
                or self._output_paths[1].stat().st_size > self._policy.max_stderr_bytes
            )
        except OSError:
            raise ProvingProcessError("proving_process_output_stat") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        cleanup_error = False
        try:
            if self.poll() is None:
                cleanup_error = not self.terminate_tree()
        except (OSError, ProvingProcessError):
            cleanup_error = True
        self.close_input()
        for handle in (self._process_info.hThread, self._process_info.hProcess, self._job):
            if not _close_handle_once(self._kernel32, handle):
                cleanup_error = True
        for path in self._output_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                cleanup_error = True
        if cleanup_error:
            raise ProvingProcessError("proving_process_cleanup")


def _owned_capacity_breached(root: Path, policy: ProvingResourcePolicyV1) -> bool:
    if not isinstance(root, Path):
        raise ProvingProcessError("proving_process_owned_root")
    try:
        root_info = os.lstat(root)
    except OSError:
        raise ProvingProcessError("proving_process_owned_root") from None
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ProvingProcessError("proving_process_owned_root")
    file_count = 0
    total_bytes = 0
    entry_count = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError:
            raise ProvingProcessError("proving_process_owned_measurement") from None
        try:
            for entry in entries:
                entry_count += 1
                if entry_count > policy.max_owned_files * 2:
                    return True
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    raise ProvingProcessError("proving_process_owned_measurement") from None
                if stat.S_ISLNK(info.st_mode):
                    raise ProvingProcessError("proving_process_owned_symlink")
                if stat.S_ISREG(info.st_mode):
                    file_count += 1
                    total_bytes += int(info.st_size)
                    if (
                        file_count > policy.max_owned_files
                        or total_bytes > policy.max_job_bytes
                    ):
                        return True
                elif stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                else:
                    raise ProvingProcessError("proving_process_owned_nonregular")
        finally:
            entries.close()
    return False


def _start_windows_process(
    command: Sequence[str],
    *,
    cwd: Path,
    policy: ProvingResourcePolicyV1,
    input_enabled: bool,
) -> tuple[_WindowsContainedProcess, Callable[[], None]]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _configure_kernel32(kernel32)
    if not isinstance(cwd, Path) or not cwd.is_dir() or cwd.is_symlink():
        raise ProvingProcessError("proving_process_cwd")
    if any(type(item) is not str or not item or "\x00" in item for item in command):
        raise ProvingProcessError("proving_process_command")
    output_paths = (
        cwd / f".bl-proving-stdout-{uuid.uuid4().hex}.tmp",
        cwd / f".bl-proving-stderr-{uuid.uuid4().hex}.tmp",
    )
    for path in output_paths:
        try:
            path.touch(mode=0o600, exist_ok=False)
        except OSError:
            for old in output_paths:
                old.unlink(missing_ok=True)
            raise ProvingProcessError("proving_process_output_create") from None

    security = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
    owned_handles: list[Any] = []
    attribute_list: Any = None
    attribute_storage: Any = None
    attribute_initialized = False
    process_created = False
    job: Any = None
    process_info = _ProcessInformation()
    stdin_write: Any = None
    try:
        def create_file(path: str, access: int, share: int) -> Any:
            handle = kernel32.CreateFileW(
                path,
                access,
                share,
                ctypes.byref(security),
                _OPEN_EXISTING,
                _FILE_ATTRIBUTE_TEMPORARY,
                None,
            )
            if not handle:
                raise _win_error("proving_process_handle_create")
            if not kernel32.SetHandleInformation(handle, _HANDLE_FLAG_INHERIT, _HANDLE_FLAG_INHERIT):
                _close_handle_once(kernel32, handle)
                raise _win_error("proving_process_handle_inherit")
            owned_handles.append(handle)
            return handle

        stdout_handle = create_file(str(output_paths[0]), _GENERIC_WRITE, _FILE_SHARE_READ | _FILE_SHARE_WRITE)
        stderr_handle = create_file(str(output_paths[1]), _GENERIC_WRITE, _FILE_SHARE_READ | _FILE_SHARE_WRITE)
        if input_enabled:
            read_handle = wintypes.HANDLE()
            write_handle = wintypes.HANDLE()
            if not kernel32.CreatePipe(ctypes.byref(read_handle), ctypes.byref(write_handle), ctypes.byref(security), 0):
                raise _win_error("proving_process_stdin_create")
            owned_handles.append(read_handle)
            stdin_write = write_handle
            if not kernel32.SetHandleInformation(stdin_write, _HANDLE_FLAG_INHERIT, 0):
                raise _win_error("proving_process_stdin_inherit")
        else:
            stdin_handle = create_file("NUL", _GENERIC_READ, _FILE_SHARE_READ)
            read_handle = stdin_handle

        startup = _StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = read_handle
        startup.StartupInfo.hStdOutput = stdout_handle
        startup.StartupInfo.hStdError = stderr_handle

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise _win_error("proving_process_job_create")
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_JOB_MEMORY
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        )
        limits.BasicLimitInformation.ActiveProcessLimit = ACTIVE_PROCESS_LIMIT
        limits.JobMemoryLimit = policy.windows_job_memory_cap_bytes
        if not kernel32.SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise _win_error("proving_process_job_limits")

        attribute_size = ctypes.c_size_t(0)
        first = kernel32.InitializeProcThreadAttributeList(
            None, 1, 0, ctypes.byref(attribute_size)
        )
        error = ctypes.get_last_error()
        if first or error != _ERROR_INSUFFICIENT_BUFFER or not attribute_size.value:
            raise ProvingProcessError("proving_process_attribute_size")
        attribute_storage = ctypes.create_string_buffer(attribute_size.value)
        attribute_list = ctypes.cast(attribute_storage, wintypes.LPVOID)
        if not kernel32.InitializeProcThreadAttributeList(attribute_list, 1, 0, ctypes.byref(attribute_size)):
            raise _win_error("proving_process_attribute_initialize")
        attribute_initialized = True
        inherited = (wintypes.HANDLE * len(owned_handles))(*owned_handles)
        if not kernel32.UpdateProcThreadAttribute(
            attribute_list,
            0,
            _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.cast(inherited, wintypes.LPVOID),
            ctypes.sizeof(inherited),
            None,
            None,
        ):
            raise _win_error("proving_process_attribute_update")
        startup.lpAttributeList = attribute_list
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(list(command)))
        flags = _CREATE_SUSPENDED | _CREATE_NO_WINDOW | _EXTENDED_STARTUPINFO_PRESENT
        if not kernel32.CreateProcessW(
            None,
            command_line,
            None,
            None,
            True,
            flags,
            None,
            str(cwd),
            ctypes.cast(ctypes.byref(startup), ctypes.POINTER(_StartupInfo)),
            ctypes.byref(process_info),
        ):
            raise _win_error("proving_process_create")
        process_created = True
        if not kernel32.AssignProcessToJobObject(job, process_info.hProcess):
            kernel32.TerminateProcess(process_info.hProcess, 1)
            raise _win_error("proving_process_job_assign")
        if kernel32.ResumeThread(process_info.hThread) in {-1, 0xFFFFFFFF}:
            raise _win_error("proving_process_resume")
        process = _WindowsContainedProcess(
            kernel32=kernel32,
            process_info=process_info,
            job=job,
            stdin_write=stdin_write,
            output_paths=output_paths,
            policy=policy,
        )
        stdin_write = None
        return process, process.close
    except BaseException:
        cleanup_error = False
        if process_created and process_info.hProcess:
            try:
                if not kernel32.TerminateJobObject(job, 1):
                    cleanup_error = True
            except Exception:
                cleanup_error = True
        if attribute_initialized:
            try:
                kernel32.DeleteProcThreadAttributeList(attribute_list)
            except Exception:
                cleanup_error = True
            attribute_initialized = False
        if stdin_write:
            if not _close_handle_once(kernel32, stdin_write):
                cleanup_error = True
            stdin_write = None
        for handle in reversed(owned_handles):
            if not _close_handle_once(kernel32, handle):
                cleanup_error = True
        owned_handles.clear()
        if process_info.hThread:
            if not _close_handle_once(kernel32, process_info.hThread):
                cleanup_error = True
        if process_info.hProcess:
            if not _close_handle_once(kernel32, process_info.hProcess):
                cleanup_error = True
        if job:
            if not _close_handle_once(kernel32, job):
                cleanup_error = True
        try:
            for path in output_paths:
                path.unlink(missing_ok=True)
        except OSError:
            cleanup_error = True
        if cleanup_error:
            raise ProvingProcessError("proving_process_cleanup") from None
        raise
    finally:
        cleanup_error = False
        if attribute_initialized:
            try:
                kernel32.DeleteProcThreadAttributeList(attribute_list)
            except Exception:
                cleanup_error = True
            attribute_initialized = False
        for handle in reversed(owned_handles):
            if not _close_handle_once(kernel32, handle):
                cleanup_error = True
        owned_handles.clear()
        if cleanup_error:
            if process_created and job:
                try:
                    kernel32.TerminateJobObject(job, 1)
                except Exception:
                    pass
            if stdin_write:
                _close_handle_once(kernel32, stdin_write)
                stdin_write = None
            if process_created:
                _close_handle_once(kernel32, process_info.hThread)
                _close_handle_once(kernel32, process_info.hProcess)
                _close_handle_once(kernel32, job)
            for path in output_paths:
                path.unlink(missing_ok=True)
            raise ProvingProcessError("proving_process_cleanup") from None


def start_contained_process(
    command: Sequence[str],
    *,
    cwd: Path,
    policy: ProvingResourcePolicyV1,
    input_enabled: bool = False,
) -> tuple[Any, Callable[[], None]]:
    if not isinstance(policy, ProvingResourcePolicyV1):
        raise ProvingProcessError("proving_process_policy")
    if os.name == "nt":
        return _start_windows_process(command, cwd=cwd, policy=policy, input_enabled=input_enabled)
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            stdin=subprocess.PIPE if input_enabled else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            shell=False,
        )
    except (OSError, ValueError):
        raise ProvingProcessError("proving_process_launch") from None

    def close_group() -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass

    return process, close_group


def run_contained_process(
    command: Sequence[str],
    *,
    cwd: Path,
    policy: ProvingResourcePolicyV1,
    input_bytes: bytes | None = None,
    owned_root: Path | None = None,
) -> ContainedProcessResult:
    process, close = start_contained_process(
        command,
        cwd=cwd,
        policy=policy,
        input_enabled=input_bytes is not None,
    )
    started = time.monotonic()
    timed_out = False
    output_overflow = False
    capacity_breach = False
    try:
        if isinstance(process, _WindowsContainedProcess):
            if input_bytes is not None:
                process.send_input(input_bytes)
            else:
                process.close_input()
            while process.poll() is None:
                if process.output_over_limit():
                    output_overflow = True
                    if not process.terminate_tree():
                        raise ProvingProcessError("proving_process_tree_termination")
                    break
                if owned_root is not None and _owned_capacity_breached(owned_root, policy):
                    capacity_breach = True
                    if not process.terminate_tree():
                        raise ProvingProcessError("proving_process_tree_termination")
                    break
                if time.monotonic() - started >= policy.timeout_seconds:
                    timed_out = True
                    if not process.terminate_tree():
                        raise ProvingProcessError("proving_process_tree_termination")
                    break
                time.sleep(0.05)
            result = process.collect(
                timed_out=timed_out,
                output_overflow=output_overflow,
                capacity_breach=capacity_breach,
            )
            return result

        streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = threading.Event()
        reader_errors: list[str] = []
        writer_errors: list[str] = []
        stop_termination = threading.Event()

        def terminate_group() -> None:
            if stop_termination.is_set():
                return
            stop_termination.set()
            close()

        def read_stream(name: str, stream: Any, maximum: int) -> None:
            try:
                while True:
                    chunk = stream.read(min(64 * 1024, maximum + 1))
                    if not chunk:
                        return
                    remaining = maximum - len(streams[name])
                    if len(chunk) > remaining:
                        if remaining > 0:
                            streams[name].extend(chunk[:remaining])
                        overflow.set()
                        terminate_group()
                        return
                    streams[name].extend(chunk)
            except (OSError, ValueError):
                reader_errors.append("proving_process_output_read")
                terminate_group()

        def write_input() -> None:
            if input_bytes is None or process.stdin is None:
                return
            try:
                process.stdin.write(input_bytes)
                process.stdin.close()
            except (OSError, ValueError):
                writer_errors.append("proving_process_input_write")
                terminate_group()

        readers = [
            threading.Thread(
                target=read_stream,
                args=("stdout", process.stdout, policy.max_stdout_bytes),
                daemon=True,
            ),
            threading.Thread(
                target=read_stream,
                args=("stderr", process.stderr, policy.max_stderr_bytes),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()
        writer = threading.Thread(target=write_input, daemon=True)
        writer.start()
        while process.poll() is None:
            if overflow.is_set():
                break
            if owned_root is not None and _owned_capacity_breached(owned_root, policy):
                capacity_breach = True
                terminate_group()
                break
            if time.monotonic() - started >= policy.timeout_seconds:
                timed_out = True
                terminate_group()
                break
            time.sleep(0.05)
        if process.poll() is None:
            terminate_group()
        process.wait()
        writer.join(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        if reader_errors:
            raise ProvingProcessError(reader_errors[0])
        if writer_errors:
            raise ProvingProcessError(writer_errors[0])
        output_overflow = overflow.is_set()
        stdout = bytes(streams["stdout"])
        stderr = bytes(streams["stderr"])
        if output_overflow:
            return ContainedProcessResult(
                exit_code=int(process.returncode or 1),
                stdout_bytes=min(len(stdout), policy.max_stdout_bytes),
                stderr_bytes=min(len(stderr), policy.max_stderr_bytes),
                peak_job_commit_bytes=0,
                cap_bytes=0,
                cap_enforced=False,
                active_process_limit=0,
                timed_out=timed_out,
                output_overflow=True,
                tree_confirmed=True,
                capacity_breach=capacity_breach,
            )
        return ContainedProcessResult(
            exit_code=int(process.returncode or 0),
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            peak_job_commit_bytes=0,
            cap_bytes=0,
            cap_enforced=False,
            active_process_limit=0,
            timed_out=timed_out,
            output_overflow=False,
            tree_confirmed=True,
            capacity_breach=capacity_breach,
        )
    finally:
        close()


__all__ = (
    "ACTIVE_PROCESS_LIMIT",
    "CAP_BYTES",
    "ContainedProcessResult",
    "ProvingProcessError",
    "run_contained_process",
    "start_contained_process",
)
