from __future__ import annotations

import ctypes
import hashlib
import itertools
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import app.minimal_clearance_verifier_process as process


class _FakeFunction:
    def __init__(self, callback):
        self._callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self._callback(*args)


class _Kernel:
    def __init__(self, *, failure: str | None = None, overlap: bool = False, pin_failure: str | None = None, pin_data: bytes | None = None, job_limit_mismatch: str | None = None):
        self.failure = failure
        self.pin_failure = pin_failure
        self.job_limit_mismatch = job_limit_mismatch
        self.pin_data = pin_data or b""
        self.pin_path: Path | None = None
        self.canonical_path = r"\\?\Volume{11111111-2222-3333-4444-555555555555}\synthetic\verifier.exe"
        self.nt_path = r"\Device\HarddiskVolume3\synthetic\verifier.exe"
        self.dos_path = r"\\?\C:\synthetic\verifier.exe"
        self.dos_parent = r"\\?\C:\synthetic"
        self.native_volume_prefix = r"\Device\HarddiskVolume3"
        self.child_image_path = self.nt_path
        self.drive_mapping = self.native_volume_prefix
        self.query_dos_device_count = 0
        self.pin_handles: dict[int, dict[str, object]] = {}
        self._next_pin_handle = 16000
        self.pin_closed = False
        self.pin_close_count = 0
        self.job_limit_flags = 0
        self.job_memory_limit = 0
        self.job_active_process_limit = 0
        self.events: list[tuple[str, object]] = []
        self.handles: list[int] = []
        self._processes = itertools.count(1)
        self._jobs = itertools.count(1)
        self._barrier = threading.Barrier(2) if overlap else None
        self._install()

    def _install(self) -> None:
        self.CreateJobObjectW = _FakeFunction(self._job)
        self.SetInformationJobObject = _FakeFunction(self._limits)
        self.CreateProcessW = _FakeFunction(self._create)
        self.AssignProcessToJobObject = _FakeFunction(self._assign)
        self.ResumeThread = _FakeFunction(self._resume)
        self.WaitForSingleObject = _FakeFunction(self._wait)
        self.TerminateJobObject = _FakeFunction(lambda *_: self._record("terminate_job") or 1)
        self.TerminateProcess = _FakeFunction(lambda *_: self._record("terminate_process") or 1)
        self.GetExitCodeProcess = _FakeFunction(self._exit)
        self.QueryInformationJobObject = _FakeFunction(self._query)
        self.CloseHandle = _FakeFunction(self._close)
        self.SetHandleInformation = _FakeFunction(lambda *_: 1)
        self.GetCurrentProcess = _FakeFunction(lambda: 9000)
        self.GetSystemInfo = _FakeFunction(self._system_info)
        self.DuplicateHandle = _FakeFunction(self._duplicate)
        self.CreateFileW = _FakeFunction(self._open_file)
        self.GetFileType = _FakeFunction(self._file_type)
        self.GetFileInformationByHandle = _FakeFunction(self._file_information)
        self.GetFinalPathNameByHandleW = _FakeFunction(self._final_path)
        self.GetFileInformationByHandleEx = _FakeFunction(self._file_information_ex)
        self.QueryDosDeviceW = _FakeFunction(self._query_dos_device)
        self.CompareStringOrdinal = _FakeFunction(self._compare_string_ordinal)
        self.K32GetProcessImageFileNameW = _FakeFunction(self._process_image)
        self.ReadFile = _FakeFunction(self._read_file)
        self.GetProcessMemoryInfo, self.PeekNamedPipe = _FakeFunction(self._memory_info), _FakeFunction(lambda *_: 1)
        self.InitializeProcThreadAttributeList = _FakeFunction(self._attrs_init)
        self.UpdateProcThreadAttribute = _FakeFunction(self._attrs_update)
        self.DeleteProcThreadAttributeList = _FakeFunction(self._attrs_delete)

    def _record(self, name: str) -> bool:
        self.events.append((name, True))
        return True

    def _job(self, *_):
        if self.failure == "setup":
            return 0
        value = 7000 + next(self._jobs)
        self.events.append(("job", value))
        return value

    def _limits(self, _job, _class, limits_ptr, _size):
        limits = ctypes.cast(limits_ptr, ctypes.POINTER(process._JobObjectExtendedLimitInformation)).contents
        self.job_limit_flags = int(limits.BasicLimitInformation.LimitFlags)
        self.job_memory_limit = int(limits.JobMemoryLimit)
        self.job_active_process_limit = int(limits.BasicLimitInformation.ActiveProcessLimit)
        self.events.append(("job_limits_set", (self.job_limit_flags, self.job_memory_limit, self.job_active_process_limit)))
        self.events.append(("limits", True))
        return 0 if self.failure == "limits" else 1

    def _system_info(self, info_ptr):
        information = ctypes.cast(info_ptr, ctypes.POINTER(process._SystemInfo)).contents
        information.dwPageSize = 4096
        self.events.append(("system_info", 4096))

    def _attrs_init(self, attribute_list, _count, _flags, size_ptr):
        size = ctypes.cast(size_ptr, ctypes.POINTER(ctypes.c_size_t)).contents
        if not attribute_list:
            size.value = 64
            self.events.append(("attr_size", 64))
            return 0
        self.events.append(("attr_initialize", True))
        return 0 if self.failure == "attribute_initialize" else 1

    def _attrs_update(self, _attribute_list, _flags, attribute, value, size, _previous, _returned):
        self.events.append(("attr_update", int(attribute)))
        if self.failure == "attribute_update":
            return 0
        count = int(size) // ctypes.sizeof(process.wintypes.HANDLE)
        handles = ctypes.cast(value, ctypes.POINTER(process.wintypes.HANDLE * count)).contents
        self.handles = [int(item.value if hasattr(item, "value") else item) for item in handles]
        self.events.append(("attr_bytes", int(size)))
        return 1

    def _duplicate(self, _source_process, _source_handle, _target_process, target_ptr, _access, _inherit, _options):
        target = ctypes.cast(target_ptr, ctypes.POINTER(process.wintypes.HANDLE)).contents
        target.value = 14000
        self.events.append(("duplicate", 14000))
        return 1

    def _open_file(self, application, access, share_mode, _security, creation, flags, _template):
        self.events.append(("pin_open", (str(application), int(access), int(share_mode), int(creation), int(flags))))
        path = str(application)
        is_directory = bool(int(flags) & process._FILE_FLAG_BACKUP_SEMANTICS)
        if self.pin_failure == "open" and not is_directory:
            return process._INVALID_HANDLE_VALUE
        if self.pin_failure == "directory_open" and is_directory:
            return process._INVALID_HANDLE_VALUE
        if self.pin_failure == "reopen_open" and not is_directory and path == self.dos_path:
            return process._INVALID_HANDLE_VALUE
        if not is_directory and self.pin_path is None:
            self.pin_path = Path(path)
            if not self.pin_data:
                self.pin_data = self.pin_path.read_bytes()
        handle = self._next_pin_handle
        self._next_pin_handle += 1
        self.pin_handles[handle] = {
            "path": path,
            "directory": is_directory,
            "data": b"" if is_directory else self.pin_data,
            "offset": 0,
            "closed": False,
        }
        self.pin_closed = False
        return handle

    def _file_type(self, _handle):
        return 0 if self.pin_failure == "type" else process._FILE_TYPE_DISK

    def _file_information(self, handle, information_ptr):
        if self.pin_failure == "stat":
            return 0
        state = self.pin_handles[int(handle)]
        information = ctypes.cast(information_ptr, ctypes.POINTER(process._ByHandleFileInformation)).contents
        attributes = process._FILE_ATTRIBUTE_DIRECTORY if state["directory"] else 0
        if self.pin_failure == "directory" and not state["directory"]:
            attributes |= process._FILE_ATTRIBUTE_DIRECTORY
        if self.pin_failure == "reparse" or (
            self.pin_failure == "directory_reparse" and state["directory"]
        ):
            attributes |= process._FILE_ATTRIBUTE_REPARSE_POINT
        information.dwFileAttributes = attributes
        data = state["data"]
        information.nFileSizeHigh = len(data) >> 32
        information.nFileSizeLow = len(data) & 0xFFFFFFFF
        return 1

    def _final_path(self, _handle, buffer, _size, flags):
        if self.pin_failure == "final_path":
            return 0
        if self.pin_failure == "nt_non_device" and (
            int(flags) & process._VOLUME_NAME_NT
        ):
            path = r"\Device\Mup\synthetic\verifier.exe"
        elif self.pin_failure == "dos_unc" and not int(flags) & (
            process._VOLUME_NAME_NT | process._VOLUME_NAME_GUID
        ):
            path = r"\\?\UNC\server\share\verifier.exe"
        elif int(flags) & process._VOLUME_NAME_NT:
            path = self.nt_path
        elif int(flags) & process._VOLUME_NAME_GUID:
            path = self.canonical_path
        else:
            path = self.dos_path
        buffer.value = path
        self.events.append(("final_path", (int(flags), path)))
        return len(path)

    def _file_information_ex(self, handle, _class, information_ptr, _size):
        if self.pin_failure == "file_id":
            return 0
        state = self.pin_handles[int(handle)]
        information = ctypes.cast(information_ptr, ctypes.POINTER(process._FileIdInfo)).contents
        information.VolumeSerialNumber = 0x123456789ABCDEF0
        value = b"R" * 16
        if self.pin_failure == "file_id_mismatch" and state["path"] == self.dos_path:
            value = b"M" * 16
        information.FileId[:] = value
        self.events.append(("file_id", (state["path"], value)))
        return 1

    def _query_dos_device(self, drive, buffer, _size):
        if self.pin_failure == "dos_mapping":
            return 0
        self.query_dos_device_count += 1
        mapping = self.drive_mapping
        if self.pin_failure == "dos_mapping_mismatch" or (
            self.pin_failure == "dos_mapping_after_create"
            and self.query_dos_device_count >= 2
        ):
            mapping = r"\Device\HarddiskVolume99"
        buffer.value = mapping
        self.events.append(("query_dos_device", (str(drive), mapping)))
        return len(mapping)

    def _compare_string_ordinal(self, first, _first_length, second, _second_length, ignore_case):
        left = str(first)
        right = str(second)
        if ignore_case:
            left = left.casefold()
            right = right.casefold()
        return 2 if left == right else 1

    def _process_image(self, _process, buffer, _size):
        if self.pin_failure == "image_api":
            return 0
        if self.pin_failure == "image_truncated":
            return process._MAX_FINAL_PATH_CHARS
        if self.pin_failure == "image_non_device":
            value = r"C:\synthetic\verifier.exe"
        elif self.pin_failure == "image_mismatch":
            value = self.nt_path + r"\other.exe"
        else:
            value = self.child_image_path
        buffer.value = value
        self.events.append(("child_image", value))
        return len(value)

    def _read_file(self, handle, buffer, requested, read_ptr, _overlapped):
        if self.pin_failure == "read":
            return 0
        state = self.pin_handles[int(handle)]
        data = state["data"]
        offset = int(state["offset"])
        count = min(int(requested), len(data) - offset)
        if count > 0:
            ctypes.memmove(buffer, data[offset:offset + count], count)
            state["offset"] = offset + count
        ctypes.cast(read_ptr, ctypes.POINTER(process.wintypes.DWORD)).contents.value = count
        self.events.append(("pin_read", count))
        return 1

    def _memory_info(self, _handle, counters_ptr, _size):
        counters = ctypes.cast(counters_ptr, ctypes.POINTER(process._ProcessMemoryCountersEx)).contents
        counters.PeakWorkingSetSize = 1
        counters.PrivateUsage = 1
        self.events.append(("memory", True))
        return 1

    def _attrs_delete(self, _attribute_list):
        self.events.append(("attr_delete", True))
        if self.failure == "attribute_delete":
            raise RuntimeError("attribute cleanup canary")

    def _create(self, application, command, _p1, _p2, inherit, flags, _env, directory, startup_ptr, process_ptr):
        if self.pin_handles:
            self.events.append(("pin_held_during_create", all(not state["closed"] for state in self.pin_handles.values())))
        self.events.append(("create_application", str(application)))
        self.events.append(("create_command", command.value))
        self.events.append(("create_directory", str(directory)))
        self.events.append(("create_args", (bool(inherit), int(flags))))
        startup = ctypes.cast(startup_ptr, ctypes.POINTER(process._StartupInfoEx)).contents
        self.events.append(("startup_cb", int(startup.StartupInfo.cb)))
        input_handle = startup.StartupInfo.hStdInput
        self.events.append(("startup_input", 0 if input_handle is None else int(input_handle)))
        if self.failure == "create":
            return 0
        if self._barrier is not None:
            self._barrier.wait(timeout=5)
        number = next(self._processes)
        info = ctypes.cast(process_ptr, ctypes.POINTER(process._ProcessInformation)).contents
        info.hProcess = 5000 + number
        info.hThread = 6000 + number
        self.events.append(("create", number))
        return 1

    def _assign(self, *_):
        self.events.append(("assign", True))
        return 0 if self.failure == "assign" else 1

    def _resume(self, *_):
        self.events.append(("resume", True))
        return 0xFFFFFFFF if self.failure == "resume" else 0

    def _wait(self, *_):
        self.events.append(("wait", True))
        return 3 if self.failure == "wait" else 0

    def _exit(self, _process, code_ptr):
        if self.failure == "exit":
            return 0
        ctypes.cast(code_ptr, ctypes.POINTER(process.wintypes.DWORD)).contents.value = 0
        return 1

    def _query(self, _job, _class, observed_ptr, _size, _returned):
        if self.failure == "query":
            return 0
        if _class == 1:
            accounting = ctypes.cast(observed_ptr, ctypes.POINTER(process._JobObjectBasicAccountingInformation)).contents
            accounting.TotalProcesses = 1
            accounting.ActiveProcesses = 0
        else:
            observed = ctypes.cast(observed_ptr, ctypes.POINTER(process._JobObjectExtendedLimitInformation)).contents
            observed.PeakJobMemoryUsed = 1
            flags = self.job_limit_flags
            memory_limit = process._effective_job_memory_limit(self.job_memory_limit, 4096)
            active_limit = self.job_active_process_limit
            if self.job_limit_mismatch == "flags":
                flags ^= process._JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            elif self.job_limit_mismatch == "memory":
                memory_limit += 1
            elif self.job_limit_mismatch == "active":
                active_limit += 1
            observed.BasicLimitInformation.LimitFlags = flags
            observed.BasicLimitInformation.ActiveProcessLimit = active_limit
            observed.JobMemoryLimit = memory_limit
            self.events.append(("job_limits_readback", (flags, memory_limit, active_limit)))
        return 1

    def _close(self, handle):
        handle_number = int(handle)
        if handle_number in self.pin_handles:
            self.pin_handles[handle_number]["closed"] = True
            self.pin_close_count += 1
            self.pin_closed = all(state["closed"] for state in self.pin_handles.values())
            self.events.append(("pin_close", handle_number))
            return 0 if self.pin_failure == "close" else 1
        self.events.append(("close", handle_number))
        return 0 if self.failure == "close" else 1


class MinimalClearanceVerifierProcessTests(unittest.TestCase):
    def _inputs(self):
        return {
            "executable": Path(sys.executable),
            "startup": process._StartupInfoEx(),
            "environment": ctypes.create_unicode_buffer("SystemRoot=C:\\Windows\0WINDIR=C:\\Windows\0PATH=C:\\Windows\\System32\0TEMP=C:\\Windows\0TMP=C:\\Windows\0\0"),
            "command_line": ctypes.create_unicode_buffer("verifier"),
            "creation_flags": process._CREATE_SUSPENDED | process._EXTENDED_STARTUPINFO_PRESENT,
            "process_info": process._ProcessInformation(),
        }

    @staticmethod
    def _descriptors() -> tuple[list[int], list[int]]:
        first = os.pipe()
        second = os.pipe()
        return [first[1], second[1]], [first[0], second[0]]

    @staticmethod
    def _contained_result(*, timed_out: bool = False) -> process.ContainedVerifierResult:
        return process.ContainedVerifierResult(
            exit_code=0,
            stdout=b"",
            stderr=b"",
            peak_job_commit_bytes=1,
            cap_bytes=process.ADMISSION_CAP_BYTES,
            cap_enforced=True,
            active_process_limit=process.ACTIVE_PROCESS_LIMIT,
            timed_out=timed_out,
            child_process_count=1,
            process_tree_complete=True,
            measurement_complete=True,
            cleanup_complete=True,
        )

    @staticmethod
    def _run_pinned_stream(
        executable: Path,
        payload: bytes,
        workspace: Path,
        *,
        frame: bytes = b"frame",
        arguments: tuple[str, ...] = (),
        timeout_seconds: float = 1.0,
        **options: object,
    ) -> process.ContainedVerifierResult:
        return process.run_contained_verifier_stream(
            executable,
            arguments,
            frame,
            workspace=workspace,
            timeout_seconds=timeout_seconds,
            expected_executable_size_bytes=len(payload),
            expected_executable_sha256=hashlib.sha256(payload).digest(),
            **options,
        )

    def test_handle_list_is_exact_and_attribute_cleanup_is_ordered(self):
        kernel = _Kernel()
        parent, readers = self._descriptors()
        try:
            process._create_process_with_owned_output_handles(
                kernel32=kernel, output_handles=(13101, 13102), parent_descriptors=parent,
                **self._inputs(),
            )
        finally:
            for descriptor in readers:
                os.close(descriptor)
        self.assertEqual(kernel.handles, [13101, 13102])
        create_args = next(value for name, value in kernel.events if name == "create_args")
        self.assertTrue(create_args[0])
        self.assertTrue(create_args[1] & process._EXTENDED_STARTUPINFO_PRESENT)
        self.assertEqual([name for name, _ in kernel.events if name.startswith("attr_")], ["attr_size", "attr_initialize", "attr_update", "attr_bytes", "attr_delete"])

    def test_verify_handle_list_adds_only_artifact_stdin(self):
        kernel = _Kernel()
        parent, readers = self._descriptors()
        try:
            process._create_process_with_owned_output_handles(
                kernel32=kernel, output_handles=(13101, 13102), stdin_handle=13103,
                parent_descriptors=parent, **self._inputs(),
            )
        finally:
            for descriptor in readers:
                os.close(descriptor)
        self.assertEqual(kernel.handles, [13101, 13102, 14000])
        self.assertIn(("duplicate", 14000), kernel.events)
        self.assertIn(("close", 14000), kernel.events)
        self.assertIn(("startup_input", 14000), kernel.events)

    def test_missing_or_partial_executable_pin_is_rejected_before_create(self):
        payload = b"unpinned-path-is-forbidden"
        digest = hashlib.sha256(payload).digest()
        cases = ((None, None), (len(payload), None), (None, digest))
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = root / "verifier.exe"
            executable.write_bytes(payload)
            for expected_size, expected_hash in cases:
                with self.subTest(expected_size=expected_size, expected_hash=expected_hash):
                    with patch.object(
                        process.ctypes,
                        "WinDLL",
                        side_effect=AssertionError("CreateProcess boundary was reached"),
                    ):
                        with self.assertRaisesRegex(process.VerifierProcessError, "verifier_executable_pin"):
                            process.run_contained_verifier(
                                executable,
                                (),
                                workspace=root,
                                timeout_seconds=1.0,
                                expected_executable_size_bytes=expected_size,
                                expected_executable_sha256=expected_hash,
                            )
                    with patch.object(
                        process,
                        "run_contained_verifier",
                        side_effect=AssertionError("stream delegated before pin validation"),
                    ):
                        with self.assertRaisesRegex(process.VerifierProcessError, "verifier_executable_pin"):
                            process.run_contained_verifier_stream(
                                executable,
                                (),
                                b"frame",
                                workspace=root,
                                timeout_seconds=1.0,
                                expected_executable_size_bytes=expected_size,
                                expected_executable_sha256=expected_hash,
                            )

    def test_per_call_output_caps_and_encodings_are_validated_before_windows_boundary(self):
        payload = b"output-cap-validation"
        digest = hashlib.sha256(payload).digest()
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = root / "verifier.exe"
            executable.write_bytes(payload)
            cases = (
                ("stdout_zero", "stdout_cap_bytes", 0, "verifier_stdout_cap"),
                ("stderr_zero", "stderr_cap_bytes", 0, "verifier_stderr_cap"),
                ("stdout_bool", "stdout_cap_bytes", True, "verifier_stdout_cap"),
                ("stderr_large", "stderr_cap_bytes", process.STREAM_MAX_AGGREGATE_BYTES + 1, "verifier_stderr_cap"),
                ("stdout_encoding", "stdout_ascii", 1, "verifier_stdout_encoding"),
                ("stderr_encoding", "stderr_ascii", None, "verifier_stderr_encoding"),
            )
            for name, keyword, value, error_code in cases:
                with self.subTest(name=name):
                    with patch.object(
                        process.ctypes,
                        "WinDLL",
                        side_effect=AssertionError("invalid stream parameter reached Win32 boundary"),
                    ):
                        with self.assertRaisesRegex(process.VerifierProcessError, error_code):
                            process.run_contained_verifier(
                                executable,
                                (),
                                workspace=root,
                                timeout_seconds=1.0,
                                expected_executable_size_bytes=len(payload),
                                expected_executable_sha256=digest,
                                **{keyword: value},
                            )
            stream_cases = (
                ("stream_stdout_cap", {"stdout_cap_bytes": 0}, "verifier_stdout_cap"),
                ("stream_stderr_encoding", {"stderr_ascii": 1}, "verifier_stderr_encoding"),
                ("stream_input_type", {"expected_input_bytes": True}, "verifier_stream_input_length"),
                ("stream_input_zero", {"expected_input_bytes": 0}, "verifier_stream_input_length"),
                ("stream_input_large", {"expected_input_bytes": process.STREAM_MAX_FRAME_BYTES + 1}, "verifier_stream_input_length"),
            )
            for name, kwargs, error_code in stream_cases:
                with self.subTest(name=name):
                    with self.assertRaisesRegex(process.VerifierProcessError, error_code):
                        self._run_pinned_stream(executable, payload, root, **kwargs)

    def test_stream_expected_input_length_rejects_off_by_one_before_pipe(self):
        executable = Path(sys.executable)
        payload = executable.read_bytes()
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            for length in (9_467, 9_469):
                with self.subTest(length=length):
                    with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_input_length"):
                        self._run_pinned_stream(
                            executable,
                            payload,
                            workspace,
                            frame=b"x" * length,
                            expected_input_bytes=9_468,
                        )

    def test_stream_forwards_caller_bounds_and_encoding_to_contained_runner(self):
        captured: dict[str, object] = {}
        executable = Path(sys.executable)
        payload = executable.read_bytes()
        contained = process.ContainedVerifierResult(
            exit_code=0,
            stdout=b"\x00\xff",
            stderr=b"",
            peak_job_commit_bytes=1,
            cap_bytes=process.ADMISSION_CAP_BYTES,
            cap_enforced=True,
            active_process_limit=process.ACTIVE_PROCESS_LIMIT,
            timed_out=False,
            child_process_count=1,
            process_tree_complete=True,
            measurement_complete=True,
            cleanup_complete=True,
        )

        def runner(*args: object, **kwargs: object) -> process.ContainedVerifierResult:
            captured["args"] = args
            captured.update(kwargs)
            return contained

        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process, "run_contained_verifier", side_effect=runner):
                result = self._run_pinned_stream(
                    executable,
                    payload,
                    workspace,
                    stdout_cap_bytes=64,
                    stderr_cap_bytes=8,
                    stdout_ascii=False,
                    stderr_ascii=True,
                    expected_input_bytes=5,
                )
            self.assertIs(result, contained)
            self.assertEqual(captured["stdout_cap_bytes"], 64)
            self.assertEqual(captured["stderr_cap_bytes"], 8)
            self.assertIs(captured["stdout_ascii"], False)
            self.assertIs(captured["stderr_ascii"], True)
            self.assertIsInstance(captured["_stdin_descriptor"], int)
            self.assertGreaterEqual(captured["_stdin_descriptor"], 0)
            self.assertEqual(captured["expected_executable_size_bytes"], len(payload))
            self.assertEqual(captured["expected_executable_sha256"], hashlib.sha256(payload).digest())
            self.assertEqual(captured["job_memory_cap_bytes"], process.ADMISSION_CAP_BYTES)
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_stream_forwards_explicit_memory_cap_and_rejects_out_of_range_caps(self):
        captured: dict[str, object] = {}
        executable = Path(sys.executable)
        payload = executable.read_bytes()
        contained = self._contained_result()

        def runner(*args: object, **kwargs: object) -> process.ContainedVerifierResult:
            captured.update(kwargs)
            return contained

        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process, "run_contained_verifier", side_effect=runner):
                result = self._run_pinned_stream(
                    executable,
                    payload,
                    workspace,
                    job_memory_cap_bytes=2_000_000_000,
                )
            self.assertIs(result, contained)
            self.assertEqual(captured["job_memory_cap_bytes"], 2_000_000_000)

            for invalid in (True, 0, -1, process.ADMISSION_CAP_BYTES + 1):
                with self.subTest(invalid=invalid):
                    with patch.object(
                        process,
                        "run_contained_verifier",
                        side_effect=AssertionError("invalid stream cap reached runner"),
                    ):
                        with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_memory_cap"):
                            self._run_pinned_stream(
                                executable,
                                payload,
                                workspace,
                                job_memory_cap_bytes=invalid,
                            )

    def test_stream_writer_start_failure_releases_known_open_descriptors(self):
        real_pipe = os.pipe
        descriptors: list[int] = []
        executable = Path(sys.executable)
        payload = executable.read_bytes()

        def pipe_factory():
            pair = real_pipe()
            descriptors.extend(pair)
            return pair

        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process.os, "pipe", side_effect=pipe_factory), \
                 patch.object(process.threading.Thread, "start", side_effect=RuntimeError("start")), \
                 patch.object(process, "run_contained_verifier", side_effect=AssertionError("runner reached")):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_start"):
                    process.run_contained_verifier_stream(
                        executable,
                        (),
                        b"frame",
                        workspace=workspace,
                        timeout_seconds=1.0,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                    )
            self.assertEqual(len(descriptors), 2)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_stream_writer_accounts_for_partial_and_zero_writes(self):
        real_pipe = os.pipe
        real_write = os.write
        executable = Path(sys.executable)
        payload = executable.read_bytes()
        frame = b"abcdef"

        for mode in ("partial", "zero"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root_name:
                workspace = Path(root_name)
                descriptors: list[int] = []
                write_descriptor: int | None = None
                write_complete = threading.Event()
                write_total = 0

                def pipe_factory():
                    nonlocal write_descriptor
                    pair = real_pipe()
                    descriptors.extend(pair)
                    write_descriptor = pair[1]
                    return pair

                def write_wrapper(descriptor, data):
                    nonlocal write_total
                    if descriptor != write_descriptor:
                        return real_write(descriptor, data)
                    if mode == "zero":
                        write_complete.set()
                        return 0
                    count = real_write(descriptor, data[:1])
                    write_total += count
                    if write_total == len(frame):
                        write_complete.set()
                    return count

                def runner(*args: object, **kwargs: object):
                    if not write_complete.wait(2):
                        raise AssertionError("writer did not reach its terminal write")
                    return self._contained_result()

                with patch.object(process.os, "pipe", side_effect=pipe_factory), \
                     patch.object(process.os, "write", side_effect=write_wrapper), \
                     patch.object(process, "run_contained_verifier", side_effect=runner):
                    if mode == "partial":
                        result = process.run_contained_verifier_stream(
                            executable,
                            (),
                            frame,
                            workspace=workspace,
                            timeout_seconds=1.0,
                            expected_executable_size_bytes=len(payload),
                            expected_executable_sha256=hashlib.sha256(payload).digest(),
                            expected_input_bytes=len(frame),
                        )
                        self.assertEqual(result.exit_code, 0)
                    else:
                        with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_input_incomplete"):
                            process.run_contained_verifier_stream(
                                executable,
                                (),
                                frame,
                                workspace=workspace,
                                timeout_seconds=1.0,
                                expected_executable_size_bytes=len(payload),
                                expected_executable_sha256=hashlib.sha256(payload).digest(),
                                expected_input_bytes=len(frame),
                            )
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                self.assertEqual(tuple(workspace.iterdir()), ())

    def test_stream_verifier_exception_is_preserved_after_stream_cleanup(self):
        real_pipe = os.pipe
        real_write = os.write
        descriptors: list[int] = []
        write_descriptor: int | None = None
        write_complete = threading.Event()
        executable = Path(sys.executable)
        payload = executable.read_bytes()

        def pipe_factory():
            nonlocal write_descriptor
            pair = real_pipe()
            descriptors.extend(pair)
            write_descriptor = pair[1]
            return pair

        def write_wrapper(descriptor, data):
            count = real_write(descriptor, data)
            if descriptor == write_descriptor:
                write_complete.set()
            return count

        def runner(*args: object, **kwargs: object):
            if not write_complete.wait(2):
                raise AssertionError("writer did not finish")
            raise process.VerifierProcessError("verifier_runner_failure")

        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process.os, "pipe", side_effect=pipe_factory), \
                 patch.object(process.os, "write", side_effect=write_wrapper), \
                 patch.object(process, "run_contained_verifier", side_effect=runner):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_runner_failure"):
                    process.run_contained_verifier_stream(
                        executable,
                        (),
                        b"frame",
                        workspace=workspace,
                        timeout_seconds=1.0,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                    )
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_stream_timeout_precedes_broken_pipe_writer_failure(self):
        real_pipe = os.pipe
        real_write = os.write
        descriptors: list[int] = []
        write_descriptor: int | None = None
        write_started = threading.Event()
        executable = Path(sys.executable)
        payload = executable.read_bytes()
        frame = b"x" * (256 * 1024)

        def pipe_factory():
            nonlocal write_descriptor
            pair = real_pipe()
            descriptors.extend(pair)
            write_descriptor = pair[1]
            return pair

        def write_wrapper(descriptor, data):
            if descriptor == write_descriptor:
                write_started.set()
            return real_write(descriptor, data)

        def runner(*args: object, **kwargs: object):
            if not write_started.wait(2):
                raise AssertionError("writer did not start")
            return self._contained_result(timed_out=True)

        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process.os, "pipe", side_effect=pipe_factory), \
                 patch.object(process.os, "write", side_effect=write_wrapper), \
                 patch.object(process, "run_contained_verifier", side_effect=runner):
                result = process.run_contained_verifier_stream(
                    executable,
                    (),
                    frame,
                    workspace=workspace,
                    timeout_seconds=1.0,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                    expected_input_bytes=len(frame),
                )
            self.assertTrue(result.timed_out)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_stream_blocked_writer_is_bounded_when_read_release_is_unknown(self):
        real_pipe = os.pipe
        real_close = os.close
        descriptors: list[int] = []
        read_descriptor: int | None = None
        write_descriptor: int | None = None
        write_started = threading.Event()
        release_writer = threading.Event()
        writer_released = threading.Event()
        close_counts: dict[int, int] = {}
        executable = Path(sys.executable)
        payload = executable.read_bytes()

        def pipe_factory():
            nonlocal read_descriptor, write_descriptor
            pair = real_pipe()
            descriptors.extend(pair)
            read_descriptor, write_descriptor = pair
            return pair

        def write_wrapper(descriptor, data):
            if descriptor == write_descriptor:
                write_started.set()
                release_writer.wait(10)
                writer_released.set()
                raise OSError("blocked writer released")
            return os.write(descriptor, data)

        def close_wrapper(descriptor):
            close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
            if descriptor == read_descriptor:
                raise OSError("read release unknown")
            return real_close(descriptor)

        def runner(*args: object, **kwargs: object):
            if not write_started.wait(2):
                raise AssertionError("writer did not block")
            return self._contained_result()

        try:
            with tempfile.TemporaryDirectory() as root_name:
                workspace = Path(root_name)
                with patch.object(process.os, "pipe", side_effect=pipe_factory), \
                     patch.object(process.os, "write", side_effect=write_wrapper), \
                     patch.object(process.os, "close", side_effect=close_wrapper), \
                     patch.object(process, "run_contained_verifier", side_effect=runner):
                    with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_cleanup"):
                        process.run_contained_verifier_stream(
                            executable,
                            (),
                            b"frame",
                            workspace=workspace,
                            timeout_seconds=1.0,
                            expected_executable_size_bytes=len(payload),
                            expected_executable_sha256=hashlib.sha256(payload).digest(),
                        )
                self.assertEqual(tuple(workspace.iterdir()), ())
        finally:
            release_writer.set()
            if read_descriptor is not None:
                try:
                    real_close(read_descriptor)
                except OSError:
                    pass
            self.assertTrue(writer_released.wait(2))
            if write_descriptor is not None:
                try:
                    real_close(write_descriptor)
                except OSError:
                    pass
        self.assertEqual(close_counts.get(read_descriptor), 1)

    def test_stream_write_descriptor_close_failure_never_returns_success_or_retries(self):
        real_pipe = os.pipe
        real_close = os.close
        real_write = os.write
        descriptors: list[int] = []
        write_descriptor: int | None = None
        write_complete = threading.Event()
        close_counts: dict[int, int] = {}
        executable = Path(sys.executable)
        payload = executable.read_bytes()

        def pipe_factory():
            nonlocal write_descriptor
            pair = real_pipe()
            descriptors.extend(pair)
            write_descriptor = pair[1]
            return pair

        def write_wrapper(descriptor, data):
            count = real_write(descriptor, data)
            if descriptor == write_descriptor:
                write_complete.set()
            return count

        def close_wrapper(descriptor):
            close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
            if descriptor == write_descriptor:
                raise OSError("write release unknown")
            return real_close(descriptor)

        def runner(*args: object, **kwargs: object):
            if not write_complete.wait(2):
                raise AssertionError("writer did not finish")
            return self._contained_result()

        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process.os, "pipe", side_effect=pipe_factory), \
                 patch.object(process.os, "write", side_effect=write_wrapper), \
                 patch.object(process.os, "close", side_effect=close_wrapper), \
                 patch.object(process, "run_contained_verifier", side_effect=runner):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_cleanup"):
                    process.run_contained_verifier_stream(
                        executable,
                        (),
                        b"frame",
                        workspace=workspace,
                        timeout_seconds=1.0,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                    )
            self.assertEqual(close_counts.get(write_descriptor), 1)
            self.assertIsNotNone(write_descriptor)
            try:
                os.fstat(write_descriptor)
            except OSError:
                pass
            else:
                real_close(write_descriptor)
            for descriptor in descriptors:
                if descriptor == write_descriptor:
                    continue
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_stream_read_descriptor_close_failure_never_returns_success_or_retries(self):
        real_pipe = os.pipe
        real_close = os.close
        real_write = os.write
        descriptors: list[int] = []
        read_descriptor: int | None = None
        write_descriptor: int | None = None
        write_complete = threading.Event()
        close_counts: dict[int, int] = {}
        executable = Path(sys.executable)
        payload = executable.read_bytes()

        def pipe_factory():
            nonlocal read_descriptor, write_descriptor
            pair = real_pipe()
            descriptors.extend(pair)
            read_descriptor, write_descriptor = pair
            return pair

        def write_wrapper(descriptor, data):
            count = real_write(descriptor, data)
            if descriptor == write_descriptor:
                write_complete.set()
            return count

        def close_wrapper(descriptor):
            close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
            if descriptor == read_descriptor:
                raise OSError("read release unknown")
            return real_close(descriptor)

        def runner(*args: object, **kwargs: object):
            if not write_complete.wait(2):
                raise AssertionError("writer did not finish")
            return self._contained_result()

        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process.os, "pipe", side_effect=pipe_factory), \
                 patch.object(process.os, "write", side_effect=write_wrapper), \
                 patch.object(process.os, "close", side_effect=close_wrapper), \
                 patch.object(process, "run_contained_verifier", side_effect=runner):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_cleanup"):
                    process.run_contained_verifier_stream(
                        executable,
                        (),
                        b"frame",
                        workspace=workspace,
                        timeout_seconds=1.0,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                    )
            self.assertEqual(close_counts.get(read_descriptor), 1)
            self.assertIsNotNone(read_descriptor)
            try:
                os.fstat(read_descriptor)
            except OSError:
                pass
            else:
                real_close(read_descriptor)
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_stream_cleanup_exception_is_fixed_and_never_returns_success(self):
        real_pipe = os.pipe
        real_write = os.write
        descriptors: list[int] = []
        write_descriptor: int | None = None
        write_complete = threading.Event()
        executable = Path(sys.executable)
        payload = executable.read_bytes()

        def pipe_factory():
            nonlocal write_descriptor
            pair = real_pipe()
            descriptors.extend(pair)
            write_descriptor = pair[1]
            return pair

        def write_wrapper(descriptor, data):
            count = real_write(descriptor, data)
            if descriptor == write_descriptor:
                write_complete.set()
            return count

        def runner(*args: object, **kwargs: object):
            if not write_complete.wait(2):
                raise AssertionError("writer did not finish")
            return self._contained_result()

        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process.os, "pipe", side_effect=pipe_factory), \
                 patch.object(process.os, "write", side_effect=write_wrapper), \
                 patch.object(process, "run_contained_verifier", side_effect=runner), \
                 patch.object(process, "_cleanup_verifier_workspace", side_effect=RuntimeError("cleanup fault")):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_cleanup"):
                    process.run_contained_verifier_stream(
                        executable,
                        (),
                        b"frame",
                        workspace=workspace,
                        timeout_seconds=1.0,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                    )
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_resource_limit_contract_rejects_five_gib_and_keeps_five_gib_minus_one(self):
        payload = b"resource-limited-verifier"
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = root / "verifier.exe"
            executable.write_bytes(payload)
            kernel = _Kernel(pin_data=payload)
            with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                result = process.run_contained_verifier(
                    executable,
                    (),
                    workspace=root,
                    timeout_seconds=1.0,
                    job_memory_cap_bytes=process.PROCESS_TREE_PEAK_CAP_BYTES,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )
            self.assertEqual(result.cap_bytes, process.PROCESS_TREE_PEAK_CAP_BYTES)
            with patch.object(
                process.ctypes,
                "WinDLL",
                side_effect=AssertionError("invalid cap reached Win32 boundary"),
            ):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_memory_cap"):
                    process.run_contained_verifier(
                        executable,
                        (),
                        workspace=root,
                        timeout_seconds=1.0,
                        job_memory_cap_bytes=5_000_000_000,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                    )

    def test_job_limit_readback_mismatch_fails_closed(self):
        payload = b"synthetic-pinned-verifier"
        for mismatch in ("flags", "memory", "active"):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                executable = root / "verifier.exe"
                executable.write_bytes(payload)
                kernel = _Kernel(pin_data=payload, job_limit_mismatch=mismatch)
                with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                    with self.assertRaisesRegex(process.VerifierProcessError, "verifier_job_limits_readback"):
                        process.run_contained_verifier(
                            executable,
                            (),
                            workspace=root,
                            timeout_seconds=1.0,
                            expected_executable_size_bytes=len(payload),
                            expected_executable_sha256=hashlib.sha256(payload).digest(),
                        )
                self.assertGreaterEqual(
                    sum(name == "job_limits_readback" for name, _ in kernel.events),
                    1,
                )
                self.assertEqual(kernel.pin_close_count, len(kernel.pin_handles))
                self.assertTrue(all(state["closed"] for state in kernel.pin_handles.values()))

    def test_pinned_handles_are_held_through_create_assignment_sample_and_resume(self):
        payload = b"synthetic-pinned-verifier"
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = root / "verifier.exe"
            executable.write_bytes(payload)
            kernel = _Kernel(pin_data=payload)
            kernel.child_image_path = kernel.nt_path.upper()
            with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                result = process.run_contained_verifier(
                    executable,
                    (),
                    workspace=root,
                    timeout_seconds=1.0,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.measurement_complete)
            self.assertTrue(kernel.pin_closed)
            self.assertEqual(kernel.pin_close_count, len(kernel.pin_handles))
            self.assertGreaterEqual(kernel.pin_close_count, 4)
            self.assertTrue(all(handle not in kernel.pin_handles for handle in kernel.handles))
            self.assertTrue(next(value for name, value in kernel.events if name == "pin_held_during_create"))
            open_args = next(value for name, value in kernel.events if name == "pin_open")
            self.assertEqual(open_args[1], process._GENERIC_READ)
            self.assertEqual(open_args[2], process._FILE_SHARE_READ)
            self.assertEqual(open_args[3], process._OPEN_EXISTING)
            self.assertTrue(open_args[4] & process._FILE_FLAG_OPEN_REPARSE_POINT)
            names = [name for name, _ in kernel.events]
            self.assertEqual(
                next(value for name, value in kernel.events if name == "create_application"),
                kernel.dos_path,
            )
            self.assertEqual(
                next(value for name, value in kernel.events if name == "create_command"),
                kernel.dos_path,
            )
            self.assertEqual(
                next(value for name, value in kernel.events if name == "create_directory"),
                str(root),
            )
            self.assertIn(("file_id", (str(executable), b"R" * 16)), kernel.events)
            self.assertIn(("file_id", (kernel.dos_path, b"R" * 16)), kernel.events)
            self.assertIn(("final_path", (process._FILE_NAME_NORMALIZED | process._VOLUME_NAME_GUID, kernel.canonical_path)), kernel.events)
            self.assertIn(("final_path", (process._FILE_NAME_NORMALIZED | process._VOLUME_NAME_NT, kernel.nt_path)), kernel.events)
            self.assertIn(("final_path", (process._FILE_NAME_NORMALIZED | process._VOLUME_NAME_DOS, kernel.dos_path)), kernel.events)
            self.assertEqual(
                [value for name, value in kernel.events if name == "query_dos_device"],
                [("C:", kernel.native_volume_prefix), ("C:", kernel.native_volume_prefix)],
            )
            self.assertEqual(
                next(value for name, value in kernel.events if name == "child_image"),
                kernel.nt_path.upper(),
            )
            self.assertLess(names.index("create"), names.index("pin_close"))
            query_positions = [index for index, name in enumerate(names) if name == "query_dos_device"]
            self.assertLess(query_positions[0], names.index("create"))
            self.assertLess(names.index("create"), query_positions[1])
            self.assertLess(query_positions[1], names.index("child_image"))
            self.assertLess(names.index("create"), names.index("child_image"))
            self.assertLess(names.index("child_image"), names.index("assign"))
            self.assertLess(names.index("assign"), names.index("pin_close"))
            self.assertLess(names.index("assign"), names.index("memory"))
            self.assertLess(names.index("memory"), names.index("resume"))
            self.assertLess(names.index("memory"), names.index("pin_close"))
            self.assertLess(names.index("resume"), names.index("pin_close"))
            self.assertEqual(
                next(value for name, value in kernel.events if name == "job_limits_set"),
                (
                    process._JOB_LIMIT_FLAGS,
                    process.PROCESS_TREE_PEAK_CAP_BYTES,
                    process.ACTIVE_PROCESS_LIMIT,
                ),
            )
            self.assertGreaterEqual(sum(name == "job_limits_readback" for name, _ in kernel.events), 1)

    def test_suspended_child_binding_failures_kill_and_reap_before_assignment(self):
        payload = b"synthetic-pinned-verifier"
        failures = ("dos_mapping_after_create", "image_api", "image_truncated", "image_non_device", "image_mismatch")
        for failure in failures:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                executable = root / "verifier.exe"
                executable.write_bytes(payload)
                kernel = _Kernel(pin_failure=failure, pin_data=payload)
                with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                    with self.assertRaises(process.VerifierProcessError):
                        process.run_contained_verifier(
                            executable,
                            (),
                            workspace=root,
                            timeout_seconds=1.0,
                            expected_executable_size_bytes=len(payload),
                            expected_executable_sha256=hashlib.sha256(payload).digest(),
                        )
                names = [name for name, _ in kernel.events]
                self.assertIn("terminate_process", names)
                self.assertIn("wait", names)
                self.assertNotIn("assign", names)
                self.assertNotIn("resume", names)
                self.assertLess(names.index("terminate_process"), names.index("wait"))
                self.assertLess(names.index("wait"), names.index("pin_close"))
                self.assertEqual(kernel.pin_close_count, len(kernel.pin_handles))
                self.assertTrue(all(state["closed"] for state in kernel.pin_handles.values()))

    def test_post_create_cleanup_failure_is_killed_and_reaped_once_before_pin_close(self):
        payload = b"synthetic-pinned-verifier"
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = root / "verifier.exe"
            executable.write_bytes(payload)
            kernel = _Kernel(failure="attribute_delete", pin_data=payload)
            with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_process_cleanup"):
                    process.run_contained_verifier(
                        executable,
                        (),
                        workspace=root,
                        timeout_seconds=1.0,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                    )
            names = [name for name, _ in kernel.events]
            self.assertEqual(names.count("terminate_process"), 1)
            self.assertEqual(names.count("wait"), 1)
            self.assertEqual(names.count("assign"), 0)
            self.assertEqual(names.count("resume"), 0)
            self.assertLess(names.index("create"), names.index("terminate_process"))
            self.assertLess(names.index("terminate_process"), names.index("wait"))
            self.assertLess(names.index("wait"), names.index("pin_close"))
            self.assertEqual(kernel.pin_close_count, len(kernel.pin_handles))
            self.assertTrue(all(state["closed"] for state in kernel.pin_handles.values()))

    @unittest.skipUnless(os.name == "nt", "Windows share-mode pin test")
    def test_real_pinned_handle_denies_write_delete_and_replace_until_close(self):
        payload = b"real-share-mode-pin"
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = root / "verifier.bin"
            replacement = root / "replacement.bin"
            executable.write_bytes(payload)
            replacement.write_bytes(b"replacement")
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            pinned = process._open_pinned_executable(
                kernel32=kernel32,
                executable=executable,
                expected_executable_size_bytes=len(payload),
                expected_executable_sha256=hashlib.sha256(payload).digest(),
            )
            try:
                with self.assertRaises(OSError):
                    executable.write_bytes(b"changed")
                with self.assertRaises(OSError):
                    executable.unlink()
                with self.assertRaises(OSError):
                    os.replace(replacement, executable)
            finally:
                pinned.close()
            self.assertTrue(pinned.closed)
            executable.write_bytes(b"closed")
            self.assertEqual(executable.read_bytes(), b"closed")

    @unittest.skipUnless(os.name == "nt", "Windows namespace pin test")
    def test_real_pinned_ancestor_denies_parent_rename_until_close(self):
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            parent = root / "private-parent"
            sibling = root / "renamed-parent"
            parent.mkdir()
            executable = parent / "harmless.exe"
            shutil.copyfile(sys._base_executable, executable)
            payload = executable.read_bytes()
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            pinned = process._open_pinned_executable(
                kernel32=kernel32,
                executable=executable,
                expected_executable_size_bytes=len(payload),
                expected_executable_sha256=hashlib.sha256(payload).digest(),
            )
            try:
                with self.assertRaises(OSError):
                    parent.rename(sibling)
            finally:
                pinned.close()
            parent.rename(sibling)
            self.assertTrue((sibling / "harmless.exe").is_file())

    @unittest.skipUnless(os.name == "nt", "Windows loader share-mode pin test")
    def test_real_pinned_process_creation_succeeds_with_loader_share_semantics(self):
        executable = Path(sys._base_executable)
        payload = executable.read_bytes()
        with tempfile.TemporaryDirectory() as root_name:
            result = process.run_contained_verifier(
                executable,
                ("-c", "import sys;sys.exit(0)"),
                workspace=Path(root_name),
                timeout_seconds=30.0,
                expected_executable_size_bytes=len(payload),
                expected_executable_sha256=hashlib.sha256(payload).digest(),
            )
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.measurement_complete)

    @unittest.skipUnless(os.name == "nt", "Windows reparse-point pin test")
    def test_real_symlink_is_rejected_without_following_target(self):
        payload = b"symlink-target"
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            target = root / "target.exe"
            link = root / "link.exe"
            target.write_bytes(payload)
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            with self.assertRaisesRegex(process.VerifierProcessError, "not_regular"):
                process._open_pinned_executable(
                    kernel32=kernel32,
                    executable=link,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )

    def test_pinned_metadata_and_hash_failures_close_the_validated_handle(self):
        payload = b"synthetic-pinned-verifier"
        failures = (
            "stat", "type", "directory", "reparse", "read", "final_path",
            "directory_open", "directory_reparse", "file_id", "file_id_mismatch",
            "reopen_open", "nt_non_device", "dos_unc", "dos_mapping",
            "dos_mapping_mismatch", "image_api", "image_truncated",
            "image_non_device", "image_mismatch",
        )
        for failure in failures:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                executable = root / "verifier.exe"
                executable.write_bytes(payload)
                kernel = _Kernel(pin_failure=failure, pin_data=payload)
                with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                    with self.assertRaises(process.VerifierProcessError):
                        process.run_contained_verifier(
                            executable,
                            (),
                            workspace=root,
                            timeout_seconds=1.0,
                            expected_executable_size_bytes=len(payload),
                            expected_executable_sha256=hashlib.sha256(payload).digest(),
                        )
                self.assertEqual(kernel.pin_close_count, len(kernel.pin_handles))
                self.assertTrue(all(state["closed"] for state in kernel.pin_handles.values()))

        for expected_size, expected_hash in ((len(payload) + 1, hashlib.sha256(payload).digest()), (len(payload), b"x" * 32)):
            with self.subTest(expected_size=expected_size, expected_hash=expected_hash), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                executable = root / "verifier.exe"
                executable.write_bytes(payload)
                kernel = _Kernel(pin_data=payload)
                with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                    with self.assertRaises(process.VerifierProcessError):
                        process.run_contained_verifier(
                            executable,
                            (),
                            workspace=root,
                            timeout_seconds=1.0,
                            expected_executable_size_bytes=expected_size,
                            expected_executable_sha256=expected_hash,
                        )
                self.assertEqual(kernel.pin_close_count, len(kernel.pin_handles))
                self.assertTrue(all(state["closed"] for state in kernel.pin_handles.values()))

    def test_pinned_create_and_close_failures_close_all_owned_handles_once(self):
        payload = b"synthetic-pinned-verifier"
        for failure in ("create", "close"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                executable = root / "verifier.exe"
                executable.write_bytes(payload)
                kernel = _Kernel(failure=failure, pin_data=payload)
                with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                    with self.assertRaises(process.VerifierProcessError):
                        process.run_contained_verifier(
                            executable,
                            (),
                            workspace=root,
                            timeout_seconds=1.0,
                            expected_executable_size_bytes=len(payload),
                            expected_executable_sha256=hashlib.sha256(payload).digest(),
                        )
                self.assertEqual(kernel.pin_close_count, len(kernel.pin_handles))
                self.assertTrue(all(state["closed"] for state in kernel.pin_handles.values()))

    def test_pinned_open_failure_has_no_handle_to_close(self):
        payload = b"synthetic-pinned-verifier"
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = root / "verifier.exe"
            executable.write_bytes(payload)
            kernel = _Kernel(pin_failure="open", pin_data=payload)
            with patch.object(process.ctypes, "WinDLL", return_value=kernel):
                with self.assertRaises(process.VerifierProcessError):
                    process.run_contained_verifier(
                        executable,
                        (),
                        workspace=root,
                        timeout_seconds=1.0,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                    )
            self.assertEqual(kernel.pin_close_count, 0)

    def test_parallel_creation_has_no_global_creation_lock_or_shared_capture(self):
        kernel = _Kernel(overlap=True)
        kernels = (kernel, kernel)

        def launch(kernel):
            parent, readers = self._descriptors()
            try:
                process._create_process_with_owned_output_handles(
                    kernel32=kernel, output_handles=(13101, 13102), parent_descriptors=parent,
                    **self._inputs(),
                )
            finally:
                for descriptor in readers:
                    os.close(descriptor)

        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(launch, kernels))
        self.assertFalse(hasattr(process, "_PROCESS_CREATION_LOCK"))
        self.assertTrue(all(any(name == "create" for name, _ in kernel.events) for kernel in kernels))

    def test_attribute_and_creation_failures_cleanup_once(self):
        for failure in ("attribute_initialize", "attribute_update", "create"):
            with self.subTest(failure=failure):
                kernel = _Kernel(failure=failure)
                parent, readers = self._descriptors()
                try:
                    with patch.object(process.ctypes, "get_last_error", return_value=5):
                        with self.assertRaises(process.VerifierProcessError):
                            process._create_process_with_owned_output_handles(
                                kernel32=kernel, output_handles=(13101, 13102), parent_descriptors=parent,
                                **self._inputs(),
                            )
                finally:
                    for descriptor in readers:
                        os.close(descriptor)
                self.assertEqual(sum(name == "attr_delete" for name, _ in kernel.events), 0 if failure == "attribute_initialize" else 1)

    def test_drain_pipe_is_bounded_and_reports_overflow(self):
        read_descriptor, write_descriptor = os.pipe()
        output: dict[str, bytes] = {}
        failure: dict[str, str] = {}
        overflow = threading.Event()
        try:
            os.write(write_descriptor, b"x" * 33)
        finally:
            os.close(write_descriptor)
        process._drain_pipe(read_descriptor, 32, "stdout", output, failure, overflow)
        self.assertTrue(overflow.is_set())
        self.assertEqual(failure["code"], "stdout_cap")
        self.assertEqual(len(output["stdout"]), 33)

    def test_stream_requires_empty_nonreparse_preprovisioned_workspace(self):
        executable = Path(sys.executable)
        payload = executable.read_bytes()
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name) / "workspace"
            workspace.mkdir()
            stale = workspace / "stale-entry"
            stale.write_bytes(b"stale")
            with self.assertRaisesRegex(process.VerifierProcessError, "verifier_workspace_not_empty"):
                self._run_pinned_stream(executable, payload, workspace, timeout_seconds=30.0)
            stale.unlink()
            with patch.object(process, "_is_reparse_point", return_value=True):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_workspace"):
                    self._run_pinned_stream(executable, payload, workspace, timeout_seconds=30.0)

    def test_workspace_identity_ignores_volatile_windows_attribute_bits(self):
        class _Metadata:
            st_dev = 11
            st_ino = 22
            st_nlink = 1

            def __init__(self, attributes):
                self.st_file_attributes = attributes

        first = process._verifier_workspace_identity(
            _Metadata(process._FILE_ATTRIBUTE_DIRECTORY | 0x10000000)
        )
        second = process._verifier_workspace_identity(
            _Metadata(process._FILE_ATTRIBUTE_DIRECTORY)
        )
        self.assertEqual(first, second)
        self.assertEqual(first[-1], process._FILE_ATTRIBUTE_DIRECTORY)

    @unittest.skipUnless(os.name == "nt", "Windows bounded child-output test")
    def test_real_child_output_overflow_is_terminated_without_output_files(self):
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            executable = Path(sys._base_executable)
            payload = executable.read_bytes()
            with self.assertRaisesRegex(process.VerifierProcessError, "stdout_cap"):
                process.run_contained_verifier(
                    executable,
                    ("-c", "import sys;sys.stdout.write('x'*70000);sys.stdout.flush()"),
                    workspace=workspace,
                    timeout_seconds=30.0,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )
            self.assertEqual(tuple(workspace.iterdir()), ())

    @unittest.skipUnless(os.name == "nt", "Windows verifier workspace containment test")
    def test_real_stream_child_workspace_file_fails_closed_and_is_removed(self):
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            executable = Path(sys._base_executable)
            payload = executable.read_bytes()
            spill = str(workspace / "spill")
            script = f"import os;spill={spill!r};os.mkdir(spill);handle=open(os.path.join(spill,'proof.bin'),'wb');handle.write(b'x');handle.close()"
            with self.assertRaisesRegex(process.VerifierProcessError, "verifier_workspace_contents"):
                process.run_contained_verifier_stream(
                    executable,
                    ("-c", script),
                    b"frame",
                    workspace=workspace,
                    timeout_seconds=30.0,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )
            self.assertEqual(tuple(workspace.iterdir()), ())

    @unittest.skipUnless(os.name == "nt", "Windows relative workspace containment test")
    def test_real_stream_child_relative_file_is_contained_and_removed(self):
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            helper_parent = root / "helper"
            helper_parent.mkdir()
            source_executable = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
            executable = helper_parent / "helper.exe"
            shutil.copyfile(source_executable, executable)
            workspace = root / "workspace"
            workspace.mkdir()
            spill_name = f"relative-spill-{root.name}.bin"
            parent_entries = tuple(sorted(entry.name for entry in helper_parent.iterdir()))
            payload = executable.read_bytes()
            result = None
            caught = None
            try:
                result = process.run_contained_verifier_stream(
                    executable,
                    ("/d", "/c", f"type nul > {spill_name}"),
                    b"frame",
                    workspace=workspace,
                    timeout_seconds=30.0,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )
            except process.VerifierProcessError as error:
                caught = error
            if result is None:
                self.assertIsNotNone(caught)
                self.assertRegex(str(caught), "verifier_workspace_contents")
            else:
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"")
                self.assertTrue(result.cleanup_complete)
            self.assertEqual(tuple(workspace.iterdir()), ())
            self.assertEqual(
                tuple(sorted(entry.name for entry in helper_parent.iterdir())),
                parent_entries,
            )
            self.assertFalse((workspace / spill_name).exists())
            self.assertFalse((helper_parent / spill_name).exists())

    @unittest.skipUnless(os.name == "nt", "Windows stream writer completion test")
    def test_stream_requires_writer_completion_after_early_runner_return(self):
        executable = Path(sys.executable)
        executable_bytes = executable.read_bytes()
        contained = process.ContainedVerifierResult(
            exit_code=0,
            stdout=b"",
            stderr=b"",
            peak_job_commit_bytes=1,
            cap_bytes=process.ADMISSION_CAP_BYTES,
            cap_enforced=True,
            active_process_limit=process.ACTIVE_PROCESS_LIMIT,
            timed_out=False,
            child_process_count=1,
            process_tree_complete=True,
            measurement_complete=True,
            cleanup_complete=True,
        )
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with patch.object(process, "run_contained_verifier", return_value=contained):
                with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_input_incomplete"):
                    process.run_contained_verifier_stream(
                        executable,
                        (),
                        b"x" * (1 << 20),
                        workspace=workspace,
                        timeout_seconds=1.0,
                        expected_executable_size_bytes=len(executable_bytes),
                        expected_executable_sha256=hashlib.sha256(executable_bytes).digest(),
                    )
            self.assertEqual(tuple(workspace.iterdir()), ())

    @unittest.skipUnless(os.name == "nt", "Windows early-child-exit stream test")
    def test_real_stream_child_exit_before_read_cannot_accept_partial_input(self):
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            executable = Path(sys._base_executable)
            payload = executable.read_bytes()
            with self.assertRaisesRegex(process.VerifierProcessError, "verifier_stream_input_incomplete"):
                process.run_contained_verifier_stream(
                    executable,
                    ("-c", "import sys;sys.exit(0)"),
                    b"x" * (1 << 20),
                    workspace=workspace,
                    timeout_seconds=30.0,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )
            self.assertEqual(tuple(workspace.iterdir()), ())

    @unittest.skipUnless(os.name == "nt", "Windows never-read stream timeout test")
    def test_real_stream_never_read_timeout_has_no_surviving_writer_or_child(self):
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            executable = Path(sys._base_executable)
            payload = executable.read_bytes()
            result = process.run_contained_verifier_stream(
                executable,
                ("-c", "import time;time.sleep(60)"),
                b"x" * 9_468,
                workspace=workspace,
                timeout_seconds=1.0,
                expected_executable_size_bytes=len(payload),
                expected_executable_sha256=hashlib.sha256(payload).digest(),
                expected_input_bytes=9_468,
            )
            self.assertTrue(result.timed_out)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")
            self.assertTrue(result.process_tree_complete)
            self.assertTrue(result.cleanup_complete)
            self.assertEqual(tuple(workspace.iterdir()), ())

    @unittest.skipUnless(os.name == "nt", "Windows per-call child-output cap test")
    def test_real_child_per_call_stdout_and_stderr_caps_are_enforced(self):
        cases = (
            ("stdout", "import sys;sys.stdout.write('x'*64);sys.stdout.flush()", "stdout_cap"),
            ("stderr", "import sys;sys.stderr.write('x'*64);sys.stderr.flush()", "stderr_cap"),
        )
        for name, script, expected_code in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root_name:
                workspace = Path(root_name)
                executable = Path(sys._base_executable)
                payload = executable.read_bytes()
                with self.assertRaisesRegex(process.VerifierProcessError, expected_code):
                    process.run_contained_verifier(
                        executable,
                        ("-c", script),
                        workspace=workspace,
                        timeout_seconds=30.0,
                        expected_executable_size_bytes=len(payload),
                        expected_executable_sha256=hashlib.sha256(payload).digest(),
                        stdout_cap_bytes=8,
                        stderr_cap_bytes=8,
                    )
                self.assertEqual(tuple(workspace.iterdir()), ())

    @unittest.skipUnless(os.name == "nt", "Windows binary stdout test")
    def test_real_child_binary_stdout_is_allowed_only_when_requested(self):
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            executable = Path(sys._base_executable)
            payload = executable.read_bytes()
            result = process.run_contained_verifier(
                executable,
                ("-c", "import sys;sys.stdout.buffer.write(b'\\x00\\xff');sys.stdout.flush()"),
                workspace=workspace,
                timeout_seconds=30.0,
                expected_executable_size_bytes=len(payload),
                expected_executable_sha256=hashlib.sha256(payload).digest(),
                stdout_cap_bytes=8,
                stdout_ascii=False,
            )
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, b"\x00\xff")
            self.assertEqual(result.stderr, b"")
            self.assertTrue(result.cleanup_complete)
            self.assertEqual(tuple(workspace.iterdir()), ())

    @unittest.skipUnless(os.name == "nt", "Windows contained timeout test")
    def test_real_child_timeout_before_output_is_terminated_and_reaped(self):
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            executable = Path(sys._base_executable)
            payload = executable.read_bytes()
            result = process.run_contained_verifier(
                executable,
                ("-c", "import time;time.sleep(60)"),
                workspace=workspace,
                timeout_seconds=1.0,
                expected_executable_size_bytes=len(payload),
                expected_executable_sha256=hashlib.sha256(payload).digest(),
            )
            self.assertTrue(result.timed_out)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")
            self.assertTrue(result.process_tree_complete)
            self.assertTrue(result.cleanup_complete)
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_failure_boundaries_remain_fixed_and_close_handles(self):
        stages = {"setup", "limits", "attribute_initialize", "attribute_update", "create", "assign", "resume", "wait", "exit", "query", "close"}
        executable = Path(sys.executable)
        payload = executable.read_bytes()
        for failure in sorted(stages):
            with self.subTest(failure=failure):
                kernel = _Kernel(failure=failure)

                def fake_pipe():
                    read_descriptor, write_descriptor = os.pipe()
                    return read_descriptor, write_descriptor, 13100 + (0 if len(kernel.events) % 2 == 0 else 1)

                with tempfile.TemporaryDirectory() as root:
                    workspace = Path(root)
                    with patch.object(process.ctypes, "WinDLL", return_value=kernel), patch.object(process, "_create_output_pipe", side_effect=fake_pipe), patch.object(process.ctypes, "get_last_error", return_value=5):
                        with self.assertRaises(process.VerifierProcessError):
                            process.run_contained_verifier(
                                executable,
                                ("-c", "print(1)"),
                                workspace=workspace,
                                timeout_seconds=1.0,
                                expected_executable_size_bytes=len(payload),
                                expected_executable_sha256=hashlib.sha256(payload).digest(),
                            )

    @unittest.skipUnless(os.name == "nt", "Windows handle inheritance test")
    def test_real_windows_handle_canary_is_not_inherited_and_capture_works(self):
        import msvcrt

        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = Path(sys._base_executable)
            payload = executable.read_bytes()
            canary = root / "canary.bin"
            descriptor = os.open(canary, os.O_BINARY | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                handle = msvcrt.get_osfhandle(descriptor)
                os.set_handle_inheritable(handle, True)
                script = "exec(\"try:\\n fd=msvcrt.open_osfhandle(int(sys.argv[1]),os.O_WRONLY)\\n os.write(fd,b'LEAK')\\n os.close(fd)\\n print('CANARY_WRITE_OK')\\nexcept OSError:\\n print('CANARY_HANDLE_UNAVAILABLE')\")"
                script = "import msvcrt,os,sys;" + script
                workspace = root / "workspace"
                workspace.mkdir()
                result = process.run_contained_verifier(
                    executable,
                    ("-c", script, str(handle)),
                    workspace=workspace,
                    timeout_seconds=30.0,
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(canary.read_bytes(), b"")
                self.assertIn(b"CANARY_HANDLE_UNAVAILABLE", result.stdout)
                self.assertNotIn(b"CANARY_WRITE_OK", result.stdout)
                self.assertEqual(result.stderr, b"")
            finally:
                os.close(descriptor)

    def test_contained_worker_watchdog_kills_a_silent_worker_and_ends_with_it(self):
        # One watchdog thread per worker enforces every exchange's deadline; a worker that never answers is killed and the thread ends.
        stdin, stdout = os.pipe(), os.pipe()
        killed = []

        class Kernel:
            def TerminateJobObject(self, job, code):
                if not killed:
                    killed.append(code)
                    os.close(stdout[1])  # the dead child's end: the blocked read now sees end of stream

        worker = process.ContainedWorker(kernel32=Kernel(), job=None, process_handle=None, stdin_descriptor=stdin[1], stdout_descriptor=stdout[0], stderr_descriptor=-1, psapi=None)
        for descriptor in (stdin[0], stdin[1], stdout[0]):
            self.addCleanup(os.close, descriptor)
        with self.assertRaises(process.VerifierProcessError) as caught:
            worker.exchange(b"x", response_cap_bytes=16, timeout_seconds=0.2)
        worker._watchdog.join(5)
        self.assertEqual((str(caught.exception), worker.alive, killed, worker._watchdog.is_alive()), ("worker_timeout", False, [1], False))


if __name__ == "__main__":
    unittest.main()
