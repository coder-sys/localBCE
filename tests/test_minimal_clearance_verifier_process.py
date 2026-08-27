from __future__ import annotations

import ctypes
import hashlib
import itertools
import os
from pathlib import Path
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
    def __init__(self, *, failure: str | None = None, overlap: bool = False, pin_failure: str | None = None, pin_data: bytes | None = None):
        self.failure = failure
        self.pin_failure = pin_failure
        self.pin_data = pin_data or b""
        self.pin_handle = 16000
        self.pin_path: Path | None = None
        self.pin_offset = 0
        self.pin_closed = False
        self.pin_close_count = 0
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
        self.DuplicateHandle = _FakeFunction(self._duplicate)
        self.CreateFileW = _FakeFunction(self._open_file)
        self.GetFileType = _FakeFunction(self._file_type)
        self.GetFileInformationByHandle = _FakeFunction(self._file_information)
        self.ReadFile = _FakeFunction(self._read_file)
        self.GetProcessMemoryInfo = _FakeFunction(self._memory_info)
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

    def _limits(self, *_):
        self.events.append(("limits", True))
        return 0 if self.failure == "limits" else 1

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
        if self.pin_failure == "open":
            return process._INVALID_HANDLE_VALUE
        self.pin_path = Path(str(application))
        if not self.pin_data:
            self.pin_data = self.pin_path.read_bytes()
        self.pin_offset = 0
        self.pin_closed = False
        return self.pin_handle

    def _file_type(self, _handle):
        return 0 if self.pin_failure == "type" else process._FILE_TYPE_DISK

    def _file_information(self, _handle, information_ptr):
        if self.pin_failure == "stat":
            return 0
        information = ctypes.cast(information_ptr, ctypes.POINTER(process._ByHandleFileInformation)).contents
        attributes = 0
        if self.pin_failure == "directory":
            attributes |= process._FILE_ATTRIBUTE_DIRECTORY
        if self.pin_failure == "reparse":
            attributes |= process._FILE_ATTRIBUTE_REPARSE_POINT
        information.dwFileAttributes = attributes
        information.nFileSizeHigh = len(self.pin_data) >> 32
        information.nFileSizeLow = len(self.pin_data) & 0xFFFFFFFF
        return 1

    def _read_file(self, _handle, buffer, requested, read_ptr, _overlapped):
        if self.pin_failure == "read":
            return 0
        count = min(int(requested), len(self.pin_data) - self.pin_offset)
        if count > 0:
            ctypes.memmove(buffer, self.pin_data[self.pin_offset:self.pin_offset + count], count)
            self.pin_offset += count
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

    def _create(self, _application, _command, _p1, _p2, inherit, flags, _env, _directory, startup_ptr, process_ptr):
        if self.pin_path is not None:
            self.events.append(("pin_held_during_create", not self.pin_closed))
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
        return 1

    def _close(self, handle):
        if int(handle) == self.pin_handle:
            self.pin_closed = True
            self.pin_close_count += 1
            self.events.append(("pin_close", int(handle)))
            return 0 if self.pin_failure == "close" else 1
        self.events.append(("close", int(handle)))
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

    def test_pinned_handle_is_held_through_suspended_create_then_closed_before_assignment(self):
        payload = b"synthetic-pinned-verifier"
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
                    expected_executable_size_bytes=len(payload),
                    expected_executable_sha256=hashlib.sha256(payload).digest(),
                )
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.measurement_complete)
            self.assertTrue(kernel.pin_closed)
            self.assertEqual(kernel.pin_close_count, 1)
            self.assertTrue(next(value for name, value in kernel.events if name == "pin_held_during_create"))
            open_args = next(value for name, value in kernel.events if name == "pin_open")
            self.assertEqual(open_args[1], process._GENERIC_READ)
            self.assertEqual(open_args[2], process._FILE_SHARE_READ)
            self.assertEqual(open_args[3], process._OPEN_EXISTING)
            self.assertTrue(open_args[4] & process._FILE_FLAG_OPEN_REPARSE_POINT)
            names = [name for name, _ in kernel.events]
            self.assertLess(names.index("create"), names.index("pin_close"))
            self.assertLess(names.index("pin_close"), names.index("assign"))
            self.assertLess(names.index("assign"), names.index("memory"))
            self.assertLess(names.index("memory"), names.index("resume"))

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
        failures = ("stat", "type", "directory", "reparse", "read")
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
                self.assertEqual(kernel.pin_close_count, 1)

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
                self.assertEqual(kernel.pin_close_count, 1)

    def test_pinned_create_and_close_failures_still_attempt_exactly_one_handle_close(self):
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
                self.assertEqual(kernel.pin_close_count, 1)

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
        for failure in ("attribute_initialize", "attribute_update", "create", "attribute_delete"):
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

    @unittest.skipUnless(os.name == "nt", "Windows bounded child-output test")
    def test_real_child_output_overflow_is_terminated_without_output_files(self):
        with tempfile.TemporaryDirectory() as root_name:
            workspace = Path(root_name)
            with self.assertRaisesRegex(process.VerifierProcessError, "stdout_cap"):
                process.run_contained_verifier(
                    Path(sys._base_executable),
                    ("-c", "import sys;sys.stdout.write('x'*70000);sys.stdout.flush()"),
                    workspace=workspace,
                    timeout_seconds=30.0,
                )
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_failure_boundaries_remain_fixed_and_close_handles(self):
        stages = {"setup", "limits", "attribute_initialize", "attribute_update", "create", "assign", "resume", "wait", "exit", "query", "close"}
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
                            process.run_contained_verifier(Path(sys.executable), ("-c", "print(1)"), workspace=workspace, timeout_seconds=1.0)

    @unittest.skipUnless(os.name == "nt", "Windows handle inheritance test")
    def test_real_windows_handle_canary_is_not_inherited_and_capture_works(self):
        import msvcrt

        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            canary = root / "canary.bin"
            descriptor = os.open(canary, os.O_BINARY | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                handle = msvcrt.get_osfhandle(descriptor)
                os.set_handle_inheritable(handle, True)
                script = "exec(\"try:\\n fd=msvcrt.open_osfhandle(int(sys.argv[1]),os.O_WRONLY)\\n os.write(fd,b'LEAK')\\n os.close(fd)\\n print('CANARY_WRITE_OK')\\nexcept OSError:\\n print('CANARY_HANDLE_UNAVAILABLE')\")"
                script = "import msvcrt,os,sys;" + script
                workspace = root / "workspace"
                workspace.mkdir()
                result = process.run_contained_verifier(Path(sys._base_executable), ("-c", script, str(handle)), workspace=workspace, timeout_seconds=30.0)
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(canary.read_bytes(), b"")
                self.assertIn(b"CANARY_HANDLE_UNAVAILABLE", result.stdout)
                self.assertNotIn(b"CANARY_WRITE_OK", result.stdout)
                self.assertEqual(result.stderr, b"")
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
