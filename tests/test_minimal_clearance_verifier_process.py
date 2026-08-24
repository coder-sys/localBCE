from __future__ import annotations

import ctypes
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
    def __init__(self, *, failure: str | None = None, overlap: bool = False):
        self.failure = failure
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
        handles = ctypes.cast(value, ctypes.POINTER(process.wintypes.HANDLE * 2)).contents
        self.handles = [int(item.value if hasattr(item, "value") else item) for item in handles]
        self.events.append(("attr_bytes", int(size)))
        return 1

    def _attrs_delete(self, _attribute_list):
        self.events.append(("attr_delete", True))
        if self.failure == "attribute_delete":
            raise RuntimeError("attribute cleanup canary")

    def _create(self, _application, _command, _p1, _p2, inherit, flags, _env, _directory, startup_ptr, process_ptr):
        self.events.append(("create_args", (bool(inherit), int(flags))))
        startup = ctypes.cast(startup_ptr, ctypes.POINTER(process._StartupInfoEx)).contents
        self.events.append(("startup_cb", int(startup.StartupInfo.cb)))
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
        observed = ctypes.cast(observed_ptr, ctypes.POINTER(process._JobObjectExtendedLimitInformation)).contents
        observed.PeakJobMemoryUsed = 1
        return 1

    def _close(self, handle):
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
