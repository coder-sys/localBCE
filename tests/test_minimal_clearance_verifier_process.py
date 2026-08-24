from __future__ import annotations

import ctypes
from concurrent.futures import ThreadPoolExecutor
import itertools
from pathlib import Path
import os
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import app.minimal_clearance_verifier_process as process


class _FakeFunction:
    def __init__(self, callback):
        self._callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self._callback(*args)


class _ScriptedKernel:
    def __init__(self, *, failure: str | None = None, overlap: bool = False):
        self.failure = failure
        self.events: list[tuple[str, object]] = []
        self._lock = threading.Lock()
        self._process_counter = itertools.count(1)
        self._job_counter = itertools.count(1)
        self._wait_barrier = threading.Barrier(2) if overlap else None
        self._create_barrier = threading.Barrier(2) if overlap else None
        self._active_waiters = 0
        self.overlap_observed = False
        self.handle_list: list[int] = []
        self._install_functions()

    def _install_functions(self) -> None:
        self.CreateJobObjectW = _FakeFunction(self._create_job)
        self.SetInformationJobObject = _FakeFunction(self._set_limits)
        self.CreateProcessW = _FakeFunction(self._create_process)
        self.AssignProcessToJobObject = _FakeFunction(self._assign)
        self.ResumeThread = _FakeFunction(self._resume)
        self.WaitForSingleObject = _FakeFunction(self._wait)
        self.TerminateJobObject = _FakeFunction(self._terminate_job)
        self.TerminateProcess = _FakeFunction(self._terminate_process)
        self.GetExitCodeProcess = _FakeFunction(self._exit_code)
        self.QueryInformationJobObject = _FakeFunction(self._query)
        self.CloseHandle = _FakeFunction(self._close_handle)
        self.SetHandleInformation = _FakeFunction(lambda *args: 1)
        self.InitializeProcThreadAttributeList = _FakeFunction(self._initialize_attrs)
        self.UpdateProcThreadAttribute = _FakeFunction(self._update_attrs)
        self.DeleteProcThreadAttributeList = _FakeFunction(self._delete_attrs)

    def _create_job(self, *_args):
        if self.failure == "setup":
            return 0
        job = 7000 + next(self._job_counter)
        self.events.append(("job", job))
        return job

    def _set_limits(self, *_args):
        return 0 if self.failure == "limits" else 1

    def _initialize_attrs(self, attribute_list, _count, _flags, size_ptr):
        size = ctypes.cast(size_ptr, ctypes.POINTER(ctypes.c_size_t)).contents
        if not attribute_list:
            size.value = 64
            self.events.append(("attr_size", 64))
            return 0
        self.events.append(("attr_initialize", True))
        return 0 if self.failure == "attribute_initialize" else 1

    def _update_attrs(self, _attribute_list, _flags, attribute, value, size, _previous, _returned):
        self.events.append(("attr_update", int(attribute)))
        if self.failure == "attribute_update":
            return 0
        handles = ctypes.cast(
            value, ctypes.POINTER(process.wintypes.HANDLE * 2)
        ).contents
        self.handle_list = [
            int(item.value if hasattr(item, "value") else item) for item in handles
        ]
        self.events.append(("attr_bytes", int(size)))
        return 1

    def _delete_attrs(self, _attribute_list):
        self.events.append(("attr_delete", True))
        if self.failure == "attribute_delete":
            raise RuntimeError("attribute cleanup")

    def _create_process(self, _application, _command, _p1, _p2, inherit, flags,
                        _environment, _directory, startup_ptr, process_ptr):
        self.events.append(("create_args", (bool(inherit), int(flags))))
        startup = ctypes.cast(
            startup_ptr, ctypes.POINTER(process._StartupInfoEx)
        ).contents
        self.events.append(("startup_cb", int(startup.StartupInfo.cb)))
        if self.failure == "create":
            return 0
        if self._create_barrier is not None:
            self._create_barrier.wait(timeout=5)
            self.overlap_observed = True
        index = next(self._process_counter)
        info = ctypes.cast(
            process_ptr, ctypes.POINTER(process._ProcessInformation)
        ).contents
        info.hProcess = 5000 + index
        info.hThread = 6000 + index
        self.events.append(("create", index))
        return 1

    def _assign(self, _job, _process):
        self.events.append(("assign", True))
        return 0 if self.failure == "assign" else 1

    def _resume(self, _thread):
        self.events.append(("resume", True))
        return 0xFFFFFFFF if self.failure == "resume" else 0

    def _wait(self, _process, _timeout):
        self.events.append(("wait", True))
        if self.failure == "wait":
            return 3
        with self._lock:
            self._active_waiters += 1
            if self._active_waiters == 2:
                self.overlap_observed = True
        try:
            if self._wait_barrier is not None:
                self._wait_barrier.wait(timeout=5)
            return 0
        finally:
            with self._lock:
                self._active_waiters -= 1

    def _terminate_job(self, *_args):
        self.events.append(("terminate_job", True))
        return 1

    def _terminate_process(self, *_args):
        self.events.append(("terminate_process", True))
        return 1

    def _exit_code(self, _process, code_ptr):
        if self.failure == "exit":
            return 0
        ctypes.cast(code_ptr, ctypes.POINTER(process.wintypes.DWORD)).contents.value = 0
        return 1

    def _query(self, _job, _info_class, observed_ptr, _size, _returned):
        if self.failure == "query":
            return 0
        observed = ctypes.cast(
            observed_ptr, ctypes.POINTER(process._JobObjectExtendedLimitInformation)
        ).contents
        observed.PeakJobMemoryUsed = 1
        return 1

    def _close_handle(self, handle):
        self.events.append(("close_handle", int(handle)))
        return 0 if self.failure == "close_handle" else 1


class _CreateOnlyKernel(_ScriptedKernel):
    def __init__(self, create_callback):
        super().__init__()
        self.CreateProcessW = _FakeFunction(create_callback)


class MinimalClearanceVerifierProcessTests(unittest.TestCase):
    def _inputs(self, operation: int):
        return {
            "executable": Path(f"verifier-{operation}.exe"),
            "output_paths": (
                Path(f"op{operation}-stdout.bin"),
                Path(f"op{operation}-stderr.bin"),
            ),
            "startup": process._StartupInfoEx(),
            "environment": ctypes.create_unicode_buffer("BL_NETWORK_DISABLED=1\0\0"),
            "command_line": ctypes.create_unicode_buffer("verifier"),
            "creation_flags": process._CREATE_SUSPENDED | process._EXTENDED_STARTUPINFO_PRESENT,
            "process_info": process._ProcessInformation(),
        }

    def test_handle_list_contains_only_owned_output_handles_and_extended_flag(self):
        kernel = _ScriptedKernel()
        descriptors = iter((4101, 4102))
        closed: list[int] = []

        def fake_output(_path: Path):
            descriptor = next(descriptors)
            return descriptor, descriptor + 9000

        values = self._inputs(1)
        with patch.object(process, "_create_output_handle", side_effect=fake_output), \
             patch.object(process.os, "close", side_effect=closed.append):
            process._create_process_with_owned_output_handles(kernel32=kernel, **values)
        self.assertEqual(kernel.handle_list, [13101, 13102])
        self.assertEqual(sorted(closed), [4101, 4102])
        create_args = next(item[1] for item in kernel.events if item[0] == "create_args")
        self.assertTrue(create_args[0])
        self.assertTrue(create_args[1] & process._EXTENDED_STARTUPINFO_PRESENT)
        self.assertEqual(
            [item[0] for item in kernel.events if item[0].startswith("attr_")],
            ["attr_size", "attr_initialize", "attr_update", "attr_bytes", "attr_delete"],
        )

    def test_parallel_creation_has_no_global_creation_lock_or_shared_capture(self):
        kernel = _ScriptedKernel(overlap=True)
        descriptor_counter = itertools.count(1000)
        closed: list[int] = []

        def fake_output(_path: Path):
            descriptor = next(descriptor_counter)
            return descriptor, descriptor + 10000

        def launch(operation: int) -> None:
            values = self._inputs(operation)
            process._create_process_with_owned_output_handles(kernel32=kernel, **values)

        with patch.object(process, "_create_output_handle", side_effect=fake_output), \
             patch.object(process.os, "close", side_effect=closed.append):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(launch, operation) for operation in (1, 2)]
                for future in futures:
                    future.result(timeout=10)
        self.assertTrue(kernel.overlap_observed)
        self.assertEqual(len(closed), 4)
        self.assertFalse(hasattr(process, "_PROCESS_CREATION_LOCK"))

    def test_attribute_and_creation_failures_delete_attribute_and_close_descriptors_once(self):
        for failure, expected in (
            ("attribute_initialize", "verifier_attribute_list_initialize"),
            ("attribute_update", "verifier_attribute_list_update"),
            ("create", "verifier_process_create"),
            ("attribute_delete", "verifier_process_cleanup"),
        ):
            with self.subTest(failure=failure):
                kernel = _ScriptedKernel(failure=failure)
                descriptors = iter((4101, 4102))
                closed: list[int] = []

                def fake_output(_path: Path):
                    descriptor = next(descriptors)
                    return descriptor, descriptor + 9000

                with patch.object(process, "_create_output_handle", side_effect=fake_output), \
                     patch.object(process.os, "close", side_effect=closed.append), \
                     patch.object(process.ctypes, "get_last_error", return_value=5):
                    with self.assertRaisesRegex(process.VerifierProcessError, expected):
                        process._create_process_with_owned_output_handles(
                            kernel32=kernel, **self._inputs(1)
                        )
                self.assertEqual(sorted(closed), [4101, 4102])
                deletes = [item for item in kernel.events if item[0] == "attr_delete"]
                self.assertEqual(len(deletes), 0 if failure == "attribute_initialize" else 1)

    def test_parent_descriptor_close_failure_terminates_created_process(self):
        kernel = _ScriptedKernel()
        with patch.object(
            process, "_create_output_handle", side_effect=((4101, 13101), (4102, 13102))
        ), patch.object(
            process, "_close_parent_descriptors_once",
            side_effect=process.VerifierProcessError("verifier_output_close"),
        ):
            with self.assertRaisesRegex(process.VerifierProcessError, "verifier_process_cleanup"):
                process._create_process_with_owned_output_handles(
                    kernel32=kernel, **self._inputs(1)
                )
        self.assertIn(("terminate_process", True), kernel.events)
        self.assertEqual(
            len([item for item in kernel.events if item[0] == "attr_delete"]), 1
        )

    def test_failure_boundaries_remain_bounded_and_close_owned_handles_once(self):
        stages = {
            "setup": "verifier_job_create",
            "limits": "verifier_job_limits",
            "create": "verifier_process_create",
            "assign": "verifier_job_assign",
            "resume": "verifier_process_resume",
            "wait": "verifier_wait",
            "exit": "verifier_exit_code",
            "query": "verifier_job_query",
            "read": "verifier_stdout_read",
            "close_handle": "verifier_cleanup",
            "cleanup": "verifier_cleanup",
        }
        for failure, expected in stages.items():
            with self.subTest(failure=failure):
                kernel = _ScriptedKernel(failure=failure)
                descriptor_counter = itertools.count(1000)
                closed: list[int] = []

                def fake_output(_path: Path):
                    descriptor = next(descriptor_counter)
                    return descriptor, descriptor + 10000

                def fake_read(_path: Path, _limit: int, _label: str) -> bytes:
                    if failure == "read":
                        raise process.VerifierProcessError("verifier_stdout_read")
                    return b"bounded\n"

                def fail_unlink(self: Path, *, missing_ok: bool = False) -> None:
                    raise PermissionError(32, "sharing violation")

                patches = [
                    patch.object(process.ctypes, "WinDLL", return_value=kernel),
                    patch.object(process, "_create_output_handle", side_effect=fake_output),
                    patch.object(process.os, "close", side_effect=closed.append),
                    patch.object(process, "_read_capped", side_effect=fake_read),
                    patch.object(process.ctypes, "get_last_error", return_value=5),
                ]
                if failure == "cleanup":
                    patches.append(patch.object(Path, "unlink", fail_unlink))
                with tempfile.TemporaryDirectory() as root_name:
                    workspace = Path(root_name)
                    for item in patches:
                        item.__enter__()
                    try:
                        with self.assertRaisesRegex(process.VerifierProcessError, expected):
                            process.run_contained_verifier(
                                Path(__file__), ("--synthetic",),
                                workspace=workspace, timeout_seconds=1.0,
                            )
                    finally:
                        for item in reversed(patches):
                            item.__exit__(None, None, None)
                self.assertEqual(len(closed), len(set(closed)))
                self.assertEqual(
                    len([item for item in kernel.events if item[0] == "attr_delete"]),
                    0 if failure in ("setup", "limits") else 1,
                )

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
                script = (
                    "import msvcrt, os, sys\n"
                    "h = int(sys.argv[1])\n"
                    "try:\n"
                    "    fd = msvcrt.open_osfhandle(h, os.O_WRONLY)\n"
                    "    os.write(fd, b'LEAK')\n"
                    "    os.close(fd)\n"
                    "    print('CANARY_WRITE_OK')\n"
                    "except OSError:\n"
                    "    print('CANARY_HANDLE_UNAVAILABLE')\n"
                )
                workspace = root / "workspace"
                workspace.mkdir()
                result = process.run_contained_verifier(
                    Path(sys._base_executable), ("-c", script, str(handle)),
                    workspace=workspace, timeout_seconds=30.0,
                )
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(canary.read_bytes(), b"")
                self.assertIn(b"CANARY_HANDLE_UNAVAILABLE", result.stdout)
                self.assertNotIn(b"CANARY_WRITE_OK", result.stdout)
                self.assertEqual(result.stderr, b"")
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
