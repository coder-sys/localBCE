from __future__ import annotations

import ctypes
from concurrent.futures import ThreadPoolExecutor
import itertools
from pathlib import Path
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


class _CreateOnlyKernel:
    def __init__(self, create_callback):
        self.CreateProcessW = _FakeFunction(create_callback)


class _ScriptedKernel:
    def __init__(self, *, failure: str | None = None, overlap: bool = False):
        self.failure = failure
        self.events: list[tuple[str, object]] = []
        self._lock = threading.Lock()
        self._process_counter = itertools.count(1)
        self._job_counter = itertools.count(1)
        self._wait_barrier = threading.Barrier(2) if overlap else None
        self._active_waiters = 0
        self.overlap_observed = False
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

    def _create_job(self, *_args):
        if self.failure == "setup":
            return 0
        job = 7000 + next(self._job_counter)
        self.events.append(("job", job))
        return job

    def _set_limits(self, *_args):
        return 0 if self.failure == "limits" else 1

    def _create_process(self, _application, _command, _p1, _p2, _inherit, _flags,
                        _environment, _directory, _startup_ptr, process_ptr):
        if self.failure == "create":
            return 0
        index = next(self._process_counter)
        info = ctypes.cast(
            process_ptr, ctypes.POINTER(process._ProcessInformation)
        ).contents
        info.hProcess = 5000 + index
        info.hThread = 6000 + index
        self.events.append(("create", index))
        return 1

    def _assign(self, _job, _process):
        unlocked = not process._PROCESS_CREATION_LOCK.locked()
        self.events.append(("assign_unlocked", unlocked))
        return 0 if self.failure == "assign" else 1

    def _resume(self, _thread):
        unlocked = not process._PROCESS_CREATION_LOCK.locked()
        self.events.append(("resume_unlocked", unlocked))
        return 0xFFFFFFFF if self.failure == "resume" else 0

    def _wait(self, _process, _timeout):
        unlocked = not process._PROCESS_CREATION_LOCK.locked()
        self.events.append(("wait_unlocked", unlocked))
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


class MinimalClearanceVerifierProcessTests(unittest.TestCase):
    def _inputs(self, operation: int):
        return {
            "executable": Path(f"verifier-{operation}.exe"),
            "output_paths": (
                Path(f"op{operation}-stdout.bin"),
                Path(f"op{operation}-stderr.bin"),
            ),
            "startup": process._StartupInfo(),
            "environment": ctypes.create_unicode_buffer("BL_NETWORK_DISABLED=1\0\0"),
            "command_line": ctypes.create_unicode_buffer("verifier"),
            "creation_flags": process._CREATE_SUSPENDED,
            "process_info": process._ProcessInformation(),
        }

    def test_creation_window_serializes_inheritable_handles_only(self):
        events: list[tuple[str, object]] = []
        events_lock = threading.Lock()
        first_create_entered = threading.Event()
        release_first_create = threading.Event()
        create_count = itertools.count(1)
        descriptor_owner: dict[int, int] = {}

        def record(event: tuple[str, object]) -> None:
            with events_lock:
                events.append(event)

        def fake_output(path: Path):
            operation = int(path.name[2])
            fd = 1000 + len(descriptor_owner)
            descriptor_owner[fd] = operation
            record(("open", operation))
            return fd, 2000 + fd

        def fake_close(fd: int) -> None:
            record(("close", descriptor_owner[fd]))

        def fake_create(*_args):
            index = next(create_count)
            record(("create_enter", index))
            if index == 1:
                first_create_entered.set()
                if not release_first_create.wait(timeout=5):
                    raise AssertionError("fake CreateProcess gate timed out")
            record(("create_return", index))
            return 1

        def launch(operation: int) -> None:
            values = self._inputs(operation)
            kernel = _CreateOnlyKernel(fake_create)
            process._create_process_with_owned_output_handles(kernel32=kernel, **values)

        with patch.object(process, "_create_output_handle", side_effect=fake_output), \
             patch.object(process.os, "close", side_effect=fake_close):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first_future = executor.submit(launch, 1)
                self.assertTrue(first_create_entered.wait(timeout=5))
                second_future = executor.submit(launch, 2)
                with events_lock:
                    while_events = list(events)
                self.assertEqual(
                    [event for event in while_events if event[0] == "open"],
                    [("open", 1), ("open", 1)],
                )
                release_first_create.set()
                first_future.result(timeout=5)
                second_future.result(timeout=5)

        second_open = next(index for index, event in enumerate(events) if event == ("open", 2))
        first_return = next(index for index, event in enumerate(events) if event == ("create_return", 1))
        first_closes = [index for index, event in enumerate(events) if event == ("close", 1)]
        self.assertEqual(len(first_closes), 2)
        self.assertTrue(all(first_return < index < second_open for index in first_closes))
        self.assertFalse(process._PROCESS_CREATION_LOCK.locked())

    def test_assignment_resume_wait_and_execution_overlap_are_outside_lock(self):
        kernel = _ScriptedKernel(overlap=True)
        descriptor_counter = itertools.count(1000)
        closed: list[int] = []

        def fake_output(_path: Path):
            fd = next(descriptor_counter)
            return fd, fd + 10000

        def fake_close(fd: int) -> None:
            closed.append(fd)

        def run(operation: int, root: Path):
            workspace = root / f"op{operation}"
            workspace.mkdir()
            return process.run_contained_verifier(
                Path(__file__), ("--synthetic",), workspace=workspace, timeout_seconds=1.0
            )

        with tempfile.TemporaryDirectory() as root_name, \
             patch.object(process.ctypes, "WinDLL", return_value=kernel), \
             patch.object(process, "_create_output_handle", side_effect=fake_output), \
             patch.object(process.os, "close", side_effect=fake_close), \
             patch.object(process, "_read_capped", return_value=b"bounded\n"):
            root = Path(root_name)
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = [executor.submit(run, operation, root) for operation in (1, 2)]
                for future in results:
                    result = future.result(timeout=10)
                    self.assertEqual(result.exit_code, 0)

        self.assertTrue(kernel.overlap_observed)
        self.assertEqual([event for event in kernel.events if event[0] == "assign_unlocked"],
                         [("assign_unlocked", True), ("assign_unlocked", True)])
        self.assertEqual([event for event in kernel.events if event[0] == "resume_unlocked"],
                         [("resume_unlocked", True), ("resume_unlocked", True)])
        self.assertEqual([event for event in kernel.events if event[0] == "wait_unlocked"],
                         [("wait_unlocked", True), ("wait_unlocked", True)])
        self.assertEqual(len(closed), 4)

    def test_create_failure_closes_each_parent_descriptor_once(self):
        descriptors = [4101, 4102]
        closed: list[int] = []
        descriptor_values = iter(descriptors)

        def fake_output(_path: Path):
            fd = next(descriptor_values)
            return fd, 9000 + fd

        def fake_close(fd: int) -> None:
            closed.append(fd)

        kernel = _CreateOnlyKernel(lambda *_args: 0)
        values = self._inputs(1)
        with patch.object(process, "_create_output_handle", side_effect=fake_output), \
             patch.object(process.os, "close", side_effect=fake_close), \
             patch.object(process.ctypes, "get_last_error", return_value=5):
            with self.assertRaisesRegex(process.VerifierProcessError, r"verifier_process_create"):
                process._create_process_with_owned_output_handles(kernel32=kernel, **values)
        self.assertEqual(sorted(closed), descriptors)
        self.assertEqual(len(closed), len(set(closed)))

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
                    fd = next(descriptor_counter)
                    return fd, fd + 10000

                def fake_close(fd: int) -> None:
                    closed.append(fd)

                def fake_read(_path: Path, _limit: int, _label: str) -> bytes:
                    if failure == "read":
                        raise process.VerifierProcessError("verifier_stdout_read")
                    return b"bounded\n"

                def fail_unlink(self: Path, *, missing_ok: bool = False) -> None:
                    raise PermissionError(32, "sharing violation")

                patches = [
                    patch.object(process.ctypes, "WinDLL", return_value=kernel),
                    patch.object(process, "_create_output_handle", side_effect=fake_output),
                    patch.object(process.os, "close", side_effect=fake_close),
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


if __name__ == "__main__":
    unittest.main()
