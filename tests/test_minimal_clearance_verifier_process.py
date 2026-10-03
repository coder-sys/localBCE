from __future__ import annotations

import ctypes
import hashlib
import itertools
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import app.minimal_clearance_verifier_process as process


_ECHO = """
import os, sys, time
mode, go = sys.argv[1:]
n = 0
while len(head := sys.stdin.buffer.read(4)) == 4:
    body = sys.stdin.buffer.read(int.from_bytes(head, "big")); n += 1
    if mode == "silent":
        time.sleep(60)
    frame = (len(body) + 11).to_bytes(4, "big") + b"ANSWER-FOR-" + body
    sys.stdout.buffer.write(frame * (2 if mode == "dup" and n == 1 else 1)); sys.stdout.buffer.flush()
    if mode == "late" and n == 1:
        while not os.path.exists(go):
            time.sleep(0.01)
        sys.stdout.buffer.write(frame); sys.stdout.buffer.flush()
"""


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
        self.CloseHandle = _FakeFunction(self._close)
        self.SetHandleInformation = _FakeFunction(lambda *_: 1)
        self.GetCurrentProcess = _FakeFunction(lambda: 9000)
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
        self.events.append(("job_limits_set", (int(limits.BasicLimitInformation.LimitFlags), int(limits.JobMemoryLimit), int(limits.BasicLimitInformation.ActiveProcessLimit))))
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
        if int(attribute) == process._PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY:
            self.events.append(("attr_image_policy", ctypes.cast(value, ctypes.POINTER(ctypes.c_uint64)).contents.value))
            return 1
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
        return 0

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
        self.assertEqual([name for name, _ in kernel.events if name.startswith("attr_")], ["attr_size", "attr_initialize", "attr_update", "attr_bytes", "attr_image_policy", "attr_delete"])
        self.assertEqual(next(value for name, value in kernel.events if name == "attr_image_policy"), process._IMAGE_LOAD_POLICY)

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

    PAYLOAD = b"synthetic-pinned-verifier"

    def _launch(self, kernel, **override):
        """Launch a worker on a fake kernel (None: any Win32 call is an error); returns the worker and the pinned file."""

        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = root / "verifier.exe"
            executable.write_bytes(self.PAYLOAD)
            arguments = {
                "workspace": root, "job_memory_cap_bytes": process.ADMISSION_CAP_BYTES,
                "expected_executable_size_bytes": len(self.PAYLOAD),
                "expected_executable_sha256": hashlib.sha256(self.PAYLOAD).digest(),
            } | override
            boundary = patch.object(process.ctypes, "WinDLL", return_value=kernel) if kernel else patch.object(process.ctypes, "WinDLL", side_effect=AssertionError("Win32 boundary was reached"))
            with boundary:
                return process.launch_contained_worker(executable, **arguments), executable

    def _launch_fails(self, kernel, pattern="", **override):
        with self.assertRaisesRegex(process.VerifierProcessError, pattern):
            self._launch(kernel, **override)
        if kernel:
            self.assertEqual(kernel.pin_close_count, len(kernel.pin_handles))
            self.assertTrue(all(state["closed"] for state in kernel.pin_handles.values()))

    def test_missing_or_partial_executable_pin_is_rejected_before_create(self):
        digest = hashlib.sha256(self.PAYLOAD).digest()
        for size, sha in ((None, None), (len(self.PAYLOAD), None), (None, digest)):
            with self.subTest(size=size, sha=sha):
                self._launch_fails(None, "verifier_executable_pin", expected_executable_size_bytes=size, expected_executable_sha256=sha)

    def test_memory_cap_must_be_a_positive_int_within_the_admission_cap(self):
        for cap in (0, True, process.ADMISSION_CAP_BYTES + 1):
            with self.subTest(cap=cap):
                self._launch_fails(None, "verifier_memory_cap", job_memory_cap_bytes=cap)

    def test_pinned_handles_are_held_through_create_assignment_and_resume(self):
        kernel = _Kernel(pin_data=self.PAYLOAD)
        kernel.child_image_path = kernel.nt_path.upper()
        worker, executable = self._launch(kernel)
        self.addCleanup(worker.close)
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
        self.assertEqual(next(value for name, value in kernel.events if name == "create_application"), kernel.dos_path)
        self.assertEqual(next(value for name, value in kernel.events if name == "create_command"), kernel.dos_path)
        self.assertEqual(next(value for name, value in kernel.events if name == "create_directory"), str(executable.parent))
        self.assertIn(("file_id", (str(executable), b"R" * 16)), kernel.events)
        self.assertIn(("file_id", (kernel.dos_path, b"R" * 16)), kernel.events)
        self.assertIn(("final_path", (process._FILE_NAME_NORMALIZED | process._VOLUME_NAME_GUID, kernel.canonical_path)), kernel.events)
        self.assertIn(("final_path", (process._FILE_NAME_NORMALIZED | process._VOLUME_NAME_NT, kernel.nt_path)), kernel.events)
        self.assertIn(("final_path", (process._FILE_NAME_NORMALIZED | process._VOLUME_NAME_DOS, kernel.dos_path)), kernel.events)
        self.assertEqual([value for name, value in kernel.events if name == "query_dos_device"], [("C:", kernel.native_volume_prefix)] * 2)
        self.assertEqual(next(value for name, value in kernel.events if name == "child_image"), kernel.nt_path.upper())
        query_positions = [index for index, name in enumerate(names) if name == "query_dos_device"]
        self.assertLess(query_positions[0], names.index("create"))
        self.assertLess(names.index("create"), query_positions[1])
        self.assertLess(query_positions[1], names.index("child_image"))
        self.assertLess(names.index("child_image"), names.index("assign"))
        self.assertLess(names.index("assign"), names.index("resume"))
        self.assertLess(names.index("resume"), names.index("pin_close"))
        self.assertEqual(
            next(value for name, value in kernel.events if name == "job_limits_set"),
            (process._JOB_LIMIT_FLAGS, process.ADMISSION_CAP_BYTES, process.ACTIVE_PROCESS_LIMIT),
        )

    def test_suspended_child_binding_failures_kill_and_reap_before_assignment(self):
        for failure in ("dos_mapping_after_create", "image_api", "image_truncated", "image_non_device", "image_mismatch"):
            with self.subTest(failure=failure):
                kernel = _Kernel(pin_failure=failure, pin_data=self.PAYLOAD)
                self._launch_fails(kernel)
                names = [name for name, _ in kernel.events]
                self.assertIn("terminate_process", names)
                self.assertIn("wait", names)
                self.assertNotIn("assign", names)
                self.assertNotIn("resume", names)
                self.assertLess(names.index("terminate_process"), names.index("wait"))
                self.assertLess(names.index("wait"), names.index("pin_close"))

    def test_post_create_cleanup_failure_is_killed_and_reaped_once_before_pin_close(self):
        kernel = _Kernel(failure="attribute_delete", pin_data=self.PAYLOAD)
        self._launch_fails(kernel, "verifier_process_cleanup")
        names = [name for name, _ in kernel.events]
        self.assertEqual(names.count("terminate_process"), 1)
        self.assertEqual(names.count("wait"), 1)
        self.assertEqual(names.count("assign"), 0)
        self.assertEqual(names.count("resume"), 0)
        self.assertLess(names.index("create"), names.index("terminate_process"))
        self.assertLess(names.index("terminate_process"), names.index("wait"))
        self.assertLess(names.index("wait"), names.index("pin_close"))

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

    @unittest.skipUnless(os.name == "nt", "Windows loader test")
    def test_real_dll_planted_beside_the_pinned_exe_is_not_loaded(self):
        # safety red team L1: more.com imports ulib.dll, which is no KnownDLL, so a copy beside the exe is loaded
        # first unless the launch sets the image-load policy; the planted copy is the real DLL, so only its path differs
        system = Path(os.environ["SystemRoot"]) / "System32"
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32]
        psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
        for policy, loaded_from in ((process._IMAGE_LOAD_POLICY, "system"), (0, "beside")):  # 0: the attack works without the policy
            with self.subTest(policy=policy), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as root_name, patch.object(process, "_IMAGE_LOAD_POLICY", policy):
                beside, work = Path(root_name) / "artifact", Path(root_name) / "work"
                beside.mkdir(), work.mkdir()
                shutil.copyfile(system / "more.com", beside / "more.com")
                shutil.copyfile(system / "ulib.dll", beside / "ulib.dll")
                payload = (beside / "more.com").read_bytes()
                worker = process.launch_contained_worker(beside / "more.com", workspace=work, job_memory_cap_bytes=1_000_000_000,
                                                         expected_executable_size_bytes=len(payload), expected_executable_sha256=hashlib.sha256(payload).digest())
                try:
                    found = None
                    for _ in range(200):  # the loader resolves imports shortly after the resume
                        modules, needed = (ctypes.c_void_p * 512)(), ctypes.c_uint32()
                        self.assertTrue(psapi.EnumProcessModulesEx(worker._process, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3))
                        for module in modules[: needed.value // ctypes.sizeof(ctypes.c_void_p)]:
                            name = ctypes.create_unicode_buffer(1024)
                            psapi.GetModuleFileNameExW(worker._process, module, name, 1024)
                            if os.path.basename(name.value).lower() == "ulib.dll":
                                found = Path(name.value.removeprefix("\\\\?\\")).parent
                        if found is not None:
                            break
                        time.sleep(0.05)
                finally:
                    worker._terminate()
                self.assertIsNotNone(found)
                self.assertEqual(os.path.normcase(found), os.path.normcase(system if loaded_from == "system" else beside))

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
        failures = (
            "stat", "type", "directory", "reparse", "read", "final_path",
            "directory_open", "directory_reparse", "file_id", "file_id_mismatch",
            "reopen_open", "nt_non_device", "dos_unc", "dos_mapping",
            "dos_mapping_mismatch", "image_api", "image_truncated",
            "image_non_device", "image_mismatch",
        )
        for failure in failures:
            with self.subTest(failure=failure):
                self._launch_fails(_Kernel(pin_failure=failure, pin_data=self.PAYLOAD))
        for size, sha in ((len(self.PAYLOAD) + 1, hashlib.sha256(self.PAYLOAD).digest()), (len(self.PAYLOAD), b"x" * 32)):
            with self.subTest(size=size, sha=sha):
                self._launch_fails(_Kernel(pin_data=self.PAYLOAD), expected_executable_size_bytes=size, expected_executable_sha256=sha)

    def test_pinned_create_and_close_failures_close_all_owned_handles_once(self):
        for failure in ("create", "close"):
            with self.subTest(failure=failure):
                self._launch_fails(_Kernel(failure=failure, pin_data=self.PAYLOAD))

    def test_pinned_open_failure_has_no_handle_to_close(self):
        kernel = _Kernel(pin_failure="open", pin_data=self.PAYLOAD)
        self._launch_fails(kernel)
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
    def test_failure_boundaries_remain_fixed_and_close_handles(self):
        for failure in ("setup", "limits", "attribute_initialize", "attribute_update", "create", "assign", "resume", "close"):
            with self.subTest(failure=failure), patch.object(process.ctypes, "get_last_error", return_value=5):
                self._launch_fails(_Kernel(failure=failure, pin_data=self.PAYLOAD))

    @unittest.skipUnless(os.name == "nt", "Windows handle inheritance test")
    def test_real_windows_handle_canary_is_not_inherited(self):
        import msvcrt

        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            executable = Path(sys._base_executable)
            payload = executable.read_bytes()
            descriptor = os.open(root / "canary.bin", os.O_BINARY | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                handle = msvcrt.get_osfhandle(descriptor)
                os.set_handle_inheritable(handle, True)
                workspace = root / "workspace"
                workspace.mkdir()
                worker = process.launch_contained_worker(executable, workspace=workspace, job_memory_cap_bytes=1_000_000_000,
                                                         expected_executable_size_bytes=len(payload), expected_executable_sha256=hashlib.sha256(payload).digest())
                try:
                    # Python with no arguments runs the program it reads from standard input.
                    program = "import msvcrt,os,sys\ntry:\n fd=msvcrt.open_osfhandle(%d,os.O_WRONLY)\n os.write(fd,b'LEAK')\n os.close(fd)\n print('CANARY_WRITE_OK')\nexcept OSError:\n print('CANARY_HANDLE_UNAVAILABLE')\n" % handle
                    os.write(worker._stdin, program.encode())
                    os.close(worker._stdin)
                    worker._stdin = os.open(os.devnull, os.O_RDONLY)
                    streams = []
                    for stream in (worker._stdout, worker._stderr):
                        data = b""
                        while chunk := os.read(stream, 4096):
                            data += chunk
                        streams.append(data)
                finally:
                    worker.close()
                self.assertEqual((root / "canary.bin").read_bytes(), b"")
                self.assertIn(b"CANARY_HANDLE_UNAVAILABLE", streams[0])
                self.assertNotIn(b"CANARY_WRITE_OK", streams[0])
                self.assertEqual(streams[1], b"")
            finally:
                os.close(descriptor)

    def _worker(self, mode="ok"):
        """A ContainedWorker over real pipes to a tiny child: real PeekNamedPipe, the job is fake (killing it kills the child)."""

        go = Path(self.enterContext(tempfile.TemporaryDirectory())) / "go"
        child = subprocess.Popen([sys.executable, "-c", _ECHO, mode, str(go)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.addCleanup(lambda: [child.kill(), child.wait(), *(pipe.close() for pipe in (child.stdin, child.stdout, child.stderr))])
        kernel = types.SimpleNamespace(TerminateJobObject=lambda job, code: child.kill(), PeekNamedPipe=process._launch_apis()[0].PeekNamedPipe)
        worker = process.ContainedWorker(kernel32=kernel, job=None, process_handle=None, stdin_descriptor=child.stdin.fileno(), stdout_descriptor=child.stdout.fileno(), stderr_descriptor=child.stderr.fileno(), psapi=None)
        self.addCleanup(worker._terminate)
        return worker, child, go

    @unittest.skipUnless(os.name == "nt", "Windows worker pipe test")
    def test_contained_worker_watchdog_kills_a_silent_worker_and_ends_with_it(self):
        # One watchdog thread per worker enforces every exchange's deadline; a worker that never answers is killed and the thread ends.
        worker, child, _ = self._worker("silent")
        with self.assertRaises(process.VerifierProcessError) as caught:
            worker.exchange(b"x", response_cap_bytes=16, timeout_seconds=0.5)
        worker._watchdog.join(5)
        self.assertEqual((str(caught.exception), worker.alive, child.wait(5) != 0, worker._watchdog.is_alive()), ("worker_timeout", False, True, False))

    @unittest.skipUnless(os.name == "nt", "Windows worker pipe test")
    def test_contained_worker_answers_pair_with_requests_across_many_exchanges(self):
        worker, _, _ = self._worker()
        for n in range(200):
            self.assertEqual(worker.exchange(b"REQ-%d" % n, response_cap_bytes=64, timeout_seconds=10.0), b"ANSWER-FOR-REQ-%d" % n)
        self.assertTrue(worker.alive)

    @unittest.skipUnless(os.name == "nt", "Windows worker pipe test")
    def test_contained_worker_extra_frame_fails_closed_and_never_pairs_answers_off_by_one(self):
        # "dup": the first answer is written twice.  "late": the copy arrives after the first exchange returned.
        for mode in ("dup", "late"):
            with self.subTest(mode=mode):
                worker, child, go = self._worker(mode)
                if mode == "dup":
                    with self.assertRaises(process.VerifierProcessError) as caught:
                        worker.exchange(b"REQ-1", response_cap_bytes=64, timeout_seconds=10.0)
                else:
                    self.assertEqual(worker.exchange(b"REQ-1", response_cap_bytes=64, timeout_seconds=10.0), b"ANSWER-FOR-REQ-1")
                    go.write_bytes(b"")
                    for _ in range(500):
                        if worker._pending(child.stdout.fileno()):
                            break
                        time.sleep(0.01)
                    with self.assertRaises(process.VerifierProcessError) as caught:
                        worker.exchange(b"REQ-2", response_cap_bytes=64, timeout_seconds=10.0)
                self.assertEqual((str(caught.exception), worker.alive), ("worker_exchange", False))
                self.assertNotEqual(child.wait(5), 0)
                with self.assertRaises(process.VerifierProcessError) as again:
                    worker.exchange(b"REQ-3", response_cap_bytes=64, timeout_seconds=10.0)
                self.assertEqual(str(again.exception), "worker_unavailable")


if __name__ == "__main__":
    unittest.main()
