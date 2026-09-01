from __future__ import annotations

from contextlib import redirect_stdout
import ctypes
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

import profile11_complete_path as screen
import app.minimal_clearance_source_auth_verifier_adapter as source_auth_adapter


class _Backend:
    def __init__(self, *, capability=(True, True, True, True), result=None) -> None:
        self._capability = capability
        self._result = result
        self.started_with: int | None = None

    def capability(self):
        return self._capability

    def start(self, root_pid: int) -> None:
        self.started_with = root_pid

    def stop(self):
        return self._result or screen.FileWriteObservation("observer_ready", True, True, True, False)


class Profile11CompletePathTests(unittest.TestCase):
    @staticmethod
    def _timed_sample(index: int = 0) -> screen.StageSample:
        breakdown = screen.VerifyStateBreakdown(1.0 + index, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0)
        source = 1.0 + index
        verify_state = 2.0 + index
        ack = 3.0 + index
        total_unbucketed = 1.0
        total = source + verify_state + ack + total_unbucketed
        return screen.StageSample(source, verify_state, ack, total, breakdown, total_unbucketed)

    def test_manifest_and_exact_pins(self) -> None:
        manifest = json.loads(screen.MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["topology"], {"batch_operations": 100, "proofs": 1, "source_frames": 1, "verifier_batches": 1, "outbox_acks": 100})
        self.assertEqual(manifest["limits"]["component_admission_bytes"], 4_500_000_000)
        self.assertEqual(manifest["limits"]["complete_tree_hard_peak_bytes"], 4_999_999_999)
        self.assertEqual(manifest["git_pins"]["producer"]["head"], screen.PRODUCER_HEAD)
        self.assertEqual(manifest["git_pins"]["producer"]["tree"], screen.PRODUCER_TREE)
        self.assertEqual(manifest["git_pins"]["c"]["head"], screen.C_HEAD)
        self.assertEqual(manifest["git_pins"]["c"]["tree"], screen.C_TREE)
        self.assertEqual(manifest["file_pins"]["producer_executable"]["bytes"], screen.PRODUCER_EXECUTABLE_SIZE_BYTES)
        self.assertEqual(manifest["file_pins"]["producer_executable"]["sha256"], screen.PRODUCER_EXECUTABLE_SHA256)
        self.assertEqual(manifest["file_pins"]["source_host"]["bytes"], screen.SOURCE_HOST_SIZE_BYTES)
        self.assertEqual(manifest["file_pins"]["c_verifier"]["bytes"], screen.SOURCE_AUTH_EXECUTABLE_SIZE_BYTES)
        self.assertIsNone(manifest["qualification"]["proofSuiteId"])
        self.assertFalse(manifest["qualification"]["production_usable"])
        self.assertFalse(manifest["qualification"]["activation"])

    def test_dependency_pins_and_empty_workspaces(self) -> None:
        with tempfile.TemporaryDirectory(prefix="profile11-preflight-") as directory:
            root = Path(directory)
            source = root / "source"
            verifier = root / "verifier"
            state = root / "state"
            source.mkdir()
            verifier.mkdir()
            state.mkdir()
            report = screen.validate_dependencies(source_workspace=source, verifier_workspace=verifier, state_workspace=state)
        self.assertTrue(report.ready, (report.missing, report.mismatched))
        self.assertEqual(report.failure_count, 0)

    def test_topology_is_exactly_one_proof_and_100_operations(self) -> None:
        screen.validate_topology(proof_count=1, operation_count=100, frame_count=1, verifier_batch_count=1, ack_count=100)
        for values in ((2, 100, 1, 1, 100), (1, 99, 1, 1, 100), (1, 100, 2, 1, 100), (1, 100, 1, 2, 100), (1, 100, 1, 1, 99)):
            with self.subTest(values=values):
                with self.assertRaisesRegex(screen.CompletePathError, "topology_mismatch"):
                    screen.validate_topology(proof_count=values[0], operation_count=values[1], frame_count=values[2], verifier_batch_count=values[3], ack_count=values[4])

    def test_state_port_advances_persisted_sequence_between_batches(self) -> None:
        port = screen._ScreenStatePort()
        first_refs = tuple(index.to_bytes(32, "big") for index in range(100))
        second_refs = tuple((100 + index).to_bytes(32, "big") for index in range(100))
        first = port.controls_for(batch_id=bytes(32), operation_refs=first_refs, verification_outcome=object())
        second = port.controls_for(batch_id=bytes([1]) * 32, operation_refs=second_refs, verification_outcome=object())
        self.assertEqual((first[first_refs[0]].sequence_before, first[first_refs[-1]].sequence_before), (0, 99))
        self.assertEqual((second[second_refs[0]].sequence_before, second[second_refs[-1]].sequence_before), (100, 199))
        self.assertEqual(second[second_refs[0]].predecessor_state_id, first[first_refs[-1]].state_after_id)
        self.assertEqual(second[second_refs[0]].predecessor_continuity_root, first[first_refs[-1]].state_after_continuity_root)

    def test_outer_cap_is_strict_and_readback_is_exact(self) -> None:
        effective = screen.effective_outer_cap(screen.PROCESS_TREE_PEAK_CAP_BYTES, 4096)
        self.assertLess(effective, screen.OUTER_HARD_CAP_BYTES)
        with self.assertRaisesRegex(screen.CompletePathError, "outer_cap_invalid"):
            screen.effective_outer_cap(screen.OUTER_HARD_CAP_BYTES, 4096)
        good = screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 2, 3, True, True, True)
        screen.validate_job_observation(good)
        for bad, code in (
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective + 4096, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 2, 3, True, True, True), "outer_cap_readback"),
            (screen.JobObservation(screen.OUTER_HARD_CAP_BYTES, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 2, 3, True, True, True), "outer_memory_cap"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT - 1, 2, 3, True, True, True), "outer_process_limit_readback"),
            (screen.JobObservation(1024, screen.PROCESS_TREE_PEAK_CAP_BYTES, effective, effective, screen.OUTER_ACTIVE_PROCESS_LIMIT, screen.OUTER_ACTIVE_PROCESS_LIMIT, 2, 0, True, True, True), "outer_process_lineage"),
        ):
            with self.subTest(code=code):
                with self.assertRaisesRegex(screen.CompletePathError, code):
                    screen.validate_job_observation(bad)

    def test_outer_job_probe_contains_child_and_grandchild(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows Job Object ABI is unavailable")
        with tempfile.TemporaryDirectory(prefix="profile11-job-") as directory:
            run = screen._launch_coordinator(Path(directory), timeout_seconds=5.0, arguments=("--probe-coordinator", "0.15"))
        self.assertIsNone(run.error_code, run.error_code)
        self.assertIsNotNone(run.payload)
        self.assertGreaterEqual(run.observation.total_processes, 2)
        self.assertGreaterEqual(run.observation.peak_active_processes, 1)
        screen.validate_job_observation(run.observation)

    def test_outer_job_timeout_terminates_and_reaps(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows Job Object ABI is unavailable")
        with tempfile.TemporaryDirectory(prefix="profile11-timeout-") as directory:
            run = screen._launch_coordinator(Path(directory), timeout_seconds=0.2, arguments=("--probe-coordinator", "3.0"))
        self.assertEqual(run.error_code, "outer_timeout")
        self.assertTrue(run.observation.timed_out)
        self.assertTrue(run.observation.cleanup_complete)
        self.assertTrue(run.observation.process_tree_complete)

    def test_default_observer_fails_closed_without_verified_backend(self) -> None:
        observer = screen.WindowsEtwFileWriteObserver()
        result = observer.probe()
        self.assertEqual(result.status, "observer_unavailable")
        with tempfile.TemporaryDirectory(prefix="profile11-observer-") as directory:
            self.assertEqual(screen.evaluate_disk_gate(result, state_workspace=Path(directory)), "observer_unavailable")

    def test_native_etw_schema_and_abi_fail_closed(self) -> None:
        self.assertFalse(screen._ETW_REQUIRED_FILE_OPERATION_SCHEMA_COMPLETE)
        self.assertEqual(screen._ETW_FILE_TASK_OPERATIONS[16], "write")
        self.assertEqual(screen._ETW_FILE_TASK_OPERATIONS[19], "rename")
        self.assertEqual(screen._ETW_FILE_TASK_OPERATIONS[26], "delete")
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(screen._EtwEventTraceProperties), 120)
            self.assertEqual(ctypes.sizeof(screen._EtwEventRecord), 112)
            self.assertEqual(ctypes.sizeof(screen._EtwTraceLogfileHeader), 280)
            self.assertEqual(ctypes.sizeof(screen._EtwEventTraceLogfileW), 448)
        backend = screen.WindowsEtwWriteTraceBackend()
        capability = backend.capability()
        self.assertFalse(capability[0])
        self.assertEqual(screen.WindowsEtwFileWriteObserver(backend).probe().status, "observer_unavailable")

    def test_native_etw_realtime_session_has_no_logfile(self) -> None:
        backend = screen.WindowsEtwWriteTraceBackend()
        name = "BLProfile11Etw-self-test"
        storage, properties = backend._properties_for_session(name, uuid.uuid4())
        self.assertEqual(properties.contents.LogFileNameOffset, 0)
        self.assertEqual(properties.contents.LoggerNameOffset, ctypes.sizeof(screen._EtwEventTraceProperties))
        self.assertTrue(properties.contents.LogFileMode & screen._ETW_EVENT_TRACE_REAL_TIME_MODE)
        self.assertTrue(properties.contents.LogFileMode & screen._ETW_EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING)
        self.assertEqual(properties.contents.Wnode.Flags, screen._ETW_WNODE_FLAG_TRACED_GUID)
        self.assertEqual(
            ctypes.wstring_at(ctypes.addressof(storage) + properties.contents.LoggerNameOffset),
            name,
        )

    def test_etw_trace_state_requires_causal_lineage_and_generation(self) -> None:
        state = screen._EtwTraceState(100, 123)
        state.record_process(pid=100, key=1000, parent_pid=1, started=True)
        state.record_process(pid=101, key=1001, parent_pid=100, started=True)
        state.record_process(pid=102, key=1002, parent_pid=101, started=True)
        state.record_file(pid=101, key=1001, path=Path(r"C:\state\state.sqlite"), operation="write")
        state.record_process(pid=102, key=1002, parent_pid=101, started=False)
        state.record_process(pid=101, key=1001, parent_pid=100, started=False)
        state.record_process(pid=100, key=1000, parent_pid=1, started=False)
        self.assertTrue(state.complete_lineage())
        self.assertEqual(len(state.events), 1)

        reused = screen._EtwTraceState(100, 123)
        reused.record_process(pid=100, key=1000, parent_pid=1, started=True)
        reused.record_process(pid=101, key=1001, parent_pid=100, started=True)
        reused.record_process(pid=101, key=1001, parent_pid=100, started=False)
        reused.record_process(pid=101, key=2001, parent_pid=100, started=True)
        reused.record_file(pid=101, key=1001, path=Path(r"C:\state\proof.bin"), operation="write")
        self.assertTrue(reused.malformed)
        self.assertFalse(reused.complete_lineage())

    def test_etw_trace_state_rejects_missing_termination_and_bad_paths(self) -> None:
        state = screen._EtwTraceState(100, 123)
        state.record_process(pid=100, key=1000, parent_pid=1, started=True)
        state.record_process(pid=101, key=1001, parent_pid=100, started=True)
        state.record_file(pid=101, key=1001, path=Path(r"relative.tmp"), operation="write")
        self.assertTrue(state.malformed)
        self.assertFalse(state.complete_lineage())

        missing_stop = screen._EtwTraceState(100, 123)
        missing_stop.record_process(pid=100, key=1000, parent_pid=1, started=True)
        missing_stop.record_process(pid=101, key=1001, parent_pid=100, started=True)
        missing_stop.record_process(pid=100, key=1000, parent_pid=1, started=False)
        self.assertFalse(missing_stop.complete_lineage())

    def test_etw_device_path_mapping_fails_closed_for_unknown_devices(self) -> None:
        self.assertEqual(
            screen._etw_path_from_provider(r"\Device\HarddiskVolume3\state.sqlite", ((r"\Device\HarddiskVolume3", "C:"),)),
            Path(r"C:\state.sqlite"),
        )
        with self.assertRaises(screen._EtwMalformedEvent):
            screen._etw_path_from_provider(r"\Device\UnknownVolume\state.sqlite", ())
        with self.assertRaises(screen._EtwMalformedEvent):
            screen._etw_path_from_provider(r"relative\state.sqlite", ())

    def test_screen_does_not_launch_without_ready_observer(self) -> None:
        observer = screen.WindowsEtwFileWriteObserver()
        with mock.patch.object(screen, "_launch_coordinator", side_effect=AssertionError("screen launch must be gated")):
            result = screen.run_falsification_screen(observer=observer)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "observer_unavailable")
        self.assertEqual(result["completed_samples"], 0)
        self.assertEqual(result["observer_status"], "observer_unavailable")
        self.assertEqual(result["disk_gate"], "observer_unavailable")

    def test_main_screen_failure_returns_nonzero_and_preserves_json(self) -> None:
        failed = screen.build_test_aggregate(completed_samples=0, error_code="observer_unavailable")
        output = io.StringIO()
        with mock.patch.object(screen, "run_falsification_screen", return_value=failed) as run_screen, redirect_stdout(output):
            code = screen.main(["--screen"])
        self.assertEqual(code, 1)
        run_screen.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue()), failed)

    def test_main_screen_complete_aggregate_returns_zero(self) -> None:
        warmup = self._timed_sample()
        timings = tuple(self._timed_sample(index + 1) for index in range(5))
        complete = screen.build_test_aggregate(completed_samples=5, timings=timings, warmup=warmup, observer_status="observer_ready", disk_gate="disk_gate_pass")
        output = io.StringIO()
        with mock.patch.object(screen, "run_falsification_screen", return_value=complete) as run_screen, redirect_stdout(output):
            code = screen.main(["--screen"])
        self.assertEqual(code, 0)
        run_screen.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue()), complete)

    def test_observer_capability_loss_and_lineage_fail_closed(self) -> None:
        observer = screen.WindowsEtwFileWriteObserver(_Backend(capability=(True, True, True, False)))
        self.assertEqual(observer.probe().status, "observer_unavailable")
        with tempfile.TemporaryDirectory(prefix="profile11-observer-") as directory:
            root = Path(directory)
            result = screen.FileWriteObservation("observer_ready", True, True, True, True)
            self.assertEqual(screen.evaluate_disk_gate(result, state_workspace=root), "observer_incomplete")
            result = screen.FileWriteObservation("observer_ready", True, True, False, False)
            self.assertEqual(screen.evaluate_disk_gate(result, state_workspace=root), "observer_incomplete")

    def test_disk_allowlist_allows_configured_state_durability_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="profile11-disk-") as directory:
            root = Path(directory)
            events = tuple(screen.FileWriteEvent(path, op, 100 + index) for index, (path, op) in enumerate((
                (root / "state.sqlite", "write"),
                (root / "state.sqlite-journal", "create"),
                (root / "state.sqlite-journal", "delete"),
                (root / "state.sqlite.runtime-lock", "write"),
                (root, "directory_metadata"),
            )))
            ready = screen.FileWriteObservation("observer_ready", True, True, True, False, events)
            self.assertEqual(screen.evaluate_disk_gate(ready, state_workspace=root), "disk_gate_pass")
            forbidden = screen.FileWriteObservation("observer_ready", True, True, True, False, (screen.FileWriteEvent(root / "deleted-proof.tmp", "delete", 101),))
            self.assertEqual(screen.evaluate_disk_gate(forbidden, state_workspace=root), "unauthorized_write")
            nonconfigured = screen.FileWriteObservation("observer_ready", True, True, True, False, (screen.FileWriteEvent(root / "state.sqlite-wal", "write", 101),))
            self.assertEqual(screen.evaluate_disk_gate(nonconfigured, state_workspace=root), "unauthorized_write")
            for filename in (
                "proof.bin", "signature.bin", "frame.bin", "statement.bin", "digest.bin", "phi.bin",
                "temp.tmp", "spill.bin", "stdout.log", "stderr.log", "crash.dmp", "core",
            ):
                for operation in ("create", "write", "rename", "delete"):
                    with self.subTest(filename=filename, operation=operation):
                        event = screen.FileWriteEvent(root / filename, operation, 101)
                        self.assertEqual(
                            screen.evaluate_disk_gate(screen.FileWriteObservation("observer_ready", True, True, True, False, (event,)), state_workspace=root),
                            "unauthorized_write",
                        )

    def test_observer_backend_stop_loss_becomes_incomplete(self) -> None:
        backend = _Backend(result=screen.FileWriteObservation("observer_ready", True, True, True, True))
        observer = screen.WindowsEtwFileWriteObserver(backend)
        with tempfile.TemporaryDirectory(prefix="profile11-observer-") as directory:
            started = observer.start(1234)
            self.assertEqual(started.status, "observer_ready")
            self.assertEqual(backend.started_with, 1234)
            stopped = observer.stop()
            self.assertEqual(stopped.status, "observer_incomplete")

    def test_measurement_schedule_is_one_warmup_and_five_measured(self) -> None:
        calls = 0
        def sample() -> screen.StageSample:
            nonlocal calls
            calls += 1
            return screen.StageSample(float(calls), float(calls + 1), float(calls + 2), float(calls + 3))
        schedule = screen.run_measurement_schedule_with_warmup(sample)
        self.assertEqual(calls, 6)
        self.assertEqual(schedule.warmup, screen.StageSample(1.0, 2.0, 3.0, 4.0))
        values = schedule.measured
        self.assertEqual(len(values), 5)
        p95 = screen.nearest_rank_p95(values)
        self.assertEqual(p95, screen.StageSample(6.0, 7.0, 8.0, 9.0))

    def test_measurement_schedule_does_not_silently_skip(self) -> None:
        calls = 0
        def sample():
            nonlocal calls
            calls += 1
            return None if calls == 4 else screen.StageSample(1.0, 1.0, 1.0, 1.0)
        with self.assertRaisesRegex(screen.CompletePathError, "sample_shape"):
            screen.run_measurement_schedule(sample)
        self.assertEqual(calls, 4)

    def test_aggregate_is_zero_phi_and_nonactivating(self) -> None:
        warmup = self._timed_sample()
        timings = tuple(self._timed_sample(index + 1) for index in range(5))
        value = screen.build_test_aggregate(completed_samples=5, timings=timings, warmup=warmup, peak_job_commit_bytes=1024, effective_cap_bytes=screen.effective_outer_cap(screen.PROCESS_TREE_PEAK_CAP_BYTES, 4096), peak_active_processes=2, total_processes=7)
        encoded = screen._aggregate_json(value)
        self.assertNotIn("statement", encoded.lower())
        self.assertNotIn("operation_ref", encoded.lower())
        self.assertNotIn("stdout", encoded.lower())
        self.assertIsNone(value["proofSuiteId"])
        self.assertFalse(value["production_usable"])
        self.assertFalse(value["activation"])
        self.assertEqual(value["proof_count"], 1)
        self.assertEqual(value["operation_count"], 100)
        self.assertEqual(value["warmup_count"], 1)
        self.assertEqual(len(value["verify_state_substages_ms"]), 5)
        self.assertEqual(value["p95_verify_state_substages_ms"]["handoff"], 6.0)

    def test_verifier_timing_wrapper_restores_and_records_inclusive_scope(self) -> None:
        timing = screen._VerifierTiming()
        with mock.patch.object(source_auth_adapter, "_read_exact_frame", lambda *args, **kwargs: bytearray(b"frame")), mock.patch.object(source_auth_adapter, "_build_ipc_input", lambda *args, **kwargs: bytearray(b"ipc")), mock.patch.object(source_auth_adapter, "run_contained_verifier_stream", lambda *args, **kwargs: "result"):
            patched_read = source_auth_adapter._read_exact_frame
            with screen._timed_verifier_functions(timing):
                self.assertEqual(source_auth_adapter._read_exact_frame(None), bytearray(b"frame"))
                self.assertEqual(source_auth_adapter._build_ipc_input(None), bytearray(b"ipc"))
                self.assertEqual(source_auth_adapter.run_contained_verifier_stream(None), "result")
            self.assertIs(source_auth_adapter._read_exact_frame, patched_read)
        self.assertIsNotNone(timing.verifier_finished_at)
        self.assertGreaterEqual(timing.frame_read_ms, 0.0)
        self.assertGreaterEqual(timing.ipc_prepare_ms, 0.0)
        self.assertGreaterEqual(timing.contained_verifier_ms, 0.0)

    def test_aggregate_rejects_unreconciled_timing(self) -> None:
        value = screen.build_test_aggregate(completed_samples=5, timings=tuple(self._timed_sample(index + 1) for index in range(5)), warmup=self._timed_sample())
        value["verify_state_substages_ms"][0]["unbucketed"] += 1.0
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_timing_reconciliation"):
            screen._validate_aggregate_mapping(value)
        value = screen.build_test_aggregate(completed_samples=5, timings=tuple(self._timed_sample(index + 1) for index in range(5)), warmup=self._timed_sample())
        value["p95_timings_ms"]["total"] += 1.0
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_p95"):
            screen._validate_aggregate_mapping(value)

    def test_aggregate_rejects_sensitive_or_wrong_shape_fields(self) -> None:
        value = screen.build_test_aggregate()
        value["unexpected"] = 1
        with self.assertRaisesRegex(screen.CompletePathError, "aggregate_fields"):
            screen._validate_aggregate_mapping(value)
        value = screen.build_test_aggregate()
        value["proof_count"] = 2
        with self.assertRaisesRegex(screen.CompletePathError, "topology_mismatch"):
            screen._validate_aggregate_mapping(value)


if __name__ == "__main__":
    unittest.main()
