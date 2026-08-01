"""Measured synthetic C0 boundaries for Gate 2E-0.

The measurement boundary is intentionally separate from the canonical C0
fixture manifest.  It records one fresh Windows process for either the
state-only reference or the complete fixture build; timing and process
resource values therefore never change the semantic fixture identity.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import asdict, dataclass
from hashlib import sha3_512
import json
import os
import sys
import time
from typing import Final

from experiments.bl_pq512_crypto_foundation import c0_control_fixture as c0
from experiments.fixed_shape_claim_air.profile import CalibrationProfile, PROFILES


STATUS: Final[str] = "C0_BOUNDARY_MEASUREMENT_V1_SYNTHETIC_NONPRODUCTION"
SCHEMA_VERSION: Final[str] = "blind-ledger-c0-boundary-measurement-v1"
BOUNDARIES: Final[tuple[str, ...]] = ("state-only", "complete")
MEASURED_PROFILES: Final[tuple[str, ...]] = (
    "K128_CALIBRATION",
    "K512_CALIBRATION",
)


class _ProcessMemoryCountersEx(ctypes.Structure):
    if sys.platform == "win32":
        from ctypes import wintypes

        _fields_ = (
            ("cb", wintypes.DWORD),
            ("page_fault_count", wintypes.DWORD),
            ("peak_working_set_size", ctypes.c_size_t),
            ("working_set_size", ctypes.c_size_t),
            ("quota_peak_paged_pool_usage", ctypes.c_size_t),
            ("quota_paged_pool_usage", ctypes.c_size_t),
            ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
            ("quota_non_paged_pool_usage", ctypes.c_size_t),
            ("pagefile_usage", ctypes.c_size_t),
            ("peak_pagefile_usage", ctypes.c_size_t),
            ("private_usage", ctypes.c_size_t),
        )


class _ProcessIoCounters(ctypes.Structure):
    _fields_ = (
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    )


@dataclass(frozen=True, slots=True)
class _ProcessSnapshot:
    peak_working_set_bytes: int
    pagefile_usage_bytes: int
    read_operations: int
    write_operations: int
    read_bytes: int
    write_bytes: int


@dataclass(frozen=True, slots=True)
class C0BoundaryMeasurement:
    status: str
    schema_version: str
    profile_id: str
    boundary: str
    result_length: int
    result_sha3_512_hex: str
    measured_seconds: str
    peak_rss_bytes: int
    scratch_bytes: int
    pagefile_growth_bytes: int
    io_read_operations: int
    io_write_operations: int
    io_read_bytes: int
    io_write_bytes: int
    scratch_policy: str
    evidence_class: str
    production_usable: bool

    def __post_init__(self) -> None:
        if self.status != STATUS or self.schema_version != SCHEMA_VERSION:
            raise ValueError("c0_measurement_identity_invalid")
        if self.profile_id not in MEASURED_PROFILES:
            raise ValueError("c0_measurement_profile_invalid")
        if self.boundary not in BOUNDARIES:
            raise ValueError("c0_measurement_boundary_invalid")
        if type(self.result_length) is not int or self.result_length <= 0:
            raise ValueError("c0_measurement_result_length_invalid")
        if len(self.result_sha3_512_hex) != 128:
            raise ValueError("c0_measurement_result_identity_invalid")
        for field_name in (
            "peak_rss_bytes",
            "scratch_bytes",
            "pagefile_growth_bytes",
            "io_read_operations",
            "io_write_operations",
            "io_read_bytes",
            "io_write_bytes",
        ):
            if type(getattr(self, field_name)) is not int or getattr(self, field_name) < 0:
                raise ValueError(f"c0_measurement_{field_name}_invalid")
        if self.scratch_policy != "no_fixture_scratch_api":
            raise ValueError("c0_measurement_scratch_policy_invalid")
        if self.evidence_class != "C0_ONE_FRESH_PROCESS_MEASURED_NONQUALIFYING":
            raise ValueError("c0_measurement_evidence_class_invalid")
        if self.production_usable is not False:
            raise ValueError("c0_measurement_production_must_remain_false")

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.update(
            {
                "peak_rss_decimal_mb": f"{self.peak_rss_bytes / 1_000_000:.6f}",
                "scratch_decimal_mb": f"{self.scratch_bytes / 1_000_000:.6f}",
                "pagefile_growth_decimal_mb": f"{self.pagefile_growth_bytes / 1_000_000:.6f}",
                "io_read_decimal_mb": f"{self.io_read_bytes / 1_000_000:.6f}",
                "io_write_decimal_mb": f"{self.io_write_bytes / 1_000_000:.6f}",
            }
        )
        return value


def _process_snapshot() -> _ProcessSnapshot:
    if sys.platform != "win32":
        raise RuntimeError("c0_measurement_windows_required")
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessIoCounters.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ProcessIoCounters),
    )
    kernel32.GetProcessIoCounters.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ProcessMemoryCountersEx),
        wintypes.DWORD,
    )
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel32.GetCurrentProcess()

    memory = _ProcessMemoryCountersEx()
    memory.cb = ctypes.sizeof(memory)
    if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    io = _ProcessIoCounters()
    if not kernel32.GetProcessIoCounters(handle, ctypes.byref(io)):
        raise ctypes.WinError(ctypes.get_last_error())
    return _ProcessSnapshot(
        int(memory.peak_working_set_size),
        int(memory.pagefile_usage),
        int(io.read_operation_count),
        int(io.write_operation_count),
        int(io.read_transfer_count),
        int(io.write_transfer_count),
    )


def _nonnegative_delta(after: int, before: int) -> int:
    return max(0, after - before)


def _state_only_artifact(profile: CalibrationProfile) -> bytes:
    """Return the canonical state-only result without claim/receipt projection."""

    _, replay_batch, replay_result = c0._replay_fixture(profile)
    payment_before, payment_after, payment, payment_maps = c0._payment_fixture(profile)
    payload = {
        "status": c0.STATUS,
        "schema_version": c0.SCHEMA_VERSION,
        "profile_id": profile.profile_id,
        "state_root_before_hex": c0._sha3(
            c0._STATE_DOMAIN + payment_before.root() + replay_batch.root_before
        ).hex(),
        "state_root_after_hex": c0._sha3(
            c0._STATE_DOMAIN + payment_after.root() + replay_batch.root_after
        ).hex(),
        "map_results": [
            replay_result.as_dict(),
            *(value.as_dict() for value in payment_maps),
        ],
        "payment": payment.as_dict(),
    }
    return c0._canonical_json(payload)


def _complete_artifact(profile: CalibrationProfile) -> bytes:
    return c0.build_c0_control_fixture(profile).manifest_bytes


def measure_c0_boundary(profile: CalibrationProfile, boundary: str) -> C0BoundaryMeasurement:
    """Measure one explicit boundary in the current process.

    The caller must launch a fresh process for each profile/boundary pair.  The
    process-level peak working set is intentionally reported as observed, not
    normalized or projected.
    """

    if type(profile) is not CalibrationProfile or profile.profile_id not in MEASURED_PROFILES:
        raise ValueError("c0_measurement_profile_not_governed")
    if boundary not in BOUNDARIES:
        raise ValueError("c0_measurement_boundary_unknown")
    if (
        os.environ.get("BL_ENV") != "test"
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE") != "1"
    ):
        raise RuntimeError("c0_measurement_requires_explicit_synthetic_environment")

    before = _process_snapshot()
    started = time.perf_counter_ns()
    result = (
        _state_only_artifact(profile)
        if boundary == "state-only"
        else _complete_artifact(profile)
    )
    elapsed_ns = time.perf_counter_ns() - started
    after = _process_snapshot()
    return C0BoundaryMeasurement(
        STATUS,
        SCHEMA_VERSION,
        profile.profile_id,
        boundary,
        len(result),
        sha3_512(result).hexdigest(),
        f"{elapsed_ns / 1_000_000_000:.6f}",
        after.peak_working_set_bytes,
        0,
        _nonnegative_delta(after.pagefile_usage_bytes, before.pagefile_usage_bytes),
        _nonnegative_delta(after.read_operations, before.read_operations),
        _nonnegative_delta(after.write_operations, before.write_operations),
        _nonnegative_delta(after.read_bytes, before.read_bytes),
        _nonnegative_delta(after.write_bytes, before.write_bytes),
        "no_fixture_scratch_api",
        "C0_ONE_FRESH_PROCESS_MEASURED_NONQUALIFYING",
        False,
    )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=MEASURED_PROFILES, required=True)
    parser.add_argument("--boundary", choices=BOUNDARIES, required=True)
    args = parser.parse_args(argv)
    record = measure_c0_boundary(PROFILES[args.profile], args.boundary)
    print(json.dumps(record.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = (
    "BOUNDARIES",
    "C0BoundaryMeasurement",
    "MEASURED_PROFILES",
    "SCHEMA_VERSION",
    "STATUS",
    "measure_c0_boundary",
)
