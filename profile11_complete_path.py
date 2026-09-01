"""Profile 11 complete-path containment and falsification screen.

This is a test-only coordinator.  The parent process creates the coordinator
suspended, assigns it to one outer Windows Job, and resumes it only after the
assignment succeeds.  The coordinator owns the volatile source frame and
Queue/State transaction; it emits only a fixed aggregate after every
sensitive buffer is closed or wiped.  No production, activation, or complete
zero-PHI observation claim is made here.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Final, Iterable, Protocol
import uuid

import app.minimal_clearance_composition as composition
import app.minimal_clearance_source_auth_verifier_adapter as source_auth_adapter
from app.minimal_clearance_composition import (
    ClearanceCompositionStoreV2,
    StateDispositionControl,
    build_synthetic_acknowledgment,
)
from app.minimal_clearance_resource_limits import (
    ADMISSION_CAP_BYTES,
    PROCESS_TREE_PEAK_CAP_BYTES,
)
from app.minimal_clearance_source_auth_verifier_adapter import (
    ML_DSA_87_PUBLIC_KEY_BYTES,
    SOURCE_AUTH_EXECUTABLE_SHA256,
    SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
    SourceAuthVerifierConfig,
)
from app.minimal_clearance_verification_queue import (
    IssuedVerificationBatch,
    OperationTemplate,
    QueueConfig,
    VolatileProofHandoff,
    _build_statement,
    _compute_batch_root_from_refs,
)
from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime
from profile11_source_boundary import (
    Profile11SourceBoundaryCaller,
    SourceApplianceConfig,
    SOURCE_APPLIANCE_EXECUTABLE_SHA256,
    SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES,
    SOURCE_AUTH_FRAME_BYTES,
    SOURCE_AUTH_OPERATION_COUNT,
)


PROFILE_ID: Final[str] = "BLIND-ZKBPP-RANGE100-CDG-DIRECT-SEEDED-V1"
PROFILE_SCHEMA: Final[str] = "BL/NATIVE-V3/PROFILE11-COMPLETE-PATH/v1"
MANIFEST_PATH: Final[Path] = Path(__file__).with_name("profile11_complete_path_manifest.json")

SOURCE_REPO: Final[Path] = Path(
    r"C:\Users\neers\Documents\Codex\2026-09-01\blind-profile11-source-transaction-v1"
)
SOURCE_HEAD: Final[str] = "0538862de4b7580bf0a5613ee8f86d71de032cf8"
SOURCE_TREE: Final[str] = "fa18bfd8aec72643ad1d494c63fdbe1ede5245de"

PRODUCER_REPO: Final[Path] = Path(
    r"C:\Users\neers\Documents\Codex\2026-08-31\blind-zkbpp-range100-profile11-seeded-v1"
)
PRODUCER_HEAD: Final[str] = "2bfabac2738d546e75063fd77081cbfd8ff604b3"
PRODUCER_TREE: Final[str] = "9689987cf6854c7553f5792c9d6f15bddf13446a"
PRODUCER_EXECUTABLE: Final[Path] = PRODUCER_REPO / "target" / "release" / "blind_range100_prove_cdg_direct.exe"
PRODUCER_EXECUTABLE_SIZE_BYTES: Final[int] = 423_936
PRODUCER_EXECUTABLE_SHA256: Final[str] = "C4BD6BC6D5399149010E100D5F9737412F4CC5EF6AAAC2B187486BE0DEEBFB4E"

C_REPO: Final[Path] = Path(
    r"C:\Users\neers\Documents\Codex\2026-08-31\blind-zkbpp-c-profile11-extmu-v1"
)
C_HEAD: Final[str] = "9ca1ba2ccb6fa78384e3c3e21cfd3dfd0cb38eb2"
C_TREE: Final[str] = "178a5f20c6738f7272cd38f77315da83650bbac0"

QUEUE_REPO: Final[Path] = Path(
    r"C:\Users\neers\Documents\Codex\2026-08-31\blind-queue-profile11-outbox-batch-v1"
)
QUEUE_HEAD: Final[str] = "412b53e68091561657106345a22a772699761945"
QUEUE_TREE: Final[str] = "72746eb68e667698fdb0a72c8aea7c9bf027076a"

SOURCE_HOST: Final[Path] = Path(__file__).parent / "experiments" / "profile11_source_host" / "target" / "release" / "profile11_source_host.exe"
SOURCE_HOST_SIZE_BYTES: Final[int] = 480_768
SOURCE_HOST_SHA256: Final[bytes] = bytes.fromhex(
    "3D2C0A468303E68AA63B2A6A52BA922422231695D589ED1562E4F1CA3A8F5562"
)

C_BUILD: Final[Path] = Path(
    r"C:\Users\neers\Documents\Codex\2026-09-01\blind-zkbpp-c-profile11-extmu-v1-prod-msvc\Release"
)
C_SOURCE_LIBRARY: Final[Path] = C_BUILD / "blind_source_auth_v1.lib"
C_SOURCE_LIBRARY_SIZE_BYTES: Final[int] = 152_624
C_SOURCE_LIBRARY_SHA256: Final[str] = "D4F5FD22F80CB1ECA9BAEF944E18F5427AB6F8192BB210278D69EBBB05B28841"
C_RANGE_LIBRARY: Final[Path] = C_BUILD / "blind_range100_cdg_direct_v1.lib"
C_RANGE_LIBRARY_SIZE_BYTES: Final[int] = 109_342
C_RANGE_LIBRARY_SHA256: Final[str] = "1B190B727D612CCC53C37E211BDC04C7BB1EA971D9E694FDD9B97C67549A7C30"
C_VERIFIER: Final[Path] = Path(
    r"C:\Users\neers\Documents\Codex\2026-08-31\build-profile11-throughput-v1\Release\blind_source_auth_verify_process_v1.exe"
)

OUTER_HARD_CAP_BYTES: Final[int] = 5_000_000_000
OUTER_ACTIVE_PROCESS_LIMIT: Final[int] = 8
COORDINATOR_TIMEOUT_SECONDS: Final[float] = 240.0
COORDINATOR_STDOUT_CAP_BYTES: Final[int] = 256 * 1024
COORDINATOR_STDERR_CAP_BYTES: Final[int] = 4 * 1024
MEASURED_SAMPLE_COUNT: Final[int] = 5
WARMUP_SAMPLE_COUNT: Final[int] = 1
PRODUCT_TARGET_MS: Final[float] = 35_000.0
TIMING_RECONCILIATION_TOLERANCE_MS: Final[float] = 0.01
SOURCE_KEY_EPOCH: Final[int] = 0x0102_0304_0506_0708
PUBLIC_KEY_BYTES: Final[int] = ML_DSA_87_PUBLIC_KEY_BYTES
PUBLIC_KEY_SHA256: Final[str] = "3D1F0F47DF60B4E2F31F82A99E32B42776837D974CF798CCFDAD98D617026F32"
AGGREGATE_ERROR_CODES: Final[frozenset[str]] = frozenset({
    "dependency_unavailable", "coordinator_failure", "coordinator_output",
    "coordinator_stderr", "coordinator_output_cap", "coordinator_output_read",
    "coordinator_output_close", "outer_timeout", "outer_job_assign",
    "outer_observer_start", "probe_only",
    "observer_unavailable", "observer_incomplete", "unauthorized_write",
})

FIXED_QUALIFICATION_FLAGS: Final[tuple[str, ...]] = (
    "nonactivating",
    "synthetic_receiver",
    "synthetic_source_authority",
    "timing_memory_only",
)
FORBIDDEN_AGGREGATE_WORDS: Final[tuple[str, ...]] = (
    "statement", "operation_ref", "proof", "frame", "key", "signature",
    "seed", "witness", "nonce", "tape", "phi", "path", "stdout", "stderr",
    "digest", "raw", "source_identity",
)


class CompletePathError(RuntimeError):
    """Fixed, non-sensitive preparation/screen failure."""


def _fixed(code: str) -> None:
    error = CompletePathError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _wipe(value: bytearray | None) -> None:
    if value is None:
        return
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
    except (OSError, ValueError):
        _fixed("dependency_read")
    return digest.hexdigest().upper()


@dataclass(frozen=True, slots=True)
class FilePin:
    code: str
    path: Path
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class GitPin:
    code: str
    path: Path
    head: str
    tree: str


@dataclass(frozen=True, slots=True)
class DependencyReport:
    missing: tuple[str, ...]
    mismatched: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return not self.missing and not self.mismatched

    @property
    def failure_count(self) -> int:
        return len(self.missing) + len(self.mismatched)


def _file_pins() -> tuple[FilePin, ...]:
    return (
        FilePin("producer_executable", PRODUCER_EXECUTABLE, PRODUCER_EXECUTABLE_SIZE_BYTES, PRODUCER_EXECUTABLE_SHA256),
        FilePin("source_host", SOURCE_HOST, SOURCE_HOST_SIZE_BYTES, SOURCE_HOST_SHA256.hex().upper()),
        FilePin("c_verifier", C_VERIFIER, SOURCE_AUTH_EXECUTABLE_SIZE_BYTES, SOURCE_AUTH_EXECUTABLE_SHA256.hex().upper()),
        FilePin("c_source_library", C_SOURCE_LIBRARY, C_SOURCE_LIBRARY_SIZE_BYTES, C_SOURCE_LIBRARY_SHA256),
        FilePin("c_range_library", C_RANGE_LIBRARY, C_RANGE_LIBRARY_SIZE_BYTES, C_RANGE_LIBRARY_SHA256),
    )


def _git_pins() -> tuple[GitPin, ...]:
    return (
        GitPin("producer_repo", PRODUCER_REPO, PRODUCER_HEAD, PRODUCER_TREE),
        GitPin("source_repo", SOURCE_REPO, SOURCE_HEAD, SOURCE_TREE),
        GitPin("c_repo", C_REPO, C_HEAD, C_TREE),
        GitPin("queue_repo", QUEUE_REPO, QUEUE_HEAD, QUEUE_TREE),
    )


def _check_file_pin(pin: FilePin, missing: list[str], mismatched: list[str]) -> None:
    if not pin.path.is_file() or pin.path.is_symlink():
        missing.append(pin.code)
        return
    try:
        size = pin.path.stat().st_size
    except OSError:
        missing.append(pin.code)
        return
    if size != pin.size_bytes or _sha256_file(pin.path) != pin.sha256:
        mismatched.append(pin.code)


def _run_git(path: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), *args],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _check_git_pin(pin: GitPin, missing: list[str], mismatched: list[str]) -> None:
    if not pin.path.is_dir():
        missing.append(pin.code)
        return
    head = _run_git(pin.path, "rev-parse", "HEAD")
    tree = _run_git(pin.path, "rev-parse", "HEAD^{tree}")
    status = _run_git(pin.path, "status", "--short")
    if head is None or tree is None or status is None:
        mismatched.append(pin.code)
        return
    if head != pin.head or tree != pin.tree or status != "":
        mismatched.append(pin.code)


def _load_synthetic_public_key() -> bytes:
    """Load the already-used test fixture without placing key bytes on disk."""

    try:
        from tests.test_profile11_source_boundary import SOURCE_TEST_PUBLIC_KEY
        value = bytes(SOURCE_TEST_PUBLIC_KEY)
    except BaseException:
        _fixed("public_key_missing")
    if len(value) != PUBLIC_KEY_BYTES or hashlib.sha256(value).hexdigest().upper() != PUBLIC_KEY_SHA256:
        _fixed("public_key_identity")
    return value


def _check_workspace(path: Path | None, code: str, missing: list[str], mismatched: list[str]) -> None:
    if path is None:
        missing.append(code)
        return
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        missing.append(code)
        return
    try:
        entries = tuple(path.iterdir())
    except OSError:
        mismatched.append(code)
        return
    if entries:
        mismatched.append(code)


def validate_dependencies(
    *,
    source_workspace: Path | None = None,
    verifier_workspace: Path | None = None,
    state_workspace: Path | None = None,
) -> DependencyReport:
    missing: list[str] = []
    mismatched: list[str] = []
    for pin in _file_pins():
        _check_file_pin(pin, missing, mismatched)
    for pin in _git_pins():
        _check_git_pin(pin, missing, mismatched)
    try:
        _load_synthetic_public_key()
    except CompletePathError as error:
        mismatched.append(str(error))
    _check_workspace(source_workspace, "source_workspace", missing, mismatched)
    _check_workspace(verifier_workspace, "verifier_workspace", missing, mismatched)
    _check_workspace(state_workspace, "state_workspace", missing, mismatched)
    return DependencyReport(tuple(missing), tuple(mismatched))


def effective_outer_cap(requested: int, page_size: int) -> int:
    if type(requested) is not int or requested <= 0 or requested >= OUTER_HARD_CAP_BYTES:
        _fixed("outer_cap_invalid")
    if type(page_size) is not int or page_size <= 0 or page_size & (page_size - 1):
        _fixed("outer_page_size")
    effective = requested - requested % page_size
    if effective <= 0 or effective >= OUTER_HARD_CAP_BYTES:
        _fixed("outer_cap_invalid")
    return effective


@dataclass(frozen=True, slots=True)
class JobObservation:
    peak_job_commit_bytes: int
    requested_cap_bytes: int
    effective_cap_bytes: int
    cap_readback_bytes: int
    active_process_limit: int
    active_process_limit_readback: int
    peak_active_processes: int
    total_processes: int
    process_tree_complete: bool
    measurement_complete: bool
    cleanup_complete: bool
    timed_out: bool = False


def validate_job_observation(observation: JobObservation) -> None:
    values = (
        observation.peak_job_commit_bytes,
        observation.requested_cap_bytes,
        observation.effective_cap_bytes,
        observation.cap_readback_bytes,
        observation.active_process_limit,
        observation.active_process_limit_readback,
        observation.peak_active_processes,
        observation.total_processes,
    )
    if any(type(value) is not int or value < 0 for value in values):
        _fixed("outer_observation_shape")
    if observation.requested_cap_bytes >= OUTER_HARD_CAP_BYTES:
        _fixed("outer_cap_invalid")
    if observation.cap_readback_bytes != observation.effective_cap_bytes:
        _fixed("outer_cap_readback")
    if observation.active_process_limit_readback != observation.active_process_limit:
        _fixed("outer_process_limit_readback")
    if observation.peak_job_commit_bytes >= OUTER_HARD_CAP_BYTES or observation.peak_job_commit_bytes > observation.effective_cap_bytes:
        _fixed("outer_memory_cap")
    if observation.total_processes < 1 or observation.peak_active_processes < 1:
        _fixed("outer_process_lineage")
    if observation.timed_out:
        _fixed("outer_timeout")
    if observation.process_tree_complete is not True or observation.measurement_complete is not True or observation.cleanup_complete is not True:
        _fixed("outer_cleanup")


_ETW_ERROR_SUCCESS: Final[int] = 0
_ETW_ERROR_INSUFFICIENT_BUFFER: Final[int] = 122
_ETW_ERROR_CTX_CLOSE_PENDING: Final[int] = 592
_ETW_INVALID_PROCESS_TRACE_HANDLE: Final[int] = (1 << 64) - 1
_ETW_PROCESS_TRACE_MODE_REAL_TIME: Final[int] = 0x00000100
_ETW_PROCESS_TRACE_MODE_EVENT_RECORD: Final[int] = 0x10000000
_ETW_EVENT_TRACE_REAL_TIME_MODE: Final[int] = 0x00000100
_ETW_EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING: Final[int] = 0x10000000
_ETW_WNODE_FLAG_TRACED_GUID: Final[int] = 0x00020000
_ETW_EVENT_CONTROL_ENABLE: Final[int] = 1
_ETW_EVENT_CONTROL_CAPTURE_STATE: Final[int] = 2
_ETW_EVENT_CONTROL_FLUSH: Final[int] = 3
_ETW_EVENT_CONTROL_STOP: Final[int] = 1
_ETW_TRACE_LEVEL_VERBOSE: Final[int] = 5
_ETW_ENABLE_PROPERTY_PROCESS_START_KEY: Final[int] = 0x00000080
_ETW_EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY: Final[int] = 0x000D
_ETW_TOKEN_QUERY: Final[int] = 0x0008
_ETW_TOKEN_PRIVILEGES: Final[int] = 3
_ETW_SE_PRIVILEGE_ENABLED: Final[int] = 0x00000002
_ETW_PROCESS_QUERY_LIMITED_INFORMATION: Final[int] = 0x00001000
_ETW_KERNEL_FILE_PROVIDER_GUID: Final[bytes] = uuid.UUID("edd08927-9cc4-4e65-b970-c2560fb5c289").bytes_le
_ETW_KERNEL_PROCESS_PROVIDER_GUID: Final[bytes] = uuid.UUID("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716").bytes_le
_ETW_LEGACY_FILE_CLASS_GUID: Final[bytes] = uuid.UUID("90cbdc39-4a3e-11d1-84f4-0000f80464e3").bytes_le
_ETW_LEGACY_PROCESS_CLASS_GUID: Final[bytes] = uuid.UUID("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c").bytes_le

_ETW_TDH_INTYPE_UNICODESTRING: Final[int] = 1
_ETW_TDH_INTYPE_UINT32: Final[int] = 8
_ETW_TDH_INTYPE_UINT64: Final[int] = 10
_ETW_TDH_INTYPE_POINTER: Final[int] = 16
_ETW_TDH_INTYPE_FILETIME: Final[int] = 17
_ETW_PROPERTY_STRUCT: Final[int] = 0x1
_ETW_ROOT_CAPTURE_TIMEOUT_SECONDS: Final[float] = 5.0

_ETW_FILE_MUTATION_OPERATIONS: Final[frozenset[str]] = frozenset({
    "write", "create", "delete", "rename", "link", "metadata", "flush", "fsctl",
})
_ETW_FILE_NONMUTATION_IDS: Final[frozenset[int]] = frozenset({10, 11, 12, 13, 14, 15, 20, 22, 24, 25, 32, 34})
_ETW_FILE_MUTATION_IDS: Final[frozenset[int]] = frozenset({16, 17, 18, 19, 21, 23, 26, 27, 28, 29, 30, 31, 33})
_ETW_FILE_TASK_OPERATIONS: Final[dict[int, str]] = {
    16: "write",
    17: "metadata",
    18: "delete",
    19: "rename",
    21: "flush",
    23: "fsctl",
    26: "delete",
    27: "rename",
    28: "link",
    29: "link",
    30: "create",
    31: "metadata",
    33: "metadata",
}
_ETW_FILE_TASKS_IGNORED: Final[frozenset[int]] = _ETW_FILE_NONMUTATION_IDS
_ETW_PROCESS_START_TASKS: Final[frozenset[int]] = frozenset({1, 15})
_ETW_PROCESS_STOP_TASKS: Final[frozenset[int]] = frozenset({2})


@dataclass(frozen=True, slots=True)
class _EtwEventSchemaSpec:
    provider: bytes
    event_id: int
    versions: frozenset[int]
    task: int
    opcode: int
    properties: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class _EtwSchemaFact:
    provider: bytes
    event_id: int
    version: int
    task: int
    opcode: int
    properties: tuple[tuple[str, int], ...]


def _etw_file_spec(event_id: int, versions: frozenset[int], task: int, properties: tuple[tuple[str, int], ...] = ()) -> _EtwEventSchemaSpec:
    return _EtwEventSchemaSpec(_ETW_KERNEL_FILE_PROVIDER_GUID, event_id, versions, task, 0, properties)


def _etw_process_spec(event_id: int, versions: frozenset[int], task: int, opcode: int, properties: tuple[tuple[str, int], ...]) -> _EtwEventSchemaSpec:
    return _EtwEventSchemaSpec(_ETW_KERNEL_PROCESS_PROVIDER_GUID, event_id, versions, task, opcode, properties)


_PTR: Final[int] = _ETW_TDH_INTYPE_POINTER
_U32: Final[int] = _ETW_TDH_INTYPE_UINT32
_U64: Final[int] = _ETW_TDH_INTYPE_UINT64
_TEXT: Final[int] = _ETW_TDH_INTYPE_UNICODESTRING
_TIME: Final[int] = _ETW_TDH_INTYPE_FILETIME
_FILE_OBJECT_KEY: Final[tuple[tuple[str, int], ...]] = (("FileObject", _PTR), ("FileKey", _PTR))
_FILE_IRP_KEY: Final[tuple[tuple[str, int], ...]] = _FILE_OBJECT_KEY + (("Irp", _PTR),)
_INFO_PROPERTIES: Final[tuple[tuple[str, int], ...]] = _FILE_IRP_KEY + (("ExtraInformation", _PTR), ("InfoClass", _U32))
_PATH_PROPERTIES: Final[tuple[tuple[str, int], ...]] = _FILE_IRP_KEY + (("ExtraInformation", _PTR), ("InfoClass", _U32), ("FilePath", _TEXT))
_CREATE_PROPERTIES: Final[tuple[tuple[str, int], ...]] = (("FileObject", _PTR), ("FileName", _TEXT), ("CreateOptions", _U32), ("CreateAttributes", _U32), ("ShareAccess", _U32))
_NAME_PROPERTIES: Final[tuple[tuple[str, int], ...]] = (("FileKey", _PTR), ("FileName", _TEXT))
_END_PROPERTIES: Final[tuple[tuple[str, int], ...]] = (("Irp", _PTR), ("ExtraInformation", _PTR), ("Status", _U32))

_ETW_FILE_SCHEMA_SPECS: Final[dict[tuple[int, int], _EtwEventSchemaSpec]] = {
    (10, 0): _etw_file_spec(10, frozenset({0}), 10, _NAME_PROPERTIES),
    (11, 0): _etw_file_spec(11, frozenset({0}), 11, _NAME_PROPERTIES),
    (12, 0): _etw_file_spec(12, frozenset({0, 1}), 12, _CREATE_PROPERTIES),
    (13, 0): _etw_file_spec(13, frozenset({0, 1}), 13, _FILE_OBJECT_KEY),
    (14, 0): _etw_file_spec(14, frozenset({0, 1}), 14, _FILE_OBJECT_KEY),
    (15, 0): _etw_file_spec(15, frozenset({0, 1}), 15, _FILE_OBJECT_KEY),
    (16, 0): _etw_file_spec(16, frozenset({0, 1}), 16, _FILE_IRP_KEY + (("ByteOffset", _U64), ("IOSize", _U32), ("IOFlags", _U32))),
    (17, 0): _etw_file_spec(17, frozenset({0, 1}), 17, _INFO_PROPERTIES),
    (18, 0): _etw_file_spec(18, frozenset({0, 1}), 18, _INFO_PROPERTIES),
    (19, 0): _etw_file_spec(19, frozenset({0, 1}), 19, _INFO_PROPERTIES),
    (20, 0): _etw_file_spec(20, frozenset({0, 1}), 20, _FILE_OBJECT_KEY + (("Length", _U32), ("InfoClass", _U32), ("FileIndex", _U32), ("FileName", _TEXT))),
    (21, 0): _etw_file_spec(21, frozenset({0, 1}), 21, _FILE_OBJECT_KEY),
    (22, 0): _etw_file_spec(22, frozenset({0, 1}), 22),
    (23, 0): _etw_file_spec(23, frozenset({0, 1}), 23, _INFO_PROPERTIES),
    (24, 0): _etw_file_spec(24, frozenset({0}), 24, _END_PROPERTIES),
    (25, 0): _etw_file_spec(25, frozenset({0, 1}), 25, _FILE_OBJECT_KEY + (("Length", _U32), ("InfoClass", _U32), ("FileIndex", _U32), ("FileName", _TEXT))),
    (26, 0): _etw_file_spec(26, frozenset({0, 1}), 26, _PATH_PROPERTIES),
    (27, 0): _etw_file_spec(27, frozenset({0, 1}), 27, _PATH_PROPERTIES),
    (28, 0): _etw_file_spec(28, frozenset({0, 1}), 28, _PATH_PROPERTIES),
    (29, 0): _etw_file_spec(29, frozenset({0, 1}), 19, _INFO_PROPERTIES),
    (30, 0): _etw_file_spec(30, frozenset({0, 1}), 30, _CREATE_PROPERTIES),
    (31, 0): _etw_file_spec(31, frozenset({1}), 31, _INFO_PROPERTIES),
    (32, 0): _etw_file_spec(32, frozenset({1}), 32),
    (33, 0): _etw_file_spec(33, frozenset({1}), 33, _INFO_PROPERTIES),
    (34, 0): _etw_file_spec(34, frozenset({1}), 34),
}
_ETW_PROCESS_SCHEMA_SPECS: Final[dict[tuple[int, int], _EtwEventSchemaSpec]] = {
    (1, 0): _etw_process_spec(1, frozenset({0, 1, 2, 3, 4}), 1, 1, (("ProcessID", _U32), ("CreateTime", _TIME), ("ParentProcessID", _U32))),
    (2, 0): _etw_process_spec(2, frozenset({0, 1, 2}), 2, 2, (("ProcessID", _U32), ("CreateTime", _TIME))),
    (15, 0): _etw_process_spec(15, frozenset({0, 1, 2}), 15, 0, (("ProcessID", _U32), ("CreateTime", _TIME), ("ParentProcessID", _U32))),
}
_ETW_SCHEMA_SPECS: Final[tuple[_EtwEventSchemaSpec, ...]] = tuple(_ETW_FILE_SCHEMA_SPECS.values()) + tuple(_ETW_PROCESS_SCHEMA_SPECS.values())
_ETW_SCHEMA_BY_PROVIDER_ID: Final[dict[tuple[bytes, int], _EtwEventSchemaSpec]] = {
    (spec.provider, spec.event_id): spec for spec in _ETW_SCHEMA_SPECS
}
_ETW_SCHEMA_KEYS: Final[frozenset[tuple[bytes, int, int]]] = frozenset(
    (spec.provider, spec.event_id, version)
    for spec in _ETW_SCHEMA_SPECS
    for version in spec.versions
)

_FILE_IO_V0: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("ThreadId", _PTR), ("FileObject", _PTR), ("FileKey", _PTR),
)
_FILE_IO_V1: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("FileObject", _PTR), ("FileKey", _PTR), ("IssuingThreadId", _U32),
)
_FILE_CREATE_V0: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("ThreadId", _PTR), ("FileObject", _PTR),
    ("CreateOptions", _U32), ("CreateAttributes", _U32), ("ShareAccess", _U32), ("FileName", _TEXT),
)
_FILE_CREATE_V1: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("FileObject", _PTR), ("IssuingThreadId", _U32),
    ("CreateOptions", _U32), ("CreateAttributes", _U32), ("ShareAccess", _U32), ("FileName", _TEXT),
)
_FILE_READ_WRITE_V0: Final[tuple[tuple[str, int], ...]] = (
    ("ByteOffset", _U64), ("Irp", _PTR), ("ThreadId", _PTR), ("FileObject", _PTR), ("FileKey", _PTR),
    ("IOSize", _U32), ("IOFlags", _U32),
)
_FILE_READ_WRITE_V1: Final[tuple[tuple[str, int], ...]] = (
    ("ByteOffset", _U64), ("Irp", _PTR), ("FileObject", _PTR), ("FileKey", _PTR),
    ("IssuingThreadId", _U32), ("IOSize", _U32), ("IOFlags", _U32), ("ExtraFlags", _U32),
)
_FILE_INFO_V0: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("ThreadId", _PTR), ("FileObject", _PTR), ("FileKey", _PTR),
    ("ExtraInformation", _PTR), ("InfoClass", _U32),
)
_FILE_INFO_V1: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("FileObject", _PTR), ("FileKey", _PTR), ("ExtraInformation", _PTR),
    ("IssuingThreadId", _U32), ("InfoClass", _U32),
)
_FILE_DIRECTORY_V0: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("ThreadId", _PTR), ("FileObject", _PTR), ("FileKey", _PTR),
    ("Length", _U32), ("InfoClass", _U32), ("FileIndex", _U32), ("FileName", _TEXT),
)
_FILE_DIRECTORY_V1: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("FileObject", _PTR), ("FileKey", _PTR), ("IssuingThreadId", _U32),
    ("Length", _U32), ("InfoClass", _U32), ("FileIndex", _U32), ("FileName", _TEXT),
)
_FILE_PATH_V0: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("ThreadId", _PTR), ("FileObject", _PTR), ("FileKey", _PTR),
    ("ExtraInformation", _PTR), ("InfoClass", _U32), ("FilePath", _TEXT),
)
_FILE_PATH_V1: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("FileObject", _PTR), ("FileKey", _PTR), ("ExtraInformation", _PTR),
    ("IssuingThreadId", _U32), ("InfoClass", _U32), ("FilePath", _TEXT),
)
_FILE_OPERATION_END: Final[tuple[tuple[str, int], ...]] = (
    ("Irp", _PTR), ("ExtraInformation", _PTR), ("Status", _U32),
)

_ETW_FILE_SCHEMA_PROPERTIES: Final[dict[tuple[int, int], tuple[tuple[str, int], ...]]] = {
    (10, 0): _NAME_PROPERTIES, (11, 0): _NAME_PROPERTIES,
    (12, 0): _FILE_CREATE_V0, (12, 1): _FILE_CREATE_V1,
    (13, 0): _FILE_IO_V0, (13, 1): _FILE_IO_V1,
    (14, 0): _FILE_IO_V0, (14, 1): _FILE_IO_V1,
    (15, 0): _FILE_READ_WRITE_V0, (15, 1): _FILE_READ_WRITE_V1,
    (16, 0): _FILE_READ_WRITE_V0, (16, 1): _FILE_READ_WRITE_V1,
    (17, 0): _FILE_INFO_V0, (17, 1): _FILE_INFO_V1,
    (18, 0): _FILE_INFO_V0, (18, 1): _FILE_INFO_V1,
    (19, 0): _FILE_INFO_V0, (19, 1): _FILE_INFO_V1,
    (20, 0): _FILE_DIRECTORY_V0, (20, 1): _FILE_DIRECTORY_V1,
    (21, 0): _FILE_IO_V0, (21, 1): _FILE_IO_V1,
    (22, 0): _FILE_INFO_V0, (22, 1): _FILE_INFO_V1,
    (23, 0): _FILE_INFO_V0, (23, 1): _FILE_INFO_V1,
    (24, 0): _FILE_OPERATION_END,
    (25, 0): _FILE_DIRECTORY_V0, (25, 1): _FILE_DIRECTORY_V1,
    (26, 0): _FILE_PATH_V0, (26, 1): _FILE_PATH_V1,
    (27, 0): _FILE_PATH_V0, (27, 1): _FILE_PATH_V1,
    (28, 0): _FILE_PATH_V0, (28, 1): _FILE_PATH_V1,
    (29, 0): _FILE_INFO_V0, (29, 1): _FILE_INFO_V1,
    (30, 0): _FILE_CREATE_V0, (30, 1): _FILE_CREATE_V1,
    (31, 1): _FILE_INFO_V1, (32, 1): _FILE_INFO_V1,
    (33, 1): _FILE_INFO_V1, (34, 1): _FILE_INFO_V1,
}

_PROCESS_START_V0: Final[tuple[tuple[str, int], ...]] = (
    ("ProcessID", _U32), ("CreateTime", _TIME), ("ParentProcessID", _U32), ("SessionID", _U32), ("ImageName", _TEXT),
)
_PROCESS_START_V1: Final[tuple[tuple[str, int], ...]] = _PROCESS_START_V0[:-1] + (("Flags", _U32), ("ImageName", _TEXT))
_PROCESS_START_V2: Final[tuple[tuple[str, int], ...]] = _PROCESS_START_V1 + (
    ("ImageChecksum", _U32), ("TimeDateStamp", _U32), ("PackageFullName", _TEXT), ("PackageRelativeAppId", _TEXT),
)
_PROCESS_START_V3: Final[tuple[tuple[str, int], ...]] = (
    ("ProcessID", _U32), ("ProcessSequenceNumber", _U64), ("CreateTime", _TIME),
    ("ParentProcessID", _U32), ("ParentProcessSequenceNumber", _U64), ("SessionID", _U32),
    ("Flags", _U32), ("ProcessTokenElevationType", _U32), ("ProcessTokenIsElevated", _U32),
    ("MandatoryLabel", 19), ("ImageName", _TEXT), ("ImageChecksum", _U32), ("TimeDateStamp", _U32),
    ("PackageFullName", _TEXT), ("PackageRelativeAppId", _TEXT),
)
_PROCESS_START_V4: Final[tuple[tuple[str, int], ...]] = _PROCESS_START_V3 + (("SecurityMitigations", _U32),)
_PROCESS_STOP_V0: Final[tuple[tuple[str, int], ...]] = (
    ("ProcessID", _U32), ("CreateTime", _TIME), ("ExitTime", _TIME), ("ExitCode", _U32),
    ("TokenElevationType", _U32), ("HandleCount", _U32), ("CommitCharge", _U64), ("CommitPeak", _U64), ("ImageName", 2),
)
_PROCESS_STOP_V1: Final[tuple[tuple[str, int], ...]] = _PROCESS_STOP_V0[:-1] + (
    ("CPUCycleCount", _U64), ("ReadOperationCount", _U32), ("WriteOperationCount", _U32),
    ("ReadTransferKiloBytes", _U32), ("WriteTransferKiloBytes", _U32), ("HardFaultCount", _U32), ("ImageName", 2),
)
_PROCESS_STOP_V2: Final[tuple[tuple[str, int], ...]] = (
    ("ProcessID", _U32), ("ProcessSequenceNumber", _U64),
) + _PROCESS_STOP_V1[1:]
_PROCESS_RUNDOWN_V0: Final[tuple[tuple[str, int], ...]] = (
    ("ProcessID", _U32), ("CreateTime", _TIME), ("ParentProcessID", _U32), ("SessionID", _U32),
    ("Flags", _U32), ("ImageName", _TEXT), ("ImageChecksum", _U32), ("TimeDateStamp", _U32),
    ("PackageFullName", _TEXT), ("PackageRelativeAppId", _TEXT),
)
_PROCESS_RUNDOWN_V1: Final[tuple[tuple[str, int], ...]] = (
    ("ProcessID", _U32), ("ProcessSequenceNumber", _U64), ("CreateTime", _TIME),
    ("ParentProcessID", _U32), ("ParentProcessSequenceNumber", _U64), ("SessionID", _U32),
    ("Flags", _U32), ("ProcessTokenElevationType", _U32), ("ProcessTokenIsElevated", _U32),
    ("MandatoryLabel", 19), ("ImageName", _TEXT), ("ImageChecksum", _U32), ("TimeDateStamp", _U32),
    ("PackageFullName", _TEXT), ("PackageRelativeAppId", _TEXT),
)
_PROCESS_RUNDOWN_V2: Final[tuple[tuple[str, int], ...]] = _PROCESS_RUNDOWN_V1 + (("SecurityMitigations", _U32),)

_ETW_PROCESS_SCHEMA_PROPERTIES: Final[dict[tuple[int, int], tuple[tuple[str, int], ...]]] = {
    (1, 0): _PROCESS_START_V0, (1, 1): _PROCESS_START_V1, (1, 2): _PROCESS_START_V2,
    (1, 3): _PROCESS_START_V3, (1, 4): _PROCESS_START_V4,
    (2, 0): _PROCESS_STOP_V0, (2, 1): _PROCESS_STOP_V1, (2, 2): _PROCESS_STOP_V2,
    (15, 0): _PROCESS_RUNDOWN_V0, (15, 1): _PROCESS_RUNDOWN_V1, (15, 2): _PROCESS_RUNDOWN_V2,
}
_ETW_SCHEMA_PROPERTIES: Final[dict[tuple[bytes, int, int], tuple[tuple[str, int], ...]]] = {
    (_ETW_KERNEL_FILE_PROVIDER_GUID, event_id, version): properties
    for (event_id, version), properties in _ETW_FILE_SCHEMA_PROPERTIES.items()
} | {
    (_ETW_KERNEL_PROCESS_PROVIDER_GUID, event_id, version): properties
    for (event_id, version), properties in _ETW_PROCESS_SCHEMA_PROPERTIES.items()
}


def _etw_schema_fact_matches(fact: _EtwSchemaFact) -> bool:
    if type(fact) is not _EtwSchemaFact:
        return False
    spec = _ETW_SCHEMA_BY_PROVIDER_ID.get((fact.provider, fact.event_id))
    if spec is None or fact.version not in spec.versions or fact.task != spec.task or fact.opcode != spec.opcode:
        return False
    expected = _ETW_SCHEMA_PROPERTIES.get((fact.provider, fact.event_id, fact.version))
    if expected is None or tuple(fact.properties) != expected:
        return False
    return True


def _etw_schema_facts_complete(facts: Iterable[_EtwSchemaFact]) -> bool:
    values = tuple(facts)
    keys = tuple((fact.provider, fact.event_id, fact.version) for fact in values if type(fact) is _EtwSchemaFact)
    if len(keys) != len(values) or len(set(keys)) != len(keys) or frozenset(keys) != _ETW_SCHEMA_KEYS:
        return False
    return all(_etw_schema_fact_matches(fact) for fact in values)


class _EtwGuid(ctypes.Structure):
    _fields_ = (
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    )


class _EtwWnodeHeader(ctypes.Structure):
    _fields_ = (
        ("BufferSize", ctypes.c_ulong),
        ("ProviderId", ctypes.c_ulong),
        ("HistoricalContext", ctypes.c_ulonglong),
        ("TimeStamp", ctypes.c_longlong),
        ("Guid", _EtwGuid),
        ("ClientContext", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
    )


class _EtwEventTraceProperties(ctypes.Structure):
    _fields_ = (
        ("Wnode", _EtwWnodeHeader),
        ("BufferSize", ctypes.c_ulong),
        ("MinimumBuffers", ctypes.c_ulong),
        ("MaximumBuffers", ctypes.c_ulong),
        ("MaximumFileSize", ctypes.c_ulong),
        ("LogFileMode", ctypes.c_ulong),
        ("FlushTimer", ctypes.c_ulong),
        ("EnableFlags", ctypes.c_ulong),
        ("FlushThreshold", ctypes.c_long),
        ("NumberOfBuffers", ctypes.c_ulong),
        ("FreeBuffers", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("BuffersWritten", ctypes.c_ulong),
        ("LogBuffersLost", ctypes.c_ulong),
        ("RealTimeBuffersLost", ctypes.c_ulong),
        ("LoggerThreadId", ctypes.c_void_p),
        ("LogFileNameOffset", ctypes.c_ulong),
        ("LoggerNameOffset", ctypes.c_ulong),
    )


class _EtwEventDescriptor(ctypes.Structure):
    _fields_ = (
        ("Id", ctypes.c_ushort),
        ("Version", ctypes.c_ubyte),
        ("Channel", ctypes.c_ubyte),
        ("Level", ctypes.c_ubyte),
        ("Opcode", ctypes.c_ubyte),
        ("Task", ctypes.c_ushort),
        ("Keyword", ctypes.c_ulonglong),
    )


class _EtwEventHeader(ctypes.Structure):
    _fields_ = (
        ("Size", ctypes.c_ushort),
        ("HeaderType", ctypes.c_ushort),
        ("Flags", ctypes.c_ushort),
        ("EventProperty", ctypes.c_ushort),
        ("ThreadId", ctypes.c_ulong),
        ("ProcessId", ctypes.c_ulong),
        ("TimeStamp", ctypes.c_longlong),
        ("ProviderId", _EtwGuid),
        ("EventDescriptor", _EtwEventDescriptor),
        ("ProcessorTime", ctypes.c_ulonglong),
        ("ActivityId", _EtwGuid),
    )


class _EtwBufferContext(ctypes.Structure):
    _fields_ = (("ProcessorNumber", ctypes.c_ubyte), ("Alignment", ctypes.c_ubyte), ("LoggerId", ctypes.c_ushort))


class _EtwEventHeaderExtendedDataItem(ctypes.Structure):
    _fields_ = (
        ("Reserved1", ctypes.c_ushort),
        ("ExtType", ctypes.c_ushort),
        ("LinkageAndReserved", ctypes.c_ushort),
        ("DataSize", ctypes.c_ushort),
        ("DataPtr", ctypes.c_ulonglong),
    )


class _EtwEventRecord(ctypes.Structure):
    _fields_ = (
        ("EventHeader", _EtwEventHeader),
        ("BufferContext", _EtwBufferContext),
        ("ExtendedDataCount", ctypes.c_ushort),
        ("UserDataLength", ctypes.c_ushort),
        ("ExtendedData", ctypes.POINTER(_EtwEventHeaderExtendedDataItem)),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    )


class _EtwEventPropertyNonStruct(ctypes.Structure):
    _fields_ = (
        ("InType", ctypes.c_ushort),
        ("OutType", ctypes.c_ushort),
        ("MapNameOffset", ctypes.c_ulong),
    )


class _EtwEventPropertyStruct(ctypes.Structure):
    _fields_ = (
        ("StructStartIndex", ctypes.c_ushort),
        ("NumOfStructMembers", ctypes.c_ushort),
        ("Padding", ctypes.c_ulong),
    )


class _EtwEventPropertyUnion(ctypes.Union):
    _fields_ = (
        ("nonStructType", _EtwEventPropertyNonStruct),
        ("structType", _EtwEventPropertyStruct),
    )


class _EtwEventPropertyInfo(ctypes.Structure):
    _fields_ = (
        ("Flags", ctypes.c_ulong),
        ("NameOffset", ctypes.c_ulong),
        ("Type", _EtwEventPropertyUnion),
        ("Count", ctypes.c_ushort),
        ("Length", ctypes.c_ushort),
        ("Reserved", ctypes.c_ulong),
    )


class _EtwTraceEventInfoHeader(ctypes.Structure):
    _fields_ = (
        ("ProviderGuid", _EtwGuid),
        ("EventGuid", _EtwGuid),
        ("EventDescriptor", _EtwEventDescriptor),
        ("DecodingSource", ctypes.c_ulong),
        ("ProviderNameOffset", ctypes.c_ulong),
        ("LevelNameOffset", ctypes.c_ulong),
        ("ChannelNameOffset", ctypes.c_ulong),
        ("KeywordsNameOffset", ctypes.c_ulong),
        ("TaskNameOffset", ctypes.c_ulong),
        ("OpcodeNameOffset", ctypes.c_ulong),
        ("EventMessageOffset", ctypes.c_ulong),
        ("ProviderMessageOffset", ctypes.c_ulong),
        ("BinaryXMLOffset", ctypes.c_ulong),
        ("BinaryXMLSize", ctypes.c_ulong),
        ("EventNameOffset", ctypes.c_ulong),
        ("EventAttributesOffset", ctypes.c_ulong),
        ("PropertyCount", ctypes.c_ulong),
        ("TopLevelPropertyCount", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
    )


class _EtwEventTraceHeader(ctypes.Structure):
    _fields_ = (
        ("Size", ctypes.c_ushort),
        ("FieldTypeFlags", ctypes.c_ushort),
        ("Version", ctypes.c_ulong),
        ("ThreadId", ctypes.c_ulong),
        ("ProcessId", ctypes.c_ulong),
        ("TimeStamp", ctypes.c_longlong),
        ("Guid", _EtwGuid),
        ("ProcessorTime", ctypes.c_ulonglong),
    )


class _EtwEventTrace(ctypes.Structure):
    _fields_ = (
        ("Header", _EtwEventTraceHeader),
        ("InstanceId", ctypes.c_ulong),
        ("ParentInstanceId", ctypes.c_ulong),
        ("ParentGuid", _EtwGuid),
        ("MofData", ctypes.c_void_p),
        ("MofLength", ctypes.c_ulong),
        ("ClientContext", ctypes.c_ulong),
    )


class _EtwTimeZoneInformation(ctypes.Structure):
    _fields_ = (
        ("Bias", ctypes.c_long),
        ("StandardName", ctypes.c_ushort * 32),
        ("StandardDate", ctypes.c_ushort * 8),
        ("StandardBias", ctypes.c_long),
        ("DaylightName", ctypes.c_ushort * 32),
        ("DaylightDate", ctypes.c_ushort * 8),
        ("DaylightBias", ctypes.c_long),
    )


class _EtwTraceLogfileHeader(ctypes.Structure):
    _fields_ = (
        ("BufferSize", ctypes.c_ulong),
        ("Version", ctypes.c_ulong),
        ("ProviderVersion", ctypes.c_ulong),
        ("NumberOfProcessors", ctypes.c_ulong),
        ("EndTime", ctypes.c_longlong),
        ("TimerResolution", ctypes.c_ulong),
        ("MaximumFileSize", ctypes.c_ulong),
        ("LogFileMode", ctypes.c_ulong),
        ("BuffersWritten", ctypes.c_ulong),
        ("LogInstanceGuid", _EtwGuid),
        ("LoggerName", ctypes.c_void_p),
        ("LogFileName", ctypes.c_void_p),
        ("TimeZone", _EtwTimeZoneInformation),
        ("BootTime", ctypes.c_longlong),
        ("PerfFreq", ctypes.c_longlong),
        ("StartTime", ctypes.c_longlong),
        ("ReservedFlags", ctypes.c_ulong),
        ("BuffersLost", ctypes.c_ulong),
    )


class _EtwEventTraceLogfileW(ctypes.Structure):
    _fields_ = (
        ("LogFileName", ctypes.c_void_p),
        ("LoggerName", ctypes.c_void_p),
        ("CurrentTime", ctypes.c_longlong),
        ("BuffersRead", ctypes.c_ulong),
        ("ProcessTraceMode", ctypes.c_ulong),
        ("CurrentEvent", _EtwEventTrace),
        ("LogfileHeader", _EtwTraceLogfileHeader),
        ("BufferCallback", ctypes.c_void_p),
        ("BufferSize", ctypes.c_ulong),
        ("Filled", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("EventRecordCallback", ctypes.c_void_p),
        ("IsKernelTrace", ctypes.c_ulong),
        ("Context", ctypes.c_void_p),
    )


class _EtwEnableTraceParameters(ctypes.Structure):
    _fields_ = (
        ("Version", ctypes.c_ulong),
        ("EnableProperty", ctypes.c_ulong),
        ("ControlFlags", ctypes.c_ulong),
        ("SourceId", _EtwGuid),
        ("EnableFilterDesc", ctypes.c_void_p),
        ("FilterDescCount", ctypes.c_ulong),
    )


class _EtwPropertyDataDescriptor(ctypes.Structure):
    _fields_ = (
        ("PropertyName", ctypes.c_ulonglong),
        ("ArrayIndex", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
    )


class _EtwLuid(ctypes.Structure):
    _fields_ = (("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long))


class _EtwSidIdentifierAuthority(ctypes.Structure):
    _fields_ = (("Value", ctypes.c_ubyte * 6),)


def _etw_bounded_wstring(storage: ctypes.Array[ctypes.c_char], offset: int) -> str:
    size = len(storage)
    if type(offset) is not int or offset <= 0 or offset >= size or offset % 2:
        raise _EtwMalformedEvent()
    raw = ctypes.string_at(ctypes.addressof(storage) + offset, size - offset)
    end = None
    for index in range(0, len(raw) - 1, 2):
        if raw[index:index + 2] == b"\x00\x00":
            end = index
            break
    if end is None:
        raise _EtwMalformedEvent()
    try:
        return raw[:end].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as error:
        raise _EtwMalformedEvent() from error


class _EtwWindowsApi:
    """Small ctypes binding; it never supplies a logfile path to ETW."""

    def __init__(self) -> None:
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.tdh = ctypes.WinDLL("tdh", use_last_error=True)
        self._configure()

    def _configure(self) -> None:
        self.advapi32.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_wchar_p, ctypes.POINTER(_EtwEventTraceProperties)]
        self.advapi32.StartTraceW.restype = ctypes.c_ulong
        self.advapi32.ControlTraceW.argtypes = [ctypes.c_ulonglong, ctypes.c_wchar_p, ctypes.POINTER(_EtwEventTraceProperties), ctypes.c_ulong]
        self.advapi32.ControlTraceW.restype = ctypes.c_ulong
        self.advapi32.EnableTraceEx2.argtypes = [ctypes.c_ulonglong, ctypes.POINTER(_EtwGuid), ctypes.c_ulong, ctypes.c_ubyte, ctypes.c_ulonglong, ctypes.c_ulonglong, ctypes.c_ulong, ctypes.POINTER(_EtwEnableTraceParameters)]
        self.advapi32.EnableTraceEx2.restype = ctypes.c_ulong
        self.advapi32.OpenTraceW.argtypes = [ctypes.POINTER(_EtwEventTraceLogfileW)]
        self.advapi32.OpenTraceW.restype = ctypes.c_ulonglong
        self.advapi32.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
        self.advapi32.ProcessTrace.restype = ctypes.c_ulong
        self.advapi32.CloseTrace.argtypes = [ctypes.c_ulonglong]
        self.advapi32.CloseTrace.restype = ctypes.c_ulong
        self.tdh.TdhEnumerateProviders.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        self.tdh.TdhEnumerateProviders.restype = ctypes.c_ulong
        self.tdh.TdhGetPropertySize.argtypes = [ctypes.POINTER(_EtwEventRecord), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(_EtwPropertyDataDescriptor), ctypes.POINTER(ctypes.c_ulong)]
        self.tdh.TdhGetPropertySize.restype = ctypes.c_ulong
        self.tdh.TdhGetProperty.argtypes = [ctypes.POINTER(_EtwEventRecord), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(_EtwPropertyDataDescriptor), ctypes.c_ulong, ctypes.c_void_p]
        self.tdh.TdhGetProperty.restype = ctypes.c_ulong
        self.tdh.TdhGetEventInformation.argtypes = [ctypes.POINTER(_EtwEventRecord), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        self.tdh.TdhGetEventInformation.restype = ctypes.c_ulong
        self.kernel32.OpenProcess.argtypes = [ctypes.c_ulong, wintypes.BOOL, ctypes.c_ulong]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
        self.kernel32.GetProcessTimes.restype = wintypes.BOOL
        self.kernel32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        self.kernel32.IsProcessInJob.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.GetCurrentProcess.argtypes = []
        self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel32.QueryDosDeviceW.argtypes = [ctypes.c_wchar_p, wintypes.LPWSTR, ctypes.c_ulong]
        self.kernel32.QueryDosDeviceW.restype = ctypes.c_ulong
        self.advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.POINTER(wintypes.HANDLE)]
        self.advapi32.OpenProcessToken.restype = wintypes.BOOL
        self.advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        self.advapi32.GetTokenInformation.restype = wintypes.BOOL
        self.advapi32.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(_EtwLuid)]
        self.advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
        self.advapi32.AllocateAndInitializeSid.argtypes = [ctypes.POINTER(_EtwSidIdentifierAuthority), ctypes.c_ubyte, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
        self.advapi32.AllocateAndInitializeSid.restype = wintypes.BOOL
        self.advapi32.CheckTokenMembership.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]
        self.advapi32.CheckTokenMembership.restype = wintypes.BOOL
        self.advapi32.FreeSid.argtypes = [ctypes.c_void_p]
        self.advapi32.FreeSid.restype = ctypes.c_void_p

    def providers(self) -> frozenset[bytes]:
        size = ctypes.c_ulong(0)
        status = int(self.tdh.TdhEnumerateProviders(None, ctypes.byref(size)))
        if status != _ETW_ERROR_INSUFFICIENT_BUFFER or size.value < 8 or size.value > 16 * 1024 * 1024:
            return frozenset()
        storage = ctypes.create_string_buffer(size.value)
        status = int(self.tdh.TdhEnumerateProviders(storage, ctypes.byref(size)))
        if status != _ETW_ERROR_SUCCESS:
            return frozenset()
        raw = bytes(storage)
        count = int.from_bytes(raw[:4], "little")
        if count > 100_000 or 8 + count * 24 > len(raw):
            return frozenset()
        return frozenset(raw[8 + index * 24:8 + index * 24 + 16] for index in range(count))

    def event_schema(self, record: _EtwEventRecord) -> _EtwSchemaFact:
        size = ctypes.c_ulong(0)
        status = int(self.tdh.TdhGetEventInformation(ctypes.byref(record), 0, None, None, ctypes.byref(size)))
        if status != _ETW_ERROR_INSUFFICIENT_BUFFER or size.value < ctypes.sizeof(_EtwTraceEventInfoHeader) or size.value > 4 * 1024 * 1024:
            raise _EtwMalformedEvent()
        storage = ctypes.create_string_buffer(size.value)
        status = int(self.tdh.TdhGetEventInformation(ctypes.byref(record), 0, None, storage, ctypes.byref(size)))
        if status != _ETW_ERROR_SUCCESS:
            raise _EtwMalformedEvent()
        info = ctypes.cast(storage, ctypes.POINTER(_EtwTraceEventInfoHeader)).contents
        header = record.EventHeader
        descriptor = info.EventDescriptor
        if bytes(info.ProviderGuid) != bytes(header.ProviderId):
            raise _EtwMalformedEvent()
        if (int(descriptor.Id), int(descriptor.Version), int(descriptor.Task), int(descriptor.Opcode)) != (
            int(header.EventDescriptor.Id), int(header.EventDescriptor.Version), int(header.EventDescriptor.Task), int(header.EventDescriptor.Opcode),
        ):
            raise _EtwMalformedEvent()
        count = int(info.PropertyCount)
        property_size = ctypes.sizeof(_EtwEventPropertyInfo)
        if count < 0 or count > 1024 or ctypes.sizeof(_EtwTraceEventInfoHeader) + count * property_size > len(storage):
            raise _EtwMalformedEvent()
        array_address = ctypes.addressof(storage) + ctypes.sizeof(_EtwTraceEventInfoHeader)
        array = ctypes.cast(array_address, ctypes.POINTER(_EtwEventPropertyInfo))
        properties: list[tuple[str, int]] = []
        for index in range(count):
            property_info = array[index]
            name = _etw_bounded_wstring(storage, int(property_info.NameOffset))
            if not name or any(existing == name for existing, _ in properties):
                raise _EtwMalformedEvent()
            if int(property_info.Flags) & _ETW_PROPERTY_STRUCT:
                property_type = -1
            else:
                property_type = int(property_info.Type.nonStructType.InType)
            properties.append((name, property_type))
        return _EtwSchemaFact(
            bytes(header.ProviderId),
            int(header.EventDescriptor.Id),
            int(header.EventDescriptor.Version),
            int(header.EventDescriptor.Task),
            int(header.EventDescriptor.Opcode),
            tuple(properties),
        )

    def installed_schema_facts(self) -> tuple[_EtwSchemaFact, ...]:
        facts: list[_EtwSchemaFact] = []
        for provider, properties_by_event in (
            (_ETW_KERNEL_FILE_PROVIDER_GUID, _ETW_FILE_SCHEMA_PROPERTIES),
            (_ETW_KERNEL_PROCESS_PROVIDER_GUID, _ETW_PROCESS_SCHEMA_PROPERTIES),
        ):
            for event_id, version in sorted(properties_by_event):
                spec = _ETW_SCHEMA_BY_PROVIDER_ID[(provider, event_id)]
                record = _EtwEventRecord()
                record.EventHeader.ProviderId = _EtwGuid.from_buffer_copy(provider)
                record.EventHeader.EventDescriptor = _EtwEventDescriptor(
                    event_id, version, 16, 4, spec.opcode, spec.task, 0,
                )
                facts.append(self.event_schema(record))
        return tuple(facts)

    def has_builtin_alias(self, rid: int) -> bool:
        authority = _EtwSidIdentifierAuthority((0, 0, 0, 0, 0, 5))
        sid = ctypes.c_void_p()
        if not self.advapi32.AllocateAndInitializeSid(ctypes.byref(authority), 2, 32, rid, 0, 0, 0, 0, 0, 0, ctypes.byref(sid)):
            return False
        try:
            member = wintypes.BOOL(False)
            return bool(self.advapi32.CheckTokenMembership(None, sid, ctypes.byref(member)) and member.value)
        finally:
            self.advapi32.FreeSid(sid)

    def has_enabled_profile_privilege(self) -> bool:
        token = wintypes.HANDLE()
        if not self.advapi32.OpenProcessToken(self.kernel32.GetCurrentProcess(), _ETW_TOKEN_QUERY, ctypes.byref(token)):
            return False
        try:
            size = ctypes.c_ulong(0)
            self.advapi32.GetTokenInformation(token, _ETW_TOKEN_PRIVILEGES, None, 0, ctypes.byref(size))
            if not size.value or size.value > 1024 * 1024:
                return False
            storage = ctypes.create_string_buffer(size.value)
            if not self.advapi32.GetTokenInformation(token, _ETW_TOKEN_PRIVILEGES, storage, size.value, ctypes.byref(size)):
                return False
            target = _EtwLuid()
            if not self.advapi32.LookupPrivilegeValueW(None, "SeSystemProfilePrivilege", ctypes.byref(target)):
                return False
            raw = bytes(storage)
            count = int.from_bytes(raw[:4], "little")
            for index in range(count):
                offset = 4 + index * 12
                if offset + 12 > len(raw):
                    return False
                if raw[offset:offset + 8] == bytes(target) and int.from_bytes(raw[offset + 8:offset + 12], "little") & _ETW_SE_PRIVILEGE_ENABLED:
                    return True
            return False
        finally:
            self.kernel32.CloseHandle(token)

    def root_identity(self, pid: int) -> tuple[int | None, bool]:
        handle = self.kernel32.OpenProcess(_ETW_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None, False
        try:
            creation = wintypes.FILETIME()
            exit_time = wintypes.FILETIME()
            kernel_time = wintypes.FILETIME()
            user_time = wintypes.FILETIME()
            if not self.kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)):
                return None, False
            in_job = wintypes.BOOL(False)
            if not self.kernel32.IsProcessInJob(handle, None, ctypes.byref(in_job)) or not in_job.value:
                return None, False
            value = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
            return value, True
        finally:
            self.kernel32.CloseHandle(handle)

    def device_map(self) -> tuple[tuple[str, str], ...]:
        values: list[tuple[str, str]] = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            target = ctypes.create_unicode_buffer(32_768)
            length = int(self.kernel32.QueryDosDeviceW(f"{letter}:", target, len(target)))
            if length:
                first = target.value.split("\x00", 1)[0]
                if first:
                    values.append((first, f"{letter}:"))
        return tuple(sorted(values, key=lambda item: len(item[0]), reverse=True))


class _EtwMalformedEvent(RuntimeError):
    pass


@dataclass(slots=True)
class _EtwPendingMutation:
    source_path: Path | None = None
    target_path: Path | None = None


class _EtwTraceState:
    """Volatile lineage and file-event state; it has no serialization path."""

    def __init__(self, root_pid: int, root_creation_filetime: int) -> None:
        self.root_pid = root_pid
        self.root_creation_filetime = root_creation_filetime
        self._active: dict[int, int] = {root_pid: 0}
        self._history: dict[int, set[int]] = {root_pid: {0}}
        self._root_key: int | None = None
        self.root_start_seen = False
        self.root_stop_seen = False
        self.root_creation_match = False
        self.root_observed = threading.Event()
        self.malformed = False
        self.loss_detected = False
        self.events: list[FileWriteEvent] = []
        self._file_objects: dict[int, Path] = {}
        self._file_keys: dict[int, Path] = {}
        self.file_names = self._file_keys
        self._pending: dict[tuple[int, int, int, str], _EtwPendingMutation] = {}
        self._completed_pairs: set[tuple[int, int, int, str]] = set()

    def mark_malformed(self) -> None:
        self.malformed = True

    def mark_loss(self) -> None:
        self.loss_detected = True

    def _bind_root_key(self, key: int) -> bool:
        if type(key) is not int or key <= 0:
            self.mark_malformed()
            return False
        if self._root_key is None:
            self._root_key = key
            self._active[self.root_pid] = key
            self._history[self.root_pid].discard(0)
            self._history[self.root_pid].add(key)
            return True
        if self._root_key != key:
            self.mark_malformed()
            return False
        return True

    def actor_is_traced(self, pid: int, key: int) -> bool:
        if type(pid) is not int or pid <= 0 or type(key) is not int or key <= 0:
            self.mark_malformed()
            return False
        active = self._active.get(pid)
        if active is None:
            return False
        if pid == self.root_pid and active == 0:
            return self._bind_root_key(key)
        if active != key:
            self.mark_malformed()
            return False
        return True

    def record_process(self, *, event_id: int, pid: int, key: int, parent_pid: int, create_time: int) -> None:
        if (
            type(event_id) is not int
            or event_id not in _ETW_PROCESS_START_TASKS | _ETW_PROCESS_STOP_TASKS
            or type(pid) is not int
            or pid <= 0
            or type(key) is not int
            or key <= 0
            or type(parent_pid) is not int
            or parent_pid < 0
            or type(create_time) is not int
            or create_time <= 0
        ):
            self.mark_malformed()
            return
        started = event_id in _ETW_PROCESS_START_TASKS
        if pid == self.root_pid:
            if create_time != self.root_creation_filetime:
                self.mark_malformed()
                return
            if not self._bind_root_key(key):
                return
            self.root_creation_match = True
            if started:
                self.root_start_seen = True
                self.root_observed.set()
            else:
                if self._active.get(pid) != key:
                    self.mark_malformed()
                    return
                self._active.pop(pid, None)
                self.root_stop_seen = True
            return
        if started:
            if pid in self._active:
                self.mark_malformed()
                return
            parent_active = self._active.get(parent_pid)
            if parent_active is None:
                parent_history = self._history.get(parent_pid, set())
                parent_history.discard(0)
                if len(parent_history) == 0:
                    return  # unrelated process; no trusted parent edge
                self.mark_malformed()
                return
            if parent_pid <= 0:
                self.mark_malformed()
                return
            if key in self._history.get(pid, set()):
                self.mark_malformed()
                return
            self._active[pid] = key
            self._history.setdefault(pid, set()).add(key)
            return
        active = self._active.get(pid)
        if active is None:
            return
        if active != key:
            self.mark_malformed()
            return
        self._active.pop(pid, None)
        if key not in self._history.get(pid, set()):
            self.mark_malformed()
            return

    @staticmethod
    def _merge_path(existing: Path | None, candidate: Path | None) -> Path | None:
        if existing is not None and candidate is not None and existing != candidate:
            return None
        return existing or candidate

    def update_file_correlation(self, *, file_object: int | None, file_key: int | None, path: Path | None) -> Path | None:
        if (file_object is None and file_key is None) or (file_object is not None and (type(file_object) is not int or file_object <= 0)) or (file_key is not None and (type(file_key) is not int or file_key <= 0)):
            self.mark_malformed()
            return None
        if path is not None and (not isinstance(path, Path) or not path.is_absolute()):
            self.mark_malformed()
            return None
        resolved = path
        for candidate in (
            self._file_objects.get(file_object) if file_object is not None else None,
            self._file_keys.get(file_key) if file_key is not None else None,
        ):
            if resolved is not None and candidate is not None and resolved != candidate:
                self.mark_malformed()
                return None
            if resolved is None:
                resolved = candidate
        if resolved is None:
            self.mark_malformed()
            return None
        if file_object is not None:
            self._file_objects[file_object] = resolved
        if file_key is not None:
            self._file_keys[file_key] = resolved
        return resolved

    def cleanup_file_correlation(self, *, file_object: int | None, file_key: int | None, path: Path | None = None) -> None:
        if file_object is None and file_key is None:
            self.mark_malformed()
            return
        resolved = self.update_file_correlation(file_object=file_object, file_key=file_key, path=path)
        if resolved is None:
            return
        if file_object is not None:
            self._file_objects.pop(file_object, None)
        if file_key is not None:
            self._file_keys.pop(file_key, None)

    def delete_file_name(self, *, file_key: int, path: Path | None = None) -> None:
        if type(file_key) is not int or file_key <= 0:
            self.mark_malformed()
            return
        known = self._file_keys.get(file_key)
        if path is not None and (not isinstance(path, Path) or not path.is_absolute() or (known is not None and known != path)):
            self.mark_malformed()
            return
        self._file_keys.pop(file_key, None)

    def remember_file_name(self, key: int, path: Path) -> None:
        self.update_file_correlation(file_object=None, file_key=key, path=path)

    def record_file(self, *, pid: int, key: int, path: Path, operation: str, source_path: Path | None = None, target_path: Path | None = None) -> None:
        if not self.actor_is_traced(pid, key):
            return
        if operation not in _ETW_FILE_MUTATION_OPERATIONS or not isinstance(path, Path) or not path.is_absolute():
            self.mark_malformed()
            return
        if operation in {"rename", "link"}:
            if source_path is None or target_path is None or not source_path.is_absolute() or not target_path.is_absolute() or path != target_path:
                self.mark_malformed()
                return
        self.events.append(FileWriteEvent(path, operation, pid, True, key, source_path, target_path))

    def record_paired_mutation(self, *, pid: int, key: int, irp: int, operation: str, source_path: Path | None, target_path: Path | None) -> None:
        if not self.actor_is_traced(pid, key) or operation not in {"rename", "link"} or type(irp) is not int or irp <= 0:
            self.mark_malformed()
            return
        if source_path is not None and (not isinstance(source_path, Path) or not source_path.is_absolute()):
            self.mark_malformed()
            return
        if target_path is not None and (not isinstance(target_path, Path) or not target_path.is_absolute()):
            self.mark_malformed()
            return
        pending_key = (pid, key, irp, operation)
        if pending_key in self._completed_pairs:
            self.mark_malformed()
            return
        pending = self._pending.setdefault(pending_key, _EtwPendingMutation())
        merged_source = self._merge_path(pending.source_path, source_path)
        merged_target = self._merge_path(pending.target_path, target_path)
        if (pending.source_path is not None and source_path is not None and merged_source is None) or (pending.target_path is not None and target_path is not None and merged_target is None):
            self.mark_malformed()
            return
        pending.source_path = merged_source
        pending.target_path = merged_target
        if pending.source_path is not None and pending.target_path is not None:
            self.events.append(FileWriteEvent(pending.target_path, operation, pid, True, key, pending.source_path, pending.target_path))
            del self._pending[pending_key]
            self._completed_pairs.add(pending_key)

    def complete_lineage(self) -> bool:
        return (
            not self.malformed
            and not self.loss_detected
            and self.root_start_seen
            and self.root_stop_seen
            and self._root_key is not None
            and not self._active
            and not self._pending
            and not self._file_objects
            and not self._file_keys
        )

    def wipe(self) -> None:
        self._active.clear()
        self._history.clear()
        self._root_key = None
        self._file_objects.clear()
        self._file_keys.clear()
        self._pending.clear()
        self._completed_pairs.clear()
        self.events.clear()
        self.root_start_seen = False
        self.root_stop_seen = False
        self.root_creation_match = False
        self.root_observed.clear()


def _etw_event_task(record: _EtwEventRecord, known: frozenset[int]) -> int | None:
    descriptor = record.EventHeader.EventDescriptor
    event_id = int(descriptor.Id)
    return event_id if event_id in known else None


def _etw_process_start_key(record: _EtwEventRecord) -> int | None:
    count = int(record.ExtendedDataCount)
    pointer = record.ExtendedData
    if count <= 0 or not pointer:
        return None
    found: int | None = None
    for index in range(count):
        item = pointer[index]
        if int(item.ExtType) != _ETW_EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY:
            continue
        if int(item.DataSize) != 8 or not int(item.DataPtr):
            raise _EtwMalformedEvent()
        value = int(ctypes.c_ulonglong.from_address(int(item.DataPtr)).value)
        if value <= 0 or (found is not None and found != value):
            raise _EtwMalformedEvent()
        found = value
    return found


def _etw_property_bytes(api: _EtwWindowsApi, record: _EtwEventRecord, name: str) -> bytes | None:
    name_buffer = ctypes.create_unicode_buffer(name)
    descriptor = _EtwPropertyDataDescriptor(ctypes.cast(name_buffer, ctypes.c_void_p).value or 0, 0, 0)
    size = ctypes.c_ulong(0)
    status = int(api.tdh.TdhGetPropertySize(ctypes.byref(record), 0, None, 1, ctypes.byref(descriptor), ctypes.byref(size)))
    if status != _ETW_ERROR_SUCCESS:
        return None
    if not size.value or size.value > 1_048_576:
        raise _EtwMalformedEvent()
    storage = ctypes.create_string_buffer(size.value)
    status = int(api.tdh.TdhGetProperty(ctypes.byref(record), 0, None, 1, ctypes.byref(descriptor), size.value, storage))
    if status != _ETW_ERROR_SUCCESS:
        raise _EtwMalformedEvent()
    return bytes(storage)


def _etw_property_int(api: _EtwWindowsApi, record: _EtwEventRecord, names: tuple[str, ...]) -> int | None:
    for name in names:
        raw = _etw_property_bytes(api, record, name)
        if raw is None:
            continue
        if len(raw) not in {4, 8}:
            raise _EtwMalformedEvent()
        value = int.from_bytes(raw, "little", signed=False)
        return value if value > 0 else None
    return None


def _etw_property_text(api: _EtwWindowsApi, record: _EtwEventRecord, names: tuple[str, ...]) -> str | None:
    for name in names:
        raw = _etw_property_bytes(api, record, name)
        if raw is None:
            continue
        if len(raw) % 2:
            raise _EtwMalformedEvent()
        try:
            value = raw.decode("utf-16-le", errors="strict").split("\x00", 1)[0]
        except UnicodeDecodeError as error:
            raise _EtwMalformedEvent() from error
        return value or None
    return None


def _etw_path_from_provider(raw: str, devices: tuple[tuple[str, str], ...]) -> Path:
    value = raw.strip()
    if not value:
        raise _EtwMalformedEvent()
    if value.startswith("\\??\\"):
        value = value[4:]
    if value.startswith("\\\\?\\") or (len(value) >= 3 and value[1:3] == ":\\"):
        path = Path(value)
    elif value.casefold().startswith("\\device\\mup\\"):
        path = Path("\\\\" + value[len("\\Device\\Mup\\"):])
    elif value.casefold().startswith("\\device\\"):
        path = None
        folded = value.casefold()
        for device, drive in devices:
            if folded == device.casefold() or folded.startswith(device.casefold() + "\\"):
                path = Path(drive + value[len(device):])
                break
        if path is None:
            raise _EtwMalformedEvent()
    else:
        raise _EtwMalformedEvent()
    if not path.is_absolute():
        raise _EtwMalformedEvent()
    return path


class WindowsEtwWriteTraceBackend:
    """Direct real-time Kernel-File/Kernel-Process ETW consumer.

    The session is memory-backed and real-time only.  It has no ETL/PML/log
    filename and retains only lineage plus relevant paths until ``stop``.
    """

    __slots__ = (
        "_api", "_session_name", "_session_id", "_properties_storage", "_properties",
        "_logger_name", "_trace_handle", "_trace_thread", "_trace_status", "_state",
        "_devices", "_schema_facts", "_event_callback", "_buffer_callback", "_event_callback_c", "_buffer_callback_c",
    )

    def __init__(self, *, schema_facts: Iterable[_EtwSchemaFact] | None = None) -> None:
        self._api: _EtwWindowsApi | None = None
        self._session_name: str | None = None
        self._session_id = 0
        self._properties_storage: ctypes.Array[ctypes.c_char] | None = None
        self._properties: ctypes.POINTER(_EtwEventTraceProperties) | None = None
        self._logger_name: ctypes.Array[ctypes.c_wchar] | None = None
        self._trace_handle = 0
        self._trace_thread: threading.Thread | None = None
        self._trace_status: int | None = None
        self._state: _EtwTraceState | None = None
        self._devices: tuple[tuple[str, str], ...] = ()
        self._schema_facts = None if schema_facts is None else tuple(schema_facts)
        self._event_callback = None
        self._buffer_callback = None
        self._event_callback_c = None
        self._buffer_callback_c = None

    def _ensure_api(self) -> _EtwWindowsApi:
        if os.name != "nt":
            raise RuntimeError("etw_windows_only")
        if self._api is None:
            self._api = _EtwWindowsApi()
        return self._api

    def capability(self) -> tuple[bool, bool, bool, bool]:
        try:
            if ctypes.sizeof(ctypes.c_void_p) != 8:
                return False, False, False, False
            api = self._ensure_api()
            providers = api.providers()
            schema_complete = _etw_schema_facts_complete(
                self._schema_facts if self._schema_facts is not None else api.installed_schema_facts()
            )
            provider_available = (
                _ETW_KERNEL_FILE_PROVIDER_GUID in providers
                and _ETW_KERNEL_PROCESS_PROVIDER_GUID in providers
                and schema_complete
            )
            privilege_available = api.has_enabled_profile_privilege() or api.has_builtin_alias(544) or api.has_builtin_alias(559)
            lineage_available = all(hasattr(api.kernel32, name) for name in ("OpenProcess", "GetProcessTimes", "IsProcessInJob"))
            loss_available = all(hasattr(api.advapi32, name) for name in ("ControlTraceW", "CloseTrace"))
            return provider_available, privilege_available, lineage_available, loss_available
        except BaseException:
            return False, False, False, False

    def _properties_for_session(self, name: str, session_guid: uuid.UUID) -> tuple[ctypes.Array[ctypes.c_char], ctypes.POINTER(_EtwEventTraceProperties)]:
        property_size = ctypes.sizeof(_EtwEventTraceProperties)
        name_bytes = name.encode("utf-16-le") + b"\x00\x00"
        storage = ctypes.create_string_buffer(property_size + len(name_bytes))
        properties = ctypes.cast(storage, ctypes.POINTER(_EtwEventTraceProperties))
        properties.contents.Wnode.BufferSize = len(storage)
        properties.contents.Wnode.Guid = _EtwGuid.from_buffer_copy(session_guid.bytes_le)
        properties.contents.Wnode.ClientContext = 1
        properties.contents.Wnode.Flags = _ETW_WNODE_FLAG_TRACED_GUID
        properties.contents.BufferSize = 64
        properties.contents.MinimumBuffers = 4
        properties.contents.MaximumBuffers = 128
        properties.contents.FlushTimer = 1
        properties.contents.LogFileMode = _ETW_EVENT_TRACE_REAL_TIME_MODE | _ETW_EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
        properties.contents.LogFileNameOffset = 0
        properties.contents.LoggerNameOffset = property_size
        ctypes.memmove(ctypes.addressof(storage) + property_size, name_bytes, len(name_bytes))
        return storage, properties

    def _enable(self, provider_bytes: bytes, keywords: int, *, control_code: int = _ETW_EVENT_CONTROL_ENABLE) -> None:
        assert self._api is not None and self._session_id
        provider = _EtwGuid.from_buffer_copy(provider_bytes)
        params = None
        if control_code in {_ETW_EVENT_CONTROL_ENABLE, _ETW_EVENT_CONTROL_CAPTURE_STATE}:
            params = _EtwEnableTraceParameters(
                2, _ETW_ENABLE_PROPERTY_PROCESS_START_KEY, 0, _EtwGuid(), None, 0,
            )
        status = int(self._api.advapi32.EnableTraceEx2(
            self._session_id, ctypes.byref(provider), control_code,
            _ETW_TRACE_LEVEL_VERBOSE, keywords, 0, 5000, ctypes.byref(params) if params is not None else None,
        ))
        if status != _ETW_ERROR_SUCCESS:
            raise RuntimeError("etw_provider_enable")

    def _capture_process_state(self) -> None:
        self._enable(_ETW_KERNEL_PROCESS_PROVIDER_GUID, 0x10, control_code=_ETW_EVENT_CONTROL_CAPTURE_STATE)

    def start(self, root_pid: int) -> None:
        if self._trace_handle or self._session_id:
            raise RuntimeError("etw_already_started")
        api = self._ensure_api()
        if type(root_pid) is not int or root_pid <= 0:
            raise RuntimeError("etw_root_pid")
        creation, in_job = api.root_identity(root_pid)
        if creation is None or not in_job:
            raise RuntimeError("etw_root_identity")
        provider, privilege, lineage, loss = self.capability()
        if not all((provider, privilege, lineage, loss)):
            raise RuntimeError("etw_capability")
        self._devices = api.device_map()
        if not self._devices:
            raise RuntimeError("etw_device_map")
        self._state = _EtwTraceState(root_pid, creation)
        session_guid = uuid.uuid4()
        self._session_name = f"BLProfile11Etw-{session_guid.hex}"
        self._properties_storage, self._properties = self._properties_for_session(self._session_name, session_guid)
        session_id = ctypes.c_ulonglong(0)
        status = int(api.advapi32.StartTraceW(ctypes.byref(session_id), self._session_name, self._properties))
        if status != _ETW_ERROR_SUCCESS:
            self._abort_start()
            raise RuntimeError("etw_session_start")
        self._session_id = int(session_id.value)
        self._logger_name = ctypes.create_unicode_buffer(self._session_name)
        logfile = _EtwEventTraceLogfileW()
        logfile.LogFileName = None
        logfile.LoggerName = ctypes.cast(self._logger_name, ctypes.c_void_p).value
        logfile.ProcessTraceMode = _ETW_PROCESS_TRACE_MODE_REAL_TIME | _ETW_PROCESS_TRACE_MODE_EVENT_RECORD
        self._event_callback_c = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_EtwEventRecord))(self._on_event)
        self._buffer_callback_c = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.POINTER(_EtwEventTraceLogfileW))(self._on_buffer)
        logfile.EventRecordCallback = ctypes.cast(self._event_callback_c, ctypes.c_void_p).value
        logfile.BufferCallback = ctypes.cast(self._buffer_callback_c, ctypes.c_void_p).value
        self._trace_handle = int(api.advapi32.OpenTraceW(ctypes.byref(logfile)))
        if self._trace_handle == _ETW_INVALID_PROCESS_TRACE_HANDLE:
            self._abort_start()
            raise RuntimeError("etw_consumer_open")
        self._trace_thread = threading.Thread(target=self._consume, name="profile11-etw-consumer", daemon=False)
        self._trace_thread.start()
        try:
            file_keywords = 0x10 | 0x20 | 0x80 | 0x200 | 0x400 | 0x800 | 0x1000
            self._enable(_ETW_KERNEL_PROCESS_PROVIDER_GUID, 0x10)
            self._enable(_ETW_KERNEL_FILE_PROVIDER_GUID, file_keywords)
            self._capture_process_state()
            if not self._state.root_observed.wait(_ETW_ROOT_CAPTURE_TIMEOUT_SECONDS):
                raise RuntimeError("etw_root_capture_timeout")
            if self._state.malformed or self._state.loss_detected or not self._state.root_creation_match:
                raise RuntimeError("etw_root_capture_invalid")
        except BaseException:
            self._abort_start()
            raise

    def _consume(self) -> None:
        assert self._api is not None
        handle_array = (ctypes.c_ulonglong * 1)(self._trace_handle)
        try:
            self._trace_status = int(self._api.advapi32.ProcessTrace(handle_array, 1, None, None))
        except BaseException:
            self._trace_status = -1
            if self._state is not None:
                self._state.mark_loss()

    def _on_buffer(self, logfile: ctypes.POINTER(_EtwEventTraceLogfileW)) -> int:
        state = self._state
        if state is not None and logfile and int(logfile.contents.EventsLost):
            state.mark_loss()
        return 1

    def _provider_process_key(self, record: _EtwEventRecord) -> int:
        key = _etw_process_start_key(record)
        if key is None:
            raise _EtwMalformedEvent()
        return key

    def _validate_record_schema(self, record: _EtwEventRecord, provider: bytes) -> _EtwEventSchemaSpec | None:
        assert self._api is not None
        event_id = int(record.EventHeader.EventDescriptor.Id)
        spec = _ETW_SCHEMA_BY_PROVIDER_ID.get((provider, event_id))
        if spec is None:
            raise _EtwMalformedEvent()
        fact = self._api.event_schema(record)
        if not _etw_schema_fact_matches(fact):
            raise _EtwMalformedEvent()
        return spec

    def _on_process_event(self, record: _EtwEventRecord, event_id: int) -> None:
        state = self._state
        api = self._api
        if state is None or api is None:
            return
        if event_id not in {1, 2, 15}:
            state.mark_malformed()
            return
        pid = _etw_property_int(api, record, ("ProcessID",))
        create_time = _etw_property_int(api, record, ("CreateTime",))
        parent = _etw_property_int(api, record, ("ParentProcessID",))
        if pid is None or create_time is None or (event_id in _ETW_PROCESS_START_TASKS and parent is None):
            raise _EtwMalformedEvent()
        if parent is None:
            parent = 0
        key = self._provider_process_key(record)
        state.record_process(event_id=event_id, pid=pid, key=key, parent_pid=parent, create_time=create_time)

    def _on_file_event(self, record: _EtwEventRecord, event_id: int) -> None:
        state = self._state
        api = self._api
        if state is None or api is None:
            return
        if event_id not in _ETW_FILE_NONMUTATION_IDS | _ETW_FILE_MUTATION_IDS:
            state.mark_malformed()
            return
        pid = int(record.EventHeader.ProcessId)
        key = self._provider_process_key(record)
        if not state.actor_is_traced(pid, key):
            return
        if event_id == 10:
            file_key = _etw_property_int(api, record, ("FileKey",))
            raw_path = _etw_property_text(api, record, ("FileName",))
            if file_key is None or raw_path is None:
                raise _EtwMalformedEvent()
            state.update_file_correlation(file_object=None, file_key=file_key, path=_etw_path_from_provider(raw_path, self._devices))
            return
        if event_id == 11:
            file_key = _etw_property_int(api, record, ("FileKey",))
            raw_path = _etw_property_text(api, record, ("FileName",))
            if file_key is None or raw_path is None:
                raise _EtwMalformedEvent()
            state.delete_file_name(file_key=file_key, path=_etw_path_from_provider(raw_path, self._devices))
            return
        if event_id in {12, 30}:
            file_object = _etw_property_int(api, record, ("FileObject",))
            raw_path = _etw_property_text(api, record, ("FileName",))
            if file_object is None or raw_path is None:
                raise _EtwMalformedEvent()
            path = state.update_file_correlation(file_object=file_object, file_key=None, path=_etw_path_from_provider(raw_path, self._devices))
            if event_id == 30:
                if path is None:
                    raise _EtwMalformedEvent()
                state.record_file(pid=pid, key=key, path=path, operation="create")
            return
        if event_id in {13, 14}:
            file_object = _etw_property_int(api, record, ("FileObject",))
            file_key = _etw_property_int(api, record, ("FileKey",))
            if file_object is None or file_key is None:
                raise _EtwMalformedEvent()
            state.cleanup_file_correlation(file_object=file_object, file_key=file_key)
            return
        if event_id in {15, 22, 24, 32, 34}:
            return
        file_object = _etw_property_int(api, record, ("FileObject",))
        file_key = _etw_property_int(api, record, ("FileKey",))
        if file_object is None or file_key is None:
            raise _EtwMalformedEvent()
        if event_id in {20, 25}:
            raw_path = _etw_property_text(api, record, ("FileName",))
            if raw_path is None:
                raise _EtwMalformedEvent()
            state.update_file_correlation(file_object=file_object, file_key=file_key, path=_etw_path_from_provider(raw_path, self._devices))
            return
        if event_id in {27, 28}:
            source_path = state.update_file_correlation(file_object=file_object, file_key=file_key, path=None)
            raw_path = _etw_property_text(api, record, ("FilePath",))
            irp = _etw_property_int(api, record, ("Irp",))
            if source_path is None or raw_path is None or irp is None:
                raise _EtwMalformedEvent()
            target_path = _etw_path_from_provider(raw_path, self._devices)
            state.record_paired_mutation(
                pid=pid,
                key=key,
                irp=irp,
                operation=_ETW_FILE_TASK_OPERATIONS[event_id],
                source_path=source_path,
                target_path=target_path,
            )
            return
        direct_path = None
        if event_id == 26:
            raw_path = _etw_property_text(api, record, ("FilePath",))
            if raw_path is None:
                raise _EtwMalformedEvent()
            direct_path = _etw_path_from_provider(raw_path, self._devices)
        path = state.update_file_correlation(file_object=file_object, file_key=file_key, path=direct_path)
        if path is None:
            raise _EtwMalformedEvent()
        operation = _ETW_FILE_TASK_OPERATIONS[event_id]
        if event_id in {19, 29}:
            irp = _etw_property_int(api, record, ("Irp",))
            if irp is None:
                raise _EtwMalformedEvent()
            state.record_paired_mutation(pid=pid, key=key, irp=irp, operation=operation, source_path=path, target_path=None)
            return
        state.record_file(pid=pid, key=key, path=path, operation=operation)

    def _on_event(self, record_pointer: ctypes.POINTER(_EtwEventRecord)) -> None:
        state = self._state
        if state is None or not record_pointer:
            if state is not None:
                state.mark_malformed()
            return
        try:
            record = record_pointer.contents
            provider = bytes(record.EventHeader.ProviderId)
            event_id = int(record.EventHeader.EventDescriptor.Id)
            if provider == _ETW_KERNEL_PROCESS_PROVIDER_GUID:
                if self._validate_record_schema(record, provider) is not None:
                    self._on_process_event(record, event_id)
            elif provider == _ETW_KERNEL_FILE_PROVIDER_GUID:
                if self._validate_record_schema(record, provider) is not None:
                    self._on_file_event(record, event_id)
        except BaseException:
            state.mark_malformed()

    def _stop_session(self) -> tuple[bool, bool]:
        api = self._api
        if api is None or not self._session_id or self._properties is None or self._session_name is None:
            return False, False
        flush_ok = int(api.advapi32.ControlTraceW(self._session_id, self._session_name, self._properties, _ETW_EVENT_CONTROL_FLUSH)) == _ETW_ERROR_SUCCESS
        stop_ok = int(api.advapi32.ControlTraceW(self._session_id, self._session_name, self._properties, _ETW_EVENT_CONTROL_STOP)) == _ETW_ERROR_SUCCESS
        return flush_ok, stop_ok

    def _close_consumer(self) -> bool:
        api = self._api
        if api is None or not self._trace_handle:
            return True
        status = int(api.advapi32.CloseTrace(self._trace_handle))
        if self._trace_thread is not None:
            self._trace_thread.join(timeout=10.0)
        if self._trace_thread is not None and self._trace_thread.is_alive():
            return False
        return status in {_ETW_ERROR_SUCCESS, _ETW_ERROR_CTX_CLOSE_PENDING}

    def _abort_start(self) -> None:
        try:
            self._stop_session()
        except BaseException:
            pass
        try:
            self._close_consumer()
        except BaseException:
            pass
        if self._state is not None:
            self._state.wipe()
        self._session_id = 0
        self._trace_handle = 0
        self._trace_thread = None
        self._properties = None
        self._properties_storage = None
        self._logger_name = None
        self._session_name = None
        self._trace_status = None
        self._state = None
        self._devices = ()
        self._event_callback = None
        self._buffer_callback = None
        self._event_callback_c = None
        self._buffer_callback_c = None

    def stop(self) -> "FileWriteObservation":
        state = self._state
        if state is None or not self._session_id:
            return FileWriteObservation("observer_incomplete", True, True, False, True)
        try:
            flush_ok, stop_ok = self._stop_session()
            close_ok = self._close_consumer()
            trace_ok = self._trace_status == _ETW_ERROR_SUCCESS
            properties = self._properties.contents if self._properties is not None else None
            loss = state.loss_detected or not flush_ok or not stop_ok or not close_ok or not trace_ok
            if properties is not None:
                loss = loss or bool(properties.EventsLost or properties.LogBuffersLost or properties.RealTimeBuffersLost)
            lineage = state.complete_lineage()
            ready = not loss and lineage
            events = tuple(state.events) if ready else ()
            state.wipe()
            result = FileWriteObservation("observer_ready" if ready else "observer_incomplete", True, True, lineage, bool(loss), events)
        except BaseException:
            state.mark_loss()
            state.wipe()
            result = FileWriteObservation("observer_incomplete", True, True, False, True)
        finally:
            self._session_id = 0
            self._trace_handle = 0
            self._trace_thread = None
            self._properties = None
            self._properties_storage = None
            self._logger_name = None
            self._session_name = None
            self._trace_status = None
            self._state = None
            self._devices = ()
            self._event_callback = None
            self._buffer_callback = None
            self._event_callback_c = None
            self._buffer_callback_c = None
        return result


class WriteTraceBackend(Protocol):
    def capability(self) -> tuple[bool, bool, bool, bool]: ...
    def start(self, root_pid: int) -> None: ...
    def stop(self) -> "FileWriteObservation": ...


@dataclass(frozen=True, slots=True)
class FileWriteEvent:
    path: Path
    operation: str
    pid: int
    lineage_complete: bool = True
    process_generation: int | None = None
    source_path: Path | None = None
    target_path: Path | None = None


@dataclass(frozen=True, slots=True)
class FileWriteObservation:
    status: str
    provider_available: bool
    privilege_available: bool
    lineage_complete: bool
    loss_detected: bool
    events: tuple[FileWriteEvent, ...] = ()


class WindowsEtwFileWriteObserver:
    """Capability probe; no snapshot is treated as a trace.

    A verified callback backend must provide direct Kernel-File ETW events,
    provider/privilege evidence, PID lineage, lost-event detection, and a
    complete stop/readback.  This repository intentionally does not pretend
    that checking for ``advapi32`` exports establishes those properties.
    """

    __slots__ = ("_backend", "_started")

    def __init__(self, backend: WriteTraceBackend | None = None) -> None:
        self._backend = backend if backend is not None else (WindowsEtwWriteTraceBackend() if os.name == "nt" else None)
        self._started = False

    def probe(self) -> FileWriteObservation:
        if os.name != "nt" or self._backend is None:
            return FileWriteObservation("observer_unavailable", False, False, False, False)
        try:
            provider, privilege, lineage, loss_detection = self._backend.capability()
        except BaseException:
            return FileWriteObservation("observer_unavailable", False, False, False, False)
        if not all((provider, privilege, lineage, loss_detection)):
            return FileWriteObservation("observer_unavailable", provider, privilege, lineage, False)
        return FileWriteObservation("observer_ready", True, True, True, False)

    def start(self, root_pid: int) -> FileWriteObservation:
        capability = self.probe()
        if capability.status != "observer_ready" or self._backend is None:
            return capability
        try:
            self._backend.start(root_pid)
            self._started = True
            return capability
        except BaseException:
            return FileWriteObservation("observer_unavailable", True, True, True, False)

    def stop(self) -> FileWriteObservation:
        if not self._started or self._backend is None:
            return self.probe()
        self._started = False
        try:
            result = self._backend.stop()
        except BaseException:
            return FileWriteObservation("observer_incomplete", True, True, False, True)
        if type(result) is not FileWriteObservation:
            return FileWriteObservation("observer_incomplete", True, True, False, True)
        if result.status != "observer_ready" or not result.provider_available or not result.privilege_available or not result.lineage_complete or result.loss_detected:
            return FileWriteObservation("observer_incomplete", result.provider_available, result.privilege_available, result.lineage_complete, result.loss_detected, result.events)
        return result


def configured_state_allowlist(state_workspace: Path, *, journal_mode: str = "delete") -> frozenset[Path]:
    if not isinstance(state_workspace, Path) or not state_workspace.is_absolute():
        _fixed("state_workspace")
    if journal_mode.lower() != "delete":
        _fixed("state_durability_configuration")
    database = state_workspace / "state.sqlite"
    return frozenset((
        database,
        state_workspace / "state.sqlite-journal",
        state_workspace / "state.sqlite.runtime-lock",
    ))


def evaluate_disk_gate(
    observation: FileWriteObservation,
    *,
    state_workspace: Path,
    journal_mode: str = "delete",
) -> str:
    if type(observation) is not FileWriteObservation:
        return "observer_incomplete"
    if observation.status == "observer_unavailable":
        return "observer_unavailable"
    if observation.status != "observer_ready" or not observation.provider_available or not observation.privilege_available or not observation.lineage_complete or observation.loss_detected:
        return "observer_incomplete"
    try:
        allowlist = configured_state_allowlist(state_workspace, journal_mode=journal_mode)
    except CompletePathError as error:
        return str(error)
    state_root = state_workspace.resolve()
    for event in observation.events:
        if type(event) is not FileWriteEvent or type(event.pid) is not int or event.pid <= 0 or type(event.process_generation) is not int or event.process_generation <= 0 or event.operation not in _ETW_FILE_MUTATION_OPERATIONS | {"directory_metadata"}:
            return "observer_incomplete"
        if not event.lineage_complete:
            return "observer_incomplete"
        try:
            path = event.path.resolve()
        except OSError:
            return "observer_incomplete"
        if event.operation in {"rename", "link"}:
            if event.source_path is None or event.target_path is None or not event.source_path.is_absolute() or not event.target_path.is_absolute() or event.target_path != event.path:
                return "observer_incomplete"
            try:
                source_path = event.source_path.resolve()
                target_path = event.target_path.resolve()
            except OSError:
                return "observer_incomplete"
            if source_path not in allowlist or target_path not in allowlist:
                return "unauthorized_write"
        elif event.operation == "directory_metadata":
            if path != state_root:
                return "unauthorized_write"
        elif event.operation == "metadata" and path == state_root:
            continue
        elif path not in allowlist:
            return "unauthorized_write"
    return "disk_gate_pass"


@dataclass(frozen=True, slots=True)
class VerifyStateBreakdown:
    handoff_ms: float
    frame_read_ms: float
    ipc_prepare_ms: float
    contained_verifier_ms: float
    queue_state_ms: float
    integrity_ms: float
    close_ms: float
    unbucketed_ms: float


@dataclass(frozen=True, slots=True)
class StageSample:
    source_ms: float
    verify_state_ms: float
    ack_ms: float
    total_ms: float
    verify_state_breakdown: VerifyStateBreakdown | None = None
    total_unbucketed_ms: float | None = None


@dataclass(frozen=True, slots=True)
class MeasurementSchedule:
    warmup: StageSample
    measured: tuple[StageSample, ...]


@dataclass(slots=True)
class _VerifierTiming:
    frame_read_ms: float = 0.0
    ipc_prepare_ms: float = 0.0
    contained_verifier_ms: float = 0.0
    verifier_finished_at: float | None = None
    handoff_ms: float = 0.0
    queue_state_ms: float = 0.0
    integrity_ms: float = 0.0
    close_ms: float = 0.0


@contextmanager
def _timed_verifier_functions(timing: _VerifierTiming) -> Iterable[None]:
    original_read = source_auth_adapter._read_exact_frame
    original_build = source_auth_adapter._build_ipc_input
    original_run = source_auth_adapter.run_contained_verifier_stream

    def timed_read(*args: Any, **kwargs: Any) -> bytearray:
        started = time.perf_counter()
        try:
            return original_read(*args, **kwargs)
        finally:
            timing.frame_read_ms += (time.perf_counter() - started) * 1000.0

    def timed_build(*args: Any, **kwargs: Any) -> bytearray:
        started = time.perf_counter()
        try:
            return original_build(*args, **kwargs)
        finally:
            timing.ipc_prepare_ms += (time.perf_counter() - started) * 1000.0

    def timed_run(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        try:
            return original_run(*args, **kwargs)
        finally:
            timing.contained_verifier_ms += (time.perf_counter() - started) * 1000.0
            timing.verifier_finished_at = time.perf_counter()

    source_auth_adapter._read_exact_frame = timed_read
    source_auth_adapter._build_ipc_input = timed_build
    source_auth_adapter.run_contained_verifier_stream = timed_run
    try:
        yield
    finally:
        source_auth_adapter._read_exact_frame = original_read
        source_auth_adapter._build_ipc_input = original_build
        source_auth_adapter.run_contained_verifier_stream = original_run


def _max_breakdown(samples: tuple[StageSample, ...]) -> VerifyStateBreakdown | None:
    values = tuple(sample.verify_state_breakdown for sample in samples)
    if not values or all(value is None for value in values):
        return None
    if any(value is None for value in values):
        _fixed("sample_breakdown")
    assert all(value is not None for value in values)
    return VerifyStateBreakdown(
        max(value.handoff_ms for value in values),
        max(value.frame_read_ms for value in values),
        max(value.ipc_prepare_ms for value in values),
        max(value.contained_verifier_ms for value in values),
        max(value.queue_state_ms for value in values),
        max(value.integrity_ms for value in values),
        max(value.close_ms for value in values),
        max(value.unbucketed_ms for value in values),
    )


def nearest_rank_p95(samples: Iterable[StageSample]) -> StageSample:
    values = tuple(samples)
    if len(values) != MEASURED_SAMPLE_COUNT:
        _fixed("sample_count")
    if any(type(item) is not StageSample for item in values):
        _fixed("sample_shape")
    breakdown = _max_breakdown(values)
    unbucketed = tuple(item.total_unbucketed_ms for item in values)
    if any(item is None for item in unbucketed) and not all(item is None for item in unbucketed):
        _fixed("sample_reconciliation")
    return StageSample(
        max(item.source_ms for item in values),
        max(item.verify_state_ms for item in values),
        max(item.ack_ms for item in values),
        max(item.total_ms for item in values),
        breakdown,
        None if all(item is None for item in unbucketed) else max(item for item in unbucketed if item is not None),
    )


def run_measurement_schedule_with_warmup(sample: Callable[[], StageSample]) -> MeasurementSchedule:
    if not callable(sample):
        _fixed("sample_factory")
    warmup = sample()
    if type(warmup) is not StageSample:
        _fixed("sample_shape")
    measured: list[StageSample] = []
    for _ in range(MEASURED_SAMPLE_COUNT):
        value = sample()
        if type(value) is not StageSample:
            _fixed("sample_shape")
        measured.append(value)
    return MeasurementSchedule(warmup, tuple(measured))


def run_measurement_schedule(sample: Callable[[], StageSample]) -> tuple[StageSample, ...]:
    return run_measurement_schedule_with_warmup(sample).measured


def validate_topology(*, proof_count: int, operation_count: int, frame_count: int, verifier_batch_count: int, ack_count: int) -> None:
    if (proof_count, operation_count, frame_count, verifier_batch_count, ack_count) != (1, 100, 1, 1, 100):
        _fixed("topology_mismatch")


def _safe_number(value: object) -> float:
    if type(value) not in (int, float) or isinstance(value, bool) or not 0 <= float(value) < 10**12:
        _fixed("aggregate_timing")
    return round(float(value), 3)


_VERIFY_STATE_BREAKDOWN_KEYS: Final[tuple[str, ...]] = (
    "handoff", "frame_read", "ipc_prepare", "contained_verifier",
    "queue_state", "integrity", "close", "unbucketed",
)


def _stage_timing_mapping(value: StageSample) -> dict[str, float]:
    return {
        "source": _safe_number(value.source_ms),
        "verify_state": _safe_number(value.verify_state_ms),
        "ack": _safe_number(value.ack_ms),
        "total": _safe_number(value.total_ms),
    }


def _breakdown_mapping(value: VerifyStateBreakdown) -> dict[str, float]:
    return {
        "handoff": _safe_number(value.handoff_ms),
        "frame_read": _safe_number(value.frame_read_ms),
        "ipc_prepare": _safe_number(value.ipc_prepare_ms),
        "contained_verifier": _safe_number(value.contained_verifier_ms),
        "queue_state": _safe_number(value.queue_state_ms),
        "integrity": _safe_number(value.integrity_ms),
        "close": _safe_number(value.close_ms),
        "unbucketed": _safe_number(value.unbucketed_ms),
    }


def _validate_stage_timing_mapping(value: object) -> None:
    if type(value) is not dict or set(value) != {"source", "verify_state", "ack", "total"}:
        _fixed("aggregate_timing")
    for item in value.values():
        _safe_number(item)


def _validate_breakdown_mapping(value: object) -> dict[str, float]:
    if type(value) is not dict or set(value) != set(_VERIFY_STATE_BREAKDOWN_KEYS):
        _fixed("aggregate_timing")
    return {key: _safe_number(value[key]) for key in _VERIFY_STATE_BREAKDOWN_KEYS}


def _validate_verify_state_reconciliation(verify_state: float, breakdown: dict[str, float]) -> None:
    if abs(verify_state - sum(breakdown.values())) > TIMING_RECONCILIATION_TOLERANCE_MS:
        _fixed("aggregate_timing_reconciliation")


def _validate_total_reconciliation(stage: dict[str, float], unbucketed: float) -> None:
    if abs(stage["total"] - (stage["source"] + stage["verify_state"] + stage["ack"] + unbucketed)) > TIMING_RECONCILIATION_TOLERANCE_MS:
        _fixed("aggregate_timing_reconciliation")


def _validate_aggregate_mapping(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        _fixed("aggregate_shape")
    allowed = {
        "schema", "status", "proofSuiteId", "production_usable", "activation",
        "warmup_count", "measured_count", "completed_samples", "proof_count",
        "operation_count", "frame_count", "verifier_batch_count", "ack_count",
        "stage_timings_ms", "p95_timings_ms", "peak_job_commit_bytes",
        "effective_cap_bytes", "peak_active_processes", "total_processes",
        "observer_status", "disk_gate", "error_code", "qualification_flags",
        "warmup_timing_ms", "warmup_verify_state_substages_ms",
        "warmup_total_unbucketed_ms", "verify_state_substages_ms",
        "total_unbucketed_ms", "p95_verify_state_substages_ms",
        "p95_total_unbucketed_ms",
    }
    if set(value) != allowed:
        _fixed("aggregate_fields")
    if value["schema"] != PROFILE_SCHEMA or value["proofSuiteId"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fixed("aggregate_nonactivation")
    if value["status"] not in {"complete", "failed"}:
        _fixed("aggregate_status")
    if (value["warmup_count"], value["measured_count"]) != (1, 5):
        _fixed("aggregate_schedule")
    validate_topology(
        proof_count=value["proof_count"],
        operation_count=value["operation_count"],
        frame_count=value["frame_count"],
        verifier_batch_count=value["verifier_batch_count"],
        ack_count=value["ack_count"],
    )
    if type(value["completed_samples"]) is not int or not 0 <= value["completed_samples"] <= 5:
        _fixed("aggregate_samples")
    if type(value["stage_timings_ms"]) is not list or len(value["stage_timings_ms"]) not in {0, value["completed_samples"]}:
        _fixed("aggregate_timing")
    for sample in value["stage_timings_ms"]:
        _validate_stage_timing_mapping(sample)
    if type(value["p95_timings_ms"]) is not dict or set(value["p95_timings_ms"]) != {"source", "verify_state", "ack", "total"}:
        _fixed("aggregate_timing")
    for item in value["p95_timings_ms"].values():
        _safe_number(item)
    measured_breakdowns = value["verify_state_substages_ms"]
    measured_unbucketed = value["total_unbucketed_ms"]
    if type(measured_breakdowns) is not list or type(measured_unbucketed) is not list:
        _fixed("aggregate_timing")
    if len(measured_breakdowns) != value["completed_samples"] or len(measured_unbucketed) != value["completed_samples"]:
        _fixed("aggregate_timing")
    validated_stages: list[dict[str, float]] = []
    validated_breakdowns: list[dict[str, float]] = []
    validated_unbucketed: list[float] = []
    for stage, raw_breakdown, raw_unbucketed in zip(value["stage_timings_ms"], measured_breakdowns, measured_unbucketed):
        validated_stage = {
            "source": _safe_number(stage["source"]),
            "verify_state": _safe_number(stage["verify_state"]),
            "ack": _safe_number(stage["ack"]),
            "total": _safe_number(stage["total"]),
        }
        validated_breakdown = _validate_breakdown_mapping(raw_breakdown)
        validated_total_unbucketed = _safe_number(raw_unbucketed)
        _validate_verify_state_reconciliation(validated_stage["verify_state"], validated_breakdown)
        _validate_total_reconciliation(validated_stage, validated_total_unbucketed)
        validated_stages.append(validated_stage)
        validated_breakdowns.append(validated_breakdown)
        validated_unbucketed.append(validated_total_unbucketed)
    warmup_timing = value["warmup_timing_ms"]
    warmup_breakdown = value["warmup_verify_state_substages_ms"]
    warmup_unbucketed = value["warmup_total_unbucketed_ms"]
    p95_breakdown = value["p95_verify_state_substages_ms"]
    p95_unbucketed = value["p95_total_unbucketed_ms"]
    if value["completed_samples"] == MEASURED_SAMPLE_COUNT:
        _validate_stage_timing_mapping(warmup_timing)
        validated_warmup_breakdown = _validate_breakdown_mapping(warmup_breakdown)
        validated_warmup_unbucketed = _safe_number(warmup_unbucketed)
        validated_warmup = {key: _safe_number(warmup_timing[key]) for key in ("source", "verify_state", "ack", "total")}
        _validate_verify_state_reconciliation(validated_warmup["verify_state"], validated_warmup_breakdown)
        _validate_total_reconciliation(validated_warmup, validated_warmup_unbucketed)
        validated_p95_breakdown = _validate_breakdown_mapping(p95_breakdown)
        validated_p95_unbucketed = _safe_number(p95_unbucketed)
        validated_p95_stage = {key: _safe_number(value["p95_timings_ms"][key]) for key in ("source", "verify_state", "ack", "total")}
        if validated_stages and any(validated_p95_stage[key] != max(item[key] for item in validated_stages) for key in validated_p95_stage):
            _fixed("aggregate_p95")
        if validated_breakdowns and any(
            validated_p95_breakdown[key] != max(item[key] for item in validated_breakdowns)
            for key in _VERIFY_STATE_BREAKDOWN_KEYS
        ):
            _fixed("aggregate_p95")
        if validated_unbucketed and validated_p95_unbucketed != max(validated_unbucketed):
            _fixed("aggregate_p95")
    elif any(item is not None for item in (warmup_timing, warmup_breakdown, warmup_unbucketed, p95_breakdown, p95_unbucketed)) or measured_breakdowns or measured_unbucketed:
        _fixed("aggregate_timing")
    if type(value["peak_job_commit_bytes"]) is not int or value["peak_job_commit_bytes"] < 0 or value["peak_job_commit_bytes"] >= OUTER_HARD_CAP_BYTES:
        _fixed("aggregate_peak")
    if type(value["effective_cap_bytes"]) is not int or value["effective_cap_bytes"] >= OUTER_HARD_CAP_BYTES:
        _fixed("aggregate_cap")
    if type(value["peak_active_processes"]) is not int or type(value["total_processes"]) is not int:
        _fixed("aggregate_processes")
    if value["observer_status"] not in {"observer_ready", "observer_unavailable", "observer_incomplete"}:
        _fixed("aggregate_observer")
    if value["disk_gate"] not in {"disk_gate_pass", "observer_unavailable", "observer_incomplete", "unauthorized_write"}:
        _fixed("aggregate_disk")
    if value["error_code"] is not None and (type(value["error_code"]) is not str or value["error_code"] not in AGGREGATE_ERROR_CODES):
        _fixed("aggregate_error")
    if type(value["qualification_flags"]) is not list or tuple(value["qualification_flags"]) != FIXED_QUALIFICATION_FLAGS:
        _fixed("aggregate_flags")
    return value


def _aggregate_json(value: dict[str, Any]) -> str:
    _validate_aggregate_mapping(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        _fixed("aggregate_encoding")


def build_test_aggregate(*, completed_samples: int = 0, timings: tuple[StageSample, ...] = (), warmup: StageSample | None = None, peak_job_commit_bytes: int = 0, effective_cap_bytes: int = PROCESS_TREE_PEAK_CAP_BYTES, peak_active_processes: int = 1, total_processes: int = 1, observer_status: str = "observer_unavailable", disk_gate: str = "observer_unavailable", error_code: str | None = None) -> dict[str, Any]:
    if completed_samples == MEASURED_SAMPLE_COUNT and len(timings) != MEASURED_SAMPLE_COUNT:
        _fixed("aggregate_samples")
    if completed_samples != MEASURED_SAMPLE_COUNT and timings:
        _fixed("aggregate_samples")
    if completed_samples == MEASURED_SAMPLE_COUNT:
        if warmup is None or warmup.verify_state_breakdown is None or warmup.total_unbucketed_ms is None or any(item.verify_state_breakdown is None or item.total_unbucketed_ms is None for item in timings):
            _fixed("aggregate_timing")
    elif warmup is not None:
        _fixed("aggregate_samples")
    p95 = nearest_rank_p95(timings) if timings else StageSample(0.0, 0.0, 0.0, 0.0)
    has_breakdowns = bool(timings) and all(item.verify_state_breakdown is not None for item in timings)
    has_total_unbucketed = bool(timings) and all(item.total_unbucketed_ms is not None for item in timings)
    value = {
        "schema": PROFILE_SCHEMA,
        "status": "complete" if completed_samples == MEASURED_SAMPLE_COUNT and error_code is None else "failed",
        "proofSuiteId": None,
        "production_usable": False,
        "activation": False,
        "warmup_count": WARMUP_SAMPLE_COUNT,
        "measured_count": MEASURED_SAMPLE_COUNT,
        "completed_samples": completed_samples,
        "proof_count": 1,
        "operation_count": SOURCE_AUTH_OPERATION_COUNT,
        "frame_count": 1,
        "verifier_batch_count": 1,
        "ack_count": SOURCE_AUTH_OPERATION_COUNT,
        "stage_timings_ms": [
            _stage_timing_mapping(item)
            for item in timings
        ],
        "p95_timings_ms": {"source": _safe_number(p95.source_ms), "verify_state": _safe_number(p95.verify_state_ms), "ack": _safe_number(p95.ack_ms), "total": _safe_number(p95.total_ms)},
        "warmup_timing_ms": None if warmup is None else _stage_timing_mapping(warmup),
        "warmup_verify_state_substages_ms": None if warmup is None or warmup.verify_state_breakdown is None else _breakdown_mapping(warmup.verify_state_breakdown),
        "warmup_total_unbucketed_ms": None if warmup is None or warmup.total_unbucketed_ms is None else _safe_number(warmup.total_unbucketed_ms),
        "verify_state_substages_ms": [] if not has_breakdowns else [_breakdown_mapping(item.verify_state_breakdown) for item in timings if item.verify_state_breakdown is not None],
        "total_unbucketed_ms": [] if not has_total_unbucketed else [_safe_number(item.total_unbucketed_ms) for item in timings if item.total_unbucketed_ms is not None],
        "p95_verify_state_substages_ms": None if p95.verify_state_breakdown is None else _breakdown_mapping(p95.verify_state_breakdown),
        "p95_total_unbucketed_ms": None if p95.total_unbucketed_ms is None else _safe_number(p95.total_unbucketed_ms),
        "peak_job_commit_bytes": peak_job_commit_bytes,
        "effective_cap_bytes": effective_cap_bytes,
        "peak_active_processes": peak_active_processes,
        "total_processes": total_processes,
        "observer_status": observer_status,
        "disk_gate": disk_gate,
        "error_code": error_code,
        "qualification_flags": list(FIXED_QUALIFICATION_FLAGS),
    }
    _validate_aggregate_mapping(value)
    return value


class _ScreenStatePort:
    def __init__(self) -> None:
        self._state_id = bytes(64)
        self._state_bytes = bytes(64)
        self._continuity = bytes(64)
        self._audit = bytes(64)
        self._clearance = bytes(64)
        self._sequence = 0

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome: object) -> dict[bytes, StateDispositionControl]:
        del batch_id, verification_outcome
        profile = bytes([0x11]) * 64
        state_id = self._state_id
        state_bytes = self._state_bytes
        continuity = self._continuity
        audit = self._audit
        clearance = self._clearance
        sequence = self._sequence
        controls: dict[bytes, StateDispositionControl] = {}
        for operation_ref in operation_refs:
            control = StateDispositionControl(
                operation_ref=operation_ref,
                policy_result="MISSING",
                state_profile_identity=profile,
                predecessor_state_id=state_id,
                predecessor_state_bytes=state_bytes,
                sequence_before=sequence,
                predecessor_continuity_root=continuity,
                predecessor_audit_head=audit,
                predecessor_clearance_root=clearance,
            )
            controls[operation_ref] = control
            state_id, state_bytes = control.state_after_id, control.state_after_bytes
            continuity = control.state_after_continuity_root
            audit = composition._sha(composition._STATE, audit, control.decision_id, control.effective_directive.encode("ascii"))
            sequence += 1
        self._state_id = state_id
        self._state_bytes = state_bytes
        self._continuity = continuity
        self._audit = audit
        self._clearance = clearance
        self._sequence = sequence
        return controls


class _SyntheticReceiver:
    def __init__(self, config: object) -> None:
        self._config = config
        self.calls = 0

    def identity_sha256(self) -> bytes:
        return self._config.receiver_identity  # type: ignore[attr-defined]

    def epoch(self) -> int:
        return self._config.receiver_epoch  # type: ignore[attr-defined]

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.calls += 1
        return build_synthetic_acknowledgment(
            envelope_bytes,
            config=self._config,  # type: ignore[arg-type]
            idempotency_key=idempotency_key,
            accepted_ms=1_700_000_000_000,
        )


def _template(queue_config: QueueConfig) -> OperationTemplate:
    valid_from_ms = time.time_ns() // 1_000_000 - 60_000
    return OperationTemplate(
        "assertion",
        1,
        "state-profile-v11",
        valid_from_ms,
        valid_from_ms + 3_000_000,
        None,
        queue_config.qualification_flags,
    )


def _run_one_sample(*, root: Path, source_workspace: Path, verifier_workspace: Path, source_caller: Profile11SourceBoundaryCaller, queue_config: QueueConfig, source_config: SourceAuthVerifierConfig, state_port: _ScreenStatePort, expected_acknowledged_count: int) -> StageSample:
    total_start = time.perf_counter()
    runtime = MinimalClearanceVerificationRuntime.from_source_auth(
        root=root,
        source_auth_config=source_config,
        state_disposition_port=state_port,
    )
    frame: bytearray | None = None
    timing = _VerifierTiming()
    verify_start: float | None = None
    try:
        batch = runtime.issue_batch(template=_template(queue_config))
        source_start = time.perf_counter()
        frame = source_caller.prove_one(batch=batch, source_key_epoch=queue_config.source_key_epoch)
        source_ms = (time.perf_counter() - source_start) * 1000.0
        if len(frame) != SOURCE_AUTH_FRAME_BYTES:
            _fixed("source_frame_shape")
        verify_start = time.perf_counter()
        handoff_start = time.perf_counter()
        runtime.submit_batch_handoff(issued_batch=batch, proof_stream=VolatileProofHandoff(frame))
        timing.handoff_ms = (time.perf_counter() - handoff_start) * 1000.0
        frame = None
        with _timed_verifier_functions(timing):
            run_result = runtime.run(max_batches=1)
            run_end = time.perf_counter()
        if timing.verifier_finished_at is None:
            _fixed("timing_verifier_scope")
        timing.queue_state_ms = (run_end - timing.verifier_finished_at) * 1000.0
        if (run_result.outcome, run_result.verified_batch_count, run_result.accepted_operation_count) != ("PROCESSED", 1, SOURCE_AUTH_OPERATION_COUNT):
            _fixed("state_batch_shape")
        integrity_start = time.perf_counter()
        runtime._verify_integrity()
        timing.integrity_ms = (time.perf_counter() - integrity_start) * 1000.0
        database = runtime._database_path
        composition_config = runtime._composition_config
    finally:
        _wipe(frame)
        close_start = time.perf_counter()
        try:
            runtime.close()
        finally:
            timing.close_ms = (time.perf_counter() - close_start) * 1000.0
    if verify_start is None:
        _fixed("timing_verify_scope")
    verify_state_ms = (time.perf_counter() - verify_start) * 1000.0
    measured_verify_ms = (
        timing.handoff_ms
        + timing.frame_read_ms
        + timing.ipc_prepare_ms
        + timing.contained_verifier_ms
        + timing.queue_state_ms
        + timing.integrity_ms
        + timing.close_ms
    )
    verify_unbucketed_ms = verify_state_ms - measured_verify_ms
    if verify_unbucketed_ms < 0.0:
        _fixed("timing_reconciliation")
    breakdown = VerifyStateBreakdown(
        timing.handoff_ms,
        timing.frame_read_ms,
        timing.ipc_prepare_ms,
        timing.contained_verifier_ms,
        timing.queue_state_ms,
        timing.integrity_ms,
        timing.close_ms,
        verify_unbucketed_ms,
    )
    ack_start = time.perf_counter()
    store = ClearanceCompositionStoreV2(path=database, config=composition_config)
    try:
        receiver = _SyntheticReceiver(composition_config)
        delivery = store.dispatch_outbox_batch("profile11-screen-receiver", receiver=receiver)
        if delivery is None or len(delivery.results) != SOURCE_AUTH_OPERATION_COUNT or receiver.calls != SOURCE_AUTH_OPERATION_COUNT or any(result.status != "ACKNOWLEDGED" for result in delivery.results):
            _fixed("ack_batch_shape")
        state = store.snapshot()
        if state["outbox_counts"] != {"READY": 0, "LEASED": 0, "ACKNOWLEDGED": expected_acknowledged_count, "DELIVERY_UNCONFIRMED": 0}:
            _fixed("ack_state_shape")
    finally:
        store.close()
    ack_ms = (time.perf_counter() - ack_start) * 1000.0
    for workspace in (source_workspace, verifier_workspace):
        try:
            if tuple(workspace.iterdir()):
                _fixed("workspace_changed")
        except OSError:
            _fixed("workspace_changed")
    total_ms = (time.perf_counter() - total_start) * 1000.0
    total_unbucketed_ms = total_ms - source_ms - verify_state_ms - ack_ms
    if total_unbucketed_ms < 0.0:
        _fixed("timing_total_reconciliation")
    return StageSample(source_ms, verify_state_ms, ack_ms, total_ms, breakdown, total_unbucketed_ms)


def _run_coordinator(run_root: Path) -> dict[str, Any]:
    source_workspace = run_root / "source-workspace"
    verifier_workspace = run_root / "verifier-workspace"
    state_workspace = run_root / "state"
    for workspace in (source_workspace, verifier_workspace, state_workspace):
        if not workspace.is_dir() or workspace.is_symlink() or tuple(workspace.iterdir()):
            _fixed("workspace_not_empty")
    report = validate_dependencies(
        source_workspace=source_workspace,
        verifier_workspace=verifier_workspace,
        state_workspace=state_workspace,
    )
    if not report.ready:
        return build_test_aggregate(completed_samples=0, error_code="dependency_unavailable", observer_status="observer_unavailable", disk_gate="observer_unavailable")
    queue_config = QueueConfig("queue-profile11-process", SOURCE_AUTH_OPERATION_COUNT, source_key_epoch=SOURCE_KEY_EPOCH)
    public_key = _load_synthetic_public_key()
    source_caller = Profile11SourceBoundaryCaller(
        SourceApplianceConfig(SOURCE_HOST, source_workspace, SOURCE_HOST_SIZE_BYTES, SOURCE_HOST_SHA256, 180.0)
    )
    source_config = SourceAuthVerifierConfig(
        queue_config=queue_config,
        executable_path=C_VERIFIER,
        executable_size_bytes=SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
        executable_sha256=SOURCE_AUTH_EXECUTABLE_SHA256,
        workspace=verifier_workspace,
        ml_dsa_87_public_key=public_key,
        timeout_seconds=30.0,
    )
    state_port = _ScreenStatePort()
    sample_number = 0

    def sample() -> StageSample:
        nonlocal sample_number
        sample_number += 1
        return _run_one_sample(
            root=state_workspace,
            source_workspace=source_workspace,
            verifier_workspace=verifier_workspace,
            source_caller=source_caller,
            queue_config=queue_config,
            source_config=source_config,
            state_port=state_port,
            expected_acknowledged_count=sample_number * SOURCE_AUTH_OPERATION_COUNT,
        )

    try:
        schedule = run_measurement_schedule_with_warmup(sample)
        timings = schedule.measured
        validate_topology(proof_count=1, operation_count=100, frame_count=1, verifier_batch_count=1, ack_count=100)
        return build_test_aggregate(completed_samples=len(timings), timings=timings, warmup=schedule.warmup, peak_job_commit_bytes=0, effective_cap_bytes=PROCESS_TREE_PEAK_CAP_BYTES, peak_active_processes=1, total_processes=1, observer_status="observer_unavailable", disk_gate="observer_unavailable")
    except CompletePathError as error:
        return build_test_aggregate(completed_samples=0, timings=(), error_code=str(error), observer_status="observer_unavailable", disk_gate="observer_unavailable")
    except BaseException:
        return build_test_aggregate(completed_samples=0, timings=(), error_code="coordinator_failure", observer_status="observer_unavailable", disk_gate="observer_unavailable")
    finally:
        del public_key, source_config, source_caller, queue_config, state_port


# Windows Job Object ABI used only by the parent launcher.
_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_STARTF_USESTDHANDLES = 0x00000100
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 0x102
_INFINITE = 0xFFFFFFFF
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOB_LIMIT_FLAGS = _JOB_OBJECT_LIMIT_ACTIVE_PROCESS | _JOB_OBJECT_LIMIT_JOB_MEMORY | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE


class _JobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimitInformation), ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JobBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class _SystemInfo(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD), ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD), ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID), ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", wintypes.DWORD), ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD), ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("StartupInfo", _StartupInfo), ("lpAttributeList", wintypes.LPVOID)]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


@dataclass(frozen=True, slots=True)
class CoordinatorRun:
    payload: bytes | None
    observation: JobObservation
    error_code: str | None


def _read_pipe(fd: int, cap: int, output: dict[str, bytes], key: str, failed: dict[str, str]) -> None:
    data = bytearray()
    try:
        while len(data) <= cap:
            chunk = os.read(fd, min(64 * 1024, cap + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > cap:
            failed.setdefault("code", "coordinator_output_cap")
        output[key] = bytes(data[: cap + 1])
    except BaseException:
        failed.setdefault("code", "coordinator_output_read")
    finally:
        try:
            os.close(fd)
        except OSError:
            failed.setdefault("code", "coordinator_output_close")


def _configure_kernel32(kernel32: Any) -> None:
    required = (
        "CreateJobObjectW", "SetInformationJobObject", "CreateProcessW", "AssignProcessToJobObject",
        "ResumeThread", "WaitForSingleObject", "TerminateProcess", "TerminateJobObject", "GetExitCodeProcess",
        "QueryInformationJobObject", "CloseHandle", "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute", "DeleteProcThreadAttributeList", "GetCurrentProcess", "GetSystemInfo",
    )
    if any(not hasattr(kernel32, name) for name in required):
        _fixed("outer_api_missing")
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR, ctypes.POINTER(_StartupInfo), ctypes.POINTER(_ProcessInformation)]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetSystemInfo.argtypes = [ctypes.POINTER(_SystemInfo)]
    kernel32.GetSystemInfo.restype = None
    kernel32.InitializeProcThreadAttributeList.argtypes = [wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.c_size_t, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
    kernel32.DeleteProcThreadAttributeList.restype = None


def _launch_coordinator(run_root: Path, timeout_seconds: float = COORDINATOR_TIMEOUT_SECONDS, *, executable: Path | None = None, arguments: tuple[str, ...] = (), on_assigned: Callable[[int], None] | None = None) -> CoordinatorRun:
    if os.name != "nt":
        _fixed("outer_windows_only")
    if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 30 * 60:
        _fixed("outer_timeout")
    if not run_root.is_absolute() or not run_root.is_dir():
        _fixed("outer_run_root")
    executable = executable or Path(sys.executable).resolve()
    if not executable.is_file():
        _fixed("outer_python")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _configure_kernel32(kernel32)
    system_info = _SystemInfo()
    kernel32.GetSystemInfo(ctypes.byref(system_info))
    page_size = int(system_info.dwPageSize)
    requested_cap = PROCESS_TREE_PEAK_CAP_BYTES
    effective_cap = effective_outer_cap(requested_cap, page_size)
    stdout_read = stdout_write = stderr_read = stderr_write = None
    job = process_handle = thread_handle = None
    job_assigned = False
    reader_threads: list[threading.Thread] = []
    output: dict[str, bytes] = {}
    failed: dict[str, str] = {}
    timed_out = False
    peak_commit = 0
    peak_active = 0
    total_processes = 0
    measurement_complete = False
    process_tree_complete = False
    cleanup_complete = True
    process_info = _ProcessInformation()
    attribute_list_initialized = False
    attribute_list = wintypes.LPVOID()
    try:
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        import msvcrt
        child_stdout = int(msvcrt.get_osfhandle(stdout_write))
        child_stderr = int(msvcrt.get_osfhandle(stderr_write))
        os.set_handle_inheritable(child_stdout, True)
        os.set_handle_inheritable(child_stderr, True)
        size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        if not size.value:
            _fixed("outer_attribute_size")
        storage = ctypes.create_string_buffer(size.value)
        attribute_list = ctypes.cast(storage, wintypes.LPVOID)
        if not kernel32.InitializeProcThreadAttributeList(attribute_list, 1, 0, ctypes.byref(size)):
            _fixed("outer_attribute_init")
        attribute_list_initialized = True
        handles = (wintypes.HANDLE * 2)(wintypes.HANDLE(child_stdout), wintypes.HANDLE(child_stderr))
        if not kernel32.UpdateProcThreadAttribute(attribute_list, 0, _PROC_THREAD_ATTRIBUTE_HANDLE_LIST, ctypes.cast(handles, wintypes.LPVOID), ctypes.sizeof(handles), None, None):
            _fixed("outer_attribute_update")
        startup = _StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = wintypes.HANDLE(0)
        startup.StartupInfo.hStdOutput = wintypes.HANDLE(child_stdout)
        startup.StartupInfo.hStdError = wintypes.HANDLE(child_stderr)
        startup.lpAttributeList = attribute_list
        command = subprocess.list2cmdline([
            str(executable), "-B", str(Path(__file__).resolve()), "--coordinator", "--run-root", str(run_root), *arguments,
        ])
        command_line = ctypes.create_unicode_buffer(command)
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            _fixed("outer_job_create")
        limits = _JobExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = _JOB_LIMIT_FLAGS
        limits.BasicLimitInformation.ActiveProcessLimit = OUTER_ACTIVE_PROCESS_LIMIT
        limits.JobMemoryLimit = effective_cap
        if not kernel32.SetInformationJobObject(job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits), ctypes.sizeof(limits)):
            _fixed("outer_job_limits")
        if not kernel32.CreateProcessW(
            str(executable), command_line, None, None, True,
            _CREATE_SUSPENDED | _CREATE_NO_WINDOW | _CREATE_UNICODE_ENVIRONMENT | _EXTENDED_STARTUPINFO_PRESENT,
            None, str(Path(__file__).resolve().parent), ctypes.cast(ctypes.byref(startup), ctypes.POINTER(_StartupInfo)), ctypes.byref(process_info),
        ):
            _fixed("outer_process_create")
        process_handle, thread_handle = process_info.hProcess, process_info.hThread
        if not kernel32.AssignProcessToJobObject(job, process_handle):
            _fixed("outer_job_assign")
        job_assigned = True
        if on_assigned is not None:
            try:
                on_assigned(int(process_info.dwProcessId))
            except BaseException:
                _fixed("outer_observer_start")
        resume_count = int(kernel32.ResumeThread(thread_handle))
        if resume_count in {0, 0xFFFFFFFF}:
            _fixed("outer_process_resume")
        os.close(stdout_write); stdout_write = None
        os.close(stderr_write); stderr_write = None
        reader_threads = [
            threading.Thread(target=_read_pipe, args=(stdout_read, COORDINATOR_STDOUT_CAP_BYTES, output, "stdout", failed), daemon=True),
            threading.Thread(target=_read_pipe, args=(stderr_read, COORDINATOR_STDERR_CAP_BYTES, output, "stderr", failed), daemon=True),
        ]
        stdout_read = stderr_read = None
        for reader in reader_threads:
            reader.start()
        deadline = time.monotonic() + timeout_seconds
        while True:
            current = _JobExtendedLimitInformation()
            accounting = _JobBasicAccountingInformation()
            if not kernel32.QueryInformationJobObject(job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(current), ctypes.sizeof(current), None):
                _fixed("outer_job_query")
            if not kernel32.QueryInformationJobObject(job, _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                _fixed("outer_accounting_query")
            peak_commit = max(peak_commit, int(current.PeakJobMemoryUsed))
            peak_active = max(peak_active, int(accounting.ActiveProcesses))
            total_processes = max(total_processes, int(accounting.TotalProcesses))
            if peak_commit >= OUTER_HARD_CAP_BYTES or peak_commit > effective_cap:
                _fixed("outer_memory_cap")
            wait = kernel32.WaitForSingleObject(process_handle, 50)
            if wait == _WAIT_OBJECT_0:
                break
            if wait != _WAIT_TIMEOUT:
                _fixed("outer_wait")
            if time.monotonic() >= deadline:
                timed_out = True
                if not kernel32.TerminateJobObject(job, 1):
                    _fixed("outer_timeout_terminate")
                if kernel32.WaitForSingleObject(process_handle, _INFINITE) != _WAIT_OBJECT_0:
                    _fixed("outer_timeout_wait")
                break
        for reader in reader_threads:
            reader.join(timeout=5.0)
        if any(reader.is_alive() for reader in reader_threads):
            _fixed("outer_output_read")
        final_info = _JobExtendedLimitInformation()
        final_accounting = _JobBasicAccountingInformation()
        if not kernel32.QueryInformationJobObject(job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(final_info), ctypes.sizeof(final_info), None):
            _fixed("outer_job_query")
        if not kernel32.QueryInformationJobObject(job, _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, ctypes.byref(final_accounting), ctypes.sizeof(final_accounting), None):
            _fixed("outer_accounting_query")
        peak_commit = max(peak_commit, int(final_info.PeakJobMemoryUsed))
        peak_active = max(peak_active, int(final_accounting.ActiveProcesses))
        total_processes = max(total_processes, int(final_accounting.TotalProcesses))
        observed_limit = int(final_info.JobMemoryLimit)
        observed_basic = int(final_info.BasicLimitInformation.ActiveProcessLimit)
        if int(final_info.BasicLimitInformation.LimitFlags) != _JOB_LIMIT_FLAGS or observed_limit != effective_cap or observed_basic != OUTER_ACTIVE_PROCESS_LIMIT:
            _fixed("outer_job_limits_readback")
        # A process handle can signal before Job accounting publishes the
        # final nested-job exit.  Wait for the accounting view to reach zero;
        # returning earlier would falsely claim complete-tree reaping.
        for _ in range(100):
            if int(final_accounting.ActiveProcesses) == 0:
                break
            time.sleep(0.01)
            if not kernel32.QueryInformationJobObject(job, _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, ctypes.byref(final_accounting), ctypes.sizeof(final_accounting), None):
                _fixed("outer_accounting_query")
            peak_active = max(peak_active, int(final_accounting.ActiveProcesses))
            total_processes = max(total_processes, int(final_accounting.TotalProcesses))
        process_tree_complete = total_processes >= 1 and int(final_accounting.ActiveProcesses) == 0
        measurement_complete = True
        cleanup_complete = process_tree_complete
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
            _fixed("outer_exit_code")
        if output.get("stderr", b""):
            error_code = "coordinator_stderr"
        elif timed_out:
            error_code = "outer_timeout"
        elif failed:
            error_code = failed.get("code", "outer_output")
        elif int(exit_code.value) != 0:
            error_code = "coordinator_failure"
        else:
            error_code = None
        payload = output.get("stdout", b"") if error_code is None else None
        observation = JobObservation(peak_commit, requested_cap, effective_cap, observed_limit, OUTER_ACTIVE_PROCESS_LIMIT, observed_basic, peak_active, total_processes, process_tree_complete, measurement_complete, cleanup_complete, timed_out)
        if error_code is None:
            validate_job_observation(observation)
        return CoordinatorRun(payload, observation, error_code)
    except CompletePathError as error:
        error_code = str(error)
        if process_handle:
            try:
                if job_assigned and job:
                    if not kernel32.TerminateJobObject(job, 1):
                        cleanup_complete = False
                elif not kernel32.TerminateProcess(process_handle, 1):
                    cleanup_complete = False
                kernel32.WaitForSingleObject(process_handle, _INFINITE)
            except BaseException:
                cleanup_complete = False
        observation = JobObservation(peak_commit, requested_cap, effective_cap, effective_cap, OUTER_ACTIVE_PROCESS_LIMIT, OUTER_ACTIVE_PROCESS_LIMIT, peak_active, total_processes, False, measurement_complete, cleanup_complete, timed_out)
        return CoordinatorRun(None, observation, error_code)
    finally:
        for reader in reader_threads:
            if reader.is_alive():
                reader.join(timeout=5.0)
        for fd in (stdout_read, stdout_write, stderr_read, stderr_write):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if attribute_list_initialized:
            try:
                kernel32.DeleteProcThreadAttributeList(attribute_list)
            except BaseException:
                pass
        for handle in (thread_handle, process_handle, job):
            if handle:
                try:
                    kernel32.CloseHandle(handle)
                except BaseException:
                    pass


def _parse_payload(payload: bytes | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fixed("coordinator_output")
    return _validate_aggregate_mapping(value)


def run_falsification_screen(*, observer: WindowsEtwFileWriteObserver | None = None) -> dict[str, Any]:
    observer = observer or WindowsEtwFileWriteObserver()
    capability = observer.probe()
    if capability.status != "observer_ready":
        error_code = capability.status if capability.status in {"observer_unavailable", "observer_incomplete"} else "observer_incomplete"
        return build_test_aggregate(completed_samples=0, error_code=error_code, observer_status=capability.status if capability.status in {"observer_unavailable", "observer_incomplete"} else "observer_incomplete", disk_gate=capability.status if capability.status in {"observer_unavailable", "observer_incomplete"} else "observer_incomplete")
    with tempfile.TemporaryDirectory(prefix="blind-profile11-screen-") as directory:
        run_root = Path(directory)
        source_workspace = run_root / "source-workspace"
        verifier_workspace = run_root / "verifier-workspace"
        state_workspace = run_root / "state"
        source_workspace.mkdir()
        verifier_workspace.mkdir()
        state_workspace.mkdir()
        report = validate_dependencies(source_workspace=source_workspace, verifier_workspace=verifier_workspace, state_workspace=state_workspace)
        if not report.ready:
            return build_test_aggregate(completed_samples=0, error_code="dependency_unavailable", observer_status="observer_unavailable", disk_gate="observer_unavailable")
        def start_observation(pid: int) -> None:
            started = observer.start(pid)
            if started.status != "observer_ready":
                _fixed("outer_observer_start")

        run = _launch_coordinator(run_root, on_assigned=start_observation)
        observed_after = observer.stop()
        disk_gate = evaluate_disk_gate(observed_after, state_workspace=state_workspace)
        try:
            payload = _parse_payload(run.payload)
        except CompletePathError:
            payload = None
        if payload is None:
            result = build_test_aggregate(completed_samples=0, error_code=run.error_code or "coordinator_output", peak_job_commit_bytes=run.observation.peak_job_commit_bytes, effective_cap_bytes=run.observation.effective_cap_bytes, peak_active_processes=run.observation.peak_active_processes, total_processes=run.observation.total_processes, observer_status=observed_after.status, disk_gate=disk_gate)
        else:
            payload["peak_job_commit_bytes"] = run.observation.peak_job_commit_bytes
            payload["effective_cap_bytes"] = run.observation.effective_cap_bytes
            payload["peak_active_processes"] = run.observation.peak_active_processes
            payload["total_processes"] = run.observation.total_processes
            payload["observer_status"] = observed_after.status
            payload["disk_gate"] = disk_gate
            if run.error_code is not None:
                payload["status"] = "failed"
                payload["error_code"] = run.error_code
            elif observed_after.status != "observer_ready" or disk_gate != "disk_gate_pass":
                payload["status"] = "failed"
                payload["error_code"] = observed_after.status if observed_after.status in {"observer_unavailable", "observer_incomplete"} else disk_gate
            _validate_aggregate_mapping(payload)
            result = payload
        return result


def prepare_report() -> dict[str, Any]:
    report = validate_dependencies()
    return {
        "schema": PROFILE_SCHEMA,
        "mode": "prepare",
        "launches": 0,
        "missing_count": len(report.missing),
        "mismatch_count": len(report.mismatched),
        "missing": list(report.missing),
        "mismatched": list(report.mismatched),
        "full_mode": "available" if report.ready else "fail_closed",
        "proofSuiteId": None,
        "production_usable": False,
        "activation": False,
    }


def _probe_tree_child(sleep_seconds: float = 0.15) -> int:
    if os.name != "nt":
        return 0
    time.sleep(sleep_seconds)
    return 0


def _probe_tree_coordinator(run_root: Path, sleep_seconds: float) -> dict[str, Any]:
    del run_root
    child = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "--probe-grandchild", str(sleep_seconds)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    child.wait(timeout=max(5.0, sleep_seconds + 2.0))
    return build_test_aggregate(completed_samples=0, error_code="probe_only", observer_status="observer_unavailable", disk_gate="observer_unavailable")


def main(argv: list[str] | None = None) -> int:
    parser = __import__("argparse").ArgumentParser(add_help=False)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--screen", action="store_true")
    parser.add_argument("--coordinator", action="store_true")
    parser.add_argument("--probe-coordinator", type=float)
    parser.add_argument("--probe-grandchild", type=float)
    parser.add_argument("--run-root")
    args = parser.parse_args(argv)
    try:
        if args.prepare:
            print(json.dumps(prepare_report(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.probe_grandchild is not None:
            return _probe_tree_child(args.probe_grandchild)
        if args.probe_coordinator is not None:
            if not args.run_root:
                _fixed("outer_run_root")
            print(_aggregate_json(_probe_tree_coordinator(Path(args.run_root), args.probe_coordinator)), end="")
            return 0
        if args.coordinator:
            if not args.run_root:
                _fixed("outer_run_root")
            value = _run_coordinator(Path(args.run_root))
            print(_aggregate_json(value), end="")
            return 0
        if args.screen:
            value = run_falsification_screen()
            print(_aggregate_json(value), end="")
            if value["status"] == "complete" and value["error_code"] is None and value["completed_samples"] == MEASURED_SAMPLE_COUNT and value["observer_status"] == "observer_ready" and value["disk_gate"] == "disk_gate_pass":
                return 0
            return 1
        _fixed("mode_required")
    except CompletePathError as error:
        print(json.dumps({"schema": PROFILE_SCHEMA, "mode": "error", "error_code": str(error), "proofSuiteId": None, "production_usable": False, "activation": False}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "C_BUILD", "C_HEAD", "C_RANGE_LIBRARY", "C_REPO", "C_SOURCE_LIBRARY", "C_VERIFIER", "C_TREE",
    "CompletePathError", "DependencyReport", "FileWriteEvent", "FileWriteObservation", "GitPin",
    "JobObservation", "MANIFEST_PATH", "MEASURED_SAMPLE_COUNT", "OUTER_ACTIVE_PROCESS_LIMIT",
    "OUTER_HARD_CAP_BYTES", "PROFILE_ID", "PROFILE_SCHEMA", "PRODUCER_EXECUTABLE", "PRODUCER_EXECUTABLE_SHA256", "PRODUCER_EXECUTABLE_SIZE_BYTES", "PRODUCER_HEAD", "PRODUCER_REPO", "PRODUCER_TREE", "MeasurementSchedule", "StageSample", "VerifyStateBreakdown", "WindowsEtwFileWriteObserver", "WindowsEtwWriteTraceBackend",
    "build_test_aggregate", "configured_state_allowlist", "effective_outer_cap", "evaluate_disk_gate",
    "nearest_rank_p95", "prepare_report", "run_falsification_screen", "run_measurement_schedule", "run_measurement_schedule_with_warmup", "validate_dependencies",
    "validate_job_observation", "validate_topology",
)
