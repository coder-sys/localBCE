"""Profile 11 complete-path containment and falsification screen.

This is a test-only coordinator.  The parent process creates the coordinator
suspended, assigns it to one outer Windows Job, and resumes it only after the
assignment succeeds.  The coordinator owns the volatile source frame and
Queue/State transaction; it emits only a fixed aggregate after every
sensitive buffer is closed or wiped.  No production, activation, or complete
zero-PHI observation claim is made here.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Final, Iterable, Protocol
import uuid

# Execution-only Queue source binding.  Library imports deliberately retain the
# checkout selected by the test collector; only direct script execution binds
# the coordinator to the exact clean source set reviewed by the local manifest.
_QUEUE_SOURCE_PATH: Path | None = None
_QUEUE_SOURCE_BOUND = False
_QUEUE_CACHE_PREFIX: Path | None = None
_QUEUE_EXPECTED_APP_BLOBS: dict[str, str] = {}
_QUEUE_BINDING_SCHEMA = "BL/NATIVE-V3/PROFILE11-COMPLETE-PATH/v1"
_QUEUE_MODULE_SOURCES: Final[dict[str, Path]] = {
    "app": Path("app/__init__.py"),
    "app.minimal_clearance_composition": Path("app/minimal_clearance_composition.py"),
    "app.minimal_clearance_composition_independent": Path("app/minimal_clearance_composition_independent.py"),
    "app.minimal_clearance_resource_limits": Path("app/minimal_clearance_resource_limits.py"),
    "app.minimal_clearance_source_auth_verifier_adapter": Path("app/minimal_clearance_source_auth_verifier_adapter.py"),
    "app.minimal_clearance_verification_queue": Path("app/minimal_clearance_verification_queue.py"),
    "app.minimal_clearance_verification_queue_independent": Path("app/minimal_clearance_verification_queue_independent.py"),
    "app.minimal_clearance_verification_runtime": Path("app/minimal_clearance_verification_runtime.py"),
    "app.minimal_clearance_verifier_process": Path("app/minimal_clearance_verifier_process.py"),
}


def _queue_binding_failure() -> None:
    print(json.dumps({"schema": _QUEUE_BINDING_SCHEMA, "mode": "error", "error_code": "queue_source_binding", "proofSuiteId": None, "production_usable": False, "activation": False}, sort_keys=True, separators=(",", ":")))
    raise SystemExit(2)


def _binding_manifest_path() -> Path:
    return Path(__file__).resolve().with_name("profile11_complete_path_manifest.json")


def _regular_source_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    reparse = int(getattr(info, "st_file_attributes", 0)) & 0x00000400
    return stat.S_ISREG(info.st_mode) and not path.is_symlink() and not reparse


def _load_manifest_source_binding(*, fail_closed: bool = True) -> tuple[Path, dict[str, str]]:
    def invalid() -> None:
        if fail_closed:
            _queue_binding_failure()
        raise ValueError("queue_source_binding")

    manifest_path = _binding_manifest_path()
    if not _regular_source_file(manifest_path):
        invalid()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("schema") != "BL/NATIVE-V3/PROFILE11-COMPLETE-PATH-MANIFEST/v2":
            invalid()
        binding = manifest.get("python_source_binding")
        if not isinstance(binding, dict):
            invalid()
        if (
            binding.get("canonical_package") != "app"
            or binding.get("content_hash") != "git-blob-sha1"
            or binding.get("source_only_cache_handling") is not True
            or binding.get("fallback") is not False
            or binding.get("git_clean_required") is not True
        ):
            invalid()
        source_root_record = binding.get("source_root")
        if not isinstance(source_root_record, dict) or set(source_root_record) != {"relative_to", "relative_path", "max_depth"}:
            invalid()
        relative_to = source_root_record.get("relative_to")
        relative_text = source_root_record.get("relative_path")
        max_depth = source_root_record.get("max_depth")
        if relative_to != "manifest_parent" or relative_text != "." or max_depth != 0:
            invalid()
        relative = PurePosixPath(relative_text)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            invalid()
        relative_path = Path(*relative.parts) if relative.parts else Path(".")
        source_root = (manifest_path.parent / relative_path).resolve()
        required_modules = binding.get("required_modules")
        if not isinstance(required_modules, dict) or set(required_modules) != set(_QUEUE_MODULE_SOURCES):
            invalid()
        expected_blobs: dict[str, str] = {}
        for name, relative_source in _QUEUE_MODULE_SOURCES.items():
            record = required_modules.get(name)
            if not isinstance(record, dict) or set(record) != {"path", "git_blob"}:
                invalid()
            if record.get("path") != relative_source.as_posix():
                invalid()
            blob = record.get("git_blob")
            if not isinstance(blob, str) or len(blob) != 40 or blob != blob.lower() or any(character not in "0123456789abcdef" for character in blob):
                invalid()
            expected_blobs[name] = blob
        if "queue" in manifest.get("git_pins", {}):
            invalid()
        return source_root, expected_blobs
    except SystemExit:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        invalid()


def _normalize_source_line_endings(data: bytes) -> bytes | None:
    normalized = data.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        return None
    return normalized


def _git_canonical_sources(root: Path, expected_blobs: dict[str, str]) -> dict[str, bytes] | None:
    names = tuple(_QUEUE_MODULE_SOURCES)
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "cat-file",
                "--batch",
            ],
            input=b"".join((expected_blobs[name] + "\n").encode("ascii") for name in names),
            capture_output=True,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    output = result.stdout
    offset = 0
    canonical_sources: dict[str, bytes] = {}
    for name in names:
        line_end = output.find(b"\n", offset)
        if line_end < 0:
            return None
        fields = output[offset:line_end].split()
        expected_blob = expected_blobs[name].encode("ascii")
        if len(fields) != 3 or fields[0] != expected_blob or fields[1] != b"blob":
            return None
        try:
            byte_count = int(fields[2])
        except ValueError:
            return None
        offset = line_end + 1
        end = offset + byte_count
        if end >= len(output) or output[end:end + 1] != b"\n":
            return None
        canonical = output[offset:end]
        header = b"blob " + str(len(canonical)).encode("ascii") + b"\0"
        if hashlib.sha1(header + canonical).hexdigest() != expected_blobs[name]:
            return None
        canonical_sources[name] = canonical
        offset = end + 1
    return canonical_sources if offset == len(output) else None


def _git_filter_attributes_are_unset(root: Path, relative_sources: Iterable[Path]) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "check-attr", "--all", "--", *(path.as_posix() for path in relative_sources)],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        fields = line.split(": ", 2)
        if len(fields) == 3 and fields[1] == "filter" and fields[2] not in {"unspecified", "unset"}:
            return False
    return True


def _source_bytes_match(path: Path, canonical: bytes) -> bool:
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    normalized_raw = _normalize_source_line_endings(raw)
    normalized_canonical = _normalize_source_line_endings(canonical)
    return normalized_raw is not None and normalized_canonical is not None and normalized_raw == normalized_canonical


def _validate_source_checkout(root: Path, expected_blobs: dict[str, str], *, fail_closed: bool = True) -> None:
    def invalid() -> None:
        if fail_closed:
            _queue_binding_failure()
        raise ValueError("queue_source_binding")

    if not root.is_absolute() or not root.is_dir() or root.is_symlink() or not _regular_source_file(root / "profile11_complete_path.py"):
        invalid()
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        invalid()
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != root or status.returncode != 0 or status.stdout.strip() != "":
        invalid()
    if not _git_filter_attributes_are_unset(root, _QUEUE_MODULE_SOURCES.values()):
        invalid()
    canonical_sources = _git_canonical_sources(root, expected_blobs)
    if canonical_sources is None:
        invalid()
    for name, relative_source in _QUEUE_MODULE_SOURCES.items():
        path = root / relative_source
        if not _regular_source_file(path) or not _source_bytes_match(path, canonical_sources[name]):
            invalid()


def _run_queue_binding_preflight() -> None:
    global _QUEUE_CACHE_PREFIX, _QUEUE_SOURCE_PATH, _QUEUE_EXPECTED_APP_BLOBS
    try:
        if any(name == "app" or name.startswith("app.") for name in sys.modules):
            _queue_binding_failure()
        source_root, expected_blobs = _load_manifest_source_binding()
        _validate_source_checkout(source_root, expected_blobs)
        _QUEUE_SOURCE_PATH = source_root
        _QUEUE_EXPECTED_APP_BLOBS = expected_blobs
        cache_prefix = Path(tempfile.gettempdir()) / ("blind-queue-pycache-" + uuid.uuid4().hex)
        if cache_prefix.exists() or not cache_prefix.is_absolute():
            _queue_binding_failure()
        sys.dont_write_bytecode = True
        sys.pycache_prefix = str(cache_prefix)
        _QUEUE_CACHE_PREFIX = cache_prefix
        queue_root = (_QUEUE_SOURCE_PATH / "app").resolve()
        if not queue_root.is_dir() or queue_root.is_symlink():
            _queue_binding_failure()
        sys.path.insert(0, str(_QUEUE_SOURCE_PATH))
    except SystemExit:
        raise
    except BaseException:
        _queue_binding_failure()


def _finalize_queue_binding() -> None:
    global _QUEUE_SOURCE_BOUND
    if _QUEUE_SOURCE_PATH is None or not _QUEUE_EXPECTED_APP_BLOBS:
        _queue_binding_failure()
    queue_root = (_QUEUE_SOURCE_PATH / "app").resolve()
    cache_prefix = _QUEUE_CACHE_PREFIX
    app_package = sys.modules.get("app")
    if (
        cache_prefix is None
        or cache_prefix.exists()
        or sys.pycache_prefix != str(cache_prefix)
        or sys.dont_write_bytecode is not True
        or app_package is None
    ):
        _queue_binding_failure()
    if tuple(Path(item).resolve() for item in getattr(app_package, "__path__", ())) != (queue_root,):
        _queue_binding_failure()
    if not _git_filter_attributes_are_unset(_QUEUE_SOURCE_PATH, _QUEUE_MODULE_SOURCES.values()):
        _queue_binding_failure()
    canonical_sources = _git_canonical_sources(_QUEUE_SOURCE_PATH, _QUEUE_EXPECTED_APP_BLOBS)
    if canonical_sources is None:
        _queue_binding_failure()
    loaded = {name for name in sys.modules if name == "app" or name.startswith("app.")}
    if loaded != set(_QUEUE_MODULE_SOURCES):
        _queue_binding_failure()
    for name, relative_source in _QUEUE_MODULE_SOURCES.items():
        module = sys.modules.get(name)
        expected_source = (_QUEUE_SOURCE_PATH / relative_source).resolve()
        spec = getattr(module, "__spec__", None)
        loader = getattr(spec, "loader", None)
        source_file = getattr(module, "__file__", None)
        cached_file = getattr(module, "__cached__", None)
        if (
            module is None
            or not expected_source.is_file()
            or not _regular_source_file(expected_source)
            or not _source_bytes_match(expected_source, canonical_sources[name])
            or source_file is None
            or Path(source_file).resolve() != expected_source
            or spec is None
            or spec.origin is None
            or Path(spec.origin).resolve() != expected_source
            or not isinstance(loader, importlib.machinery.SourceFileLoader)
            or Path(loader.path).resolve() != expected_source
            or cached_file is None
        ):
            _queue_binding_failure()
        expected_cache = Path(importlib.util.cache_from_source(str(expected_source))).resolve()
        if Path(cached_file).resolve() != expected_cache or cache_prefix not in expected_cache.parents or expected_cache.exists():
            _queue_binding_failure()
    import app.minimal_clearance_composition as _composition
    import app.minimal_clearance_source_auth_verifier_adapter as _source_auth
    import app.minimal_clearance_verification_queue as _queue
    import app.minimal_clearance_verification_runtime as _runtime
    if not (
        _queue.QueueConfig is _source_auth.QueueConfig is _runtime.QueueConfig
        and _queue.IssuedVerificationBatch is _source_auth.IssuedVerificationBatch is _runtime.IssuedVerificationBatch
        and _queue.VolatileProofHandoff is _source_auth.VolatileProofHandoff is _runtime.VolatileProofHandoff
        and _source_auth.SourceAuthVerifierConfig is _runtime.SourceAuthVerifierConfig
        and _composition.CompositionConfigV2 is _runtime.CompositionConfigV2
        and _composition.StateDispositionControl is _runtime.StateDispositionControl
    ):
        _queue_binding_failure()
    _QUEUE_SOURCE_BOUND = True


if __name__ == "__main__":
    _run_queue_binding_preflight()

def _import_queue_dependencies() -> tuple[Any, ...]:
    import app.minimal_clearance_composition as imported_composition
    import app.minimal_clearance_composition_independent
    import app.minimal_clearance_source_auth_verifier_adapter as imported_source_auth_adapter
    from app.minimal_clearance_composition import StateDispositionControl as imported_state_control
    from app.minimal_clearance_composition import build_synthetic_acknowledgment as imported_build_ack
    from app.minimal_clearance_resource_limits import ADMISSION_CAP_BYTES as imported_admission_cap
    from app.minimal_clearance_resource_limits import PROCESS_TREE_PEAK_CAP_BYTES as imported_tree_cap
    from app.minimal_clearance_source_auth_verifier_adapter import ML_DSA_87_PUBLIC_KEY_BYTES as imported_key_bytes
    from app.minimal_clearance_source_auth_verifier_adapter import SOURCE_AUTH_EXECUTABLE_SHA256 as imported_verifier_sha256
    from app.minimal_clearance_source_auth_verifier_adapter import SOURCE_AUTH_EXECUTABLE_SIZE_BYTES as imported_verifier_size
    from app.minimal_clearance_source_auth_verifier_adapter import SourceAuthVerifierConfig as imported_source_config
    from app.minimal_clearance_verification_queue import IssuedVerificationBatch as imported_issued_batch
    from app.minimal_clearance_verification_queue import OperationTemplate as imported_operation_template
    from app.minimal_clearance_verification_queue import QueueConfig as imported_queue_config
    from app.minimal_clearance_verification_queue import VolatileProofHandoff as imported_handoff
    from app.minimal_clearance_verification_queue import _build_statement as imported_build_statement
    from app.minimal_clearance_verification_queue import _compute_batch_root_from_refs as imported_batch_root
    from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime as imported_runtime
    return (
        imported_composition, imported_source_auth_adapter,
        imported_state_control, imported_build_ack, imported_admission_cap, imported_tree_cap,
        imported_key_bytes, imported_verifier_sha256, imported_verifier_size, imported_source_config,
        imported_issued_batch, imported_operation_template, imported_queue_config, imported_handoff,
        imported_build_statement, imported_batch_root, imported_runtime,
    )


if __name__ == "__main__":
    try:
        (
            composition, source_auth_adapter, StateDispositionControl,
            build_synthetic_acknowledgment, ADMISSION_CAP_BYTES, PROCESS_TREE_PEAK_CAP_BYTES,
            ML_DSA_87_PUBLIC_KEY_BYTES, SOURCE_AUTH_EXECUTABLE_SHA256, SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
            SourceAuthVerifierConfig, IssuedVerificationBatch, OperationTemplate, QueueConfig,
            VolatileProofHandoff, _build_statement, _compute_batch_root_from_refs,
            MinimalClearanceVerificationRuntime,
        ) = _import_queue_dependencies()
        _finalize_queue_binding()
    except SystemExit:
        raise
    except BaseException:
        _queue_binding_failure()
else:
    (
        composition, source_auth_adapter, StateDispositionControl,
        build_synthetic_acknowledgment, ADMISSION_CAP_BYTES, PROCESS_TREE_PEAK_CAP_BYTES,
        ML_DSA_87_PUBLIC_KEY_BYTES, SOURCE_AUTH_EXECUTABLE_SHA256, SOURCE_AUTH_EXECUTABLE_SIZE_BYTES,
        SourceAuthVerifierConfig, IssuedVerificationBatch, OperationTemplate, QueueConfig,
        VolatileProofHandoff, _build_statement, _compute_batch_root_from_refs,
        MinimalClearanceVerificationRuntime,
    ) = _import_queue_dependencies()
from profile11_source_boundary import (
    Profile11SourceBoundaryCaller,
    SourceApplianceConfig,
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

QUEUE_REPO: Final[Path] = Path(__file__).resolve().parent

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
STATE_SQLITE_JOURNAL_MODE: Final[str] = "delete"
STATE_SQLITE_JOURNAL_MODES: Final[frozenset[str]] = frozenset({"delete", "wal"})
STATE_SQLITE_RUNTIME_LOCK_NAME: Final[str] = "state.sqlite.runtime-lock"
SOURCE_KEY_EPOCH: Final[int] = 0x0102_0304_0506_0708
PUBLIC_KEY_BYTES: Final[int] = ML_DSA_87_PUBLIC_KEY_BYTES
PUBLIC_KEY_SHA256: Final[str] = "3D1F0F47DF60B4E2F31F82A99E32B42776837D974CF798CCFDAD98D617026F32"
_SYNTHETIC_FIXTURE_RELATIVE_PATH: Final[Path] = Path("tests") / "test_profile11_source_boundary.py"
# The current fixture source is 27,438 bytes; this bounded ceiling permits small test-file
# growth while preventing an unbounded source read at the trust boundary.
_SYNTHETIC_FIXTURE_MAX_BYTES: Final[int] = 128 * 1024
AGGREGATE_ERROR_CODES: Final[frozenset[str]] = frozenset({
    "dependency_unavailable", "coordinator_failure", "coordinator_output",
    "coordinator_stderr", "coordinator_output_cap", "coordinator_output_read",
    "coordinator_output_close", "outer_timeout", "outer_job_assign",
    "outer_observer_start", "probe_only",
    "observer_unavailable", "observer_incomplete", "unauthorized_write",
    "state_durability_configuration", "state_durability_readback",
    "outer_process_limit", "outer_process_limit_configuration", "outer_cleanup",
    "outer_observation_shape", "outer_cap_configuration", "outer_cap_invalid", "outer_cap_readback",
    "outer_memory_cap", "outer_process_limit_readback", "outer_process_lineage",
    "outer_measurement_incomplete", "outer_measurement_missing", "resource_payload_missing",
    "aggregate_p95_target",
    "product_target_exceeded", "runtime_restart", "runtime_restart_database", "timing_ack_reconciliation",
})

FIXED_QUALIFICATION_FLAGS: Final[tuple[str, ...]] = (
    "nonactivating",
    "synthetic_receiver",
    "synthetic_source_authority",
    "timing_memory_only",
)
OBSERVER_DIAGNOSTIC_SCHEMA: Final[str] = "BL/NATIVE-V3/PROFILE11-OBSERVER-CAPABILITY-DIAGNOSTIC/v1"
RESOURCE_OBSERVATION_SCHEMA: Final[str] = "BL/NATIVE-V3/PROFILE11-RESOURCE-OBSERVATION/v1"
ACTIVE_PROCESS_METRIC_SEMANTICS: Final[str] = "sampled_maximum_lower_bound_not_exact_high_water_mark"
ACTIVE_PROCESS_LIMIT_SEMANTICS: Final[str] = "os_enforced_job_object_limit"
TOTAL_PROCESS_METRIC_SEMANTICS: Final[str] = "os_cumulative_total_processes"
_OBSERVER_DIAGNOSTIC_REASON_ORDER: Final[tuple[str, ...]] = (
    "observer_non_windows",
    "observer_pointer_width",
    "observer_api_unavailable",
    "observer_api_failure",
    "observer_provider_query_failure",
    "observer_provider_missing",
    "observer_schema_query_failure",
    "observer_schema_incomplete",
    "observer_privilege_query_failure",
    "observer_privilege_api_failure",
    "observer_privilege_absent",
    "observer_privilege_present_disabled",
    "observer_privilege_unavailable",
    "observer_lineage_api_failure",
    "observer_lineage_api_unavailable",
    "observer_loss_api_failure",
    "observer_loss_api_unavailable",
)
_OBSERVER_DIAGNOSTIC_REASON_CODES: Final[frozenset[str]] = frozenset(_OBSERVER_DIAGNOSTIC_REASON_ORDER)
_OBSERVER_PRIVILEGE_STATES: Final[frozenset[str]] = frozenset({
    "enabled", "present_disabled", "absent", "api_failure", "unknown",
})
_OBSERVER_EXECUTION_CONTEXTS: Final[frozenset[str]] = frozenset({
    "current_process_token_se_system_profile_enabled",
    "current_process_token_builtin_alias_544",
    "current_process_token_builtin_alias_559",
    "unavailable", "api_failure", "unknown",
})
_OBSERVER_SUPPORTED_EXECUTION_CONTEXTS: Final[frozenset[str]] = frozenset({
    "current_process_token_se_system_profile_enabled",
    "current_process_token_builtin_alias_544",
    "current_process_token_builtin_alias_559",
})


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
        FilePin("c_verifier", C_VERIFIER, SOURCE_AUTH_EXECUTABLE_SIZE_BYTES, SOURCE_AUTH_EXECUTABLE_SHA256.hex().upper()),
        FilePin("c_source_library", C_SOURCE_LIBRARY, C_SOURCE_LIBRARY_SIZE_BYTES, C_SOURCE_LIBRARY_SHA256),
        FilePin("c_range_library", C_RANGE_LIBRARY, C_RANGE_LIBRARY_SIZE_BYTES, C_RANGE_LIBRARY_SHA256),
        FilePin("source_host", SOURCE_HOST, SOURCE_HOST_SIZE_BYTES, SOURCE_HOST_SHA256.hex().upper()),
    )


def _git_pins() -> tuple[GitPin, ...]:
    return (
        GitPin("producer_repo", PRODUCER_REPO, PRODUCER_HEAD, PRODUCER_TREE),
        GitPin("source_repo", SOURCE_REPO, SOURCE_HEAD, SOURCE_TREE),
        GitPin("c_repo", C_REPO, C_HEAD, C_TREE),
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


def _check_python_source_binding_pin(missing: list[str], mismatched: list[str]) -> None:
    try:
        source_root, expected_blobs = _load_manifest_source_binding(fail_closed=False)
        _validate_source_checkout(source_root, expected_blobs, fail_closed=False)
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        mismatched.append("queue_source_binding")


def _load_synthetic_public_key() -> bytes:
    """Parse the E2E-owned fixture source without importing the test module."""

    fixture_path = Path(__file__).resolve().parent / _SYNTHETIC_FIXTURE_RELATIVE_PATH
    try:
        if (
            not fixture_path.is_file()
            or fixture_path.is_symlink()
            or fixture_path.stat().st_size > _SYNTHETIC_FIXTURE_MAX_BYTES
        ):
            _fixed("public_key_missing")
        with fixture_path.open("rb") as stream:
            handle_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(handle_stat.st_mode):
                _fixed("public_key_missing")
            source_bytes = stream.read(_SYNTHETIC_FIXTURE_MAX_BYTES + 1)
        if len(source_bytes) > _SYNTHETIC_FIXTURE_MAX_BYTES:
            _fixed("public_key_missing")
        source = source_bytes.decode("utf-8")
        tree = ast.parse(source, filename=str(fixture_path), mode="exec")
        declarations = [
            node
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            and (
                any(isinstance(target, ast.Name) and target.id == "SOURCE_TEST_PUBLIC_KEY" for target in getattr(node, "targets", ()))
                or (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "SOURCE_TEST_PUBLIC_KEY")
                or (isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == "SOURCE_TEST_PUBLIC_KEY")
            )
        ]
        if len(declarations) != 1:
            _fixed("public_key_missing")
        declaration = declarations[0]
        value_node = declaration.value
        if (
            not isinstance(declaration, ast.Assign)
            or len(declaration.targets) != 1
            or not isinstance(declaration.targets[0], ast.Name)
            or declaration.targets[0].id != "SOURCE_TEST_PUBLIC_KEY"
            or not isinstance(value_node, ast.Call)
            or not isinstance(value_node.func, ast.Attribute)
            or not isinstance(value_node.func.value, ast.Name)
            or value_node.func.value.id != "bytes"
            or value_node.func.attr != "fromhex"
            or len(value_node.args) != 1
            or value_node.keywords
            or not isinstance(value_node.args[0], ast.Constant)
            or not isinstance(value_node.args[0].value, str)
        ):
            _fixed("public_key_missing")
        value = bytes.fromhex(value_node.args[0].value)
    except CompletePathError:
        raise
    except (OSError, UnicodeError, SyntaxError, ValueError, TypeError):
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
    _check_python_source_binding_pin(missing, mismatched)
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
    _validate_job_observation_safety(observation)
    if observation.total_processes < 1 or observation.peak_active_processes < 1 or observation.peak_active_processes > observation.total_processes:
        _fixed("outer_process_lineage")
    if observation.timed_out:
        _fixed("outer_timeout")
    if observation.measurement_complete is not True:
        _fixed("outer_measurement_incomplete")
    if observation.process_tree_complete is not True or observation.cleanup_complete is not True:
        _fixed("outer_cleanup")


def _validate_job_observation_safety(observation: JobObservation) -> None:
    if type(observation) is not JobObservation:
        _fixed("outer_observation_shape")
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
    if any(type(value) is not bool for value in (observation.process_tree_complete, observation.measurement_complete, observation.cleanup_complete, observation.timed_out)):
        _fixed("outer_observation_shape")
    if observation.requested_cap_bytes != PROCESS_TREE_PEAK_CAP_BYTES:
        _fixed("outer_cap_configuration")
    if observation.requested_cap_bytes >= OUTER_HARD_CAP_BYTES:
        _fixed("outer_cap_invalid")
    if observation.cap_readback_bytes != observation.effective_cap_bytes:
        _fixed("outer_cap_readback")
    if observation.active_process_limit_readback != observation.active_process_limit:
        _fixed("outer_process_limit_readback")
    if observation.active_process_limit != OUTER_ACTIVE_PROCESS_LIMIT or observation.active_process_limit_readback != OUTER_ACTIVE_PROCESS_LIMIT:
        _fixed("outer_process_limit_configuration")
    if observation.measurement_complete is True and observation.peak_job_commit_bytes <= 0:
        _fixed("outer_measurement_missing")
    if observation.peak_job_commit_bytes >= OUTER_HARD_CAP_BYTES or observation.peak_job_commit_bytes > observation.effective_cap_bytes:
        _fixed("outer_memory_cap")
    if observation.peak_active_processes > OUTER_ACTIVE_PROCESS_LIMIT:
        _fixed("outer_process_limit")
    if observation.peak_active_processes > observation.total_processes:
        _fixed("outer_process_lineage")


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

    def builtin_alias_state(self, rid: int) -> str:
        if type(rid) is not int or rid not in {544, 559}:
            return "api_failure"
        authority = _EtwSidIdentifierAuthority((0, 0, 0, 0, 0, 5))
        sid = ctypes.c_void_p()
        if not self.advapi32.AllocateAndInitializeSid(ctypes.byref(authority), 2, 32, rid, 0, 0, 0, 0, 0, 0, ctypes.byref(sid)):
            return "api_failure"
        try:
            member = wintypes.BOOL(False)
            if not self.advapi32.CheckTokenMembership(None, sid, ctypes.byref(member)):
                return "api_failure"
            return "present" if member.value else "absent"
        finally:
            self.advapi32.FreeSid(sid)

    def has_builtin_alias(self, rid: int) -> bool:
        return self.builtin_alias_state(rid) == "present"

    def profile_privilege_state(self) -> str:
        token = wintypes.HANDLE()
        if not self.advapi32.OpenProcessToken(self.kernel32.GetCurrentProcess(), _ETW_TOKEN_QUERY, ctypes.byref(token)):
            return "api_failure"
        result = "api_failure"
        try:
            size = ctypes.c_ulong(0)
            if not self.advapi32.GetTokenInformation(token, _ETW_TOKEN_PRIVILEGES, None, 0, ctypes.byref(size)):
                if ctypes.get_last_error() == _ETW_ERROR_INSUFFICIENT_BUFFER and size.value and size.value <= 1024 * 1024:
                    storage = ctypes.create_string_buffer(size.value)
                    if self.advapi32.GetTokenInformation(token, _ETW_TOKEN_PRIVILEGES, storage, size.value, ctypes.byref(size)):
                        target = _EtwLuid()
                        if self.advapi32.LookupPrivilegeValueW(None, "SeSystemProfilePrivilege", ctypes.byref(target)):
                            raw = bytes(storage)[: int(size.value)]
                            if len(raw) >= 4:
                                count = int.from_bytes(raw[:4], "little")
                                if count <= (len(raw) - 4) // 12:
                                    result = "absent"
                                    for index in range(count):
                                        offset = 4 + index * 12
                                        if raw[offset:offset + 8] == bytes(target):
                                            attributes = int.from_bytes(raw[offset + 8:offset + 12], "little")
                                            result = "enabled" if attributes & _ETW_SE_PRIVILEGE_ENABLED else "present_disabled"
                                            break
        finally:
            if not self.kernel32.CloseHandle(token):
                result = "api_failure"
        return result

    def has_enabled_profile_privilege(self) -> bool:
        return self.profile_privilege_state() == "enabled"

    def execution_context(self) -> ObserverExecutionEvidence:
        privilege_state = self.profile_privilege_state()
        if privilege_state in {"enabled", "api_failure"}:
            return _observer_execution_evidence(privilege_state=privilege_state)
        alias_544 = self.builtin_alias_state(544)
        alias_559 = self.builtin_alias_state(559)
        return _observer_execution_evidence(
            privilege_state=privilege_state,
            alias_544=alias_544,
            alias_559=alias_559,
        )

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
            execution_method = getattr(api, "execution_context", None)
            if callable(execution_method):
                execution = execution_method()
                privilege_available = execution.execution_context in _OBSERVER_SUPPORTED_EXECUTION_CONTEXTS
            else:
                privilege_available = bool(api.has_enabled_profile_privilege() or api.has_builtin_alias(544) or api.has_builtin_alias(559))
            lineage_available = all(hasattr(api.kernel32, name) for name in ("OpenProcess", "GetProcessTimes", "IsProcessInJob"))
            loss_available = all(hasattr(api.advapi32, name) for name in ("ControlTraceW", "CloseTrace"))
            return provider_available, privilege_available, lineage_available, loss_available
        except BaseException:
            return False, False, False, False

    def capability_diagnostic(self) -> ObserverCapabilityDiagnostic:
        if os.name != "nt":
            return _observer_diagnostic_fallback("observer_non_windows")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            return _observer_diagnostic_fallback("observer_pointer_width")
        try:
            api = self._ensure_api()
        except BaseException:
            return _observer_diagnostic_fallback("observer_api_unavailable")
        reasons: list[str] = []
        provider_available = False
        schema_complete = False
        privilege_available = False
        privilege_state = "unknown"
        execution_context = "unknown"
        lineage_available = False
        loss_detection_available = False
        execution_method = None
        try:
            providers = api.providers()
            provider_available = _ETW_KERNEL_FILE_PROVIDER_GUID in providers and _ETW_KERNEL_PROCESS_PROVIDER_GUID in providers
        except BaseException:
            reasons.append("observer_provider_query_failure")
        try:
            schema_facts = self._schema_facts if self._schema_facts is not None else api.installed_schema_facts()
            schema_complete = _etw_schema_facts_complete(schema_facts)
        except BaseException:
            reasons.append("observer_schema_query_failure")
        try:
            execution_method = getattr(api, "execution_context", None)
            if callable(execution_method):
                execution = execution_method()
                if type(execution) is not ObserverExecutionEvidence:
                    raise RuntimeError("observer_execution_evidence_shape")
                privilege_state = execution.privilege_state
                execution_context = execution.execution_context
                if privilege_state not in _OBSERVER_PRIVILEGE_STATES - {"unknown"} or execution_context not in _OBSERVER_EXECUTION_CONTEXTS:
                    raise RuntimeError("observer_execution_evidence_values")
                privilege_available = execution_context in _OBSERVER_SUPPORTED_EXECUTION_CONTEXTS
            else:
                privilege_available = bool(api.has_enabled_profile_privilege() or api.has_builtin_alias(544) or api.has_builtin_alias(559))
        except BaseException:
            if callable(execution_method):
                privilege_state = "api_failure"
                execution_context = "api_failure"
                reasons.append("observer_privilege_api_failure")
            else:
                reasons.append("observer_privilege_query_failure")
        try:
            lineage_available = all(hasattr(api.kernel32, name) for name in ("OpenProcess", "GetProcessTimes", "IsProcessInJob"))
        except BaseException:
            reasons.append("observer_lineage_api_failure")
        try:
            loss_detection_available = all(hasattr(api.advapi32, name) for name in ("ControlTraceW", "CloseTrace"))
        except BaseException:
            reasons.append("observer_loss_api_failure")
        if not provider_available and "observer_provider_query_failure" not in reasons:
            reasons.append("observer_provider_missing")
        if not schema_complete and "observer_schema_query_failure" not in reasons:
            reasons.append("observer_schema_incomplete")
        if not privilege_available and "observer_privilege_query_failure" not in reasons:
            if "observer_privilege_api_failure" not in reasons:
                if execution_context == "api_failure" or privilege_state == "api_failure":
                    privilege_reason = "observer_privilege_api_failure"
                else:
                    privilege_reason = {
                        "absent": "observer_privilege_absent",
                        "present_disabled": "observer_privilege_present_disabled",
                    }.get(privilege_state, "observer_privilege_unavailable")
                reasons.append(privilege_reason)
        if not lineage_available and "observer_lineage_api_failure" not in reasons:
            reasons.append("observer_lineage_api_unavailable")
        if not loss_detection_available and "observer_loss_api_failure" not in reasons:
            reasons.append("observer_loss_api_unavailable")
        return ObserverCapabilityDiagnostic(
            True,
            provider_available,
            schema_complete,
            privilege_available,
            lineage_available,
            loss_detection_available,
            tuple(reason for reason in _OBSERVER_DIAGNOSTIC_REASON_ORDER if reason in reasons),
            privilege_state,
            execution_context,
        )

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
    def capability_diagnostic(self) -> ObserverCapabilityDiagnostic: ...
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


@dataclass(frozen=True, slots=True)
class ObserverCapabilityDiagnostic:
    api_available: bool
    provider_available: bool
    schema_complete: bool
    privilege_available: bool
    lineage_available: bool
    loss_detection_available: bool
    reasons: tuple[str, ...] = ()
    privilege_state: str = "unknown"
    execution_context: str = "unknown"


@dataclass(frozen=True, slots=True)
class ObserverExecutionEvidence:
    """Bounded native evidence for the least-scoped ETW execution context."""

    privilege_state: str
    execution_context: str


def _observer_execution_evidence(
    *,
    privilege_state: str,
    alias_544: str | None = None,
    alias_559: str | None = None,
) -> ObserverExecutionEvidence:
    if privilege_state not in _OBSERVER_PRIVILEGE_STATES - {"unknown"}:
        return ObserverExecutionEvidence("api_failure", "api_failure")
    if privilege_state == "enabled":
        return ObserverExecutionEvidence(privilege_state, "current_process_token_se_system_profile_enabled")
    if privilege_state == "api_failure":
        return ObserverExecutionEvidence(privilege_state, "api_failure")
    if alias_544 == "present":
        return ObserverExecutionEvidence(privilege_state, "current_process_token_builtin_alias_544")
    if alias_559 == "present":
        return ObserverExecutionEvidence(privilege_state, "current_process_token_builtin_alias_559")
    if alias_544 == "api_failure" or alias_559 == "api_failure":
        return ObserverExecutionEvidence(privilege_state, "api_failure")
    return ObserverExecutionEvidence(privilege_state, "unavailable")


def _observer_diagnostic_fallback(reason: str) -> ObserverCapabilityDiagnostic:
    if reason not in _OBSERVER_DIAGNOSTIC_REASON_CODES:
        reason = "observer_api_failure"
    privilege_state = "api_failure" if "privilege" in reason or reason == "observer_api_failure" else "unknown"
    execution_context = "api_failure" if privilege_state == "api_failure" else "unknown"
    return ObserverCapabilityDiagnostic(False, False, False, False, False, False, (reason,), privilege_state, execution_context)


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

    def capability_diagnostic(self) -> ObserverCapabilityDiagnostic:
        if os.name != "nt" or self._backend is None:
            return _observer_diagnostic_fallback("observer_non_windows")
        diagnostic_method = getattr(self._backend, "capability_diagnostic", None)
        if callable(diagnostic_method):
            try:
                value = diagnostic_method()
            except BaseException:
                return _observer_diagnostic_fallback("observer_api_failure")
            if type(value) is not ObserverCapabilityDiagnostic:
                return _observer_diagnostic_fallback("observer_api_failure")
            flags = (
                value.api_available,
                value.provider_available,
                value.schema_complete,
                value.privilege_available,
                value.lineage_available,
                value.loss_detection_available,
            )
            if (
                any(type(item) is not bool for item in flags)
                or type(value.reasons) is not tuple
                or len(value.reasons) > len(_OBSERVER_DIAGNOSTIC_REASON_ORDER)
                or any(reason not in _OBSERVER_DIAGNOSTIC_REASON_CODES for reason in value.reasons)
                or len(set(value.reasons)) != len(value.reasons)
                or value.privilege_state not in _OBSERVER_PRIVILEGE_STATES
                or value.execution_context not in _OBSERVER_EXECUTION_CONTEXTS
            ):
                return _observer_diagnostic_fallback("observer_api_failure")
            return value
        return _observer_diagnostic_fallback("observer_api_failure")

    def probe(self) -> FileWriteObservation:
        if os.name != "nt" or self._backend is None:
            return FileWriteObservation("observer_unavailable", False, False, False, False)
        diagnostic = self.capability_diagnostic()
        provider = diagnostic.provider_available and diagnostic.schema_complete
        if not all((diagnostic.api_available, provider, diagnostic.privilege_available, diagnostic.lineage_available, diagnostic.loss_detection_available)):
            return FileWriteObservation("observer_unavailable", provider, diagnostic.privilege_available, diagnostic.lineage_available, False)
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


def observer_diagnostic_report(*, observer: WindowsEtwFileWriteObserver | None = None) -> dict[str, Any]:
    observer = observer or WindowsEtwFileWriteObserver()
    diagnostic = observer.capability_diagnostic()
    reasons = list(diagnostic.reasons)
    if not reasons and not all((diagnostic.api_available, diagnostic.provider_available, diagnostic.schema_complete, diagnostic.privilege_available, diagnostic.lineage_available, diagnostic.loss_detection_available)):
        reasons = ["observer_api_failure"]
    ready = not reasons and all((diagnostic.api_available, diagnostic.provider_available, diagnostic.schema_complete, diagnostic.privilege_available, diagnostic.lineage_available, diagnostic.loss_detection_available))
    if ready:
        next_operation = "none"
    elif "observer_privilege_absent" in reasons:
        next_operation = "owner_grant_SeSystemProfilePrivilege_to_current_execution_identity_or_BUILTIN_alias_544_or_559"
    elif "observer_privilege_present_disabled" in reasons:
        next_operation = "enable_existing_SeSystemProfilePrivilege_in_current_execution_token_or_use_BUILTIN_alias_544_or_559"
    elif "observer_privilege_api_failure" in reasons or "observer_privilege_query_failure" in reasons:
        next_operation = "resolve_native_privilege_query_before_qualification"
    elif "observer_privilege_unavailable" in reasons:
        next_operation = "enable_SeSystemProfilePrivilege_or_BUILTIN_alias_544_or_559"
    else:
        next_operation = "resolve_fixed_capability_reasons_and_rerun_diagnostic"
    return {
        "schema": OBSERVER_DIAGNOSTIC_SCHEMA,
        "mode": "observer_diagnostic",
        "status": "ready" if ready else "blocked",
        "capability": {
            "api_available": diagnostic.api_available,
            "provider_available": diagnostic.provider_available,
            "schema_complete": diagnostic.schema_complete,
            "privilege_available": diagnostic.privilege_available,
            "lineage_available": diagnostic.lineage_available,
            "loss_detection_available": diagnostic.loss_detection_available,
            "privilege_state": diagnostic.privilege_state,
            "execution_context": diagnostic.execution_context,
        },
        "reasons": reasons,
        "next_operation": next_operation,
        "coordinator_launches": 0,
        "trace_launches": 0,
        "proof_launches": 0,
        "proofSuiteId": None,
        "production_usable": False,
        "activation": False,
    }


def _state_workspace_root(state_workspace: Path) -> Path:
    if not isinstance(state_workspace, Path) or not state_workspace.is_absolute() or state_workspace.is_symlink() or not state_workspace.is_dir():
        _fixed("state_workspace")
    try:
        return state_workspace.resolve()
    except OSError:
        _fixed("state_workspace")


def _normalize_state_journal_mode(journal_mode: object) -> str:
    if type(journal_mode) is not str or journal_mode.lower() not in STATE_SQLITE_JOURNAL_MODES:
        _fixed("state_durability_configuration")
    return journal_mode.lower()


def configured_state_allowlist(state_workspace: Path, *, journal_mode: str = STATE_SQLITE_JOURNAL_MODE) -> frozenset[Path]:
    root = _state_workspace_root(state_workspace)
    mode = _normalize_state_journal_mode(journal_mode)
    database = root / "state.sqlite"
    allowed = {database, root / STATE_SQLITE_RUNTIME_LOCK_NAME}
    if mode == "delete":
        allowed.add(root / "state.sqlite-journal")
    else:
        allowed.update((root / "state.sqlite-wal", root / "state.sqlite-shm"))
    return frozenset(allowed)


def _read_state_journal_mode(state_workspace: Path) -> str:
    root = _state_workspace_root(state_workspace)
    database = root / "state.sqlite"
    if not database.is_file() or database.is_symlink():
        _fixed("state_durability_readback")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=1.0)
        row = connection.execute("PRAGMA journal_mode").fetchone()
        mode = _normalize_state_journal_mode(None if row is None else row[0])
    except (OSError, ValueError, sqlite3.Error):
        _fixed("state_durability_readback")
    finally:
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                _fixed("state_durability_readback")
    if mode != STATE_SQLITE_JOURNAL_MODE:
        _fixed("state_durability_configuration")
    return mode


def _assert_state_producer_journal_mode(config: object) -> str:
    try:
        mode = config.as_json["database_journal_mode"]  # type: ignore[attr-defined]
    except (AttributeError, KeyError, TypeError):
        _fixed("state_durability_configuration")
    normalized = _normalize_state_journal_mode(mode)
    if normalized != STATE_SQLITE_JOURNAL_MODE:
        _fixed("state_durability_configuration")
    return normalized


def _evaluate_disk_gate_for_mode(
    observation: FileWriteObservation,
    *,
    state_workspace: Path,
    journal_mode: str,
) -> str:
    allowlist = configured_state_allowlist(state_workspace, journal_mode=journal_mode)
    state_root = _state_workspace_root(state_workspace)
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


def evaluate_disk_gate(
    observation: FileWriteObservation,
    *,
    state_workspace: Path,
) -> str:
    if type(observation) is not FileWriteObservation:
        return "observer_incomplete"
    if observation.status == "observer_unavailable":
        return "observer_unavailable"
    if observation.status != "observer_ready" or not observation.provider_available or not observation.privilege_available or not observation.lineage_complete or observation.loss_detected:
        return "observer_incomplete"
    try:
        journal_mode = _read_state_journal_mode(state_workspace)
    except CompletePathError as error:
        return str(error)
    return _evaluate_disk_gate_for_mode(observation, state_workspace=state_workspace, journal_mode=journal_mode)


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


def _validated_number(value: object) -> float:
    if type(value) not in (int, float) or isinstance(value, bool) or not 0 <= float(value) < 10**12:
        _fixed("aggregate_timing")
    return float(value)


def _safe_number(value: object) -> float:
    return _validated_number(value)


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
    error_code = value["error_code"]
    if error_code is not None and (type(error_code) is not str or error_code not in AGGREGATE_ERROR_CODES):
        _fixed("aggregate_error")
    if value["status"] == "complete":
        if error_code is not None or value["completed_samples"] != MEASURED_SAMPLE_COUNT:
            _fixed("aggregate_status")
    elif error_code is None:
        _fixed("aggregate_status")
    if type(value["stage_timings_ms"]) is not list or len(value["stage_timings_ms"]) != value["completed_samples"]:
        _fixed("aggregate_timing")
    for sample in value["stage_timings_ms"]:
        _validate_stage_timing_mapping(sample)
    measured_breakdowns = value["verify_state_substages_ms"]
    measured_unbucketed = value["total_unbucketed_ms"]
    if type(measured_breakdowns) is not list or type(measured_unbucketed) is not list:
        _fixed("aggregate_timing")
    if len(measured_breakdowns) not in {0, value["completed_samples"]} or len(measured_unbucketed) not in {0, value["completed_samples"]}:
        _fixed("aggregate_timing")
    if (len(measured_breakdowns) == 0) != (len(measured_unbucketed) == 0):
        _fixed("aggregate_timing")
    if value["completed_samples"] == MEASURED_SAMPLE_COUNT and (len(measured_breakdowns) != MEASURED_SAMPLE_COUNT or len(measured_unbucketed) != MEASURED_SAMPLE_COUNT):
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
    if warmup_timing is None:
        if warmup_breakdown is not None or warmup_unbucketed is not None or value["completed_samples"] > 0 or value["status"] == "complete":
            _fixed("aggregate_timing")
    else:
        _validate_stage_timing_mapping(warmup_timing)
        if (warmup_breakdown is None) != (warmup_unbucketed is None):
            _fixed("aggregate_timing")
        if warmup_breakdown is not None:
            validated_warmup_breakdown = _validate_breakdown_mapping(warmup_breakdown)
            validated_warmup_unbucketed = _safe_number(warmup_unbucketed)
            validated_warmup = {key: _safe_number(warmup_timing[key]) for key in ("source", "verify_state", "ack", "total")}
            _validate_verify_state_reconciliation(validated_warmup["verify_state"], validated_warmup_breakdown)
            _validate_total_reconciliation(validated_warmup, validated_warmup_unbucketed)
        if value["completed_samples"] == MEASURED_SAMPLE_COUNT and warmup_breakdown is None:
            _fixed("aggregate_timing")
    p95_breakdown = value["p95_verify_state_substages_ms"]
    p95_unbucketed = value["p95_total_unbucketed_ms"]
    p95_timings = value["p95_timings_ms"]
    target_exceeded = False
    if value["completed_samples"] == MEASURED_SAMPLE_COUNT:
        if type(p95_timings) is not dict or set(p95_timings) != {"source", "verify_state", "ack", "total"}:
            _fixed("aggregate_timing")
        if p95_breakdown is None or p95_unbucketed is None:
            _fixed("aggregate_timing")
        validated_p95_breakdown = _validate_breakdown_mapping(p95_breakdown)
        validated_p95_unbucketed = _safe_number(p95_unbucketed)
        validated_p95_stage = {key: _safe_number(p95_timings[key]) for key in ("source", "verify_state", "ack", "total")}
        if any(validated_p95_stage[key] != max(item[key] for item in validated_stages) for key in validated_p95_stage):
            _fixed("aggregate_p95")
        if any(
            validated_p95_breakdown[key] != max(item[key] for item in validated_breakdowns)
            for key in _VERIFY_STATE_BREAKDOWN_KEYS
        ):
            _fixed("aggregate_p95")
        if validated_p95_unbucketed != max(validated_unbucketed):
            _fixed("aggregate_p95")
        raw_p95_total = _validated_number(p95_timings["total"])
        raw_stage_total = max(_validated_number(stage["total"]) for stage in value["stage_timings_ms"])
        target_exceeded = raw_p95_total > PRODUCT_TARGET_MS or raw_stage_total > PRODUCT_TARGET_MS
        if target_exceeded:
            if value["status"] != "failed" or error_code is None:
                _fixed("aggregate_p95_target")
    elif any(item is not None for item in (p95_timings, p95_breakdown, p95_unbucketed)):
        _fixed("aggregate_timing")
    if error_code == "product_target_exceeded" and not target_exceeded:
        _fixed("aggregate_status")
    peak_job_commit_bytes = value["peak_job_commit_bytes"]
    if type(peak_job_commit_bytes) is not int or peak_job_commit_bytes < 0:
        _fixed("aggregate_peak")
    effective_cap_bytes = value["effective_cap_bytes"]
    if type(effective_cap_bytes) is not int or effective_cap_bytes <= 0 or effective_cap_bytes >= OUTER_HARD_CAP_BYTES:
        _fixed("aggregate_cap")
    numeric_memory_cap_violation = peak_job_commit_bytes >= OUTER_HARD_CAP_BYTES or peak_job_commit_bytes > effective_cap_bytes
    if numeric_memory_cap_violation and (value["status"] != "failed" or error_code != "outer_memory_cap"):
        _fixed("aggregate_peak")
    if error_code == "outer_memory_cap" and not numeric_memory_cap_violation:
        _fixed("aggregate_status")
    if type(value["peak_active_processes"]) is not int or type(value["total_processes"]) is not int or value["peak_active_processes"] < 0 or value["total_processes"] < 0 or value["peak_active_processes"] > value["total_processes"]:
        _fixed("aggregate_processes")
    if value["peak_active_processes"] > OUTER_ACTIVE_PROCESS_LIMIT and (value["status"] != "failed" or error_code not in {"outer_process_limit", "outer_process_limit_configuration"}):
        _fixed("aggregate_processes")
    if error_code == "outer_process_limit" and value["peak_active_processes"] <= OUTER_ACTIVE_PROCESS_LIMIT:
        _fixed("aggregate_status")
    if value["status"] == "complete" and (value["peak_active_processes"] < 1 or value["total_processes"] < 1):
        _fixed("aggregate_processes")
    if value["observer_status"] not in {"observer_ready", "observer_unavailable", "observer_incomplete"}:
        _fixed("aggregate_observer")
    if value["disk_gate"] not in {"disk_gate_pass", "observer_unavailable", "observer_incomplete", "unauthorized_write", "state_durability_configuration", "state_durability_readback"}:
        _fixed("aggregate_disk")
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
    if type(completed_samples) is not int or not 0 <= completed_samples <= MEASURED_SAMPLE_COUNT or len(timings) != completed_samples:
        _fixed("aggregate_samples")
    if warmup is not None and type(warmup) is not StageSample:
        _fixed("aggregate_timing")
    if completed_samples > 0 and warmup is None:
        _fixed("aggregate_samples")
    if completed_samples == MEASURED_SAMPLE_COUNT and (warmup is None or warmup.verify_state_breakdown is None or warmup.total_unbucketed_ms is None):
        _fixed("aggregate_timing")
    if any(item.verify_state_breakdown is not None for item in timings) and not all(item.verify_state_breakdown is not None for item in timings):
        _fixed("aggregate_timing")
    if any(item.total_unbucketed_ms is not None for item in timings) and not all(item.total_unbucketed_ms is not None for item in timings):
        _fixed("aggregate_timing")
    has_breakdowns = bool(timings) and all(item.verify_state_breakdown is not None for item in timings)
    has_total_unbucketed = bool(timings) and all(item.total_unbucketed_ms is not None for item in timings)
    p95 = nearest_rank_p95(timings) if completed_samples == MEASURED_SAMPLE_COUNT else None
    if p95 is not None and p95.total_ms > PRODUCT_TARGET_MS and error_code is None:
        error_code = "product_target_exceeded"
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
        "p95_timings_ms": None if p95 is None else {"source": _safe_number(p95.source_ms), "verify_state": _safe_number(p95.verify_state_ms), "ack": _safe_number(p95.ack_ms), "total": _safe_number(p95.total_ms)},
        "warmup_timing_ms": None if warmup is None else _stage_timing_mapping(warmup),
        "warmup_verify_state_substages_ms": None if warmup is None or warmup.verify_state_breakdown is None else _breakdown_mapping(warmup.verify_state_breakdown),
        "warmup_total_unbucketed_ms": None if warmup is None or warmup.total_unbucketed_ms is None else _safe_number(warmup.total_unbucketed_ms),
        "verify_state_substages_ms": [] if not has_breakdowns else [_breakdown_mapping(item.verify_state_breakdown) for item in timings if item.verify_state_breakdown is not None],
        "total_unbucketed_ms": [] if not has_total_unbucketed else [_safe_number(item.total_unbucketed_ms) for item in timings if item.total_unbucketed_ms is not None],
        "p95_verify_state_substages_ms": None if p95 is None or p95.verify_state_breakdown is None else _breakdown_mapping(p95.verify_state_breakdown),
        "p95_total_unbucketed_ms": None if p95 is None or p95.total_unbucketed_ms is None else _safe_number(p95.total_unbucketed_ms),
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
        self.lookup_calls = 0
        self._acknowledgments: dict[bytes, bytes] = {}
        self._lost_ack_sent = False

    def identity_sha256(self) -> bytes:
        return self._config.receiver_identity  # type: ignore[attr-defined]

    def epoch(self) -> int:
        return self._config.receiver_epoch  # type: ignore[attr-defined]

    def acknowledgment_profile(self) -> object:
        return self._config.acknowledgment_profile  # type: ignore[attr-defined]

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes | None:
        self.calls += 1
        acknowledgment = self._acknowledgments.get(idempotency_key)
        if acknowledgment is None:
            acknowledgment = build_synthetic_acknowledgment(
                envelope_bytes,
                config=self._config,  # type: ignore[arg-type]
                idempotency_key=idempotency_key,
                accepted_ms=1_700_000_000_000 + self.calls,
            )
            self._acknowledgments[idempotency_key] = acknowledgment
        if not self._lost_ack_sent:
            self._lost_ack_sent = True
            return None
        return acknowledgment

    def lookup_acknowledgment(self, **query: object) -> bytes | None:
        self.lookup_calls += 1
        if query.get("receiver_identity") != self._config.receiver_identity or query.get("receiver_epoch") != self._config.receiver_epoch:  # type: ignore[attr-defined]
            return None
        idempotency_key = query.get("idempotency_key")
        if type(idempotency_key) is not bytes:
            return None
        return self._acknowledgments.get(idempotency_key)


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
    composition_config = composition.CompositionConfigV2(
        queue_config.queue_id,
        queue_config.digest,
        verifier_profile_identity=bytes([0x11]) * 32,
        receiver_identity=bytes([0x22]) * 32,
    )
    receiver = _SyntheticReceiver(composition_config)
    def open_runtime() -> MinimalClearanceVerificationRuntime:
        return MinimalClearanceVerificationRuntime.from_source_auth(
            root=root,
            source_auth_config=source_config,
            state_disposition_port=state_port,
            composition_config=composition_config,
            receiver=receiver,
            lookup=receiver,
        )

    runtime: MinimalClearanceVerificationRuntime | None = open_runtime()
    frame: bytearray | None = None
    timing = _VerifierTiming()
    verify_start: float | None = None
    try:
        if runtime is None:
            _fixed("runtime_startup")
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
        verify_end = time.perf_counter()
        verify_state_ms = (verify_end - verify_start) * 1000.0
    except BaseException:
        _wipe(frame)
        runtime.close()
        raise
    else:
        _wipe(frame)
    if verify_start is None:
        _fixed("timing_verify_scope")
    ack_start = time.perf_counter()
    restart_ms = 0.0
    try:
        if runtime is None:
            _fixed("runtime_restart")
        delivery = runtime.dispatch_outbox(max_batches=1)
        if (
            delivery.outcome,
            delivery.batch_count,
            delivery.attempted_operation_count,
            delivery.acknowledged_operation_count,
            delivery.unconfirmed_operation_count,
            delivery.has_more,
        ) != ("PROCESSED", 1, SOURCE_AUTH_OPERATION_COUNT, SOURCE_AUTH_OPERATION_COUNT - 1, 1, False):
            _fixed("ack_batch_shape")

        restart_start = time.perf_counter()
        database_before_restart = runtime._database_path
        runtime.close()
        runtime = None
        runtime = open_runtime()
        if runtime._database_path != database_before_restart:
            _fixed("runtime_restart_database")
        restart_ms = (time.perf_counter() - restart_start) * 1000.0

        reconciliation = runtime.reconcile_outbox(max_batches=1)
        if (reconciliation.outcome, reconciliation.batch_count, reconciliation.attempted_operation_count, reconciliation.acknowledged_operation_count, reconciliation.unconfirmed_operation_count) != ("PROCESSED", 1, 1, 1, 0):
            _fixed("reconciliation_batch_shape")
        if receiver.calls != SOURCE_AUTH_OPERATION_COUNT or receiver.lookup_calls != 1:
            _fixed("ack_call_shape")
        state = runtime.support_summary()
        if state["outbox_counts"] != {"READY": 0, "LEASED": 0, "ACKNOWLEDGED": expected_acknowledged_count, "DELIVERY_UNCONFIRMED": 0}:
            _fixed("ack_state_shape")
        runtime._verify_integrity()
    finally:
        ack_end = time.perf_counter()
        close_start = time.perf_counter()
        try:
            if runtime is not None:
                runtime.close()
        finally:
            timing.close_ms = restart_ms + (time.perf_counter() - close_start) * 1000.0
        ack_ms = (ack_end - ack_start) * 1000.0 - restart_ms
        if ack_ms < 0.0:
            _fixed("timing_ack_reconciliation")
    verify_state_ms += timing.close_ms
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
    if not _QUEUE_SOURCE_BOUND:
        _fixed("queue_source_binding")
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
    _assert_state_producer_journal_mode(queue_config)
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

    warmup: StageSample | None = None
    timings: list[StageSample] = []
    try:
        candidate = sample()
        if type(candidate) is not StageSample:
            _fixed("sample_shape")
        warmup = candidate
        for _ in range(MEASURED_SAMPLE_COUNT):
            candidate = sample()
            if type(candidate) is not StageSample:
                _fixed("sample_shape")
            timings.append(candidate)
        validate_topology(proof_count=1, operation_count=100, frame_count=1, verifier_batch_count=1, ack_count=100)
        return build_test_aggregate(completed_samples=len(timings), timings=tuple(timings), warmup=warmup, peak_job_commit_bytes=0, effective_cap_bytes=PROCESS_TREE_PEAK_CAP_BYTES, peak_active_processes=1, total_processes=1, observer_status="observer_unavailable", disk_gate="observer_unavailable")
    except CompletePathError as error:
        error_code = str(error) if str(error) in AGGREGATE_ERROR_CODES else "coordinator_failure"
        return build_test_aggregate(completed_samples=len(timings), timings=tuple(timings), warmup=warmup, error_code=error_code, observer_status="observer_unavailable", disk_gate="observer_unavailable")
    except BaseException:
        return build_test_aggregate(completed_samples=len(timings), timings=tuple(timings), warmup=warmup, error_code="coordinator_failure", observer_status="observer_unavailable", disk_gate="observer_unavailable")
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


def _failed_coordinator_run() -> CoordinatorRun:
    """Return a bounded, unmeasured failure when launch orchestration raises unexpectedly."""

    observation = JobObservation(
        0,
        PROCESS_TREE_PEAK_CAP_BYTES,
        PROCESS_TREE_PEAK_CAP_BYTES,
        PROCESS_TREE_PEAK_CAP_BYTES,
        OUTER_ACTIVE_PROCESS_LIMIT,
        OUTER_ACTIVE_PROCESS_LIMIT,
        0,
        0,
        False,
        False,
        False,
    )
    return CoordinatorRun(None, observation, "coordinator_failure")


class _CoordinatorOwnedDescriptor:
    """Own one launcher pipe descriptor across a possible thread-start race."""

    __slots__ = ("descriptor", "owner", "state")

    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor
        self.owner = "launcher"
        self.state = "open"

    def transfer_to_reader(self) -> None:
        if self.owner != "launcher":
            raise RuntimeError("coordinator_descriptor_ownership")
        self.owner = "reader"

    def close_once(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "unknown":
            return False
        try:
            os.close(self.descriptor)
        except BaseException:
            self.state = "unknown"
            return False
        self.state = "closed"
        return True

    def release_from_launcher(self) -> bool:
        if self.state == "closed":
            return True
        if self.owner != "launcher":
            return False
        return self.close_once()


def _read_pipe(
    fd: int,
    cap: int,
    output: dict[str, bytes],
    key: str,
    failed: dict[str, str],
    cleanup_failures: list[str] | None = None,
    descriptor_owner: _CoordinatorOwnedDescriptor | None = None,
) -> None:
    if descriptor_owner is not None:
        fd = descriptor_owner.descriptor
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
        if descriptor_owner is None:
            try:
                os.close(fd)
                released = True
            except BaseException:
                released = False
        else:
            released = descriptor_owner.close_once()
        if not released:
            failed.setdefault("code", "coordinator_output_close")
            if cleanup_failures is not None:
                cleanup_failures.append(f"outer_{key}_close")


def _close_owned_fd_once(fd: int | None, *, label: str, cleanup_failures: list[str]) -> None:
    """Release one owned descriptor exactly once; a failed close is ambiguous."""

    if fd is None:
        return
    try:
        os.close(fd)
    except BaseException:
        cleanup_failures.append(label)


def _close_owned_handle_once(kernel32: Any | None, handle: Any, *, label: str, cleanup_failures: list[str]) -> None:
    """Release one owned Windows handle exactly once; never retry an ambiguous identity."""

    if not handle:
        return
    try:
        if kernel32 is None or not kernel32.CloseHandle(handle):
            cleanup_failures.append(label)
    except BaseException:
        cleanup_failures.append(label)


def _release_coordinator_resources(
    *,
    kernel32: Any | None,
    stdout_read: int | None,
    stdout_write: int | None,
    stderr_read: int | None,
    stderr_write: int | None,
    attribute_list_initialized: bool,
    attribute_list: Any,
    thread_handle: Any,
    process_handle: Any,
    job: Any,
    cleanup_failures: list[str],
    reader_owners: tuple[_CoordinatorOwnedDescriptor, ...] = (),
) -> None:
    """Release every resource still owned by the launcher, without unsafe retries."""

    for label, fd in (
        ("outer_stdout_read_close", stdout_read),
        ("outer_stdout_write_close", stdout_write),
        ("outer_stderr_read_close", stderr_read),
        ("outer_stderr_write_close", stderr_write),
    ):
        _close_owned_fd_once(fd, label=label, cleanup_failures=cleanup_failures)
    for owner in reader_owners:
        if not owner.release_from_launcher():
            cleanup_failures.append("outer_reader_descriptor")
    if attribute_list_initialized:
        try:
            if kernel32 is None:
                cleanup_failures.append("outer_attribute_list_close")
            else:
                kernel32.DeleteProcThreadAttributeList(attribute_list)
        except BaseException:
            cleanup_failures.append("outer_attribute_list_close")
    for label, handle in (
        ("outer_thread_handle_close", thread_handle),
        ("outer_process_handle_close", process_handle),
        ("outer_job_handle_close", job),
    ):
        _close_owned_handle_once(kernel32, handle, label=label, cleanup_failures=cleanup_failures)


def _terminate_coordinator_tree_once(
    *,
    kernel32: Any,
    job: Any,
    process_handle: Any,
    job_assigned: bool,
    cleanup_failures: list[str],
) -> bool:
    """Attempt process-tree termination once and never retry an ambiguous identity."""

    if not process_handle:
        return True
    try:
        if job_assigned and job:
            terminated = bool(kernel32.TerminateJobObject(job, 1))
        else:
            terminated = bool(kernel32.TerminateProcess(process_handle, 1))
    except BaseException:
        cleanup_failures.append("outer_process_terminate")
        return False
    if not terminated:
        cleanup_failures.append("outer_process_terminate")
        return False
    try:
        waited = kernel32.WaitForSingleObject(process_handle, _INFINITE)
    except BaseException:
        cleanup_failures.append("outer_process_wait")
        return False
    if waited != _WAIT_OBJECT_0:
        cleanup_failures.append("outer_process_wait")
        return False
    return True


def _new_coordinator_reader_thread(
    owner: _CoordinatorOwnedDescriptor,
    cap: int,
    output: dict[str, bytes],
    key: str,
    failed: dict[str, str],
    cleanup_failures: list[str],
) -> threading.Thread:
    return threading.Thread(
        target=_read_pipe,
        args=(owner.descriptor, cap, output, key, failed, cleanup_failures, owner),
        daemon=True,
    )


def _reader_start_may_have_started(reader: Any, cleanup_failures: list[str]) -> bool:
    try:
        if reader.ident is not None:
            return True
    except BaseException:
        cleanup_failures.append("outer_reader_start_state")
        return True
    try:
        return bool(reader.is_alive())
    except BaseException:
        cleanup_failures.append("outer_reader_start_state")
        return True


def _join_coordinator_reader_once(
    reader: Any,
    attempted: set[int],
    started_or_maybe: set[int],
    cleanup_failures: list[str],
) -> None:
    identity = id(reader)
    if identity in attempted or identity not in started_or_maybe:
        return
    attempted.add(identity)
    try:
        reader.join(timeout=5.0)
    except BaseException:
        cleanup_failures.append("outer_reader_join")
        return
    try:
        alive = bool(reader.is_alive())
    except BaseException:
        cleanup_failures.append("outer_reader_join")
        return
    if alive:
        cleanup_failures.append("outer_reader_thread")


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
    requested_cap = PROCESS_TREE_PEAK_CAP_BYTES
    effective_cap = requested_cap
    kernel32: Any | None = None
    stdout_read = stdout_write = stderr_read = stderr_write = None
    job = process_handle = thread_handle = None
    job_assigned = False
    reader_threads: list[threading.Thread] = []
    reader_owners: list[_CoordinatorOwnedDescriptor] = []
    reader_join_attempted: set[int] = set()
    reader_started_or_maybe: set[int] = set()
    output: dict[str, bytes] = {}
    failed: dict[str, str] = {}
    cleanup_failures: list[str] = []
    timed_out = False
    peak_commit = 0
    peak_active = 0
    total_processes = 0
    measurement_complete = False
    process_tree_complete = False
    observed_limit = effective_cap
    observed_basic = OUTER_ACTIVE_PROCESS_LIMIT
    process_info = _ProcessInformation()
    attribute_list_initialized = False
    attribute_list = wintypes.LPVOID()
    termination_attempted = False
    primary_error: str | None = None
    payload: bytes | None = None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _configure_kernel32(kernel32)
        system_info = _SystemInfo()
        kernel32.GetSystemInfo(ctypes.byref(system_info))
        page_size = int(system_info.dwPageSize)
        if page_size <= 0:
            _fixed("outer_page_size")
        effective_cap = effective_outer_cap(requested_cap, page_size)
        stdout_read, stdout_write = os.pipe()
        reader_owners.append(_CoordinatorOwnedDescriptor(stdout_read))
        stdout_read = None
        stderr_read, stderr_write = os.pipe()
        reader_owners.append(_CoordinatorOwnedDescriptor(stderr_read))
        stderr_read = None
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
        _close_owned_fd_once(stdout_write, label="outer_stdout_write_close", cleanup_failures=cleanup_failures)
        stdout_write = None
        _close_owned_fd_once(stderr_write, label="outer_stderr_write_close", cleanup_failures=cleanup_failures)
        stderr_write = None
        reader_threads = [
            _new_coordinator_reader_thread(reader_owners[0], COORDINATOR_STDOUT_CAP_BYTES, output, "stdout", failed, cleanup_failures),
            _new_coordinator_reader_thread(reader_owners[1], COORDINATOR_STDERR_CAP_BYTES, output, "stderr", failed, cleanup_failures),
        ]
        for index, reader in enumerate(reader_threads):
            try:
                reader.start()
            except BaseException:
                if _reader_start_may_have_started(reader, cleanup_failures):
                    reader_started_or_maybe.add(id(reader))
                    reader_owners[index].transfer_to_reader()
                _fixed("outer_reader_start")
            else:
                reader_started_or_maybe.add(id(reader))
                reader_owners[index].transfer_to_reader()
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
                termination_attempted = True
                if not _terminate_coordinator_tree_once(
                    kernel32=kernel32,
                    job=job,
                    process_handle=process_handle,
                    job_assigned=job_assigned,
                    cleanup_failures=cleanup_failures,
                ):
                    _fixed("outer_timeout_terminate")
                break
        # The process handle can signal before a descendant exits.  The final
        # memory read must occur only after the complete Job accounting view is
        # at zero, otherwise a descendant tail allocation can be missed.
        final_accounting = _JobBasicAccountingInformation()
        if not kernel32.QueryInformationJobObject(job, _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, ctypes.byref(final_accounting), ctypes.sizeof(final_accounting), None):
            _fixed("outer_accounting_query")
        while int(final_accounting.ActiveProcesses) != 0 and time.monotonic() < deadline:
            time.sleep(0.01)
            if not kernel32.QueryInformationJobObject(job, _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, ctypes.byref(final_accounting), ctypes.sizeof(final_accounting), None):
                _fixed("outer_accounting_query")
            peak_active = max(peak_active, int(final_accounting.ActiveProcesses))
            total_processes = max(total_processes, int(final_accounting.TotalProcesses))
        process_tree_complete = total_processes >= 1 and int(final_accounting.ActiveProcesses) == 0
        if not process_tree_complete:
            _fixed("outer_cleanup")
        final_info = _JobExtendedLimitInformation()
        if not kernel32.QueryInformationJobObject(job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(final_info), ctypes.sizeof(final_info), None):
            _fixed("outer_job_query")
        # PeakJobMemoryUsed is read after the final zero-active-process
        # observation, so it covers the entire completed process tree.
        peak_commit = max(peak_commit, int(final_info.PeakJobMemoryUsed))
        observed_limit = int(final_info.JobMemoryLimit)
        observed_basic = int(final_info.BasicLimitInformation.ActiveProcessLimit)
        if int(final_info.BasicLimitInformation.LimitFlags) != _JOB_LIMIT_FLAGS or observed_limit != effective_cap or observed_basic != OUTER_ACTIVE_PROCESS_LIMIT:
            _fixed("outer_job_limits_readback")
        if peak_commit >= OUTER_HARD_CAP_BYTES or peak_commit > effective_cap:
            _fixed("outer_memory_cap")
        measurement_complete = True
        for reader in reader_threads:
            _join_coordinator_reader_once(reader, reader_join_attempted, reader_started_or_maybe, cleanup_failures)
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
            _fixed("outer_exit_code")
        if output.get("stderr", b""):
            primary_error = "coordinator_stderr"
        elif timed_out:
            primary_error = "outer_timeout"
        elif failed:
            primary_error = failed.get("code", "outer_output")
        elif int(exit_code.value) != 0:
            primary_error = "coordinator_failure"
    except CompletePathError as error:
        if primary_error is None:
            primary_error = str(error)
        if process_handle and kernel32 is not None and not process_tree_complete and not termination_attempted:
            termination_attempted = True
            _terminate_coordinator_tree_once(
                kernel32=kernel32,
                job=job,
                process_handle=process_handle,
                job_assigned=job_assigned,
                cleanup_failures=cleanup_failures,
            )
    except BaseException:
        if primary_error is None:
            primary_error = "coordinator_failure"
        if process_handle and kernel32 is not None and not process_tree_complete and not termination_attempted:
            termination_attempted = True
            _terminate_coordinator_tree_once(
                kernel32=kernel32,
                job=job,
                process_handle=process_handle,
                job_assigned=job_assigned,
                cleanup_failures=cleanup_failures,
            )
    finally:
        for reader in reader_threads:
            _join_coordinator_reader_once(reader, reader_join_attempted, reader_started_or_maybe, cleanup_failures)
        _release_coordinator_resources(
            kernel32=kernel32,
            stdout_read=stdout_read,
            stdout_write=stdout_write,
            stderr_read=stderr_read,
            stderr_write=stderr_write,
            attribute_list_initialized=attribute_list_initialized,
            attribute_list=attribute_list,
            thread_handle=thread_handle,
            process_handle=process_handle,
            job=job,
            cleanup_failures=cleanup_failures,
            reader_owners=tuple(reader_owners),
        )
    cleanup_complete = process_tree_complete and not cleanup_failures
    if not cleanup_complete and primary_error is None:
        primary_error = "outer_cleanup"
    observation = JobObservation(
        peak_commit,
        requested_cap,
        effective_cap,
        observed_limit,
        OUTER_ACTIVE_PROCESS_LIMIT,
        observed_basic,
        peak_active,
        total_processes,
        process_tree_complete,
        measurement_complete,
        cleanup_complete,
        timed_out,
    )
    try:
        _validate_job_observation_safety(observation)
    except CompletePathError as error:
        if primary_error is None:
            primary_error = str(error)
    try:
        validate_job_observation(observation)
    except CompletePathError as error:
        if primary_error is None:
            primary_error = str(error)
    if primary_error is None:
        payload = output.get("stdout", b"")
    else:
        payload = None
    return CoordinatorRun(payload, observation, primary_error)


def _parse_payload(payload: bytes | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fixed("coordinator_output")
    return _validate_aggregate_mapping(value)


def _resource_observation_mapping(observation: JobObservation) -> dict[str, Any]:
    return {
        "source": "windows_job_object",
        "enforcement": "job_memory_limit_and_active_process_limit",
        "measurement": "PeakJobMemoryUsed_and_basic_accounting",
        "active_process_metric_semantics": ACTIVE_PROCESS_METRIC_SEMANTICS,
        "active_process_limit_semantics": ACTIVE_PROCESS_LIMIT_SEMANTICS,
        "total_process_metric_semantics": TOTAL_PROCESS_METRIC_SEMANTICS,
        "requested_cap_bytes": observation.requested_cap_bytes,
        "effective_cap_bytes": observation.effective_cap_bytes,
        "cap_readback_bytes": observation.cap_readback_bytes,
        "active_process_limit": observation.active_process_limit,
        "active_process_limit_readback": observation.active_process_limit_readback,
        "peak_job_commit_bytes": observation.peak_job_commit_bytes,
        "peak_active_processes": observation.peak_active_processes,
        "total_processes": observation.total_processes,
        "process_tree_complete": observation.process_tree_complete,
        "measurement_complete": observation.measurement_complete,
        "cleanup_complete": observation.cleanup_complete,
        "timed_out": observation.timed_out,
    }


def _validate_resource_observation_mapping(value: object) -> dict[str, Any]:
    allowed = {
        "source", "enforcement", "measurement", "requested_cap_bytes",
        "active_process_metric_semantics", "active_process_limit_semantics",
        "total_process_metric_semantics",
        "effective_cap_bytes", "cap_readback_bytes", "active_process_limit",
        "active_process_limit_readback", "peak_job_commit_bytes",
        "peak_active_processes", "total_processes", "process_tree_complete",
        "measurement_complete", "cleanup_complete", "timed_out",
    }
    if type(value) is not dict or set(value) != allowed:
        _fixed("resource_observation_shape")
    if (
        value["source"] != "windows_job_object"
        or value["enforcement"] != "job_memory_limit_and_active_process_limit"
        or value["measurement"] != "PeakJobMemoryUsed_and_basic_accounting"
        or value["active_process_metric_semantics"] != ACTIVE_PROCESS_METRIC_SEMANTICS
        or value["active_process_limit_semantics"] != ACTIVE_PROCESS_LIMIT_SEMANTICS
        or value["total_process_metric_semantics"] != TOTAL_PROCESS_METRIC_SEMANTICS
    ):
        _fixed("resource_observation_authority")
    observation = JobObservation(
        value["peak_job_commit_bytes"],
        value["requested_cap_bytes"],
        value["effective_cap_bytes"],
        value["cap_readback_bytes"],
        value["active_process_limit"],
        value["active_process_limit_readback"],
        value["peak_active_processes"],
        value["total_processes"],
        value["process_tree_complete"],
        value["measurement_complete"],
        value["cleanup_complete"],
        value["timed_out"],
    )
    validate_job_observation(observation)
    return value


def _resource_report_from_run(*, run: CoordinatorRun, payload: dict[str, Any] | None) -> dict[str, Any]:
    resource = _resource_observation_mapping(run.observation)
    error_code = run.error_code
    try:
        _validate_resource_observation_mapping(resource)
    except CompletePathError as error:
        if error_code is None:
            error_code = str(error)
    aggregate = None if payload is None else dict(payload)
    if aggregate is None:
        if error_code is None:
            error_code = "resource_payload_missing"
    else:
        aggregate["peak_job_commit_bytes"] = run.observation.peak_job_commit_bytes
        aggregate["effective_cap_bytes"] = run.observation.effective_cap_bytes
        aggregate["peak_active_processes"] = run.observation.peak_active_processes
        aggregate["total_processes"] = run.observation.total_processes
        aggregate["observer_status"] = "observer_unavailable"
        aggregate["disk_gate"] = "observer_unavailable"
        try:
            _validate_aggregate_mapping(aggregate)
        except CompletePathError as error:
            if error_code is None:
                error_code = str(error)
        if aggregate["status"] != "complete" or aggregate["error_code"] is not None:
            if error_code is None:
                error_code = aggregate["error_code"] or "coordinator_failure"
    return {
        "schema": RESOURCE_OBSERVATION_SCHEMA,
        "mode": "resource_observation",
        "status": "measured" if error_code is None else "failed",
        "error_code": error_code,
        "resource_observation": resource,
        "aggregate": aggregate,
        "observer_status": "observer_unavailable",
        "disk_gate": "observer_unavailable",
        "complete_profile_qualification": False,
        "proofSuiteId": None,
        "production_usable": False,
        "activation": False,
    }


def _validate_resource_run_root(run_root: Path) -> None:
    if not isinstance(run_root, Path) or not run_root.is_absolute() or run_root.is_symlink() or not run_root.is_dir():
        _fixed("resource_run_root")
    for name in ("source-workspace", "verifier-workspace", "state"):
        workspace = run_root / name
        try:
            if not workspace.is_dir() or workspace.is_symlink() or tuple(workspace.iterdir()):
                _fixed("resource_run_root")
        except OSError:
            _fixed("resource_run_root")


def run_resource_measurement(*, run_root: Path) -> dict[str, Any]:
    _validate_resource_run_root(run_root)
    run = _launch_coordinator(run_root)
    try:
        payload = _parse_payload(run.payload)
    except CompletePathError as error:
        payload = None
        if run.error_code is None:
            run = CoordinatorRun(run.payload, run.observation, str(error))
    return _resource_report_from_run(run=run, payload=payload)


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

        run: CoordinatorRun
        try:
            run = _launch_coordinator(run_root, on_assigned=start_observation)
        except BaseException:
            run = _failed_coordinator_run()
        finally:
            try:
                observed_after = observer.stop()
            except BaseException:
                observed_after = FileWriteObservation("observer_incomplete", True, True, False, True)
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


def _probe_tree_child(sleep_seconds: float = 0.15, tail_bytes: int = 0, tail_delay: float = 0.0) -> int:
    if os.name != "nt":
        return 0
    time.sleep(sleep_seconds)
    if type(tail_bytes) is not int or tail_bytes < 0 or type(tail_delay) is not float or tail_delay < 0.0:
        _fixed("probe_tail_arguments")
    if tail_delay:
        time.sleep(tail_delay)
    allocation = bytearray(tail_bytes)
    for offset in range(0, len(allocation), 4096):
        allocation[offset] = offset // 4096 & 0xFF
    if allocation:
        time.sleep(0.05)
    del allocation
    return 0


def _probe_tree_coordinator(run_root: Path, sleep_seconds: float, *, tail_bytes: int = 0, tail_delay: float = 0.0) -> dict[str, Any]:
    del run_root
    child = subprocess.Popen(
        [
            sys.executable, "-B", str(Path(__file__).resolve()), "--probe-grandchild", str(sleep_seconds),
            "--probe-tail-bytes", str(tail_bytes), "--probe-tail-delay", str(tail_delay),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if tail_bytes:
        return build_test_aggregate(completed_samples=0, error_code="probe_only", observer_status="observer_unavailable", disk_gate="observer_unavailable")
    child.wait(timeout=max(5.0, sleep_seconds + 2.0))
    return build_test_aggregate(completed_samples=0, error_code="probe_only", observer_status="observer_unavailable", disk_gate="observer_unavailable")


def main(argv: list[str] | None = None) -> int:
    parser = __import__("argparse").ArgumentParser(add_help=False)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--diagnose-observer", action="store_true")
    parser.add_argument("--screen", action="store_true")
    parser.add_argument("--resource", action="store_true")
    parser.add_argument("--coordinator", action="store_true")
    parser.add_argument("--probe-coordinator", type=float)
    parser.add_argument("--probe-grandchild", type=float)
    parser.add_argument("--probe-tail-bytes", type=int, default=0)
    parser.add_argument("--probe-tail-delay", type=float, default=0.0)
    parser.add_argument("--run-root")
    args = parser.parse_args(argv)
    try:
        mode_count = sum((
            bool(args.prepare),
            bool(args.diagnose_observer),
            bool(args.screen),
            bool(args.resource),
            bool(args.coordinator or args.probe_coordinator is not None),
            args.probe_grandchild is not None,
        ))
        if mode_count == 0:
            _fixed("mode_required")
        if mode_count != 1:
            _fixed("mode_conflict")
        if args.run_root and not (args.coordinator or args.probe_coordinator is not None or args.resource):
            _fixed("run_root_mode")
        if args.prepare:
            print(json.dumps(prepare_report(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.diagnose_observer:
            print(json.dumps(observer_diagnostic_report(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.probe_grandchild is not None:
            return _probe_tree_child(args.probe_grandchild, args.probe_tail_bytes, args.probe_tail_delay)
        if args.probe_coordinator is not None:
            if not args.run_root:
                _fixed("outer_run_root")
            print(_aggregate_json(_probe_tree_coordinator(Path(args.run_root), args.probe_coordinator, tail_bytes=args.probe_tail_bytes, tail_delay=args.probe_tail_delay)), end="")
            return 0
        if args.resource:
            if not args.run_root:
                _fixed("resource_run_root")
            value = run_resource_measurement(run_root=Path(args.run_root))
            print(json.dumps(value, sort_keys=True, separators=(",", ":")), end="")
            return 0 if value["status"] == "measured" else 1
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
    "JobObservation", "MANIFEST_PATH", "MEASURED_SAMPLE_COUNT", "OBSERVER_DIAGNOSTIC_SCHEMA", "ObserverCapabilityDiagnostic", "ObserverExecutionEvidence", "OUTER_ACTIVE_PROCESS_LIMIT",
    "OUTER_HARD_CAP_BYTES", "PROFILE_ID", "PROFILE_SCHEMA", "PRODUCER_EXECUTABLE", "PRODUCER_EXECUTABLE_SHA256", "PRODUCER_EXECUTABLE_SIZE_BYTES", "PRODUCER_HEAD", "PRODUCER_REPO", "PRODUCER_TREE", "RESOURCE_OBSERVATION_SCHEMA", "MeasurementSchedule", "StageSample", "VerifyStateBreakdown", "WindowsEtwFileWriteObserver", "WindowsEtwWriteTraceBackend",
    "build_test_aggregate", "configured_state_allowlist", "effective_outer_cap", "evaluate_disk_gate", "observer_diagnostic_report",
    "nearest_rank_p95", "prepare_report", "run_falsification_screen", "run_measurement_schedule", "run_measurement_schedule_with_warmup", "validate_dependencies",
    "run_resource_measurement", "validate_job_observation", "validate_topology",
)
