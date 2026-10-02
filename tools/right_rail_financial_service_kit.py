"""Assemble, verify, extract, run and serve the offline synthetic Financial service kit.

The kit bundles no third-party Python code. Assembly needs a separate Engine
build receipt binding the exact Lean source manifest to the evaluator worker
executable; this command never creates that receipt or infers provenance.

Where each safety property lives:
- Exact digest-bound manifest: every member's size and SHA-256 are in
  MANIFEST.json (`_manifest_files`), the archive digest is supplied out of band
  (`_verify_open_archive`), and `verify` is the one checker (assembly runs it).
- Pinned runtime identity: `EXPECTED_PYTHON_EXE_SHA256` (`_check_runtime_member`),
  version probe at assembly (`_probe_runtime`); always run with `-I -S`.
- Pinned engine identity: pins parsed from the bundled Engine adapter
  (`_check_contents`), bound to the guarded build receipt (`_check_receipt`,
  `_check_guard_log`, including resource accounting).
- Fail-closed archive parsing: `_safe_archive_path`, `_check_names`,
  `_verify_open_archive` (stored-only, no encryption, sizes, exact membership).
- Symlink/reparse/hard-link refusal and bounded reads: `_open_regular`, `_walk`.
- No third-party code bundled: `_runtime_files` (RUNTIME_EXCLUDED line) and
  the runtime inventory check in `_check_contents`.
- Loopback-only serving: app/right_rail_financial_staff_server.py binds
  127.0.0.1 and checks peer and Host; the kit passes only a port.
- Exact retry / lost-response recovery: the digest-bound scenario test named
  by `SERVICE_SCENARIO`, run unchanged from the extracted kit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import unicodedata
import zipfile
from typing import Any, BinaryIO, Callable


KIT_SCHEMA = "RR/FINANCIAL/SERVICE-KIT-MANIFEST/v2"
BUILD_RECEIPT_SCHEMA = "RR/LEAN-ENGINE/BUILD-RECEIPT/v2"
SOURCE_MANIFEST_SCHEMA = "RR/LEAN-ENGINE/SOURCE-MANIFEST/v1"
ENGINE_TARGET = "blind_financial_worker"
EXPECTED_PYTHON_VERSION = "3.11.15"
EXPECTED_PYTHON_EXE_SHA256 = "F1D8D2AA2A8AD7C74B6C6300B29CFDBCB484FC7FFAD99B7FBFE1E31C048343B9"
GUARD_SHA256 = "57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB"
PHYSICAL_FREE_FLOOR_BYTES = 2_190_433_321
ENGINE_MINIMUM_START_FREE_BYTES = 4_190_433_321
PHYSICAL_RESERVE_BYTES = 3_221_225_472
PHYSICAL_RESERVE_TOLERANCE_PERCENT = 32
GUARD_MUTEX_NAME = r"Local\BlindLedgerDirectMaskBuild20260907"
MAX_SMALL_FILE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES + 64 * 1024 * 1024
MAX_WALK_ENTRIES = 100_000
MAX_WALK_DEPTH = 64
WINDOWS_RESERVED_NAMES = {
    "aux", "con", "conin$", "conout$", "nul", "prn",
    *(f"com{digit}" for digit in "123456789¹²³"),
    *(f"lpt{digit}" for digit in "123456789¹²³"),
}
THIRD_PARTY_DIRECTORIES = {"site-packages", "dist-packages"}
KIT_CLAIMS = {
    "proofSuiteId": None,
    "production_usable": False,
    "activation": False,
    "owner_mode": "TEST",
    "shadow_mode": "SHADOW",
    "dispatch_enabled": False,
    "egress_enabled": False,
    "payment_movement": False,
    "queue": "omitted: no current source-bound Queue runtime handoff",
    "scope": "synthetic, local, non-PHI, nonpayment, dispatch-disabled, nonactivating",
}
SERVICE_SCENARIO = (
    "tests.test_right_rail_financial_staff_server.RightRailFinancialStaffWorkspaceTests."
    "test_service_kit_correction_lost_response_retry_and_shadow_restore"
)
REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "MANIFEST.json"
RETIRED_PIN_REGISTRY = "artifacts/engine-correction/RETIRED_PINS"

# The scenario's static import closure, the staff app it serves, the kit itself and
# the two governing documents. A listed file that is missing fails assembly.
STATE_FILES = (
    "CONSTITUTION.md",
    "README.md",
    "app/__init__.py",
    "app/minimal_clearance_resource_limits.py",
    "app/minimal_clearance_verifier_process.py",
    "app/fixtures/h_followthrough_rules_v1.json",
    "app/right_rail_financial_engine.py",
    "app/right_rail_financial_cash_file.py",
    "app/right_rail_financial_cash_file_independent.py",
    "app/right_rail_financial_custody.py",
    "app/right_rail_financial_derived.py",
    "app/right_rail_financial_followthrough.py",
    "app/right_rail_financial_line_pack.py",
    "app/right_rail_financial_mirror.py",
    "app/right_rail_financial_owner.py",
    "app/right_rail_financial_owner_independent.py",
    "app/right_rail_financial_semantic_adapter.py",
    "app/right_rail_financial_staff_server.py",
    "app/right_rail_financial_switch.py",
    "app/right_rail_gate_codec.py",
    "app/right_rail_gate_signer.py",
    "app/staff_workspace/index.html",
    "app/staff_workspace/interaction-model.json",
    "app/staff_workspace/staff.css",
    "app/staff_workspace/staff.js",
    RETIRED_PIN_REGISTRY,
    "tests/__init__.py",
    "tests/financial_decision_package_oracle.py",
    "tests/rightrail_financial_expected_cases.py",
    "tests/test_right_rail_financial_acceptance.py",
    "tests/test_right_rail_financial_staff_server.py",
    "tools/right_rail_financial_cli.py",
    "tools/right_rail_financial_service_kit.py",
    "tools/service_kit/run_scenario.py",
    "tools/service_kit/run_server.py",
)

ENGINE_SOURCE_PREFIX = "engine/source/"
LEAN_CONFIG_FILES = ("lakefile.toml", "lake-manifest.json", "lean-toolchain")
REQUIRED_LEAN_FILES = (
    "BlindLedger/Financial/Worker.lean",
    "BlindLedger/Financial/WorkerCli.lean",
    *LEAN_CONFIG_FILES,
)
ENGINE_EXE = "artifacts/engine-evaluator/blind_financial_worker.exe"  # where the Engine adapter looks for it
VECTORS = "engine/vectors/"
PROVENANCE = "engine/provenance/"
PRODUCER = "engine/producer/build_financial_correction_release.ps1"
# Engine release directory (exact inventory) -> archive path.
RELEASE_FILES = {
    "blind_financial_worker.exe": ENGINE_EXE,
    "source-manifest.json": PROVENANCE + "source-manifest.json",
    "provenance/engine-build-receipt.json": PROVENANCE + "engine-build-receipt.json",
    **{f"logs/{name}": PROVENANCE + name for name in (
        "child.stdout.log", "child.stderr.log", "guard.stdout.log", "guard.stderr.log",
    )},
    **{f"vectors/{name}": VECTORS + name for name in (
        "request.bin", "result.expected.bin", "result.actual.bin",
    )},
}
RELEASE_DIRECTORIES = {"vectors", "logs", "provenance"}
RUNTIME_PREFIX = "runtime/python311/"
RUNTIME_EXE = RUNTIME_PREFIX + "python.exe"
RECEIPT_FIELDS = frozenset({
    "schema", "status", "target", "engine_source_manifest_sha256", "lean_toolchain",
    "lean_toolchain_sha256", "lakefile_sha256", "lake_manifest_sha256", "executable_size_bytes",
    "executable_sha256", "request_vector_sha256", "result_vector_sha256",
    "stdout_sha256", "stderr_sha256", "producer_script_sha256",
    "guard_stdout_sha256", "guard_stderr_sha256", "guard_wrapper_sha256", "guard_outer_exit_code",
    "guard_child_exit_code", "guard_self_test_exit7", "guard_self_test_exit0",
    "guard_minimum_start_free_bytes", "guard_minimum_free_bytes", "guard_cleanup", "guard_mutex",
    "lake_build_exit_code", "transition_vector_exit_code", "engine_git_head",
    "engine_git_tree", "engine_git_status_sha256", "lake_version", "lake_executable_sha256",
    "lean_executable_sha256", "direct_lane_grant_reference",
})
SHA256_HEX = re.compile(r"[0-9A-F]{64}")

Members = dict[str, tuple[int, str]]  # archive path -> (size_bytes, SHA-256)


class KitError(RuntimeError):
    """Stable, concise failure raised by the kit commands."""


# ---- JSON -----------------------------------------------------------------

def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise KitError(f"json_duplicate_key:{key}")
        result[key] = value
    return result


def _no_json_constant(value: str) -> None:
    raise KitError(f"json_nonstandard_number:{value}")


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object, parse_constant=_no_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise KitError(f"json_invalid:{label}") from error
    if type(value) is not dict:
        raise KitError(f"json_object_required:{label}")
    return value


def _strict_canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    value = _strict_json(raw, label)
    if raw != _canonical_json(value):
        raise KitError(f"json_not_canonical:{label}")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest().upper()


def _text(value: object, code: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > 2048
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise KitError(code)
    return value


# ---- Archive paths --------------------------------------------------------

def _safe_archive_path(value: object) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise KitError("archive_path_invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(part in ("", ".", "..") or ":" in part for part in path.parts)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise KitError("archive_path_invalid")
    try:
        path_length = len(value.encode("utf-16-le")) // 2
        segment_lengths = [len(part.encode("utf-16-le")) // 2 for part in path.parts]
    except UnicodeEncodeError as error:
        raise KitError("archive_path_invalid_unicode") from error
    for part, segment_length in zip(path.parts, segment_lengths):
        if (
            part.endswith((".", " "))
            or any(ord(character) < 32 or character in '<>"|?*' for character in part)
            or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
            or segment_length > 255
        ):
            raise KitError("archive_path_not_portable")
    if path_length > 240:
        raise KitError("archive_path_too_long")
    return value


def _check_names(names: list[str]) -> None:
    """Safe paths with no case-folded duplicate and no file that is also a directory."""
    keys: dict[tuple[str, ...], str] = {}
    for name in names:
        key = tuple(part.casefold() for part in PurePosixPath(_safe_archive_path(name)).parts)
        if key in keys:
            raise KitError(f"archive_path_portable_collision:{keys[key]}:{name}")
        keys[key] = name
    for key, name in keys.items():
        for size in range(1, len(key)):
            if key[:size] in keys:
                raise KitError(f"archive_file_directory_collision:{keys[key[:size]]}:{name}")


# ---- Local files ----------------------------------------------------------

def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _open_regular(path: Path, max_bytes: int) -> tuple[BinaryIO, int]:
    """Open a regular single-link file without following links, refusing oversize files."""
    path = Path(os.path.abspath(path))
    try:
        before = path.lstat()
        if _is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise KitError(f"regular_unlinked_file_required:{path}")
        if before.st_size > max_bytes:
            raise KitError(f"file_too_large:{path}")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise KitError(f"file_unavailable:{path}") from error
    stream = os.fdopen(descriptor, "rb")
    opened = os.fstat(stream.fileno())
    if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
        stream.close()
        raise KitError(f"file_identity_changed:{path}")
    return stream, before.st_size


def _copy_digest(source: BinaryIO, limit: int, label: str, sink: BinaryIO | None = None) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(1024 * 1024):
        size += len(chunk)
        if size > limit:
            raise KitError(f"stream_exceeds_expected_size:{label}")
        digest.update(chunk)
        if sink is not None:
            sink.write(chunk)
    return size, digest.hexdigest().upper()


def _hash_file(path: Path, max_bytes: int = MAX_MEMBER_BYTES) -> tuple[int, str]:
    stream, size = _open_regular(path, max_bytes)
    with stream:
        actual = _copy_digest(stream, size, str(path))
    if actual[0] != size:
        raise KitError(f"file_size_changed:{path}")
    return actual


def _walk(root: Path, label: str, skip: frozenset[str] = frozenset()) -> tuple[dict[str, Path], set[str]]:
    """Regular files and directories under root; never follows links; bounded entries, depth and bytes."""
    root = Path(os.path.abspath(root))
    try:
        root_info = root.lstat()
    except OSError as error:
        raise KitError(f"{label}_root_unavailable") from error
    if _is_link(root_info) or not stat.S_ISDIR(root_info.st_mode):
        raise KitError(f"{label}_root_invalid")
    files: dict[str, Path] = {}
    directories: set[str] = set()
    entries = total_bytes = 0

    def walk_error(error: OSError) -> None:
        raise KitError(f"{label}_walk_failed:{type(error).__name__}") from error

    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        base = Path(current)
        if len(base.relative_to(root).parts) > MAX_WALK_DEPTH:
            raise KitError(f"{label}_walk_depth_limit")
        entries += len(directory_names) + len(file_names)
        if entries > MAX_WALK_ENTRIES:
            raise KitError(f"{label}_walk_entry_limit")
        directory_names[:] = [name for name in directory_names if name.casefold() not in skip]
        for name, is_directory in [(name, True) for name in directory_names] + [(name, False) for name in file_names]:
            relative = (base / name).relative_to(root).as_posix()
            try:
                info = (base / name).lstat()
            except OSError as error:
                raise KitError(f"{label}_path_identity_lost:{relative}") from error
            if is_directory:
                if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                    raise KitError(f"{label}_directory_not_regular:{relative}")
                directories.add(relative)
                continue
            if _is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise KitError(f"{label}_file_not_regular:{relative}")
            total_bytes += info.st_size
            if total_bytes > MAX_TOTAL_BYTES:
                raise KitError(f"{label}_tree_size_limit")
            files[relative] = base / name
    return files, directories


# ---- Runtime --------------------------------------------------------------

def _runtime_files(runtime_root: Path) -> dict[str, Path]:
    files, _ = _walk(runtime_root, "python_runtime")
    kept: dict[str, Path] = {}
    excluded = 0
    for relative, path in files.items():
        parts = [part.lower() for part in PurePosixPath(relative).parts]
        # The pinned CPython ships pip under Lib/site-packages. The kit always
        # runs the bundled interpreter with -S, so that directory is never on
        # sys.path; leave it out rather than bundle third-party code.
        if len(parts) > 2 and parts[:2] == ["lib", "site-packages"]:
            excluded += 1
            continue
        if THIRD_PARTY_DIRECTORIES.intersection(parts):
            raise KitError("python_runtime_contains_third_party_packages")
        kept[relative] = path
    if excluded:
        print(f"RUNTIME_EXCLUDED path=Lib/site-packages files={excluded} reason=third_party_not_bundled")
    return kept


def _probe_runtime(executable: Path) -> None:
    try:
        result = subprocess.run(
            [str(executable), "-I", "-S", "-c", "import sys; print('.'.join(map(str, sys.version_info[:3])))"],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise KitError("python_runtime_version_probe_failed") from error
    if result.returncode != 0 or result.stderr or result.stdout.decode("ascii", "replace").strip() != EXPECTED_PYTHON_VERSION:
        raise KitError("python_runtime_version_mismatch")


def _check_runtime_member(members: Members) -> tuple[int, str]:
    entry = members.get(RUNTIME_EXE)
    if (
        type(entry) is not tuple
        or type(entry[0]) is not int
        or entry[0] <= 0
        or entry[1] != EXPECTED_PYTHON_EXE_SHA256
    ):
        raise KitError("kit_python_executable_member_pin")
    return entry


# ---- Engine provenance ----------------------------------------------------

def _engine_pins(engine_adapter: bytes) -> dict[str, object]:
    text = engine_adapter.decode("utf-8")
    hex_pin = r"\s*:\s*Final\[bytes\]\s*=\s*bytes\.fromhex\(\s*\"([0-9A-F]{64})\""
    patterns = {
        "size": r"EVALUATOR_ARTIFACT_SIZE_BYTES\s*:\s*Final\[int\]\s*=\s*([0-9_]+)",
        ENGINE_EXE: "EVALUATOR_ARTIFACT_SHA256" + hex_pin,
        "request": "CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256" + hex_pin,
        "result": "CORRECTION_TRANSITION_RESULT_VECTOR_SHA256" + hex_pin,
    }
    pins: dict[str, object] = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, text)
        if match is None:
            raise KitError(f"engine_pin_not_found:{name}")
        pins[name] = int(match.group(1).replace("_", "")) if name == "size" else match.group(1)
    return pins


def _check_receipt(members: Members, read: Callable[[str], bytes], expected: dict[str, object]) -> dict[str, Any]:
    receipt = _strict_canonical_json(read(PROVENANCE + "engine-build-receipt.json"), "engine_build_receipt")
    if set(receipt) != RECEIPT_FIELDS:
        raise KitError("engine_build_receipt_fields")
    expected = {
        **expected,
        "schema": BUILD_RECEIPT_SCHEMA,
        "status": "PASS",
        "target": ENGINE_TARGET,
        "stdout_sha256": members[PROVENANCE + "child.stdout.log"][1],
        "stderr_sha256": members[PROVENANCE + "child.stderr.log"][1],
        "guard_stdout_sha256": members[PROVENANCE + "guard.stdout.log"][1],
        "guard_stderr_sha256": members[PROVENANCE + "guard.stderr.log"][1],
        "producer_script_sha256": members[PRODUCER][1],
        "guard_wrapper_sha256": GUARD_SHA256,
        "guard_outer_exit_code": 0,
        "guard_child_exit_code": 0,
        "guard_self_test_exit7": 7,
        "guard_self_test_exit0": 0,
        "guard_cleanup": "PASS",
        "guard_mutex": "RELEASED",
        "lake_build_exit_code": 0,
        "transition_vector_exit_code": 0,
    }
    for key, value in expected.items():
        if type(receipt[key]) is not type(value) or receipt[key] != value:
            raise KitError(f"engine_build_receipt_mismatch:{key}")
    start_floor = receipt["guard_minimum_start_free_bytes"]
    if type(start_floor) is not int or start_floor < ENGINE_MINIMUM_START_FREE_BYTES:
        raise KitError("engine_build_receipt_start_threshold_too_low")
    if type(receipt["guard_minimum_free_bytes"]) is not int or receipt["guard_minimum_free_bytes"] < PHYSICAL_FREE_FLOOR_BYTES:
        raise KitError("engine_build_receipt_resource_gate:guard_minimum_free_bytes")
    for key in ("engine_git_status_sha256", "lake_executable_sha256", "lean_executable_sha256"):
        if type(receipt[key]) is not str or SHA256_HEX.fullmatch(receipt[key]) is None:
            raise KitError(f"engine_build_receipt_digest:{key}")
    for key in ("engine_git_head", "engine_git_tree"):
        if type(receipt[key]) is not str or re.fullmatch(r"[0-9a-f]{40}", receipt[key]) is None:
            raise KitError(f"engine_build_receipt_git_identity:{key}")
    for key in ("lake_version", "direct_lane_grant_reference"):
        _text(receipt[key], f"engine_build_receipt_text:{key}")
    _check_guard_log(read(PROVENANCE + "guard.stdout.log"), start_floor, receipt["guard_minimum_free_bytes"])
    return receipt


def _guard_fields(line: str, keys: set[str], code: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        key, separator, value = token.partition("=")
        if not separator or not key or not value or key in result:
            raise KitError("engine_guard_log_field_invalid")
        result[key] = value
    if set(result) != keys:
        raise KitError(code)
    return result


def _decimal(value: str, code: str) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise KitError(code)
    return int(value)


def _check_guard_log(raw: bytes, start_floor: int, minimum_free: int) -> None:
    """The guarded build ran under the v4 policy, met its memory floors, and cleaned up."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise KitError("engine_guard_log_invalid_utf8") from error
    if re.search(
        r"(?m)^(?:RUNNER_FAILURE|GUARD_STOP|CLEANUP_STOP_FAILURE|CLEANUP=FAIL|MUTEX=HELD_UNTIL_PROCESS_EXIT)(?:[=\s]|$)",
        text,
    ):
        raise KitError("engine_guard_log_failure_marker")

    def records(tag: str) -> list[str]:
        return re.findall(rf"(?m)^{tag} ([^\r\n]+)\r?$", text)

    reserve = {
        "reserve_floor_bytes": str(PHYSICAL_FREE_FLOOR_BYTES),
        "tolerance_percent": str(PHYSICAL_RESERVE_TOLERANCE_PERCENT),
    }
    policy = records("RESOURCE_POLICY")
    if len(policy) != 1 or _guard_fields(policy[0], {
        "version", "owner_waiver_effective", "process_tree_memory_cap", "physical_reserve_bytes",
        "physical_free_floor_bytes", "target_start_floor_bytes", "effective_start_floor_bytes",
        "tolerance_percent", "process_tree_sampling", "cleanup", "mutex", "activation",
    }, "engine_guard_log_policy_mismatch") != {
        "version": "v4",
        "owner_waiver_effective": "2026-09-23",
        "process_tree_memory_cap": "WAIVED_UNTIL_REVOKED",
        "physical_reserve_bytes": str(PHYSICAL_RESERVE_BYTES),
        "physical_free_floor_bytes": str(PHYSICAL_FREE_FLOOR_BYTES),
        "target_start_floor_bytes": str(start_floor),
        "effective_start_floor_bytes": str(start_floor),
        "tolerance_percent": str(PHYSICAL_RESERVE_TOLERANCE_PERCENT),
        "process_tree_sampling": "ENABLED",
        "cleanup": "ENABLED",
        "mutex": GUARD_MUTEX_NAME,
        "activation": "NONE",
    }:
        raise KitError("engine_guard_log_policy_mismatch")

    preflights = records("PHYSICAL_PREFLIGHT")
    if len(preflights) != 1:
        raise KitError("engine_guard_log_preflight_count")
    preflight = _guard_fields(preflights[0], {
        "free_bytes", "reserve_bytes", "reserve_floor_bytes", "target_start_floor_bytes",
        "effective_start_floor_bytes", "tolerance_percent",
    }, "engine_guard_log_preflight_fields")
    if _decimal(preflight.pop("free_bytes"), "engine_guard_log_preflight_fields") < start_floor or preflight != {
        **reserve,
        "reserve_bytes": str(PHYSICAL_RESERVE_BYTES),
        "target_start_floor_bytes": str(start_floor),
        "effective_start_floor_bytes": str(start_floor),
    }:
        raise KitError("engine_guard_log_preflight_mismatch")

    if records("CHILD_EXIT_CHECK") != ["exit7=7 exit0=0"]:
        raise KitError("engine_guard_log_self_test_check")
    statuses: dict[str, int] = {}
    for record in records("CHILD_EXIT_STATUS"):
        match = re.fullmatch(r"label=(\S+) exit=(0|[1-9][0-9]*)", record)
        if match is None:
            raise KitError("engine_guard_log_child_status_fields")
        if match.group(1) in statuses:
            raise KitError(f"engine_guard_log_duplicate_child:{match.group(1)}")
        statuses[match.group(1)] = int(match.group(2))
    if statuses.get("child-exit-7") != 7 or statuses.get("child-exit-0") != 0:
        raise KitError("engine_guard_log_self_test_status")
    targets = set(statuses) - {"child-exit-7", "child-exit-0"}
    if not targets or any(statuses[label] != 0 for label in targets):
        raise KitError("engine_guard_log_target_child_status")
    if re.findall(r"(?m)^CLEANUP=([^\r\n]*)\r?$", text) != [
        f"PASS label={label} owned_process_tree=empty" for label in statuses
    ]:
        raise KitError("engine_guard_log_cleanup_inventory")

    summaries: dict[str, int] = {}
    for line in records("LIVE_PHYSICAL_SUMMARY"):
        summary = _guard_fields(line, {
            "label", "samples", "min_free_bytes", "reserve_bytes", "peak_working_set_bytes",
            "peak_private_bytes", "reserve_floor_bytes", "tolerance_percent",
        }, "engine_guard_log_summary_fields")
        label = summary.pop("label")
        samples, free, _, _ = (
            _decimal(summary.pop(key), "engine_guard_log_summary_fields")
            for key in ("samples", "min_free_bytes", "peak_working_set_bytes", "peak_private_bytes")
        )
        if (
            label in summaries
            or samples <= 0
            or free < PHYSICAL_FREE_FLOOR_BYTES
            or summary != {**reserve, "reserve_bytes": str(PHYSICAL_RESERVE_BYTES)}
        ):
            raise KitError("engine_guard_log_summary_invalid")
        if label not in statuses:
            raise KitError("engine_guard_log_summary_without_child")
        summaries[label] = free
    if set(summaries) != set(statuses):
        raise KitError("engine_guard_log_summary_inventory")
    if min(summaries.values()) != minimum_free:
        raise KitError("engine_guard_log_minimum_free_mismatch")
    if re.findall(r"(?m)^MUTEX=([^\r\n]+)\r?$", text) != [f"RELEASED name={GUARD_MUTEX_NAME}"]:
        raise KitError("engine_guard_log_mutex_release")


# ---- Verification (the one checker) ----------------------------------------

def _manifest_files(manifest: dict[str, Any]) -> Members:
    if set(manifest) != {"claims", "files", "schema"} or manifest["schema"] != KIT_SCHEMA:
        raise KitError("kit_manifest_fields")
    if _canonical_json(manifest["claims"]) != _canonical_json(KIT_CLAIMS):
        raise KitError("kit_claims_pin")
    entries = manifest["files"]
    if type(entries) is not list or not entries or len(entries) > MAX_ARCHIVE_MEMBERS:
        raise KitError("kit_manifest_files")
    members: Members = {}
    previous = ""
    total = 0
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"path", "sha256", "size_bytes"}:
            raise KitError("kit_manifest_entry")
        path, digest, size = _safe_archive_path(entry["path"]), entry["sha256"], entry["size_bytes"]
        if path <= previous:
            raise KitError("kit_manifest_order_or_duplicate")
        if type(digest) is not str or SHA256_HEX.fullmatch(digest) is None:
            raise KitError("kit_manifest_digest")
        if type(size) is not int or not 0 <= size <= MAX_MEMBER_BYTES:
            raise KitError("kit_manifest_entry_value")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise KitError("kit_manifest_total_size_limit")
        members[path] = (size, digest)
        previous = path
    return members


def _check_retired_pins(read: Callable[[str], bytes]) -> None:
    # Parse the bundled checker's pin without executing bundled code during verification.
    pins = re.findall(rb'(?m)^RETIRED_PINS_SHA256 = "([0-9a-f]{64})"\r?$', read("app/right_rail_financial_owner_independent.py"))
    if len(pins) != 1 or hashlib.sha256(read(RETIRED_PIN_REGISTRY)).hexdigest().encode("ascii") != pins[0]:
        raise KitError("kit_retired_pins_mismatch")


def _check_contents(members: Members, read: Callable[[str], bytes]) -> dict[str, Any]:
    """Exact inventory, engine pins, closed Lean dependencies and the guarded build receipt."""
    paths = set(members)
    if {path for path in paths if not path.startswith(("engine/", "runtime/"))} != {*STATE_FILES, ENGINE_EXE}:
        raise KitError("kit_state_source_inventory")
    _check_retired_pins(read)
    if {path for path in paths if path.startswith("engine/") and not path.startswith(ENGINE_SOURCE_PREFIX)} != {
        *RELEASE_FILES.values(), PRODUCER,
    } - {ENGINE_EXE}:
        raise KitError("kit_engine_inventory")
    engine_sources = sorted(path for path in paths if path.startswith(ENGINE_SOURCE_PREFIX))
    if any(not (path.endswith(".lean") or path.removeprefix(ENGINE_SOURCE_PREFIX) in LEAN_CONFIG_FILES) for path in engine_sources):
        raise KitError("kit_engine_source_inventory")
    missing = [name for name in REQUIRED_LEAN_FILES if ENGINE_SOURCE_PREFIX + name not in paths]
    if missing:
        raise KitError("lean_source_missing:" + ",".join(missing))
    if any(
        not path.startswith(RUNTIME_PREFIX) or THIRD_PARTY_DIRECTORIES.intersection(part.lower() for part in PurePosixPath(path).parts)
        for path in paths if path.startswith("runtime/")
    ):
        raise KitError("kit_python_runtime_inventory")
    _check_runtime_member(members)

    source_manifest = _canonical_json({
        "files": [{"path": path, "sha256": members[path][1], "size_bytes": members[path][0]} for path in engine_sources],
        "schema": SOURCE_MANIFEST_SCHEMA,
    })
    if read(PROVENANCE + "source-manifest.json") != source_manifest:
        raise KitError("engine_source_manifest_not_canonical_or_current")

    pins = _engine_pins(read("app/right_rail_financial_engine.py"))
    for path, digest in (
        (ENGINE_EXE, pins[ENGINE_EXE]),
        (VECTORS + "request.bin", pins["request"]),
        (VECTORS + "result.expected.bin", pins["result"]),
        (VECTORS + "result.actual.bin", pins["result"]),
    ):
        if members[path][1] != digest:
            raise KitError(f"engine_artifact_pin_mismatch:{path}")
    if members[ENGINE_EXE][0] != pins["size"]:
        raise KitError(f"engine_artifact_size_mismatch:{ENGINE_EXE}")

    try:
        toolchain = read(ENGINE_SOURCE_PREFIX + "lean-toolchain").decode("utf-8").rstrip("\r\n")
        lake_manifest = _strict_json(read(ENGINE_SOURCE_PREFIX + "lake-manifest.json"), "lake_manifest")
        lakefile = tomllib.loads(read(ENGINE_SOURCE_PREFIX + "lakefile.toml").decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise KitError("lean_dependency_lock_invalid") from error
    if not toolchain:
        raise KitError("lean_toolchain_empty")
    if lake_manifest.get("packages") != [] or "require" in lakefile:
        raise KitError("lean_external_dependencies_not_closed")
    targets = lakefile.get("lean_exe", [])
    if type(targets) is not list or not any(type(item) is dict and item.get("name") == ENGINE_TARGET for item in targets):
        raise KitError("lean_engine_target_missing")

    return _check_receipt(members, read, {
        "engine_source_manifest_sha256": _sha256(source_manifest),
        "lean_toolchain": toolchain,
        "lean_toolchain_sha256": members[ENGINE_SOURCE_PREFIX + "lean-toolchain"][1],
        "lakefile_sha256": members[ENGINE_SOURCE_PREFIX + "lakefile.toml"][1],
        "lake_manifest_sha256": members[ENGINE_SOURCE_PREFIX + "lake-manifest.json"][1],
        "executable_size_bytes": pins["size"],
        "executable_sha256": pins[ENGINE_EXE],
        "request_vector_sha256": pins["request"],
        "result_vector_sha256": pins["result"],
    })


def _verify_open_archive(stream: BinaryIO, size: int, expected_digest: str | None) -> tuple[str, Members, dict[str, Any]]:
    """Return (archive digest, members including MANIFEST.json, engine receipt); fail closed on anything else."""
    if size > MAX_ARCHIVE_BYTES:
        raise KitError("archive_size_limit")
    stream.seek(0)
    actual_size, digest = _copy_digest(stream, size, "archive")
    if actual_size != size:
        raise KitError("archive_size_changed")
    if expected_digest is not None and digest != expected_digest:
        raise KitError(f"archive_sha256_mismatch:actual={digest}")
    stream.seek(0)
    try:
        archive = zipfile.ZipFile(stream, "r")
    except (OSError, zipfile.BadZipFile) as error:
        raise KitError("archive_invalid") from error
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS + 1:
            raise KitError("archive_member_limit")
        names = [info.filename for info in infos]
        _check_names(names)
        total = 0
        for info in infos:
            total += info.file_size
            if (
                info.is_dir()
                or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG)
                or info.flag_bits & 0x1
                or info.compress_type != zipfile.ZIP_STORED
                or info.compress_size != info.file_size
                or info.file_size > MAX_MEMBER_BYTES
                or total > MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES
            ):
                raise KitError("archive_member_format_or_size_invalid")
        if MANIFEST not in names or archive.getinfo(MANIFEST).file_size > MAX_MANIFEST_BYTES:
            raise KitError("archive_manifest_missing_or_too_large")
        manifest_raw = archive.read(MANIFEST)
        members = _manifest_files(_strict_canonical_json(manifest_raw, "kit_manifest"))
        if set(names) != set(members) | {MANIFEST}:
            raise KitError(
                f"archive_membership_mismatch:missing={sorted(set(members) - set(names))}:"
                f"extra={sorted(set(names) - set(members) - {MANIFEST})}"
            )
        for name, (member_size, member_digest) in members.items():
            with archive.open(name, "r") as member:
                if _copy_digest(member, member_size, name) != (member_size, member_digest):
                    raise KitError(f"archive_file_pin_mismatch:{name}")

        def read(name: str) -> bytes:
            if members[name][0] > MAX_SMALL_FILE_BYTES:
                raise KitError(f"provenance_file_too_large:{name}")
            return archive.read(name)

        receipt = _check_contents(members, read)
    members[MANIFEST] = (len(manifest_raw), _sha256(manifest_raw))
    return digest, members, receipt


def _verify_archive(path: Path, expected_digest: str | None) -> tuple[str, Members, dict[str, Any]]:
    stream, size = _open_regular(path, MAX_ARCHIVE_BYTES)
    with stream:
        return _verify_open_archive(stream, size, expected_digest)


def _verify_tree(root: Path, members: Members) -> None:
    """The extracted tree holds exactly the verified members, byte for byte, and nothing else."""
    files, directories = _walk(root, "extraction")
    expected_directories = {
        PurePosixPath(*PurePosixPath(name).parts[:index]).as_posix()
        for name in members for index in range(1, len(PurePosixPath(name).parts))
    }
    if set(files) != set(members) or directories != expected_directories:
        raise KitError(
            f"extraction_membership_mismatch:missing_files={sorted(set(members) - set(files))}:"
            f"extra_files={sorted(set(files) - set(members))}:"
            f"extra_directories={sorted(directories - expected_directories)}"
        )
    for name, pin in members.items():
        if _hash_file(files[name]) != pin:
            raise KitError(f"extraction_file_pin_mismatch:{name}")


def _expected_digest(value: str) -> str:
    if re.fullmatch(r"[0-9A-Fa-f]{64}", value) is None:
        raise KitError("expected_archive_sha256_invalid")
    return value.upper()


# ---- Commands -------------------------------------------------------------

def _absolute(value: Path, code: str) -> Path:
    if not Path(value).is_absolute():
        raise KitError(code)
    return Path(os.path.abspath(value))


def _collect_sources(args: argparse.Namespace) -> dict[str, Path]:
    sources = {name: REPO_ROOT / name for name in STATE_FILES}
    lean_root = _absolute(args.engine_root, "lean_source_root_must_be_absolute")
    for relative, path in _walk(lean_root, "lean_source", frozenset({".lake", ".git"}))[0].items():
        if relative.endswith(".lean") or relative in LEAN_CONFIG_FILES:
            sources[ENGINE_SOURCE_PREFIX + relative] = path
    release_root = _absolute(args.engine_release_dir, "engine_release_root_must_be_absolute")
    release_files, release_directories = _walk(release_root, "engine_release")
    if set(release_files) != set(RELEASE_FILES) or release_directories != RELEASE_DIRECTORIES:
        raise KitError(
            f"engine_release_inventory_mismatch:missing={sorted(set(RELEASE_FILES) - set(release_files))}:"
            f"extra={sorted(set(release_files) - set(RELEASE_FILES))}:directories={sorted(release_directories)}"
        )
    sources.update({RELEASE_FILES[relative]: path for relative, path in release_files.items()})
    sources[PRODUCER] = REPO_ROOT / "parked" / "release-producer" / "build_financial_correction_release.ps1"
    runtime_root = _absolute(args.python_runtime_root, "python_runtime_root_invalid")
    sources.update({RUNTIME_PREFIX + relative: path for relative, path in _runtime_files(runtime_root).items()})
    if len(sources) > MAX_ARCHIVE_MEMBERS:
        raise KitError("kit_manifest_member_limit")
    _check_names([*sources, MANIFEST])
    return dict(sorted(sources.items()))


def _zip_member(archive: zipfile.ZipFile, name: str, size: int) -> BinaryIO:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 0
    info.external_attr = 0x20
    info.file_size = size
    return archive.open(info, "w")


def _remove_created(path: Path, identity: tuple[int, int]) -> str | None:
    try:
        info = path.lstat()
        if _is_link(info) or not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != identity:
            return "archive_path_identity_not_owned; output preserved"
        path.unlink()
        return None
    except OSError as error:
        return f"archive_cleanup:{type(error).__name__}:{error}; output preserved"


def _assemble(args: argparse.Namespace) -> int:
    start_floor = args.expected_engine_guard_minimum_start_free_bytes
    if start_floor < ENGINE_MINIMUM_START_FREE_BYTES:
        raise KitError("engine_guard_minimum_start_free_bytes_invalid")
    grant = _text(args.direct_lane_grant_reference, "direct_lane_grant_reference_required")
    output = Path(os.path.abspath(args.output))
    sources = _collect_sources(args)
    pins = {name: _hash_file(path) for name, path in sources.items()}
    _check_runtime_member(pins)
    _probe_runtime(sources[RUNTIME_EXE])
    manifest = _canonical_json({
        "claims": KIT_CLAIMS,
        "files": [{"path": name, "sha256": digest, "size_bytes": size} for name, (size, digest) in pins.items()],
        "schema": KIT_SCHEMA,
    })
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError as error:
        raise KitError("archive_destination_must_be_new") from error
    info = os.fstat(descriptor)
    identity = (info.st_dev, info.st_ino)
    try:
        with os.fdopen(descriptor, "wb") as stream, zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED, allowZip64=True) as archive:
            for name, (size, digest) in pins.items():
                source, _ = _open_regular(sources[name], size)
                with source, _zip_member(archive, name, size) as sink:
                    if _copy_digest(source, size, name, sink) != (size, digest):
                        raise KitError(f"source_changed_during_assembly:{name}")
            with _zip_member(archive, MANIFEST, len(manifest)) as sink:
                sink.write(manifest)
        digest, members, receipt = _verify_archive(output, None)
        if receipt["guard_minimum_start_free_bytes"] != start_floor or receipt["direct_lane_grant_reference"] != grant:
            raise KitError("engine_build_receipt_handoff_mismatch")
    except BaseException as error:
        problem = _remove_created(output, identity)
        if problem is not None:
            raise KitError(f"archive_assembly_failed:{type(error).__name__}:{error};{problem}") from error
        raise
    print(f"ASSEMBLED archive={output} sha256={digest} files={len(members)} engine_guard_minimum_start_free_bytes={start_floor}")
    print("NEXT verify with --expected-archive-sha256 copied through an independent channel")
    return 0


def _verify_command(args: argparse.Namespace) -> int:
    digest, members, receipt = _verify_archive(Path(args.archive), _expected_digest(args.expected_archive_sha256))
    print(
        f"ARCHIVE_VERIFIED sha256={digest} files={len(members)} "
        f"engine_source_sha256={receipt['engine_source_manifest_sha256']} "
        f"engine_executable_sha256={receipt['executable_sha256']} "
        f"engine_guard_minimum_start_free_bytes={receipt['guard_minimum_start_free_bytes']}"
    )
    return 0


def _extract_command(args: argparse.Namespace) -> int:
    destination = Path(os.path.abspath(args.destination))
    stream, size = _open_regular(Path(args.archive), MAX_ARCHIVE_BYTES)
    with stream:
        digest, members, _ = _verify_open_archive(stream, size, _expected_digest(args.expected_archive_sha256))
        try:
            destination.mkdir()
        except FileExistsError as error:
            raise KitError("extraction_destination_must_be_new") from error
        try:
            stream.seek(0)
            with zipfile.ZipFile(stream, "r") as archive:
                for name, pin in members.items():
                    target = destination
                    for part in PurePosixPath(name).parts[:-1]:
                        target = target / part
                        target.mkdir(exist_ok=True)
                        info = target.lstat()
                        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                            raise KitError(f"extraction_directory_not_regular:{name}")
                    with archive.open(name, "r") as source, (target / PurePosixPath(name).name).open("xb") as sink:
                        if _copy_digest(source, pin[0], name, sink) != pin:
                            raise KitError(f"extraction_member_pin_mismatch:{name}")
            _verify_tree(destination, members)
        except Exception as error:
            raise KitError(f"extraction_incomplete_preserved:{type(error).__name__}:{error}:{destination}") from error
    print(f"EXTRACTED path={destination} files={len(members)} archive_sha256={digest}")
    return 0


def _verified_kit(args: argparse.Namespace) -> tuple[Path, Members]:
    _, members, _ = _verify_archive(Path(args.archive), _expected_digest(args.expected_archive_sha256))
    root = Path(os.path.abspath(args.extraction_root)) if args.extraction_root else REPO_ROOT
    _verify_tree(root, members)
    return root, members


def _runtime_environment(temporary_root: Path) -> dict[str, str]:
    environment = {name: os.environ[name] for name in ("PATH", "SystemRoot", "SYSTEMROOT", "WINDIR") if os.environ.get(name)}
    environment["TEMP"] = environment["TMP"] = str(temporary_root)
    return environment


def _launch(command: list[str], root: Path, environment: dict[str, str], code: str) -> int:
    try:
        return subprocess.run(command, cwd=root, env=environment, check=False, shell=False).returncode
    except OSError as error:
        raise KitError(code) from error


def _run_scenario(args: argparse.Namespace) -> int:
    root, members = _verified_kit(args)
    with tempfile.TemporaryDirectory(prefix="rightrail-financial-service-kit-") as temporary:
        work = Path(temporary)
        (work / "owner-workspace").mkdir()
        environment = _runtime_environment(work)
        environment["RR_FINANCIAL_SERVICE_KIT_TEST_WORKSPACE"] = str(work / "owner-workspace")
        print(f"RUNNING scenario={SERVICE_SCENARIO}", flush=True)
        code = _launch(
            [str(root / RUNTIME_EXE), "-I", "-B", "-S", str(root / "tools/service_kit/run_scenario.py")],
            root, environment, "service_scenario_launch_failed",
        )
    print(f"SERVICE_SCENARIO_EXIT={code}", flush=True)
    _verify_tree(root, members)
    return code


def _directory_identity(path: Path, label: str) -> tuple[int, int, int]:
    try:
        info = path.lstat()
    except OSError as error:
        raise KitError(f"{label}_workspace_unavailable") from error
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise KitError(f"{label}_workspace_must_be_existing_directory")
    return info.st_dev, info.st_ino, info.st_mode


def _is_empty(path: Path, code: str) -> bool:
    try:
        return next(path.iterdir(), None) is None
    except OSError as error:
        raise KitError(code) from error


def _owner_database(owner: Path) -> tuple[int, int, int] | None:
    """Identity of an existing owner database (and regular sidecars), or None for an empty workspace."""
    database = owner / "financial-owner.sqlite"
    for path in (database, *(Path(f"{database}{suffix}") for suffix in ("-journal", "-wal", "-shm"))):
        try:
            info = path.lstat()
        except FileNotFoundError:
            if path == database:
                if not _is_empty(owner, "owner_workspace_unreadable"):
                    raise KitError("owner_workspace_without_database_must_be_empty")
                return None
            continue
        except OSError as error:
            raise KitError("owner_database_identity_unavailable") from error
        if _is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise KitError("owner_database_files_must_be_regular_unlinked")
        if path == database:
            identity = (info.st_dev, info.st_ino, info.st_mode)
    return identity


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((os.path.normcase(path), os.path.normcase(root))) == os.path.normcase(root)
    except ValueError:
        return False


def _serve(args: argparse.Namespace) -> int:
    root, members = _verified_kit(args)
    owner = _absolute(args.owner_workspace, "owner_workspace_must_be_absolute")
    owner_identity = _directory_identity(owner, "owner")
    resolved_root, resolved_owner = (path.resolve(strict=True) for path in (root, owner))
    if _path_is_within(resolved_owner, resolved_root):
        raise KitError("service_workspace_inside_extracted_kit")
    database = _owner_database(owner)
    command = [
        str(root / RUNTIME_EXE), "-I", "-B", "-S", str(root / "tools/service_kit/run_server.py"),
        "--port", str(args.port),
        "--workspace", str(owner),
    ]
    if database is not None:
        command.append("--resume-existing-workspace")
    print(
        "STARTING synthetic loopback TEST Owner; application dispatch and egress flags are false; "
        "host-level outbound isolation is external",
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="rightrail-financial-service-temp-") as temporary:
        code = _launch(command, root, _runtime_environment(Path(temporary)), "service_server_launch_failed")
    print(f"SERVICE_SERVER_EXIT={code}", flush=True)
    if _directory_identity(owner, "owner") != owner_identity:
        raise KitError("service_workspace_identity_changed")
    after = _owner_database(owner)
    if (database is not None and after != database) or (code == 0 and after is None):
        raise KitError("owner_database_identity_changed_after_service")
    _verify_tree(root, members)
    return code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)

    assemble = commands.add_parser("assemble", help="create a deterministic, create-only offline ZIP archive")
    assemble.add_argument("--output", required=True, type=Path)
    assemble.add_argument("--engine-root", required=True, type=Path, help="absolute Lean workspace root (the trunk's lean/)")
    assemble.add_argument("--engine-release-dir", required=True, type=Path, help="Engine's exact release evidence directory")
    assemble.add_argument("--python-runtime-root", required=True, type=Path, help="complete pinned CPython 3.11.15 installation")
    assemble.add_argument(
        "--expected-engine-guard-minimum-start-free-bytes", required=True, type=int,
        help="exact Engine build guard value supplied in its authorized handoff",
    )
    assemble.add_argument(
        "--direct-lane-grant-reference", required=True,
        help="exact Driver lane grant reference from the authorized Engine handoff",
    )
    assemble.set_defaults(function=_assemble)

    verify = commands.add_parser("verify", help="verify archive bytes, exact membership, source pins, and Engine receipt")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--expected-archive-sha256", required=True)
    verify.set_defaults(function=_verify_command)

    extract = commands.add_parser("extract", help="verify then extract into a new directory without overwriting")
    extract.add_argument("archive", type=Path)
    extract.add_argument("destination", type=Path)
    extract.add_argument("--expected-archive-sha256", required=True)
    extract.set_defaults(function=_extract_command)

    for name, function, help_text in (
        ("run", _run_scenario, "verify an extracted kit and run the one focused synthetic service scenario"),
        ("serve", _serve, "verify an extracted kit and start the loopback synthetic staff workspace"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--archive", required=True, type=Path)
        command.add_argument("--expected-archive-sha256", required=True)
        command.add_argument("--extraction-root", type=Path)
        if name == "serve":
            command.add_argument("--owner-workspace", required=True, type=Path)
            command.add_argument("--port", type=int, default=8765)
        command.set_defaults(function=function)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.function(args))
    except KitError as error:
        print(f"SERVICE_KIT_BLOCKED code={error}", file=sys.stderr)
    except OSError as error:
        print(f"SERVICE_KIT_BLOCKED code=filesystem:{type(error).__name__}:{error}", file=sys.stderr)
    except (KeyError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        print(f"SERVICE_KIT_BLOCKED code=invalid_input:{type(error).__name__}:{error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
