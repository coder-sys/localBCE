"""Build, verify, extract, and run the offline synthetic Financial service kit.

The kit has no third-party Python dependencies. Assembly requires a separate
Engine build receipt binding the exact Lean source manifest to the correction
executable. This command never creates that receipt or infers source provenance.
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


KIT_SCHEMA = "RR/FINANCIAL/SERVICE-KIT-MANIFEST/v1"
BUILD_RECEIPT_SCHEMA = "RR/LEAN-ENGINE/BUILD-RECEIPT/v2"
ENGINE_TARGET = "blind_financial_correction"
EXPECTED_PYTHON_VERSION = "3.11.15"
EXPECTED_PYTHON_EXE_SHA256 = "F1D8D2AA2A8AD7C74B6C6300B29CFDBCB484FC7FFAD99B7FBFE1E31C048343B9"
GUARD_SHA256 = "57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB"
PHYSICAL_FREE_FLOOR_BYTES = 2_190_433_321
ENGINE_MINIMUM_START_FREE_BYTES = 4_190_433_321
PHYSICAL_RESERVE_BYTES = 3_221_225_472
PHYSICAL_RESERVE_TOLERANCE_PERCENT = 32
GUARD_MUTEX_NAME = r"Local\BlindLedgerDirectMaskBuild20260907"
MAX_PROVENANCE_FILE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_ARCHIVE_TOTAL_BYTES + 64 * 1024 * 1024
MAX_SOURCE_WALK_ENTRIES = 100_000
MAX_SOURCE_WALK_DEPTH = 64
MAX_SOURCE_TREE_BYTES = MAX_ARCHIVE_TOTAL_BYTES
WINDOWS_RESERVED_NAMES = {
    "aux", "con", "conin$", "conout$", "nul", "prn",
    *(f"com{digit}" for digit in "123456789¹²³"),
    *(f"lpt{digit}" for digit in "123456789¹²³"),
}
KIT_CLAIMS = {
    "proofSuiteId": None,
    "production_usable": False,
    "activation": False,
    "owner_mode": "TEST",
    "shadow_mode": "SHADOW",
    "dispatch_enabled": False,
    "egress_enabled": False,
    "payment_movement": False,
}
SERVICE_SCENARIO = (
    "tests.test_right_rail_financial_staff_server.RightRailFinancialStaffWorkspaceTests."
    "test_service_kit_correction_lost_response_retry_and_shadow_restore"
)

STATE_FILES = (
    "README.md",
    "docs/FINANCIAL_SERVICE_KIT.md",
    "docs/FINANCIAL_STAFF_WORKSPACE_ARCHITECTURE.md",
    "app/__init__.py",
    "app/minimal_clearance_resource_limits.py",
    "app/minimal_clearance_verifier_process.py",
    "app/right_rail_financial_engine.py",
    "app/right_rail_financial_mirror.py",
    "app/right_rail_financial_owner.py",
    "app/right_rail_financial_owner_independent.py",
    "app/right_rail_financial_semantic_adapter.py",
    "app/right_rail_financial_staff_server.py",
    "app/right_rail_financial_switch.py",
    "app/staff_workspace/index.html",
    "app/staff_workspace/staff.css",
    "app/staff_workspace/staff.js",
    "tests/__init__.py",
    "tests/rightrail_financial_expected_cases.py",
    "tests/test_right_rail_financial_acceptance.py",
    "tests/test_right_rail_financial_cli_switch.py",
    "tests/test_right_rail_financial_staff_server.py",
    "tests/test_right_rail_financial_switch.py",
    "tools/right_rail_financial_cli.py",
    "tools/right_rail_financial_service_kit.py",
    "tools/service_kit/run_scenario.py",
    "tools/service_kit/run_server.py",
)

REQUIRED_LEAN_FILES = (
    "BlindLedger/Financial/CorrectionTransition/Transition.lean",
    "BlindLedger/Financial/CorrectionTransition/Runtime.lean",
    "BlindLedger/Financial/CorrectionTransitionCli.lean",
    "lakefile.toml",
    "lake-manifest.json",
    "lean-toolchain",
)


class KitError(RuntimeError):
    """Stable, concise failure raised by the kit commands."""


def _sha256_stream(stream: BinaryIO) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest().upper()


def _sha256_path(path: Path) -> tuple[int, str]:
    stream, initial, parent_identities = _open_regular_source(path, f"file_unavailable:{path}")
    with stream:
        if initial.st_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise KitError(f"archive_member_too_large:{path}")
        size, digest = _sha256_stream(stream)
        _require_unchanged_open_source(path, stream, initial, parent_identities)
        if size > MAX_ARCHIVE_MEMBER_BYTES:
            raise KitError(f"archive_member_too_large:{path}")
        return size, digest


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _no_json_constant(value: str) -> None:
    raise KitError(f"json_nonstandard_number:{value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise KitError(f"json_duplicate_key:{key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_no_json_constant,
        )
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


def _safe_archive_path(value: object) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise KitError("archive_path_invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in path.parts)
        or any(":" in part for part in path.parts)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise KitError("archive_path_invalid")
    try:
        path_length = len(value.encode("utf-16-le")) // 2
        segment_lengths = [len(part.encode("utf-16-le")) // 2 for part in path.parts]
    except UnicodeEncodeError as error:
        raise KitError("archive_path_invalid_unicode") from error
    for part, segment_length in zip(path.parts, segment_lengths):
        base_name = part.split(".", 1)[0].casefold()
        if (
            part.endswith((".", " "))
            or any(ord(character) < 32 or character in '<>"|?*' for character in part)
            or base_name in WINDOWS_RESERVED_NAMES
            or segment_length > 255
        ):
            raise KitError("archive_path_not_portable")
    if path_length > 240:
        raise KitError("archive_path_too_long")
    return path.as_posix()


def _archive_path_key(value: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in PurePosixPath(value).parts)


def _validate_archive_name_inventory(names: list[str]) -> None:
    keys: dict[tuple[str, ...], str] = {}
    for name in names:
        safe_name = _safe_archive_path(name)
        key = _archive_path_key(safe_name)
        previous = keys.get(key)
        if previous is not None:
            raise KitError(f"archive_path_portable_collision:{previous}:{safe_name}")
        keys[key] = safe_name
    for key, name in keys.items():
        for size in range(1, len(key)):
            parent = keys.get(key[:size])
            if parent is not None:
                raise KitError(f"archive_file_directory_collision:{parent}:{name}")


def _is_reparse_point(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _source_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
        info.st_nlink,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        getattr(info, "st_file_attributes", 0),
    )


def _directory_chain_snapshot(path: Path) -> tuple[Path, dict[Path, tuple[int, int, int, int]]]:
    absolute = Path(os.path.abspath(path))
    identities: dict[Path, tuple[int, int, int, int]] = {}
    try:
        for ancestor in reversed(absolute.parents):
            info = ancestor.lstat()
            if _is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
                raise KitError(f"directory_path_not_regular:{ancestor}")
            identities[ancestor] = _directory_identity(info)
    except OSError as error:
        raise KitError(f"directory_path_unavailable:{path}") from error
    return absolute, identities


def _require_directory_chain_unchanged(identities: dict[Path, tuple[int, int, int, int]]) -> None:
    for path, identity in identities.items():
        try:
            current = path.lstat()
        except OSError as error:
            raise KitError(f"directory_identity_recheck_failed:{path}") from error
        if (
            _directory_identity(current) != identity
            or _is_reparse_point(current)
            or not stat.S_ISDIR(current.st_mode)
        ):
            raise KitError(f"directory_identity_changed:{path}")


def _require_safe_parent_chain(path: Path) -> Path:
    absolute, _ = _directory_chain_snapshot(path)
    return absolute


def _open_regular_source(
    path: Path, unavailable_code: str
) -> tuple[BinaryIO, os.stat_result, dict[Path, tuple[int, int, int, int]]]:
    absolute, parent_identities = _directory_chain_snapshot(path)
    try:
        before = absolute.lstat()
        if (
            _is_reparse_point(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise KitError(f"regular_unlinked_file_required:{absolute}")
        descriptor = os.open(
            absolute,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        stream = os.fdopen(descriptor, "rb")
        opened = os.fstat(stream.fileno())
        if (
            _source_identity(opened) != _source_identity(before)
            or _is_reparse_point(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            stream.close()
            raise KitError(f"file_identity_changed:{absolute}")
        _require_directory_chain_unchanged(parent_identities)
        return stream, before, parent_identities
    except KitError:
        raise
    except OSError as error:
        raise KitError(unavailable_code) from error


def _require_unchanged_open_source(
    path: Path,
    stream: BinaryIO,
    initial: os.stat_result,
    parent_identities: dict[Path, tuple[int, int, int, int]],
) -> None:
    absolute = Path(os.path.abspath(path))
    try:
        opened = os.fstat(stream.fileno())
        current = absolute.lstat()
    except OSError as error:
        raise KitError(f"file_identity_recheck_failed:{absolute}") from error
    if (
        _source_identity(opened) != _source_identity(initial)
        or _source_identity(current) != _source_identity(initial)
        or _is_reparse_point(current)
        or not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
    ):
        raise KitError(f"file_identity_changed:{absolute}")
    _require_directory_chain_unchanged(parent_identities)


def _require_regular_source(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise KitError(f"file_unavailable:{path}") from error
    if _is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise KitError(f"regular_file_required:{path}")


def _add_file(files: dict[str, dict[str, Any]], archive_path: str, source: Path, kind: str) -> None:
    relative = _safe_archive_path(archive_path)
    if relative in files:
        raise KitError(f"archive_path_duplicate:{relative}")
    _validate_archive_name_inventory([*files, relative])
    _require_regular_source(source)
    size, digest = _sha256_path(source)
    files[relative] = {"kind": kind, "path": relative, "sha256": digest, "size_bytes": size}


def _walk_regular_tree(
    root: Path,
    label: str,
    *,
    excluded_directories: set[str] | None = None,
    directory_inventory: set[str] | None = None,
) -> list[Path]:
    absolute_root = Path(os.path.abspath(root))
    _require_safe_parent_chain(absolute_root)
    try:
        root_info = absolute_root.lstat()
    except OSError as error:
        raise KitError(f"{label}_root_unavailable") from error
    if _is_reparse_point(root_info) or not stat.S_ISDIR(root_info.st_mode):
        raise KitError(f"{label}_root_invalid")
    excluded = {name.casefold() for name in (excluded_directories or set())}
    paths: list[Path] = []
    visited = 0
    total_bytes = 0

    def walk_error(error: OSError) -> None:
        raise KitError(f"{label}_walk_failed:{type(error).__name__}") from error

    for current, directory_names, file_names in os.walk(
        absolute_root, topdown=True, followlinks=False, onerror=walk_error
    ):
        current_path = Path(current)
        relative_directory = current_path.relative_to(absolute_root)
        if len(relative_directory.parts) > MAX_SOURCE_WALK_DEPTH:
            raise KitError(f"{label}_walk_depth_limit")
        try:
            current_info = current_path.lstat()
        except OSError as error:
            raise KitError(f"{label}_directory_identity_lost") from error
        if _is_reparse_point(current_info) or not stat.S_ISDIR(current_info.st_mode):
            raise KitError(f"{label}_directory_not_regular")
        retained_directories: list[str] = []
        for name in directory_names:
            visited += 1
            if visited > MAX_SOURCE_WALK_ENTRIES:
                raise KitError(f"{label}_walk_entry_limit")
            if name.casefold() in excluded:
                continue
            child = current_path / name
            try:
                info = child.lstat()
            except OSError as error:
                raise KitError(f"{label}_path_identity_lost:{child.relative_to(absolute_root).as_posix()}") from error
            if _is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
                raise KitError(f"{label}_directory_not_regular:{child.relative_to(absolute_root).as_posix()}")
            if directory_inventory is not None:
                directory_inventory.add(child.relative_to(absolute_root).as_posix())
            retained_directories.append(name)
        directory_names[:] = retained_directories
        for name in file_names:
            visited += 1
            if visited > MAX_SOURCE_WALK_ENTRIES:
                raise KitError(f"{label}_walk_entry_limit")
            path = current_path / name
            try:
                info = path.lstat()
            except OSError as error:
                raise KitError(f"{label}_path_identity_lost:{path.relative_to(absolute_root).as_posix()}") from error
            if _is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise KitError(f"{label}_file_not_regular:{path.relative_to(absolute_root).as_posix()}")
            total_bytes += info.st_size
            if total_bytes > MAX_SOURCE_TREE_BYTES:
                raise KitError(f"{label}_tree_size_limit")
            paths.append(path)
    return paths


def _engine_sources(lean_root: Path) -> list[Path]:
    if not lean_root.is_absolute():
        raise KitError("lean_source_root_must_be_absolute")
    lean_root = Path(os.path.abspath(lean_root))
    source_files: list[Path] = []
    for path in _walk_regular_tree(lean_root, "lean_source", excluded_directories={".lake", ".git"}):
        relative = path.relative_to(lean_root)
        if path.suffix == ".lean" or relative.as_posix() in {"lakefile.toml", "lake-manifest.json", "lean-toolchain"}:
            source_files.append(path)
    source_files.sort(key=lambda item: item.relative_to(lean_root).as_posix())
    present = {path.relative_to(lean_root).as_posix() for path in source_files}
    missing = sorted(set(REQUIRED_LEAN_FILES) - present)
    if missing:
        raise KitError("lean_source_missing:" + ",".join(missing))
    return source_files


def _engine_source_manifest(files: list[dict[str, Any]]) -> tuple[bytes, str]:
    entries = sorted([
        {"path": item["path"], "sha256": item["sha256"], "size_bytes": item["size_bytes"]}
        for item in files
        if item["kind"] == "engine_source"
    ], key=lambda item: item["path"])
    if not entries:
        raise KitError("engine_source_manifest_empty")
    raw = _canonical_json({"files": entries, "schema": "RR/LEAN-ENGINE/SOURCE-MANIFEST/v1"})
    return raw, hashlib.sha256(raw).hexdigest().upper()


def _parse_engine_pins(engine_source: bytes) -> dict[str, object]:
    text = engine_source.decode("utf-8")
    patterns = {
        "artifact_size_bytes": r"CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES\s*:\s*Final\[int\]\s*=\s*([0-9_]+)",
        "artifact_sha256": r"CORRECTION_TRANSITION_ARTIFACT_SHA256\s*:\s*Final\[bytes\]\s*=\s*bytes\.fromhex\(\s*\"([0-9A-F]{64})\"",
        "request_vector_sha256": r"CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256\s*:\s*Final\[bytes\]\s*=\s*bytes\.fromhex\(\s*\"([0-9A-F]{64})\"",
        "result_vector_sha256": r"CORRECTION_TRANSITION_RESULT_VECTOR_SHA256\s*:\s*Final\[bytes\]\s*=\s*bytes\.fromhex\(\s*\"([0-9A-F]{64})\"",
    }
    values: dict[str, object] = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, text)
        if match is None:
            raise KitError(f"engine_pin_not_found:{name}")
        values[name] = int(match.group(1).replace("_", "")) if name == "artifact_size_bytes" else match.group(1)
    return values


def _validate_engine_artifacts(files: dict[str, dict[str, Any]], source_payload: bytes) -> dict[str, object]:
    pins = _parse_engine_pins(source_payload)
    checks = {
        "engine/artifacts/blind_financial_correction.exe": (pins["artifact_size_bytes"], pins["artifact_sha256"]),
        "engine/vectors/request.bin": (None, pins["request_vector_sha256"]),
        "engine/vectors/result.expected.bin": (None, pins["result_vector_sha256"]),
        "engine/vectors/result.actual.bin": (None, pins["result_vector_sha256"]),
    }
    for archive_path, (expected_size, expected_digest) in checks.items():
        item = files.get(archive_path)
        if item is None or item["sha256"] != expected_digest:
            raise KitError(f"engine_artifact_pin_mismatch:{archive_path}")
        if expected_size is not None and item["size_bytes"] != expected_size:
            raise KitError(f"engine_artifact_size_mismatch:{archive_path}")
    actual = files["engine/vectors/result.actual.bin"]
    expected = files["engine/vectors/result.expected.bin"]
    if actual["size_bytes"] != expected["size_bytes"] or actual["sha256"] != expected["sha256"]:
        raise KitError("engine_result_vector_not_byte_equal")
    return pins


def _validate_receipt(
    receipt_raw: bytes,
    stdout_raw: bytes,
    stderr_raw: bytes,
    guard_stdout_raw: bytes,
    guard_stderr_raw: bytes,
    producer_script_raw: bytes,
    *,
    source_manifest_sha256: str,
    source_pins: dict[str, object],
    reuse_request_sha256: str,
    reuse_result_sha256: str,
    toolchain: str,
    toolchain_sha256: str,
    lakefile_sha256: str,
    lake_manifest_sha256: str,
    expected_engine_guard_minimum_start_free_bytes: int,
    expected_direct_lane_grant_reference: str,
) -> dict[str, Any]:
    receipt = _strict_canonical_json(receipt_raw, "engine_build_receipt")
    required = {
        "schema", "status", "target", "engine_source_manifest_sha256", "lean_toolchain",
        "lean_toolchain_sha256", "lakefile_sha256", "lake_manifest_sha256", "executable_size_bytes",
        "executable_sha256", "request_vector_sha256", "result_vector_sha256", "reuse_request_vector_sha256",
        "reuse_result_vector_sha256", "stdout_sha256", "stderr_sha256", "producer_script_sha256",
        "guard_stdout_sha256", "guard_stderr_sha256", "guard_wrapper_sha256", "guard_outer_exit_code",
        "guard_child_exit_code", "guard_self_test_exit7", "guard_self_test_exit0",
        "guard_minimum_start_free_bytes", "guard_minimum_free_bytes", "guard_cleanup", "guard_mutex",
        "lake_build_exit_code", "transition_vector_exit_code", "reuse_vector_exit_code", "engine_git_head",
        "engine_git_tree", "engine_git_status_sha256", "lake_version", "lake_executable_sha256",
        "lean_executable_sha256", "direct_lane_grant_reference",
    }
    if set(receipt) != required:
        raise KitError("engine_build_receipt_fields")
    if type(receipt.get("executable_size_bytes")) is not int or receipt["executable_size_bytes"] <= 0:
        raise KitError("engine_build_receipt_executable_size")
    expected = {
        "schema": BUILD_RECEIPT_SCHEMA,
        "status": "PASS",
        "target": ENGINE_TARGET,
        "engine_source_manifest_sha256": source_manifest_sha256,
        "lean_toolchain": toolchain,
        "lean_toolchain_sha256": toolchain_sha256,
        "lakefile_sha256": lakefile_sha256,
        "lake_manifest_sha256": lake_manifest_sha256,
        "executable_size_bytes": source_pins["artifact_size_bytes"],
        "executable_sha256": source_pins["artifact_sha256"],
        "request_vector_sha256": source_pins["request_vector_sha256"],
        "result_vector_sha256": source_pins["result_vector_sha256"],
        "reuse_request_vector_sha256": reuse_request_sha256,
        "reuse_result_vector_sha256": reuse_result_sha256,
        "stdout_sha256": hashlib.sha256(stdout_raw).hexdigest().upper(),
        "stderr_sha256": hashlib.sha256(stderr_raw).hexdigest().upper(),
        "producer_script_sha256": hashlib.sha256(producer_script_raw).hexdigest().upper(),
        "guard_stdout_sha256": hashlib.sha256(guard_stdout_raw).hexdigest().upper(),
        "guard_stderr_sha256": hashlib.sha256(guard_stderr_raw).hexdigest().upper(),
        "guard_wrapper_sha256": GUARD_SHA256,
        "guard_outer_exit_code": 0,
        "guard_child_exit_code": 0,
        "guard_self_test_exit7": 7,
        "guard_self_test_exit0": 0,
        "guard_minimum_start_free_bytes": expected_engine_guard_minimum_start_free_bytes,
        "guard_cleanup": "PASS",
        "guard_mutex": "RELEASED",
        "lake_build_exit_code": 0,
        "transition_vector_exit_code": 0,
        "reuse_vector_exit_code": 0,
        "direct_lane_grant_reference": expected_direct_lane_grant_reference,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise KitError(f"engine_build_receipt_mismatch:{key}")
    for key in (
        "guard_outer_exit_code", "guard_child_exit_code", "guard_self_test_exit7", "guard_self_test_exit0",
        "guard_minimum_start_free_bytes", "lake_build_exit_code", "transition_vector_exit_code",
        "reuse_vector_exit_code",
    ):
        if type(receipt.get(key)) is not int:
            raise KitError(f"engine_build_receipt_type:{key}")
    for key in ("guard_minimum_start_free_bytes", "guard_minimum_free_bytes"):
        value = receipt.get(key)
        if type(value) is not int or value < PHYSICAL_FREE_FLOOR_BYTES:
            raise KitError(f"engine_build_receipt_resource_gate:{key}")
    for key in (
        "engine_git_status_sha256", "lake_executable_sha256", "lean_executable_sha256",
    ):
        value = receipt.get(key)
        if type(value) is not str or re.fullmatch(r"[0-9A-F]{64}", value) is None:
            raise KitError(f"engine_build_receipt_digest:{key}")
    for key in ("engine_git_head", "engine_git_tree"):
        value = receipt.get(key)
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise KitError(f"engine_build_receipt_git_identity:{key}")
    for key in ("lake_version", "direct_lane_grant_reference"):
        value = receipt.get(key)
        if (
            type(value) is not str
            or not value.strip()
            or len(value) > 2048
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise KitError(f"engine_build_receipt_text:{key}")
    if expected_engine_guard_minimum_start_free_bytes < ENGINE_MINIMUM_START_FREE_BYTES:
        raise KitError("engine_build_receipt_start_threshold_too_low")
    _validate_guard_log(
        guard_stdout_raw,
        expected_start_free_bytes=expected_engine_guard_minimum_start_free_bytes,
        expected_minimum_free_bytes=receipt["guard_minimum_free_bytes"],
    )
    return receipt


def _validate_guard_log(
    raw: bytes,
    *,
    expected_start_free_bytes: int,
    expected_minimum_free_bytes: int,
) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise KitError("engine_guard_log_invalid_utf8") from error
    if re.search(
        r"(?m)^(?:RUNNER_FAILURE|GUARD_STOP|CLEANUP_STOP_FAILURE|CLEANUP=FAIL|"
        r"MUTEX=HELD_UNTIL_PROCESS_EXIT)(?:[=\s]|$)",
        text,
    ):
        raise KitError("engine_guard_log_failure_marker")

    def fields(line: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for token in line.split():
            if "=" not in token:
                raise KitError("engine_guard_log_field_invalid")
            key, value = token.split("=", 1)
            if not key or not value or key in result:
                raise KitError("engine_guard_log_field_invalid")
            result[key] = value
        return result

    def decimal(record: dict[str, str], key: str, error_code: str) -> int:
        value = record.get(key)
        if type(value) is not str or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
            raise KitError(error_code)
        return int(value)

    policy_lines = re.findall(r"(?m)^RESOURCE_POLICY ([^\r\n]+)$", text)
    if len(policy_lines) != 1:
        raise KitError("engine_guard_log_policy_count")
    policy = fields(policy_lines[0])
    expected_policy = {
        "version": "v4",
        "owner_waiver_effective": "2026-09-23",
        "process_tree_memory_cap": "WAIVED_UNTIL_REVOKED",
        "physical_reserve_bytes": str(PHYSICAL_RESERVE_BYTES),
        "physical_free_floor_bytes": str(PHYSICAL_FREE_FLOOR_BYTES),
        "target_start_floor_bytes": str(expected_start_free_bytes),
        "effective_start_floor_bytes": str(expected_start_free_bytes),
        "tolerance_percent": str(PHYSICAL_RESERVE_TOLERANCE_PERCENT),
        "process_tree_sampling": "ENABLED",
        "cleanup": "ENABLED",
        "mutex": GUARD_MUTEX_NAME,
        "activation": "NONE",
    }
    if policy != expected_policy:
        raise KitError("engine_guard_log_policy_mismatch")

    preflights = re.findall(r"(?m)^PHYSICAL_PREFLIGHT ([^\r\n]+)$", text)
    if len(preflights) != 1:
        raise KitError("engine_guard_log_preflight_count")
    preflight = fields(preflights[0])
    if set(preflight) != {
        "free_bytes", "reserve_bytes", "reserve_floor_bytes", "target_start_floor_bytes",
        "effective_start_floor_bytes", "tolerance_percent",
    }:
        raise KitError("engine_guard_log_preflight_fields")
    preflight_free = decimal(preflight, "free_bytes", "engine_guard_log_preflight_fields")
    preflight_reserve = decimal(preflight, "reserve_bytes", "engine_guard_log_preflight_fields")
    preflight_floor = decimal(preflight, "reserve_floor_bytes", "engine_guard_log_preflight_fields")
    preflight_target = decimal(preflight, "target_start_floor_bytes", "engine_guard_log_preflight_fields")
    preflight_effective = decimal(preflight, "effective_start_floor_bytes", "engine_guard_log_preflight_fields")
    preflight_tolerance = decimal(preflight, "tolerance_percent", "engine_guard_log_preflight_fields")
    if (
        preflight_free < expected_start_free_bytes
        or preflight_target != expected_start_free_bytes
        or preflight_effective != expected_start_free_bytes
        or preflight_reserve != PHYSICAL_RESERVE_BYTES
        or preflight_floor != PHYSICAL_FREE_FLOOR_BYTES
        or preflight_tolerance != PHYSICAL_RESERVE_TOLERANCE_PERCENT
    ):
        raise KitError("engine_guard_log_preflight_mismatch")

    check_lines = re.findall(r"(?m)^CHILD_EXIT_CHECK ([^\r\n]+)$", text)
    if check_lines != ["exit7=7 exit0=0"]:
        raise KitError("engine_guard_log_self_test_check")
    status_records = re.findall(r"(?m)^CHILD_EXIT_STATUS ([^\r\n]+)$", text)
    statuses: dict[str, int] = {}
    for record in status_records:
        match = re.fullmatch(r"label=(\S+) exit=(0|[1-9][0-9]*)", record)
        if match is None:
            raise KitError("engine_guard_log_child_status_fields")
        label, value = match.groups()
        if label in statuses:
            raise KitError(f"engine_guard_log_duplicate_child:{label}")
        statuses[label] = int(value)
    if statuses.get("child-exit-7") != 7 or statuses.get("child-exit-0") != 0:
        raise KitError("engine_guard_log_self_test_status")
    target_labels = set(statuses) - {"child-exit-7", "child-exit-0"}
    if not target_labels or any(statuses[label] != 0 for label in target_labels):
        raise KitError("engine_guard_log_target_child_status")

    cleanup_records = re.findall(r"(?m)^CLEANUP=([^\r\n]*)$", text)
    expected_cleanups = [
        f"PASS label={label} owned_process_tree=empty"
        for label in statuses
    ]
    if cleanup_records != expected_cleanups:
        raise KitError("engine_guard_log_cleanup_inventory")
    summaries: dict[str, tuple[int, int]] = {}
    for line in re.findall(r"(?m)^LIVE_PHYSICAL_SUMMARY ([^\r\n]+)$", text):
        summary = fields(line)
        if set(summary) != {
            "label", "samples", "min_free_bytes", "reserve_bytes", "peak_working_set_bytes",
            "peak_private_bytes", "reserve_floor_bytes", "tolerance_percent",
        }:
            raise KitError("engine_guard_log_summary_fields")
        label = summary["label"]
        sample_count = decimal(summary, "samples", "engine_guard_log_summary_fields")
        minimum_free = decimal(summary, "min_free_bytes", "engine_guard_log_summary_fields")
        reserve = decimal(summary, "reserve_bytes", "engine_guard_log_summary_fields")
        decimal(summary, "peak_working_set_bytes", "engine_guard_log_summary_fields")
        decimal(summary, "peak_private_bytes", "engine_guard_log_summary_fields")
        reserve_floor = decimal(summary, "reserve_floor_bytes", "engine_guard_log_summary_fields")
        tolerance = decimal(summary, "tolerance_percent", "engine_guard_log_summary_fields")
        if (
            label in summaries
            or sample_count <= 0
            or minimum_free < PHYSICAL_FREE_FLOOR_BYTES
            or reserve != PHYSICAL_RESERVE_BYTES
            or reserve_floor != PHYSICAL_FREE_FLOOR_BYTES
            or tolerance != PHYSICAL_RESERVE_TOLERANCE_PERCENT
        ):
            raise KitError("engine_guard_log_summary_invalid")
        if label not in statuses:
            raise KitError("engine_guard_log_summary_without_child")
        summaries[label] = (sample_count, minimum_free)
    if set(summaries) != set(statuses):
        raise KitError("engine_guard_log_summary_inventory")
    if min(minimum for _, minimum in summaries.values()) != expected_minimum_free_bytes:
        raise KitError("engine_guard_log_minimum_free_mismatch")
    mutex_lines = re.findall(r"(?m)^MUTEX=([^\r\n]+)$", text)
    if mutex_lines != [f"RELEASED name={GUARD_MUTEX_NAME}"]:
        raise KitError("engine_guard_log_mutex_release")


def _check_runtime(runtime_root: Path) -> list[tuple[str, Path]]:
    if not runtime_root.is_absolute():
        raise KitError("python_runtime_root_invalid")
    runtime_root = Path(os.path.abspath(runtime_root))
    runtime_files = _walk_regular_tree(runtime_root, "python_runtime")
    executable = runtime_root / "python.exe"
    stream, initial, parent_identities = _open_regular_source(executable, "python_runtime_executable_unavailable")
    with stream:
        size, digest = _sha256_stream(stream)
        _require_unchanged_open_source(executable, stream, initial, parent_identities)
        if size != initial.st_size or digest != EXPECTED_PYTHON_EXE_SHA256:
            raise KitError("python_runtime_executable_pin_mismatch")
        try:
            result = subprocess.run(
                [str(executable), "-I", "-S", "-c", "import sys; print('.'.join(map(str, sys.version_info[:3])))"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise KitError("python_runtime_version_probe_failed") from error
        _require_unchanged_open_source(executable, stream, initial, parent_identities)
        stream.seek(0)
        post_size, post_digest = _sha256_stream(stream)
        _require_unchanged_open_source(executable, stream, initial, parent_identities)
        if post_size != size or post_digest != digest:
            raise KitError("python_runtime_executable_changed_during_probe")
    if result.returncode != 0 or result.stdout.decode("ascii", "replace").strip() != EXPECTED_PYTHON_VERSION or result.stderr:
        raise KitError("python_runtime_version_mismatch")
    found: list[tuple[str, Path]] = []
    excluded_site_files = 0
    for path in runtime_files:
        relative = path.relative_to(runtime_root)
        # The pinned CPython ships pip under Lib/site-packages. The kit always
        # runs the bundled interpreter with -S, so that directory is never on
        # sys.path; leave it out rather than bundle third-party code.
        if len(relative.parts) > 2 and relative.parts[0].lower() == "lib" and relative.parts[1].lower() == "site-packages":
            excluded_site_files += 1
            continue
        if any(part.lower() in {"site-packages", "dist-packages"} for part in relative.parts):
            raise KitError("python_runtime_contains_third_party_packages")
        found.append((relative.as_posix(), path))
    if excluded_site_files:
        print(f"RUNTIME_EXCLUDED path=Lib/site-packages files={excluded_site_files} reason=third_party_not_bundled")
    found.sort(key=lambda item: item[0])
    if not found or "python.exe" not in {name for name, _ in found}:
        raise KitError("python_runtime_files_missing")
    return found


def _read_external_file(path: Path, label: str) -> bytes:
    stream, initial, parent_identities = _open_regular_source(path, f"file_unavailable:{label}")
    with stream:
        if initial.st_size > MAX_PROVENANCE_FILE_BYTES:
            raise KitError(f"provenance_file_too_large:{label}")
        raw = stream.read(MAX_PROVENANCE_FILE_BYTES + 1)
        if len(raw) > MAX_PROVENANCE_FILE_BYTES:
            raise KitError(f"provenance_file_too_large:{label}")
        _require_unchanged_open_source(path, stream, initial, parent_identities)
        if len(raw) != initial.st_size:
            raise KitError(f"file_size_changed:{label}")
        return raw


def _collect_payload(args: argparse.Namespace) -> tuple[dict[str, dict[str, Any]], dict[str, object]]:
    repo_root = Path(__file__).resolve().parents[1]
    expected_engine_guard_minimum_start_free_bytes = args.expected_engine_guard_minimum_start_free_bytes
    if (
        type(expected_engine_guard_minimum_start_free_bytes) is not int
        or expected_engine_guard_minimum_start_free_bytes < ENGINE_MINIMUM_START_FREE_BYTES
    ):
        raise KitError("engine_guard_minimum_start_free_bytes_invalid")
    expected_direct_lane_grant_reference = args.direct_lane_grant_reference
    if (
        type(expected_direct_lane_grant_reference) is not str
        or not expected_direct_lane_grant_reference.strip()
        or len(expected_direct_lane_grant_reference) > 2048
        or any(ord(character) < 32 or ord(character) == 127 for character in expected_direct_lane_grant_reference)
    ):
        raise KitError("direct_lane_grant_reference_required")
    files: dict[str, dict[str, Any]] = {}
    for relative in STATE_FILES:
        source = repo_root / Path(relative)
        _add_file(files, relative, source, "state_source")

    lean_root = Path(args.engine_root)
    if not lean_root.is_absolute():
        raise KitError("lean_source_root_must_be_absolute")
    lean_root = Path(os.path.abspath(lean_root))
    for source in _engine_sources(lean_root):
        relative = source.relative_to(lean_root).as_posix()
        _add_file(files, f"engine/source/{relative}", source, "engine_source")

    release_root = Path(args.engine_release_dir)
    if not release_root.is_absolute():
        raise KitError("engine_release_root_must_be_absolute")
    release_root = Path(os.path.abspath(release_root))
    release_directories: set[str] = set()
    release_files = _walk_regular_tree(
        release_root,
        "engine_release",
        directory_inventory=release_directories,
    )
    expected_release_paths = {
        "blind_financial_correction.exe",
        "source-manifest.json",
        "vectors/request.bin",
        "vectors/result.expected.bin",
        "vectors/result.actual.bin",
        "vectors/reuse-request.bin",
        "vectors/reuse-result.expected.bin",
        "vectors/reuse-result.actual.bin",
        "logs/child.stdout.log",
        "logs/child.stderr.log",
        "logs/guard.stdout.log",
        "logs/guard.stderr.log",
        "provenance/engine-build-receipt.json",
    }
    actual_release_paths = {path.relative_to(release_root).as_posix() for path in release_files}
    if actual_release_paths != expected_release_paths:
        missing = sorted(expected_release_paths - actual_release_paths)
        extra = sorted(actual_release_paths - expected_release_paths)
        raise KitError(f"engine_release_inventory_mismatch:missing={missing}:extra={extra}")
    if release_directories != {"vectors", "logs", "provenance"}:
        missing = sorted({"vectors", "logs", "provenance"} - release_directories)
        extra = sorted(release_directories - {"vectors", "logs", "provenance"})
        raise KitError(f"engine_release_directory_inventory_mismatch:missing={missing}:extra={extra}")
    release_source = {path.relative_to(release_root).as_posix(): path for path in release_files}
    _add_file(
        files,
        "engine/artifacts/blind_financial_correction.exe",
        release_source["blind_financial_correction.exe"],
        "engine_executable",
    )
    for name in ("request.bin", "result.expected.bin", "result.actual.bin"):
        _add_file(files, f"engine/vectors/{name}", release_source[f"vectors/{name}"], "engine_vector")
    for name in (
        "reuse-request.bin", "reuse-result.expected.bin", "reuse-result.actual.bin",
    ):
        _add_file(files, f"engine/vectors/{name}", release_source[f"vectors/{name}"], "engine_vector")
    reuse_expected = files["engine/vectors/reuse-result.expected.bin"]
    reuse_actual = files["engine/vectors/reuse-result.actual.bin"]
    if (
        reuse_actual["size_bytes"] != reuse_expected["size_bytes"]
        or reuse_actual["sha256"] != reuse_expected["sha256"]
    ):
        raise KitError("engine_reuse_result_vector_not_byte_equal")

    runtime_root = Path(args.python_runtime_root)
    runtime_files = _check_runtime(runtime_root)
    for relative, source in runtime_files:
        _add_file(files, f"runtime/python311/{relative}", source, "python_runtime")

    raw_receipt = _read_external_file(release_source["provenance/engine-build-receipt.json"], "engine_build_receipt")
    raw_stdout = _read_external_file(release_source["logs/child.stdout.log"], "engine_build_stdout")
    raw_stderr = _read_external_file(release_source["logs/child.stderr.log"], "engine_build_stderr")
    raw_guard_stdout = _read_external_file(release_source["logs/guard.stdout.log"], "engine_guard_stdout")
    raw_guard_stderr = _read_external_file(release_source["logs/guard.stderr.log"], "engine_guard_stderr")
    source_manifest_path_on_disk = release_source["source-manifest.json"]
    raw_source_manifest = _read_external_file(source_manifest_path_on_disk, "engine_source_manifest")
    producer_script_path_on_disk = lean_root.parents[1] / "tools" / "build_financial_correction_release.ps1"
    raw_producer_script = _read_external_file(producer_script_path_on_disk, "engine_producer_script")
    receipt_path = "engine/provenance/engine-build-receipt.json"
    stdout_path = "engine/provenance/child.stdout.log"
    stderr_path = "engine/provenance/child.stderr.log"
    guard_stdout_path = "engine/provenance/guard.stdout.log"
    guard_stderr_path = "engine/provenance/guard.stderr.log"
    producer_script_path = "engine/producer/build_financial_correction_release.ps1"
    source_manifest_path = "engine/provenance/source-manifest.json"
    for relative, payload, kind in (
        (receipt_path, raw_receipt, "engine_build_receipt"),
        (stdout_path, raw_stdout, "engine_build_log"),
        (stderr_path, raw_stderr, "engine_build_log"),
        (guard_stdout_path, raw_guard_stdout, "engine_guard_log"),
        (guard_stderr_path, raw_guard_stderr, "engine_guard_log"),
        (producer_script_path, raw_producer_script, "engine_build_producer"),
        (source_manifest_path, raw_source_manifest, "engine_source_manifest"),
    ):
        digest = hashlib.sha256(payload).hexdigest().upper()
        files[relative] = {"kind": kind, "path": relative, "sha256": digest, "size_bytes": len(payload)}

    engine_source_files = [item for item in files.values() if item["kind"] == "engine_source"]
    source_manifest_raw, source_manifest_sha = _engine_source_manifest(engine_source_files)
    if raw_source_manifest != source_manifest_raw:
        raise KitError("engine_source_manifest_not_canonical_or_current")
    engine_adapter_path = repo_root / "app/right_rail_financial_engine.py"
    engine_adapter = _read_external_file(engine_adapter_path, "financial_engine_adapter")
    if hashlib.sha256(engine_adapter).hexdigest().upper() != files["app/right_rail_financial_engine.py"]["sha256"]:
        raise KitError("financial_engine_adapter_changed_during_assembly")
    source_pins = _validate_engine_artifacts(files, engine_adapter)

    lean_config = {
        name: next(item for item in files.values() if item["path"] == f"engine/source/{name}")
        for name in ("lean-toolchain", "lakefile.toml", "lake-manifest.json")
    }
    toolchain_entry = lean_config["lean-toolchain"]
    toolchain_path = lean_root / "lean-toolchain"
    toolchain_raw = _read_external_file(toolchain_path, "lean_toolchain")
    try:
        toolchain = toolchain_raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise KitError("lean_toolchain_invalid_utf8") from error
    if not toolchain:
        raise KitError("lean_toolchain_empty")
    try:
        lake_manifest = _strict_json(_read_external_file(lean_root / "lake-manifest.json", "lake_manifest"), "lake_manifest")
        lakefile = tomllib.loads(_read_external_file(lean_root / "lakefile.toml", "lakefile").decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise KitError("lean_dependency_lock_invalid") from error
    if lake_manifest.get("packages") != [] or "require" in lakefile:
        raise KitError("lean_external_dependencies_not_closed")
    lake_targets = lakefile.get("lean_exe", [])
    if type(lake_targets) is not list or not any(
        type(item) is dict and item.get("name") == ENGINE_TARGET for item in lake_targets
    ):
        raise KitError("lean_correction_target_missing")
    receipt = _validate_receipt(
        raw_receipt,
        raw_stdout,
        raw_stderr,
        raw_guard_stdout,
        raw_guard_stderr,
        raw_producer_script,
        source_manifest_sha256=source_manifest_sha,
        source_pins=source_pins,
        reuse_request_sha256=files["engine/vectors/reuse-request.bin"]["sha256"],
        reuse_result_sha256=files["engine/vectors/reuse-result.expected.bin"]["sha256"],
        toolchain=toolchain,
        toolchain_sha256=toolchain_entry["sha256"],
        lakefile_sha256=lean_config["lakefile.toml"]["sha256"],
        lake_manifest_sha256=lean_config["lake-manifest.json"]["sha256"],
        expected_engine_guard_minimum_start_free_bytes=expected_engine_guard_minimum_start_free_bytes,
        expected_direct_lane_grant_reference=expected_direct_lane_grant_reference,
    )
    runtime_executable = files["runtime/python311/python.exe"]
    metadata = {
        "blocked_components": {
            "queue.lifecycle_source_bound_runtime": {
                "reason": "MISSING/BLOCKED: no current source-bound Queue runtime handoff; Queue omitted",
                "status": "MISSING/BLOCKED",
            }
        },
        "claims": KIT_CLAIMS,
        "engine": {
            "build_receipt_sha256": hashlib.sha256(raw_receipt).hexdigest().upper(),
            "executable_path": "engine/artifacts/blind_financial_correction.exe",
            "executable_sha256": source_pins["artifact_sha256"],
            "executable_size_bytes": source_pins["artifact_size_bytes"],
            "request_vector_sha256": source_pins["request_vector_sha256"],
            "result_vector_sha256": source_pins["result_vector_sha256"],
            "reuse_request_vector_sha256": files["engine/vectors/reuse-request.bin"]["sha256"],
            "reuse_result_vector_sha256": files["engine/vectors/reuse-result.expected.bin"]["sha256"],
            "source_manifest_sha256": source_manifest_sha,
            "source_manifest_path": source_manifest_path,
            "target": ENGINE_TARGET,
            "toolchain": toolchain,
        },
        "python": {
            "executable_path": "runtime/python311/python.exe",
            "executable_sha256": runtime_executable["sha256"],
            "executable_size_bytes": runtime_executable["size_bytes"],
            "third_party_packages": [],
            "version": EXPECTED_PYTHON_VERSION,
        },
        "python_dependency_lock": {"schema": "RR/PYTHON-DEPENDENCIES/v1", "third_party_packages": []},
        "scenario": SERVICE_SCENARIO,
        "scope": "synthetic, local, non-PHI, nonpayment, dispatch-disabled, nonactivating",
    }
    metadata["engine"]["build_receipt"] = receipt_path
    metadata["engine"]["build_stdout"] = stdout_path
    metadata["engine"]["build_stderr"] = stderr_path
    metadata["engine"]["guard_stdout"] = guard_stdout_path
    metadata["engine"]["guard_stderr"] = guard_stderr_path
    metadata["engine"]["producer_script"] = producer_script_path
    metadata["engine"]["toolchain_sha256"] = toolchain_entry["sha256"]
    metadata["engine"]["lakefile_sha256"] = lean_config["lakefile.toml"]["sha256"]
    metadata["engine"]["lake_manifest_sha256"] = lean_config["lake-manifest.json"]["sha256"]
    metadata["engine"]["build_receipt_status"] = receipt["status"]
    metadata["engine"]["guard_wrapper_sha256"] = receipt["guard_wrapper_sha256"]
    metadata["engine"]["guard_minimum_start_free_bytes"] = expected_engine_guard_minimum_start_free_bytes
    metadata["engine"]["producer_script_sha256"] = receipt["producer_script_sha256"]
    metadata["engine"]["guard_stdout_sha256"] = receipt["guard_stdout_sha256"]
    metadata["engine"]["guard_stderr_sha256"] = receipt["guard_stderr_sha256"]
    metadata["engine"]["direct_lane_grant_reference"] = receipt["direct_lane_grant_reference"]
    return files, metadata


def _manifest(files: dict[str, dict[str, Any]], metadata: dict[str, object]) -> bytes:
    return _canonical_json({"files": sorted(files.values(), key=lambda item: item["path"]), "schema": KIT_SCHEMA, **metadata})


def _write_zip_member(
    zip_file: zipfile.ZipFile,
    name: str,
    *,
    source: Path | None = None,
    content: bytes | None = None,
    expected_size: int,
    expected_sha256: str,
) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 0
    info.external_attr = 0x20
    with zip_file.open(info, "w") as destination:
        if content is not None:
            if (
                len(content) != expected_size
                or hashlib.sha256(content).hexdigest().upper() != expected_sha256
            ):
                raise KitError(f"zip_content_pin_mismatch:{name}")
            destination.write(content)
            return
        if source is None:
            raise KitError("zip_source_missing")
        stream, initial, parent_identities = _open_regular_source(source, f"file_unavailable:{name}")
        with stream:
            if initial.st_size != expected_size or initial.st_size > MAX_ARCHIVE_MEMBER_BYTES:
                raise KitError(f"zip_source_size_pin_mismatch:{name}")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > expected_size:
                    raise KitError(f"zip_source_grew:{name}")
                digest.update(chunk)
                destination.write(chunk)
            _require_unchanged_open_source(source, stream, initial, parent_identities)
            if size != expected_size or digest.hexdigest().upper() != expected_sha256:
                raise KitError(f"zip_source_pin_mismatch:{name}")


def _assemble(args: argparse.Namespace) -> int:
    output = Path(args.output).absolute()
    output, output_parent_identities = _directory_chain_snapshot(output)
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise KitError("archive_destination_must_be_new")
    files, metadata = _collect_payload(args)
    manifest_raw = _manifest(files, metadata)
    repo_root = Path(__file__).resolve().parents[1]
    sources = {item["path"]: repo_root / Path(item["path"]) for item in files.values() if item["kind"] == "state_source"}
    engine_root = Path(os.path.abspath(args.engine_root))
    for item in files.values():
        if item["kind"] == "engine_source":
            relative = item["path"].removeprefix("engine/source/")
            sources[item["path"]] = engine_root / Path(relative)
    release_root = Path(os.path.abspath(args.engine_release_dir))
    sources["engine/artifacts/blind_financial_correction.exe"] = release_root / "blind_financial_correction.exe"
    for name in (
        "request.bin", "result.expected.bin", "result.actual.bin", "reuse-request.bin",
        "reuse-result.expected.bin", "reuse-result.actual.bin",
    ):
        sources[f"engine/vectors/{name}"] = release_root / "vectors" / name
    for name in (
        "engine-build-receipt.json", "source-manifest.json", "child.stdout.log", "child.stderr.log",
        "guard.stdout.log", "guard.stderr.log",
    ):
        source = {
            "engine-build-receipt.json": release_root / "provenance" / name,
            "source-manifest.json": release_root / "source-manifest.json",
            "child.stdout.log": release_root / "logs" / name,
            "child.stderr.log": release_root / "logs" / name,
            "guard.stdout.log": release_root / "logs" / name,
            "guard.stderr.log": release_root / "logs" / name,
        }[name]
        archive_name = {
            "engine-build-receipt.json": "engine/provenance/engine-build-receipt.json",
            "source-manifest.json": "engine/provenance/source-manifest.json",
            "child.stdout.log": "engine/provenance/child.stdout.log",
            "child.stderr.log": "engine/provenance/child.stderr.log",
            "guard.stdout.log": "engine/provenance/guard.stdout.log",
            "guard.stderr.log": "engine/provenance/guard.stderr.log",
        }[name]
        sources[archive_name] = source
    sources["engine/producer/build_financial_correction_release.ps1"] = (
        engine_root.parents[1] / "tools" / "build_financial_correction_release.ps1"
    )
    runtime_root = Path(args.python_runtime_root)
    for item in files.values():
        if item["kind"] == "python_runtime":
            relative = item["path"].removeprefix("runtime/python311/")
            sources[item["path"]] = runtime_root / Path(relative)
    if set(sources) != set(files):
        missing = sorted(set(files) - set(sources))
        extra = sorted(set(sources) - set(files))
        raise KitError(f"assembly_source_inventory_mismatch:missing={missing}:extra={extra}")
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        info = os.fstat(descriptor)
        identity = (info.st_dev, info.st_ino)
        _require_directory_chain_unchanged(output_parent_identities)
        with os.fdopen(descriptor, "wb") as archive_stream:
            descriptor = None
            with zipfile.ZipFile(archive_stream, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                for name in sorted(sources):
                    entry = files[name]
                    _write_zip_member(
                        archive,
                        name,
                        source=sources[name],
                        expected_size=entry["size_bytes"],
                        expected_sha256=entry["sha256"],
                    )
                _write_zip_member(
                    archive,
                    "MANIFEST.json",
                    content=manifest_raw,
                    expected_size=len(manifest_raw),
                    expected_sha256=hashlib.sha256(manifest_raw).hexdigest().upper(),
                )
    except Exception as original_error:
        cleanup_problem: str | None = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_problem = f"descriptor_close:{type(error).__name__}:{error}"
        if identity is not None:
            try:
                _require_directory_chain_unchanged(output_parent_identities)
                current = output.lstat()
                if (
                    not _is_reparse_point(current)
                    and stat.S_ISREG(current.st_mode)
                    and current.st_nlink == 1
                    and (current.st_dev, current.st_ino) == identity
                ):
                    output.unlink()
                else:
                    cleanup_problem = "archive_path_identity_not_owned; output preserved"
            except Exception as error:
                cleanup_problem = f"archive_cleanup:{type(error).__name__}:{error}; output preserved"
        if cleanup_problem is not None:
            raise KitError(
                f"archive_assembly_failed:{type(original_error).__name__}:{original_error};{cleanup_problem}"
            ) from original_error
        raise
    _require_directory_chain_unchanged(output_parent_identities)
    try:
        current = output.lstat()
    except OSError as error:
        raise KitError("archive_identity_lost_after_assembly") from error
    if (
        _is_reparse_point(current)
        or not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or (current.st_dev, current.st_ino) != identity
    ):
        raise KitError("archive_identity_changed_after_assembly")
    size, digest = _sha256_path(output)
    _verify_archive(output, digest)
    _require_directory_chain_unchanged(output_parent_identities)
    current = output.lstat()
    if _is_reparse_point(current) or (current.st_dev, current.st_ino) != identity:
        raise KitError("archive_identity_changed_after_verification")
    print(
        f"ASSEMBLED archive={output} sha256={digest} bytes={size} files={len(files)} "
        f"engine_guard_minimum_start_free_bytes={metadata['engine']['guard_minimum_start_free_bytes']}"
    )
    print("NEXT verify with --expected-archive-sha256 copied through an independent channel")
    return 0


def _manifest_files(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if manifest.get("schema") != KIT_SCHEMA:
        raise KitError("kit_manifest_schema")
    entries = manifest.get("files")
    if type(entries) is not list:
        raise KitError("kit_manifest_files")
    result: dict[str, dict[str, Any]] = {}
    previous = ""
    total_size = 0
    if len(entries) > MAX_ARCHIVE_MEMBERS:
        raise KitError("kit_manifest_member_limit")
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"kind", "path", "sha256", "size_bytes"}:
            raise KitError("kit_manifest_entry")
        path = _safe_archive_path(entry["path"])
        digest = entry["sha256"]
        size = entry["size_bytes"]
        kind = entry["kind"]
        if path <= previous or path in result:
            raise KitError("kit_manifest_order_or_duplicate")
        if type(digest) is not str or re.fullmatch(r"[0-9A-F]{64}", digest) is None:
            raise KitError("kit_manifest_digest")
        if (
            type(size) is not int
            or size < 0
            or size > MAX_ARCHIVE_MEMBER_BYTES
            or type(kind) is not str
            or kind not in {
            "state_source", "engine_source", "engine_executable", "engine_vector", "python_runtime",
                "engine_build_receipt", "engine_build_log", "engine_guard_log", "engine_build_producer",
                "engine_source_manifest",
            }
        ):
            raise KitError("kit_manifest_entry_value")
        total_size += size
        if total_size > MAX_ARCHIVE_TOTAL_BYTES:
            raise KitError("kit_manifest_total_size_limit")
        expected_prefix = {
            "engine_source": "engine/source/",
            "engine_executable": "engine/artifacts/",
            "engine_vector": "engine/vectors/",
            "python_runtime": "runtime/python311/",
            "engine_build_receipt": "engine/provenance/",
            "engine_build_log": "engine/provenance/",
            "engine_guard_log": "engine/provenance/",
            "engine_build_producer": "engine/producer/",
            "engine_source_manifest": "engine/provenance/",
        }.get(kind)
        if expected_prefix is not None and not path.startswith(expected_prefix):
            raise KitError("kit_manifest_kind_path")
        if kind == "state_source" and path not in STATE_FILES:
            raise KitError("kit_manifest_unapproved_state_file")
        result[path] = entry
        previous = path
    if not result:
        raise KitError("kit_manifest_empty")
    _validate_archive_name_inventory([*result, "MANIFEST.json"])
    return result


def _validate_runtime_metadata(
    python_metadata: object,
    file_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    entry = file_map.get("runtime/python311/python.exe")
    if (
        type(entry) is not dict
        or entry.get("kind") != "python_runtime"
        or type(entry.get("size_bytes")) is not int
        or entry["size_bytes"] <= 0
        or entry.get("sha256") != EXPECTED_PYTHON_EXE_SHA256
    ):
        raise KitError("kit_python_executable_member_pin")
    if python_metadata != {
        "executable_path": "runtime/python311/python.exe",
        "executable_sha256": EXPECTED_PYTHON_EXE_SHA256,
        "executable_size_bytes": entry["size_bytes"],
        "third_party_packages": [],
        "version": EXPECTED_PYTHON_VERSION,
    }:
        raise KitError("kit_python_pin")
    return entry


def _validate_manifest_metadata(manifest: dict[str, Any], file_map: dict[str, dict[str, Any]], read_bytes: Callable[[str], bytes]) -> None:
    if set(manifest) != {
        "files", "schema", "blocked_components", "claims", "engine", "python", "python_dependency_lock", "scenario", "scope",
    }:
        raise KitError("kit_manifest_fields")
    required_paths = set(STATE_FILES) | {
        "engine/artifacts/blind_financial_correction.exe",
        "engine/source/lean-toolchain",
        "engine/source/lakefile.toml",
        "engine/source/lake-manifest.json",
        "engine/source/BlindLedger/Financial/CorrectionTransition/Transition.lean",
        "engine/source/BlindLedger/Financial/CorrectionTransition/Runtime.lean",
        "engine/source/BlindLedger/Financial/CorrectionTransitionCli.lean",
        "engine/vectors/request.bin",
        "engine/vectors/result.expected.bin",
        "engine/vectors/result.actual.bin",
        "engine/vectors/reuse-request.bin",
        "engine/vectors/reuse-result.expected.bin",
        "engine/vectors/reuse-result.actual.bin",
        "engine/provenance/engine-build-receipt.json",
        "engine/provenance/source-manifest.json",
        "engine/provenance/child.stdout.log",
        "engine/provenance/child.stderr.log",
        "engine/provenance/guard.stdout.log",
        "engine/provenance/guard.stderr.log",
        "engine/producer/build_financial_correction_release.ps1",
        "runtime/python311/python.exe",
    }
    if not required_paths.issubset(file_map):
        raise KitError("kit_manifest_required_files_missing")
    if manifest.get("scope") != "synthetic, local, non-PHI, nonpayment, dispatch-disabled, nonactivating":
        raise KitError("kit_scope_pin")
    if manifest.get("claims") != KIT_CLAIMS:
        raise KitError("kit_claims_pin")
    if manifest.get("scenario") != SERVICE_SCENARIO:
        raise KitError("kit_scenario_pin")
    if manifest.get("blocked_components") != {
        "queue.lifecycle_source_bound_runtime": {
            "reason": "MISSING/BLOCKED: no current source-bound Queue runtime handoff; Queue omitted",
            "status": "MISSING/BLOCKED",
        }
    }:
        raise KitError("kit_queue_blocker_pin")
    _validate_runtime_metadata(manifest.get("python"), file_map)
    if manifest.get("python_dependency_lock") != {"schema": "RR/PYTHON-DEPENDENCIES/v1", "third_party_packages": []}:
        raise KitError("kit_python_dependency_lock")

    engine_source_entries = [item for item in file_map.values() if item["kind"] == "engine_source"]
    state_source_paths = {item["path"] for item in file_map.values() if item["kind"] == "state_source"}
    executable_paths = {item["path"] for item in file_map.values() if item["kind"] == "engine_executable"}
    vector_paths = {item["path"] for item in file_map.values() if item["kind"] == "engine_vector"}
    receipt_paths = {item["path"] for item in file_map.values() if item["kind"] == "engine_build_receipt"}
    child_log_paths = {item["path"] for item in file_map.values() if item["kind"] == "engine_build_log"}
    guard_log_paths = {item["path"] for item in file_map.values() if item["kind"] == "engine_guard_log"}
    producer_paths = {item["path"] for item in file_map.values() if item["kind"] == "engine_build_producer"}
    source_manifest_paths = {item["path"] for item in file_map.values() if item["kind"] == "engine_source_manifest"}
    if state_source_paths != set(STATE_FILES):
        raise KitError("kit_state_source_inventory")
    if executable_paths != {"engine/artifacts/blind_financial_correction.exe"}:
        raise KitError("kit_engine_executable_inventory")
    if vector_paths != {
        "engine/vectors/request.bin", "engine/vectors/result.expected.bin", "engine/vectors/result.actual.bin",
        "engine/vectors/reuse-request.bin", "engine/vectors/reuse-result.expected.bin",
        "engine/vectors/reuse-result.actual.bin",
    }:
        raise KitError("kit_engine_vector_inventory")
    if receipt_paths != {"engine/provenance/engine-build-receipt.json"} or child_log_paths != {
        "engine/provenance/child.stdout.log", "engine/provenance/child.stderr.log",
    } or guard_log_paths != {
        "engine/provenance/guard.stdout.log", "engine/provenance/guard.stderr.log",
    } or producer_paths != {
        "engine/producer/build_financial_correction_release.ps1",
    } or source_manifest_paths != {
        "engine/provenance/source-manifest.json",
    }:
        raise KitError("kit_engine_provenance_inventory")
    if any(
        not item["path"].startswith("engine/source/")
        or not (
            item["path"].endswith(".lean")
            or item["path"] in {
                "engine/source/lean-toolchain", "engine/source/lakefile.toml", "engine/source/lake-manifest.json",
            }
        )
        for item in engine_source_entries
    ):
        raise KitError("kit_engine_source_inventory")
    if any(
        item["kind"] == "python_runtime"
        and (
            not item["path"].startswith("runtime/python311/")
            or any(part.lower() in {"site-packages", "dist-packages"} for part in PurePosixPath(item["path"]).parts)
        )
        for item in file_map.values()
    ):
        raise KitError("kit_python_runtime_inventory")
    for relative in STATE_FILES:
        if relative not in file_map or file_map[relative]["kind"] != "state_source":
            raise KitError(f"kit_state_source_kind:{relative}")
    source_manifest_raw, source_manifest_sha = _engine_source_manifest(engine_source_entries)
    if read_bytes("engine/provenance/source-manifest.json") != source_manifest_raw:
        raise KitError("kit_engine_source_manifest_bytes")
    if type(manifest.get("engine")) is not dict or manifest["engine"].get("source_manifest_sha256") != source_manifest_sha:
        raise KitError("kit_engine_source_manifest_pin")
    engine_source = read_bytes("app/right_rail_financial_engine.py")
    pins = _validate_engine_artifacts(file_map, engine_source)
    engine_meta = manifest["engine"]
    if set(engine_meta) != {
        "build_receipt_sha256", "build_receipt_status", "build_receipt", "build_stdout", "build_stderr",
        "guard_stdout", "guard_stderr", "producer_script", "producer_script_sha256", "source_manifest_path",
        "executable_path", "executable_sha256", "executable_size_bytes", "request_vector_sha256",
        "result_vector_sha256", "reuse_request_vector_sha256", "reuse_result_vector_sha256",
        "source_manifest_sha256", "target", "toolchain", "toolchain_sha256", "lakefile_sha256",
        "lake_manifest_sha256", "guard_wrapper_sha256", "guard_minimum_start_free_bytes",
        "guard_stdout_sha256", "guard_stderr_sha256", "direct_lane_grant_reference",
    }:
        raise KitError("kit_engine_metadata_fields")
    for key, value in {
        "target": ENGINE_TARGET,
        "executable_path": "engine/artifacts/blind_financial_correction.exe",
        "executable_sha256": pins["artifact_sha256"],
        "executable_size_bytes": pins["artifact_size_bytes"],
        "request_vector_sha256": pins["request_vector_sha256"],
        "result_vector_sha256": pins["result_vector_sha256"],
        "reuse_request_vector_sha256": file_map["engine/vectors/reuse-request.bin"]["sha256"],
        "reuse_result_vector_sha256": file_map["engine/vectors/reuse-result.expected.bin"]["sha256"],
        "source_manifest_sha256": source_manifest_sha,
    }.items():
        if engine_meta.get(key) != value:
            raise KitError(f"kit_engine_pin:{key}")
    if (
        file_map["engine/vectors/reuse-result.actual.bin"]["sha256"]
        != file_map["engine/vectors/reuse-result.expected.bin"]["sha256"]
        or file_map["engine/vectors/reuse-result.actual.bin"]["size_bytes"]
        != file_map["engine/vectors/reuse-result.expected.bin"]["size_bytes"]
    ):
        raise KitError("kit_engine_reuse_vectors_not_byte_equal")
    toolchain_raw = read_bytes("engine/source/lean-toolchain")
    try:
        toolchain = toolchain_raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise KitError("kit_lean_toolchain_invalid_utf8") from error
    if not toolchain or engine_meta.get("toolchain") != toolchain:
        raise KitError("kit_lean_toolchain_pin")
    for field, path in (
        ("toolchain_sha256", "engine/source/lean-toolchain"),
        ("lakefile_sha256", "engine/source/lakefile.toml"),
        ("lake_manifest_sha256", "engine/source/lake-manifest.json"),
    ):
        if engine_meta.get(field) != file_map[path]["sha256"]:
            raise KitError(f"kit_lean_lock_pin:{field}")
    try:
        lake_manifest = _strict_json(read_bytes("engine/source/lake-manifest.json"), "lake_manifest")
        lakefile = tomllib.loads(read_bytes("engine/source/lakefile.toml").decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise KitError("kit_lean_dependency_lock_invalid") from error
    if lake_manifest.get("packages") != [] or "require" in lakefile:
        raise KitError("kit_lean_external_dependencies_not_closed")
    lake_targets = lakefile.get("lean_exe", [])
    if type(lake_targets) is not list or not any(
        type(item) is dict and item.get("name") == ENGINE_TARGET for item in lake_targets
    ):
        raise KitError("kit_lean_correction_target_missing")
    receipt_path = engine_meta.get("build_receipt")
    stdout_path = engine_meta.get("build_stdout")
    stderr_path = engine_meta.get("build_stderr")
    guard_stdout_path = engine_meta.get("guard_stdout")
    guard_stderr_path = engine_meta.get("guard_stderr")
    producer_script_path = engine_meta.get("producer_script")
    source_manifest_path = engine_meta.get("source_manifest_path")
    if (
        receipt_path,
        stdout_path,
        stderr_path,
        guard_stdout_path,
        guard_stderr_path,
        producer_script_path,
        source_manifest_path,
    ) != (
        "engine/provenance/engine-build-receipt.json",
        "engine/provenance/child.stdout.log",
        "engine/provenance/child.stderr.log",
        "engine/provenance/guard.stdout.log",
        "engine/provenance/guard.stderr.log",
        "engine/producer/build_financial_correction_release.ps1",
        "engine/provenance/source-manifest.json",
    ):
        raise KitError("kit_engine_provenance_paths")
    expected_engine_guard_minimum_start_free_bytes = engine_meta["guard_minimum_start_free_bytes"]
    if (
        type(expected_engine_guard_minimum_start_free_bytes) is not int
        or expected_engine_guard_minimum_start_free_bytes < ENGINE_MINIMUM_START_FREE_BYTES
    ):
        raise KitError("kit_engine_guard_minimum_start_free_bytes")
    receipt = _validate_receipt(
        read_bytes(receipt_path),
        read_bytes(stdout_path),
        read_bytes(stderr_path),
        read_bytes(guard_stdout_path),
        read_bytes(guard_stderr_path),
        read_bytes(producer_script_path),
        source_manifest_sha256=source_manifest_sha,
        source_pins=pins,
        reuse_request_sha256=engine_meta["reuse_request_vector_sha256"],
        reuse_result_sha256=engine_meta["reuse_result_vector_sha256"],
        toolchain=toolchain,
        toolchain_sha256=file_map["engine/source/lean-toolchain"]["sha256"],
        lakefile_sha256=file_map["engine/source/lakefile.toml"]["sha256"],
        lake_manifest_sha256=file_map["engine/source/lake-manifest.json"]["sha256"],
        expected_engine_guard_minimum_start_free_bytes=expected_engine_guard_minimum_start_free_bytes,
        expected_direct_lane_grant_reference=engine_meta["direct_lane_grant_reference"],
    )
    for key, path in (
        ("build_receipt_sha256", receipt_path),
        ("producer_script_sha256", producer_script_path),
        ("guard_stdout_sha256", guard_stdout_path),
        ("guard_stderr_sha256", guard_stderr_path),
    ):
        if engine_meta.get(key) != file_map[path]["sha256"]:
            raise KitError(f"kit_engine_provenance_hash:{key}")
    if (
        engine_meta.get("build_receipt_status") != receipt["status"]
        or engine_meta.get("guard_wrapper_sha256") != GUARD_SHA256
    ):
        raise KitError("kit_engine_receipt_status")


def _verify_archive_open_stream(
    archive_path: Path,
    stream: BinaryIO,
    initial: os.stat_result,
    parent_identities: dict[Path, tuple[int, int, int, int]],
    expected_digest: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if re.fullmatch(r"[0-9A-Fa-f]{64}", expected_digest) is None:
        raise KitError("expected_archive_sha256_invalid")
    if initial.st_size > MAX_ARCHIVE_BYTES:
        raise KitError("archive_size_limit")
    stream.seek(0)
    size, digest = _sha256_stream(stream)
    _require_unchanged_open_source(archive_path, stream, initial, parent_identities)
    if size != initial.st_size or digest != expected_digest.upper():
        raise KitError(f"archive_sha256_mismatch:actual={digest}")
    stream.seek(0)
    try:
        archive = zipfile.ZipFile(stream, "r")
    except (OSError, zipfile.BadZipFile) as error:
        raise KitError("archive_invalid") from error
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS + 1 or any(info.is_dir() for info in infos):
            raise KitError("archive_duplicate_or_directory_entry")
        names = [info.filename for info in infos]
        _validate_archive_name_inventory(names)
        if len(names) != len(set(names)):
            raise KitError("archive_duplicate_or_directory_entry")
        total_member_bytes = 0
        for info in infos:
            _safe_archive_path(info.filename)
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            total_member_bytes += info.file_size
            if (
                (file_type not in (0, stat.S_IFREG))
                or info.flag_bits & 0x1
                or info.file_size > MAX_ARCHIVE_MEMBER_BYTES
                or total_member_bytes > MAX_ARCHIVE_TOTAL_BYTES + 8 * 1024 * 1024
                or info.compress_type != zipfile.ZIP_STORED
                or info.compress_size != info.file_size
            ):
                raise KitError("archive_member_format_or_size_invalid")
        if "MANIFEST.json" not in names:
            raise KitError("archive_manifest_missing")
        if archive.getinfo("MANIFEST.json").file_size > 8 * 1024 * 1024:
            raise KitError("archive_manifest_too_large")
        manifest_raw = archive.read("MANIFEST.json")
        manifest = _strict_json(manifest_raw, "kit_manifest")
        if manifest_raw != _canonical_json(manifest):
            raise KitError("kit_manifest_not_canonical")
        file_map = _manifest_files(manifest)
        expected_names = set(file_map) | {"MANIFEST.json"}
        if set(names) != expected_names:
            missing = sorted(expected_names - set(names))
            extra = sorted(set(names) - expected_names)
            raise KitError(f"archive_membership_mismatch:missing={missing}:extra={extra}")
        for name, entry in file_map.items():
            if archive.getinfo(name).file_size != entry["size_bytes"]:
                raise KitError(f"archive_file_size_pin_mismatch:{name}")
            with archive.open(name, "r") as member:
                actual_size, actual_digest = _sha256_stream(member)
            if actual_size != entry["size_bytes"] or actual_digest != entry["sha256"]:
                raise KitError(f"archive_file_pin_mismatch:{name}")
        _validate_manifest_metadata(manifest, file_map, archive.read)
    _require_unchanged_open_source(archive_path, stream, initial, parent_identities)
    return manifest, file_map


def _verify_archive(archive_path: Path, expected_digest: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    stream, initial, parent_identities = _open_regular_source(archive_path, "archive_unavailable")
    with stream:
        return _verify_archive_open_stream(
            archive_path,
            stream,
            initial,
            parent_identities,
            expected_digest,
        )


def _verify_extracted_tree(root: Path, manifest: dict[str, Any], file_map: dict[str, dict[str, Any]]) -> None:
    if not root.is_absolute():
        raise KitError("extraction_root_invalid")
    root = Path(os.path.abspath(root))
    _, parent_identities = _directory_chain_snapshot(root)
    try:
        initial_root = root.lstat()
    except OSError as error:
        raise KitError("extraction_root_invalid") from error
    if _is_reparse_point(initial_root) or not stat.S_ISDIR(initial_root.st_mode):
        raise KitError("extraction_root_invalid")
    root_identity = _directory_identity(initial_root)
    actual_directories: set[str] = set()
    actual_paths = _walk_regular_tree(root, "extraction", directory_inventory=actual_directories)
    actual_files = {path.relative_to(root).as_posix() for path in actual_paths}
    for relative in actual_files | actual_directories:
        _safe_archive_path(relative)
    _validate_archive_name_inventory([*actual_files])
    expected = set(file_map) | {"MANIFEST.json"}
    expected_directories: set[str] = set()
    for relative in expected:
        parts = PurePosixPath(relative).parts
        expected_directories.update(PurePosixPath(*parts[:index]).as_posix() for index in range(1, len(parts)))
    if actual_files != expected or actual_directories != expected_directories:
        raise KitError(
            "extraction_membership_mismatch:"
            f"missing_files={sorted(expected - actual_files)}:extra_files={sorted(actual_files - expected)}:"
            f"missing_directories={sorted(expected_directories - actual_directories)}:"
            f"extra_directories={sorted(actual_directories - expected_directories)}"
        )
    for relative, entry in file_map.items():
        size, digest = _sha256_path(root / Path(relative))
        if size != entry["size_bytes"] or digest != entry["sha256"]:
            raise KitError(f"extraction_file_pin_mismatch:{relative}")
    manifest_path = root / "MANIFEST.json"
    manifest_raw = _read_external_file(manifest_path, "extracted_manifest")
    if len(manifest_raw) > 8 * 1024 * 1024 or manifest_raw != _canonical_json(manifest):
        raise KitError("extracted_manifest_mismatch")
    current_root = root.lstat()
    if _directory_identity(current_root) != root_identity or _is_reparse_point(current_root):
        raise KitError("extraction_root_identity_changed")
    _require_directory_chain_unchanged(parent_identities)


def _verify_command(args: argparse.Namespace) -> int:
    manifest, files = _verify_archive(Path(args.archive).absolute(), args.expected_archive_sha256)
    print(
        "ARCHIVE_VERIFIED "
        f"sha256={args.expected_archive_sha256.upper()} files={len(files)} "
        f"engine_source_sha256={manifest['engine']['source_manifest_sha256']} "
        f"engine_executable_sha256={manifest['engine']['executable_sha256']} "
        f"engine_guard_minimum_start_free_bytes={manifest['engine']['guard_minimum_start_free_bytes']}"
    )
    return 0


def _extract_command(args: argparse.Namespace) -> int:
    archive_path = Path(args.archive).absolute()
    archive_stream, archive_info, archive_parents = _open_regular_source(archive_path, "archive_unavailable")
    with archive_stream:
        manifest, file_map = _verify_archive_open_stream(
            archive_path, archive_stream, archive_info, archive_parents, args.expected_archive_sha256
        )
        destination = Path(os.path.abspath(args.destination))
        _, destination_parents = _directory_chain_snapshot(destination)
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        else:
            raise KitError("extraction_destination_must_be_new")
        _require_directory_chain_unchanged(destination_parents)
        try:
            destination.mkdir()
        except FileExistsError as error:
            raise KitError("extraction_destination_must_be_new") from error
        try:
            root_info = destination.lstat()
            if _is_reparse_point(root_info) or not stat.S_ISDIR(root_info.st_mode):
                raise KitError("extraction_root_creation_identity_invalid")
            directory_identities = {destination: _directory_identity(root_info)}

            def verify_extract_directories() -> None:
                _require_directory_chain_unchanged(destination_parents)
                for directory, identity in directory_identities.items():
                    try:
                        current = directory.lstat()
                    except OSError as error:
                        raise KitError(f"extraction_directory_identity_lost:{directory}") from error
                    if (
                        _is_reparse_point(current)
                        or not stat.S_ISDIR(current.st_mode)
                        or _directory_identity(current) != identity
                    ):
                        raise KitError(f"extraction_directory_identity_changed:{directory}")

            def ensure_extract_parent(relative: str) -> Path:
                verify_extract_directories()
                current = destination
                for part in PurePosixPath(relative).parts[:-1]:
                    candidate = current / part
                    try:
                        candidate.mkdir()
                    except FileExistsError:
                        pass
                    try:
                        info = candidate.lstat()
                    except OSError as error:
                        raise KitError(f"extraction_directory_unavailable:{relative}") from error
                    if _is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
                        raise KitError(f"extraction_directory_not_regular:{relative}")
                    identity = _directory_identity(info)
                    previous = directory_identities.get(candidate)
                    if previous is not None and previous != identity:
                        raise KitError(f"extraction_directory_identity_changed:{candidate}")
                    directory_identities[candidate] = identity
                    verify_extract_directories()
                    current = candidate
                return current

            archive_stream.seek(0)
            with zipfile.ZipFile(archive_stream, "r") as archive:
                for name in [*sorted(file_map), "MANIFEST.json"]:
                    parent = ensure_extract_parent(name)
                    target = parent / PurePosixPath(name).name
                    entry = file_map.get(name)
                    if entry is None:
                        expected_content = _canonical_json(manifest)
                        expected_size = len(expected_content)
                        expected_sha256 = hashlib.sha256(expected_content).hexdigest().upper()
                    else:
                        expected_content = None
                        expected_size = entry["size_bytes"]
                        expected_sha256 = entry["sha256"]
                    verify_extract_directories()
                    digest = hashlib.sha256()
                    total = 0
                    with archive.open(name, "r") as source, target.open("xb") as sink:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > expected_size:
                                raise KitError(f"extraction_member_grew:{name}")
                            digest.update(chunk)
                            sink.write(chunk)
                    if (
                        total != expected_size
                        or digest.hexdigest().upper() != expected_sha256
                        or (expected_content is not None and total != len(expected_content))
                    ):
                        raise KitError(f"extraction_member_pin_mismatch:{name}")
                    size, written_digest = _sha256_path(target)
                    if size != expected_size or written_digest != expected_sha256:
                        raise KitError(f"extraction_written_file_pin_mismatch:{name}")
                    verify_extract_directories()
            verified_again = _verify_archive_open_stream(
                archive_path, archive_stream, archive_info, archive_parents, args.expected_archive_sha256
            )
            if verified_again != (manifest, file_map):
                raise KitError("archive_identity_changed_after_extraction")
            _verify_extracted_tree(destination, manifest, file_map)
        except Exception as error:
            raise KitError(
                f"extraction_incomplete_preserved:{type(error).__name__}:{error}:{destination}"
            ) from error
        print(f"EXTRACTED path={destination} files={len(file_map)} archive_sha256={args.expected_archive_sha256.upper()}")
        return 0


def _package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _post_extract_check(args: argparse.Namespace) -> tuple[Path, dict[str, Any], dict[str, dict[str, Any]]]:
    archive_path = Path(args.archive).absolute()
    manifest, file_map = _verify_archive(archive_path, args.expected_archive_sha256)
    root = Path(args.extraction_root).absolute() if args.extraction_root else _package_root()
    _verify_extracted_tree(root, manifest, file_map)
    return root, manifest, file_map


def _existing_directory_snapshot(path: Path, label: str) -> tuple[Path, tuple[int, int, int, int], dict[Path, tuple[int, int, int, int]]]:
    absolute, parent_identities = _directory_chain_snapshot(path)
    try:
        info = absolute.lstat()
    except OSError as error:
        raise KitError(f"{label}_workspace_unavailable") from error
    if _is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
        raise KitError(f"{label}_workspace_must_be_existing_directory")
    return absolute, _directory_identity(info), parent_identities


def _require_existing_directory_unchanged(
    path: Path,
    identity: tuple[int, int, int, int],
    parent_identities: dict[Path, tuple[int, int, int, int]],
    label: str,
) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise KitError(f"{label}_workspace_identity_lost") from error
    if (
        _is_reparse_point(info)
        or not stat.S_ISDIR(info.st_mode)
        or _directory_identity(info) != identity
    ):
        raise KitError(f"{label}_workspace_identity_changed")
    _require_directory_chain_unchanged(parent_identities)


def _owner_database_snapshot(owner_work: Path) -> tuple[bool, tuple[int, int, int] | None]:
    database = owner_work / "financial-owner.sqlite"
    try:
        info = database.lstat()
    except FileNotFoundError:
        try:
            if next(owner_work.iterdir(), None) is not None:
                raise KitError("owner_workspace_without_database_must_be_empty")
        except OSError as error:
            raise KitError("owner_workspace_unreadable") from error
        return False, None
    except OSError as error:
        raise KitError("owner_database_identity_unavailable") from error
    if _is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise KitError("owner_database_must_be_regular_unlinked_file")
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{database}{suffix}")
        try:
            sidecar_info = sidecar.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise KitError("owner_database_sidecar_identity_unavailable") from error
        if _is_reparse_point(sidecar_info) or not stat.S_ISREG(sidecar_info.st_mode) or sidecar_info.st_nlink != 1:
            raise KitError("owner_database_sidecar_must_be_regular_unlinked_file")
    return True, (info.st_dev, info.st_ino, info.st_mode)


def _path_is_within(path: Path, root: Path) -> bool:
    path_value = os.path.normcase(str(path))
    root_value = os.path.normcase(str(root))
    try:
        return os.path.commonpath((path_value, root_value)) == root_value
    except ValueError:
        return False


def _run_scenario(args: argparse.Namespace) -> int:
    root, manifest, file_map = _post_extract_check(args)
    runtime = root / Path(manifest["python"]["executable_path"])
    runner = root / "tools/service_kit/run_scenario.py"
    with tempfile.TemporaryDirectory(prefix="rightrail-financial-service-kit-") as temporary:
        work = Path(temporary)
        environment = _runtime_environment(work)
        environment["RR_FINANCIAL_CORRECTION_ENGINE_PATH"] = str(root / "engine/artifacts/blind_financial_correction.exe")
        environment["RR_FINANCIAL_CORRECTION_VECTOR_DIR"] = str(root / "engine/vectors")
        environment["RR_FINANCIAL_SERVICE_KIT_TEST_WORKSPACE"] = str(work / "owner-workspace")
        (work / "owner-workspace").mkdir()
        command = [str(runtime), "-I", "-B", "-S", str(runner)]
        print(f"RUNNING scenario={SERVICE_SCENARIO}", flush=True)
        try:
            result = subprocess.run(command, cwd=root, env=environment, check=False, shell=False)
        except OSError as error:
            raise KitError("service_scenario_launch_failed") from error
        print(f"SERVICE_SCENARIO_EXIT={result.returncode}", flush=True)
        _verify_extracted_tree(root, manifest, file_map)
        return result.returncode


def _serve(args: argparse.Namespace) -> int:
    root, manifest, file_map = _post_extract_check(args)
    runtime = root / Path(manifest["python"]["executable_path"])
    owner_work, owner_identity, owner_parents = _existing_directory_snapshot(Path(args.owner_workspace), "owner")
    engine_work, engine_identity, engine_parents = _existing_directory_snapshot(Path(args.engine_workspace), "engine")
    owner_exists, original_database_identity = _owner_database_snapshot(owner_work)
    try:
        if next(engine_work.iterdir(), None) is not None:
            raise KitError("engine_workspace_must_be_empty")
    except OSError as error:
        raise KitError("engine_workspace_unreadable") from error
    resolved_root = root.resolve(strict=True)
    resolved_owner = owner_work.resolve(strict=True)
    resolved_engine = engine_work.resolve(strict=True)
    if (
        resolved_owner == resolved_engine
        or _path_is_within(resolved_owner, resolved_engine)
        or _path_is_within(resolved_engine, resolved_owner)
    ):
        raise KitError("owner_engine_workspaces_must_be_disjoint")
    if _path_is_within(resolved_owner, resolved_root) or _path_is_within(resolved_engine, resolved_root):
        raise KitError("service_workspace_inside_extracted_kit")
    command = [
        str(runtime), "-I", "-B", "-S", str(root / "tools/service_kit/run_server.py"),
        "--port", str(args.port),
        "--workspace", str(owner_work),
        "--correction-transition-executable", str(root / "engine/artifacts/blind_financial_correction.exe"),
        "--correction-transition-workspace", str(engine_work),
    ]
    if owner_exists:
        command.append("--resume-existing-workspace")
    print(
        "STARTING synthetic loopback TEST Owner; application dispatch and egress flags are false; "
        "host-level outbound isolation is external",
        flush=True,
    )
    _require_existing_directory_unchanged(owner_work, owner_identity, owner_parents, "owner")
    _require_existing_directory_unchanged(engine_work, engine_identity, engine_parents, "engine")
    current_owner_exists, current_database_identity = _owner_database_snapshot(owner_work)
    if current_owner_exists != owner_exists or current_database_identity != original_database_identity:
        raise KitError("owner_database_identity_changed_before_start")
    try:
        if next(engine_work.iterdir(), None) is not None:
            raise KitError("engine_workspace_must_be_empty")
    except OSError as error:
        raise KitError("engine_workspace_unreadable") from error
    with tempfile.TemporaryDirectory(prefix="rightrail-financial-service-temp-") as temporary:
        temporary_root = Path(temporary)
        try:
            result = subprocess.run(
                command,
                cwd=root,
                env=_runtime_environment(temporary_root),
                check=False,
                shell=False,
            )
        except OSError as error:
            raise KitError("service_server_launch_failed") from error
    print(f"SERVICE_SERVER_EXIT={result.returncode}", flush=True)
    _require_existing_directory_unchanged(owner_work, owner_identity, owner_parents, "owner")
    _require_existing_directory_unchanged(engine_work, engine_identity, engine_parents, "engine")
    current_owner_exists, current_database_identity = _owner_database_snapshot(owner_work)
    if (
        (owner_exists and not current_owner_exists)
        or (owner_exists and current_database_identity != original_database_identity)
        or (result.returncode == 0 and not current_owner_exists)
    ):
        raise KitError("owner_database_identity_changed_after_service")
    try:
        if next(engine_work.iterdir(), None) is not None:
            raise KitError("engine_workspace_not_empty_after_service")
    except OSError as error:
        raise KitError("engine_workspace_unreadable_after_service") from error
    _verify_extracted_tree(root, manifest, file_map)
    return result.returncode


def _runtime_environment(temporary_root: Path) -> dict[str, str]:
    environment: dict[str, str] = {}
    for name in ("PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    environment["TEMP"] = str(temporary_root)
    environment["TMP"] = str(temporary_root)
    return environment


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    assemble = commands.add_parser("assemble", help="create a deterministic, create-only offline ZIP archive")
    assemble.add_argument("--output", required=True, type=Path)
    assemble.add_argument("--engine-root", required=True, type=Path, help="Engine semantic_kernel/lean source root")
    assemble.add_argument("--engine-release-dir", required=True, type=Path, help="Engine's exact create-only release evidence directory")
    assemble.add_argument("--python-runtime-root", required=True, type=Path, help="complete pinned CPython 3.11.15 installation")
    assemble.add_argument(
        "--expected-engine-guard-minimum-start-free-bytes",
        required=True,
        type=int,
        help="exact Engine build guard value supplied in its authorized handoff",
    )
    assemble.add_argument(
        "--direct-lane-grant-reference",
        required=True,
        help="exact real Driver lane grant reference from the authorized Engine handoff",
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

    run = commands.add_parser("run", help="verify an extracted kit and run the one focused synthetic service scenario")
    run.add_argument("--archive", required=True, type=Path)
    run.add_argument("--expected-archive-sha256", required=True)
    run.add_argument("--extraction-root", type=Path)
    run.set_defaults(function=_run_scenario)

    serve = commands.add_parser("serve", help="verify an extracted kit and start the loopback synthetic staff workspace")
    serve.add_argument("--archive", required=True, type=Path)
    serve.add_argument("--expected-archive-sha256", required=True)
    serve.add_argument("--extraction-root", type=Path)
    serve.add_argument("--owner-workspace", required=True, type=Path)
    serve.add_argument("--engine-workspace", required=True, type=Path)
    serve.add_argument("--port", type=int, default=8765)
    serve.set_defaults(function=_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.function(args))
    except KitError as error:
        print(f"SERVICE_KIT_BLOCKED code={error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"SERVICE_KIT_BLOCKED code=filesystem:{type(error).__name__}:{error}", file=sys.stderr)
        return 2
    except (KeyError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        print(f"SERVICE_KIT_BLOCKED code=invalid_input:{type(error).__name__}:{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
