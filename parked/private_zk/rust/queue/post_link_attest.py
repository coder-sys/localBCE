#!/usr/bin/env python3
"""Build Lifecycle with the pinned toolchain and attest its post-link inputs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
RUST_ROOT = Path(__file__).resolve().parent
LEAN_ROOT = REPO_ROOT / "lean" / "queue"
LEAN_TOOLCHAIN = Path(r"C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1")
PINNED_CARGO = Path(r"C:\Users\neers\.rustup\toolchains\1.96.0-x86_64-pc-windows-msvc\bin\cargo.exe")
PINNED_CARGO_SHA256 = "122f18d28a63fa358f3db266abee1ff1d8aabf0ab7f2dd9ac38a38da99977ae5"
PINNED_RUSTC = Path(r"C:\Users\neers\.rustup\toolchains\1.96.0-x86_64-pc-windows-msvc\bin\rustc.exe")
PINNED_RUSTC_SHA256 = "acb138286bbe20c6cf3ec39a7e0a68c3fab0cd949baa2912cf466514d0d531ab"
PINNED_GNU_MANIFEST = PINNED_RUSTC.parent.parent / "lib" / "rustlib" / "manifest-rust-std-x86_64-pc-windows-gnu"
PINNED_GNU_MANIFEST_SHA256 = "3e18bbb8b5c6ad86b8faceefd9ac4fb934e857dd546b82216a084546f0ec1cbe"
PINNED_PROJECT_CARGO_CONFIG_SHA256 = "385d15c7142267a1fdee1cda6ab13d41966b2e9557084828922f4a4ee3644e81"
TARGET = "x86_64-pc-windows-gnu"
LIFECYCLE_MANIFEST_SYMBOL = "blind_ledger_lifecycle_source_manifest"
SOURCE_MANIFEST_NAME = "lifecycle_lean_source_manifest.v2.txt"
BUILD_RECEIPT_NAME = "lifecycle_build_receipt.v2.txt"
LINK_ARGUMENTS_NAME = "lifecycle_link_arguments.v3.txt"
REPRODUCER_NAME = "lifecycle_link_repro.v1.tar"
RESPONSE_NAME = "response.txt"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_ARGUMENTS = 262_144
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\Z")
LINK_INPUT_SUFFIXES = {".a", ".bc", ".def", ".dll", ".exp", ".lib", ".o", ".obj", ".res", ".rlib"}

LEAN_SOURCE_PATHS = (
    "Admission/Checker.lean",
    "Admission/Library.lean",
    "Admission/Lifecycle.lean",
    "Admission/LifecycleKernel.lean",
    "Admission/Main.lean",
    "Admission/Model.lean",
    "BlindLedger/Sha3.lean",
    "lake-manifest.json",
    "lakefile.toml",
    "lean-toolchain",
)
RUST_SOURCE_PATHS = (
    ".cargo/config.toml",
    "Cargo.lock",
    "Cargo.toml",
    "build.rs",
    "native_boundary.c",
    "post_link_attest.py",
    "src/bin/lifecycle.rs",
)
LEAN_TOOL_PATHS = (
    "bin/clang.exe",
    "bin/ld.lld.exe",
    "bin/lake.exe",
    "bin/lean.exe",
    "bin/llvm-ar.exe",
)
SUPPORT_ARCHIVES_FIRST = (
    "libgmp.a", "libuv.a", "libpsapi.a", "libuser32.a", "libadvapi32.a", "libiphlpapi.a",
    "libuserenv.a", "libws2_32.a", "libdbghelp.a", "libole32.a", "libshell32.a", "libssl.a",
    "libcrypto.a", "libunwind.a", "libcrypt32.a", "libgdi32.a",
)
LEAN_ARCHIVES = ("libleancpp.a", "libLean.a", "libStd.a", "libInit.a", "libleanrt.a")
SUPPORT_ARCHIVES_MIDDLE = ("libc++.a", "libc++abi.a")
SUPPORT_ARCHIVES_LAST = (
    "libgmp.a", "libuv.a", "libpsapi.a", "libuser32.a", "libadvapi32.a", "libiphlpapi.a",
    "libuserenv.a", "libws2_32.a", "libdbghelp.a", "libole32.a", "libshell32.a", "libssl.a",
    "libcrypto.a", "libcrypt32.a", "libgdi32.a", "libicu.a", "libm.a", "libbcrypt.a",
    "libpthread.a",
)


class AttestationError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceRecord:
    path: str
    count: int
    length: int
    sha256: str


@dataclass(frozen=True)
class FileIdentity:
    path: Path
    identity: str
    category: str
    length: int
    sha256: str


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    is_directory: bool
    length: int
    sha256: str
    response_bytes: bytes | None = None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _read_regular(path: Path, *, limit: int | None = None) -> bytes:
    try:
        info = path.lstat()
    except OSError as error:
        raise AttestationError(f"cannot stat {path}: {error}") from error
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse_point(path):
        raise AttestationError(f"not a regular non-reparse file: {path}")
    if limit is not None and info.st_size > limit:
        raise AttestationError(f"file exceeds the {limit}-byte limit: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise AttestationError(f"cannot read {path}: {error}") from error


def _file_digest(path: Path) -> tuple[int, str]:
    try:
        info = path.lstat()
    except OSError as error:
        raise AttestationError(f"cannot stat {path}: {error}") from error
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse_point(path):
        raise AttestationError(f"not a regular non-reparse file: {path}")
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                hasher.update(chunk)
    except OSError as error:
        raise AttestationError(f"cannot hash {path}: {error}") from error
    return info.st_size, hasher.hexdigest()


def _file_identity(path: Path, identity: str, category: str) -> FileIdentity:
    length, digest = _file_digest(path)
    return FileIdentity(path, identity, category, length, digest)


def _record_identity(record: SourceRecord, data: bytes, description: str) -> None:
    if record.count != 1 or record.length != len(data) or record.sha256 != _sha256(data):
        raise AttestationError(f"source manifest identity mismatch for {description}")


def _canonical_ascii_lines(data: bytes, label: str) -> list[str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise AttestationError(f"{label} is not ASCII") from error
    if not text.endswith("\n") or "\r" in text:
        raise AttestationError(f"{label} is not in canonical LF form")
    return text[:-1].split("\n")


def parse_source_manifest(data: bytes) -> list[SourceRecord]:
    lines = _canonical_ascii_lines(data, "source manifest")
    if not lines or lines[0] != "blind-ledger-lifecycle-source-manifest-v2":
        raise AttestationError("unsupported source manifest header")
    records: list[SourceRecord] = []
    previous = ""
    for line_number, line in enumerate(lines[1:], start=2):
        fields = line.split("\t")
        if len(fields) != 4:
            raise AttestationError(f"malformed source manifest row {line_number}")
        path, count_text, length_text, digest = fields
        pure = PurePosixPath(path)
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or ":" in path
            or str(pure) != path
            or any(part in ("", ".", "..") for part in path.split("/"))
        ):
            raise AttestationError(f"noncanonical source manifest path at row {line_number}")
        if path <= previous:
            raise AttestationError(f"source manifest paths are duplicate or unsorted at row {line_number}")
        if not DECIMAL_PATTERN.fullmatch(count_text) or not DECIMAL_PATTERN.fullmatch(length_text):
            raise AttestationError(f"noncanonical numeric field at source manifest row {line_number}")
        if len(count_text) > 20 or len(length_text) > 20:
            raise AttestationError(f"oversized numeric field at source manifest row {line_number}")
        if not HASH_PATTERN.fullmatch(digest):
            raise AttestationError(f"invalid source manifest SHA-256 at row {line_number}")
        count, length = int(count_text), int(length_text)
        if count < 1 or length < 1 or count > 2**64 - 1 or length > 2**64 - 1:
            raise AttestationError(f"empty source manifest identity at row {line_number}")
        records.append(SourceRecord(path, count, length, digest))
        previous = path
    if not records:
        raise AttestationError("source manifest has no records")
    return records


def parse_build_receipt(data: bytes) -> dict[str, tuple[int, str]]:
    lines = _canonical_ascii_lines(data, "pre-link receipt")
    if not lines or lines[0] != "blind-ledger-lifecycle-build-receipt-v2":
        raise AttestationError("unsupported pre-link receipt header")
    expected = (
        "source_manifest",
        "lifecycle_kernel_object",
        "lifecycle_object",
        "model_object",
        "sha3_object",
        "manifest_object",
        "lifecycle_archive",
    )
    if len(lines) != len(expected) + 1:
        raise AttestationError("pre-link receipt has missing or extra records")
    parsed: dict[str, tuple[int, str]] = {}
    for line_number, (line, expected_name) in enumerate(zip(lines[1:], expected), start=2):
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != expected_name:
            raise AttestationError(f"unexpected pre-link receipt row {line_number}")
        if expected_name == "source_manifest":
            digest, length_text = fields[1], fields[2]
        else:
            length_text, digest = fields[1], fields[2]
        if (
            len(length_text) > 20
            or not DECIMAL_PATTERN.fullmatch(length_text)
            or int(length_text) < 1
            or int(length_text) > 2**64 - 1
            or not HASH_PATTERN.fullmatch(digest)
        ):
            raise AttestationError(f"invalid pre-link receipt length at row {line_number}")
        parsed[expected_name] = (int(length_text), digest)
    return parsed


def verify_embedded_manifest(executable: bytes, manifest: bytes, expected_sha256: str) -> None:
    if not HASH_PATTERN.fullmatch(expected_sha256) or _sha256(manifest) != expected_sha256:
        raise AttestationError("source manifest digest mismatch")
    if executable.count(manifest) != 1:
        raise AttestationError("embedded source manifest is missing or occurs more than once")


def _adapter_provenance_line(manifest_sha256: str, executable: bytes) -> str:
    if not HASH_PATTERN.fullmatch(manifest_sha256) or not executable:
        raise AttestationError("cannot derive adapter provenance from an empty or unbound artifact")
    return (
        "BL-LIFECYCLE-PROVENANCE/1;"
        f"manifest_sha256={manifest_sha256};"
        f"exe_size={len(executable)};"
        f"exe_sha256={_sha256(executable)}\n"
    )


def expected_link_argument_manifest() -> bytes:
    arguments = [
        "-Btoolchain/bin",
        "-fuse-ld=lld",
        "--ld-path=OUT_DIR:native_link_inputs/ld.lld.exe",
        "-Wl,--reproduce=OUT_DIR:lifecycle_link_repro.v1.tar",
        "-v",
        "-Wl,--no-insert-timestamp",
        f"-Wl,--undefined={LIFECYCLE_MANIFEST_SYMBOL}",
        "OUT_DIR:blind_ledger_lifecycle_link.gnu.a",
    ]
    arguments.extend(f"toolchain/lib/{name}" for name in SUPPORT_ARCHIVES_FIRST)
    arguments.extend(f"toolchain/lib/lean/{name}" for name in LEAN_ARCHIVES)
    arguments.extend(f"toolchain/lib/{name}" for name in SUPPORT_ARCHIVES_MIDDLE)
    arguments.append("toolchain/lib/lean/libLake.a")
    arguments.extend(f"toolchain/lib/{name}" for name in SUPPORT_ARCHIVES_LAST)
    arguments.extend(
        (
            "OUT_DIR:native_link_inputs/libgcc.a",
            "OUT_DIR:native_link_inputs/libgcc_eh.a",
            "OUT_DIR:native_link_inputs/libntdll.a",
            "-Wl,--stack,104857600",
            "-Wl,--gc-sections",
        )
    )
    lines = ["lifecycle-link-arguments-v3", "search-path\tOUT_DIR:native_link_inputs"]
    lines.extend(f"{index}\t{argument}" for index, argument in enumerate(arguments))
    return ("\n".join(lines) + "\n").encode("ascii")


def parse_link_argument_manifest(data: bytes) -> list[str]:
    if data != expected_link_argument_manifest():
        raise AttestationError("ordered Lifecycle link argument manifest differs from the reviewed contract")
    lines = data.decode("ascii").splitlines()
    return [line.split("\t", 1)[1] for line in lines[2:]]


def _validate_tar_name(name: str, is_directory: bool) -> str:
    if not name or "\\" in name or "\x00" in name or ":" in name:
        raise AttestationError("LLD reproducer contains a noncanonical member name")
    normalized = name[:-1] if is_directory and name.endswith("/") else name
    pure = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or str(pure) != normalized
        or any(part in ("", ".", "..") for part in normalized.split("/"))
    ):
        raise AttestationError(f"LLD reproducer contains an unsafe member path: {name!r}")
    return normalized


def read_lld_reproducer(path: Path) -> list[ArchiveMember]:
    members: list[ArchiveMember] = []
    seen: set[str] = set()
    response_count = 0
    last_data_end = 0
    try:
        archive = tarfile.open(path, mode="r:")
    except (OSError, tarfile.TarError) as error:
        raise AttestationError(f"cannot read uncompressed LLD reproducer tar: {error}") from error
    with archive:
        infos = archive.getmembers()
        if not infos:
            raise AttestationError("LLD reproducer tar is empty")
        non_directory_paths: set[str] = set()
        for info in infos:
            if info.isdir():
                if info.size != 0:
                    raise AttestationError(f"LLD reproducer directory has payload: {info.name!r}")
                name = _validate_tar_name(info.name, True)
                digest = _sha256(b"")
                is_directory = True
                response = None
                data_end = info.offset_data
            elif info.isreg():
                name = _validate_tar_name(info.name, False)
                if info.size < 0:
                    raise AttestationError(f"negative LLD reproducer member length: {name!r}")
                source = archive.extractfile(info)
                if source is None:
                    raise AttestationError(f"cannot read LLD reproducer member: {name!r}")
                hasher = hashlib.sha256()
                response_buffer = bytearray() if name == RESPONSE_NAME else None
                total = 0
                with source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        hasher.update(chunk)
                        total += len(chunk)
                        if response_buffer is not None:
                            if total > MAX_RESPONSE_BYTES:
                                raise AttestationError("LLD response file exceeds the supported size limit")
                            response_buffer.extend(chunk)
                if total != info.size:
                    raise AttestationError(f"truncated LLD reproducer member: {name!r}")
                digest = hasher.hexdigest()
                is_directory = False
                response = bytes(response_buffer) if response_buffer is not None else None
                data_end = info.offset_data + ((info.size + 511) // 512) * 512
                if name == RESPONSE_NAME:
                    response_count += 1
            else:
                raise AttestationError(f"LLD reproducer contains a link or special member: {info.name!r}")
            if name in seen:
                raise AttestationError(f"LLD reproducer contains a duplicate member: {name!r}")
            parts = PurePosixPath(name).parts
            for end in range(1, len(parts)):
                parent = "/".join(parts[:end])
                if parent in non_directory_paths:
                    raise AttestationError(f"LLD reproducer member is nested under a file: {name!r}")
            if not is_directory:
                prefix = name + "/"
                if any(existing.startswith(prefix) for existing in seen):
                    raise AttestationError(f"LLD reproducer file is a parent of another member: {name!r}")
                non_directory_paths.add(name)
            seen.add(name)
            last_data_end = max(last_data_end, data_end)
            members.append(ArchiveMember(name, is_directory, info.size, digest, response))
    if response_count != 1:
        raise AttestationError(f"expected one root {RESPONSE_NAME}, found {response_count}")
    try:
        size = path.stat().st_size
        if size % 512 != 0 or size - last_data_end < 1024:
            raise AttestationError("LLD reproducer tar has a truncated or noncanonical trailer")
        with path.open("rb") as stream:
            stream.seek(last_data_end)
            while chunk := stream.read(1024 * 1024):
                if any(chunk):
                    raise AttestationError("LLD reproducer tar has nonzero trailing data")
    except OSError as error:
        raise AttestationError(f"cannot validate LLD reproducer trailer: {error}") from error
    return members


def match_reproducer_inputs(
    members: Sequence[ArchiveMember],
    candidates: Sequence[FileIdentity],
    explicit_inputs: Sequence[FileIdentity],
) -> list[tuple[ArchiveMember, FileIdentity]]:
    payload_members = [
        member for member in members
        if not member.is_directory and member.name not in (RESPONSE_NAME, "version.txt")
    ]
    by_identity: dict[tuple[str, int, str], list[FileIdentity]] = {}
    for candidate in candidates:
        key = (candidate.path.name.casefold(), candidate.length, candidate.sha256)
        by_identity.setdefault(key, []).append(candidate)
    mapped: list[tuple[ArchiveMember, FileIdentity]] = []
    mapped_paths: set[str] = set()
    for member in payload_members:
        key = (PurePosixPath(member.name).name.casefold(), member.length, member.sha256)
        matches = by_identity.get(key, [])
        if len(matches) != 1:
            detail = "unknown" if not matches else "ambiguous"
            raise AttestationError(f"{detail} LLD link input: {member.name!r}")
        candidate = matches[0]
        mapped.append((member, candidate))
        mapped_paths.add(os.path.normcase(str(candidate.path.resolve())))
    missing = [
        item.identity for item in explicit_inputs
        if os.path.normcase(str(item.path.resolve())) not in mapped_paths
    ]
    if missing:
        raise AttestationError("explicit link arguments absent from LLD reproducer: " + ", ".join(missing))
    if not payload_members:
        raise AttestationError("LLD reproducer has no link input payloads")
    return mapped


def _lld_reproducer_name(path: Path) -> str:
    try:
        absolute = str(path.resolve(strict=False)).replace("\\", "/")
    except OSError as error:
        raise AttestationError(f"cannot resolve LLD input path {path}: {error}") from error
    match = re.fullmatch(r"([A-Za-z]):/(.+)", absolute)
    if match is None:
        raise AttestationError(f"LLD input is outside the supported local drive-path form: {path}")
    return _validate_tar_name(f"{match.group(1)}/{match.group(2)}", False)


def parse_lld_response_inputs(response: bytes) -> list[str]:
    """Parse the pinned Windows-GNU LLD/MinGW COFF reproducer row format only."""
    try:
        text = response.decode("ascii")
    except UnicodeDecodeError as error:
        raise AttestationError("LLD response is not ASCII") from error
    if (
        not text
        or not text.endswith("\n")
        or "\r" in text
        or "\x00" in text
        or any(ord(character) < 0x20 and character != "\n" for character in text)
        or "\x7f" in text
    ):
        raise AttestationError("LLD response is not in canonical bounded LF form")
    lines = text[:-1].split("\n")
    if not lines or len(lines) > MAX_RESPONSE_ARGUMENTS:
        raise AttestationError("LLD response has an unsupported argument count")
    if "--chroot ." in lines:
        raise AttestationError("LLD response uses the unsupported ELF reproducer grammar")

    inputs: list[str] = []
    mingw_mode_count = 0
    file_option_prefixes = (
        "/wholearchive:",
        "/def:",
        "/manifestinput:",
        "/natvis:",
        "/call-graph-profile-sort:",
        "/order:",
        "/pdbstream:",
        "-reproduce:",
    )
    for line_number, line in enumerate(lines, start=1):
        if not line or line != line.strip():
            raise AttestationError(f"LLD response has a blank or padded row at line {line_number}")
        if line == "-lldmingw":
            mingw_mode_count += 1
            continue
        if line.startswith("@") or line == "--":
            raise AttestationError(f"LLD response contains unsupported response indirection at line {line_number}")

        path_text = line
        if path_text.startswith('"') or path_text.endswith('"'):
            if (
                len(path_text) < 3
                or not path_text.startswith('"')
                or not path_text.endswith('"')
                or '"' in path_text[1:-1]
                or "\\" in path_text
                or " " not in path_text[1:-1]
            ):
                raise AttestationError(f"LLD response has unsupported quoting at line {line_number}")
            path_text = path_text[1:-1]

        if re.fullmatch(r"[A-Za-z]/.+", path_text):
            try:
                inputs.append(_validate_tar_name(path_text, False))
            except AttestationError as error:
                raise AttestationError(f"LLD response has an unsafe input path at line {line_number}: {error}") from error
            continue

        if not line.startswith(("-", "/")):
            raise AttestationError(f"LLD response has an unsupported non-option row at line {line_number}")
        folded_line = line.casefold()
        if folded_line.startswith(file_option_prefixes):
            raise AttestationError(f"LLD response uses unsupported file-bearing option at line {line_number}")
        if folded_line.startswith("/defaultlib:"):
            raise AttestationError(f"LLD response uses unsupported deferred library lookup at line {line_number}")
        if (folded_line.startswith("-l") and line != "-lldmingw"):
            raise AttestationError(f"LLD response contains unresolved MinGW library syntax at line {line_number}")
        quote_start = line.find('"')
        quote_end = line.rfind('"')
        if quote_start >= 0 and (quote_start == 0 or quote_end != len(line) - 1 or " " not in line[quote_start + 1:quote_end]):
            raise AttestationError(f"LLD response has unsupported option quoting at line {line_number}")
        if line.count('"') not in (0, 2) or line.count("\\"):
            raise AttestationError(f"LLD response has ambiguous option quoting at line {line_number}")

    if mingw_mode_count != 1:
        raise AttestationError(f"expected one MinGW COFF marker in LLD response, found {mingw_mode_count}")
    if not inputs:
        raise AttestationError("LLD response has no direct file inputs")
    return inputs


def _response_input_file(name: str, target_dir: Path) -> Path:
    parts = PurePosixPath(name).parts
    if len(parts) < 2 or len(parts[0]) != 1 or not parts[0].isascii() or not parts[0].isalpha():
        raise AttestationError(f"LLD response input is not a local drive-relative path: {name!r}")
    path = Path(parts[0] + ":\\" + "\\".join(parts[1:]))
    roots = [target_dir, RUST_ROOT, LEAN_TOOLCHAIN, PINNED_RUSTC.parent.parent]
    roots.extend(Path(value) for name in ("TEMP", "TMP") if (value := os.environ.get(name)))
    for root in roots:
        try:
            resolved_root = root.resolve(strict=True)
        except OSError:
            continue
        lexical = Path(os.path.abspath(path))
        try:
            lexical.relative_to(resolved_root)
        except ValueError:
            continue
        current = resolved_root
        for part in lexical.relative_to(resolved_root).parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                return lexical
            except OSError as error:
                raise AttestationError(f"cannot inspect LLD response input {current}: {error}") from error
            if stat.S_ISLNK(info.st_mode) or _is_reparse_point(current):
                raise AttestationError(f"reparse point at LLD response input: {current}")
        return lexical.resolve(strict=True)
    raise AttestationError(f"LLD response input is outside the pinned build roots: {name!r}")


def verify_response_references(
    input_names: Sequence[str],
    candidates: Sequence[FileIdentity],
    mapped_inputs: Sequence[tuple[ArchiveMember, FileIdentity]],
    explicit_inputs: Sequence[FileIdentity],
) -> list[tuple[ArchiveMember, FileIdentity]]:
    by_reproducer_name: dict[str, FileIdentity] = {}
    for item in candidates:
        name = _lld_reproducer_name(item.path).casefold()
        if name in by_reproducer_name:
            raise AttestationError(f"ambiguous candidate path in LLD response inventory: {name!r}")
        by_reproducer_name[name] = item

    ordered: list[tuple[ArchiveMember, FileIdentity]] = []
    response_keys: list[str] = []
    for name in input_names:
        key = name.casefold()
        item = by_reproducer_name.get(key)
        if item is None:
            raise AttestationError(f"LLD response references an uncaptured input path: {name!r}")
        response_keys.append(os.path.normcase(str(item.path.resolve(strict=False))))

    captured_by_path: dict[str, tuple[ArchiveMember, FileIdentity]] = {}
    for member, item in mapped_inputs:
        key = os.path.normcase(str(item.path.resolve(strict=False)))
        if member.name.casefold() != _lld_reproducer_name(item.path).casefold():
            raise AttestationError(
                f"LLD reproducer member path differs from its response input path: {member.name!r}"
            )
        if key in captured_by_path:
            raise AttestationError(f"LLD reproducer captures one input path more than once: {member.name!r}")
        captured_by_path[key] = (member, item)
    if set(response_keys) != set(captured_by_path):
        missing = sorted(set(response_keys) - set(captured_by_path))
        unreferenced = sorted(set(captured_by_path) - set(response_keys))
        raise AttestationError(
            "LLD response and captured input paths differ; "
            f"response_without_payload={missing!r}; payload_without_response={unreferenced!r}"
        )

    cursor = 0
    for expected in explicit_inputs:
        expected_key = os.path.normcase(str(expected.path.resolve(strict=False)))
        while cursor < len(response_keys) and response_keys[cursor] != expected_key:
            cursor += 1
        if cursor == len(response_keys):
            raise AttestationError("LLD response input order differs from the reviewed explicit argument order")
        cursor += 1

    for key in response_keys:
        ordered.append(captured_by_path[key])
    return ordered


def verify_explicit_link_input_identities(
    explicit_inputs: Sequence[FileIdentity],
    source_records: dict[str, SourceRecord],
    build_receipt: dict[str, tuple[int, str]],
) -> None:
    for item in explicit_inputs:
        argument = item.identity.partition("=")[2]
        if argument == "OUT_DIR:blind_ledger_lifecycle_link.gnu.a":
            expected = build_receipt["lifecycle_archive"]
        elif argument.startswith("OUT_DIR:native_link_inputs/"):
            name = PurePosixPath(argument.removeprefix("OUT_DIR:native_link_inputs/")).name
            record = source_records.get(f"link-input/native/{name}")
            if record is None:
                raise AttestationError(f"explicit native link input is absent from the source manifest: {name}")
            expected = (record.length, record.sha256)
        elif argument.startswith("toolchain/lib/lean/"):
            name = PurePosixPath(argument.removeprefix("toolchain/lib/lean/")).name
            record = source_records.get(f"link-input/lean/{name}")
            if record is None:
                raise AttestationError(f"explicit Lean archive is absent from the source manifest: {name}")
            expected = (record.length, record.sha256)
        elif argument.startswith("toolchain/lib/"):
            name = PurePosixPath(argument.removeprefix("toolchain/lib/")).name
            record = source_records.get(f"link-input/support/{name}")
            if record is None:
                raise AttestationError(f"explicit support archive is absent from the source manifest: {name}")
            expected = (record.length, record.sha256)
        else:
            raise AttestationError(f"unsupported explicit Lifecycle link input: {argument!r}")
        if (item.length, item.sha256) != expected:
            raise AttestationError(f"explicit link input differs from its pre-link identity: {argument}")


def _walk_olean_tree(root: Path) -> tuple[int, int, str]:
    records: list[tuple[str, int, str]] = []
    def walk_error(error: OSError) -> None:
        raise AttestationError(f"cannot enumerate Lean import tree: {error}") from error

    for directory, dirnames, filenames in os.walk(root, topdown=True, onerror=walk_error, followlinks=False):
        base = Path(directory)
        for name in list(dirnames):
            child = base / name
            info = child.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse_point(child):
                raise AttestationError(f"symlink or non-directory in Lean import tree: {child}")
        for name in filenames:
            child = base / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or _is_reparse_point(child):
                raise AttestationError(f"symlink in Lean import tree: {child}")
            if child.suffix != ".olean":
                continue
            if not stat.S_ISREG(info.st_mode):
                raise AttestationError(f"nonregular Lean import file: {child}")
            relative = child.relative_to(root).as_posix()
            if not relative.isascii() or relative.startswith("/") or "../" in relative:
                raise AttestationError(f"noncanonical Lean import path: {relative}")
            data = _read_regular(child)
            records.append((relative, len(data), _sha256(data)))
    records.sort(key=lambda row: row[0])
    if not records:
        raise AttestationError("Lean import tree contains no .olean files")
    total = sum(length for _, length, _ in records)
    lines = ["lean-olean-tree-v1"]
    lines.extend(f"{relative}\t{length}\t{digest}" for relative, length, digest in records)
    digest = _sha256(("\n".join(lines) + "\n").encode("ascii"))
    return len(records), total, digest


def _rust_std_file_records() -> dict[str, Path]:
    manifest_bytes = _read_regular(PINNED_GNU_MANIFEST)
    if _sha256(manifest_bytes) != PINNED_GNU_MANIFEST_SHA256:
        raise AttestationError("pinned GNU Rust target manifest digest mismatch")
    try:
        lines = manifest_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AttestationError("GNU Rust target manifest is not UTF-8") from error
    sysroot = PINNED_RUSTC.parent.parent
    paths = {"rust-target-std/manifest": PINNED_GNU_MANIFEST}
    for line in lines:
        if not line.startswith("file:"):
            raise AttestationError("unexpected GNU Rust target manifest record")
        relative = line[len("file:"):]
        if not relative.startswith(f"lib/rustlib/{TARGET}/") or "\\" in relative or ".." in PurePosixPath(relative).parts:
            raise AttestationError("GNU Rust target manifest path is outside the pinned target")
        role = f"rust-target-std/{relative}"
        if role in paths:
            raise AttestationError("duplicate GNU Rust target manifest path")
        paths[role] = sysroot.joinpath(*PurePosixPath(relative).parts)
    if len(paths) <= 1:
        raise AttestationError("GNU Rust target manifest has no file records")
    return paths


def _hash_record(record: SourceRecord, path: Path) -> None:
    length, digest = _file_digest(path)
    if record.count != 1 or record.length != length or record.sha256 != digest:
        raise AttestationError(f"source manifest identity mismatch for {record.path}")


def _source_file_map(out_dir: Path, rust_std_paths: dict[str, Path]) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for relative in LEAN_SOURCE_PATHS:
        paths[f"lean/{relative}"] = LEAN_ROOT / Path(*PurePosixPath(relative).parts)
    for relative in RUST_SOURCE_PATHS:
        paths[f"rust/{relative}"] = RUST_ROOT / Path(*PurePosixPath(relative).parts)
    for relative in LEAN_TOOL_PATHS:
        paths[f"toolchain/{relative}"] = LEAN_TOOLCHAIN / Path(*PurePosixPath(relative).parts)
    paths["rust-toolchain/cargo.exe"] = PINNED_CARGO
    paths["toolchain/rustc.exe"] = PINNED_RUSTC
    paths["toolchain/rust-std-manifest-x86_64-pc-windows-gnu"] = PINNED_GNU_MANIFEST
    paths.update(rust_std_paths)
    for name in sorted(set(SUPPORT_ARCHIVES_FIRST + SUPPORT_ARCHIVES_MIDDLE + SUPPORT_ARCHIVES_LAST)):
        paths[f"link-input/support/{name}"] = LEAN_TOOLCHAIN / "lib" / name
    for name in sorted(set(LEAN_ARCHIVES + ("libLake.a",))):
        paths[f"link-input/lean/{name}"] = LEAN_TOOLCHAIN / "lib" / "lean" / name
    for name in ("libgcc.a", "libgcc_eh.a", "libntdll.a"):
        paths[f"link-input/native/{name}"] = out_dir / "native_link_inputs" / name
    paths["link-tool/ld.lld.exe"] = out_dir / "native_link_inputs" / "ld.lld.exe"
    paths["build/lifecycle-link-arguments-v1"] = out_dir / LINK_ARGUMENTS_NAME
    generated = out_dir / "lifecycle_lean_build" / ".lake" / "build" / "ir"
    paths.update(
        {
            "build-output/lifecycle-kernel-object": generated / "Admission" / "LifecycleKernel.c.o.export",
            "build-output/lifecycle-object": generated / "Admission" / "Lifecycle.c.o.noexport",
            "build-output/model-object": generated / "Admission" / "Model.c.o.noexport",
            "build-output/sha3-object": generated / "BlindLedger" / "Sha3.c.o.noexport",
        }
    )
    return paths


def _expected_text_identities() -> dict[str, bytes]:
    values = {
        "build/host": "x86_64-pc-windows-msvc",
        "build/target": TARGET,
        "build/profile": "release",
        "build/opt-level": "3",
        "build/debug": "false",
        "build/effective-rustflags": "-C\x1flink-self-contained=no\x1f-C\x1fpanic=abort",
        "build/linker": "toolchain/bin/clang.exe",
        "build/target-arch": "x86_64",
        "build/target-os": "windows",
        "build/target-env": "gnu",
        "build/target-family": "windows",
        "build/target-pointer-width": "64",
        "build/target-endian": "little",
        "build/cargo-cfg/target_arch": "x86_64",
        "build/cargo-cfg/target_os": "windows",
        "build/cargo-cfg/target_env": "gnu",
        "build/cargo-cfg/target_family": "windows",
        "build/cargo-cfg/target_pointer_width": "64",
        "build/cargo-cfg/target_endian": "little",
    }
    return {path: value.encode("utf-8") for path, value in values.items()}


def verify_source_manifest_inputs(out_dir: Path, records: Sequence[SourceRecord]) -> dict[str, SourceRecord]:
    by_path = {record.path: record for record in records}
    if len(by_path) != len(records):
        raise AttestationError("duplicate source manifest path")
    rust_std_paths = _rust_std_file_records()
    source_files = _source_file_map(out_dir, rust_std_paths)
    expected_files = set(source_files)
    expected_files.update({"toolchain/lib/lean-olean-tree-v1", "toolchain/gnu-target-binding"})
    actual_file_paths = {path for path in by_path if path in expected_files}
    if actual_file_paths != expected_files:
        missing = sorted(expected_files - actual_file_paths)
        raise AttestationError("source manifest omits required file records: " + ", ".join(missing))

    allowed_nonfile = set(_expected_text_identities())
    allowed_nonfile.update(
        path for path in by_path
        if path.startswith("build/cargo-cfg/")
        and re.fullmatch(r"build/cargo-cfg/target_[a-z0-9_]+", path)
    )
    allowed_environment = {
        "build/environment/path",
        "build/environment/systemroot",
        "build/environment/cargo_home",
        "build/environment/cargo_target_dir",
        "build/environment/temp",
        "build/environment/tmp",
    }
    allowed_nonfile.update(path for path in by_path if path in allowed_environment)
    expected_paths = expected_files | allowed_nonfile
    unknown = sorted(set(by_path) - expected_paths)
    missing_text = sorted(set(_expected_text_identities()) - set(by_path))
    if unknown or missing_text:
        raise AttestationError(
            "source manifest record set mismatch; unknown=" + repr(unknown) + "; missing=" + repr(missing_text)
        )
    for path, value in _expected_text_identities().items():
        record = by_path[path]
        _record_identity(record, value, path)
    for path in allowed_nonfile - set(_expected_text_identities()):
        record = by_path[path]
        if record.count != 1:
            raise AttestationError(f"nonfile build identity has an invalid count: {path}")

    for path, file_path in source_files.items():
        _hash_record(by_path[path], file_path)
    olean_record = by_path["toolchain/lib/lean-olean-tree-v1"]
    count, length, digest = _walk_olean_tree(LEAN_TOOLCHAIN / "lib" / "lean")
    if (olean_record.count, olean_record.length, olean_record.sha256) != (count, length, digest):
        raise AttestationError("Lean .olean tree identity changed after link")
    binding_record = by_path["toolchain/gnu-target-binding"]
    hasher = hashlib.sha256()
    for role, file_path in rust_std_paths.items():
        data = _read_regular(file_path)
        hasher.update(role.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    binding = hasher.hexdigest().encode("ascii")
    _record_identity(binding_record, binding, "toolchain/gnu-target-binding")
    return by_path


def _safe_under(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    lexical = Path(os.path.abspath(candidate))
    try:
        relative = lexical.relative_to(resolved_root)
    except ValueError as error:
        raise AttestationError(f"path escaped its required root: {candidate}") from error
    current = resolved_root
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise AttestationError(f"cannot inspect contained path {current}: {error}") from error
        if stat.S_ISLNK(info.st_mode) or _is_reparse_point(current):
            raise AttestationError(f"reparse point in contained build output: {current}")
    return lexical.resolve(strict=True)


def _validate_outdirs(target_arg: str, evidence_arg: str) -> tuple[Path, Path]:
    source_root = REPO_ROOT.resolve(strict=True)
    target = Path(target_arg).expanduser().absolute().resolve(strict=False)
    evidence = Path(evidence_arg).expanduser().absolute().resolve(strict=False)
    for label, path in (("target directory", target), ("evidence directory", evidence)):
        try:
            path.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise AttestationError(f"{label} must be outside the source root")
        if os.path.lexists(path):
            raise AttestationError(f"{label} must be fresh and nonexistent: {path}")
    if target == evidence or target in evidence.parents or evidence in target.parents:
        raise AttestationError("target and evidence directories must be disjoint")
    return target, evidence


def _resolve_cargo_home(environment: dict[str, str]) -> Path:
    configured = environment.get("CARGO_HOME")
    if configured is not None:
        if not configured:
            raise AttestationError("CARGO_HOME is empty")
        home = Path(configured).expanduser()
    else:
        profile = environment.get("USERPROFILE") or str(Path.home())
        home = Path(profile).expanduser() / ".cargo"
    if not home.is_absolute():
        raise AttestationError("CARGO_HOME must be an absolute path")
    return home.resolve(strict=False)


def _verify_cargo_configuration(
    environment: dict[str, str],
    *,
    cargo_home: Path | None = None,
) -> dict[str, object]:
    root = RUST_ROOT.resolve(strict=True)
    project_config = root / ".cargo" / "config.toml"
    project_config_resolved = project_config.resolve(strict=True)
    home = cargo_home or _resolve_cargo_home(environment)
    candidates: list[Path] = []
    current = root
    while True:
        candidates.extend(current / ".cargo" / name for name in ("config.toml", "config"))
        if current.parent == current:
            break
        current = current.parent
    candidates.extend(home / name for name in ("config.toml", "config"))

    searched: list[str] = []
    checked: set[str] = set()
    found: list[dict[str, object]] = []
    for candidate in candidates:
        key = os.path.normcase(str(candidate.absolute()))
        if key in checked:
            continue
        checked.add(key)
        searched.append(str(candidate))
        if not os.path.lexists(candidate):
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise AttestationError(f"cannot resolve Cargo configuration {candidate}: {error}") from error
        if resolved != project_config_resolved:
            raise AttestationError(f"unreviewed Cargo configuration file: {candidate}")
        length, digest = _file_digest(candidate)
        if digest != PINNED_PROJECT_CARGO_CONFIG_SHA256:
            raise AttestationError("pinned project Cargo configuration SHA-256 mismatch")
        found.append({"file": str(resolved), "length": length, "sha256": digest})
    if len(found) != 1:
        raise AttestationError(f"expected one pinned project Cargo configuration file, found {len(found)}")
    return {"cargo_home": str(home), "searched_paths": searched, "files": found}


def _check_build_environment(environment: dict[str, str]) -> dict[str, object]:
    forbidden = (
        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS", "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "CARGO_PROFILE_RELEASE_OPT_LEVEL", "CARGO_PROFILE_RELEASE_DEBUG", "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS",
        "CARGO_PROFILE_RELEASE_PANIC", "CARGO_PROFILE_RELEASE_STRIP", "CARGO_PROFILE_RELEASE_INCREMENTAL",
        "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS", "CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO",
        "CARGO_PROFILE_RELEASE_RPATH", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_BUILD_DIR",
        "CARGO_BUILD_WARNINGS", "CARGO_INCREMENTAL", "RUSTC_BOOTSTRAP",
        "RUSTC_FORCE_INCREMENTAL", "CL", "_CL_", "CC", "CXX", "AR", "LLVM_AR", "LLVM_CLANG",
        "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
        "LIBRARY_PATH", "CCC_OVERRIDE_OPTIONS", "INCLUDE", "LIB", "LEAN_PATH", "LEAN_SYSROOT",
        "LEAN_TOOLCHAIN_ROOT", "LLD_REPRODUCE", "CARGO_BUILD_TARGET",
        "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER",
    )
    present = [name for name in forbidden if name in environment]
    present.extend(sorted(
        name for name in environment
        if name.startswith("CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_")
    ))
    if present:
        raise AttestationError("unreviewed build environment override(s): " + ", ".join(present))
    cargo_home = _resolve_cargo_home(environment)
    environment["CARGO_HOME"] = str(cargo_home)
    return _verify_cargo_configuration(environment, cargo_home=cargo_home)


def _load_cargo_artifact(stdout: bytes, target_dir: Path) -> tuple[Path, list[str]]:
    try:
        lines = stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AttestationError("Cargo JSON output is not UTF-8") from error
    messages = []
    for index, line in enumerate(lines, start=1):
        if not line:
            raise AttestationError(f"blank Cargo JSON output line {index}")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise AttestationError(f"invalid Cargo JSON output line {index}: {error}") from error
        if not isinstance(message, dict) or not isinstance(message.get("reason"), str):
            raise AttestationError(f"unexpected Cargo JSON output object at line {index}")
        messages.append(message)
    finished = [message for message in messages if message.get("reason") == "build-finished"]
    if len(finished) != 1 or finished[0].get("success") is not True:
        raise AttestationError("Cargo JSON does not contain one successful build-finished record")
    artifacts = [
        message for message in messages
        if message.get("reason") == "compiler-artifact"
        and isinstance(message.get("target"), dict)
        and message["target"].get("name") == "lifecycle"
        and "bin" in message["target"].get("kind", [])
    ]
    if len(artifacts) != 1:
        raise AttestationError(f"expected one lifecycle binary compiler-artifact record, found {len(artifacts)}")
    artifact = artifacts[0]
    profile = artifact.get("profile")
    if (
        not isinstance(profile, dict)
        or profile.get("test") is not False
        or profile.get("debug_assertions") is not False
        or profile.get("opt_level") != "3"
    ):
        raise AttestationError("Cargo lifecycle artifact has an unreviewed profile")
    expected = target_dir / TARGET / "release" / "lifecycle.exe"
    executable_text = artifact.get("executable")
    if not isinstance(executable_text, str):
        raise AttestationError("Cargo lifecycle artifact has no executable path")
    reported = Path(executable_text).resolve(strict=False)
    if reported != expected.resolve(strict=False):
        raise AttestationError("Cargo lifecycle artifact path differs from the fresh release target")
    warnings: list[str] = []
    for message in messages:
        if message.get("reason") == "compiler-message":
            diagnostic = message.get("message")
            if isinstance(diagnostic, dict) and diagnostic.get("level") == "warning":
                rendered = diagnostic.get("rendered")
                warnings.append(rendered if isinstance(rendered, str) else str(diagnostic.get("message", "warning")))
    return expected, warnings


def _find_out_dir(target_dir: Path) -> Path:
    receipts = []
    for path in target_dir.rglob(BUILD_RECEIPT_NAME):
        resolved = _safe_under(target_dir, path)
        _read_regular(resolved)
        receipts.append(resolved)
    if len(receipts) != 1:
        raise AttestationError(f"expected one pre-link receipt under fresh target directory, found {len(receipts)}")
    return receipts[0].parent


def _candidate_files(
    target_dir: Path,
    source_records: dict[str, SourceRecord],
    out_dir: Path,
    response_input_names: Sequence[str],
    captured_members: Sequence[ArchiveMember],
) -> tuple[list[FileIdentity], list[FileIdentity]]:
    candidates: dict[str, FileIdentity] = {}

    def add(path: Path, identity: str, category: str) -> FileIdentity:
        item = _file_identity(path, identity, category)
        key = os.path.normcase(str(item.path.resolve(strict=False)))
        previous = candidates.get(key)
        if previous is None or (category == "explicit-link-argument" and previous.category != category):
            candidates[key] = item
        return candidates[key]

    explicit: list[FileIdentity] = []
    argument_data = _read_regular(out_dir / LINK_ARGUMENTS_NAME)
    arguments = parse_link_argument_manifest(argument_data)
    for index, argument in enumerate(arguments):
        if argument.startswith("OUT_DIR:"):
            relative = PurePosixPath(argument[len("OUT_DIR:"):])
            if relative.is_absolute() or ".." in relative.parts or "\\" in argument:
                raise AttestationError("unsafe OUT_DIR input in ordered link argument manifest")
            path = out_dir.joinpath(*relative.parts)
            identity = f"arg[{index}]={argument}"
        elif argument.startswith("toolchain/lib/"):
            relative = PurePosixPath(argument[len("toolchain/lib/"):])
            if relative.is_absolute() or ".." in relative.parts or "\\" in argument:
                raise AttestationError("unsafe toolchain input in ordered link argument manifest")
            path = LEAN_TOOLCHAIN / "lib" / Path(*relative.parts)
            identity = f"arg[{index}]={argument}"
        else:
            continue
        item = add(path, identity, "explicit-link-argument")
        explicit.append(item)

    for directory, dirnames, filenames in os.walk(target_dir, topdown=True, followlinks=False):
        base = Path(directory)
        for dirname in dirnames:
            path = base / dirname
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or _is_reparse_point(path):
                raise AttestationError(f"reparse point in fresh Cargo target directory: {path}")
        for filename in filenames:
            path = base / filename
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse_point(path):
                raise AttestationError(f"nonregular file in fresh Cargo target directory: {path}")
            if path.suffix.lower() not in LINK_INPUT_SUFFIXES:
                continue
            relative = path.relative_to(target_dir).as_posix()
            add(path, f"target/{relative}", "cargo-target-artifact")

    rust_std_paths = _rust_std_file_records()
    for role, path in rust_std_paths.items():
        if role == "rust-target-std/manifest" or path.suffix.lower() not in LINK_INPUT_SUFFIXES:
            continue
        if role not in source_records:
            raise AttestationError(f"Rust target artifact is absent from source manifest: {role}")
        _hash_record(source_records[role], path)
        add(path, role, "rust-target-std")

    known_paths = {os.path.normcase(str(item.path.resolve(strict=False))) for item in candidates.values()}
    captured_by_name = {
        member.name.casefold(): member
        for member in captured_members
        if not member.is_directory and member.name not in (RESPONSE_NAME, "version.txt")
    }
    for index, name in enumerate(response_input_names):
        path = _response_input_file(name, target_dir)
        key = os.path.normcase(str(path.resolve(strict=False)))
        if key in known_paths:
            continue
        try:
            path.lstat()
        except FileNotFoundError:
            member = captured_by_name.get(name.casefold())
            if member is None:
                raise AttestationError(f"LLD response input has no reproducer payload: {name!r}")
            candidates[key] = FileIdentity(
                path,
                f"lld-response-capture[{index}]={name}",
                "lld-response-capture",
                member.length,
                member.sha256,
            )
        except OSError as error:
            raise AttestationError(f"cannot inspect LLD response input {path}: {error}") from error
        else:
            add(path, f"lld-response-input[{index}]={name}", "lld-response-input")
        known_paths.add(key)
    return list(candidates.values()), explicit


def _write_new(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise AttestationError(f"cannot create evidence file {path}: {error}") from error


def _write_receipt(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    _write_new(temporary, data)
    try:
        if os.path.lexists(path):
            raise AttestationError(f"receipt path unexpectedly exists: {path}")
        os.rename(temporary, path)
    except OSError as error:
        raise AttestationError(f"cannot publish complete post-link receipt {path}: {error}") from error


def _forward_cargo_output(stdout: bytes, stderr: bytes) -> None:
    if stdout:
        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
    if stderr:
        sys.stderr.buffer.write(stderr)
        sys.stderr.buffer.flush()


def _attest_success(
    target_dir: Path,
    evidence_dir: Path,
    cargo_stdout: bytes,
    cargo_stderr: bytes,
    command: Sequence[str],
    warnings: Sequence[str],
    cargo_configuration: dict[str, object],
) -> dict[str, object]:
    executable_path = target_dir / TARGET / "release" / "lifecycle.exe"
    executable_path = _safe_under(target_dir, executable_path)
    executable = _read_regular(executable_path)
    out_dir = _find_out_dir(target_dir)
    source_manifest_path = _safe_under(target_dir, out_dir / SOURCE_MANIFEST_NAME)
    prelink_receipt_path = _safe_under(target_dir, out_dir / BUILD_RECEIPT_NAME)
    arguments_path = _safe_under(target_dir, out_dir / LINK_ARGUMENTS_NAME)
    reproducer_path = _safe_under(target_dir, out_dir / REPRODUCER_NAME)
    manifest_data = _read_regular(source_manifest_path, limit=64 * 1024 * 1024)
    manifest_hash = _sha256(manifest_data)
    records = parse_source_manifest(manifest_data)
    by_path = verify_source_manifest_inputs(out_dir, records)
    receipt_data = _read_regular(prelink_receipt_path, limit=1024 * 1024)
    receipt_hash = _sha256(receipt_data)
    receipt = parse_build_receipt(receipt_data)
    if receipt["source_manifest"] != (len(manifest_data), manifest_hash):
        raise AttestationError("pre-link receipt does not bind the exact source manifest")
    receipt_record_map = {
        "lifecycle_kernel_object": "build-output/lifecycle-kernel-object",
        "lifecycle_object": "build-output/lifecycle-object",
        "model_object": "build-output/model-object",
        "sha3_object": "build-output/sha3-object",
    }
    for receipt_name, source_name in receipt_record_map.items():
        item = receipt[receipt_name]
        record = by_path[source_name]
        if item != (record.length, record.sha256):
            raise AttestationError(f"pre-link receipt and source manifest disagree for {receipt_name}")
    link_archive = out_dir / "blind_ledger_lifecycle_link.gnu.a"
    archive_identity = _file_digest(link_archive)
    if receipt["lifecycle_archive"] != archive_identity:
        raise AttestationError("pre-link receipt does not bind the Lifecycle link archive")
    manifest_object_path = out_dir / "lifecycle_manifest_object" / "lifecycle_source_manifest.o"
    if receipt["manifest_object"] != _file_digest(manifest_object_path):
        raise AttestationError("pre-link receipt does not bind the generated source-manifest object")
    args_data = _read_regular(arguments_path)
    parse_link_argument_manifest(args_data)
    arguments_record = by_path["build/lifecycle-link-arguments-v1"]
    _record_identity(arguments_record, args_data, "ordered link arguments")
    verify_embedded_manifest(executable, manifest_data, manifest_hash)
    link_members = read_lld_reproducer(reproducer_path)
    response_members = [member for member in link_members if member.name == RESPONSE_NAME]
    response = response_members[0].response_bytes
    if response is None:
        raise AttestationError("LLD response member has no captured content")
    response_input_names = parse_lld_response_inputs(response)
    candidates, explicit_inputs = _candidate_files(
        target_dir,
        by_path,
        out_dir,
        response_input_names,
        link_members,
    )
    verify_explicit_link_input_identities(explicit_inputs, by_path, receipt)
    mapped = match_reproducer_inputs(link_members, candidates, explicit_inputs)
    ordered_inputs = verify_response_references(
        response_input_names,
        candidates,
        mapped,
        explicit_inputs,
    )

    stdout_path = evidence_dir / "cargo.stdout.log"
    stderr_path = evidence_dir / "cargo.stderr.log"
    response_path = evidence_dir / "lifecycle_link_response.v1.bin"
    _write_new(response_path, response)
    reproducer_length, reproducer_digest = _file_digest(reproducer_path)
    executable_sha256 = _sha256(executable)
    adapter_provenance_line = _adapter_provenance_line(manifest_hash, executable)
    receipt_object: dict[str, object] = {
        "format": "blind-ledger-lifecycle-post-link-receipt-v1",
        "invocation": {
            "argv": list(command),
            "cwd": str(RUST_ROOT.resolve(strict=True)),
            "cargo_sha256": PINNED_CARGO_SHA256,
            "target": TARGET,
            "profile": "release",
            "offline": True,
            "locked": True,
            "exit_status": 0,
        },
        "cargo_configuration": cargo_configuration,
        "cargo_output": {
            "stdout": {"file": stdout_path.name, "length": len(cargo_stdout), "sha256": _sha256(cargo_stdout)},
            "stderr": {"file": stderr_path.name, "length": len(cargo_stderr), "sha256": _sha256(cargo_stderr)},
            "warning_count": len(warnings),
        },
        "source_manifest": {"file": str(source_manifest_path), "length": len(manifest_data), "sha256": manifest_hash},
        "prelink_receipt": {"file": str(prelink_receipt_path), "length": len(receipt_data), "sha256": receipt_hash},
        "link_arguments": {"file": str(arguments_path), "length": len(args_data), "sha256": _sha256(args_data)},
        "link_reproducer": {
            "file": str(reproducer_path),
            "length": reproducer_length,
            "sha256": reproducer_digest,
            "member_count": len(link_members),
            "input_count": len(mapped),
            "ordered_input_count": len(ordered_inputs),
        },
        "archive_members": [
            {
                "index": index,
                "name": member.name,
                "kind": "directory" if member.is_directory else "regular",
                "length": member.length,
                "sha256": member.sha256,
            }
            for index, member in enumerate(link_members)
        ],
        "link_response": {
            "file": response_path.name,
            "length": len(response),
            "sha256": _sha256(response),
        },
        "executable": {
            "file": str(executable_path),
            "length": len(executable),
            "sha256": executable_sha256,
        },
        "adapter_provenance": {
            "protocol": "BL-LIFECYCLE-PROVENANCE/1",
            "source_manifest_sha256": manifest_hash,
            "executable_size": len(executable),
            "executable_sha256": executable_sha256,
            "stderr_line": adapter_provenance_line,
        },
        "ordered_link_inputs": [
            {
                "index": index,
                "archive_member": member.name,
                "length": member.length,
                "sha256": member.sha256,
                "identity": item.identity,
                "category": item.category,
            }
            for index, (member, item) in enumerate(ordered_inputs)
        ],
    }
    return receipt_object


def _run(target_arg: str, evidence_arg: str) -> int:
    target_dir, evidence_dir = _validate_outdirs(target_arg, evidence_arg)
    cargo_length, cargo_digest = _file_digest(PINNED_CARGO)
    if cargo_length < 1 or cargo_digest != PINNED_CARGO_SHA256:
        raise AttestationError("pinned Cargo executable SHA-256 mismatch")
    rustc_length, rustc_digest = _file_digest(PINNED_RUSTC)
    if rustc_length < 1 or rustc_digest != PINNED_RUSTC_SHA256:
        raise AttestationError("pinned Rustc executable SHA-256 mismatch")
    environment = os.environ.copy()
    cargo_configuration = _check_build_environment(environment)
    environment.pop("CARGO_TARGET_DIR", None)
    environment["CARGO"] = str(PINNED_CARGO)
    environment["RUSTC"] = str(PINNED_RUSTC)
    target_dir.mkdir(parents=True, exist_ok=False)
    evidence_dir.mkdir(parents=True, exist_ok=False)
    command = [
        str(PINNED_CARGO),
        "build",
        "--locked",
        "--offline",
        "--jobs",
        "1",
        "--target",
        TARGET,
        "--release",
        "--bin",
        "lifecycle",
        "--message-format=json-render-diagnostics",
        "--target-dir",
        str(target_dir),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=RUST_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise AttestationError(f"cannot start pinned Cargo: {error}") from error
    try:
        _write_new(evidence_dir / "cargo.stdout.log", completed.stdout)
        _write_new(evidence_dir / "cargo.stderr.log", completed.stderr)
    except AttestationError:
        _forward_cargo_output(completed.stdout, completed.stderr)
        raise
    if completed.returncode != 0:
        _forward_cargo_output(completed.stdout, completed.stderr)
        raise AttestationError(f"Cargo build exited with status {completed.returncode}; no post-link receipt created")
    try:
        if _verify_cargo_configuration(environment) != cargo_configuration:
            raise AttestationError("Cargo configuration changed during the build")
        _artifact, warnings = _load_cargo_artifact(completed.stdout, target_dir)
        receipt_object = _attest_success(
            target_dir,
            evidence_dir,
            completed.stdout,
            completed.stderr,
            command,
            warnings,
            cargo_configuration,
        )
        receipt_data = (json.dumps(receipt_object, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")
        receipt_path = evidence_dir / "lifecycle_post_link_receipt.v1.json"
        _write_receipt(receipt_path, receipt_data)
    except Exception as error:
        _forward_cargo_output(completed.stdout, completed.stderr)
        if isinstance(error, AttestationError):
            raise
        raise AttestationError(f"post-link attestation failed closed: {type(error).__name__}: {error}") from error
    for warning in warnings:
        sys.stderr.write(warning)
        if not warning.endswith("\n"):
            sys.stderr.write("\n")
    if completed.stderr:
        sys.stderr.flush()
        sys.stderr.buffer.write(completed.stderr)
        sys.stderr.buffer.flush()
    print(
        json.dumps(
            {
                "status": "attested",
                "receipt": str(receipt_path),
                "receipt_sha256": _sha256(receipt_data),
                "executable_sha256": receipt_object["executable"]["sha256"],
                "link_input_count": receipt_object["link_reproducer"]["input_count"],
                "warning_count": len(warnings),
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, help="fresh Cargo target directory outside the source root")
    parser.add_argument("--evidence-dir", required=True, help="fresh evidence directory outside the source root")
    args = parser.parse_args(argv)
    try:
        return _run(args.target_dir, args.evidence_dir)
    except Exception as error:
        print(f"post-link attestation failed closed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
